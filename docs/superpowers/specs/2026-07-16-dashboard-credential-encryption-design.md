# Design: Dashboard Credential Encryption

Status: approved, ready for implementation planning
Date: 2026-07-16

## Purpose

`server-config.json` currently stores `AdPassword` (encrypted since 2026-07-16, DPAPI/`LocalMachine`), `WebPassword` (Basic Auth password for the dashboard), and `Token` (inventory-ingestion token) — the latter two still plaintext-plus-restricted-ACL. This brings both to the same DPAPI-encrypted-at-rest standard, and actively migrates existing plaintext values on every deployment rather than waiting for an unrelated future save to happen to touch them.

**Correction made during plan research (2026-07-16):** the original brainstorming session assumed a fourth secret, `CertificatePfxPassword`, was also stored in `server-config.json`. Checking the actual code (`ConfigureCertificate`/`ImportCertificateIntoStore` in `WindowsInventoryLiteServer.cs`, and the `$CertificatePfxPassword` handling in `Install-Server.ps1`) found it is used only transiently, at the moment a PFX is imported into the `LocalMachine\My` certificate store (via `Install-Server.ps1 -CertificatePfxPassword` at install time, or the dashboard's Certificate-page upload) — it converts to a `SecureString`/is read once for the import call and is never written to `$config`/`server-config.json` at all. There is no field to migrate or encrypt. Scope is corrected to 2 secrets: `WebPassword` and `Token`.

## Scope

In scope:
- Encrypt `WebPassword` and `Token` at rest using the existing `SecretProtector` (`src/server/SecretProtector.cs`), exactly as already done for `AdPassword`.
- Active migration: on every service startup, detect any of the three secrets (`AdPassword`, `WebPassword`, `Token`) still stored as plaintext and re-encrypt them in one batched config rewrite.
- `Install-Server.ps1`: generalize the existing `Protect-AdPassword` function so all three persisted install-time secret parameters are encrypted before being written to `server-config.json`.

Out of scope (explicitly not part of this change):
- `CertificatePfxPassword` — never persisted to `server-config.json` in the first place (see correction above), so there's nothing to encrypt or migrate.
- Changing where `Token` is used in plaintext by necessity — it is embedded in the generated GPO `Install-ClientGpo.cmd` (via `GenerateCmdLines`) so client machines can authenticate; that is a separate, intentional distribution channel unrelated to at-rest storage in `server-config.json`, and does not change.
- Any UI-visible change. This is entirely a storage-format change; no dashboard field, API response shape, or CLI flag changes.
- WinRM credentials (`-CredentialUsername`/`-CredentialPassword` used by `Install-ClientWinRM.ps1`) — those are provided per-invocation for a WinRM session and are never persisted to `server-config.json` in the first place, so there's nothing to migrate.

## Mechanism

Reuse `SecretProtector.Protect`/`Unprotect` unchanged (DPAPI, `DataProtectionScope.LocalMachine`, `"dpapi:"` prefix marker, graceful passthrough for legacy/unprefixed values, no-op guard against double-encrypting an already-prefixed value). No changes to `SecretProtector.cs` itself — this design only changes which config keys route through it.

**Alternatives considered and rejected:**
- **A separate AES key file alongside the config** — would make the config portable across machines (DPAPI/`LocalMachine` ciphertext is host-bound), but trades one problem for another: the key file itself now needs protecting, and there's no expressed need for cross-machine config portability today.
- **Windows Credential Manager (`CredWrite`/`cmdkey`)** — architecturally "more correct" for some security postures, but requires new interop code from both C# and PowerShell, more moving parts to test and maintain, with no clear advantage over DPAPI/`LocalMachine` for this project's actual threat model (see `docs/threat-model.md`: the control is against the config file being copied off the box or into a backup, not against a compromised host with the service already running).

## Server-side change: `SaveServerConfigValues`

`WindowsInventoryLiteServer.cs`'s `SaveServerConfigValues` already special-cases one key:

```csharp
config[pair.Key] = pair.Key == "AdPassword" ? SecretProtector.Protect(pair.Value, options) : pair.Value;
```

This becomes a set membership check covering all three secret keys:

```csharp
private static readonly HashSet<string> EncryptedConfigKeys = new HashSet<string>(
    new[] { "AdPassword", "WebPassword", "Token" },
    StringComparer.Ordinal);
...
config[pair.Key] = EncryptedConfigKeys.Contains(pair.Key) ? SecretProtector.Protect(pair.Value, options) : pair.Value;
```

Every existing call site that writes one of these four keys through `SaveServerConfigValues` (the AD settings save, the admin-password change endpoint, the certificate upload flow, etc.) is unaffected by this change beyond gaining encryption — no call site needs its own logic, since the special-casing lives in the one shared save path.

## Server-side change: `LoadConfigFile`

`AdPassword` already routes through `SecretProtector.Unprotect` on load. `WebPassword` and `Token` will route through it the same way (replacing their current direct `GetConfigString` assignment at `WindowsInventoryLiteServer.cs:304-314`):

```csharp
options.Token = SecretProtector.Unprotect(GetConfigString(config, "Token"));
options.WebPassword = SecretProtector.Unprotect(GetConfigString(config, "WebPassword"));
```

`Unprotect` already passes an unprefixed (legacy plaintext) value through unchanged, so this alone is backward-compatible with every existing deployment — the migration step below is what actively closes the gap rather than leaving it open until the next incidental save.

## Startup migration

New instance method on `InventoryServer`, called as the very first statement inside `Start()` (before `LoadServerCertificate()` and the HTTP/HTTPS slot setup) — `options` is already fully populated by `ServerOptions.Parse()`/`LoadConfigFile` by the time `InventoryServer` is constructed, so this has everything it needs the moment `Start()` begins:

```csharp
private void MigratePlaintextSecrets()
{
    if (String.IsNullOrEmpty(options.ConfigPath) || !File.Exists(options.ConfigPath))
    {
        return;
    }

    Dictionary<string, object> config;
    try
    {
        config = CreateJsonSerializer().Deserialize<Dictionary<string, object>>(
            File.ReadAllText(options.ConfigPath, Encoding.UTF8));
    }
    catch
    {
        return;
    }

    Dictionary<string, string> updates = new Dictionary<string, string>();
    foreach (string key in EncryptedConfigKeys)
    {
        string raw = config.ContainsKey(key) ? Convert.ToString(config[key]) : null;
        if (!String.IsNullOrEmpty(raw) && !raw.StartsWith("dpapi:", StringComparison.Ordinal))
        {
            updates[key] = SecretProtector.Unprotect(raw); // plaintext already, but routes through the same accessor for consistency
        }
    }

    if (updates.Count > 0)
    {
        SaveServerConfigValues(updates); // re-encrypts each key via the EncryptedConfigKeys check above
        DebugLogger.Log(options, "Server", "Migrated " + updates.Count + " plaintext secret(s) in server-config.json to encrypted storage.");
    }
}
```

Notes:
- Reads the raw config file directly (not `options.*`, which already holds decrypted plaintext regardless of on-disk form) specifically to check the stored prefix.
- Batches all four checks into a single `SaveServerConfigValues` call — one file rewrite even if multiple secrets need migrating, not one rewrite per field.
- Silent no-op when nothing needs migrating (the common case on every startup after the first migrated run) or when there's no config file to migrate (ephemeral `--console` runs with no `--config`).
- The one DebugLogger line fires only when something actually changed, and only ever states a count — never the field names or values.
- Runs synchronously before the listeners start; cost is one extra JSON parse of an already-small file plus at most four cheap DPAPI calls, on a path that only ever executes once per service start.

## `Install-Server.ps1` change

`Protect-AdPassword` (added earlier this session) is renamed to `Protect-Secret` with no behavioral change — same DPAPI/`LocalMachine` call, same `"dpapi:"` prefix, same Base64 encoding, kept byte-for-byte compatible with `SecretProtector.Unprotect`:

```powershell
function Protect-Secret {
    param(
        [string]$PlainText
    )

    if (-not $PlainText) {
        return $PlainText
    }

    Add-Type -AssemblyName System.Security
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return 'dpapi:' + [Convert]::ToBase64String($protectedBytes)
}
```

Every `$config.X = $X` assignment for the three persisted secrets becomes `$config.X = Protect-Secret -PlainText $X`:

```powershell
$config.Token       = Protect-Secret -PlainText $Token
$config.WebPassword = Protect-Secret -PlainText $WebPassword
if ($AdPassword) {
    $config.AdPassword = Protect-Secret -PlainText $AdPassword
}
```

`$CertificatePfxPassword` is untouched by this change — it is never assigned to `$config` today (confirmed by reading `Install-Server.ps1` end to end: it flows only into a local `$securePfxPassword` used for the immediate PFX import), so there's nothing to route through `Protect-Secret`.

`WebPassword`/`Token` don't currently have the `AdPassword`-style "only write if a new value was actually passed this run" guard (`Get-ConfigValue`/reload-from-existing-config already handles carrying forward an unset `-Token`/`-WebPassword` from a prior install, per the existing reload block for those parameters) — `Protect-Secret` is safe to call unconditionally on whatever value that reload logic already resolved, whether newly passed or carried forward, since it's a no-op on an already-`"dpapi:"`-prefixed value.

## Security notes for `docs/threat-model.md`

Add a bullet alongside the existing `AdPassword` DPAPI note: `WebPassword` and `Token` are now encrypted at rest the same way — DPAPI/`LocalMachine` scope, decryptable by any sufficiently privileged process on the same host, raising the bar over plaintext (protects against the config file being copied off the box or into a backup) without being a substitute for restricting who can reach the server itself. `CertificatePfxPassword` is unaffected (never persisted).

## Testing

- New self-test: a migration-detection helper (the "does this raw value need migrating" check, extracted as a small pure function so it's testable without a live config file) — covers a mix of already-`dpapi:`-prefixed and plaintext values, confirms only the plaintext ones are flagged.
- Reuse the existing `SecretProtector` round-trip/legacy-passthrough self-tests unchanged — they already cover the underlying mechanism generically, nothing field-specific to add there.
- Live verification: start a server against a config file with `WebPassword`/`Token`/`AdPassword` stored as plaintext, confirm normal operation (Basic Auth still authenticates, `X-Inventory-Token` still validates) both before and after a restart, and confirm the raw config file holds `"dpapi:..."` for all three after that first restart.
- Pester: syntax and PowerShell 5.1 compatibility check on the modified `Install-Server.ps1`, as already done for every prior change to that script this session.

## Open questions

None outstanding. Scope was corrected once during plan research (see the Purpose section) after confirming `CertificatePfxPassword` is never persisted; the corrected scope (`AdPassword`, `WebPassword`, `Token`) still satisfies the user's original intent — "encrypt the credentials this project actually stores at rest" — since there was never a fourth stored secret to include. All other decisions were confirmed with the user during brainstorming (2026-07-16): DPAPI/`LocalMachine` via the existing `SecretProtector`, active migration at every startup rather than passive on-next-save.
