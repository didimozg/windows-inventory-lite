# Dashboard Credential Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Encrypt `WebPassword` and `Token` at rest in `server-config.json` using the existing DPAPI-based `SecretProtector` (already used for `AdPassword`), and actively migrate any already-stored plaintext values to encrypted form on every service startup.

**Architecture:** Generalize the single existing `AdPassword`-only special case in `SaveServerConfigValues` into a small set of encrypted-key names covering all three secrets. Add one new startup step that detects and batch-migrates any still-plaintext secret. Rename and harden `Install-Server.ps1`'s `Protect-AdPassword` into a general `Protect-Secret` used for all three install-time secret parameters.

**Tech Stack:** C# (.NET Framework 3.5/4.0, `System.Security.Cryptography.ProtectedData`), PowerShell 5.1-compatible.

## Global Constraints

- Scope is exactly 3 secrets: `AdPassword` (already encrypted), `WebPassword`, `Token`. `CertificatePfxPassword` is explicitly out of scope - it is never persisted to `server-config.json` (confirmed by reading `ConfigureCertificate`/`ImportCertificateIntoStore` and `Install-Server.ps1`'s PFX-import code end to end) - do not add any code path that writes or reads a `CertificatePfxPassword` config key.
- Reuse `SecretProtector.Protect`/`Unprotect` (`src/server/SecretProtector.cs`) exactly as-is. Do not modify that file.
- No UI-visible change of any kind - no dashboard field, no API response shape change, no new CLI flag. This is purely a storage-format change plus one new startup step.
- The startup migration must be silent when there is nothing to migrate (the common case on every startup after the first), batch all changed fields into a single file rewrite, and never throw - a migration failure must not prevent the server from starting.
- `Protect-Secret` (PowerShell) must no-op on a value that already has the `"dpapi:"` prefix - `Token`/`WebPassword` reload their saved value from `server-config.json` on a re-run of `Install-Server.ps1` when not passed explicitly (unlike `AdPassword`, which is deliberately never reloaded), so without this guard a re-run would re-encrypt an already-encrypted value and corrupt it.
- Every code-changing task ends with a real build/self-test/Pester run, not just a compile check - use actual command output as evidence.
- Version bump required (MINOR - this adds a new behavior, not just a fix) with a CHANGELOG entry, in the final task, per this project's single-unified-version policy.

---

### Task 1: Extend `SaveServerConfigValues` and `LoadConfigFile` to cover `WebPassword`/`Token`

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs:304-315` (`LoadConfigFile`'s `Token`/`WebPassword` loading)
- Modify: `src/server/WindowsInventoryLiteServer.cs:3118-3155` (`SaveServerConfigValues`)

**Interfaces:**
- Consumes: `SecretProtector.Protect(string, ServerOptions)` / `SecretProtector.Unprotect(string)` (existing, unchanged).
- Produces: `private static readonly HashSet<string> EncryptedConfigKeys` - Task 2's `MigratePlaintextSecrets` reads this same set.

- [ ] **Step 1: Add the `EncryptedConfigKeys` set and use it in `SaveServerConfigValues`**

Find this in `src/server/WindowsInventoryLiteServer.cs` (inside `SaveServerConfigValues`):

```csharp
            foreach (KeyValuePair<string, string> pair in updates)
            {
                // AdPassword is encrypted at rest (DPAPI, see
                // SecretProtector.cs) - every other key here keeps the
                // existing plaintext-plus-restricted-ACL precedent already
                // used for WebPassword/Token.
                config[pair.Key] = pair.Key == "AdPassword" ? SecretProtector.Protect(pair.Value, options) : pair.Value;
            }
```

Replace with:

```csharp
            foreach (KeyValuePair<string, string> pair in updates)
            {
                config[pair.Key] = EncryptedConfigKeys.Contains(pair.Key) ? SecretProtector.Protect(pair.Value, options) : pair.Value;
            }
```

Add the set as a field on `InventoryServer`, immediately above `SaveServerConfigValues`:

```csharp
        // AdPassword, WebPassword, and Token are encrypted at rest (DPAPI,
        // see SecretProtector.cs) before being written to server-config.json
        // by SaveServerConfigValues below, and decrypted on load by
        // LoadConfigFile. CertificatePfxPassword is NOT in this set - it is
        // never persisted to server-config.json at all (it flows only into
        // a local SecureString used once for a PFX import, in both
        // ConfigureCertificate here and Install-Server.ps1's own import
        // step), so there is nothing to encrypt for it.
        private static readonly HashSet<string> EncryptedConfigKeys = new HashSet<string>(
            new[] { "AdPassword", "WebPassword", "Token" },
            StringComparer.Ordinal);

        private void SaveServerConfigValues(Dictionary<string, string> updates)
```

- [ ] **Step 2: Route `Token`/`WebPassword` loading through `SecretProtector.Unprotect`**

Find this in `LoadConfigFile`:

```csharp
                if (String.IsNullOrEmpty(options.Token))
                {
                    options.Token = GetConfigString(config, "Token");
                }
                if (String.IsNullOrEmpty(options.WebUsername))
                {
                    options.WebUsername = GetConfigString(config, "WebUsername");
                }
                if (String.IsNullOrEmpty(options.WebPassword))
                {
                    options.WebPassword = GetConfigString(config, "WebPassword");
                }
```

Replace with (only the `Token`/`WebPassword` lines change - `WebUsername` is not a secret and stays as-is):

```csharp
                if (String.IsNullOrEmpty(options.Token))
                {
                    options.Token = SecretProtector.Unprotect(GetConfigString(config, "Token"));
                }
                if (String.IsNullOrEmpty(options.WebUsername))
                {
                    options.WebUsername = GetConfigString(config, "WebUsername");
                }
                if (String.IsNullOrEmpty(options.WebPassword))
                {
                    options.WebPassword = SecretProtector.Unprotect(GetConfigString(config, "WebPassword"));
                }
```

- [ ] **Step 3: Build to verify it compiles**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"`
Expected: `Server executable: ...` with no error (the script throws on a nonzero `csc.exe` exit code, so any compile error surfaces as a thrown exception here, not a silent stale binary).

- [ ] **Step 4: Run self-tests to confirm no regression**

Run: `.\build\WindowsInventoryLiteServer.exe --self-test`
Expected: all existing self-tests still show `PASS` (27/27 as of this plan's writing - if the count differs, that's fine as long as none show `FAIL`), exit code 0.

- [ ] **Step 5: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Encrypt WebPassword/Token at rest alongside AdPassword"
```

---

### Task 2: Startup migration of existing plaintext secrets

**Files:**
- Modify: `src/server/WindowsInventoryLiteServer.cs` (new `NeedsMigration`/`MigratePlaintextSecrets` methods, wired into `Start()`, plus 2 new self-tests)

**Interfaces:**
- Consumes: `EncryptedConfigKeys` (Task 1), `SecretProtector.Unprotect` (existing), `SaveServerConfigValues` (existing, now encrypts via `EncryptedConfigKeys` per Task 1), `DebugLogger.Log` (existing), `CreateJsonSerializer()` (existing helper already used elsewhere in this file for ad-hoc config reads).
- Produces: `internal static bool NeedsMigration(string rawValue)` - a pure function, self-tested directly, no other task depends on it.

- [ ] **Step 1: Add the pure `NeedsMigration` helper**

Find `internal static bool ShouldSyncAd(DateTime? lastSyncedUtc, int intervalHours)` in `src/server/WindowsInventoryLiteServer.cs` and add a new method immediately after its closing brace:

```csharp
        // Returns true when a raw config value is still plaintext and
        // needs migrating to encrypted storage - i.e. it's non-empty and
        // does not already carry SecretProtector's "dpapi:" prefix. Pure
        // and parameter-driven so it's directly self-testable without a
        // live config file.
        internal static bool NeedsMigration(string rawValue)
        {
            return !String.IsNullOrEmpty(rawValue) && !rawValue.StartsWith("dpapi:", StringComparison.Ordinal);
        }
```

- [ ] **Step 2: Add `MigratePlaintextSecrets` and wire it into `Start()`**

Add a new private instance method, placed immediately after `NeedsMigration` (same file, still inside the `InventoryServer` class - note `NeedsMigration` above is `static`, but this method needs instance state (`options`, `SaveServerConfigValues`, `DebugLogger.Log`) so it is not):

```csharp
        // Detects any of the 3 encrypted secrets (see EncryptedConfigKeys)
        // still stored as plaintext in server-config.json and re-encrypts
        // them in a single batched rewrite. Runs once per service start,
        // as the very first action inside Start() - cheap (one small JSON
        // parse, at most 3 DPAPI calls) and must never throw, since a
        // migration failure must not prevent the server from starting.
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

            if (config == null)
            {
                return;
            }

            Dictionary<string, string> updates = new Dictionary<string, string>();
            foreach (string key in EncryptedConfigKeys)
            {
                string raw = config.ContainsKey(key) ? Convert.ToString(config[key]) : null;
                if (NeedsMigration(raw))
                {
                    updates[key] = raw;
                }
            }

            if (updates.Count > 0)
            {
                try
                {
                    SaveServerConfigValues(updates);
                    DebugLogger.Log(options, "Server", "Migrated " + updates.Count + " plaintext secret(s) in server-config.json to encrypted storage.");
                }
                catch
                {
                    // A migration failure must not prevent the server from
                    // starting - the affected secret(s) simply stay
                    // plaintext until the next successful attempt (every
                    // subsequent startup retries).
                }
            }
        }
```

Find `public void Start()` and add the call as its very first statement:

```csharp
        public void Start()
        {
            MigratePlaintextSecrets();
            LoadServerCertificate();
```

- [ ] **Step 3: Add self-tests for `NeedsMigration`**

Find `TestSecretProtectorLegacyPlaintext` in `src/server/WindowsInventoryLiteServer.cs` and add two new test methods immediately after its closing brace:

```csharp
        private static string TestNeedsMigrationPlaintextValue()
        {
            if (!NeedsMigration("a-plaintext-secret"))
            {
                return "expected a non-empty, unprefixed value to need migration";
            }
            return null;
        }

        private static string TestNeedsMigrationAlreadyEncryptedOrEmpty()
        {
            if (NeedsMigration("dpapi:AQAAANCMnd8BFdERjHoAwE"))
            {
                return "expected an already-'dpapi:'-prefixed value to not need migration";
            }
            if (NeedsMigration(null))
            {
                return "expected a null value to not need migration";
            }
            if (NeedsMigration(""))
            {
                return "expected an empty value to not need migration";
            }
            return null;
        }
```

Find the self-test registration line for `TestSecretProtectorLegacyPlaintext` (in the method that registers all self-tests via `SelfTestCheck`) and add two new registrations immediately after it:

```csharp
            allPassed &= SelfTestCheck(output, "SecretProtector.Unprotect passes through a legacy plaintext value", TestSecretProtectorLegacyPlaintext);
            allPassed &= SelfTestCheck(output, "NeedsMigration flags a plaintext value", TestNeedsMigrationPlaintextValue);
            allPassed &= SelfTestCheck(output, "NeedsMigration does not flag an already-encrypted or empty value", TestNeedsMigrationAlreadyEncryptedOrEmpty);
```

- [ ] **Step 4: Build and run self-tests**

Run: `powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"` then `.\build\WindowsInventoryLiteServer.exe --self-test`
Expected: build succeeds, both new tests show `PASS`, all other self-tests still `PASS`, exit code 0.

- [ ] **Step 5: Live-verify the migration end to end**

From `src/`, in a scratch directory (do not touch any real installed config):

```bash
mkdir -p /tmp/migrationtest/data
cat > /tmp/migrationtest/server-config.json << 'EOF'
{"Token":"plain-token-value","WebPassword":"plain-web-password","WebUsername":"admin"}
EOF
```

Start the server against that config (Git Bash keeps stdin open for `--console` mode with `tail -f /dev/null |`):

```bash
tail -f /dev/null | ./build/WindowsInventoryLiteServer.exe --console --prefix http://localhost:18299/ --data /tmp/migrationtest/data --config /tmp/migrationtest/server-config.json --debug-log-enabled &
sleep 2
cat /tmp/migrationtest/server-config.json
cat /tmp/migrationtest/data/_logs/debug.log
taskkill //IM WindowsInventoryLiteServer.exe //F
rm -rf /tmp/migrationtest
```

Expected: `server-config.json` now shows `"Token":"dpapi:..."` and `"WebPassword":"dpapi:..."` (both re-encrypted after the one startup), `WebUsername` unchanged (`"admin"`, never encrypted), and `debug.log` contains one line reading `Migrated 2 plaintext secret(s) in server-config.json to encrypted storage.` Re-running the same start command a second time and re-checking `debug.log` should show no second "Migrated" line (nothing left to migrate).

- [ ] **Step 6: Commit**

```bash
git add src/server/WindowsInventoryLiteServer.cs
git commit -m "Actively migrate plaintext WebPassword/Token/AdPassword on startup"
```

---

### Task 3: `Install-Server.ps1` - generalize `Protect-AdPassword` to `Protect-Secret`

**Files:**
- Modify: `src/Install-Server.ps1:312-325` (`Protect-AdPassword` function)
- Modify: `src/Install-Server.ps1:761,763,775` (the `$config.Token`/`$config.WebPassword`/`$config.AdPassword` assignments)

**Interfaces:**
- Consumes: nothing new.
- Produces: `Protect-Secret` (PowerShell function) - replaces `Protect-AdPassword`; no other task in this plan calls it directly, but any future script touching these secrets should use it.

- [ ] **Step 1: Rename `Protect-AdPassword` to `Protect-Secret` and add the already-encrypted guard**

Find this in `src/Install-Server.ps1`:

```powershell
# Encrypts a secret with Windows DPAPI (LocalMachine scope, not CurrentUser -
# the server may run as LocalSystem/NetworkService/a service account with no
# loaded interactive profile, so LocalMachine is the only scope any process
# on this machine, including the running service, can reliably decrypt with).
# Stored with a "dpapi:" prefix so WindowsInventoryLiteServer.exe's matching
# SecretProtector.Unprotect can tell an already-encrypted value apart from a
# legacy/hand-edited plaintext one (which it uses as-is rather than failing).
function Protect-AdPassword {
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

Replace with:

```powershell
# Encrypts a secret with Windows DPAPI (LocalMachine scope, not CurrentUser -
# the server may run as LocalSystem/NetworkService/a service account with no
# loaded interactive profile, so LocalMachine is the only scope any process
# on this machine, including the running service, can reliably decrypt with).
# Stored with a "dpapi:" prefix so WindowsInventoryLiteServer.exe's matching
# SecretProtector.Unprotect can tell an already-encrypted value apart from a
# legacy/hand-edited plaintext one (which it uses as-is rather than failing).
# Used for AdPassword, Token, and WebPassword - the no-op guard below matters
# for Token/WebPassword specifically, since (unlike AdPassword) they reload
# their saved value from server-config.json on a re-run when not passed
# explicitly; without the guard, an already-encrypted saved value would be
# encrypted a second time and corrupted.
function Protect-Secret {
    param(
        [string]$PlainText
    )

    if (-not $PlainText) {
        return $PlainText
    }
    if ($PlainText.StartsWith('dpapi:')) {
        return $PlainText
    }

    Add-Type -AssemblyName System.Security
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return 'dpapi:' + [Convert]::ToBase64String($protectedBytes)
}
```

- [ ] **Step 2: Apply `Protect-Secret` to the `Token`/`WebPassword`/`AdPassword` config writes**

Find this in `src/Install-Server.ps1`:

```powershell
$config.Token                   = $Token
$config.WebUsername             = $WebUsername
$config.WebPassword             = $WebPassword
```

Replace with:

```powershell
$config.Token                   = Protect-Secret -PlainText $Token
$config.WebUsername             = $WebUsername
$config.WebPassword             = Protect-Secret -PlainText $WebPassword
```

Find this (a few lines later):

```powershell
if ($AdPassword) {
    $config.AdPassword = Protect-AdPassword -PlainText $AdPassword
}
```

Replace with:

```powershell
if ($AdPassword) {
    $config.AdPassword = Protect-Secret -PlainText $AdPassword
}
```

- [ ] **Step 3: Syntax-check the script**

Run:
```powershell
powershell -NoProfile -Command "$tokens = $null; $errors = $null; [System.Management.Automation.Language.Parser]::ParseFile('src\Install-Server.ps1', [ref]$tokens, [ref]$errors) | Out-Null; $errors.Count"
```
Expected: `0`.

- [ ] **Step 4: Run the Pester suite**

Run: `powershell -NoProfile -Command "Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed"`
Expected: all tests pass, including `parses PowerShell scripts` and `does not require PowerShell 7 syntax` (both exercise `Install-Server.ps1`).

- [ ] **Step 5: Commit**

```bash
git add src/Install-Server.ps1
git commit -m "Generalize Protect-AdPassword to Protect-Secret for Token/WebPassword"
```

---

### Task 4: Documentation, version bump, final verification

**Files:**
- Modify: `docs/threat-model.md`
- Modify: `README.md`, `README_RU.md`
- Modify: `src/server/WindowsInventoryLiteServer.cs` (`Program.ProductVersion`)
- Modify: `src/client/WindowsInventoryLiteClient.cs` (`Program.ProductVersion`)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Update `docs/threat-model.md`**

Find the existing bullet about `AdPassword` encryption (added earlier this session) and add a sentence to it (do not add a new bullet - extend the existing one so the "secrets at rest" story stays in one place):

```markdown
- If explicit AD credentials are configured (rather than the service account identity), the password is encrypted at rest with Windows DPAPI (machine scope) before being written to server-config.json, unlike WebPassword/Token, which remain plaintext-plus-ACL. DPAPI at machine scope is decryptable by any sufficiently privileged process on the same host - it raises the bar over plaintext (protects against the config file being copied off the box or into a backup) but is not a substitute for restricting who can reach the server itself.
```

becomes:

```markdown
- AdPassword, WebPassword, and Token are all encrypted at rest with Windows DPAPI (machine scope) before being written to server-config.json; any already-plaintext value from an older install is migrated to encrypted form automatically on the next service start. CertificatePfxPassword is not persisted at all (used once, transiently, for a PFX import). DPAPI at machine scope is decryptable by any sufficiently privileged process on the same host - it raises the bar over plaintext (protects against the config file being copied off the box or into a backup) but is not a substitute for restricting who can reach the server itself.
```

- [ ] **Step 2: Update `README.md`'s Security Notes**

Find this line (added earlier this session):

```markdown
- The AD password (explicit-credentials mode) is encrypted at rest with Windows DPAPI; `WebPassword`/`Token`/the certificate PFX password remain plaintext in `server-config.json`, protected only by the file's restricted ACL.
```

Replace with:

```markdown
- `AdPassword`, `WebPassword`, and `Token` are encrypted at rest with Windows DPAPI; an existing plaintext value from an older install is migrated automatically on the next service start. The certificate PFX password is never written to `server-config.json` at all - it is used once, transiently, to import the certificate.
```

- [ ] **Step 3: Update `README_RU.md`'s equivalent line**

Find the Russian equivalent of that Security Notes bullet (added earlier this session, describing `AdPassword` DPAPI encryption vs. plaintext `WebPassword`/`Token`/certificate password) and adapt it to match the corrected English wording above - all three are now encrypted, migrated automatically, and the certificate PFX password was never persisted in the first place.

- [ ] **Step 4: Bump the version**

Run: `grep -n "ProductVersion = " src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs` to confirm the current version is `"0.10.1"` in both files (if it is not - e.g. another change landed on this branch first and moved it further - use the actual current value and bump from there instead). Update both to `"0.11.0"` (MINOR: 0.10.x -> 0.11.0, patch reset to 0) - identical value in both files.

- [ ] **Step 5: Add the CHANGELOG entry**

Add a new `## [0.11.0] - 2026-07-16` section at the top of `CHANGELOG.md`, after `## [Unreleased]`, matching the file's existing entry format (if the actual current version from Step 4 was not `0.10.1`, adjust this heading to match whatever the real next-MINOR version turned out to be):

```markdown
### Added

- `WebPassword` and `Token` are now encrypted at rest with Windows DPAPI, matching `AdPassword`. Any secret still stored as plaintext from an older install is migrated to encrypted form automatically on the next service start - no manual action needed.

### Fixed

- Confirmed `CertificatePfxPassword` was never persisted to `server-config.json` in the first place (it is used once, transiently, for a PFX import) - corrected an earlier design assumption to the contrary before it shipped.
```

- [ ] **Step 6: Full rebuild and verification**

```powershell
.\src\Build-Server.ps1
.\src\Build-Client.ps1 -TargetFramework Net35 -OutputPath '.\build\WindowsInventoryLiteClient-net35.exe'
.\src\Build-Client.ps1 -TargetFramework Net40 -OutputPath '.\build\WindowsInventoryLiteClient-net40.exe'
.\build\WindowsInventoryLiteServer.exe --self-test
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester -Path .\tests -Output Detailed
.\build\WindowsInventoryLiteServer.exe --version
```

Expected: all three builds succeed, self-test suite all `PASS` with exit code 0, Pester all green, printed version matches the new bumped value.

- [ ] **Step 7: Commit**

```bash
git add docs/threat-model.md README.md README_RU.md src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs CHANGELOG.md
git commit -m "Bump version for dashboard credential encryption"
```

---
