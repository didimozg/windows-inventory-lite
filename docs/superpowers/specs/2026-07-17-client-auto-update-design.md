# Client Auto-Update Design

## Goal

Let an administrator see, from the dashboard, which deployed clients are running an outdated version relative to the client package currently on the server, and push an update to the eligible ones with one action - without the server silently or automatically reinstalling anything unattended.

## Background

The server already tracks `clientVersion` on every inventory report (`WindowsInventoryLiteClient.cs` sends `Program.ProductVersion` on every report) and already has a working WinRM-based install/uninstall pipeline (`StartClientAction` / `RunClientActionJob` / `RunClientInstallTarget`, used today by the dashboard's `Client actions` tab). This feature adds detection and a dedicated UI on top of that existing pipeline - it does not change how a client actually gets installed or updated.

Two operational constraints from the environment this feature is being built for:

1. WinRM is unreliable against Windows 7/8/8.1 targets. A fully unattended push against the whole fleet risks silently failing (or partially failing) on part of the park.
2. There is currently no persisted WinRM credential in this codebase - the `Client actions` tab always requires the administrator to type a username/password into the form for that one action; nothing is saved.

## Non-Goals

- No fully automatic/unattended push (rejected during brainstorming - the admin always clicks "update selected").
- No change to how `Install-ClientWinRM.ps1`/`Deploy-ClientGpo.ps1` picks which package (net35 vs net40) to deploy on a given target - that decision already happens correctly on the remote side during deployment and is out of scope here.
- No change to the existing `Client package` tab's `net35VersionMismatch`/`net40VersionMismatch` fields (those compare the package on disk against `Program.ProductVersion` - a different, already-shipped check that answers "is the package stale relative to the server binary"). This feature answers a different question: "is a given deployed client stale relative to the package on disk."
- No new WinRM job type or execution pipeline. Pushing an update reuses the existing `POST /api/v1/client-install` endpoint and `InstallJob` machinery unchanged.
- No client-side protocol change. The client does not start reporting its target framework (.NET 3.5 vs 4.0) as part of this feature.

## Detection

New endpoint: `GET /api/v1/client-updates`.

For each client in the existing report index (`BuildClientIndex()`), compute:

- `clientVersion` - already present on every report.
- The current package versions on disk: `net35Version`/`net40Version`, computed the same way `SendClientPackageStatus` already computes them (`GetExeVersion` against the files in `options.ClientPackagePath`).
- **Up to date** if `clientVersion` equals `net35Version` OR equals `net40Version` (whichever is present). Since the client does not report which framework build it's running, matching either available package version is treated as current - this never flags a genuinely current client as outdated, at the cost of occasionally not flagging a client that happens to share a version string with the *other* framework's package by coincidence (accepted: version strings are the project's own `MAJOR.MINOR.PATCH`, coincidental cross-framework matches are not a realistic concern for a single-project version scheme).
- **Outdated** if `clientVersion` differs from every package version that is actually present on disk. A client is never flagged outdated because a package is simply missing (e.g. only net40 was ever built) - only because its own reported version doesn't match anything currently deployable.
- **Eligible for WinRM push**: `os.caption` does NOT match a Windows 7/8/8.1 pattern. Default is eligible (Windows Server and any other caption not matching the known-bad list is eligible) - this is a blocklist, not an allowlist, so it doesn't need to enumerate every valid OS caption string.

Response shape:

```json
{
  "updates": [
    {
      "computerName": "PC-042",
      "domain": "corp.local",
      "clientVersion": "0.14.0",
      "availableVersion": "0.15.1",
      "collectedAt": "2026-07-17T09:00:00Z",
      "eligible": true
    }
  ],
  "eligibleCount": 12,
  "blockedCount": 3
}
```

`eligibleCount` is what the sidebar badge shows (see UI section) - it deliberately excludes `blockedCount` so the badge only counts things a single click can actually fix.

## Credential Storage

Two new optional `server-config.json` keys, following the exact pattern already established for AD sync credentials:

- `ClientUpdateUsername` (plaintext - not a secret, same treatment as `WebUsername`/`AdUsername`).
- `ClientUpdatePassword` (DPAPI-encrypted at rest - added to the existing `EncryptedConfigKeys` set in `WindowsInventoryLiteServer.cs`, so it gets the same `Protect`/`Unprotect`/migration treatment as `AdPassword`/`WebPassword`/`Token`).

Resolution order when pushing an update, matching the AD sync precedent of "prefer the service identity, explicit credentials are an opt-in fallback":

1. If the administrator typed a username/password into the push form for that specific action, use those (transient, never saved - identical to how `Client actions` already works today).
2. Otherwise, if `ClientUpdateUsername`/`ClientUpdatePassword` are configured, use those.
3. Otherwise, no credentials are sent and the existing WinRM pipeline runs under the service's own identity - which already requires the service to run under a domain account with local admin rights on targets, an existing documented prerequisite for `Client actions` (see README's WinRM section).

New endpoint: `POST /api/v1/client-updates/credentials` (mirrors `POST /api/v1/server/admin-password`'s shape) to save `ClientUpdateUsername`/`ClientUpdatePassword`. Gated by the same Basic Auth / loopback-when-unconfigured check as every other settings endpoint (`IsWebRequestAuthorized`).

## UI

New sidebar entry: `Installation > Client updates`, alongside the existing `Client actions` and `Client package`.

- **Badge**: the sidebar has no existing count-badge convention to reuse, so this introduces the first one - a small pill next to the `Client updates` label showing `eligibleCount`, styled with the dashboard's existing `--accent` token (the same color already used for the server version badge at the bottom of the sidebar). Zero hides the pill entirely, matching how `Stale >Nh` only draws attention when non-zero.
- **Table**: computer name, domain, current version, available version, last collected, and an eligibility state. Sortable, matching every other dashboard table's convention.
- Rows for ineligible (Windows 7/8/8.1) clients render with a disabled checkbox and a short inline note ("WinRM is not supported on this OS - update via GPO or locally instead"), not hidden - the admin still needs to see they're outdated, just not offered a button that won't work.
- A collapsible credentials block above the table (same collapse/expand pattern as the `Certificate` tab's history log) with `Client update username` / `Client update password` fields and a Save button, plus a note that leaving both blank uses the service's own identity.
- `Update selected` button: enabled only when at least one eligible row is checked. Calls the existing `POST /api/v1/client-install` with `action=install`, the checked computer names as `targets`, and credentials per the resolution order above. The resulting job is tracked and displayed exactly like a `Client actions`-initiated job today (existing job-status polling/log UI, unchanged).

## Testing

- C# self-tests for the outdated/eligible classification logic (pure function, no I/O): matches-either-package case, matches-neither case, missing-package case, Windows 7/8/8.1 caption blocklist matching (including common caption string variants: "Microsoft Windows 7 Professional", "Windows 8.1 Enterprise", etc.), and a Windows Server / Windows 10/11 caption correctly staying eligible.
- Existing Pester syntax checks cover any new/modified PowerShell (none expected - no PowerShell script changes are needed for this feature, since the existing `Install-ClientWinRM.ps1` pipeline is reused unmodified).
- Live verification (Playwright against a locally-run console-mode instance, per this project's established safe-testing pattern - never a real service install) that the new page renders, the eligibility blocklist correctly disables Windows 7/8/8.1 rows using synthetic report fixtures, and the credentials block saves/reloads correctly.

## Version

This ships as a MINOR bump per the project's versioning rule (new feature, not a bug fix).
