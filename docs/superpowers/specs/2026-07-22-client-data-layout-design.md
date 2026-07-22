# Client File Layout Isolation — Design

**Status:** Approved for planning (2026-07-22)

## Problem

`Install-Server.ps1` organizes its own artifacts into dedicated subfolders under `%ProgramData%\WindowsInventoryLite\` (`server-bin`, `server-data`, `server-content`, `client-package`). `Install-Client.ps1` and `Deploy-ClientGpo.ps1` have no equivalent — their `$InstallPath` default is the bare root of the same directory, so on a machine that runs both the server and a local client (the server inventorying its own host), client artifacts (`WindowsInventoryLiteClient.exe`, its local `<hostname>.json` report, `client-version.txt`) sit directly alongside `server-config.json` and the server's own subfolders, with nothing distinguishing which files belong to which role.

Two things make this worse than a cosmetic nuisance:

1. **The client executable's own internal defaults are independent of `$InstallPath`.** `ClientOptions.Parse` in `src/client/WindowsInventoryLiteClient.cs` hardcodes its local report `OutputPath` and `DebugLogger`'s default log path to `%ProgramData%\WindowsInventoryLite` directly (via `Environment.SpecialFolder.CommonApplicationData`), and neither `Install-Client.ps1` nor `Deploy-ClientGpo.ps1` currently passes `--output`/`--debug-log-path` to override that. Simply relocating where the `.exe` gets copied would not relocate where the running client actually writes its data.
2. **`Uninstall-Client.ps1` and `Uninstall-ClientWinRM.ps1` default to recursively deleting the entire bare root.** On a co-located machine, running either with default parameters (including the dashboard's own `Client actions` → Uninstall, over WinRM) deletes `server-config.json`, `server-data`, `server-bin`, and every other server subfolder along with the client. This is a real data-loss risk, not just an organizational one.

## Goals

- Client-owned files live in their own subfolder, distinguishable from server files at a glance.
- The fix covers the actual runtime output (report JSON, debug log), not just the installed binary.
- Already-installed clients migrate to the new layout automatically the next time they're installed/updated (WinRM push, GPO startup script, or local reinstall) — no separate manual step.
- Uninstalling a client can never delete server data, regardless of migration state.
- No change to server-side layout, no change to the GPO package ZIP's own internal contents, no change to `Install-Wizard.ps1` (it already passes `-InstallPath` through blank and lets the underlying scripts resolve their own default).

## New Layout

```
%ProgramData%\WindowsInventoryLite\
├── server-config.json          (unchanged)
├── server-bin\, server-data\, server-content\, client-package\   (unchanged)
└── client-data\                (new)
    ├── WindowsInventoryLiteClient.exe
    ├── client-version.txt
    ├── <hostname>.json         (local report copy, written by the running client)
    ├── _logs\debug-client.log  (only if --debug-log-enabled)
    └── Logs\gpo-deploy.log     (only for WinRM/GPO-deployed installs)
```

`client-data` was chosen over `client-runtime`/`client-bin` for symmetry with `server-data` (both hold a role's runtime state) and to stay visually distinct from the pre-existing `client-package` (a server-side deployable-package cache, not client runtime data).

## Changes

### `Install-Client.ps1` (local install)

- `$InstallPath` default changes from `Join-Path $env:ProgramData 'WindowsInventoryLite'` to `Join-Path $env:ProgramData 'WindowsInventoryLite\client-data'`.
- The constructed service command line gains `--output "<InstallPath>"` and `--debug-log-path "<InstallPath>\_logs\debug-client.log"`, so the running client's own report/debug-log defaults are overridden to the new location instead of falling back to its internal `%ProgramData%\WindowsInventoryLite` default.
- After the new service is successfully created: if the legacy path `Join-Path $env:ProgramData 'WindowsInventoryLite\WindowsInventoryLiteClient.exe'` exists and differs from the new `$servicePath`, delete it (mirrors the script's existing legacy-`WindowsLicenseInventory*`-cleanup pattern already present in the same file).

### `deploy\client\Deploy-ClientGpo.ps1` (WinRM push and GPO startup-script path — the actual production upgrade mechanism)

- Same `$InstallPath` default change as above.
- `Get-DesiredServiceCommand` gains the same `--output`/`--debug-log-path` arguments.
- `$LogPath` (the script's own `gpo-deploy.log`) changes from `Join-Path $env:ProgramData 'WindowsInventoryLite\Logs\gpo-deploy.log'` to `Join-Path $InstallPath 'Logs\gpo-deploy.log'`.
- **Migration requires no new comparison logic.** The script already computes `$desiredCommand` (from the new default path) and `$currentCommand` (the real, currently-configured `BINARY_PATH_NAME` read via `sc.exe qc`), and already sets `$needsInstall = ... -or ($currentCommand -ne $desiredCommand)`. Once the default path changes, an already-installed client's `$currentCommand` (pointing at the old bare-root `.exe` with the old argument list) stops matching `$desiredCommand` on its own, so the script's existing reinstall branch fires with zero new conditionals.
- After the new service is successfully created in that branch: delete the legacy bare-root `WindowsInventoryLiteClient.exe` and `client-version.txt` if present, same cleanup this file already does for `WindowsLicenseInventory*`.
- Old data files left at the bare root (`<hostname>.json`, `_logs\`, the old `Logs\gpo-deploy.log`) are **not** touched — they're recreated fresh at the new location on the client's next run, and deleting arbitrary data files on a live production machine is not worth the risk for a cosmetic cleanup. Documented in the CHANGELOG as safe to remove manually.

### `Uninstall-Client.ps1` / `Uninstall-ClientWinRM.ps1` (local and remote-inline uninstall)

- `$InstallPath` / `$ClientInstallPath` default changes to the same `client-data` subfolder.
- **Safety guard (closes the data-loss risk found during design):** before the existing `Remove-Item -LiteralPath $InstallPath -Recurse -Force`, check whether the resolved `$InstallPath` is the bare `%ProgramData%\WindowsInventoryLite` root itself (case-insensitive, trailing-backslash-normalized) **and** `server-config.json` exists directly inside it. If both are true, skip the recursive delete and print a warning instead (`"Skipped removing $InstallPath - it looks like the server's own directory (server-config.json present). Remove client files manually if needed."`); the service stop/delete steps run unconditionally either way. On a client-only machine (no `server-config.json` present), a bare-root `$InstallPath` still gets fully removed as today — this guard only fires when server coexistence is actually detected.
- This guard is a safety net for edge cases (an explicit `-InstallPath` override, or an uninstall run against a legacy machine that was never reinstalled after this fix ships) — the normal case, post-migration, resolves to `client-data` and behaves exactly as it does today, just scoped to the right subfolder.

### Out of scope

- `Install-ClientWinRM.ps1`'s own `$RemotePackagePath` (a self-cleaning WinRM staging directory, `WinRMDeploy`, already distinctly named and never left behind) — unrelated to this problem, untouched.
- `New-ClientGpoPackage.ps1` — builds the downloadable ZIP's contents, not an install destination; no default to change.
- `Install-Wizard.ps1` — already passes `-InstallPath` through blank, inheriting whichever default the underlying script now uses. No prompt text references a specific path.
- Any change to `server-*` subfolder layout, naming, or defaults.

## Testing

- New/updated Pester coverage in `tests/ScriptSyntax.Tests.ps1`'s existing scope (syntax stays valid) plus targeted tests for: `Install-Client.ps1`'s legacy-exe cleanup branch, `Deploy-ClientGpo.ps1`'s migration-triggers-reinstall behavior (mock `sc.exe qc` returning an old-style BinPath, assert `$needsInstall` resolves true and the desired command embeds the new path), and the uninstall safety guard (a scratch directory containing a fake `server-config.json` skips removal; one without it does not).
- Live verification (per this project's standing constraint against running real install/uninstall scripts on the dev machine) is deferred to the user's own test stand: confirm a real WinRM push against an already-installed pre-fix client migrates it to `client-data` and removes the old bare-root `.exe`, and confirm `Uninstall-Client.ps1` against a real co-located server+client machine skips the recursive delete and leaves `server-config.json` intact.

## Version

`0.21.3` → `0.22.0` (MINOR — installer layout/behavior change, not a pure bug-fix patch).
