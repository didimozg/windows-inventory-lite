# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.16.4] - 2026-07-18

### Fixed

- Service creation (`Install-Client.ps1`, `Install-Server.ps1`, and `Deploy-ClientGpo.ps1`, the script a GPO/WinRM push runs on the target) failed with `sc.exe exit code: 1639` ("invalid command line", `sc.exe` printing its own usage text instead of a specific error) on at least Windows PowerShell 4.0. Root cause, confirmed live on a real Windows 8 target: `sc.exe create`'s `binPath=` value must itself contain embedded double quotes around the executable path, and passing that as one element of a PowerShell array via `& sc.exe @Arguments` does not reliably preserve those embedded quotes in the command line `sc.exe` actually receives - some PowerShell engines corrupt it, breaking the argument apart. Verified two ways on the affected machine: the array form reproduced the exact failure in isolation (no WinRM involved), and building the same command as one string with the quotes backslash-escaped and invoking through `cmd.exe /c` succeeded. All three scripts' `create` call now goes through this `cmd.exe /c` form; every other `sc.exe` call (query/stop/delete/description/start) has no embedded quotes in its arguments and was unaffected, so those are unchanged.

## [0.16.3] - 2026-07-18

### Fixed

- `Client updates`' saved WinRM credentials (`Client update username`/`Client update password`) were stored correctly but never actually used by a push. The dashboard's password field is cleared right after a successful Save (the real value is never sent back to the browser), and `Update selected` read straight from that same now-empty field - so every push after the first Save silently ran under the server's own service identity instead of the saved account, with no error until that identity turned out to lack rights on a target ("Access denied" from WinRM, reported live against a real Windows 8 target that a manually-supplied credential could reach fine). Fixed by having the dashboard send a `useSavedCredentials` flag with the push request; the server now falls back to the saved account when both the request's username and password are blank, still letting a freshly-typed per-push override take priority, and leaving `Client actions` (which never sends the flag) completely unaffected.

## [0.16.2] - 2026-07-17

### Fixed

- Dark theme reset to light on every page reload. Root cause: the `Content-Security-Policy` header added in 0.15.1 set `script-src 'self'` with no `'unsafe-inline'` or hash, which silently blocked `index.html`'s inline theme-restore `<script>` (reads `localStorage` before `styles.css` loads, to avoid a flash of the wrong theme on load). The script never ran, so the page always fell back to the OS's `prefers-color-scheme`, ignoring the saved preference - `toggleTheme()` itself still worked and still saved to `localStorage` correctly, only the on-load restore was broken. Fixed by adding that script's exact `sha256` hash to `script-src`, allowing only this one specific, unchanging inline script rather than a blanket `'unsafe-inline'` that would have reopened the original XSS backstop the CSP was added for.

## [0.16.1] - 2026-07-17

### Changed

- `Client updates` no longer disables Windows 7/8/8.1 targets - every outdated client can now be selected for a WinRM push, since WinRM reliability on those OS versions was a client-side issue that has since been fixed. The `eligible`/`blocked` split is gone from `GET /api/v1/client-updates`, replaced by a flat `updates` list and a single `outdatedCount`.

### Fixed

- `Install-Client.ps1` and `Collect-WindowsInventoryLite.ps1` (the two client-side scripts meant to run directly on a client machine, not just build/deploy from a server) used `$PSScriptRoot`, which is unset for a top-level script under Windows PowerShell 2.0 - it only started working outside modules in PS 3.0. Both scripts declared `#requires -Version 2.0` but would fail immediately on a real PS 2.0 host. Fixed by resolving the script's own path via `$MyInvocation.MyCommand.Path` instead, which works correctly back to PS 2.0. Server-side scripts (`Install-Server.ps1`, `Install-Wizard.ps1`, `New-ClientGpoPackage.ps1`, `Build-Server.ps1`, `Build-Client.ps1`) keep using `$PSScriptRoot` unchanged - they run on the server/build machine, which this project now assumes is PowerShell 5.1+.

## [0.16.0] - 2026-07-17

### Added

- Dashboard `Client updates` tab (Installation section): shows which reporting clients are running a version other than the current client package, with a WinRM push to update selected clients. Windows 7/8/8.1 targets are listed but not selectable, since WinRM is unreliable against them. An optional dedicated WinRM credential can be saved as a fallback to the service's own identity, encrypted at rest the same way as other stored secrets.

## [0.15.1] - 2026-07-17

### Security

- Fixed a command-injection vulnerability in `Install-ClientGpo.cmd` generation (`GenerateCmdLines` in the server, mirrored in `New-ClientGpoPackage.ps1`): `serverUrl` and `packageSharePath` were written to the `.cmd` file with no surrounding quotes, and `token`'s quoting could be broken out of with an embedded `"`. A value containing `&`, `|`, `<`, `>`, `^`, `"`, or a line break turned the generated script into an attacker-controlled command that a GPO computer startup script later runs as SYSTEM on every deployed client. Both the server's `client-package/configure` endpoint and the standalone script now reject any of these characters in `serverUrl`, `token`, or `packageSharePath` before generating the file.
- The inventory ingestion token (`X-Inventory-Token`) is now compared with the project's existing constant-time comparison (`FixedTimeEquals`), matching how `WebPassword` and the admin password are already compared, instead of a plain `!=` that could leak the token byte-by-byte via response timing.
- AD lookup error messages written to the Event Log and debug log are now passed through the existing log-injection sanitizer (`SanitizeForLog`), closing the one field that bypassed it.
- While Basic Auth is unconfigured, the entire management API (dashboard, settings, certificate import, WinRM client actions, initial admin-password setup) now only accepts requests from the local machine, instead of being reachable by anyone who can reach the port. `POST /api/v1/inventory` is unaffected, since it is already gated by its own Token. Pass `-WebUsername`/`-WebPassword` to `Install-Server.ps1` at install time, or configure Basic Auth from the server console, to manage the server remotely right away.
- `server-config.json`'s restrictive ACL (Administrators + SYSTEM only) is now reapplied on every write by the server itself, not just at install time, so it cannot drift back to a broader inherited ACL if the file is ever deleted and recreated while the service is running.
- The dashboard now sends a `Content-Security-Policy` header on every response, as a backstop against a future unescaped rendering sink.

## [0.15.0] - 2026-07-17

### Added

- The dashboard now polls for new inventory data every 30 seconds and updates in place, without disturbing the current page, sort, search, or any expanded detail rows. Polling pauses while the browser tab isn't visible and catches up immediately when it becomes visible again.

### Fixed

- Expanded detail rows (Clients/Software/Hardware "show details") no longer collapse when the table re-renders for an unrelated reason (e.g. clicking the pager's Next/Prev buttons).

## [0.14.0] - 2026-07-17

### Fixed

- `Install-Client.ps1` and `Install-Server.ps1` now rebuild `build\*.exe` fresh every run when using the default (not caller-supplied) executable path, instead of only building when the file was entirely missing. A stale binary left over from an earlier session was previously reused silently, with no version-mismatch warning - found via live testing of `Install-Wizard.ps1`'s "Install client (local)" flow.
- Fixed a resulting double build of the client executables in `Install-Server.ps1`, since `Build-Server.ps1` already refreshes them as a side effect of building the server.

### Added

- `Install-Wizard.ps1`'s "Install server" flow now detects an existing installation and offers a "just refresh" option that skips all questions and reapplies the current saved settings as-is, instead of requiring every question to be re-answered on a re-run.

## [0.13.0] - 2026-07-17

### Added

- `Install-Wizard.ps1` - an interactive console menu covering all install/uninstall actions (server, local client, remote client via WinRM, and their uninstalls), for administrators unfamiliar with the project's flag-based scripts. Supports `-WhatIf` to preview the resolved command before running anything.
- `Uninstall-Server.ps1` - previously only client-side uninstall scripts existed; this adds the missing server-side counterpart. Preserves inventory data and configuration by default; `-RemoveData` opts into full removal.

## [0.12.0] - 2026-07-16

### Added

- The Clients and Software inventory tables are now paginated, with page size adapting live to the browser window's height. The Hardware CPU/Storage/RAM tables are paginated with a fixed page size.
- The Inventory summary tiles (client count, activation counts, stale count) moved to the top of the Inventory section and are more compact.
- Swapped the `Collected`/`AD Description` column order in the Clients table.

## [0.11.0] - 2026-07-16

### Added

- `WebPassword` and `Token` are now encrypted at rest with Windows DPAPI, matching `AdPassword`. Any secret still stored as plaintext from an older install is migrated to encrypted form automatically on the next service start - no manual action needed.

### Fixed

- Confirmed `CertificatePfxPassword` was never persisted to `server-config.json` in the first place (it is used once, transiently, for a PFX import) - corrected an earlier design assumption to the contrary before it shipped.

## [0.10.1] - 2026-07-16

### Fixed

- The Client Package page's grid layout broke when the "Package share path" field was added (a 4th field, but the shared `.pkg-grid` CSS was still templated for 3) - `Ingestion token` and `Interval` were squeezed into the wrong tracks and the Save/Download buttons wrapped onto their own row. Found via a live Playwright design review.
- The first fix attempt (an ID-scoped override) introduced a worse bug: it silently un-collapsed the grid on mobile, overflowing a 480px viewport, since an ID selector outranks the mobile breakpoint's plain-class collapse rule regardless of source order. Replaced with a modifier class instead, matching the existing `.general-grid`/`.admin-password-grid` pattern.

## [0.10.0] - 2026-07-16

### Added

- `Install-Server.ps1` now keeps the client package's executables current on every run, not just at first install - it builds them (via `Build-Client.ps1`, matching how `-ServerExecutablePath` already worked) if missing and always copies the current build into `ClientPackagePath`. Previously, `ClientPackagePath` was only ever populated from `-ClientPackageSourcePath` (`dist\gpo-client`), an easy-to-forget separate packaging step - a server reinstall/upgrade with no extra flags left a stale client package in place with no warning.
- `Install-Server.ps1` gains `-ClientServerUrl` (opt-in, no derived default - guessing wrong would silently ship a broken GPO package): when set, it produces a complete, ready-to-deploy GPO package (both client executables, `Deploy-ClientGpo.ps1`, and a fully configured `Install-ClientGpo.cmd`) directly in `ClientPackagePath` by calling `New-ClientGpoPackage.ps1`, instead of a separate manual packaging step or dashboard visit. New `-ClientIntervalHours` (default 6) and `-PackageSharePath` accompany it; `-Token` is reused from the server's own ingestion token.
- Moved "Package share path" up to sit directly under "Server URL" on the Client Package dashboard page - it was easy to miss below the interval field.

## [0.9.0] - 2026-07-16

Client-package deployment usability, driven by a real GPO deployment failure on the live test stand: the client wasn't installing because the GPO startup script's package share path had no dashboard-configurable equivalent, and the deployed client package could silently go stale relative to the server with no warning.

### Added

- `Build-Server.ps1` now also builds both client targets (Net35, Net40) into `build\`, so the executables `New-ClientGpoPackage.ps1` looks for by default are always current after a server build - no separate step to remember.
- Client package share path is now configurable on the Client Package dashboard page and via `POST /api/v1/client-package/configure` (`packageSharePath`) - needed whenever the GPO startup script and the client files are deployed to different locations (e.g. script in SYSVOL, files on a separate share). Previously only `New-ClientGpoPackage.ps1 -PackageSharePath` could set this, and any later dashboard-driven save silently reset it back to the script's own folder.
- The Client Package page now compares the packaged client executables' versions against the running server's version and flags a mismatch. `GET /api/v1/client-package` gains `serverVersion`, `net35VersionMismatch`, `net40VersionMismatch`.
- `POST /api/v1/client-package/download` now refuses (400, with a clear message) to produce a package before the server URL has been configured, or when no client executable is present at all - previously it would silently include whatever partial set of files existed. Downloading a package with a version-mismatched client still works, but the dashboard now asks for confirmation first.

### Fixed

- An off-by-one in the new `ParseCmdSettings` extension (parsing `PACKAGE_ROOT` back out of the generated `.cmd`) miscounted the `"set PACKAGE_ROOT="` prefix length, corrupting the round-tripped default value - caught immediately via a new self-test before it shipped.

## [0.8.2] - 2026-07-16

Whole-branch review pass (security + code quality) covering everything added for AD Description Sync, including the live-stand follow-ups. No Critical or Important findings in security or concurrency; documentation and build-script findings fixed below.

### Fixed

- `Build-Server.ps1`/`Build-Client.ps1` did not check `csc.exe`'s exit code, so a failed compile could print "Server/Client executable: ..." and leave a stale binary in place without any visible error - this is what led to an earlier false-positive "server does not compile" review finding, and would have hidden a real one just as easily. Both scripts now throw on a nonzero exit code.
- `docs/threat-model.md` and `README_RU.md` still said the AD password is stored in plaintext; it has been DPAPI-encrypted since 0.8.0. Corrected both.
- `Install-Server.ps1` gained `-DebugLogEnabled`/`-DebugLogPath` parameters - the debug log feature existed on the server exe and in `server-config.json` since 0.8.0 but was never exposed as an install-time parameter, unlike every other setting in this project.
- Added the AD sync and debug-log parameters to the `Install-Server.ps1` table in both READMEs, and added a Diagnostics section describing the debug log to both READMEs (was previously undocumented outside the CHANGELOG).
- A stale code comment in `AdLookupService.cs` still referenced `InventoryServer.ApplyAdSync`, a method split into `ComputeAdSyncFields`/`ApplyAdSyncFields` earlier in this branch.
- The AD username is now sanitized (CRLF-escaped) before being written into a log line, matching the computer name right next to it.

## [0.8.1] - 2026-07-16

### Fixed

- Timer-mode AD sync's background sweep did not run for a full `AdSyncIntervalHours` (24h by default) after being enabled or reconfigured - its due time was set to the interval itself instead of firing almost immediately, making timer mode look completely inert for the first day of use. The sweep now starts right after enabling/reconfiguring; each computer's own AD data still only refreshes on its own schedule.

## [0.8.0] - 2026-07-16

Live-stand follow-up to 0.7.0's AD Description sync, driven by testing against a real Active Directory environment.

### Added

- Optional debug log file on both server and client (`--debug-log-enabled` / `DebugLogEnabled`, off by default), writing plain-text lines for AD lookups, client-server report traffic, and unhandled errors - independent of the Windows Event Log, which depends on this machine already having (or being able to auto-register) the relevant event source.
- AD password is now encrypted at rest in `server-config.json` (Windows DPAPI, `LocalMachine` scope) instead of stored in plaintext, both when saved from the dashboard and when set at install time (`Install-Server.ps1 -AdPassword`).

### Fixed

- Client never negotiated TLS 1.2 explicitly; on older .NET Framework/Windows defaults this could leave the HTTPS handshake unable to complete against a server that only accepts TLS 1.2, while plain HTTP kept working - masking the real cause behind what looked like a routing/config problem.
- A computer stuck on "AD unreachable" after a transient AD outage no longer waits out the full sync interval before retrying - the sync timestamp is no longer advanced on a failed lookup.
- The AD/LDAP lookup no longer runs inside the lock that serializes inventory-report writes, so a slow or unreachable AD can no longer delay ingestion for the rest of the fleet.
- `AdSyncIntervalHours` now enforces the same 1-8760 range on the CLI/config-file path that the settings API already enforced.
- A CSS specificity bug hid the AD credential fields incorrectly in some cases; `.hidden` now reliably wins over more specific component rules.
- Client-supplied computer names are now escaped before being written into Event Log or debug-log lines, closing a log-forging gap.

## [0.7.0] - 2026-07-15

### Added

- Active Directory Description sync for the Clients table - optional, off by default. When enabled, the server looks up each reporting computer's AD `description` attribute and shows it as a read-only column; the dashboard never writes back to AD.
- Two sync modes: **on inventory report** (default - refreshes a computer's cached AD data when it next reports, if the cached value is older than the configured sync interval) and **periodic timer** (refreshes every known computer on a fixed schedule, including ones that have stopped reporting).
- AD authentication defaults to the server's own Windows Service identity; explicit credentials (username/password, stored in `server-config.json` like `WebPassword`) can be used instead, toggled via "Use service account identity" in Settings > General or `-AdSyncEnabled`/`-AdUseServiceAccount` at install time (`Install-Server.ps1`).
- New `Description` column on the Clients table and in its CSV export, showing "Not found in AD" or "AD unreachable" when a lookup can't resolve.
- `AdLookupService` escapes client-reported computer names per RFC 4515 before building LDAP filters, closing off LDAP injection from a client-controlled value.

## [0.6.1] - 2026-07-15

Follow-up review of 0.6.0's new code and comments.

### Fixed

- The checkmark SVG markup for the on/off status dot was duplicated verbatim in two functions (`activationBadge`, `setStatusDot`). Extracted to a shared `CHECK_DOT_SVG` constant.
- The Connection status panel's dots (`setStatusDot`) had no accessible treatment at all - unlike the Clients table's activation dots, which are the only content in their cell and get `role="img"`/`aria-label`, these sit next to text that already states the same thing ("HTTP" + "Port 8080"/"Disabled"), so they're decorative rather than the only source of the information. Marked them `aria-hidden="true"` instead of leaving them unlabeled.
- A comment above `.status-dot` in styles.css still said "Windows/Office activation indicator in the Clients table" after the same class was reused for the Connection status panel. Updated to describe both.

### Verified, not changed

- Checked whether the two `.dashboard-card` elements on the Dashboard page (Software/Hardware) have a real gap between them, since a screenshot looked like they might - confirmed via computed styles that they sit flush with zero margin on both sides, which is intentional (the flat design spec calls for elements separated by borders/color, not shadows or gaps everywhere), not an accidental missing-spacing bug.

Version 0.6.0 -> 0.6.1.

Design pass based on a live review of the running dashboard (seeded with sample data and inspected via Playwright).

### Added

- Every count and measurement on the dashboard (stat tiles, bar-chart values, Hardware table cores/clock/size/machine counts) now renders in the same monospace/tabular-figure family as IP addresses and version strings, instead of just the three original spots. The whole dashboard reads as one consistent instrument panel for machine facts rather than mixing number styles.
- The "Stale >Nh" tile gets a distinct amber treatment (reusing the existing USB-badge amber, no new color) whenever it's non-zero - it's the one tile that calls for action; the others are neutral counts.
- Settings > General gained a "Connection status" panel showing live HTTP/HTTPS reachability and certificate validity at a glance, reusing data the settings endpoint already returns. Previously the page left a large empty area below the form with no summary of current state anywhere in the UI.
- Windows/Office activation in the Clients table is now a compact checkmark-dot indicator (reusing the same mark as the project logo) instead of "Activated"/"Not detected" text, which wrapped onto a second line at normal column widths and broke row rhythm.
- The sidebar's section list has a subtle dotted divider between groups, echoing the connector lines in the project's own logo (an org-chart of nodes) instead of a plain gap.

### Changed

- Dropped the always-visible "Computers" comma-list column from the Hardware (CPU/Storage/RAM) and Software tables - it duplicated the same computer list already available one click away (clicking the model/name link expands a details row with the full list), and became an unreadable wall of text once more than a handful of machines shared a value.
- "Delete" buttons for routine, frequent, reversible-ish actions (removing a host record, a license entry, a certificate-history log line) are now a quiet outlined style, red only on hover. The solid red fill is reserved for the one genuinely consequential delete in the app - removing the installed certificate, which can turn HTTPS off.

## [0.5.0] - 2026-07-14

This entry consolidates everything built in this release cycle — dual HTTP/HTTPS listeners, a security and code-quality review, a dark theme, a project icon, and dashboard design-token/typography work — into one version instead of the string of point releases (0.5.1 through 0.10.0) it actually shipped as internally. Only the net result is documented below.

### Added

- New Dashboard "Software" card: the Licenses tile (moved out of the top count row) plus a "Top software" bar chart — the 5 most commonly installed titles across the fleet, counted by distinct computer regardless of which version is installed.
- HTTP and HTTPS now run as two independent listeners on two independent ports instead of one listener that switches protocol. Default HTTP port is `8080` (`-ListenPrefix`, unchanged), default HTTPS port is `8443` (new `-HttpsPort`). Both can run together, HTTPS-only, or HTTP-only.
- HTTP can be disabled entirely once HTTPS is confirmed working, from Settings > General or `Install-Server.ps1 -DisableHttp`. The server refuses the change unless HTTPS is genuinely active at that moment, so the settings page can never turn off both listeners and lock the dashboard out. Recovery procedure for a certificate that later breaks after HTTP was disabled is documented in the README's [Recovering from an HTTPS lockout](./README.md#recovering-from-an-https-lockout) section.
- Settings > General can now change the HTTP port directly from the dashboard (previously only available via `-ListenPrefix` at install time, and previously did not survive a plain service restart - see Fixed).
- Settings > General reorganized into three blocks: Inventory (stale threshold), Network (HTTP port, Enable HTTP), HTTPS (HTTPS port, Enable HTTPS).
- The Dashboard's Hardware and Software cards draw a visible border/background around each mini-chart (CPU models, RAM, Storage type, Top software), so it's clear at a glance which values belong to which chart.
- Dark theme for the dashboard. Follows the OS color scheme by default (`prefers-color-scheme`), with a manual toggle button next to the sidebar brand that overrides it and remembers the choice per browser (`localStorage`). An inline head script applies a saved preference before `styles.css` loads, so there's no flash of the wrong theme on first paint. All dashboard colors are theme-aware CSS custom properties: light background `#f8f9fa`, graphite body text `#2d3748`, borders `#e2e8f0`; dark background `#111827`, panels `#1f2937`, body text `#e2e8f0`, headings pinned to white, accent teal `#126f8f` in light / `#1c93bc` in dark.
- Body font stack leads with `Inter`/`Roboto` before falling back to `Segoe UI` (the fonts only apply if already installed locally - the dashboard still ships with no web-font/CDN dependency, so it keeps working on isolated networks). IP addresses, OS version/build strings, and certificate thumbprints render in a monospace stack (`JetBrains Mono` falling back to `Consolas`), matching the dashboard's existing use of Consolas for install-job output.
- A project icon and logo: a monitor containing a small org-chart/tree of connected nodes and a checkmark hub, in the app's accent teal. Used as the dashboard's browser-tab favicon (`server/dashboard/favicon.svg`), inlined with its full wordmark ("Windows Inventory" / "Lite") in the dashboard sidebar header - theme-aware, following the same CSS variables as the rest of the UI, so it stays correct through both OS dark mode and the manual toggle - and as the logo at the top of `README.md`/`README_RU.md` (`docs/images/logo.svg`). Every sidebar navigation item also has a matching flat line icon (dashboard grid, monitor, package, chip, document, bolt, archive box, gear, shield, lock).
- Built-in `--self-test` mode coverage extended: Windows reserved device names, constant-time comparison, and `ListenPrefix` port parsing.

### Changed

- Dashboard RAM chart now buckets at the sizes actually seen in the field (4/8/16 GB, with everything above lumped into one "32 GB+") instead of generic ranges.
- Dashboard Storage chart shows only SSD and HDD; disks with no recognizable type are left out instead of appearing as a third "Unknown" bar.
- The one dashboard nav tab with a verb-phrase name ("Change admin password") is now "Admin password", matching the noun-phrase, sentence-case style already used by every other tab. The sidebar's top-level section labels also previously mixed two different type styles (standalone entries at 14px sentence case, group headers at 11px uppercase letter-spaced); group headers now share the same 14px/sentence-case typography, keeping only a muted color as the visual cue that they aren't clickable.

### Fixed

- **CSV export (Clients, Software, Hardware, Licenses) was vulnerable to formula/DDE injection.** Exported fields include client-reported and free-text values (computer names, software titles, license comments); a value starting with `=`, `+`, `-`, or `@` is treated as a formula by Excel/Sheets when the file is opened (CWE-1236). Cells are now prefixed with a leading single quote when this applies, the standard mitigation - the visible value is unchanged, but it can no longer be parsed as a formula.
- `POST /api/v1/inventory` with a malformed JSON body returned a generic 500 instead of the 400 every other endpoint returns for the same problem. Now consistent.
- The client service's collection-failure catch block claimed "Windows Event Log contains the service failure envelope," but the block was empty - nothing was ever actually logged, so a persistently-failing agent reported nothing and left no trace anywhere. Now writes a real Warning entry to the Event Log, matching what the comment always claimed.
- Report filenames derived from a client-reported computer name could collide with a Windows reserved device name (`CON`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`) - reserved regardless of extension, so `CON.json` is just as blocked as `CON`. A computer reporting one of these names would have made every write to its own report file fail. `SanitizeFileName` now prefixes an underscore when the sanitized name (up to the first `.`) matches one, breaking the collision.
- Basic Auth credential comparison used `==`/`String.Equals`, which fails fast at the first mismatched byte - a timing side-channel that leaks how many leading characters of a guess were correct (CWE-208). Replaced with a constant-time comparison that always walks the full length of both inputs, applied to both the login check and the "current password" check when rotating the admin password. Both comparisons (username and password) are evaluated unconditionally rather than short-circuited, so the password check's timing can't leak whether the username alone was right.
- WinRM install/uninstall credentials no longer travel through the spawned `powershell.exe`'s command line. They're written to the child process's stdin instead and read there into a `PSCredential`, using the `-Credential` parameter `Install-ClientWinRM.ps1`/`Uninstall-ClientWinRM.ps1` already supported. Verified end-to-end against a stub WinRM script: the credential round-trips correctly, and a live process listing during the job confirmed no process command line contains the password anymore.
- The HTTP listener port previously only took effect through the `--prefix` argument baked into the Windows Service's own start command at install time; changing it from the dashboard worked until the next plain service restart or reboot, which silently reverted to the old port. Port is now always re-read from `server-config.json` at service startup, matching how every other dashboard-configurable setting already behaved.
- `Install-Server.ps1 -OpenFirewall` always opened port 8080 regardless of the actual configured HTTP port. Now opens a firewall rule for the real HTTP port, plus a separate rule for the HTTPS port when `-UseHttps` is set.
- **Found in a follow-up review of the dual-listener work above.** `POST /api/v1/server/settings` applied an HTTP-disable before attempting an HTTPS-enable in the same request. The dashboard's General Settings form always submits both fields together, so "turn HTTPS on and turn HTTP off" in one Save click would stop the (working) HTTP listener first; if the HTTPS bind then failed for any reason (port conflict, permission), the server was left with neither listener running until a service restart - precisely the outcome the endpoint's own safety check exists to prevent, just reached through a failed bind instead of a rejected request. HTTPS is now applied first, so a failed HTTPS bind leaves HTTP untouched.
- `Install-Server.ps1 -DisableHttp` only warned, and did not block, if the certificate backing an already-configured `-UseHttps` (reloaded from `server-config.json`, not supplied on that run) was no longer present in `LocalMachine\My` - deleted by something outside this tool between runs. A reinstall or update in that state would proceed with HTTP off and HTTPS unable to start, unreachable from the very first start. Now throws instead of warning when `-DisableHttp` is combined with a `-UseHttps` setup whose certificate can't actually be found in the store.

### Breaking

- Existing installs with HTTPS already enabled were serving it on the same port as HTTP. After upgrading, HTTPS moves to its own port (default `8443`) on the next service restart. Reconfigure firewall rules and any bookmarked `https://` URLs to use the new port, or set `-HttpsPort` to the old port explicitly during the next `Install-Server.ps1` run to keep it unchanged.

## [0.4.0] - 2026-07-13

Project versioning is now unified: client and server report the same project version instead of drifting independently (client was stuck at 0.1.0 while the server moved ahead).

This entry consolidates everything built in this release cycle — dashboard navigation, licenses, HTTPS/certificate management, and the new Dashboard overview page — into one version instead of the string of point releases (0.4.1 through 0.9.0) it actually shipped as internally. Only the net result is documented below.

### Added

- New `Dashboard` landing page (opens by default when the URL has no `#hash`; existing links like `#clients` still work): tile counts for Clients, Windows activated, Office activated, Stale, and Licenses, plus a separate Hardware card with computers-with-USB-storage and bar-chart breakdowns of the top CPU models, RAM size buckets, and storage type (SSD/HDD) across the fleet — plain CSS bars, no charting library.
- Dashboard navigation is now a vertical tree sidebar (Dashboard, Inventory: Clients/Software/Hardware, Licenses, Installation: Client actions/Client package, Settings: General/Certificate/Change admin password) instead of a horizontal tab bar, and stays pinned in place while the page content scrolls.
- Licenses can be linked to specific computers: a chip-style list on the license form supports manual entry, and selecting a Name that matches installed software auto-adds the computers that have it. The licenses table has a Computers column with an expandable list.
- The Software table has a License column linking to the matching license record when one already exists for that software name (one license commonly covers several installed versions, so the match is by name only, not name and version).
- Settings > General page: configurable stale threshold (`StaleHours`, default 48, was hardcoded) and the HTTPS on/off switch, via `GET/POST /api/v1/server/settings`.
- Certificate risk evaluation (`EvaluateCertificateRisks`): flags expired/not-yet-valid certificates, missing private key, missing Subject Alternative Name, and RSA keys under 2048 bits. Enabling HTTPS with a risky certificate returns `409` with the risk list unless the request acknowledges them (`acknowledgeRisks: true`).
- Certificate history log (`GET /api/v1/server/certificate/history`) recording every upload with its risks at the time, shown as a table on the Certificate page. `DELETE /api/v1/server/certificate/history/{id}` removes a single entry.
- `DELETE /api/v1/server/certificate` and a "Delete installed certificate" button remove the configured certificate from `LocalMachine\My`. If HTTPS was using it, HTTPS is turned off in the same action.
- Settings `Change admin password` page and `POST /api/v1/server/admin-password` endpoint. Doubles as first-time Basic Auth setup (no current password required while none is configured yet — the rest of the dashboard is equally open in that state); rotating an existing password still requires the current one. `GET /api/v1/server/admin-password` reports whether Basic Auth is configured yet, so the page can disable itself instead of failing on submit.

### Changed

- Certificate upload no longer enables HTTPS by itself. `POST /api/v1/server/certificate` only imports the PFX and records it as the configured certificate; turning HTTPS on or off is exclusively a Settings > General action, gated by the risk check above.
- Licenses table: clicking the Name expands the linked computers; Edit and Delete are separate, distinctly colored columns. Empty Version/License/Comment fields render as blank cells instead of "Unknown".
- The summary count cards, the search/filter box, and the "Generated: ..." inventory timestamp now show only on Clients, Software, and Hardware, where they're meaningful — not on Licenses, Client actions, Client package, or Settings. The timestamp and the server version badge both live in the sidebar footer now.
- Settings > General is split into separate blocks (Inventory, HTTPS) instead of one mixed grid.
- License form field widths rebalanced (Name/Version narrower, License wider, Comment adjusted) so license keys stop getting clipped.

### Fixed

- Installed-software `installDate` was collected as the raw Uninstall registry value (`YYYYMMDD`, e.g. `20260527`) instead of a readable date, in the compiled client and `Collect-WindowsInventoryLite.ps1`. Now reformatted to `dd.MM.yyyy`. The dashboard also reformats it defensively at render time, so hosts still running an older, not-yet-rebuilt client display correctly too instead of waiting for a fleet-wide redeploy.
- TLS handshake used `SslProtocols.None`, which some .NET Framework builds treat as "no protocols enabled" instead of "negotiate the best available" and reject with `ArgumentException` before any handshake data is exchanged — very likely why HTTPS refused every connection after a certificate was applied. Replaced with an explicit `SslProtocols.Tls12`.
- Connections (plain HTTP and HTTPS alike) had no read/write timeout, so a stalled handshake or a client that opens a socket and never sends anything could tie up a ThreadPool thread indefinitely. Added a 30-second socket timeout.
- `Install-Server.ps1` re-enabled HTTPS on every re-run once a certificate had ever been imported, even after HTTPS had since been turned off from Settings > General — it reloaded the saved certificate thumbprint and treated that reload as if a certificate had just been freshly supplied. Now only auto-implies `UseHttps` when a certificate is actually supplied on that specific run.
- `Install-Server.ps1` silently reset dashboard-only settings (`StaleHours`) to their defaults on every reinstall, since it wrote a brand-new config object containing only the fields it explicitly knew about. It now starts from whatever is already on disk and only overlays the fields it explicitly manages, so settings it doesn't know about survive a reinstall.
- Uploading a certificate while HTTPS was already active hot-swapped the live TLS certificate immediately with no risk check, unlike enabling HTTPS from Settings > General. The live listener now keeps serving its current certificate until the operator explicitly switches to a risky one from Settings > General; a risk-free upload still hot-swaps immediately.
- Deleting a license record didn't refresh the Software table, so its License button could keep pointing at a record that no longer existed until the next navigation.

## [0.3.0] - 2026-07-13

### Added

- HTTPS support: the server wraps accepted connections in `SslStream`, resolving the certificate from the `LocalMachine\My` store by thumbprint. `Install-Server.ps1` gained `-CertificateThumbprint`, `-CertificatePfxPath`, `-CertificatePfxPassword`, and `-UseHttps` to bind a certificate at install time. The new dashboard `Certificate` tab can import a PFX and switch the listener to it (or back to plain HTTP) without a service restart, through `GET/POST/DELETE /api/v1/server/certificate`.
- License inventory: a new dashboard `Licenses` tab manages a manually entered catalog (Name, Version, License, Comment) stored as `licenses.json` under the server data path, separate from the collected software inventory. Name and Version fields offer suggestions from already-seen installed software but accept free text. Backed by `GET/POST/PUT/DELETE /api/v1/licenses`.
- Built-in `--self-test` mode on the server executable that checks the hand-rolled HTTP header parser, WinRM target/IP-range expansion, ZIP archive builder, certificate thumbprint normalization, and license id parsing without adding a NuGet test framework. Covered by `tests/SelfTest.Tests.ps1` in CI.

### Changed

- `Install-Server.ps1`, `Install-Client.ps1`, and `Deploy-ClientGpo.ps1` now quote and escape every value placed in the `sc.exe binPath=` command line, closing a service command-line injection path through `ServerUrl`, `Token`, or paths containing quotes or spaces.
- `Install-Server.ps1` restricts `server-config.json` to Administrators and SYSTEM after writing it, since the file stores `WebPassword` and `Token` in plain text.
- `.env.example` variables renamed from the old `WINDOWS_SOFT_INVENTORY_*` prefix to `WINDOWS_INVENTORY_LITE_*` to match the project name.
- CI now runs every Pester test under `tests/` instead of only `ScriptSyntax.Tests.ps1`.

### Fixed

- `Install-Server.ps1` restricted `server-config.json`'s ACL using the literal account names `Administrators` and `SYSTEM`, which only resolve on English-locale Windows. On localized installs this threw `IdentityNotMappedException` from `AddAccessRule` and aborted the install. Now resolves both groups by well-known SID, which works regardless of the OS display language.

## [0.2.0] - 2026-06-11

### Added

- Client package tab in the dashboard. Shows package status (client exe versions, current CMD settings), lets you configure server URL, ingestion token, and reporting interval, and downloads the GPO package as a ZIP.
- `GET /api/v1/client-package` endpoint returns current package status as JSON: detected client exe versions and parsed CMD settings.
- `POST /api/v1/client-package/configure` endpoint writes `Install-ClientGpo.cmd` with the submitted server URL, token, and interval. Copies `Deploy-ClientGpo.ps1` into the package directory from the server install path if present.
- `GET /api/v1/client-package/download` endpoint streams the GPO package as a ZIP archive (`WindowsInventoryLiteGpoPackage.zip`). ZIP is built in-process using uncompressed PKZIP format without requiring .NET 4.5.
- `Install-Server.ps1` now copies `Deploy-ClientGpo.ps1` from the project `deploy/client/` directory into the server install path so the configure endpoint can include it in downloaded packages.

## [0.1.0] - 2026-06-11

Initial public release as Windows Inventory Lite. Previously an internal tool.

### Added

- Windows Inventory Lite client service. Runs on Windows 7, 8, 10, and 11. Collects OS details, Office version, activation facts, installed software, hardware specs (CPU, RAM, storage), USB storage presence, and the installed client version. Requires .NET 3.5 or later.
- Windows Inventory Lite server service. Receives client reports over HTTP, stores each report as a JSON file, and serves a built-in web dashboard. No IIS, SQL Server, or Node.js required. Requires .NET 3.5 or later.
- Web dashboard with four views: Clients, Software, Hardware, and Client actions. All views support column sorting and CSV export.
- Hardware view groups machines by CPU model, storage device, and RAM configuration.
- Client actions view runs install, update, and uninstall jobs through WinRM on a single host, a list, or an IPv4 range.
- Optional Basic Auth for the dashboard and web API.
- Optional shared ingestion token to restrict report submission.
- GPO deployment package with separate .NET 3.5 and .NET 4 client builds. The deploy script compares installed and packaged versions and skips up-to-date clients.
- Server and client installation scripts compatible with PowerShell 2.0 and later.
- Service command-line construction does not wrap paths without spaces in quotes, fixing service registration failure (sc.exe exit code 1639) on Windows 7 with PowerShell 2.0.
- Dashboard credentials and shared token stored in the server config file, not in the Windows Service `ImagePath` registry key.
- Request body limited to 16 MB and headers limited to 64 KB to bound memory use under load.
