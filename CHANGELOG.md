# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.10.0] - 2026-07-14

### Changed

- The sidebar brand now uses the real project logo with its wordmark ("Windows Inventory" + "Lite") instead of a small icon next to a plain text heading. It's inlined directly in the page (not loaded as an external image) so its colors can follow the existing `--heading`/`--accent`/`--accent-text` theme variables and stay correct through both OS-based dark mode and the manual light/dark toggle - an external SVG image can only see the OS preference, not the app's own override.
- `docs/images/logo.svg` (the README logo) now includes the same wordmark, stacked under the icon, matching the artwork provided by the project owner.

## [0.9.0] - 2026-07-14

### Added

- The project icon now appears inside the dashboard itself, not just the browser tab and README: a small brand mark sits next to the "Windows Inventory Lite" title in the sidebar header.
- Every sidebar navigation item has a matching flat line icon (inline SVG, `currentColor` stroke so it follows the existing muted/active/hover text color automatically in both themes) - a dashboard grid, monitor, package, chip, document, bolt, archive box, gear, shield, and lock for Dashboard, Clients, Software, Hardware, Licenses, Client actions, Client package, General, Certificate, and Admin password respectively.

Deliberately not carried over from the reference mockup: an avatar/notifications/calendar cluster in the top bar and sparkline trend charts inside the summary tiles. Neither corresponds to a real feature of this app (no user accounts beyond one shared Basic Auth login, no notification system, no historical time-series data collection), and adding them would just be decoration with nothing behind it.

## [0.8.0] - 2026-07-14

### Changed

- Adopted a formal design-token spec for the dashboard, in both themes: light background `#f8f9fa`, graphite body text `#2d3748`, borders `#e2e8f0`; dark background `#111827`, panels `#1f2937`, body text `#e2e8f0`, headings pinned to white. The accent teal (`#126f8f`) is unchanged in light theme and slightly brightened in dark theme (`#1c93bc`) for contrast, consistent with the existing dark-theme approach.
- Body font stack now leads with `Inter`/`Roboto` before falling back to `Segoe UI` (the fonts only apply if already installed locally - the dashboard still ships with no web-font/CDN dependency, so it keeps working on isolated networks).
- IP addresses, OS version/build strings, and certificate thumbprints now render in a monospace stack (`JetBrains Mono` falling back to `Consolas`), matching the rest of the dashboard's existing use of Consolas for install-job output.

## [0.7.1] - 2026-07-14

### Changed

- Replaced the README logo (`docs/images/logo.svg`) with a fuller mark: a monitor containing a small org-chart/tree of connected nodes and a checkmark hub, representing the inventory-collection concept more directly than the earlier plain checkmark-monitor glyph. The dashboard favicon keeps the simpler glyph, since the richer version doesn't read at 16px in a browser tab.

## [0.7.0] - 2026-07-14

### Added

- Dark theme for the dashboard. Follows the OS color scheme by default (`prefers-color-scheme`), with a manual toggle button next to the sidebar title that overrides it and remembers the choice per browser (`localStorage`). An inline head script applies a saved preference before `styles.css` loads, so there's no flash of the wrong theme on first paint.
- All dashboard colors (nav highlights, table headers, status badges, USB markers, success/error messages, chip backgrounds) are now theme-aware CSS custom properties instead of hardcoded hex values, so both themes stay in sync as the UI evolves.

## [0.6.1] - 2026-07-14

### Added

- A project icon: a teal monitor-with-checkmark mark matching the dashboard's own accent color. Added as the dashboard's browser-tab favicon (`server/dashboard/favicon.svg`, served at `/favicon.svg`) and as a logo at the top of `README.md`/`README_RU.md` (`docs/images/logo.svg`).

### Changed

- The sidebar's top-level section labels (Dashboard, Inventory, Licenses, Installation, Settings) previously mixed two different type styles: standalone entries (Dashboard, Licenses) were 14px, sentence case, while group headers (Inventory, Installation, Settings) were 11px, uppercase, letter-spaced. Group headers now share the same 14px/sentence-case typography as the standalone entries; they keep a muted color as the only remaining visual cue that they aren't clickable.

## [0.6.0] - 2026-07-14

### Added

- HTTP and HTTPS now run as two independent listeners on two independent ports instead of one listener that switches protocol. Default HTTP port is `8080` (`-ListenPrefix`, unchanged), default HTTPS port is `8443` (new `-HttpsPort`). Both can run together, HTTPS-only, or HTTP-only.
- HTTP can be disabled entirely once HTTPS is confirmed working, from Settings > General or `Install-Server.ps1 -DisableHttp`. The server refuses the change unless HTTPS is genuinely active at that moment, so the settings page can never turn off both listeners and lock the dashboard out. Recovery procedure for a certificate that later breaks after HTTP was disabled is documented in the README's [Recovering from an HTTPS lockout](./README.md#recovering-from-an-https-lockout) section.
- Settings > General can now change the HTTP port directly from the dashboard (previously only available via `-ListenPrefix` at install time, and previously did not survive a plain service restart - see Fixed).
- Settings > General reorganized into three blocks: Inventory (stale threshold), Network (HTTP port, Enable HTTP), HTTPS (HTTPS port, Enable HTTPS).
- The Dashboard's Hardware and Software cards now draw a visible border/background around each mini-chart (CPU models, RAM, Storage type, Top software), so it's clear at a glance which values belong to which chart.

### Changed

- The one dashboard nav tab with a verb-phrase name ("Change admin password") is now "Admin password", matching the noun-phrase, sentence-case style already used by every other tab.

### Fixed

- The HTTP listener port previously only took effect through the `--prefix` argument baked into the Windows Service's own start command at install time; changing it from the dashboard worked until the next plain service restart or reboot, which silently reverted to the old port. Port is now always re-read from `server-config.json` at service startup, matching how every other dashboard-configurable setting already behaved.
- `Install-Server.ps1 -OpenFirewall` always opened port 8080 regardless of the actual configured HTTP port. Now opens a firewall rule for the real HTTP port, plus a separate rule for the HTTPS port when `-UseHttps` is set.

### Breaking

- Existing installs with HTTPS already enabled were serving it on the same port as HTTP. After upgrading, HTTPS moves to its own port (default `8443`) on the next service restart. Reconfigure firewall rules and any bookmarked `https://` URLs to use the new port, or set `-HttpsPort` to the old port explicitly during the next `Install-Server.ps1` run to keep it unchanged.

## [0.5.2] - 2026-07-14

Closes out the three items left documented-but-not-fixed in 0.5.1's review.

### Fixed

- Report filenames derived from a client-reported computer name could collide with a Windows reserved device name (`CON`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`) - reserved regardless of extension, so `CON.json` is just as blocked as `CON`. A computer reporting one of these names would have made every write to its own report file fail. `SanitizeFileName` now prefixes an underscore when the sanitized name (up to the first `.`) matches one, breaking the collision.
- Basic Auth credential comparison used `==`/`String.Equals`, which fails fast at the first mismatched byte - a timing side-channel that leaks how many leading characters of a guess were correct (CWE-208). Replaced with a constant-time comparison that always walks the full length of both inputs, applied to both the login check and the "current password" check when rotating the admin password. Both comparisons (username and password) are evaluated unconditionally rather than short-circuited, so the password check's timing can't leak whether the username alone was right.
- WinRM install/uninstall credentials no longer travel through the spawned `powershell.exe`'s command line. They're written to the child process's stdin instead and read there into a `PSCredential`, using the `-Credential` parameter `Install-ClientWinRM.ps1`/`Uninstall-ClientWinRM.ps1` already supported. Verified end-to-end against a stub WinRM script: the credential round-trips correctly, and a live process listing during the job confirmed no process command line contains the password anymore.

## [0.5.1] - 2026-07-14

Found by a manual security and code-quality review of the full codebase, not by a user report.

### Fixed

- **CSV export (Clients, Software, Hardware, Licenses) was vulnerable to formula/DDE injection.** Exported fields include client-reported and free-text values (computer names, software titles, license comments); a value starting with `=`, `+`, `-`, or `@` is treated as a formula by Excel/Sheets when the file is opened (CWE-1236). Cells are now prefixed with a leading single quote when this applies, the standard mitigation - the visible value is unchanged, but it can no longer be parsed as a formula.
- `POST /api/v1/inventory` with a malformed JSON body returned a generic 500 instead of the 400 every other endpoint returns for the same problem. Now consistent.
- The client service's collection-failure catch block claimed "Windows Event Log contains the service failure envelope," but the block was empty - nothing was ever actually logged, so a persistently-failing agent reported nothing and left no trace anywhere. Now writes a real Warning entry to the Event Log, matching what the comment always claimed.

### Security

- Documented, not changed: WinRM install/uninstall credentials are passed to the spawned `powershell.exe` as command-line arguments, making them visible for the life of that process to anything on the server that can list process command lines. This requires local access to the server already, at which point `server-config.json`'s own plaintext `WebPassword` is an equally easy target - not a new privilege boundary, just another instance of the same one. A proper fix (temp credential file, named pipe, or similar) is a real redesign and out of scope for this pass.
- Reviewed and found acceptable for this use case: Basic Auth credential comparison is not constant-time, a theoretical timing side-channel over a LAN admin tool. Windows reserved device names (`CON`, `NUL`, `COM1`, ...) are not specifically rejected when deriving a report filename from a reported computer name - not a traversal risk (separators are already blocked), just a possible confusing failure for an oddly-named host.

## [0.5.0] - 2026-07-13

### Added

- New Dashboard "Software" card: the Licenses tile (moved out of the top count row) plus a "Top software" bar chart — the 5 most commonly installed titles across the fleet, counted by distinct computer regardless of which version is installed.

### Changed

- Dashboard RAM chart now buckets at the sizes actually seen in the field (4/8/16 GB, with everything above lumped into one "32 GB+") instead of generic ranges.
- Dashboard Storage chart shows only SSD and HDD; disks with no recognizable type are left out instead of appearing as a third "Unknown" bar.

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
