# Antivirus exclusions for client self-update

## Why this exists

When "Enable client self-update" is on (Settings > Windows / Settings > Linux, both off by default), an already-installed client that detects a newer build downloads it and applies it itself. On Windows, this means the running service creates a one-time Scheduled Task that stops the service, overwrites its own executable, and restarts it. This pattern - a process modifying its own executable and using Task Scheduler for persistence-adjacent activity - closely resembles common antivirus/EDR heuristics for self-modifying malware, independent of anything this project does wrong. This project has already hit a real false positive of the same general kind: Kaspersky flagged `Deploy-ClientGpo.ps1` as `PDM:Trojan.Win32.Generic` during a routine push.

Nothing here is a workaround for a bug - it is standard practice for any legitimate self-updating agent (browsers, endpoint management tools, and most auto-updaters all need equivalent exclusions somewhere).

## What to exclude

If you enable Windows client self-update fleet-wide, add these to your antivirus policy for machines running the client:

- **Path exclusion:** the client's install directory (default `%ProgramData%\WindowsInventoryLite\client-data` - if you customized `Install-Client.ps1`'s `-InstallPath` at install time, confirm the actual path on a target machine via Services.msc's "WindowsInventoryLiteClient" service properties, or `sc qc WindowsInventoryLiteClient`'s `BINARY_PATH_NAME`; the dashboard does not report a client's install path).
- **Scheduled Task name exclusion (if your product supports it):** `WindowsInventoryLiteClient-SelfUpdate` - this is a fixed name, always exactly this string, never a randomly-generated one, specifically so it can be whitelisted once rather than needing per-run approval.
- **Process exclusion:** `WindowsInventoryLiteClient.exe` in the install directory above.
- **File exclusion:** `wil-self-update.cmd` inside the client's install directory (same directory as `WindowsInventoryLiteClient.exe`) - the swap script the scheduled task above actually runs. Fixed name, same directory every time - not a temp file, not randomly named.

## What you do NOT need to exclude

- `schtasks.exe`/`sc.exe` themselves - these are native Windows tools used in their ordinary, documented way; excluding them entirely would be far broader than necessary and is not recommended.
- Anything for Linux clients - the Linux self-replace mechanism is a same-process atomic file swap between systemd-timer runs, not a new persistent task or service-manipulation pattern, and is far less likely to trigger this class of heuristic.

## If you'd rather not add exclusions

Leave "Enable client self-update" off (the default) and continue using the existing WinRM/SSH push instead - self-update is a supplementary path, not a replacement, and nothing else in this project depends on it being on.
