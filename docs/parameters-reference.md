# Parameters and Configuration Reference

Full parameter tables for every install/build/uninstall script, the `server-config.json` keys they map to, and the plain uninstall commands. See the main [README](../README.md) for a quick-start walkthrough; this file is the exhaustive reference.

## Collect-WindowsInventoryLite.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-OutputPath` | `-` | Path for the output JSON report file. |
| `-ServerSharePath` | `-` | UNC path to the server drop share. When provided, the report is also copied there. |
| `-SkipSoftware` | `off` | Skip collecting installed software. |

## Install-Server.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-ListenPrefix` | `http://+:8080/` | HTTP listener prefix for the server service. |
| `-DataPath` | `-` | Folder for received JSON report files. Default: `C:\ProgramData\WindowsInventoryLite\drop`. |
| `-InstallPath` | `-` | Installation folder for the server service. Default: `C:\ProgramData\WindowsInventoryLite`. |
| `-ContentPath` | `-` | Folder for dashboard HTML, CSS, and JavaScript. Default: `InstallPath\dashboard`. |
| `-ClientPackagePath` | `-` | Destination folder for the client package on the server. Default: `InstallPath\client-package`. |
| `-ClientPackageSourcePath` | `-` | Source folder to copy the client package from before installation. |
| `-ConfigPath` | `-` | Server configuration file path. Default: `InstallPath\server-config.json`. |
| `-ServerExecutablePath` | `-` | Path to the prebuilt server executable. Triggers a build if omitted. |
| `-ClientNet35ExecutablePath` | `-` | Path to the prebuilt .NET 3.5 client executable. Triggers a build if omitted; always copied into `ClientPackagePath` to keep it current. |
| `-ClientNet40ExecutablePath` | `-` | Path to the prebuilt .NET 4 client executable. Triggers a build if omitted; always copied into `ClientPackagePath` to keep it current. |
| `-ClientServerUrl` | `-` | When set, produces a complete, ready-to-deploy GPO package (both client executables, `Deploy-ClientGpo.ps1`, and a configured `Install-ClientGpo.cmd`) in `ClientPackagePath` - the URL clients report to, e.g. `https://server.domain.local/api/v1/inventory`. No derived default. |
| `-ClientIntervalHours` | `6` | Collection interval embedded in the generated `Install-ClientGpo.cmd`, when `-ClientServerUrl` is set (1-24). |
| `-PackageSharePath` | `-` | GPO package share path embedded in the generated `Install-ClientGpo.cmd`, when `-ClientServerUrl` is set. Only needed when the GPO startup script and the client files are deployed to different locations. Default: the script's own folder. |
| `-Token` | `-` | Ingestion token required in the `X-Inventory-Token` header. Optional. |
| `-WebUsername` | `-` | Basic Auth username for dashboard and web API access. Optional. |
| `-WebPassword` | `-` | Basic Auth password for dashboard and web API access. Optional. |
| `-CertificateThumbprint` | `-` | Thumbprint of a certificate already in `LocalMachine\My` to use for HTTPS. Optional. |
| `-CertificatePfxPath` | `-` | Path to a `.pfx`/`.p12` file to import into `LocalMachine\My` at install time. Optional. |
| `-CertificatePfxPassword` | `-` | Password for `-CertificatePfxPath`. Required when that parameter is used. |
| `-UseHttps` | `off` | Enable HTTPS. Implied automatically when a certificate is supplied, unless set to `-UseHttps:$false`. |
| `-HttpsPort` | `8443` | HTTPS listener port, independent of `-ListenPrefix`. Must differ from the HTTP port when both are enabled. |
| `-DisableHttp` | `off` | Disable the plain HTTP listener. Requires `-UseHttps` (or an already-configured working HTTPS setup); refused otherwise, since it would make the dashboard unreachable. |
| `-InstallLogRetentionDays` | `30` | Default retention period in days for WinRM client action logs. |
| `-OpenFirewall` | `off` | Create a Windows Firewall inbound rule for the listener port. |
| `-NoRun` | `off` | Install and configure the service without starting it. |
| `-AdSyncEnabled` | `off` | Enable AD identity - domain/credentials for `Client actions`, `Client updates`, AD Computer Import, and (by default, on a fresh install) Description sync. |
| `-AdSyncMode` | `on-report` | Description sync mode: `on-report` or `timer`. |
| `-AdSyncIntervalHours` | `24` | How often a computer's AD Description is refreshed (1-8760). |
| `-AdDomain` | `-` | AD domain to query. Defaults to the server's own domain when omitted. |
| `-AdUsername` | `-` | Explicit AD account to authenticate with, instead of the service identity. |
| `-AdPassword` | `-` | Password for `-AdUsername`. Encrypted at rest (Windows DPAPI) before being written to `server-config.json`. |
| `-DebugLogEnabled` | `off` | Write the optional debug log. |
| `-DebugLogPath` | `-` | Debug log file path. Default: `DataPath\_logs\debug.log`. |

## Install-Client.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-ServerUrl` | `-` | HTTP endpoint that receives client JSON reports. Mandatory. |
| `-ServerSharePath` | `-` | UNC path to the server drop share for direct file delivery. Optional. |
| `-Token` | `-` | Ingestion token sent in `X-Inventory-Token`. Optional. |
| `-IntervalHours` | `6` | Collection interval in hours (1-24). |
| `-SoftwareCheckIntervalHours` | `6` | How often the client polls for assigned software-distribution jobs (1-24). Separate timer from `-IntervalHours`; emitted as `--software-check-interval-hours` in the service command line. |
| `-InstallPath` | `-` | Installation folder for the client service. Default: `C:\ProgramData\WindowsInventoryLite\client-data`. |
| `-ClientExecutablePath` | `-` | Path to the prebuilt client executable. Triggers a build if omitted. |
| `-NoRun` | `off` | Install and configure the service without starting it. |

## Install-ClientWinRM.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-ComputerName` | `-` | One or more target computer names or IP addresses. Mandatory. |
| `-ServerUrl` | `-` | HTTP endpoint that receives client JSON reports. Mandatory. |
| `-Token` | `-` | Ingestion token sent in `X-Inventory-Token`. Optional. |
| `-IntervalHours` | `6` | Collection interval in hours (1-24). |
| `-PackagePath` | `-` | Local path to the GPO client package. Default: `dist\gpo-client`. |
| `-RemotePackagePath` | `C:\ProgramData\WindowsInventoryLite\WinRMDeploy` | Temporary folder on the remote host for the package. |
| `-Credential` | `-` | PSCredential for WinRM authentication. Optional. |
| `-CredentialUsername` | `-` | WinRM username as a plain string. Used if `-Credential` is not provided. |
| `-CredentialPassword` | `-` | WinRM password as a `SecureString`. Used if `-Credential` is not provided. |
| `-AddToTrustedHosts` | `off` | Add target computers to WinRM TrustedHosts before connecting. |
| `-Force` | `off` | Reinstall the client even if the version already matches. |
| `-KeepRemotePackage` | `off` | Do not delete the temporary package folder from the remote host after deployment. |

## Uninstall-Server.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-ConfigPath` | `-` | Server configuration file path to read installed paths from. Default: `C:\ProgramData\WindowsInventoryLite\server-config.json`. |
| `-RemoveData` | `off` | Also remove inventory data (`DataPath`) and the configuration file. Without this switch, both are preserved so a reinstall picks up the previous settings. Cannot be undone. |

## Uninstall-Client.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-InstallPath` | `C:\ProgramData\WindowsInventoryLite\client-data` | Installation folder to remove. Must resolve to a real subdirectory under `C:\ProgramData\WindowsInventoryLite\` (a bare top-level or `..`-traversed path is refused), and is also refused if it resolves to the server's own shared root (detected via a `server-config.json` check), to protect a server co-located on the same machine. |

## Uninstall-ClientWinRM.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-ComputerName` | `-` | One or more target computer names or IP addresses. Mandatory. |
| `-InstallPath` | `C:\ProgramData\WindowsInventoryLite\client-data` | Installation folder to remove on remote hosts. Must resolve to a real subdirectory under `C:\ProgramData\WindowsInventoryLite\` (a bare top-level or `..`-traversed path is refused), and is also refused if it resolves to the target's own shared server root. |
| `-Credential` | `-` | PSCredential for WinRM authentication. Optional. |
| `-CredentialUsername` | `-` | WinRM username as a plain string. Used if `-Credential` is not provided. |
| `-CredentialPassword` | `-` | WinRM password as a `SecureString`. Used if `-Credential` is not provided. |
| `-AddToTrustedHosts` | `off` | Add target computers to WinRM TrustedHosts before connecting. |

## New-ClientGpoPackage.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-ServerUrl` | `-` | HTTP endpoint to embed in the client startup script. Mandatory. |
| `-Token` | `-` | Ingestion token to embed in the client startup script. Optional. |
| `-IntervalHours` | `6` | Collection interval in hours to embed in the client startup script (1-24). |
| `-OutputPath` | `-` | Output folder for the package. Default: `dist\gpo-client`. |
| `-ClientNet35Path` | `-` | Path to the prebuilt .NET 3.5 client executable. Triggers a build if omitted. |
| `-ClientNet40Path` | `-` | Path to the prebuilt .NET 4 client executable. Triggers a build if omitted. |
| `-PackageSharePath` | `-` | UNC share path embedded in the `.cmd` wrapper when the executables and script live on a share separate from SYSVOL. |

## Build-Server.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-OutputPath` | `-` | Output path for the compiled server executable. Default: `build\WindowsInventoryLiteServer.exe`. |

## Build-Client.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-OutputPath` | `-` | Output path for the compiled client executable. Default: `build\WindowsInventoryLiteClient.exe`. |
| `-TargetFramework` | `Net40` | Target .NET Framework version: `Net35` or `Net40`. |

## Build-InventoryIndex.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-DropPath` | `C:\ProgramData\WindowsInventoryLite\drop` | Folder containing JSON report files from clients. |
| `-DashboardDataPath` | `C:\inetpub\WindowsInventoryLite\data` | Output folder for the generated inventory index. |

## Deploy-ClientGpo.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-ServerUrl` | `-` | HTTP endpoint that receives client JSON reports. Mandatory. |
| `-Token` | `-` | Ingestion token sent in `X-Inventory-Token`. Optional. |
| `-IntervalHours` | `6` | Collection interval in hours (1-24). |
| `-SoftwareCheckIntervalHours` | `6` | How often the client polls for assigned software-distribution jobs (1-24). Separate timer from `-IntervalHours`; emitted as `--software-check-interval-hours` in the service command line. |
| `-InstallPath` | `-` | Installation folder for the client service. Default: `C:\ProgramData\WindowsInventoryLite\client-data`. |
| `-PackageClientPath` | `-` | Path to the client executable in the package. Resolved from the script directory if omitted. |
| `-Force` | `off` | Reinstall the client even if the version already matches. |

## Build-LinuxClient.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-Version` | current release version | Version string embedded into the built binary via `-ldflags`. |
| `-OutputPath` | `-` | Output path for the compiled binary. Default: `build\wil-linux-client`. |

Requires a Go toolchain (<https://go.dev/dl/>) to rebuild from source. `Install-Server.ps1` falls back to the committed `linux-client/prebuilt/` binary on a build machine without Go.

## Install-ClientDebianSSH.ps1 / Uninstall-ClientDebianSSH.ps1

| Parameter | Default | Description |
| --------- | ------- | ----------- |
| `-ComputerName` | `-` | Target host name or IP address. Mandatory. |
| `-ServerUrl` | `-` | HTTP(S) endpoint that receives Linux client JSON reports. Mandatory (install only). |
| `-InstallPath` | `/opt/windows-inventory-lite` | Installation directory on the target host. Must be a real subdirectory under `/opt/` - a bare `/opt`, a path outside `/opt/`, or a `.`/`..` path segment is refused. |
| `-CredentialUsername` | `-` | SSH username. Mandatory. |
| `-KeyPath` | `-` | Path to an RSA, Ed25519, or ECDSA (nistp256/384/521) SSH private key (OpenSSH format), for key-based authentication. Converted internally to PuTTY's `.ppk` format before use - see below. |
| `-CredentialPassword` | `-` | `SecureString` password, for password-based authentication. |
| `-ExpectedHostKey` | `-` | Pinned `SHA256:...` host key fingerprint from a previous trust decision. When set, the push verifies the target presents a matching key before proceeding; when omitted, the first-ever contact with a host trusts on first use, same as the password path. |

Both password- and key-based pushes require `plink.exe`/`pscp.exe` (PuTTY) in `deploy\linux-client\` - see `deploy\linux-client\NOTICE` for provenance and how to obtain them. Windows' own OpenSSH client is not used by this script at all: it cannot authenticate with a password non-interactively, and separately cannot negotiate the key-exchange algorithms some modern OpenSSH servers require. Key-based authentication requires an RSA, Ed25519, or ECDSA (nistp256/384/521) key in OpenSSH format with no passphrase - other key types or a passphrase-protected key produce a clear error rather than a silent failure.

## server-config.json keys

- `ServerUrl`: HTTP endpoint that receives client JSON files.
- `IntervalHours`: client collection interval from 1 to 24 hours.
- `ListenPrefix`: server HTTP listener prefix, for example `http://+:8080/`.
- `DataPath`: server folder for received JSON files.
- `ContentPath`: server folder for dashboard HTML, CSS, and JavaScript.
- `ConfigPath`: server configuration file. Default: `C:\ProgramData\WindowsInventoryLite\server-config.json`.
- `InstallLogRetentionDays`: default retention period for WinRM client action logs. Default: `30`, range 1-3650.
- `StaleHours`: hours after which a report counts as stale. Default: `48`. Adjustable on the dashboard Settings > Server page (Inventory section).
- `Token`: optional shared token sent in `X-Inventory-Token`.
- `RequireIngestionToken`: whether the ingestion endpoints reject requests without a matching token. Default: `true` once a `Token` is configured, unless explicitly overridden.
- `PreviousToken` and `PreviousTokenExpiresUtc`: the prior ingestion token and when it stops being accepted, set automatically by a token regeneration - not admin-editable directly. See `TokenOverlapHours` below.
- `TokenOverlapHours`: how long the previous token keeps working after `POST /api/v1/server/ingestion-token/regenerate`, so an already-deployed client has a window to pick up the new one via its inventory ack before the old one stops working. Default: `24`, range 0-168 (`0` restores the old immediate-cutover behavior). Adjustable on Settings > Server > Ingestion Token.
- `WebUsername` and `WebPassword`: optional Basic Auth credentials for dashboard and web API access.
- `SessionLifetimeHours`: how long a dashboard session (`wil_session` cookie, established by signing in) stays valid, sliding on each authorized request. Default: `12`, range 1-720. Adjustable on Settings > Admin password.
- `LoginLockoutThreshold`, `LoginLockoutWindowMinutes`, `LoginLockoutDurationMinutes`: per-IP Basic Auth lockout after repeated failures. Defaults: `10` (0 disables), `15`, `15`; ranges 0-1000, 1-1440, 1-1440. Adjustable on Settings > Admin password > Login lockout.
- `UseHttps` and `CertificateThumbprint`: optional HTTPS settings. The certificate itself lives in `LocalMachine\My`, not in this file.
- `HttpsPort`: HTTPS listener port, independent of `ListenPrefix`. Default: `8443`.
- `EnableHttp`: whether the plain HTTP listener runs at all. Default: `true`.
- `HstsEnabled` and `HstsMaxAgeHours`: opt-in `Strict-Transport-Security` header on HTTPS responses. Defaults: `false`, `24` (range 1-8760). Adjustable on Settings > Server > HTTPS.
- `IngestionRejectionLogRetentionDays` and `IngestionRejectionLogMaxEntries`: retention for the log of rejected ingestion-token attempts. Defaults: `30` (range 1-3650), `5000` (range 100-100000). Adjustable on Settings > Server > Log retention.
- `SoftwareJobAttemptLogRetentionDays` and `SoftwareJobAttemptLogMaxEntries`: retention for the software job attempt-history log. Defaults: `90` (range 1-3650), `5000` (range 100-100000). Adjustable on Settings > Server > Log retention.
- `DebugLogEnabled`: whether the optional plain-text debug log is written at all. Default: `false`. Adjustable on Settings > Server > Diagnostics.
- `DebugLogPath`: debug log file path. Default: `DataPath\_logs\debug.log`.
- `DebugLogRetentionDays` and `DebugLogMaxSizeMb`: age and size caps for the debug log (oldest content dropped first, checked opportunistically on write). Defaults: `7` (range 1-3650), `10` (range 1-100). Adjustable on Settings > Server > Diagnostics.
- `AdSyncEnabled`: the "Configure AD User" gate - whether AD identity (domain/credentials) is available at all, for Windows/Linux Client actions and updates, AD Computer Import, and (by default) Description sync. Default: `false`.
- `AdSyncMode`: Description sync mode, `on-report` (refresh when a computer next reports) or `timer` (refresh every known computer on a fixed schedule). Default: `on-report`.
- `AdSyncIntervalHours`: how often a computer's AD Description is refreshed under `timer` mode. Default: `24`, range 1-8760.
- `AdDescriptionSyncEnabled`: whether AD sync also updates each client's description field. Default mirrors `AdSyncEnabled` unless explicitly set.
- `AdDomain`: AD domain to query. Defaults to the server's own domain when omitted.
- `AdUseServiceIdentity`: whether AD sync runs as the service account instead of `AdUsername`/`AdPassword`. Default: `true`.
- `AdUsername` and `AdPassword`: explicit AD account to authenticate with instead of the service identity, when `AdUseServiceIdentity` is `false`. `AdPassword` is DPAPI-encrypted at rest.
- `AdComputerImportOUs`: newline-separated Organizational Unit DNs to search when importing computers from AD.
- `ClientUpdateUsername` and `ClientUpdatePassword`: optional dedicated WinRM credential for Windows Client Auto-Update pushes, used only as a fallback when the server's own service identity can't reach update targets. `ClientUpdatePassword` is DPAPI-encrypted at rest. Configured on Settings > Windows > "Windows Client update credentials".
- `ClientUpdateScheduleMode`, `ClientUpdateScheduleOnceAtUtc`, `ClientUpdateScheduleIntervalHours`, `ClientUpdateScheduleLastRunUtc`: the Windows Client Auto-Update schedule - `off`/`once`/`interval` mode, a one-time UTC target time, a repeat interval (default `24`, range 1-8760), and the last time it actually ran. A missed `once` target is cleared rather than fired late/unannounced at the next service start. Configured on Deploy > Windows Client updates.
- `LinuxUpdateUsername`, `LinuxUpdatePassword`, `LinuxUpdateKeyPath`: stored SSH credentials for Linux Client Auto-Update pushes - a username/password pair, and/or a path to the managed private key (superseded by uploading the key directly through the dashboard - see `docs/superpowers/specs/2026-08-03-linux-ssh-key-management-design.md`). `LinuxUpdatePassword` is DPAPI-encrypted at rest.
- `LinuxUpdateAuthPriority`: which saved Linux credential ("Global" auth mode) is tried first when both a password and an SSH key are configured - `key-first` (default) or `password-first`. A credential-specific rejection (wrong password, refused key - never a host-key mismatch) automatically retries the other, per target. Adjustable on Settings > Linux.
- `LinuxUpdateScheduleMode`, `LinuxUpdateScheduleOnceAtUtc`, `LinuxUpdateScheduleIntervalHours`, `LinuxUpdateScheduleLastRunUtc`: the Linux Client Auto-Update schedule, same shape and same missed-once-target behavior as the Windows schedule above. Configured on Deploy > Linux Client updates.
- `PreferredLinuxSubnet`: optional IPv4 CIDR (for example `192.168.1.0/24`) restricting which subnet Linux client targeting considers. Default: empty (no filtering).
- `WindowsDefaultIntervalHours` and `WindowsDefaultSoftwareCheckIntervalHours`: fleet-wide default report/software-poll intervals, pushed to Windows clients in each inventory ack's `config` object so an already-deployed client picks up a changed default without a reinstall. Defaults: `6`, `6`; range 1-24 each. Adjustable on Settings > Windows > Install defaults.
- `LinuxDefaultIntervalHours`: default collection interval offered when installing a Linux client, and pushed the same way as the Windows defaults above. Default: `6`, range 1-24.
- `LinuxDefaultStatusIntervalMinutes`: default service-status poll interval for a Linux client. Default: `30`, range 1-1440.
- `LinuxDefaultInstallPath`: default installation directory offered when installing a Linux client. Default: `/opt/windows-inventory-lite`. Must be a real subdirectory under `/opt/`, with no `.`/`..` path segment - as of v0.54.7 a value outside `/opt/` (previously accepted if it just had two path segments, e.g. `/home/svc/wil`) is rejected; re-point any such existing value under `/opt/` and reinstall affected Linux clients.
- `SoftwareInstallWindowEnabled`: restricts when the Windows client may run pending Windows Update/third-party-software catalog jobs to a UTC time-of-day window, instead of running one immediately whenever found. Default: `false` (off - existing behavior unchanged unless explicitly configured). Adjustable on Settings > Windows.
- `SoftwareInstallWindowStartUtc` and `SoftwareInstallWindowEndUtc`: the window itself, `"HH:mm"` in UTC, may span midnight (e.g. `22:00`-`06:00`). Defaults: `02:00`, `04:00`.
- `SoftwareInstallWindowJitterMinutes`: how long after the window opens admission probability ramps from 0% to 100%, so a fleet checking in around the same moment doesn't converge on installing at the exact same instant. Default: `30`, range 0-1440.
- `EnableWindowsClientSelfUpdate` and `EnableLinuxClientSelfUpdate`: server-side opt-ins that make each platform's inventory ack include an `update` field whenever a reporting client's version doesn't match the currently-built package. Both default `false`. These only control whether the server *advertises* an update - the client-side `-RequireHttpsSelfUpdate`/`-RequireSignedSelfUpdate` (Windows) and `--require-https-self-update`/`--require-signed-self-update` (Linux) enforcement flags are separate, client-side, install-time settings, not server-config.json keys, and are documented under `Install-Client.ps1`/`Install-ClientDebianSSH.ps1`'s own sections and `docs/threat-model.md`.
- `ShowUsbStorageIndicator`: whether the dashboard shows the USB-storage tile/badge/CSV column at all. Default: `true`. Display-only - the client always still collects and reports USB-storage presence regardless of this setting. Adjustable on Settings > Server > Inventory.
- `SoftwareRepositoryPath`: UNC path or local directory holding the software-distribution share. Clients read installers from `<path>\windows-updates\` and `<path>\third-party-software\`; the server scans the same two subfolders for discovery candidates. Empty by default, which disables the feature. Adjustable on Software > Settings.
- `SoftwareRepositoryUsername` and `SoftwareRepositoryPassword`: optional credentials the client impersonates to read that share. `SoftwareRepositoryPassword` is DPAPI-encrypted at rest, like `WebPassword`/`Token`/`AdPassword`. Left empty, the client falls back to its own service identity. Note that the password is returned in plaintext to any client holding a valid ingestion token - see `docs/threat-model.md`.
- `SoftwareShareScanIntervalMinutes`: how often the server rescans the software share for files no catalog entry references yet. Default: `60`, range 5-1440. Adjustable on Software > Settings.

## Uninstall commands

Remove the client service and local client files:

```powershell
.\src\Uninstall-Client.ps1
```

Remove the server service and its files (inventory data and configuration are preserved unless `-RemoveData` is passed):

```powershell
.\src\Uninstall-Server.ps1
```

For remote client uninstalls, see [Uninstall-ClientWinRM.ps1](#uninstall-clientwinrmps1) above. All three uninstall scripts are also reachable from `src/Install-Wizard.ps1`'s interactive menu.

## Project layout

- `src/`: collector, build scripts, install scripts, and service source code.
- `src/client/`: standalone C# Windows Service client.
- `src/server/`: standalone C# Windows Service server and embedded dashboard.
- `linux-client/`: Go source for the Debian/Ubuntu Linux client, plus a committed prebuilt binary as a fallback for machines without a Go toolchain.
- `deploy/client/`: GPO startup deployment script and command wrapper for the Windows client.
- `deploy/linux-client/`: PuTTY (`plink.exe`/`pscp.exe`) binaries and provenance notes for password- and key-based SSH pushes.
- `server/dashboard/`: static dashboard files copied by the server installer.
- `docs/`: threat model, API reference, and this parameters reference.
- `examples/`: example install and one-shot commands.
- `tests/`: syntax, unit, and self-test checks.
