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
| `-KeyPath` | `-` | Path to an SSH private key, for key-based authentication. |
| `-CredentialPassword` | `-` | `SecureString` password, for password-based authentication (requires `plink.exe`/`pscp.exe` in `deploy\linux-client\`; Windows' own OpenSSH client cannot authenticate with a password non-interactively). |
| `-ExpectedHostKey` | `-` | Pinned `SHA256:...` host key fingerprint from a previous trust decision. When set, the push verifies the target presents a matching key before proceeding; when omitted, the first-ever contact with a host trusts on first use, same as the password path. |

Password-based pushes additionally require `plink.exe`/`pscp.exe` (PuTTY) in `deploy\linux-client\` - see `deploy\linux-client\NOTICE` for provenance and how to obtain them.

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
- `WebUsername` and `WebPassword`: optional Basic Auth credentials for dashboard and web API access.
- `LoginLockoutThreshold`, `LoginLockoutWindowMinutes`, `LoginLockoutDurationMinutes`: per-IP Basic Auth lockout after repeated failures. Defaults: `10` (0 disables), `15`, `15`; ranges 0-1000, 1-1440, 1-1440. Adjustable on Settings > Admin password > Login lockout.
- `UseHttps` and `CertificateThumbprint`: optional HTTPS settings. The certificate itself lives in `LocalMachine\My`, not in this file.
- `HttpsPort`: HTTPS listener port, independent of `ListenPrefix`. Default: `8443`.
- `EnableHttp`: whether the plain HTTP listener runs at all. Default: `true`.
- `HstsEnabled` and `HstsMaxAgeHours`: opt-in `Strict-Transport-Security` header on HTTPS responses. Defaults: `false`, `24` (range 1-8760). Adjustable on Settings > Server > HTTPS.
- `IngestionRejectionLogRetentionDays` and `IngestionRejectionLogMaxEntries`: retention for the log of rejected ingestion-token attempts. Defaults: `30` (range 1-3650), `5000` (range 100-100000). Adjustable on Settings > Server > Ingestion Token.
- `AdDescriptionSyncEnabled`: whether AD sync also updates each client's description field. Default mirrors `AdSyncEnabled` unless explicitly set.
- `AdUseServiceIdentity`: whether AD sync runs as the service account instead of `AdUsername`/`AdPassword`. Default: `true`.
- `AdComputerImportOUs`: newline-separated Organizational Unit DNs to search when importing computers from AD.
- `PreferredLinuxSubnet`: optional IPv4 CIDR (for example `192.168.1.0/24`) restricting which subnet Linux client targeting considers. Default: empty (no filtering).
- `LinuxDefaultIntervalHours`: default collection interval offered when installing a Linux client. Default: `6`, range 1-24.
- `LinuxDefaultStatusIntervalMinutes`: default service-status poll interval for a Linux client. Default: `30`, range 1-1440.
- `LinuxDefaultInstallPath`: default installation directory offered when installing a Linux client. Default: `/opt/windows-inventory-lite`. Must be a real subdirectory under `/opt/`, with no `.`/`..` path segment - as of v0.54.7 a value outside `/opt/` (previously accepted if it just had two path segments, e.g. `/home/svc/wil`) is rejected; re-point any such existing value under `/opt/` and reinstall affected Linux clients.

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
- `deploy/linux-client/`: PuTTY (`plink.exe`/`pscp.exe`) binaries and provenance notes for password-based SSH pushes.
- `server/dashboard/`: static dashboard files copied by the server installer.
- `docs/`: threat model, API reference, and this parameters reference.
- `examples/`: example install and one-shot commands.
- `tests/`: syntax, unit, and self-test checks.
