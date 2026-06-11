# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
