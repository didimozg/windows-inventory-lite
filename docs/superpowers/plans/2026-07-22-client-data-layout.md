# Client-Data Layout Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the client its own `client-data` subfolder under `%ProgramData%\WindowsInventoryLite\` (instead of the bare root it shares with the server today), have the running client actually write its report/debug log there, migrate already-installed clients automatically on their next reinstall/update, and stop the uninstall scripts from being able to recursively delete the server's own files.

**Architecture:** Four PowerShell scripts change: `deploy\client\Deploy-ClientGpo.ps1` (the real production install/update path for both WinRM push and GPO startup script), `src\Install-Client.ps1` (local install), `src\Uninstall-Client.ps1` (local uninstall), `src\Uninstall-ClientWinRM.ps1` (remote uninstall). Each gets a new default path, and the two install scripts pass `--output`/`--debug-log-path` to the client executable so its own internal defaults (independent of where it's installed) get overridden. Migration of already-installed clients falls out of `Deploy-ClientGpo.ps1`'s existing "is the running service's real command line different from the desired one" comparison - no new comparison logic needed, just a changed default. The two uninstall scripts gain a guard that refuses to recursively delete a directory that turns out to be the server's own shared root.

**Tech Stack:** Windows PowerShell 5.1 (server-side orchestration) / PowerShell 2.0-compatible (everything that runs ON a client target, including `Deploy-ClientGpo.ps1` and the remote scriptblock in `Uninstall-ClientWinRM.ps1`), Pester (tests), `sc.exe`/`cmd.exe` (service control, unchanged from existing scripts).

## Global Constraints

- Every script step that runs ON a client machine (`Install-Client.ps1`, `Uninstall-Client.ps1`, `Deploy-ClientGpo.ps1`, and the remote scriptblock inside `Uninstall-ClientWinRM.ps1`) must stay PowerShell 2.0-compatible: no `[PSCustomObject]@{}` shorthand, no ternary/null-coalescing operators, no `ForEach-Object -Parallel`, no 3/4-argument `Join-Path`. Use the same 2-argument `Join-Path`, `Test-Path -LiteralPath`, and string-concatenation style already used throughout these files.
- New default client subfolder name: `client-data` (final, user-approved - do not rename).
- `ServerUrl`/`Token`/`ServerSharePath` values that reach `sc.exe create`'s `binPath=` must keep going through each file's existing `Test-BatchSafeValue`/injection-safe construction - do not bypass it when adding the new `--output`/`--debug-log-path` arguments (these two new values are always script-controlled paths, never user/caller-supplied free text, so they do not themselves need `Test-BatchSafeValue`, but do not remove or weaken the existing checks on `ServerUrl`/`Token`/`ServerSharePath`).
- Do NOT bump `src\client\WindowsInventoryLiteClient.cs`'s `ProductVersion` constant (currently `0.2.0`). The compiled client executable's own code is untouched by this plan - only its installer/uninstaller *scripts* change. Per this project's established convention (`CHANGELOG.md`'s own versioning note), the client version only moves when the client's own collected data or code behavior changes. Only `src\server\WindowsInventoryLiteServer.cs`'s `ProductVersion` (currently `0.21.3`) bumps, to `0.22.0`.
- Do not touch `Install-ClientWinRM.ps1`, `New-ClientGpoPackage.ps1`, `Install-Wizard.ps1`, or any `server-*`/`client-package` path or default - out of scope per the design spec (`docs/superpowers/specs/2026-07-22-client-data-layout-design.md`).
- Do not move or delete any already-written client DATA files (`<hostname>.json`, `_logs\debug-client.log`, the old `Logs\gpo-deploy.log`) that a pre-fix install left at the bare root - only the executable/version-marker files get cleaned up after a successful migration. This is a deliberate design choice (see spec's "Old data files left at the bare root... not touched" section), not an oversight to fix later.
- Run all Pester suites via Windows PowerShell 5.1 (`powershell.exe`), never `pwsh` - `pwsh` produces an unrelated, already-documented false failure in this project's test suite (`Test-InstallServerRefreshOnly`, a GAC-load artifact of PowerShell 7's .NET Core runtime having no GAC).
- Never run any of these scripts for real (even with test/scratch arguments) on the implementer's own machine - they perform real `sc.exe` service-registry actions. All new tests must dot-source the script under test (which defines functions without doing real work, per the invocation-guard pattern this plan introduces - see Task 1) and exercise pure logic against `$TestDrive`, never a real install/uninstall run.

---

### Task 1: `deploy\client\Deploy-ClientGpo.ps1` - new default path, `--output`/`--debug-log-path` wiring, automatic migration, legacy-file cleanup

This is the actual production install/update mechanism for both the dashboard's WinRM push (`Client actions`/`Client updates`) and the GPO computer-startup-script path - fixing it here is what makes already-deployed clients migrate automatically the next time they're pushed to or updated.

**Files:**
- Modify: `deploy\client\Deploy-ClientGpo.ps1`
- Test: `tests\Deploy-ClientGpo.Tests.ps1` (new)

**Interfaces:**
- Produces: `Get-DesiredServiceCommand` gains two new mandatory-by-convention parameters, `-OutputDirectory <string>` and `-DebugLogPath <string>`, appended to the returned command string as `--output "<value>"` and `--debug-log-path "<value>"`.
- Produces: new function `Remove-LegacyClientFiles -LegacyRoot <string> -NewServicePath <string>` - deletes `<LegacyRoot>\WindowsInventoryLiteClient.exe` and `<LegacyRoot>\client-version.txt` if either exists and the exe path differs from `NewServicePath`; no-op otherwise. Calls the existing `Write-DeployLog` function for its own log lines.
- Produces: the whole "resolve defaults and do the real work" section (previously unconditional top-level code) is now wrapped in `if ($MyInvocation.InvocationName -ne '.') { ... }`, matching the existing pattern already used in `src\Install-Wizard.ps1` (see that file's own use of `$MyInvocation.InvocationName -ne '.'`) - dot-sourcing this script now only defines functions, it does not attempt a real install.

- [ ] **Step 1: Write the failing tests**

Create `tests\Deploy-ClientGpo.Tests.ps1`:

```powershell
$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Deploy-ClientGpo client-data layout' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'deploy\client\Deploy-ClientGpo.ps1'
        . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
    }

    It 'Get-DesiredServiceCommand embeds --output and --debug-log-path' {
        $command = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharedToken '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $command | Should -Match '--output "C:\\ProgramData\\WindowsInventoryLite\\client-data"'
        $command | Should -Match '--debug-log-path "C:\\ProgramData\\WindowsInventoryLite\\client-data\\_logs\\debug-client\.log"'
    }

    It 'Get-DesiredServiceCommand differs between the legacy bare-root path and the new client-data path, so an already-installed client is detected as needing reinstall' {
        $legacyCommand = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharedToken '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\_logs\debug-client.log'
        $newCommand = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharedToken '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $legacyCommand | Should -Not -Be $newCommand
    }

    It 'Remove-LegacyClientFiles deletes the old bare-root exe and client-version.txt when the new path differs' {
        $script:LogPath = Join-Path -Path $TestDrive -ChildPath 'test-deploy.log'
        $legacyRoot = Join-Path -Path $TestDrive -ChildPath 'legacy'
        New-Item -Path $legacyRoot -ItemType Directory -Force | Out-Null
        $legacyExe = Join-Path -Path $legacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
        $legacyVersion = Join-Path -Path $legacyRoot -ChildPath 'client-version.txt'
        Set-Content -LiteralPath $legacyExe -Value 'stub'
        Set-Content -LiteralPath $legacyVersion -Value '0.21.3'

        Remove-LegacyClientFiles -LegacyRoot $legacyRoot -NewServicePath (Join-Path -Path $TestDrive -ChildPath 'client-data\WindowsInventoryLiteClient.exe')

        Test-Path -LiteralPath $legacyExe | Should -Be $false
        Test-Path -LiteralPath $legacyVersion | Should -Be $false
    }

    It 'Remove-LegacyClientFiles is a no-op when the new service path IS the legacy path (no migration needed)' {
        $script:LogPath = Join-Path -Path $TestDrive -ChildPath 'test-deploy2.log'
        $legacyRoot = Join-Path -Path $TestDrive -ChildPath 'legacy2'
        New-Item -Path $legacyRoot -ItemType Directory -Force | Out-Null
        $legacyExe = Join-Path -Path $legacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
        Set-Content -LiteralPath $legacyExe -Value 'stub'

        Remove-LegacyClientFiles -LegacyRoot $legacyRoot -NewServicePath $legacyExe

        Test-Path -LiteralPath $legacyExe | Should -Be $true
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests\Deploy-ClientGpo.Tests.ps1 -Output Detailed"`
Expected: FAIL - `Get-DesiredServiceCommand` does not accept `-OutputDirectory`/`-DebugLogPath` (unknown parameter), and `Remove-LegacyClientFiles` is not recognized as a command.

- [ ] **Step 3: Modify `deploy\client\Deploy-ClientGpo.ps1`**

Replace the existing `Get-DesiredServiceCommand` function (currently):

```powershell
function Get-DesiredServiceCommand {
    param(
        [string]$ServicePath,
        [string]$Url,
        [int]$Hours,
        [string]$SharedToken
    )

    $command = '"' + (ConvertTo-ServiceArgValue $ServicePath) + '" --server-url "' + (ConvertTo-ServiceArgValue $Url) + '" --interval-hours ' + $Hours
    if ($SharedToken) {
        $command += ' --token "' + (ConvertTo-ServiceArgValue $SharedToken) + '"'
    }

    return $command
}
```

with:

```powershell
function Get-DesiredServiceCommand {
    param(
        [string]$ServicePath,
        [string]$Url,
        [int]$Hours,
        [string]$SharedToken,
        [string]$OutputDirectory,
        [string]$DebugLogPath
    )

    $command = '"' + (ConvertTo-ServiceArgValue $ServicePath) + '" --server-url "' + (ConvertTo-ServiceArgValue $Url) + '" --interval-hours ' + $Hours
    if ($SharedToken) {
        $command += ' --token "' + (ConvertTo-ServiceArgValue $SharedToken) + '"'
    }
    $command += ' --output "' + (ConvertTo-ServiceArgValue $OutputDirectory) + '"'
    $command += ' --debug-log-path "' + (ConvertTo-ServiceArgValue $DebugLogPath) + '"'

    return $command
}
```

Immediately after that function (still before `Test-Administrator`), add the new cleanup function:

```powershell
# Deletes the pre-client-data-layout exe/version marker from the shared
# WindowsInventoryLite root once the service has been successfully
# recreated pointing at its new client-data location - mirrors the
# cleanup this file already does for legacy WindowsLicenseInventory*
# artifacts above. Local data files (<hostname>.json, _logs\, the old
# Logs\gpo-deploy.log) are deliberately left alone: they get recreated
# fresh at the new location on the client's next run, and deleting
# arbitrary data files on a live production machine is not worth the
# risk for a cosmetic cleanup.
function Remove-LegacyClientFiles {
    param(
        [string]$LegacyRoot,
        [string]$NewServicePath
    )

    $newDirectory = Split-Path -Parent $NewServicePath

    $legacyExePath = Join-Path -Path $LegacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
    if ((Test-Path -LiteralPath $legacyExePath) -and ($legacyExePath -ne $NewServicePath)) {
        Write-DeployLog "Removing legacy client executable: $legacyExePath"
        Remove-Item -LiteralPath $legacyExePath -Force
    }

    # Same path-equality guard as the exe above - without it, an operator
    # who explicitly passes -InstallPath back to the legacy bare root (still
    # technically permitted) would have this delete the client-version.txt
    # Save-InstalledVersion just wrote to that same path seconds earlier,
    # making Get-InstalledVersion read nothing on the next run and forcing
    # a needless reinstall on every subsequent deploy.
    $legacyVersionPath = Join-Path -Path $LegacyRoot -ChildPath 'client-version.txt'
    $newVersionPath = Join-Path -Path $newDirectory -ChildPath 'client-version.txt'
    if ((Test-Path -LiteralPath $legacyVersionPath) -and ($legacyVersionPath -ne $newVersionPath)) {
        Write-DeployLog "Removing legacy client-version.txt: $legacyVersionPath"
        Remove-Item -LiteralPath $legacyVersionPath -Force
    }
}
```

Delete the original top-level `$LogPath` assignment (currently right after `$ScriptDirectory` resolution):

```powershell
$LogPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\Logs\gpo-deploy.log'
```

Then replace everything from `if (-not $InstallPath) {` through the final `Write-DeployLog "Client service deployed. Version: $installedVersion"` (the entire remainder of the file) with:

```powershell
# Wrapped so Pester can dot-source this file (". $ScriptPath -ServerUrl ...")
# to load Get-DesiredServiceCommand/Remove-LegacyClientFiles for direct
# unit testing without performing a real install - same technique already
# used in src\Install-Wizard.ps1.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $InstallPath) {
        $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-data'
    }

    $LogPath = Join-Path -Path $InstallPath -ChildPath 'Logs\gpo-deploy.log'

    if (-not $PackageClientPath) {
        $PackageClientPath = Get-DefaultPackageClientPath
    }

    if (-not (Test-Path -LiteralPath $PackageClientPath)) {
        throw "Required package file was not found: $PackageClientPath"
    }

    Write-DeployLog "Current identity: $(Get-CurrentIdentityName)"
    if (-not (Test-Administrator)) {
        throw 'Administrator rights are required to install or update the WindowsInventoryLite service. Use a Computer Startup Script GPO, not a User Logon Script, or run PowerShell as Administrator for manual testing.'
    }

    if (-not (Test-Path -LiteralPath $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    }

    $servicePath = Join-Path -Path $InstallPath -ChildPath 'WindowsInventoryLiteClient.exe'
    $debugLogPath = Join-Path -Path $InstallPath -ChildPath '_logs\debug-client.log'
    $packageVersion = Get-ExeVersion -Path $PackageClientPath
    $installedVersion = Get-InstalledVersion -InstallDirectory $InstallPath
    $desiredCommand = Get-DesiredServiceCommand -ServicePath $servicePath -Url $ServerUrl -Hours $IntervalHours -SharedToken $Token -OutputDirectory $InstallPath -DebugLogPath $debugLogPath
    $currentCommand = Get-ServiceBinaryPath
    $serviceExists = Test-ServiceExists
    $needsInstall = $Force -or (-not $serviceExists) -or ($packageVersion -ne $installedVersion) -or ($currentCommand -ne $desiredCommand)

    Write-DeployLog "Package version: $packageVersion"
    Write-DeployLog "Installed version: $installedVersion"
    Write-DeployLog "Package client path: $PackageClientPath"

    if (-not $needsInstall) {
        Write-DeployLog "Client service is already current."
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Running') {
            Invoke-ServiceControl -Arguments @('start', $ServiceName) -FailureMessage 'Failed to start existing service.' | Out-Null
            Write-DeployLog "Client service started."
        }
        return
    }

    foreach ($legacyName in @('WindowsLicenseInventoryClient', 'WindowsLicenseInventory')) {
        $null = & sc.exe query $legacyName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-DeployLog "Removing legacy service: $legacyName"
            Invoke-ServiceControl -Arguments @('stop', $legacyName) -FailureMessage "Failed to stop legacy service $legacyName." -AllowedExitCodes @(0, 1062) | Out-Null
            Invoke-ServiceControl -Arguments @('delete', $legacyName) -FailureMessage "Failed to delete legacy service $legacyName." | Out-Null
        }
    }

    $legacyInstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsLicenseInventory'
    if (Test-Path -LiteralPath $legacyInstallPath) {
        Write-DeployLog "Removing legacy install directory: $legacyInstallPath"
        Remove-Item -LiteralPath $legacyInstallPath -Recurse -Force
    }

    if ($serviceExists) {
        Write-DeployLog "Updating existing client service."
        Invoke-ServiceControl -Arguments @('stop', $ServiceName) -FailureMessage 'Failed to stop existing service.' -AllowedExitCodes @(0, 1062) | Out-Null
        Invoke-ServiceControl -Arguments @('delete', $ServiceName) -FailureMessage 'Failed to delete existing service.' | Out-Null
        Wait-FileRelease -Path $servicePath
    }
    else {
        Write-DeployLog "Installing new client service."
    }

    Copy-Item -LiteralPath $PackageClientPath -Destination $servicePath -Force
    $installedVersion = $packageVersion
    Save-InstalledVersion -InstallDirectory $InstallPath -Version $installedVersion

    Invoke-ServiceCreate -ServiceName $ServiceName -BinPath $desiredCommand -DisplayName 'Windows Inventory Lite' -FailureMessage 'Failed to create service.' | Out-Null
    Invoke-ServiceControl -Arguments @('description', $ServiceName, "Collects Windows, Office, activation, and software inventory for Windows Inventory Lite. Version $installedVersion.") -FailureMessage 'Failed to set service description.' | Out-Null
    Invoke-ServiceControl -Arguments @('start', $ServiceName) -FailureMessage 'Failed to start service.' | Out-Null

    Remove-LegacyClientFiles -LegacyRoot (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite') -NewServicePath $servicePath

    Write-DeployLog "Client service deployed. Version: $installedVersion"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests\Deploy-ClientGpo.Tests.ps1 -Output Detailed"`
Expected: PASS, 4/4.

- [ ] **Step 5: Run the full existing Pester suite to confirm nothing else broke**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"`
Expected: PASS on every pre-existing test file, plus the 4 new ones (the pre-existing `Test-InstallServerRefreshOnly` GAC-artifact caveat does not apply here since we're on `powershell.exe`).

- [ ] **Step 6: Commit**

```bash
git add deploy/client/Deploy-ClientGpo.ps1 tests/Deploy-ClientGpo.Tests.ps1
git commit -m "feat: default Deploy-ClientGpo.ps1 to client-data subfolder, wire --output/--debug-log-path"
```

---

### Task 2: `src\Install-Client.ps1` - new default path, `--output`/`--debug-log-path` wiring, legacy-file cleanup

**Files:**
- Modify: `src\Install-Client.ps1`
- Test: `tests\Install-Client.Tests.ps1` (new)

**Interfaces:**
- Consumes: `ConvertTo-ServiceArgValue` (already defined in this file, unchanged).
- Produces: new function `Get-ClientServiceCommand -ServicePath <string> -Url <string> -Hours <int> -SharePath <string> -SharedToken <string> -OutputDirectory <string> -DebugLogPath <string>` - returns the full service command-line string (replaces the previous inline string-building block).
- Produces: new function `Remove-LegacyClientFiles -LegacyRoot <string> -NewServicePath <string>` - same contract as Task 1's version of this function (deletes the legacy exe/version-marker if present and different from the new path), but uses `Write-Host` instead of `Write-DeployLog` (this script has no deploy-log concept).
- Produces: the "resolve defaults and do the real work" section is wrapped in `if ($MyInvocation.InvocationName -ne '.') { ... }`, same technique as Task 1.

- [ ] **Step 1: Write the failing tests**

Create `tests\Install-Client.Tests.ps1`:

```powershell
$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install-Client client-data layout' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-Client.ps1'
        . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
    }

    It 'Get-ClientServiceCommand embeds --output and --debug-log-path' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharePath '' -SharedToken '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $command | Should -Match '--output "C:\\ProgramData\\WindowsInventoryLite\\client-data"'
        $command | Should -Match '--debug-log-path "C:\\ProgramData\\WindowsInventoryLite\\client-data\\_logs\\debug-client\.log"'
    }

    It 'Get-ClientServiceCommand still includes --share and --token when provided' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharePath '\\server\drop' -SharedToken 'abc123' -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Match '--share "\\\\server\\drop"'
        $command | Should -Match '--token "abc123"'
    }

    It 'Remove-LegacyClientFiles deletes the old bare-root exe and client-version.txt when the new path differs' {
        $legacyRoot = Join-Path -Path $TestDrive -ChildPath 'legacy'
        New-Item -Path $legacyRoot -ItemType Directory -Force | Out-Null
        $legacyExe = Join-Path -Path $legacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
        $legacyVersion = Join-Path -Path $legacyRoot -ChildPath 'client-version.txt'
        Set-Content -LiteralPath $legacyExe -Value 'stub'
        Set-Content -LiteralPath $legacyVersion -Value '0.21.3'

        Remove-LegacyClientFiles -LegacyRoot $legacyRoot -NewServicePath (Join-Path -Path $TestDrive -ChildPath 'client-data\WindowsInventoryLiteClient.exe')

        Test-Path -LiteralPath $legacyExe | Should -Be $false
        Test-Path -LiteralPath $legacyVersion | Should -Be $false
    }

    It 'Remove-LegacyClientFiles is a no-op when the new service path IS the legacy path' {
        $legacyRoot = Join-Path -Path $TestDrive -ChildPath 'legacy2'
        New-Item -Path $legacyRoot -ItemType Directory -Force | Out-Null
        $legacyExe = Join-Path -Path $legacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
        Set-Content -LiteralPath $legacyExe -Value 'stub'

        Remove-LegacyClientFiles -LegacyRoot $legacyRoot -NewServicePath $legacyExe

        Test-Path -LiteralPath $legacyExe | Should -Be $true
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests\Install-Client.Tests.ps1 -Output Detailed"`
Expected: FAIL - `Get-ClientServiceCommand` and `Remove-LegacyClientFiles` are not recognized commands.

- [ ] **Step 3: Modify `src\Install-Client.ps1`**

Immediately after the existing `ConvertTo-ServiceArgValue` function (the last function defined before the current `if (-not $InstallPath)` block), add:

```powershell
function Get-ClientServiceCommand {
    param(
        [string]$ServicePath,
        [string]$Url,
        [int]$Hours,
        [string]$SharePath,
        [string]$SharedToken,
        [string]$OutputDirectory,
        [string]$DebugLogPath
    )

    $command = '"' + (ConvertTo-ServiceArgValue $ServicePath) + '" --server-url "' + (ConvertTo-ServiceArgValue $Url) + '" --interval-hours ' + $Hours
    if ($SharePath) {
        $command += ' --share "' + (ConvertTo-ServiceArgValue $SharePath) + '"'
    }
    if ($SharedToken) {
        $command += ' --token "' + (ConvertTo-ServiceArgValue $SharedToken) + '"'
    }
    $command += ' --output "' + (ConvertTo-ServiceArgValue $OutputDirectory) + '"'
    $command += ' --debug-log-path "' + (ConvertTo-ServiceArgValue $DebugLogPath) + '"'

    return $command
}

# Deletes the pre-client-data-layout exe/version marker from the shared
# WindowsInventoryLite root once the service has been successfully
# recreated pointing at its new client-data location - mirrors the
# cleanup this file already does for legacy WindowsLicenseInventory*
# artifacts. Local data files (<hostname>.json, _logs\) are deliberately
# left alone: they get recreated fresh at the new location on the
# client's next run.
function Remove-LegacyClientFiles {
    param(
        [string]$LegacyRoot,
        [string]$NewServicePath
    )

    $newDirectory = Split-Path -Parent $NewServicePath

    $legacyExePath = Join-Path -Path $LegacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
    if ((Test-Path -LiteralPath $legacyExePath) -and ($legacyExePath -ne $NewServicePath)) {
        Write-Host "Removing legacy client executable: $legacyExePath"
        Remove-Item -LiteralPath $legacyExePath -Force
    }

    # Same path-equality guard as the exe above - without it, an operator
    # who explicitly passes -InstallPath back to the legacy bare root (still
    # technically permitted) would have this delete a client-version.txt
    # that legitimately belongs at that same "new" location (e.g. written by
    # an earlier Deploy-ClientGpo.ps1 run against the same path).
    $legacyVersionPath = Join-Path -Path $LegacyRoot -ChildPath 'client-version.txt'
    $newVersionPath = Join-Path -Path $newDirectory -ChildPath 'client-version.txt'
    if ((Test-Path -LiteralPath $legacyVersionPath) -and ($legacyVersionPath -ne $newVersionPath)) {
        Write-Host "Removing legacy client-version.txt: $legacyVersionPath"
        Remove-Item -LiteralPath $legacyVersionPath -Force
    }
}
```

Then replace everything from `if (-not $InstallPath) {` through the final `Write-Host "Client installed: $InstallPath"` (the entire remainder of the file) with:

```powershell
# Wrapped so Pester can dot-source this file (". $ScriptPath -ServerUrl ...")
# to load Get-ClientServiceCommand/Remove-LegacyClientFiles for direct
# unit testing without performing a real install - same technique used in
# src\Install-Wizard.ps1 and deploy\client\Deploy-ClientGpo.ps1.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $InstallPath) {
        $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-data'
    }

    $serviceName = 'WindowsInventoryLiteClient'
    $buildScript = Join-Path -Path $ScriptRoot -ChildPath 'Build-Client.ps1'

    if (-not $ClientExecutablePath) {
        # No explicit path was given, so this is the project's own build output
        # (not a caller-supplied binary) - rebuild it fresh every run, the same
        # way New-ClientGpoPackage.ps1 already does for its default paths. An
        # existence-only check let a stale build\WindowsInventoryLiteClient.exe
        # from an earlier session get installed silently, with no version
        # mismatch warning like the dashboard's package view has.
        $projectRoot = Split-Path -Parent $ScriptRoot
        $ClientExecutablePath = Join-Path -Path $projectRoot -ChildPath 'build\WindowsInventoryLiteClient.exe'
        & $buildScript -OutputPath $ClientExecutablePath
    }
    elseif (-not (Test-Path -LiteralPath $ClientExecutablePath)) {
        & $buildScript -OutputPath $ClientExecutablePath
    }

    if (-not (Test-Path -LiteralPath $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    }

    foreach ($legacyName in @('WindowsLicenseInventoryClient', 'WindowsLicenseInventory')) {
        $null = & sc.exe query $legacyName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Invoke-ServiceControl -Arguments @('stop', $legacyName) -FailureMessage "Failed to stop legacy service $legacyName." -AllowedExitCodes @(0, 1062) | Out-Null
            Invoke-ServiceControl -Arguments @('delete', $legacyName) -FailureMessage "Failed to delete legacy service $legacyName." | Out-Null
        }
    }

    $legacyInstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsLicenseInventory'
    if (Test-Path -LiteralPath $legacyInstallPath) {
        Remove-Item -LiteralPath $legacyInstallPath -Recurse -Force
    }

    $servicePath = Join-Path -Path $InstallPath -ChildPath 'WindowsInventoryLiteClient.exe'
    $debugLogPath = Join-Path -Path $InstallPath -ChildPath '_logs\debug-client.log'
    $null = & sc.exe query $serviceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Invoke-ServiceControl -Arguments @('stop', $serviceName) -FailureMessage "Failed to stop existing service." -AllowedExitCodes @(0, 1062) | Out-Null
        Invoke-ServiceControl -Arguments @('delete', $serviceName) -FailureMessage "Failed to delete existing service." | Out-Null
        Wait-FileRelease -Path $servicePath
    }

    Copy-Item -LiteralPath $ClientExecutablePath -Destination $servicePath -Force
    $clientVersion = (& $servicePath --version 2>&1 | Select-Object -First 1)

    $serviceCommand = Get-ClientServiceCommand -ServicePath $servicePath -Url $ServerUrl -Hours $IntervalHours -SharePath $ServerSharePath -SharedToken $Token -OutputDirectory $InstallPath -DebugLogPath $debugLogPath

    Invoke-ServiceCreate -ServiceName $serviceName -BinPath $serviceCommand -DisplayName 'Windows Inventory Lite' -FailureMessage "Failed to create service. Run PowerShell as Administrator." | Out-Null
    Invoke-ServiceControl -Arguments @('description', $serviceName, "Collects Windows, Office, activation, and software inventory for Windows Inventory Lite. Version $clientVersion.") -FailureMessage "Failed to set service description." | Out-Null
    Write-Host "Service created: $serviceName"
    Write-Host "Client version: $clientVersion"

    if (-not $NoRun) {
        Invoke-ServiceControl -Arguments @('start', $serviceName) -FailureMessage "Failed to start service." | Out-Null
        Write-Host "Service started: $serviceName"
    }

    Remove-LegacyClientFiles -LegacyRoot (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite') -NewServicePath $servicePath

    Write-Host "Client installed: $InstallPath"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests\Install-Client.Tests.ps1 -Output Detailed"`
Expected: PASS, 4/4.

- [ ] **Step 5: Run the full existing Pester suite to confirm nothing else broke**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"`
Expected: PASS on every test file, including Task 1's.

- [ ] **Step 6: Commit**

```bash
git add src/Install-Client.ps1 tests/Install-Client.Tests.ps1
git commit -m "feat: default Install-Client.ps1 to client-data subfolder, wire --output/--debug-log-path"
```

---

### Task 3: `src\Uninstall-Client.ps1` - new default path, shared-server-root safety guard

**Files:**
- Modify: `src\Uninstall-Client.ps1` (whole-file replacement - the file is 44 lines)
- Test: `tests\Uninstall-Client.Tests.ps1` (new)

**Interfaces:**
- Produces: new function `Test-IsSharedServerRoot -Path <string> -SharedRoot <string>` - returns `$true` only when `$Path` (trailing-backslash-normalized) equals `$SharedRoot` AND `<SharedRoot>\server-config.json` exists; `$false` otherwise.

- [ ] **Step 1: Write the failing tests**

Create `tests\Uninstall-Client.Tests.ps1`:

```powershell
$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Uninstall-Client safety guard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Uninstall-Client.ps1'
        . $script:ScriptPath -InstallPath (Join-Path -Path $TestDrive -ChildPath 'unused') -WhatIf
    }

    It 'returns true when the path matches the shared root and server-config.json is present' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'

        Test-IsSharedServerRoot -Path $sharedRoot -SharedRoot $sharedRoot | Should -Be $true
    }

    It 'returns false when server-config.json is absent (client-only machine)' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite2'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null

        Test-IsSharedServerRoot -Path $sharedRoot -SharedRoot $sharedRoot | Should -Be $false
    }

    It 'returns false when the path is the new client-data subfolder, not the shared root itself' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite3'
        $clientData = Join-Path -Path $sharedRoot -ChildPath 'client-data'
        New-Item -Path $clientData -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'

        Test-IsSharedServerRoot -Path $clientData -SharedRoot $sharedRoot | Should -Be $false
    }

    It 'is insensitive to a trailing backslash on the path being checked' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite4'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'

        Test-IsSharedServerRoot -Path ($sharedRoot + '\') -SharedRoot $sharedRoot | Should -Be $true
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests\Uninstall-Client.Tests.ps1 -Output Detailed"`
Expected: FAIL - `Test-IsSharedServerRoot` is not a recognized command.

- [ ] **Step 3: Replace the full contents of `src\Uninstall-Client.ps1`**

```powershell
#requires -Version 2.0

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Safety net for the client/server co-located case: if $InstallPath still
# resolves to the shared WindowsInventoryLite root (an explicit override,
# or an uninstall run against a machine never reinstalled since the
# client-data layout shipped) and server-config.json is sitting right
# there, a recursive delete would take the server's own data with it.
# Refuse only in that specific case - a client-only machine's bare root
# (no server-config.json) still gets fully cleaned up as before.
function Test-IsSharedServerRoot {
    param(
        [string]$Path,
        [string]$SharedRoot
    )

    if ($Path.TrimEnd('\') -ne $SharedRoot.TrimEnd('\')) {
        return $false
    }

    return Test-Path -LiteralPath (Join-Path -Path $SharedRoot -ChildPath 'server-config.json')
}

if (-not $InstallPath) {
    $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-data'
}

foreach ($legacyName in @('WindowsLicenseInventoryClient', 'WindowsLicenseInventory')) {
    & sc.exe query $legacyName | Out-Null
    if ($LASTEXITCODE -eq 0 -and $PSCmdlet.ShouldProcess($legacyName, 'Stop and delete legacy service')) {
        & sc.exe stop $legacyName | Out-Null
        & sc.exe delete $legacyName | Out-Null
        Start-Sleep -Seconds 2
    }
}

$legacyInstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsLicenseInventory'
if ((Test-Path -LiteralPath $legacyInstallPath) -and $PSCmdlet.ShouldProcess($legacyInstallPath, 'Remove legacy client files')) {
    Remove-Item -LiteralPath $legacyInstallPath -Recurse -Force
}

$serviceName = 'WindowsInventoryLiteClient'
& sc.exe query $serviceName | Out-Null
if ($LASTEXITCODE -eq 0 -and $PSCmdlet.ShouldProcess($serviceName, 'Stop and delete service')) {
    & sc.exe stop $serviceName | Out-Null
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

$sharedRoot = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'
if (Test-IsSharedServerRoot -Path $InstallPath -SharedRoot $sharedRoot) {
    Write-Warning "Skipped removing $InstallPath - it looks like the server's own directory (server-config.json present). Remove client files manually if needed."
}
else {
    if ((Test-Path -LiteralPath $InstallPath) -and $PSCmdlet.ShouldProcess($InstallPath, 'Remove client files')) {
        Remove-Item -LiteralPath $InstallPath -Recurse -Force
    }

    Write-Host "Client removed."
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests\Uninstall-Client.Tests.ps1 -Output Detailed"`
Expected: PASS, 4/4.

- [ ] **Step 5: Run the full existing Pester suite to confirm nothing else broke**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"`
Expected: PASS on every test file, including Tasks 1-2's.

- [ ] **Step 6: Commit**

```bash
git add src/Uninstall-Client.ps1 tests/Uninstall-Client.Tests.ps1
git commit -m "fix: default Uninstall-Client.ps1 to client-data subfolder, refuse to recursively delete the server's own root"
```

---

### Task 4: `src\Uninstall-ClientWinRM.ps1` - new default path, shared-server-root safety guard in the remote scriptblock

**Files:**
- Modify: `src\Uninstall-ClientWinRM.ps1` (whole-file replacement - the file is 211 lines)
- Test: `tests\Uninstall-ClientWinRM.Tests.ps1` (new)

**Interfaces:**
- Produces: script-scope variable `$script:RemoveClientScriptBlock` (a `[scriptblock]`) - takes `param([string]$ServiceName, [string]$ClientInstallPath)`, contains exactly the same body the remote `Invoke-Command` call used inline before, plus the new shared-root guard. Callable directly (no `-ComputerName`/`-Session`) to run locally, which is what the tests do.
- Produces: the `foreach ($computer in $ComputerName) { ... }` main loop is wrapped in `if ($MyInvocation.InvocationName -ne '.') { ... }`, same technique as Tasks 1-2.

- [ ] **Step 1: Write the failing tests**

Create `tests\Uninstall-ClientWinRM.Tests.ps1`:

```powershell
$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Uninstall-ClientWinRM safety guard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Uninstall-ClientWinRM.ps1'
        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test'
    }

    It 'skips removal when the target path is the shared server root with server-config.json present' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'
        $leftoverFile = Join-Path -Path $sharedRoot -ChildPath 'leftover.txt'
        Set-Content -LiteralPath $leftoverFile -Value 'stub'

        $originalProgramData = $env:ProgramData
        $env:ProgramData = $TestDrive
        try {
            & $script:RemoveClientScriptBlock -ServiceName 'NoSuchServiceForThisTest' -ClientInstallPath $sharedRoot | Out-Null
        }
        finally {
            $env:ProgramData = $originalProgramData
        }

        Test-Path -LiteralPath $sharedRoot | Should -Be $true
        Test-Path -LiteralPath $leftoverFile | Should -Be $true
    }

    It 'removes the target path when it is not the shared server root' {
        $clientOnlyRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite2\client-data'
        New-Item -Path $clientOnlyRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $clientOnlyRoot -ChildPath 'leftover.txt') -Value 'stub'

        & $script:RemoveClientScriptBlock -ServiceName 'NoSuchServiceForThisTest' -ClientInstallPath $clientOnlyRoot | Out-Null

        Test-Path -LiteralPath $clientOnlyRoot | Should -Be $false
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests\Uninstall-ClientWinRM.Tests.ps1 -Output Detailed"`
Expected: FAIL - `$script:RemoveClientScriptBlock` does not exist (dot-sourcing runs the real `foreach` loop today, which attempts `New-PSSession -ComputerName 'unused-for-dot-source-test'` and throws/fails before `BeforeAll` even completes).

- [ ] **Step 3: Replace the full contents of `src\Uninstall-ClientWinRM.ps1`**

```powershell
#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = 'C:\ProgramData\WindowsInventoryLite\client-data',

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CredentialUsername,

    # SecureString, not [string] - a plaintext password parameter is visible
    # to any local process listing (Get-Process/Win32_Process/Task Manager)
    # and lands in this session's PowerShell history for as long as it's
    # kept. The production dashboard-driven path never uses this parameter
    # anyway (it passes -Credential directly, built from stdin); this is
    # only for manual/standalone invocation.
    [Parameter()]
    [System.Security.SecureString]$CredentialPassword,

    [Parameter()]
    [switch]$AddToTrustedHosts
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$serviceName = 'WindowsInventoryLiteClient'
$hadFailure = $false

if (-not $Credential -and $CredentialUsername -and $CredentialPassword) {
    $Credential = New-Object System.Management.Automation.PSCredential($CredentialUsername, $CredentialPassword)
}

# WinRM connection failures throw System.Management.Automation.Remoting.
# PSRemotingTransportException with the OS's own localized message text
# (Russian on a Russian-locale target, English on an English one, etc.) -
# unreadable to an admin whose own console is a different language, and a
# wall of internal WS-Management troubleshooting text either way. Classify
# by the exception TYPE and its .ErrorCode (a stable, documented WSMan
# HRESULT, not locale text) instead of matching on the message string.
# Only -2144108103 (name resolution failure) is mapped with real
# confidence here - every other PSRemotingTransportException falls into
# one shared "WinRM unreachable" bucket, which covers the connection-
# refused/timeout/service-not-configured case from real fleet reports but
# is not itself split further, since verifying additional specific codes
# needs a real failing WinRM target this dev machine doesn't have. The
# original message is always appended, so misclassifying a less-common
# code never hides the real detail - it only adds a friendlier headline.
function Get-FriendlyConnectionError {
    param([System.Exception]$Exception)

    if ($Exception -is [System.Management.Automation.Remoting.PSRemotingTransportException]) {
        if ($Exception.ErrorCode -eq -2144108103) {
            $friendly = 'Computer unreachable - could not resolve its name. Try again later.'
        }
        else {
            $friendly = 'WinRM service is not reachable on this computer - check that WinRM is configured and running (winrm quickconfig), and that the computer is online.'
        }
        return "$friendly (original error: $($Exception.Message))"
    }

    return $Exception.Message
}

function New-InventorySession {
    param([string]$TargetComputer)

    if ($Credential) {
        return New-PSSession -ComputerName $TargetComputer -Credential $Credential
    }

    return New-PSSession -ComputerName $TargetComputer
}

function Add-TargetToTrustedHosts {
    param([string]$TargetComputer)

    $current = ''
    try {
        $item = Get-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop
        $current = [string]$item.Value
    }
    catch {
        throw "Failed to read WinRM TrustedHosts. Run this script on a host with WinRM client support."
    }

    if ($current -eq '*') {
        return
    }

    $items = @()
    if ($current) {
        $items = @($current.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    foreach ($item in $items) {
        if ($item -ieq $TargetComputer) {
            return
        }
    }

    $items += $TargetComputer
    Set-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -Value ($items -join ',') -Force | Out-Null
}

function Test-IpAddress {
    param([string]$Value)

    $address = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$address)
}

# Defined as a script-scope scriptblock variable (not an inline literal at
# the Invoke-Command call site) so Pester can invoke the exact same code
# locally (no -ComputerName/-Session) to test the shared-server-root guard
# below, without needing a real WinRM target.
$script:RemoveClientScriptBlock = {
    param(
        [string]$ServiceName,
        [string]$ClientInstallPath
    )

    foreach ($legacyName in @('WindowsLicenseInventoryClient', 'WindowsLicenseInventory')) {
        $null = & sc.exe query $legacyName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Stopping legacy service: $legacyName"
            & sc.exe stop $legacyName | Out-Null
            Start-Sleep -Seconds 2
            Write-Host "Deleting legacy service: $legacyName"
            & sc.exe delete $legacyName | Out-Null
            Start-Sleep -Seconds 2
        }
    }

    $legacyPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsLicenseInventory'
    if (Test-Path -LiteralPath $legacyPath) {
        Write-Host "Removing legacy client files: $legacyPath"
        Remove-Item -LiteralPath $legacyPath -Recurse -Force
    }

    $null = & sc.exe query $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Stopping service: $ServiceName"
        $stopOutput = & sc.exe stop $ServiceName 2>&1
        $stopExitCode = $LASTEXITCODE
        Write-Host "Stop service exit code: $stopExitCode"
        Start-Sleep -Seconds 2

        Write-Host "Deleting service: $ServiceName"
        $deleteOutput = & sc.exe delete $ServiceName 2>&1
        $deleteExitCode = $LASTEXITCODE
        Write-Host "Delete service exit code: $deleteExitCode"
        if ($deleteExitCode -ne 0) {
            throw "Failed to delete service. sc.exe exit code: $deleteExitCode."
        }
        Start-Sleep -Seconds 2
    }
    else {
        Write-Host "Service is not installed: $ServiceName"
    }

    # Safety net for the client/server co-located case: if $ClientInstallPath
    # still resolves to the shared WindowsInventoryLite root (an explicit
    # override, or a target never reinstalled since the client-data layout
    # shipped) and server-config.json is sitting right there, a recursive
    # delete would take the server's own data with it. Refuse only in that
    # specific case - a client-only target's bare root (no server-config.json)
    # still gets fully cleaned up as before. Inlined (not a called function)
    # because this block runs in a separate remote runspace over WinRM,
    # which cannot resolve functions defined in the local script.
    $sharedRoot = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'
    $isSharedServerRoot = ($ClientInstallPath.TrimEnd('\') -eq $sharedRoot.TrimEnd('\')) -and (Test-Path -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json'))

    if ($isSharedServerRoot) {
        Write-Warning "Skipped removing $ClientInstallPath - it looks like the server's own directory (server-config.json present). Remove client files manually if needed."
    }
    elseif (Test-Path -LiteralPath $ClientInstallPath) {
        Write-Host "Removing client files: $ClientInstallPath"
        Remove-Item -LiteralPath $ClientInstallPath -Recurse -Force
    }
    else {
        Write-Host "Client files are not present: $ClientInstallPath"
    }
}

# Wrapped so Pester can dot-source this file (". $ScriptPath -ComputerName ...")
# to load $script:RemoveClientScriptBlock for direct unit testing without
# attempting a real WinRM connection - same technique used in
# src\Install-Client.ps1 and deploy\client\Deploy-ClientGpo.ps1.
if ($MyInvocation.InvocationName -ne '.') {
    foreach ($computer in $ComputerName) {
        $session = $null
        try {
            Write-Host "Connecting: $computer"
            if ($AddToTrustedHosts -or ($Credential -and (Test-IpAddress -Value $computer))) {
                Write-Host "Adding TrustedHosts entry: $computer"
                Add-TargetToTrustedHosts -TargetComputer $computer
            }

            $session = New-InventorySession -TargetComputer $computer
            Write-Host "Uninstalling client service: $computer"

            Invoke-Command -Session $session -ScriptBlock $script:RemoveClientScriptBlock -ArgumentList $serviceName, $InstallPath

            Write-Host "Client removed: $computer"
        }
        catch {
            $hadFailure = $true
            # Write-Error would work too, but PowerShell wraps it in a full
            # ErrorRecord (position info relative to the wrapping one-line
            # -Command invocation, CategoryInfo, FullyQualifiedErrorId) when it
            # reaches the caller's captured stderr - exactly the kind of wall
            # of PowerShell plumbing text Get-FriendlyConnectionError above is
            # meant to spare the dashboard's job log from. A plain stderr write
            # carries the same message with none of that ceremony.
            [Console]::Error.WriteLine(("Failed to uninstall client on {0}: {1}" -f $computer, (Get-FriendlyConnectionError -Exception $_.Exception)))
        }
        finally {
            if ($session) {
                Remove-PSSession -Session $session
            }
        }
    }

    if ($hadFailure) {
        exit 1
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests\Uninstall-ClientWinRM.Tests.ps1 -Output Detailed"`
Expected: PASS, 2/2.

- [ ] **Step 5: Run the full existing Pester suite to confirm nothing else broke**

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"`
Expected: PASS on every test file, including Tasks 1-3's.

- [ ] **Step 6: Commit**

```bash
git add src/Uninstall-ClientWinRM.ps1 tests/Uninstall-ClientWinRM.Tests.ps1
git commit -m "fix: default Uninstall-ClientWinRM.ps1 to client-data subfolder, refuse to recursively delete the server's own root on the target"
```

---

### Task 5: Documentation, CHANGELOG, version bump

**Files:**
- Modify: `README.md`
- Modify: `README_RU.md`
- Modify: `CHANGELOG.md`
- Modify: `src\server\WindowsInventoryLiteServer.cs` (version constant only)

**Interfaces:**
- Consumes: nothing new from Tasks 1-4 beyond their shipped behavior; this task only documents it.

- [ ] **Step 1: Update `README.md`**

In the GPO deployment section, replace:

```markdown
The deploy script writes a local log to `C:\ProgramData\WindowsInventoryLite\Logs\gpo-deploy.log`.
Central logging to the package share is present in the script as commented code and is disabled by default.
```

with:

```markdown
The deploy script writes a local log to `C:\ProgramData\WindowsInventoryLite\client-data\Logs\gpo-deploy.log`.
```

(The second sentence is removed - it described commented-out code that a prior comment-accuracy pass already deleted from `Deploy-ClientGpo.ps1`; nothing in the current script matches it anymore.)

In the `Install-Client.ps1` parameter table, replace:

```markdown
| `-InstallPath` | `—` | Installation folder for the client service. Default: `C:\ProgramData\WindowsInventoryLite`. |
```

with:

```markdown
| `-InstallPath` | `—` | Installation folder for the client service. Default: `C:\ProgramData\WindowsInventoryLite\client-data`. |
```

In the `Uninstall-Client.ps1` parameter table, replace:

```markdown
| `-InstallPath` | `C:\ProgramData\WindowsInventoryLite` | Installation folder to remove. |
```

with:

```markdown
| `-InstallPath` | `C:\ProgramData\WindowsInventoryLite\client-data` | Installation folder to remove. Refused if it resolves to the server's own shared root (detected via a `server-config.json` check) - see the "Client and server on the same machine" note below. |
```

In the `Uninstall-ClientWinRM.ps1` parameter table, replace:

```markdown
| `-InstallPath` | `C:\ProgramData\WindowsInventoryLite` | Installation folder to remove on remote hosts. |
```

with:

```markdown
| `-InstallPath` | `C:\ProgramData\WindowsInventoryLite\client-data` | Installation folder to remove on remote hosts. Refused if it resolves to the target's own shared server root - see the "Client and server on the same machine" note below. |
```

In the `Deploy-ClientGpo.ps1` parameter table, replace:

```markdown
| `-InstallPath` | `—` | Installation folder for the client service. Default: `C:\ProgramData\WindowsInventoryLite`. |
```

with:

```markdown
| `-InstallPath` | `—` | Installation folder for the client service. Default: `C:\ProgramData\WindowsInventoryLite\client-data`. |
```

Add a new subsection right after the GPO deployment section (before `## Forced Client Actions Through WinRM`):

```markdown
## Client and Server on the Same Machine

When the server also runs a local client to inventory its own host, the client's files (`WindowsInventoryLiteClient.exe`, its local JSON report, `client-version.txt`, and its logs) live under `client-data\`, next to but separate from the server's own `server-bin`, `server-data`, `server-content`, and `client-package` folders - not mixed into the shared root.

An already-installed client from before this layout shipped migrates automatically the next time it's installed or updated (a WinRM push from `Client actions`/`Client updates`, a GPO startup script re-run, or a manual `Install-Client.ps1`/`Deploy-ClientGpo.ps1` run) - no separate migration step is needed. The old executable is removed after the new one is confirmed running; any data files left at the old location (the old JSON report, old logs) are not deleted automatically and can be removed by hand once you've confirmed the client is reporting normally from its new location.

`Uninstall-Client.ps1` and `Uninstall-ClientWinRM.ps1` both refuse to recursively delete their target folder if it turns out to be the shared `WindowsInventoryLite` root itself (detected by the presence of `server-config.json`) - this protects the server's own data on a co-located machine even if `-InstallPath` is overridden to point there by mistake.
```

- [ ] **Step 2: Update `README_RU.md`** (adapted, not a literal translation - matches this project's existing README_RU convention)

Apply the equivalent changes at the same line numbers/sections:

Replace:

```markdown
Скрипт развертывания пишет локальный лог в `C:\ProgramData\WindowsInventoryLite\Logs\gpo-deploy.log`.
Запись центрального лога в сетевую папку пакета оставлена в скрипте как закомментированный код и по умолчанию отключена.
```

with:

```markdown
Скрипт развертывания пишет локальный лог в `C:\ProgramData\WindowsInventoryLite\client-data\Logs\gpo-deploy.log`.
```

Replace the four matching `-InstallPath` parameter rows (for `Install-Client.ps1`, `Uninstall-Client.ps1`, `Uninstall-ClientWinRM.ps1`, `Deploy-ClientGpo.ps1`) the same way as in `README.md`, translating the new descriptive text:

```markdown
| `-InstallPath` | `—` | Папка установки клиентской службы. По умолчанию: `C:\ProgramData\WindowsInventoryLite\client-data`. |
```

```markdown
| `-InstallPath` | `C:\ProgramData\WindowsInventoryLite\client-data` | Папка установки для удаления. Удаление пропускается, если путь совпадает с общей папкой сервера (проверяется по наличию `server-config.json`) - см. примечание "Клиент и сервер на одной машине" ниже. |
```

```markdown
| `-InstallPath` | `C:\ProgramData\WindowsInventoryLite\client-data` | Папка установки для удаления на удаленных хостах. Удаление пропускается, если путь совпадает с общей папкой сервера на целевой машине - см. примечание "Клиент и сервер на одной машине" ниже. |
```

Add the matching new subsection after the GPO deployment section:

```markdown
## Клиент и сервер на одной машине

Если сервер также инвентаризирует сам себя через локально установленный клиент, файлы клиента (`WindowsInventoryLiteClient.exe`, его локальный JSON-отчёт, `client-version.txt`, логи) лежат в `client-data\` - рядом с серверными `server-bin`, `server-data`, `server-content`, `client-package`, но не вперемешку с ними.

Уже установленный клиент со старым расположением файлов переходит на новый макет автоматически при следующей установке или обновлении (push через `Client actions`/`Client updates`, повторный запуск GPO-сценария, ручной запуск `Install-Client.ps1`/`Deploy-ClientGpo.ps1`) - отдельный шаг миграции не требуется. Старый исполняемый файл удаляется после того, как новый подтверждённо запущен; файлы данных на старом месте (старый JSON-отчёт, старые логи) автоматически не удаляются - их можно убрать вручную, убедившись, что клиент нормально отчитывается с нового места.

`Uninstall-Client.ps1` и `Uninstall-ClientWinRM.ps1` отказываются рекурсивно удалять целевую папку, если она оказывается общим корнем `WindowsInventoryLite` (определяется по наличию `server-config.json`) - это защищает данные сервера на совмещённой машине, даже если `-InstallPath` по ошибке указывает туда.
```

- [ ] **Step 3: Add a `CHANGELOG.md` entry**

Insert a new section at the top, immediately after the versioning note (line 7) and before `## [0.21.3] - 2026-07-21`:

```markdown
## [0.22.0] - 2026-07-22

### Changed

- Client-owned files on a co-located client+server install (`WindowsInventoryLiteClient.exe`, its local JSON report, `client-version.txt`, its debug/deploy logs) now live in their own `client-data` subfolder under `%ProgramData%\WindowsInventoryLite\`, instead of the bare root shared with the server's `server-bin`/`server-data`/`server-content`/`client-package` folders. `Install-Client.ps1` and `Deploy-ClientGpo.ps1` now also pass `--output`/`--debug-log-path` to the client service so its own report and debug log actually land there too, not just the copied executable. Already-installed clients migrate automatically the next time they're installed or updated (WinRM push, GPO startup script, or a manual reinstall) - `Deploy-ClientGpo.ps1`'s existing "is the running service's command line still what we expect" check now detects the old path on its own, no separate migration step needed. The old executable and `client-version.txt` are removed after a successful migration; old data files are left in place and can be removed by hand.
- **Fixed a real data-loss risk**: `Uninstall-Client.ps1` and `Uninstall-ClientWinRM.ps1` previously deleted their entire target folder recursively by default, which - on a machine running both the server and a local client - could delete the server's own `server-config.json` and data folders along with the client. Both scripts now refuse to recursively delete a folder that turns out to be the shared server root (detected by the presence of `server-config.json` there), and print a warning instead.

### PowerShell 5.1 Testing Note

`deploy\client\Deploy-ClientGpo.ps1`, `src\Install-Client.ps1`, and `src\Uninstall-ClientWinRM.ps1` each gained an `if ($MyInvocation.InvocationName -ne '.')` guard around their real install/uninstall logic, matching the pattern `src\Install-Wizard.ps1` already used - this lets Pester dot-source each script to unit-test its pure helper functions without performing a real service install/uninstall.
```

- [ ] **Step 4: Bump the version constant**

In `src\server\WindowsInventoryLiteServer.cs`, change:

```csharp
internal const string ProductVersion = "0.21.3";
```

to:

```csharp
internal const string ProductVersion = "0.22.0";
```

Do **not** change `src\client\WindowsInventoryLiteClient.cs`'s `ProductVersion` (stays `0.2.0`) - see this plan's Global Constraints for why.

- [ ] **Step 5: Rebuild the server and run the full verification suite**

Run: `powershell.exe -NoProfile -File src\Build-Server.ps1` (rebuilds the server and, as a documented side effect, both client targets, picking up the new `ProductVersion`)
Run: `<built server exe> --self-test`
Expected: all self-tests still pass (this plan touches no C# code paths any self-test covers, so the count should be unchanged from before this plan).

Run: `powershell.exe -NoProfile -Command "Invoke-Pester -Path tests -Output Detailed"`
Expected: PASS on the full suite, including all four new test files from Tasks 1-4.

- [ ] **Step 6: Commit**

```bash
git add README.md README_RU.md CHANGELOG.md src/server/WindowsInventoryLiteServer.cs
git commit -m "docs: document client-data layout; bump version to 0.22.0"
```

---

## Final Whole-Plan Review Note

Live verification (per this project's standing constraint against running real install/uninstall scripts on the dev machine) is deferred to the user's own test stand:

1. Confirm a real WinRM push (`Client actions` or `Client updates`) against an already-installed pre-0.22.0 client migrates it to `client-data` and removes the old bare-root `.exe`.
2. Confirm the migrated client's local JSON report and (if enabled) debug log actually appear under `client-data`, not the bare root.
3. Confirm `Uninstall-Client.ps1` (or the dashboard's WinRM uninstall) against a real co-located server+client machine prints the skip-warning and leaves `server-config.json` intact.

Flag these explicitly in the final whole-plan review dispatch so the reviewer knows this is expected, not a coverage gap to chase further.
