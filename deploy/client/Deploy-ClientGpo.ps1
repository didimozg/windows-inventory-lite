#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerUrl,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Token,

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$IntervalHours = 6,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PackageClientPath,

    [Parameter()]
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ServerUrl/Token end up embedded in the sc.exe command line Invoke-ServiceCreate
# builds below and runs via cmd.exe /c - the surrounding double quotes do NOT
# protect &, |, <, >, ^ from being parsed as live cmd.exe operators (a well-known
# cmd.exe quoting quirk), so an unvalidated value here is a command-injection
# path to code execution as whatever identity is creating this service (often
# the calling server's own privileged WinRM/service account). Reject the same
# characters New-ClientGpoPackage.ps1's Test-BatchSafeValue already rejects for
# the GPO .cmd generation path - this script is the other place those same
# values eventually land.
function Test-BatchSafeValue {
    param([string]$Value, [string]$FieldName)
    if ([string]::IsNullOrEmpty($Value)) { return }
    $unsafeChars = [char[]]('"', '&', '|', '<', '>', '^', "`r", "`n")
    if ($Value.IndexOfAny($unsafeChars) -ge 0) {
        throw "$FieldName contains a character that is not allowed here (double quote, &, |, <, >, ^, or a line break)."
    }
}
Test-BatchSafeValue -Value $ServerUrl -FieldName 'ServerUrl'
Test-BatchSafeValue -Value $Token -FieldName 'Token'

$ServiceName = 'WindowsInventoryLiteClient'
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDirectory) {
    $ScriptDirectory = (Get-Location).Path
}

function Write-DeployLog {
    param([string]$Message)

    $directory = Split-Path -Parent $LogPath
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    $line = '{0} {1}' -f (Get-Date).ToString('s'), $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    Write-Host $line
}

function Invoke-ServiceControl {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$FailureMessage,

        [Parameter()]
        [int[]]$AllowedExitCodes = @(0)
    )

    $output = & sc.exe @Arguments 2>&1
    if ($AllowedExitCodes -notcontains $LASTEXITCODE) {
        throw ($FailureMessage + " sc.exe exit code: $LASTEXITCODE. Output: " + (($output | Out-String).Trim()))
    }

    return $output
}

# sc.exe create's binPath= value must itself contain embedded double quotes
# (around the exe path, since it can contain spaces) - passing that as one
# element of a PowerShell array via "& sc.exe @Arguments" does not reliably
# preserve those embedded quotes in the raw command line sc.exe receives on
# every PowerShell engine. Confirmed live (Windows PowerShell 4.0, a real
# Windows 8 target): the array-splat form silently corrupts the command
# line and sc.exe returns exit code 1639 (invalid command line), printing
# its own usage text instead of a specific error - every other
# Invoke-ServiceControl call (query/stop/delete/description/start) has no
# embedded quotes in its arguments and is unaffected, so only "create" gets
# this separate path. Building the full command as one string and invoking
# through cmd.exe /c, with the embedded quotes backslash-escaped the way
# cmd.exe's own parser expects, was confirmed to produce the correct
# command line on the same real target that failed with the array form.
function Invoke-ServiceCreate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [string]$BinPath,

        [Parameter(Mandatory = $true)]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [string]$FailureMessage
    )

    $escapedBinPath = $BinPath.Replace('"', '\"')
    $commandLine = 'sc.exe create ' + $ServiceName + ' binPath= "' + $escapedBinPath + '" start= auto DisplayName= "' + $DisplayName + '"'
    $output = cmd.exe /c $commandLine 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($FailureMessage + " sc.exe exit code: $LASTEXITCODE. Output: " + (($output | Out-String).Trim()))
    }

    return $output
}

function Wait-FileRelease {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter()]
        [int]$TimeoutSeconds = 30
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        try {
            $stream = [System.IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
            $stream.Close()
            return
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    } while ((Get-Date) -lt $deadline)

    throw "File is still locked: $Path"
}

function Get-ExeVersion {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        return ((& $Path --version 2>&1 | Select-Object -First 1) -as [string]).Trim()
    }
    catch {
        return $null
    }
}

function Get-InstalledVersion {
    param([string]$InstallDirectory)

    $versionPath = Join-Path -Path $InstallDirectory -ChildPath 'client-version.txt'
    if (Test-Path -LiteralPath $versionPath) {
        try {
            return ([System.IO.File]::ReadAllText($versionPath, [System.Text.Encoding]::UTF8)).Trim()
        }
        catch {
            return $null
        }
    }

    return $null
}

function Save-InstalledVersion {
    param(
        [string]$InstallDirectory,
        [string]$Version
    )

    $versionPath = Join-Path -Path $InstallDirectory -ChildPath 'client-version.txt'
    [System.IO.File]::WriteAllText($versionPath, $Version, (New-Object System.Text.UTF8Encoding($false)))
}

function Test-ServiceExists {
    $null = & sc.exe query $ServiceName 2>&1
    return ($LASTEXITCODE -eq 0)
}

function Get-ServiceBinaryPath {
    $output = & sc.exe qc $ServiceName 2>&1
    if ($LASTEXITCODE -ne 0) {
        return $null
    }

    foreach ($line in $output) {
        if ($line -match 'BINARY_PATH_NAME\s*:\s*(.+)$') {
            return $matches[1].Trim()
        }
    }

    return $null
}

function ConvertTo-ServiceArgValue {
    param([string]$Value)
    return $Value -replace '"', '\"'
}

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

function Test-Administrator {
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Get-CurrentIdentityName {
    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {
        return 'Unknown'
    }
}

function Get-IsWindows7Family {
    $version = [Environment]::OSVersion.Version
    return ($version.Major -eq 6 -and $version.Minor -le 1)
}

function Get-DefaultPackageClientPath {
    if (Get-IsWindows7Family) {
        return Join-Path -Path $ScriptDirectory -ChildPath 'WindowsInventoryLiteClient-net35.exe'
    }

    return Join-Path -Path $ScriptDirectory -ChildPath 'WindowsInventoryLiteClient-net40.exe'
}

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
