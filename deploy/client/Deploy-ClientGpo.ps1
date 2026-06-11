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

$ServiceName = 'WindowsInventoryLiteClient'
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDirectory) {
    $ScriptDirectory = (Get-Location).Path
}
$LogPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\Logs\gpo-deploy.log'
# $CentralLogPath = Join-Path -Path (Join-Path -Path $ScriptDirectory -ChildPath 'Logs') -ChildPath ($env:COMPUTERNAME + '.log')

function Write-DeployLog {
    param([string]$Message)

    $directory = Split-Path -Parent $LogPath
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    $line = '{0} {1}' -f (Get-Date).ToString('s'), $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    # try {
    #     $centralDirectory = Split-Path -Parent $CentralLogPath
    #     if (-not (Test-Path -LiteralPath $centralDirectory)) {
    #         New-Item -Path $centralDirectory -ItemType Directory -Force | Out-Null
    #     }
    #     Add-Content -LiteralPath $CentralLogPath -Value $line -Encoding UTF8
    # }
    # catch {
    # }
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

function Get-DesiredServiceCommand {
    param(
        [string]$ServicePath,
        [string]$Url,
        [int]$Hours,
        [string]$SharedToken
    )

    # PS 2.0 on Windows 7 mishandles native-command arguments that start with ".
    # Quote the exe path only when it contains a space; use \" form so the
    # resulting $command string does not start with " and splatting works correctly.
    if ($ServicePath -match ' ') {
        $exeToken = '\"' + ($ServicePath -replace '"', '\"') + '\"'
    } else {
        $exeToken = $ServicePath
    }
    $command = $exeToken + ' --server-url ' + $Url + ' --interval-hours ' + $Hours
    if ($SharedToken) {
        $command += ' --token ' + $SharedToken
    }

    return $command
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

if (-not $InstallPath) {
    $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'
}

if (-not $PackageClientPath) {
    $PackageClientPath = Get-DefaultPackageClientPath
}

if (-not (Test-Path -LiteralPath $PackageClientPath)) {
    throw "Package client executable was not found: $PackageClientPath"
}

Write-DeployLog "Current identity: $(Get-CurrentIdentityName)"
if (-not (Test-Administrator)) {
    throw 'Administrator rights are required to install or update the WindowsInventoryLite service. Use a Computer Startup Script GPO, not a User Logon Script, or run PowerShell as Administrator for manual testing.'
}

if (-not (Test-Path -LiteralPath $InstallPath)) {
    New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
}

$servicePath = Join-Path -Path $InstallPath -ChildPath 'WindowsInventoryLiteClient.exe'
$packageVersion = Get-ExeVersion -Path $PackageClientPath
$installedVersion = Get-InstalledVersion -InstallDirectory $InstallPath
$desiredCommand = Get-DesiredServiceCommand -ServicePath $servicePath -Url $ServerUrl -Hours $IntervalHours -SharedToken $Token
$currentCommand = Get-ServiceBinaryPath
$serviceExists = Test-ServiceExists
$needsInstall = $Force -or (-not $serviceExists) -or ($packageVersion -ne $installedVersion) -or ($currentCommand -ne $desiredCommand)

Write-DeployLog "Package version: $packageVersion"
Write-DeployLog "Installed version: $installedVersion"
Write-DeployLog "Package client path: $PackageClientPath"
# Write-DeployLog "Central log path: $CentralLogPath"

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

Invoke-ServiceControl -Arguments @('create', $ServiceName, 'binPath=', $desiredCommand, 'start=', 'auto', 'DisplayName=', 'Windows Inventory Lite') -FailureMessage 'Failed to create service.' | Out-Null
Invoke-ServiceControl -Arguments @('description', $ServiceName, "Collects Windows, Office, activation, and software inventory for Windows Inventory Lite. Version $installedVersion.") -FailureMessage 'Failed to set service description.' | Out-Null
Invoke-ServiceControl -Arguments @('start', $ServiceName) -FailureMessage 'Failed to start service.' | Out-Null

Write-DeployLog "Client service deployed. Version: $installedVersion"
