#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerUrl,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ServerSharePath,

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
    [string]$ClientExecutablePath,

    [Parameter()]
    [switch]$NoRun
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

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
        [int]$TimeoutSeconds = 20
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

function ConvertTo-ServiceArgValue {
    param([string]$Value)
    return $Value -replace '"', '\"'
}

if (-not $InstallPath) {
    $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'
}

$serviceName = 'WindowsInventoryLiteClient'
$buildScript = Join-Path -Path $PSScriptRoot -ChildPath 'Build-Client.ps1'

if (-not $ClientExecutablePath) {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $ClientExecutablePath = Join-Path -Path $projectRoot -ChildPath 'build\WindowsInventoryLiteClient.exe'
}

if (-not (Test-Path -LiteralPath $ClientExecutablePath)) {
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
$null = & sc.exe query $serviceName 2>&1
if ($LASTEXITCODE -eq 0) {
    Invoke-ServiceControl -Arguments @('stop', $serviceName) -FailureMessage "Failed to stop existing service." -AllowedExitCodes @(0, 1062) | Out-Null
    Invoke-ServiceControl -Arguments @('delete', $serviceName) -FailureMessage "Failed to delete existing service." | Out-Null
    Wait-FileRelease -Path $servicePath
}

Copy-Item -LiteralPath $ClientExecutablePath -Destination $servicePath -Force
$clientVersion = (& $servicePath --version 2>&1 | Select-Object -First 1)

$serviceCommand = '"' + (ConvertTo-ServiceArgValue $servicePath) + '" --server-url "' + (ConvertTo-ServiceArgValue $ServerUrl) + '" --interval-hours ' + $IntervalHours
if ($ServerSharePath) {
    $serviceCommand += ' --share "' + (ConvertTo-ServiceArgValue $ServerSharePath) + '"'
}
if ($Token) {
    $serviceCommand += ' --token "' + (ConvertTo-ServiceArgValue $Token) + '"'
}

Invoke-ServiceControl -Arguments @('create', $serviceName, 'binPath=', $serviceCommand, 'start=', 'auto', 'DisplayName=', 'Windows Inventory Lite') -FailureMessage "Failed to create service. Run PowerShell as Administrator." | Out-Null
Invoke-ServiceControl -Arguments @('description', $serviceName, "Collects Windows, Office, activation, and software inventory for Windows Inventory Lite. Version $clientVersion.") -FailureMessage "Failed to set service description." | Out-Null
Write-Host "Service created: $serviceName"
Write-Host "Client version: $clientVersion"

if (-not $NoRun) {
    Invoke-ServiceControl -Arguments @('start', $serviceName) -FailureMessage "Failed to start service." | Out-Null
    Write-Host "Service started: $serviceName"
}

Write-Host "Client installed: $InstallPath"
