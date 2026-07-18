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
# $PSScriptRoot is unset for a top-level script (not a module) on Windows
# PowerShell 2.0 - it only started working outside modules in PS 3.0. This
# script installs the client and runs on client machines, which this
# project still supports at the PS 2.0 floor, so it resolves its own path
# the PS 2.0-safe way instead.
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

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
# Windows 8 target, via Deploy-ClientGpo.ps1's identical pattern): the
# array-splat form silently corrupts the command line and sc.exe returns
# exit code 1639 (invalid command line), printing its own usage text
# instead of a specific error - every other Invoke-ServiceControl call
# (query/stop/delete/description/start) has no embedded quotes in its
# arguments and is unaffected, so only "create" gets this separate path.
# Building the full command as one string and invoking through cmd.exe /c,
# with the embedded quotes backslash-escaped the way cmd.exe's own parser
# expects, was confirmed to produce the correct command line on the same
# real target that failed with the array form.
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

Invoke-ServiceCreate -ServiceName $serviceName -BinPath $serviceCommand -DisplayName 'Windows Inventory Lite' -FailureMessage "Failed to create service. Run PowerShell as Administrator." | Out-Null
Invoke-ServiceControl -Arguments @('description', $serviceName, "Collects Windows, Office, activation, and software inventory for Windows Inventory Lite. Version $clientVersion.") -FailureMessage "Failed to set service description." | Out-Null
Write-Host "Service created: $serviceName"
Write-Host "Client version: $clientVersion"

if (-not $NoRun) {
    Invoke-ServiceControl -Arguments @('start', $serviceName) -FailureMessage "Failed to start service." | Out-Null
    Write-Host "Service started: $serviceName"
}

Write-Host "Client installed: $InstallPath"
