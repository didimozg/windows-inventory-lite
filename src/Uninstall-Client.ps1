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
