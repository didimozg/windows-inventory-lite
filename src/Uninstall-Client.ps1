#requires -Version 2.0

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not $InstallPath) {
    $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'
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

if ((Test-Path -LiteralPath $InstallPath) -and $PSCmdlet.ShouldProcess($InstallPath, 'Remove client files')) {
    Remove-Item -LiteralPath $InstallPath -Recurse -Force
}

Write-Host "Client removed."
