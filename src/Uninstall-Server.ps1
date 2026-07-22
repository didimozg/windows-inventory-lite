#requires -Version 2.0

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [Parameter()]
    [switch]$RemoveData
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-ConfigValue {
    param(
        [object]$Config,
        [string]$Name
    )

    if ($Config -and $Config.ContainsKey($Name)) {
        return $Config[$Name]
    }

    return $null
}

function Read-ServerConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return @{}
    }

    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        $config = $serializer.DeserializeObject($text)
        if ($config) {
            return $config
        }
    }
    catch {
        Write-Warning "Failed to read server config: $($_.Exception.Message)"
    }

    return @{}
}

if (-not $ConfigPath) {
    $ConfigPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-config.json'
}

$existingConfig = Read-ServerConfig -Path $ConfigPath

$installPath = Get-ConfigValue -Config $existingConfig -Name 'InstallPath'
if (-not $installPath) {
    $installPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-bin'
}

$dataPath = Get-ConfigValue -Config $existingConfig -Name 'DataPath'
if (-not $dataPath) {
    $dataPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-data'
}

$contentPath = Get-ConfigValue -Config $existingConfig -Name 'ContentPath'
if (-not $contentPath) {
    $contentPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-content'
}

$clientPackagePath = Get-ConfigValue -Config $existingConfig -Name 'ClientPackagePath'
if (-not $clientPackagePath) {
    $clientPackagePath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-package'
}

$certificateThumbprint = Get-ConfigValue -Config $existingConfig -Name 'CertificateThumbprint'

$serviceName = 'WindowsInventoryLite'
$null = & sc.exe query $serviceName 2>&1
if ($LASTEXITCODE -eq 0 -and $PSCmdlet.ShouldProcess($serviceName, 'Stop and delete service')) {
    & sc.exe stop $serviceName | Out-Null
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

# netsh silently no-ops when a named rule doesn't exist (prints "No rules
# match the specified criteria" without a nonzero exit code we could rely
# on), so this always attempts the delete rather than probing first - safe
# either way since & calls don't participate in $ErrorActionPreference.
foreach ($ruleName in @('Windows Inventory Lite Server (HTTP)', 'Windows Inventory Lite Server (HTTPS)')) {
    if ($PSCmdlet.ShouldProcess($ruleName, 'Remove firewall rule if present')) {
        & netsh.exe advfirewall firewall delete rule name="$ruleName" | Out-Null
    }
}

foreach ($path in @($installPath, $contentPath, $clientPackagePath)) {
    if ((Test-Path -LiteralPath $path) -and $PSCmdlet.ShouldProcess($path, 'Remove directory')) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}

if ($RemoveData) {
    if ((Test-Path -LiteralPath $dataPath) -and $PSCmdlet.ShouldProcess($dataPath, 'Remove inventory data')) {
        Remove-Item -LiteralPath $dataPath -Recurse -Force
    }
    if ((Test-Path -LiteralPath $ConfigPath) -and $PSCmdlet.ShouldProcess($ConfigPath, 'Remove server configuration')) {
        Remove-Item -LiteralPath $ConfigPath -Force
    }
}
else {
    Write-Host "Inventory data preserved at: $dataPath"
    Write-Host "Server configuration preserved at: $ConfigPath"
}

if ($certificateThumbprint) {
    Write-Host "A certificate may have been imported into LocalMachine\My by this server (thumbprint $certificateThumbprint)."
    Write-Host "It was not removed automatically - it may be used by other services on this host."
    Write-Host "To remove it manually: Remove-Item Cert:\LocalMachine\My\$certificateThumbprint"
}

Write-Host "Server removed."
