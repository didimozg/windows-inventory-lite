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

# installPath/contentPath/clientPackagePath/dataPath below all come from
# server-config.json (an operator-supplied -ConfigPath), with no validation
# before reaching Remove-Item -Recurse -Force further down - a malformed or
# maliciously-crafted config could point one of them at C:\, C:\Windows, or
# similar. Not reachable via any HTTP API today (none of these keys are
# writable through SaveServerConfigValues - they're only ever set by
# Install-Server.ps1 from its own install-time parameters), but the same
# "not reachable today" reasoning already stopped being true once for this
# project's Linux install-path field. This can't use the same
# %ProgramData%-only allowlist the Windows client-side sinks use, since
# -InstallPath is a documented, supported custom-path option for
# Install-Server.ps1 (any real custom install must still be removable) -
# a shape guard against known-catastrophic locations instead.
function Test-IsPathSafeToRemove {
    param([string]$Path)

    $resolved = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    $driveRoot = [System.IO.Path]::GetPathRoot($resolved).TrimEnd('\')
    if ($resolved -eq $driveRoot) {
        throw "Refusing to delete '$Path' (resolves to '$resolved') - a bare drive root is never a real Windows Inventory Lite install path."
    }

    $systemPaths = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') }
    foreach ($systemPath in $systemPaths) {
        if ($resolved -eq $systemPath) {
            throw "Refusing to delete '$Path' (resolves to '$resolved') - this is a well-known Windows system directory, not a real Windows Inventory Lite install path."
        }
    }
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
        Test-IsPathSafeToRemove -Path $path
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}

if ($RemoveData) {
    if ((Test-Path -LiteralPath $dataPath) -and $PSCmdlet.ShouldProcess($dataPath, 'Remove inventory data')) {
        Test-IsPathSafeToRemove -Path $dataPath
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
