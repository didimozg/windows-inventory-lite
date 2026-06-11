#requires -Version 2.0

# WebPassword is written to server-config.json. It is not passed in the service command line.
# PSAvoidUsingPlainTextForPassword is suppressed because SecureString is not serializable to JSON
# without explicit conversion, and the config file ACL is the appropriate protection boundary.
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'WebPassword')]
[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ListenPrefix = 'http://+:8080/',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DataPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ContentPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientPackagePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientPackageSourcePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ServerExecutablePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Token,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WebUsername,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$WebPassword,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$InstallLogRetentionDays,

    [Parameter()]
    [switch]$OpenFirewall,

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

function ConvertTo-JsonString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return 'null'
    }

    $text = [string]$Value
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')

    foreach ($char in $text.ToCharArray()) {
        switch ($char) {
            '"' { [void]$builder.Append('\"') }
            '\' { [void]$builder.Append('\\') }
            ([char]8) { [void]$builder.Append('\b') }
            ([char]9) { [void]$builder.Append('\t') }
            ([char]10) { [void]$builder.Append('\n') }
            ([char]12) { [void]$builder.Append('\f') }
            ([char]13) { [void]$builder.Append('\r') }
            default {
                $code = [int][char]$char
                if ($code -lt 32) {
                    [void]$builder.Append(('\u{0:x4}' -f $code))
                }
                else {
                    [void]$builder.Append($char)
                }
            }
        }
    }

    [void]$builder.Append('"')
    return $builder.ToString()
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

function Write-ServerConfig {
    param(
        [string]$Path,
        [hashtable]$Config
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    $items = New-Object System.Collections.ArrayList
    foreach ($key in ($Config.Keys | Sort-Object)) {
        $value = $Config[$key]
        [void]$items.Add((ConvertTo-JsonString -Value $key) + ':' + (ConvertTo-JsonString -Value $value))
    }

    $json = '{' + (($items.ToArray()) -join ',') + '}'
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

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

if (-not $ConfigPath) {
    $ConfigPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-config.json'
}

$existingConfig = Read-ServerConfig -Path $ConfigPath

if (-not $InstallPath) {
    $savedInstallPath = Get-ConfigValue -Config $existingConfig -Name 'InstallPath'
    if ($savedInstallPath) {
        $InstallPath = $savedInstallPath
    }
    else {
        $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-bin'
    }
}

if (-not $DataPath) {
    $savedDataPath = Get-ConfigValue -Config $existingConfig -Name 'DataPath'
    if ($savedDataPath) {
        $DataPath = $savedDataPath
    }
    else {
        $DataPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-data'
    }
}

if (-not $ContentPath) {
    $savedContentPath = Get-ConfigValue -Config $existingConfig -Name 'ContentPath'
    if ($savedContentPath) {
        $ContentPath = $savedContentPath
    }
    else {
        $ContentPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-content'
    }
}

if (-not $ClientPackagePath) {
    $savedClientPackagePath = Get-ConfigValue -Config $existingConfig -Name 'ClientPackagePath'
    if ($savedClientPackagePath) {
        $ClientPackagePath = $savedClientPackagePath
    }
    else {
        $ClientPackagePath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-package'
    }
}

if (-not $ClientPackageSourcePath) {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $defaultClientPackageSourcePath = Join-Path -Path $projectRoot -ChildPath 'dist\gpo-client'
    if (Test-Path -LiteralPath $defaultClientPackageSourcePath) {
        $ClientPackageSourcePath = $defaultClientPackageSourcePath
    }
}

if (-not $PSBoundParameters.ContainsKey('ListenPrefix')) {
    $savedListenPrefix = Get-ConfigValue -Config $existingConfig -Name 'ListenPrefix'
    if ($savedListenPrefix) {
        $ListenPrefix = $savedListenPrefix
    }
}

if (-not $PSBoundParameters.ContainsKey('Token')) {
    $savedToken = Get-ConfigValue -Config $existingConfig -Name 'Token'
    if ($savedToken) {
        $Token = $savedToken
    }
}

if (-not $PSBoundParameters.ContainsKey('WebUsername')) {
    $savedWebUsername = Get-ConfigValue -Config $existingConfig -Name 'WebUsername'
    if ($savedWebUsername) {
        $WebUsername = $savedWebUsername
    }
}

if (-not $PSBoundParameters.ContainsKey('WebPassword')) {
    $savedWebPassword = Get-ConfigValue -Config $existingConfig -Name 'WebPassword'
    if ($savedWebPassword) {
        $WebPassword = $savedWebPassword
    }
}

if (-not $PSBoundParameters.ContainsKey('InstallLogRetentionDays')) {
    $savedInstallLogRetentionDays = Get-ConfigValue -Config $existingConfig -Name 'InstallLogRetentionDays'
    if ($savedInstallLogRetentionDays) {
        $InstallLogRetentionDays = [int]$savedInstallLogRetentionDays
    }
    else {
        $InstallLogRetentionDays = 30
    }
}

if (-not $ServerExecutablePath) {
    $projectRoot = Split-Path -Parent $PSScriptRoot
    $ServerExecutablePath = Join-Path -Path $projectRoot -ChildPath 'build\WindowsInventoryLiteServer.exe'
}

if (-not (Test-Path -LiteralPath $ServerExecutablePath)) {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Build-Server.ps1') -OutputPath $ServerExecutablePath
}

foreach ($path in @($InstallPath, $DataPath, $ContentPath, $ClientPackagePath)) {
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
}

foreach ($legacyName in @('WindowsLicenseInventoryServer', 'WindowsLicenseInventory')) {
    $null = & sc.exe query $legacyName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Removing legacy service: $legacyName"
        Invoke-ServiceControl -Arguments @('stop', $legacyName) -FailureMessage "Failed to stop legacy service $legacyName." -AllowedExitCodes @(0, 1062) | Out-Null
        Invoke-ServiceControl -Arguments @('delete', $legacyName) -FailureMessage "Failed to delete legacy service $legacyName." | Out-Null
    }
}

$serviceName = 'WindowsInventoryLite'
$servicePath = Join-Path -Path $InstallPath -ChildPath 'WindowsInventoryLiteServer.exe'
$null = & sc.exe query $serviceName 2>&1
if ($LASTEXITCODE -eq 0) {
    Invoke-ServiceControl -Arguments @('stop', $serviceName) -FailureMessage "Failed to stop existing service." -AllowedExitCodes @(0, 1062) | Out-Null
    Invoke-ServiceControl -Arguments @('delete', $serviceName) -FailureMessage "Failed to delete existing service." | Out-Null
    Wait-FileRelease -Path $servicePath
}

Copy-Item -LiteralPath $ServerExecutablePath -Destination $servicePath -Force
$serverVersion = (& $servicePath --version 2>&1 | Select-Object -First 1)
$dashboardSource = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'server\dashboard'
Copy-Item -Path (Join-Path -Path $dashboardSource -ChildPath '*') -Destination $ContentPath -Recurse -Force
$winRmInstallerSource = Join-Path -Path $PSScriptRoot -ChildPath 'Install-ClientWinRM.ps1'
$winRmInstallerPath = Join-Path -Path $InstallPath -ChildPath 'Install-ClientWinRM.ps1'
Copy-Item -LiteralPath $winRmInstallerSource -Destination $winRmInstallerPath -Force
$winRmUninstallerSource = Join-Path -Path $PSScriptRoot -ChildPath 'Uninstall-ClientWinRM.ps1'
$winRmUninstallerPath = Join-Path -Path $InstallPath -ChildPath 'Uninstall-ClientWinRM.ps1'
Copy-Item -LiteralPath $winRmUninstallerSource -Destination $winRmUninstallerPath -Force
$deployScriptSource = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'deploy\client\Deploy-ClientGpo.ps1'
$deployScriptBinPath = Join-Path -Path $InstallPath -ChildPath 'Deploy-ClientGpo.ps1'
if (Test-Path -LiteralPath $deployScriptSource) {
    Copy-Item -LiteralPath $deployScriptSource -Destination $deployScriptBinPath -Force
}

if ($ClientPackageSourcePath -and (Test-Path -LiteralPath $ClientPackageSourcePath)) {
    Copy-Item -Path (Join-Path -Path $ClientPackageSourcePath -ChildPath '*') -Destination $ClientPackagePath -Recurse -Force
}

$clientNet35PackagePath = Join-Path -Path $ClientPackagePath -ChildPath 'WindowsInventoryLiteClient-net35.exe'
$clientNet40PackagePath = Join-Path -Path $ClientPackagePath -ChildPath 'WindowsInventoryLiteClient-net40.exe'
$clientNet35Version = $null
$clientNet40Version = $null
if (Test-Path -LiteralPath $clientNet35PackagePath) {
    $clientNet35Version = (& $clientNet35PackagePath --version 2>&1 | Select-Object -First 1)
}
if (Test-Path -LiteralPath $clientNet40PackagePath) {
    $clientNet40Version = (& $clientNet40PackagePath --version 2>&1 | Select-Object -First 1)
}

function ConvertTo-ScPathToken {
    param([string]$Value)
    if ($Value -match ' ') { return '\"' + ($Value -replace '"', '\"') + '\"' }
    return $Value
}

$serviceCommand = (ConvertTo-ScPathToken $servicePath) + ' --prefix ' + $ListenPrefix + ' --data ' + (ConvertTo-ScPathToken $DataPath) + ' --content ' + (ConvertTo-ScPathToken $ContentPath) + ' --client-package ' + (ConvertTo-ScPathToken $ClientPackagePath) + ' --winrm-installer ' + (ConvertTo-ScPathToken $winRmInstallerPath) + ' --winrm-uninstaller ' + (ConvertTo-ScPathToken $winRmUninstallerPath)
$serviceCommand += ' --install-log-retention-days ' + $InstallLogRetentionDays
$serviceCommand += ' --config ' + (ConvertTo-ScPathToken $ConfigPath)

$config = @{
    ListenPrefix            = $ListenPrefix
    DataPath                = $DataPath
    InstallPath             = $InstallPath
    ContentPath             = $ContentPath
    ClientPackagePath       = $ClientPackagePath
    InstallLogRetentionDays = $InstallLogRetentionDays
    Token                   = $Token
    WebUsername             = $WebUsername
    WebPassword             = $WebPassword
}
Write-ServerConfig -Path $ConfigPath -Config $config

Invoke-ServiceControl -Arguments @('create', $serviceName, 'binPath=', $serviceCommand, 'start=', 'auto', 'DisplayName=', 'Windows Inventory Lite Server') -FailureMessage "Failed to create service. Run PowerShell as Administrator." | Out-Null
Invoke-ServiceControl -Arguments @('description', $serviceName, "Receives Windows Inventory Lite reports and serves the dashboard. Version $serverVersion.") -FailureMessage "Failed to set service description." | Out-Null

if ($OpenFirewall) {
    & netsh.exe advfirewall firewall add rule name="Windows Inventory Lite Server" dir=in action=allow protocol=TCP localport=8080 | Out-Null
}

if (-not $NoRun) {
    Invoke-ServiceControl -Arguments @('start', $serviceName) -FailureMessage "Failed to start service." | Out-Null
}

Write-Host "Server service: $serviceName"
Write-Host "Server version: $serverVersion"
Write-Host "Server config: $ConfigPath"
Write-Host "Data path: $DataPath"
Write-Host "Client package path: $ClientPackagePath"
if ($clientNet35Version) {
    Write-Host "Client package Net35 version: $clientNet35Version"
}
if ($clientNet40Version) {
    Write-Host "Client package Net40 version: $clientNet40Version"
}
Write-Host "Client action log retention days: $InstallLogRetentionDays"
Write-Host "Dashboard URL: $ListenPrefix"
if ($WebUsername) {
    Write-Host "Web auth user: $WebUsername"
}
