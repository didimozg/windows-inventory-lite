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
    [ValidateNotNullOrEmpty()]
    [string]$CertificateThumbprint,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CertificatePfxPath,

    # PFX password is written into the LocalMachine\My store import, not into
    # server-config.json or the service command line. Same plain-string tradeoff
    # as WebPassword above: SecureString is not portable across process boundaries
    # without extra conversion, and the store import happens once, in this process.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'CertificatePfxPassword')]
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CertificatePfxPassword,

    [Parameter()]
    [switch]$UseHttps,

    [Parameter()]
    [ValidateRange(1, 65535)]
    [int]$HttpsPort,

    # Refused at install time (and again from the dashboard Settings > General
    # page - see ConfigureServerSettings) unless HTTPS is enabled and working,
    # since disabling HTTP with no working HTTPS would leave the dashboard
    # completely unreachable with no way back in except editing
    # server-config.json by hand and restarting the service.
    [Parameter()]
    [switch]$DisableHttp,

    [Parameter()]
    [switch]$AdSyncEnabled,

    [Parameter()]
    [ValidateSet('on-report', 'timer')]
    [string]$AdSyncMode = 'on-report',

    [Parameter()]
    [ValidateRange(1, 8760)]
    [int]$AdSyncIntervalHours = 24,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AdDomain,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AdUsername,

    # AdPassword is written to server-config.json, not passed on the service command
    # line. Same plain-string tradeoff as WebPassword/CertificatePfxPassword above.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'AdPassword')]
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$AdPassword,

    [Parameter()]
    [switch]$DebugLogEnabled,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DebugLogPath,

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

# Encrypts a secret with Windows DPAPI (LocalMachine scope, not CurrentUser -
# the server may run as LocalSystem/NetworkService/a service account with no
# loaded interactive profile, so LocalMachine is the only scope any process
# on this machine, including the running service, can reliably decrypt with).
# Stored with a "dpapi:" prefix so WindowsInventoryLiteServer.exe's matching
# SecretProtector.Unprotect can tell an already-encrypted value apart from a
# legacy/hand-edited plaintext one (which it uses as-is rather than failing).
function Protect-AdPassword {
    param(
        [string]$PlainText
    )

    if (-not $PlainText) {
        return $PlainText
    }

    Add-Type -AssemblyName System.Security
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    return 'dpapi:' + [Convert]::ToBase64String($protectedBytes)
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

# CertificateThumbprint and UseHttps are re-persisted below from $existingConfig
# unless a new certificate is supplied on this run, so re-running this script for
# an unrelated setting (e.g. WebUsername) does not silently disable HTTPS that was
# configured earlier here or later from the dashboard Certificate tab.
# $certificateSuppliedThisRun must be captured before $CertificateThumbprint gets
# backfilled from saved config below - otherwise the auto-imply-UseHttps branch
# further down cannot tell "operator passed -CertificateThumbprint just now" apart
# from "this is just the value from last time", and would force UseHttps back on
# every re-run even after HTTPS was explicitly disabled from the dashboard.
$certificateSuppliedThisRun = $PSBoundParameters.ContainsKey('CertificateThumbprint') -or [bool]$CertificatePfxPath

if (-not $CertificatePfxPath -and -not $PSBoundParameters.ContainsKey('CertificateThumbprint')) {
    $savedThumbprint = Get-ConfigValue -Config $existingConfig -Name 'CertificateThumbprint'
    if ($savedThumbprint) {
        $CertificateThumbprint = $savedThumbprint
    }
}

if (-not $PSBoundParameters.ContainsKey('UseHttps')) {
    $savedUseHttps = Get-ConfigValue -Config $existingConfig -Name 'UseHttps'
    if ($savedUseHttps -eq 'true') {
        $UseHttps = $true
    }
}

if ($CertificatePfxPath) {
    if (-not (Test-Path -LiteralPath $CertificatePfxPath)) {
        throw "Certificate file not found: $CertificatePfxPath"
    }

    $securePfxPassword = ConvertTo-SecureString -String $CertificatePfxPassword -Force -AsPlainText
    $importedCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $CertificatePfxPath,
        $securePfxPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags] 'MachineKeySet, PersistKeySet, Exportable')

    if (-not $importedCertificate.HasPrivateKey) {
        throw "Certificate file has no private key: $CertificatePfxPath"
    }

    $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
    $certStore.Open('ReadWrite')
    try {
        $certStore.Add($importedCertificate)
    }
    finally {
        $certStore.Close()
    }

    $CertificateThumbprint = $importedCertificate.Thumbprint
    Write-Host "Imported certificate into LocalMachine\My. Thumbprint: $CertificateThumbprint"

    if (-not $PSBoundParameters.ContainsKey('UseHttps')) {
        $UseHttps = $true
    }
}
elseif ($certificateSuppliedThisRun -and $CertificateThumbprint -and -not $PSBoundParameters.ContainsKey('UseHttps')) {
    $UseHttps = $true
}

if ($UseHttps -and -not $CertificateThumbprint) {
    throw "UseHttps requires -CertificateThumbprint or -CertificatePfxPath."
}

$certificateFoundInStore = $false
if ($CertificateThumbprint) {
    $normalizedThumbprint = ($CertificateThumbprint -replace '[\s:-]', '').ToUpperInvariant()
    $thumbprintStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
    $thumbprintStore.Open('ReadOnly')
    try {
        $found = $thumbprintStore.Certificates.Find('FindByThumbprint', $normalizedThumbprint, $false)
        $certificateFoundInStore = $found.Count -gt 0
        if (-not $certificateFoundInStore) {
            Write-Warning "No certificate with thumbprint $normalizedThumbprint was found in LocalMachine\My yet. HTTPS connections will be refused until it is imported (rerun with -CertificatePfxPath, or import it and restart the service)."
        }
    }
    finally {
        $thumbprintStore.Close()
    }
    $CertificateThumbprint = $normalizedThumbprint
}

if (-not $PSBoundParameters.ContainsKey('HttpsPort')) {
    $savedHttpsPort = Get-ConfigValue -Config $existingConfig -Name 'HttpsPort'
    if ($savedHttpsPort) {
        $HttpsPort = [int]$savedHttpsPort
    }
    else {
        $HttpsPort = 8443
    }
}

if (-not $PSBoundParameters.ContainsKey('DisableHttp')) {
    $savedEnableHttp = Get-ConfigValue -Config $existingConfig -Name 'EnableHttp'
    if ($savedEnableHttp -eq 'false') {
        $DisableHttp = $true
    }
}

if (-not $PSBoundParameters.ContainsKey('AdSyncEnabled')) {
    $savedAdSyncEnabled = Get-ConfigValue -Config $existingConfig -Name 'AdSyncEnabled'
    if ($savedAdSyncEnabled -eq 'true') {
        $AdSyncEnabled = $true
    }
}
if (-not $PSBoundParameters.ContainsKey('AdSyncMode')) {
    $savedAdSyncMode = Get-ConfigValue -Config $existingConfig -Name 'AdSyncMode'
    if ($savedAdSyncMode -eq 'timer' -or $savedAdSyncMode -eq 'on-report') {
        $AdSyncMode = $savedAdSyncMode
    }
}
if (-not $PSBoundParameters.ContainsKey('AdSyncIntervalHours')) {
    $savedAdSyncIntervalHours = Get-ConfigValue -Config $existingConfig -Name 'AdSyncIntervalHours'
    if ($savedAdSyncIntervalHours) {
        $AdSyncIntervalHours = [int]$savedAdSyncIntervalHours
    }
}
if (-not $PSBoundParameters.ContainsKey('AdDomain')) {
    $savedAdDomain = Get-ConfigValue -Config $existingConfig -Name 'AdDomain'
    if ($savedAdDomain) {
        $AdDomain = $savedAdDomain
    }
}
if (-not $PSBoundParameters.ContainsKey('AdUsername')) {
    $savedAdUsername = Get-ConfigValue -Config $existingConfig -Name 'AdUsername'
    if ($savedAdUsername) {
        $AdUsername = $savedAdUsername
    }
}
# AdPassword is deliberately NOT reloaded from the saved config the way
# AdUsername is - re-running the installer without -AdPassword must not
# require re-supplying it if it's already saved, but the *existing* saved
# value is what server-config.json already has and $config.AdPassword
# below only overwrites it when a new one was actually passed this run.
$adUseServiceIdentity = [string]::IsNullOrEmpty($AdUsername)
if ($AdSyncEnabled -and -not $adUseServiceIdentity -and -not $AdPassword -and -not (Get-ConfigValue -Config $existingConfig -Name 'AdPassword')) {
    throw "-AdUsername was supplied without -AdPassword, and no AD password is already saved - provide -AdPassword."
}

if (-not $PSBoundParameters.ContainsKey('DebugLogEnabled')) {
    $savedDebugLogEnabled = Get-ConfigValue -Config $existingConfig -Name 'DebugLogEnabled'
    if ($savedDebugLogEnabled -eq 'true') {
        $DebugLogEnabled = $true
    }
}
if (-not $PSBoundParameters.ContainsKey('DebugLogPath')) {
    $savedDebugLogPath = Get-ConfigValue -Config $existingConfig -Name 'DebugLogPath'
    if ($savedDebugLogPath) {
        $DebugLogPath = $savedDebugLogPath
    }
}

if ($DisableHttp -and -not $UseHttps) {
    throw "-DisableHttp requires -UseHttps (or an already-configured working HTTPS setup) - disabling HTTP with no HTTPS would make the dashboard unreachable."
}

# Checking the store, not just $UseHttps/$CertificateThumbprint being set: a
# previously-working HTTPS setup (UseHttps=true reloaded from server-config.json)
# can have its certificate deleted from LocalMachine\My by something outside
# this script (manual cleanup, another admin, an expiry sweep) between runs.
# Without this, a plain reinstall/update with -DisableHttp already saved from
# a prior run would only warn about the missing certificate above and still
# proceed - leaving the service with HTTP off and HTTPS unable to start,
# fully unreachable from the very first start after install.
if ($DisableHttp -and $UseHttps -and -not $certificateFoundInStore) {
    throw "-DisableHttp requires a working HTTPS setup, but the configured certificate (thumbprint $CertificateThumbprint) was not found in LocalMachine\My. Import it first (-CertificatePfxPath), or drop -DisableHttp until it is confirmed working."
}

if ($UseHttps -and -not $DisableHttp) {
    $listenPrefixPort = $null
    try {
        $listenPrefixPort = ([Uri]($ListenPrefix -replace '\+', 'localhost')).Port
    }
    catch {
    }
    if ($listenPrefixPort -and $HttpsPort -eq $listenPrefixPort) {
        throw "-HttpsPort must be different from the HTTP port ($listenPrefixPort) when both are enabled."
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

function ConvertTo-ServiceArgValue {
    param([string]$Value)
    return $Value -replace '"', '\"'
}

function Set-RestrictedFileAcl {
    param([string]$FilePath)
    # Use well-known SIDs, not literal account names: 'Administrators'/'SYSTEM'
    # only resolve on English-locale Windows. The builtin groups have a
    # localized display name on non-English installs, which throws
    # IdentityNotMappedException from AddAccessRule with a literal string.
    $adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $acl = Get-Acl -LiteralPath $FilePath
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, 'FullControl', 'Allow')
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', 'Allow')
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -LiteralPath $FilePath -AclObject $acl
}

# --prefix is deliberately NOT included here, unlike --data/--content/etc.
# The HTTP and HTTPS ports can both be changed later from the dashboard
# Settings > General page (InventoryServer.ApplySlotState, driven by
# ConfigureServerSettings); that only rewrites ListenPrefix/HttpsPort/
# EnableHttp in server-config.json, not this service's start command. If
# --prefix were baked in here too, a plain service restart or reboot would
# silently revert to whatever port was set at install time. The server reads
# ListenPrefix/HttpsPort/EnableHttp from --config on every startup instead,
# same as WebUsername, UseHttps, and the other dashboard-only settings.
$serviceCommand = '"' + (ConvertTo-ServiceArgValue $servicePath) + '" --data "' + (ConvertTo-ServiceArgValue $DataPath) + '" --content "' + (ConvertTo-ServiceArgValue $ContentPath) + '" --client-package "' + (ConvertTo-ServiceArgValue $ClientPackagePath) + '" --winrm-installer "' + (ConvertTo-ServiceArgValue $winRmInstallerPath) + '" --winrm-uninstaller "' + (ConvertTo-ServiceArgValue $winRmUninstallerPath) + '"'
$serviceCommand += ' --install-log-retention-days ' + $InstallLogRetentionDays
$serviceCommand += ' --config "' + (ConvertTo-ServiceArgValue $ConfigPath) + '"'

# Start from whatever is already on disk instead of a fresh hashtable, so
# settings this script does not know about (e.g. StaleHours, which is only
# ever set from the dashboard Settings > General page) survive a reinstall.
# Write-ServerConfig replaces the whole file rather than merging, so anything
# left out here would otherwise be silently deleted on every rerun.
$config = @{}
foreach ($key in $existingConfig.Keys) {
    $config[$key] = $existingConfig[$key]
}
$config.ListenPrefix            = $ListenPrefix
$config.DataPath                = $DataPath
$config.InstallPath             = $InstallPath
$config.ContentPath             = $ContentPath
$config.ClientPackagePath       = $ClientPackagePath
$config.InstallLogRetentionDays = $InstallLogRetentionDays
$config.Token                   = $Token
$config.WebUsername             = $WebUsername
$config.WebPassword             = $WebPassword
$config.UseHttps                = if ($UseHttps) { 'true' } else { 'false' }
$config.CertificateThumbprint   = $CertificateThumbprint
$config.HttpsPort               = $HttpsPort
$config.EnableHttp              = if ($DisableHttp) { 'false' } else { 'true' }
$config.AdSyncEnabled           = if ($AdSyncEnabled) { 'true' } else { 'false' }
$config.AdSyncMode              = $AdSyncMode
$config.AdSyncIntervalHours     = $AdSyncIntervalHours
$config.AdDomain                = $AdDomain
$config.AdUseServiceIdentity    = if ($adUseServiceIdentity) { 'true' } else { 'false' }
$config.AdUsername              = $AdUsername
if ($AdPassword) {
    $config.AdPassword = Protect-AdPassword -PlainText $AdPassword
}
$config.DebugLogEnabled         = if ($DebugLogEnabled) { 'true' } else { 'false' }
$config.DebugLogPath            = $DebugLogPath
Write-ServerConfig -Path $ConfigPath -Config $config
Set-RestrictedFileAcl -FilePath $ConfigPath

Invoke-ServiceControl -Arguments @('create', $serviceName, 'binPath=', $serviceCommand, 'start=', 'auto', 'DisplayName=', 'Windows Inventory Lite Server') -FailureMessage "Failed to create service. Run PowerShell as Administrator." | Out-Null
Invoke-ServiceControl -Arguments @('description', $serviceName, "Receives Windows Inventory Lite reports and serves the dashboard. Version $serverVersion.") -FailureMessage "Failed to set service description." | Out-Null

if ($OpenFirewall) {
    if (-not $DisableHttp) {
        $httpFirewallPort = if ($listenPrefixPort) { $listenPrefixPort } else { 8080 }
        & netsh.exe advfirewall firewall add rule name="Windows Inventory Lite Server (HTTP)" dir=in action=allow protocol=TCP localport=$httpFirewallPort | Out-Null
    }
    if ($UseHttps) {
        & netsh.exe advfirewall firewall add rule name="Windows Inventory Lite Server (HTTPS)" dir=in action=allow protocol=TCP localport=$HttpsPort | Out-Null
    }
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
if ($DisableHttp) {
    Write-Host "HTTP: disabled"
}
else {
    Write-Host "Dashboard URL (HTTP): $ListenPrefix"
}
if ($WebUsername) {
    Write-Host "Web auth user: $WebUsername"
}
if ($UseHttps) {
    Write-Host "HTTPS: enabled on port $HttpsPort, certificate thumbprint $CertificateThumbprint"
}
elseif ($CertificateThumbprint) {
    Write-Host "HTTPS: certificate imported (thumbprint $CertificateThumbprint) but not enabled. Rerun with -UseHttps to switch on."
}
