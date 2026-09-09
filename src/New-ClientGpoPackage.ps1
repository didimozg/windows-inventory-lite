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

    # How often the deployed client polls for assigned software-distribution
    # jobs (Windows Updates / Third-Party Software catalogs) - independent
    # of -IntervalHours. Default matches Deploy-ClientGpo.ps1's own default,
    # which this script's generated .cmd otherwise had no way to override:
    # every GPO package built here silently used 6 regardless of what an
    # admin configured elsewhere (the WinRM push path already exposes this
    # via Install-ClientWinRM.ps1/the wizard).
    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$SoftwareCheckIntervalHours = 6,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientNet35Path,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientNet40Path,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PackageSharePath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ServerUrl/Token/PackageSharePath land on a `set` line in the generated
# .cmd with no surrounding quotes (ServerUrl, PackageSharePath) or with
# quotes an embedded " can break out of (Token). A value containing &, |,
# <, >, ^, ", or a line break turns Install-ClientGpo.cmd into an
# attacker-controlled script that a GPO computer startup script later runs
# as SYSTEM on every deployed client.
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
Test-BatchSafeValue -Value $PackageSharePath -FieldName 'PackageSharePath'

# Restricts a file to Administrators+SYSTEM plus the identity actually
# running this script (whoever built the package, so they can still read/
# copy their own output regardless of whether they are a local admin) -
# same three-way grant Install-Server.ps1's own ApplyRestrictedConfigAcl
# uses. -OutputPath is a local staging location (its default is a
# project-relative dist\gpo-client, not a real GPO share - -PackageSharePath
# is the separate, explicit way to point the generated .cmd at wherever it
# is actually deployed), so restricting the generated .cmd here does not
# interfere with a later copy to SYSVOL or a custom share; that copy's own
# destination ACL governs what target machines can read.
function Set-RestrictedFileAcl {
    param([string]$FilePath)
    $adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $FilePath
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, 'FullControl', 'Allow')))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', 'Allow')))
    if ($currentSid -and $currentSid -ne $adminSid -and $currentSid -ne $systemSid) {
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($currentSid, 'FullControl', 'Allow')))
    }
    Set-Acl -LiteralPath $FilePath -AclObject $acl
}

$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $projectRoot -ChildPath 'dist\gpo-client'
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path -Path $projectRoot -ChildPath $OutputPath
}

if (-not $ClientNet35Path) {
    $ClientNet35Path = Join-Path -Path $projectRoot -ChildPath 'build\WindowsInventoryLiteClient-net35.exe'
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Build-Client.ps1') -OutputPath $ClientNet35Path -TargetFramework Net35
}
elseif (-not [System.IO.Path]::IsPathRooted($ClientNet35Path)) {
    $ClientNet35Path = Join-Path -Path $projectRoot -ChildPath $ClientNet35Path
}

if (-not $ClientNet40Path) {
    $ClientNet40Path = Join-Path -Path $projectRoot -ChildPath 'build\WindowsInventoryLiteClient-net40.exe'
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Build-Client.ps1') -OutputPath $ClientNet40Path -TargetFramework Net40
}
elseif (-not [System.IO.Path]::IsPathRooted($ClientNet40Path)) {
    $ClientNet40Path = Join-Path -Path $projectRoot -ChildPath $ClientNet40Path
}

if (-not (Test-Path -LiteralPath $ClientNet35Path)) {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Build-Client.ps1') -OutputPath $ClientNet35Path -TargetFramework Net35
}

if (-not (Test-Path -LiteralPath $ClientNet40Path)) {
    & (Join-Path -Path $PSScriptRoot -ChildPath 'Build-Client.ps1') -OutputPath $ClientNet40Path -TargetFramework Net40
}

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

$deploySource = Join-Path -Path $projectRoot -ChildPath 'deploy\client\Deploy-ClientGpo.ps1'
$cmdPath = Join-Path -Path $OutputPath -ChildPath 'Install-ClientGpo.cmd'
$legacyClientPath = Join-Path -Path $OutputPath -ChildPath 'WindowsInventoryLiteClient.exe'

if (Test-Path -LiteralPath $legacyClientPath) {
    Remove-Item -LiteralPath $legacyClientPath -Force
}

Copy-Item -LiteralPath $ClientNet35Path -Destination (Join-Path -Path $OutputPath -ChildPath 'WindowsInventoryLiteClient-net35.exe') -Force
Copy-Item -LiteralPath $ClientNet40Path -Destination (Join-Path -Path $OutputPath -ChildPath 'WindowsInventoryLiteClient-net40.exe') -Force
Copy-Item -LiteralPath $deploySource -Destination (Join-Path -Path $OutputPath -ChildPath 'Deploy-ClientGpo.ps1') -Force

$escapedServerUrl = $ServerUrl.Replace('%', '%%')
if (-not $PackageSharePath) {
    $PackageSharePath = '%~dp0'
}

$escapedPackageSharePath = $PackageSharePath.Replace('%', '%%').TrimEnd('\')
$lines = @(
    '@echo off',
    'setlocal',
    '',
    ('set PACKAGE_ROOT={0}' -f $escapedPackageSharePath),
    ('set SERVER_URL={0}' -f $escapedServerUrl),
    ('set INTERVAL_HOURS={0}' -f $IntervalHours),
    ('set SOFTWARE_CHECK_INTERVAL_HOURS={0}' -f $SoftwareCheckIntervalHours),
    'set DEPLOY_SCRIPT=%PACKAGE_ROOT%\Deploy-ClientGpo.ps1',
    'set WAIT_SECONDS=90',
    '',
    'set ARGS=-ServerUrl "%SERVER_URL%" -IntervalHours %INTERVAL_HOURS% -SoftwareCheckIntervalHours %SOFTWARE_CHECK_INTERVAL_HOURS%'
)

if ($Token) {
    $escapedToken = $Token.Replace('%', '%%')
    $lines += 'set ARGS=%ARGS% -Token "' + $escapedToken + '"'
}

$lines += ''
$lines += ':WAIT_PACKAGE'
$lines += 'if exist "%DEPLOY_SCRIPT%" goto RUN_DEPLOY'
$lines += 'if "%WAIT_SECONDS%"=="0" exit /b 2'
$lines += 'ping -n 2 127.0.0.1 >nul'
$lines += 'set /a WAIT_SECONDS-=1'
$lines += 'goto WAIT_PACKAGE'
$lines += ''
$lines += ':RUN_DEPLOY'
$lines += 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%DEPLOY_SCRIPT%" %ARGS%'
$lines += ''
$lines += 'exit /b %ERRORLEVEL%'

Set-Content -LiteralPath $cmdPath -Value $lines -Encoding ASCII
Set-RestrictedFileAcl -FilePath $cmdPath

Write-Host "GPO client package: $OutputPath"
Write-Host "Startup script: $cmdPath"
