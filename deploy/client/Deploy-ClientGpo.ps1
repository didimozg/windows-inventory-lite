#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerUrl,

    # No [ValidateNotNullOrEmpty()] here, unlike every other optional string
    # parameter below - PowerShell re-validates a parameter's own attributes
    # on EVERY assignment to that variable within the script, not just at
    # initial binding, and this one is reassigned further down (the
    # WIL_INGESTION_TOKEN environment fallback) when no -Token was
    # supplied - confirmed live: that fallback threw
    # ValidationMetadataException on every run with neither set, since
    # $env:WIL_INGESTION_TOKEN resolves to an empty value in that case.
    # Test-BatchSafeValue already treats null/empty as "nothing to check"
    # on its own, so the attribute was never load-bearing here.
    [Parameter()]
    [string]$Token,

    # Same no-[ValidateNotNullOrEmpty()] reasoning as -Token above - this is
    # reassigned further down from WIL_ENROLLMENT_TOKEN when not supplied
    # directly. Lets a GPO-deployed client (Install-ClientGpo.cmd, via
    # New-ClientGpoPackage.ps1) obtain its own real per-machine ingestion
    # token on first contact instead of embedding the real shared -Token in
    # a SYSVOL-readable .cmd file - see EnrollClient/docs/threat-model.md.
    [Parameter()]
    [string]$EnrollmentToken,

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$IntervalHours = 6,

    # How often the client polls for assigned software-distribution jobs
    # (Windows Updates / Third-Party Software catalogs). Independent of
    # -IntervalHours: the client runs the two on separate timers. Default
    # matches the client binary's own default.
    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$SoftwareCheckIntervalHours = 6,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PackageClientPath,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$RequireHttpsSelfUpdate,

    [Parameter()]
    [switch]$AllowHttpSelfUpdateFallback,

    [Parameter()]
    [switch]$RequireSignedSelfUpdate
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ServerUrl ends up embedded in the sc.exe command line Invoke-ServiceCreate
# builds below and runs via cmd.exe /c - the surrounding double quotes do NOT
# protect &, |, <, >, ^ from being parsed as live cmd.exe operators (a well-known
# cmd.exe quoting quirk), so an unvalidated value here is a command-injection
# path to code execution as whatever identity is creating this service (often
# the calling server's own privileged WinRM/service account). Reject the same
# characters New-ClientGpoPackage.ps1's Test-BatchSafeValue already rejects for
# the GPO .cmd generation path - this script is the other place those same
# values eventually land. Token no longer reaches the command line (see
# Set-ServiceEnvironmentToken) but is still checked here as defense in depth,
# since it is still written into a registry value derived from this string.
function Test-BatchSafeValue {
    param([string]$Value, [string]$FieldName)
    if ([string]::IsNullOrEmpty($Value)) { return }
    $unsafeChars = [char[]]('"', '&', '|', '<', '>', '^', "`r", "`n")
    if ($Value.IndexOfAny($unsafeChars) -ge 0) {
        throw "$FieldName contains a character that is not allowed here (double quote, &, |, <, >, ^, or a line break)."
    }
}
# Falls back to WIL_INGESTION_TOKEN when -Token is not supplied - lets
# Install-ClientWinRM.ps1's RemoteDeployScriptBlock set the token as an
# environment variable on the remote powershell.exe process it spawns to
# run this script, instead of passing it as a literal -Token argument,
# which would otherwise be visible via Get-Process/WMI Win32_Process.CommandLine
# on that REMOTE target for the run's duration - the same class of exposure
# already closed for the Windows client service's own ImagePath and for the
# server's own child-process invocations. An explicit -Token still wins, so
# manual/standalone invocation is unaffected.
if (-not $Token) {
    $Token = $env:WIL_INGESTION_TOKEN
}
if (-not $EnrollmentToken) {
    $EnrollmentToken = $env:WIL_ENROLLMENT_TOKEN
}

Test-BatchSafeValue -Value $ServerUrl -FieldName 'ServerUrl'
Test-BatchSafeValue -Value $Token -FieldName 'Token'
Test-BatchSafeValue -Value $EnrollmentToken -FieldName 'EnrollmentToken'
Test-BatchSafeValue -Value $InstallPath -FieldName 'InstallPath'

$ServiceName = 'WindowsInventoryLiteClient'
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDirectory) {
    $ScriptDirectory = (Get-Location).Path
}

function Write-DeployLog {
    param([string]$Message)

    $directory = Split-Path -Parent $LogPath
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    $line = '{0} {1}' -f (Get-Date).ToString('s'), $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
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

# sc.exe create's binPath= value must itself contain embedded double quotes
# (around the exe path, since it can contain spaces) - passing that as one
# element of a PowerShell array via "& sc.exe @Arguments" does not reliably
# preserve those embedded quotes in the raw command line sc.exe receives on
# every PowerShell engine. Confirmed live (Windows PowerShell 4.0, a real
# Windows 8 target): the array-splat form silently corrupts the command
# line and sc.exe returns exit code 1639 (invalid command line), printing
# its own usage text instead of a specific error - every other
# Invoke-ServiceControl call (query/stop/delete/description/start) has no
# embedded quotes in its arguments and is unaffected, so only "create" gets
# this separate path. Building the full command as one string and invoking
# through cmd.exe /c, with the embedded quotes backslash-escaped the way
# cmd.exe's own parser expects, was confirmed to produce the correct
# command line on the same real target that failed with the array form.
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
        # 2>$null, not 2>&1: $ErrorActionPreference = 'Stop' (set script-wide,
        # above) plus 2>&1 is the exact combination Install-ClientDebianSSH.ps1
        # documents turning harmless native-command stderr text into a
        # terminating error on some PowerShell engine versions (see
        # Invoke-NativeAllowingStderr there). Get-ExeVersion only needs
        # stdout - if this ever silently returned $null instead of the real
        # version, $packageVersion would never equal $installedVersion,
        # forcing $needsInstall = $true on every run. Discarding stderr
        # entirely removes that risk outright, which is simpler than routing
        # through Invoke-NativeAllowingStderr (that helper exists for a case
        # that DOES need the stderr text).
        return ((& $Path --version 2>$null | Select-Object -First 1) -as [string]).Trim()
    }
    catch {
        return $null
    }
}

function Test-ServiceExists {
    $null = & sc.exe query $ServiceName 2>&1
    return ($LASTEXITCODE -eq 0)
}

# Reads via WMI (Win32_Service.PathName), not sc.exe qc + a regex on
# BINARY_PATH_NAME (the original approach here): that field label is
# localized by the OS's own display language, so the regex never matches
# on a non-English Windows host - confirmed missing entirely on a live
# Russian-language machine, which made $needsInstall always true below
# (a null $currentCommand never equals $desiredCommand) - every GPO
# startup-script run silently reinstalled the client, even when nothing
# had changed. WMI property names are stable regardless of OS language.
function Get-ServiceBinaryPath {
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $service) {
        return $null
    }

    return $service.PathName
}

function ConvertTo-ServiceArgValue {
    param([string]$Value)
    return $Value -replace '"', '\"'
}

function Get-DesiredServiceCommand {
    param(
        [string]$ServicePath,
        [string]$Url,
        [int]$Hours,
        [int]$SoftwareHours = 6,
        [string]$OutputDirectory,
        [string]$DebugLogPath,
        [switch]$RequireHttpsSelfUpdate,
        [switch]$AllowHttpSelfUpdateFallback,
        [switch]$RequireSignedSelfUpdate
    )

    # The ingestion token is deliberately NOT accepted as a parameter here: it
    # goes into the service's registry Environment value (see
    # Get/Set-ServiceEnvironmentToken below) instead of this command line. A
    # binPath= argument ends up in HKLM\SYSTEM\CurrentControlSet\Services\<name>\
    # ImagePath, which `sc qc <name>` / Win32_Service.PathName expose to any
    # authenticated local user - the same class of exposure the Linux client's
    # EnvironmentFile switch (New-SystemdEnvFile, Install-ClientDebianSSH.ps1)
    # already avoids.
    $command = '"' + (ConvertTo-ServiceArgValue $ServicePath) + '" --server-url "' + (ConvertTo-ServiceArgValue $Url) + '" --interval-hours ' + $Hours + ' --software-check-interval-hours ' + $SoftwareHours
    $command += ' --output "' + (ConvertTo-ServiceArgValue $OutputDirectory) + '"'
    $command += ' --debug-log-path "' + (ConvertTo-ServiceArgValue $DebugLogPath) + '"'
    if ($RequireHttpsSelfUpdate) {
        $command += ' --require-https-self-update'
    }
    if ($AllowHttpSelfUpdateFallback) {
        $command += ' --allow-http-self-update-fallback'
    }
    if ($RequireSignedSelfUpdate) {
        $command += ' --require-signed-self-update'
    }

    return $command
}

# Reads back the ingestion token currently set on the service's registry
# Environment value, normalized to '' (never $null) so callers can compare
# it directly against a possibly-unbound -Token parameter without a
# null/empty-string mismatch producing a false "changed" result on every run
# where no token is configured at all (the common case per this project's
# own default-off RequireIngestionToken posture).
# -ServiceRegistryRoot defaults to the real Services key but is overridable
# so Pester can point this at a scratch HKCU key instead of writing into
# live HKLM\SYSTEM\CurrentControlSet\Services during a test run.
# Pure, directly-testable decision shared by both redeploy paths below (the
# "already current" branch and the full reinstall branch, which deletes and
# recreates the whole service key via sc.exe): what ingestion token value
# should end up written to WIL_INGESTION_TOKEN. An explicit -Token always
# wins; otherwise whatever is CURRENTLY stored is preserved - never replaced
# with an empty value just because -Token happened to be omitted this run.
# This is what keeps a client's own self-learned per-machine ingestion
# token (ApplyLearnedIngestionToken on the client side, via enrollment)
# alive across every future redeploy run that doesn't pass -Token - a
# version-mismatch (every package upgrade, or a client that has since
# self-updated past the package version) goes through the full-reinstall
# branch, which deletes the Environment value entirely before recreating
# it, so the caller must read the current value back BEFORE that delete and
# pass it in here.
function Resolve-TokenForRedeploy {
    param(
        [string]$ExplicitToken,
        [string]$CurrentlyStoredToken
    )
    if ($ExplicitToken) {
        return $ExplicitToken
    }
    return $CurrentlyStoredToken
}

function Get-ServiceEnvironmentToken {
    param(
        [string]$ServiceName,
        # Defaults to the shared ingestion token's variable name so every
        # existing caller (and the Pester suite) keeps working unchanged;
        # the "already current" redeploy check below also reads
        # WIL_ENROLLMENT_TOKEN through this same function.
        [string]$VariableName = 'WIL_INGESTION_TOKEN',
        [string]$ServiceRegistryRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    )

    # Deliberately not using Get-ItemProperty's own -Name filter: asking it
    # for a named value that does not exist on the key throws a
    # PropertyNotFoundException that ignores -ErrorAction SilentlyContinue
    # under this project's Set-StrictMode -Version 2.0 + $ErrorActionPreference
    # = 'Stop' combination (confirmed live - a fresh service key with no
    # Environment value yet, the normal case before any token is ever
    # configured, threw here instead of returning empty). Reading the whole
    # item and checking for the property's presence on the returned object
    # sidesteps that provider quirk entirely.
    $servicePath = Join-Path -Path $ServiceRegistryRoot -ChildPath $ServiceName
    $item = Get-ItemProperty -LiteralPath $servicePath -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSObject.Properties['Environment']) {
        return ''
    }
    $environment = $item.Environment
    if (-not $environment) {
        return ''
    }
    $prefix = $VariableName + '='
    foreach ($line in $environment) {
        if ($line -like ($prefix + '*')) {
            return $line.Substring($prefix.Length)
        }
    }
    return ''
}

# Writes the ingestion token and/or enrollment token into the service's own
# registry Environment value (a REG_MULTI_SZ the Service Control Manager
# injects into the process environment at start) instead of the service
# command line - see Get-DesiredServiceCommand's comment above for why.
# HKLM\SYSTEM\CurrentControlSet\Services\<name> subkeys inherit
# BUILTIN\Users: ReadKey from their parent by default (verified live) - the
# separate Set-RestrictedServiceRegistryKeyAcl call below closes this.
#
# Writes exactly what it is told - -SharedToken/-EnrollmentToken empty means
# "no such line", not "preserve whatever is there now". A caller that needs
# to preserve an already-learned value (see the "already current" branch
# below, which must never blindly wipe a real per-machine token the client
# learned for itself via enrollment) is responsible for reading the current
# value first and passing it back through unchanged.
function Set-ServiceEnvironmentToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [string]$SharedToken,

        [string]$EnrollmentToken,

        [string]$ServiceRegistryRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    )

    $servicePath = Join-Path -Path $ServiceRegistryRoot -ChildPath $ServiceName
    $environmentLines = @()
    if ($SharedToken) {
        $environmentLines += ('WIL_INGESTION_TOKEN=' + $SharedToken)
    }
    if ($EnrollmentToken) {
        $environmentLines += ('WIL_ENROLLMENT_TOKEN=' + $EnrollmentToken)
    }
    if ($environmentLines.Count -gt 0) {
        Set-ItemProperty -LiteralPath $servicePath -Name 'Environment' -Value $environmentLines -Type MultiString
    }
    else {
        Remove-ItemProperty -LiteralPath $servicePath -Name 'Environment' -ErrorAction SilentlyContinue
    }
}

# Breaks ACL inheritance on the service's own registry key and grants
# only Administrators+SYSTEM. HKLM\SYSTEM\CurrentControlSet\Services\<name>
# subkeys inherit BUILTIN\Users: ReadKey from their parent by default -
# verified live on a real Windows 10 box - which otherwise lets ANY local
# user read WIL_INGESTION_TOKEN out of this key's Environment value and
# use it to authenticate to the server (including pulling the
# software-repository share password in plaintext via
# GET /api/v1/client/software-repository-connection). Uses well-known
# SIDs, not literal 'Administrators'/'SYSTEM' strings, for the same
# non-English-locale reason Set-RestrictedFileAcl documents.
# -ServiceRegistryRoot defaults to the real Services key but is overridable
# so Pester can point this at TestRegistry: instead of writing into live
# HKLM\SYSTEM\CurrentControlSet\Services during a test run.
function Set-RestrictedServiceRegistryKeyAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [string]$ServiceRegistryRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    )
    $adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $servicePath = Join-Path -Path $ServiceRegistryRoot -ChildPath $ServiceName
    $acl = Get-Acl -Path $servicePath
    $acl.SetAccessRuleProtection($true, $false)
    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $adminRule  = New-Object System.Security.AccessControl.RegistryAccessRule($adminSid, 'FullControl', $inheritFlags, [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
    $systemRule = New-Object System.Security.AccessControl.RegistryAccessRule($systemSid, 'FullControl', $inheritFlags, [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $servicePath -AclObject $acl
}

# Deletes the pre-client-data-layout exe/version marker from the shared
# WindowsInventoryLite root once the service has been successfully
# recreated pointing at its new client-data location - mirrors the
# cleanup this file already does for legacy WindowsLicenseInventory*
# artifacts above. Local data files (<hostname>.json, _logs\, the old
# Logs\gpo-deploy.log) are deliberately left alone: they get recreated
# fresh at the new location on the client's next run, and deleting
# arbitrary data files on a live production machine is not worth the
# risk for a cosmetic cleanup.
function Remove-LegacyClientFiles {
    param(
        [string]$LegacyRoot,
        [string]$NewServicePath
    )

    $newDirectory = Split-Path -Parent $NewServicePath

    $legacyExePath = Join-Path -Path $LegacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
    if ((Test-Path -LiteralPath $legacyExePath) -and ($legacyExePath -ne $NewServicePath)) {
        Write-DeployLog "Removing legacy client executable: $legacyExePath"
        Remove-Item -LiteralPath $legacyExePath -Force
    }

    # Same path-equality guard as the exe above - without it, an operator
    # who explicitly passes -InstallPath back to the legacy bare root (still
    # technically permitted) would have this delete a client-version.txt
    # that is also the new install's own file. This project no longer
    # writes client-version.txt at all (installed-version detection reads
    # the real exe via Get-ExeVersion instead - see the top-level script
    # body) - this cleanup only removes a stray leftover from before that
    # change, on machines whose legacy bare-root install still has one.
    $legacyVersionPath = Join-Path -Path $LegacyRoot -ChildPath 'client-version.txt'
    $newVersionPath = Join-Path -Path $newDirectory -ChildPath 'client-version.txt'
    if ((Test-Path -LiteralPath $legacyVersionPath) -and ($legacyVersionPath -ne $newVersionPath)) {
        Write-DeployLog "Removing legacy client-version.txt: $legacyVersionPath"
        Remove-Item -LiteralPath $legacyVersionPath -Force
    }
}

# $InstallPath used to be created with plain New-Item and left at whatever
# ACL %ProgramData% inherits, which on a real machine grants BUILTIN\Users
# create-file rights and CREATOR OWNER full control of anything a non-admin
# user places there - a local-user-to-SYSTEM file/DLL-planting path, since
# this client runs as LocalSystem by default. ContainerInherit + ObjectInherit
# make files/subfolders created here LATER (debug logs, local report cache)
# inherit the same restriction instead of picking up whatever weaker default
# DACL Windows would otherwise apply at creation time. Applied on every run,
# not only when the directory is first created, so a re-run of this GPO
# script over a directory an earlier vulnerable version left with weak
# permissions gets corrected too.
function Set-RestrictedDirectoryAcl {
    param([string]$DirectoryPath)
    $adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    # -Path, not -LiteralPath: this script requires only PS 2.0 (#requires
    # above), and Get-Acl/Set-Acl only gained -LiteralPath in PS 3.0 - a
    # genuine Windows 7 target still on PS 2.0 fails here with "A parameter
    # cannot be found that matches parameter name 'LiteralPath'" (confirmed
    # live against a real fleet machine). $DirectoryPath is always a
    # script-built install path, never wildcard-shaped, so -Path's wildcard
    # expansion is a safe substitute here.
    $acl = Get-Acl -Path $DirectoryPath
    $acl.SetAccessRuleProtection($true, $false)
    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, 'FullControl', $inheritFlags, [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', $inheritFlags, [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $DirectoryPath -AclObject $acl
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

# Wrapped so Pester can dot-source this file (". $ScriptPath -ServerUrl ...")
# to load Get-DesiredServiceCommand/Remove-LegacyClientFiles for direct
# unit testing without performing a real install - same technique already
# used in src\Install-Wizard.ps1.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $InstallPath) {
        $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-data'
    }

    $LogPath = Join-Path -Path $InstallPath -ChildPath 'Logs\gpo-deploy.log'

    # Created and ACL-restricted BEFORE the first Write-DeployLog call below,
    # which otherwise creates $InstallPath\Logs itself (see Write-DeployLog)
    # while $InstallPath still sits at whatever ACL %ProgramData% inherits on
    # a fresh install. ContainerInherit/ObjectInherit only protects children
    # created AFTER Set-RestrictedDirectoryAcl runs - NTFS does not
    # retroactively cascade a newly-added inheritable ACE onto a directory
    # that already existed, so Logs\ (and gpo-deploy.log inside it) would
    # otherwise stay under the weak inherited ACL forever, on every
    # subsequent run too.
    if (-not (Test-Path -LiteralPath $InstallPath)) {
        New-Item -Path $InstallPath -ItemType Directory -Force | Out-Null
    }
    Set-RestrictedDirectoryAcl -DirectoryPath $InstallPath

    if (-not $PackageClientPath) {
        $PackageClientPath = Get-DefaultPackageClientPath
    }

    if (-not (Test-Path -LiteralPath $PackageClientPath)) {
        throw "Required package file was not found: $PackageClientPath"
    }

    Write-DeployLog "Current identity: $(Get-CurrentIdentityName)"
    if (-not (Test-Administrator)) {
        throw 'Administrator rights are required to install or update the WindowsInventoryLite service. Use a Computer Startup Script GPO, not a User Logon Script, or run PowerShell as Administrator for manual testing.'
    }

    $servicePath = Join-Path -Path $InstallPath -ChildPath 'WindowsInventoryLiteClient.exe'
    $debugLogPath = Join-Path -Path $InstallPath -ChildPath '_logs\debug-client.log'
    $packageVersion = Get-ExeVersion -Path $PackageClientPath
    # Reads the REAL currently-installed exe's own reported version, the
    # same way $packageVersion is read for the new package - not a
    # separate bookkeeping file. A private client-version.txt marker used
    # to track this, written only by this script's own install/reinstall
    # step below; the client's self-update mechanism (ApplySelfUpdateFromServerCore,
    # C#) swaps the exe through a completely separate path and never
    # touched that marker, so a machine that self-updated since its last
    # GPO/WinRM deploy had a marker frozen on a stale, older version than
    # what was actually running - a misleading "Installed version" log line
    # at best, an unnecessary forced service stop/reinstall at worst.
    # $null (same as before) when no exe exists yet - the fresh-install case.
    $installedVersion = Get-ExeVersion -Path $servicePath
    $desiredCommand = Get-DesiredServiceCommand -ServicePath $servicePath -Url $ServerUrl -Hours $IntervalHours -SoftwareHours $SoftwareCheckIntervalHours -OutputDirectory $InstallPath -DebugLogPath $debugLogPath -RequireHttpsSelfUpdate:$RequireHttpsSelfUpdate -AllowHttpSelfUpdateFallback:$AllowHttpSelfUpdateFallback -RequireSignedSelfUpdate:$RequireSignedSelfUpdate
    $currentCommand = Get-ServiceBinaryPath
    $serviceExists = Test-ServiceExists
    $needsInstall = $Force -or (-not $serviceExists) -or ($packageVersion -ne $installedVersion) -or ($currentCommand -ne $desiredCommand)

    Write-DeployLog "Package version: $packageVersion"
    Write-DeployLog "Installed version: $installedVersion"
    Write-DeployLog "Package client path: $PackageClientPath"

    if (-not $needsInstall) {
        Write-DeployLog "Client service is already current."
        # The token(s) live in the registry Environment value, not the binPath=
        # command compared above, so a token-only rotation would otherwise go
        # unnoticed here and never reach the service.
        #
        # The ingestion token is only ever overwritten here when -Token was
        # explicitly supplied and differs from what's stored - never merely
        # because -Token was left unset. A client deployed with -EnrollmentToken
        # instead learns its own real per-machine ingestion token on first
        # contact and persists it into this exact WIL_INGESTION_TOKEN value
        # (ApplyLearnedIngestionToken); comparing that learned value against
        # an always-empty $Token on every subsequent redeploy would otherwise
        # wipe it out on every single run.
        $currentIngestionToken = Get-ServiceEnvironmentToken -ServiceName $ServiceName -VariableName 'WIL_INGESTION_TOKEN'
        $currentEnrollmentToken = Get-ServiceEnvironmentToken -ServiceName $ServiceName -VariableName 'WIL_ENROLLMENT_TOKEN'
        $ingestionTokenToWrite = Resolve-TokenForRedeploy -ExplicitToken $Token -CurrentlyStoredToken $currentIngestionToken
        $ingestionTokenChanged = $ingestionTokenToWrite -ne $currentIngestionToken
        $enrollmentTokenChanged = $currentEnrollmentToken -ne [string]$EnrollmentToken
        if ($ingestionTokenChanged -or $enrollmentTokenChanged) {
            Write-DeployLog "Updating token(s) for existing service."
            Set-ServiceEnvironmentToken -ServiceName $ServiceName -SharedToken $ingestionTokenToWrite -EnrollmentToken $EnrollmentToken
            Set-RestrictedServiceRegistryKeyAcl -ServiceName $ServiceName
        }
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

    # Read back BEFORE the service key is deleted below - this path (any
    # version mismatch: every package upgrade, or a client that has since
    # self-updated past the package version) deletes and recreates the
    # whole service key via sc.exe, which wipes its Environment value
    # entirely. Without reading this back first, an enrolled client's real
    # per-machine token (never known to this script's own $Token, which
    # stays empty in the EnrollmentToken-only flow) would be silently lost
    # on every such redeploy, forcing a fresh enrollment it never needed.
    # Safe to call even when the service does not exist yet (fresh
    # install) - Get-ServiceEnvironmentToken returns '' for a key that was
    # never there, which Resolve-TokenForRedeploy then correctly falls
    # through to $Token (also empty in that case) for.
    $preservedIngestionToken = Resolve-TokenForRedeploy -ExplicitToken $Token -CurrentlyStoredToken (Get-ServiceEnvironmentToken -ServiceName $ServiceName -VariableName 'WIL_INGESTION_TOKEN')

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

    Invoke-ServiceCreate -ServiceName $ServiceName -BinPath $desiredCommand -DisplayName 'Windows Inventory Lite' -FailureMessage 'Failed to create service.' | Out-Null
    Set-ServiceEnvironmentToken -ServiceName $ServiceName -SharedToken $preservedIngestionToken -EnrollmentToken $EnrollmentToken
    Set-RestrictedServiceRegistryKeyAcl -ServiceName $ServiceName
    Invoke-ServiceControl -Arguments @('description', $ServiceName, "Collects Windows, Office, activation, and software inventory for Windows Inventory Lite. Version $installedVersion.") -FailureMessage 'Failed to set service description.' | Out-Null
    Invoke-ServiceControl -Arguments @('start', $ServiceName) -FailureMessage 'Failed to start service.' | Out-Null

    Remove-LegacyClientFiles -LegacyRoot (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite') -NewServicePath $servicePath

    Write-DeployLog "Client service deployed. Version: $installedVersion"
}
