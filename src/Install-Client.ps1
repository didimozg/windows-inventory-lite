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
    [string]$ClientExecutablePath,

    [Parameter()]
    [switch]$NoRun
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ServerUrl/Token/ServerSharePath end up embedded in the sc.exe command line
# Invoke-ServiceCreate builds below and runs via cmd.exe /c - the surrounding
# double quotes do NOT protect &, |, <, >, ^ from being parsed as live cmd.exe
# operators (a well-known cmd.exe quoting quirk), so an unvalidated value here
# is a command-injection path to code execution. Reject the same characters
# New-ClientGpoPackage.ps1's Test-BatchSafeValue already rejects for the GPO
# .cmd generation path.
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
Test-BatchSafeValue -Value $ServerSharePath -FieldName 'ServerSharePath'
Test-BatchSafeValue -Value $InstallPath -FieldName 'InstallPath'

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

function Get-ClientServiceCommand {
    param(
        [string]$ServicePath,
        [string]$Url,
        [int]$Hours,
        [int]$SoftwareHours = 6,
        [string]$SharePath,
        [string]$OutputDirectory,
        [string]$DebugLogPath
    )

    # The ingestion token is deliberately NOT accepted as a parameter here: it
    # goes into the service's registry Environment value (see
    # Set-ServiceEnvironmentToken) instead of this command line. A binPath=
    # argument ends up in HKLM\SYSTEM\CurrentControlSet\Services\<name>\ImagePath,
    # which `sc qc <name>` / Win32_Service.PathName expose to any authenticated
    # local user - the same class of exposure the Linux client's EnvironmentFile
    # switch (New-SystemdEnvFile, Install-ClientDebianSSH.ps1) already avoids.
    $command = '"' + (ConvertTo-ServiceArgValue $ServicePath) + '" --server-url "' + (ConvertTo-ServiceArgValue $Url) + '" --interval-hours ' + $Hours + ' --software-check-interval-hours ' + $SoftwareHours
    if ($SharePath) {
        $command += ' --share "' + (ConvertTo-ServiceArgValue $SharePath) + '"'
    }
    $command += ' --output "' + (ConvertTo-ServiceArgValue $OutputDirectory) + '"'
    $command += ' --debug-log-path "' + (ConvertTo-ServiceArgValue $DebugLogPath) + '"'

    return $command
}

# Writes the ingestion token into the service's own registry Environment
# value (HKLM\SYSTEM\CurrentControlSet\Services\<name>\Environment, a
# REG_MULTI_SZ the Service Control Manager injects into the process
# environment at start) instead of the service command line. This is the
# Windows-native equivalent of the Linux client's mode-600 EnvironmentFile
# (New-SystemdEnvFile / Install-ClientDebianSSH.ps1): HKLM\SYSTEM is
# writable/readable only by Administrators and SYSTEM by default, so no
# separate ACL step is needed here. `sc.exe create` (Invoke-ServiceCreate)
# does not expose a way to set this value itself, so it is written directly
# to the registry right after the service key exists. An empty/absent token
# clears any stale value a previous install may have left (relevant on a
# reinstall over an existing service key: sc.exe delete removes the whole
# key including this value, so this only matters if create-without-delete
# is ever used, but explicit is safer than relying on that assumption).
# -ServiceRegistryRoot defaults to the real Services key but is overridable
# so Pester can point this at a scratch HKCU key instead of writing into
# live HKLM\SYSTEM\CurrentControlSet\Services during a test run.
function Set-ServiceEnvironmentToken {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [string]$SharedToken,

        [string]$ServiceRegistryRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    )

    $servicePath = Join-Path -Path $ServiceRegistryRoot -ChildPath $ServiceName
    if ($SharedToken) {
        Set-ItemProperty -LiteralPath $servicePath -Name 'Environment' -Value @('WIL_INGESTION_TOKEN=' + $SharedToken) -Type MultiString
    }
    else {
        Remove-ItemProperty -LiteralPath $servicePath -Name 'Environment' -ErrorAction SilentlyContinue
    }
}

# Deletes the pre-client-data-layout exe/version marker from the shared
# WindowsInventoryLite root once the service has been successfully
# recreated pointing at its new client-data location - mirrors the
# cleanup this file already does for legacy WindowsLicenseInventory*
# artifacts. Local data files (<hostname>.json, _logs\) are deliberately
# left alone: they get recreated fresh at the new location on the
# client's next run.
function Remove-LegacyClientFiles {
    param(
        [string]$LegacyRoot,
        [string]$NewServicePath
    )

    $newDirectory = Split-Path -Parent $NewServicePath

    $legacyExePath = Join-Path -Path $LegacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
    if ((Test-Path -LiteralPath $legacyExePath) -and ($legacyExePath -ne $NewServicePath)) {
        Write-Host "Removing legacy client executable: $legacyExePath"
        Remove-Item -LiteralPath $legacyExePath -Force
    }

    # Same path-equality guard as the exe above - without it, an operator
    # who explicitly passes -InstallPath back to the legacy bare root (still
    # technically permitted) would have this delete a client-version.txt
    # that legitimately belongs at that same "new" location (e.g. written by
    # an earlier Deploy-ClientGpo.ps1 run against the same path).
    $legacyVersionPath = Join-Path -Path $LegacyRoot -ChildPath 'client-version.txt'
    $newVersionPath = Join-Path -Path $newDirectory -ChildPath 'client-version.txt'
    if ((Test-Path -LiteralPath $legacyVersionPath) -and ($legacyVersionPath -ne $newVersionPath)) {
        Write-Host "Removing legacy client-version.txt: $legacyVersionPath"
        Remove-Item -LiteralPath $legacyVersionPath -Force
    }
}

# $InstallPath used to be created with plain New-Item and left at whatever
# ACL %ProgramData% inherits, which on a real machine grants BUILTIN\Users
# create-file rights and CREATOR OWNER full control of anything a non-admin
# user places there - a local-user-to-SYSTEM file/DLL-planting path, since
# this client runs as LocalSystem by default (see Invoke-ServiceCreate).
# ContainerInherit + ObjectInherit make files/subfolders created here LATER
# (debug logs, local report cache) inherit the same restriction instead of
# picking up whatever weaker default DACL Windows would otherwise apply at
# creation time. Applied on every run, not only when the directory is first
# created, so an upgrade over a directory an earlier vulnerable version of
# this script left with weak permissions gets corrected too.
function Set-RestrictedDirectoryAcl {
    param([string]$DirectoryPath)
    $adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    $acl = Get-Acl -LiteralPath $DirectoryPath
    $acl.SetAccessRuleProtection($true, $false)
    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, 'FullControl', $inheritFlags, [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', $inheritFlags, [System.Security.AccessControl.PropagationFlags]::None, 'Allow')
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -LiteralPath $DirectoryPath -AclObject $acl
}

# Wrapped so Pester can dot-source this file (". $ScriptPath -ServerUrl ...")
# to load Get-ClientServiceCommand/Remove-LegacyClientFiles for direct
# unit testing without performing a real install - same technique used in
# src\Install-Wizard.ps1 and deploy\client\Deploy-ClientGpo.ps1.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not $InstallPath) {
        $InstallPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-data'
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
    Set-RestrictedDirectoryAcl -DirectoryPath $InstallPath

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
    $debugLogPath = Join-Path -Path $InstallPath -ChildPath '_logs\debug-client.log'
    $null = & sc.exe query $serviceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Invoke-ServiceControl -Arguments @('stop', $serviceName) -FailureMessage "Failed to stop existing service." -AllowedExitCodes @(0, 1062) | Out-Null
        Invoke-ServiceControl -Arguments @('delete', $serviceName) -FailureMessage "Failed to delete existing service." | Out-Null
        Wait-FileRelease -Path $servicePath
    }

    Copy-Item -LiteralPath $ClientExecutablePath -Destination $servicePath -Force
    $clientVersion = (& $servicePath --version 2>&1 | Select-Object -First 1)

    $serviceCommand = Get-ClientServiceCommand -ServicePath $servicePath -Url $ServerUrl -Hours $IntervalHours -SoftwareHours $SoftwareCheckIntervalHours -SharePath $ServerSharePath -OutputDirectory $InstallPath -DebugLogPath $debugLogPath

    Invoke-ServiceCreate -ServiceName $serviceName -BinPath $serviceCommand -DisplayName 'Windows Inventory Lite' -FailureMessage "Failed to create service. Run PowerShell as Administrator." | Out-Null
    Set-ServiceEnvironmentToken -ServiceName $serviceName -SharedToken $Token
    Invoke-ServiceControl -Arguments @('description', $serviceName, "Collects Windows, Office, activation, and software inventory for Windows Inventory Lite. Version $clientVersion.") -FailureMessage "Failed to set service description." | Out-Null
    Write-Host "Service created: $serviceName"
    Write-Host "Client version: $clientVersion"

    if (-not $NoRun) {
        Invoke-ServiceControl -Arguments @('start', $serviceName) -FailureMessage "Failed to start service." | Out-Null
        Write-Host "Service started: $serviceName"
    }

    Remove-LegacyClientFiles -LegacyRoot (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite') -NewServicePath $servicePath

    Write-Host "Client installed: $InstallPath"
}
