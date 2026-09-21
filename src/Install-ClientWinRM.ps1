#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerUrl,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Token,

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$IntervalHours = 6,

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$SoftwareCheckIntervalHours = 6,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PackagePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RemotePackagePath = 'C:\ProgramData\WindowsInventoryLite\WinRMDeploy',

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CredentialUsername,

    # SecureString, not [string] - a plaintext password parameter is visible
    # to any local process listing (Get-Process/Win32_Process/Task Manager)
    # and lands in this session's PowerShell history for as long as it's
    # kept. The production dashboard-driven path never uses this parameter
    # anyway (it passes -Credential directly, built from stdin); this is
    # only for manual/standalone invocation.
    [Parameter()]
    [System.Security.SecureString]$CredentialPassword,

    [Parameter()]
    [switch]$AddToTrustedHosts,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$KeepRemotePackage
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# This script writes to WSMan:\localhost\Client\TrustedHosts, a machine-wide
# WinRM setting - requires local admin rights. Only defined here; enforced
# below, inside the "real deploy" guard, so Pester can still dot-source this
# file to unit-test the pure functions in it without needing an elevated
# test session. Same pattern already applied to Install-Server.ps1,
# Install-Client.ps1, and Install-Wizard.ps1.
. (Join-Path -Path $PSScriptRoot -ChildPath 'WilWinRmCommon.ps1')

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDirectory) {
    $scriptDirectory = (Get-Location).Path
}
$projectRoot = Split-Path -Parent $scriptDirectory
if (-not $PackagePath) {
    $PackagePath = Join-Path -Path $projectRoot -ChildPath 'dist\gpo-client'
}
elseif (-not [System.IO.Path]::IsPathRooted($PackagePath)) {
    $PackagePath = Join-Path -Path $projectRoot -ChildPath $PackagePath
}

$deployPath = Join-Path -Path $PackagePath -ChildPath 'Deploy-ClientGpo.ps1'
$clientNet35Path = Join-Path -Path $PackagePath -ChildPath 'WindowsInventoryLiteClient-net35.exe'
$clientNet40Path = Join-Path -Path $PackagePath -ChildPath 'WindowsInventoryLiteClient-net40.exe'

foreach ($path in @($deployPath, $clientNet35Path, $clientNet40Path)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required package file was not found: $path"
    }
}

$hadFailure = $false

if (-not $Credential -and $CredentialUsername -and $CredentialPassword) {
    $Credential = New-Object System.Management.Automation.PSCredential($CredentialUsername, $CredentialPassword)
}

function Get-RemoteClientPackagePath {
    param([System.Management.Automation.Runspaces.PSSession]$Session)

    $versionText = Invoke-Command -Session $Session -ScriptBlock {
        $version = [Environment]::OSVersion.Version
        return ('{0}.{1}' -f $version.Major, $version.Minor)
    }

    if ($versionText -eq '6.1') {
        return $clientNet35Path
    }

    return $clientNet40Path
}

function Copy-FileOverWinRM {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$LocalPath,
        [string]$RemotePath
    )

    $remoteDirectory = Split-Path -Parent $RemotePath
    Invoke-Command -Session $Session -ScriptBlock {
        param([string]$Path)

        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
    } -ArgumentList $remoteDirectory

    Invoke-Command -Session $Session -ScriptBlock {
        param([string]$Path)

        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force
        }
    } -ArgumentList $RemotePath

    $bytes = [System.IO.File]::ReadAllBytes($LocalPath)
    $chunkSize = 49152
    $offset = 0

    while ($offset -lt $bytes.Length) {
        $remaining = $bytes.Length - $offset
        $count = [Math]::Min($chunkSize, $remaining)
        $chunk = New-Object byte[] $count
        [Array]::Copy($bytes, $offset, $chunk, 0, $count)
        $encoded = [Convert]::ToBase64String($chunk)

        Invoke-Command -Session $Session -ScriptBlock {
            param(
                [string]$Path,
                [string]$Content
            )

            $chunkBytes = [Convert]::FromBase64String($Content)
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
            try {
                $stream.Write($chunkBytes, 0, $chunkBytes.Length)
            }
            finally {
                $stream.Close()
            }
        } -ArgumentList $RemotePath, $encoded

        $offset += $count
    }
}

function Invoke-RemoteDeploy {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$RemoteDeployPath,
        [string]$RemoteClientPath
    )

    Invoke-Command -Session $Session -ScriptBlock $script:RemoteDeployScriptBlock -ArgumentList $RemoteDeployPath, $RemoteClientPath, $ServerUrl, $IntervalHours, $SoftwareCheckIntervalHours, $Token, ([bool]$Force)
}

# Defined as its own script-scope scriptblock (not inline at the
# Invoke-Command call site above) so Pester can invoke it directly with a
# fake set of parameters to verify the constructed argument list, the same
# testable-scriptblock pattern RemoveRemotePackageScriptBlock below already
# uses - Invoke-Command's own remoting/param-binding can't be exercised
# without a real session, but the argument-building logic inside it can be
# tested on its own.
$script:RemoteDeployScriptBlock = {
    param(
        [string]$DeployPath,
        [string]$ClientPath,
        [string]$Url,
        [int]$Hours,
        [int]$SoftwareHours,
        [string]$SharedToken,
        [bool]$ForceInstall
    )

    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-File',
        $DeployPath,
        '-ServerUrl',
        $Url,
        '-IntervalHours',
        ([string]$Hours),
        '-SoftwareCheckIntervalHours',
        ([string]$SoftwareHours),
        '-PackageClientPath',
        $ClientPath
    )

    if ($ForceInstall) {
        $arguments += '-Force'
    }

    # Set as an environment variable on this process rather than passed as
    # -Token, which the child powershell.exe below would otherwise expose
    # via Get-Process/WMI Win32_Process.CommandLine to anyone locally
    # observing this REMOTE target for the run's duration (this whole
    # scriptblock executes there, via Invoke-Command). Deploy-ClientGpo.ps1
    # reads WIL_INGESTION_TOKEN as a fallback when -Token is not supplied -
    # child processes inherit their parent's environment by default, so the
    # spawned powershell.exe picks this up automatically.
    if ($SharedToken) {
        $env:WIL_INGESTION_TOKEN = $SharedToken
    }

    & powershell.exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Remote deploy script failed with exit code $LASTEXITCODE."
    }
}

# Defined as a script-scope scriptblock variable (not an inline literal at
# the Invoke-Command call site) so Pester can invoke the exact same code
# locally (no -ComputerName/-Session) to test the path-safety guard below,
# without needing a real WinRM target.
$script:RemoveRemotePackageScriptBlock = {
    param([string]$Path)

    # Inlined (not a called function, same reason as
    # Uninstall-ClientWinRM.ps1's own $script:RemoveClientScriptBlock guard):
    # this block runs in a separate remote runspace over WinRM, which cannot
    # resolve functions defined in the local script. Only "starts with / and
    # >= 2 segments" existed for the Linux side before this same fix (see
    # docs/superpowers/plans/2026-09-04-security-hardening-batch.md) - this
    # is the Windows-path-shaped twin of that fix: the value must resolve
    # (after collapsing any ..\.\ segments via GetFullPath) to a real
    # subdirectory under %ProgramData%\WindowsInventoryLite\, not just any
    # path that happens to exist.
    $allowedRoot = [System.IO.Path]::GetFullPath((Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite')).TrimEnd('\')
    $resolvedPath = [System.IO.Path]::GetFullPath($Path).TrimEnd('\')
    if (-not $resolvedPath.StartsWith("$allowedRoot\", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to delete '$Path' (resolves to '$resolvedPath') - it is not a real subdirectory of '$allowedRoot'."
    }

    if (Test-Path -LiteralPath $Path) {
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

# Wrapped so Pester can dot-source this file (". $ScriptPath -ComputerName ...
# -ServerUrl ... -PackagePath ...") to load $script:RemoveRemotePackageScriptBlock
# for direct unit testing without attempting a real WinRM connection - same
# technique used in src\Uninstall-ClientWinRM.ps1, src\Install-Client.ps1, and
# deploy\client\Deploy-ClientGpo.ps1.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Test-IsElevatedAdmin)) {
        throw 'This script must be run from an elevated (Run as Administrator) PowerShell session.'
    }

    # Entries this run itself adds to TrustedHosts - removed again once every
    # target has been attempted (see the cleanup after the loop below), so
    # trusting a workgroup/non-domain target does not outlive this one push.
    # Never includes anything that was already configured before this run.
    $addedTrustedHosts = @()

    # Wrapped in try/finally at this level (not just the cleanup call
    # itself) so an interruption partway through the loop below (Ctrl+C, a
    # killed session) still removes any TrustedHosts entries this run
    # already added, instead of leaving them behind indefinitely.
    try {
        foreach ($computer in $ComputerName) {
            $session = $null
            try {
                Write-Host "Connecting: $computer"
                if ($AddToTrustedHosts -or ($Credential -and (Test-IpAddress -Value $computer))) {
                    Write-Host "Adding TrustedHosts entry: $computer"
                    if (Add-TargetToTrustedHosts -TargetComputer $computer) {
                        $addedTrustedHosts += $computer
                    }
                }
                $session = New-InventorySession -TargetComputer $computer

                $selectedClientPath = Get-RemoteClientPackagePath -Session $session
                $remoteDeployPath = Join-Path -Path $RemotePackagePath -ChildPath 'Deploy-ClientGpo.ps1'
                $remoteClientPath = Join-Path -Path $RemotePackagePath -ChildPath (Split-Path -Leaf $selectedClientPath)

                Write-Host "Copying deploy script: $computer"
                Copy-FileOverWinRM -Session $session -LocalPath $deployPath -RemotePath $remoteDeployPath

                Write-Host "Copying client package: $computer"
                Copy-FileOverWinRM -Session $session -LocalPath $selectedClientPath -RemotePath $remoteClientPath

                Write-Host "Installing client service: $computer"
                Invoke-RemoteDeploy -Session $session -RemoteDeployPath $remoteDeployPath -RemoteClientPath $remoteClientPath

                if (-not $KeepRemotePackage) {
                    Invoke-Command -Session $session -ScriptBlock $script:RemoveRemotePackageScriptBlock -ArgumentList $RemotePackagePath
                }

                Write-Host "Client installed: $computer"
            }
            catch {
                $hadFailure = $true
                # Write-Error would work too, but PowerShell wraps it in a full
                # ErrorRecord (position info relative to the wrapping one-line
                # -Command invocation, CategoryInfo, FullyQualifiedErrorId) when it
                # reaches the caller's captured stderr - exactly the kind of wall
                # of PowerShell plumbing text Get-FriendlyConnectionError above is
                # meant to spare the dashboard's job log from. A plain stderr write
                # carries the same message with none of that ceremony.
                [Console]::Error.WriteLine(("Failed to install client on {0}: {1}" -f $computer, (Get-FriendlyConnectionError -Exception $_.Exception)))
            }
            finally {
                if ($session) {
                    Remove-PSSession -Session $session
                }
            }
        }
    }
    finally {
        foreach ($addedTarget in $addedTrustedHosts) {
            Remove-TargetFromTrustedHosts -TargetComputer $addedTarget
        }
    }

    if ($hadFailure) {
        exit 1
    }
}
