#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = 'C:\ProgramData\WindowsInventoryLite\client-data',

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
    [switch]$AddToTrustedHosts
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# This script writes to WSMan:\localhost\Client\TrustedHosts, a machine-wide
# WinRM setting - requires local admin rights. Only defined here; enforced
# below, inside the "real uninstall" guard, so Pester can still dot-source
# this file to unit-test the pure functions in it without needing an
# elevated test session. Same pattern already applied to Install-Server.ps1,
# Install-Client.ps1, Install-Wizard.ps1, and Install-ClientWinRM.ps1.
. (Join-Path -Path $PSScriptRoot -ChildPath 'WilWinRmCommon.ps1')

$serviceName = 'WindowsInventoryLiteClient'
$hadFailure = $false

if (-not $Credential -and $CredentialUsername -and $CredentialPassword) {
    $Credential = New-Object System.Management.Automation.PSCredential($CredentialUsername, $CredentialPassword)
}

# Defined as a script-scope scriptblock variable (not an inline literal at
# the Invoke-Command call site) so Pester can invoke the exact same code
# locally (no -ComputerName/-Session) to test the shared-server-root guard
# below, without needing a real WinRM target.
$script:RemoveClientScriptBlock = {
    param(
        [string]$ServiceName,
        [string]$ClientInstallPath
    )

    foreach ($legacyName in @('WindowsLicenseInventoryClient', 'WindowsLicenseInventory')) {
        $null = & sc.exe query $legacyName 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Stopping legacy service: $legacyName"
            & sc.exe stop $legacyName | Out-Null
            Start-Sleep -Seconds 2
            Write-Host "Deleting legacy service: $legacyName"
            & sc.exe delete $legacyName | Out-Null
            Start-Sleep -Seconds 2
        }
    }

    $legacyPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsLicenseInventory'
    if (Test-Path -LiteralPath $legacyPath) {
        Write-Host "Removing legacy client files: $legacyPath"
        Remove-Item -LiteralPath $legacyPath -Recurse -Force
    }

    $null = & sc.exe query $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Stopping service: $ServiceName"
        $stopOutput = & sc.exe stop $ServiceName 2>&1
        $stopExitCode = $LASTEXITCODE
        Write-Host "Stop service exit code: $stopExitCode"
        Start-Sleep -Seconds 2

        Write-Host "Deleting service: $ServiceName"
        $deleteOutput = & sc.exe delete $ServiceName 2>&1
        $deleteExitCode = $LASTEXITCODE
        Write-Host "Delete service exit code: $deleteExitCode"
        if ($deleteExitCode -ne 0) {
            # Every other sc.exe-wrapping helper in this codebase
            # (Invoke-ServiceControl in Install-Server.ps1/Install-Client.ps1/
            # Deploy-ClientGpo.ps1/Install-Wizard.ps1) appends the captured
            # output to the thrown message for diagnosability - this one
            # captured $deleteOutput but never used it.
            throw ("Failed to delete service. sc.exe exit code: $deleteExitCode. Output: " + (($deleteOutput | Out-String).Trim()))
        }
        Start-Sleep -Seconds 2
    }
    else {
        Write-Host "Service is not installed: $ServiceName"
    }

    # Inlined (not a called function, same reason as the shared-root check
    # below): this block runs in a separate remote runspace over WinRM,
    # which cannot resolve functions defined in the local script. Only
    # "starts with / and >= 2 segments" existed for the Linux side before
    # this same fix (see docs/superpowers/plans/2026-09-04-security-
    # hardening-batch.md) - this is the Windows-path-shaped twin of that
    # fix: the value must resolve (after collapsing any ..\.\ segments via
    # GetFullPath) to a real subdirectory under
    # %ProgramData%\WindowsInventoryLite\, not just any path that happens
    # to exist.
    $allowedRoot = [System.IO.Path]::GetFullPath((Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite')).TrimEnd('\')
    $resolvedInstallPath = [System.IO.Path]::GetFullPath($ClientInstallPath).TrimEnd('\')
    if (-not $resolvedInstallPath.StartsWith("$allowedRoot\", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to delete '$ClientInstallPath' (resolves to '$resolvedInstallPath') - it is not a real subdirectory of '$allowedRoot'."
    }

    # Historical safety net for the client/server co-located case (an
    # explicit -InstallPath override pointing at the bare shared root): the
    # allowlist check above already refuses a bare $sharedRoot unconditionally
    # now (it is not a real SUBDIRECTORY of itself), so this branch can no
    # longer be reached with $isSharedServerRoot true OR false - the delete
    # below only ever runs for a genuine subdirectory. Left in place as
    # defense in depth and because it costs nothing; if $ClientInstallPath
    # is ever changed to allow the bare root again, this still catches the
    # one case that matters. Inlined (not a called function) because this
    # block runs in a separate remote runspace over WinRM, which cannot
    # resolve functions defined in the local script.
    $sharedRoot = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'
    $isSharedServerRoot = ($ClientInstallPath.TrimEnd('\') -eq $sharedRoot.TrimEnd('\')) -and (Test-Path -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json'))

    if ($isSharedServerRoot) {
        Write-Warning "Skipped removing $ClientInstallPath - it looks like the server's own directory (server-config.json present). Remove client files manually if needed."
    }
    elseif (Test-Path -LiteralPath $ClientInstallPath) {
        Write-Host "Removing client files: $ClientInstallPath"
        Remove-Item -LiteralPath $ClientInstallPath -Recurse -Force
    }
    else {
        Write-Host "Client files are not present: $ClientInstallPath"
    }
}

# Wrapped so Pester can dot-source this file (". $ScriptPath -ComputerName ...")
# to load $script:RemoveClientScriptBlock for direct unit testing without
# attempting a real WinRM connection - same technique used in
# src\Install-Client.ps1 and deploy\client\Deploy-ClientGpo.ps1.
if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Test-IsElevatedAdmin)) {
        throw 'This script must be run from an elevated (Run as Administrator) PowerShell session.'
    }

    # Entries this run itself adds to TrustedHosts - removed again once every
    # target has been attempted (see the cleanup after the loop below), so
    # trusting a workgroup/non-domain target does not outlive this one
    # uninstall. Never includes anything already configured before this run.
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
                Write-Host "Uninstalling client service: $computer"

                Invoke-Command -Session $session -ScriptBlock $script:RemoveClientScriptBlock -ArgumentList $serviceName, $InstallPath

                Write-Host "Client removed: $computer"
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
                [Console]::Error.WriteLine(("Failed to uninstall client on {0}: {1}" -f $computer, (Get-FriendlyConnectionError -Exception $_.Exception)))
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
