#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = 'C:\ProgramData\WindowsInventoryLite',

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

$serviceName = 'WindowsInventoryLiteClient'
$hadFailure = $false

if (-not $Credential -and $CredentialUsername -and $CredentialPassword) {
    $Credential = New-Object System.Management.Automation.PSCredential($CredentialUsername, $CredentialPassword)
}

# WinRM connection failures throw System.Management.Automation.Remoting.
# PSRemotingTransportException with the OS's own localized message text
# (Russian on a Russian-locale target, English on an English one, etc.) -
# unreadable to an admin whose own console is a different language, and a
# wall of internal WS-Management troubleshooting text either way. Classify
# by the exception TYPE and its .ErrorCode (a stable, documented WSMan
# HRESULT, not locale text) instead of matching on the message string.
# Only -2144108103 (name resolution failure) is mapped with real
# confidence here - every other PSRemotingTransportException falls into
# one shared "WinRM unreachable" bucket, which covers the connection-
# refused/timeout/service-not-configured case from real fleet reports but
# is not itself split further, since verifying additional specific codes
# needs a real failing WinRM target this dev machine doesn't have. The
# original message is always appended, so misclassifying a less-common
# code never hides the real detail - it only adds a friendlier headline.
function Get-FriendlyConnectionError {
    param([System.Exception]$Exception)

    if ($Exception -is [System.Management.Automation.Remoting.PSRemotingTransportException]) {
        if ($Exception.ErrorCode -eq -2144108103) {
            $friendly = 'Computer unreachable - could not resolve its name. Try again later.'
        }
        else {
            $friendly = 'WinRM service is not reachable on this computer - check that WinRM is configured and running (winrm quickconfig), and that the computer is online.'
        }
        return "$friendly (original error: $($Exception.Message))"
    }

    return $Exception.Message
}

function New-InventorySession {
    param([string]$TargetComputer)

    if ($Credential) {
        return New-PSSession -ComputerName $TargetComputer -Credential $Credential
    }

    return New-PSSession -ComputerName $TargetComputer
}

function Add-TargetToTrustedHosts {
    param([string]$TargetComputer)

    $current = ''
    try {
        $item = Get-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop
        $current = [string]$item.Value
    }
    catch {
        throw "Failed to read WinRM TrustedHosts. Run this script on a host with WinRM client support."
    }

    if ($current -eq '*') {
        return
    }

    $items = @()
    if ($current) {
        $items = @($current.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    foreach ($item in $items) {
        if ($item -ieq $TargetComputer) {
            return
        }
    }

    $items += $TargetComputer
    Set-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -Value ($items -join ',') -Force | Out-Null
}

function Test-IpAddress {
    param([string]$Value)

    $address = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$address)
}

foreach ($computer in $ComputerName) {
    $session = $null
    try {
        Write-Host "Connecting: $computer"
        if ($AddToTrustedHosts -or ($Credential -and (Test-IpAddress -Value $computer))) {
            Write-Host "Adding TrustedHosts entry: $computer"
            Add-TargetToTrustedHosts -TargetComputer $computer
        }

        $session = New-InventorySession -TargetComputer $computer
        Write-Host "Uninstalling client service: $computer"

        Invoke-Command -Session $session -ScriptBlock {
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
                    throw "Failed to delete service. sc.exe exit code: $deleteExitCode."
                }
                Start-Sleep -Seconds 2
            }
            else {
                Write-Host "Service is not installed: $ServiceName"
            }

            if (Test-Path -LiteralPath $ClientInstallPath) {
                Write-Host "Removing client files: $ClientInstallPath"
                Remove-Item -LiteralPath $ClientInstallPath -Recurse -Force
            }
            else {
                Write-Host "Client files are not present: $ClientInstallPath"
            }
        } -ArgumentList $serviceName, $InstallPath

        Write-Host "Client removed: $computer"
    }
    catch {
        $hadFailure = $true
        Write-Error ("Failed to uninstall client on {0}: {1}" -f $computer, (Get-FriendlyConnectionError -Exception $_.Exception))
    }
    finally {
        if ($session) {
            Remove-PSSession -Session $session
        }
    }
}

if ($hadFailure) {
    exit 1
}
