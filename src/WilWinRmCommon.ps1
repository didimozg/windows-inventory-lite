#requires -Version 2.0

# Shared by Install-ClientWinRM.ps1 and Uninstall-ClientWinRM.ps1 - both
# copied into the same server-bin directory at install time
# (Install-Server.ps1), so dot-sourcing a shared module is safe here.
#
# Function definitions only - no top-level side effects.

# This machine-wide WinRM setting (TrustedHosts, used by
# Add/Remove-TargetToTrustedHosts below) requires local admin rights -
# enforced only inside each calling script's own "real deploy"/"real
# uninstall" guard, so Pester can dot-source this module and the calling
# scripts to unit-test the pure functions without needing an elevated
# test session.
function Test-IsElevatedAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

# WinRM connection failures throw System.Management.Automation.Remoting.
# PSRemotingTransportException with the OS's own localized message text -
# unreadable to an admin whose own console is a different language, and a
# wall of internal WS-Management troubleshooting text either way.
# Classify by the exception TYPE and its .ErrorCode (a stable, documented
# WSMan HRESULT, not locale text) instead of matching on the message
# string. Only -2144108103 (name resolution failure) is mapped with real
# confidence here - every other PSRemotingTransportException falls into
# one shared "WinRM unreachable" bucket. The original message is always
# appended, so misclassifying a less-common code never hides the real
# detail - it only adds a friendlier headline.
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

# TrustedHosts is itself a comma-delimited list, and WSMan treats * and ?
# as wildcards - a $TargetComputer containing any of these could inject
# an unintended additional entry (including a bare * that trusts every
# host WinRM will ever connect to from this machine) instead of being
# added as the single literal hostname/IP this function assumes.
function Test-ValidTrustedHostsEntry {
    param([string]$TargetComputer)
    return [bool]($TargetComputer -and ($TargetComputer -notmatch '[,*?\s]'))
}

# Returns $true only when this call actually added a new entry - the
# caller uses that to know which entries it is responsible for removing
# again once this run's work is done (Remove-TargetFromTrustedHosts
# below). An entry that was already present (including a pre-existing
# "*") is left alone entirely, both here and on removal - this function
# only ever manages entries it itself created.
function Add-TargetToTrustedHosts {
    param([string]$TargetComputer)

    if (-not (Test-ValidTrustedHostsEntry -TargetComputer $TargetComputer)) {
        throw "TargetComputer '$TargetComputer' contains a character not allowed in a WinRM TrustedHosts entry (comma, wildcard, or whitespace)."
    }

    $current = ''
    try {
        $item = Get-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop
        $current = [string]$item.Value
    }
    catch {
        throw "Failed to read WinRM TrustedHosts. Run this script on a host with WinRM client support."
    }

    if ($current -eq '*') {
        return $false
    }

    $items = @()
    if ($current) {
        $items = @($current.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    foreach ($item in $items) {
        if ($item -ieq $TargetComputer) {
            return $false
        }
    }

    $items += $TargetComputer
    Set-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -Value ($items -join ',') -Force | Out-Null
    return $true
}

# Undoes exactly one prior Add-TargetToTrustedHosts call for the same
# TargetComputer - called only for entries this script's own run added,
# never for whatever was already configured before this run started.
# Trusting a WinRM target is a standing widening of this machine's
# attack surface (no mutual auth the way domain/Kerberos targets get),
# so it should not outlive the single operation that needed it.
function Remove-TargetFromTrustedHosts {
    param([string]$TargetComputer)

    $current = ''
    try {
        $item = Get-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop
        $current = [string]$item.Value
    }
    catch {
        return
    }

    if (-not $current -or $current -eq '*') {
        return
    }

    $items = @($current.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -ine $TargetComputer })
    Set-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -Value ($items -join ',') -Force | Out-Null
}

function Test-IpAddress {
    param([string]$Value)

    $address = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$address)
}
