#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = '/opt/windows-inventory-lite',

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$CredentialUsername,

    [Parameter(ParameterSetName = 'Key', Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$KeyPath,

    [Parameter(ParameterSetName = 'Password', Mandatory = $true)]
    [System.Security.SecureString]$CredentialPassword
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:usingPassword = $PSCmdlet.ParameterSetName -eq 'Password'

# POSIX shell metacharacters - InstallPath ends up interpolated into a
# remote shell command string (see Get-LinuxUninstallCommand below), so a
# value containing any of these could inject additional commands on the
# TARGET machine. Rejects rather than attempts to safely quote/escape,
# matching this project's existing ValidateBatchSafe convention for the
# Windows GPO cmd path - duplicated here rather than shared via a .psm1,
# matching how Install-ClientDebianSSH.ps1 already duplicates its own
# small helpers instead of sharing a module with Install-ClientWinRM.ps1.
function Test-PosixShellSafe {
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Value,
        [string]$FieldName
    )
    if ([string]::IsNullOrEmpty($Value)) {
        return
    }
    $unsafeChars = '`', '$', '"', "'", '\', ';', '|', '&', '<', '>', '(', ')', "`r", "`n"
    foreach ($char in $unsafeChars) {
        if ($Value.Contains($char)) {
            throw "$FieldName contains a character that is not allowed here (``, `$, `", ', \, ;, |, &, <, >, (, ), or a line break)."
        }
    }
}

function ConvertTo-PlainText {
    param([System.Security.SecureString]$Secure)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# Builds the remote command that stops+disables the timer/service, removes
# the unit files, removes the install directory, and reloads systemd -
# the reverse of Install-ClientDebianSSH.ps1's New-SystemdUnitFiles +
# service-enable steps. Pure function of its parameters, no network/SSH -
# directly unit-testable, same pattern as New-SystemdUnitFiles.
function Get-LinuxUninstallCommand {
    param(
        [string]$InstallPath,
        [string]$SudoPrefix
    )
    Test-PosixShellSafe -Value $InstallPath -FieldName 'InstallPath'

    return "${SudoPrefix}systemctl disable --now wil-linux-client.timer wil-linux-client.service && " +
        "${SudoPrefix}rm -f /etc/systemd/system/wil-linux-client.service /etc/systemd/system/wil-linux-client.timer && " +
        "${SudoPrefix}rm -rf $InstallPath && " +
        "${SudoPrefix}systemctl daemon-reload"
}

# Native commands merged via 2>&1 under this script's $ErrorActionPreference
# = 'Stop' turn ANY stderr line into a terminating error - even benign
# success output (systemctl's own confirmation text on success is written
# to stderr). Temporarily relaxing to 'Continue' for the duration of the
# native call is required so a successful systemctl disable/daemon-reload
# doesn't get reported as a failure - same fix Install-ClientDebianSSH.ps1
# already applies for the identical reason (found via live testing against
# this project's real Debian test fleet).
function Invoke-NativeAllowingStderr {
    param([scriptblock]$ScriptBlock)

    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $ScriptBlock
    }
    finally {
        $ErrorActionPreference = $previousEap
    }
}

function Invoke-PlinkWithPasswordFile {
    param(
        [string]$ExePath,
        [string[]]$Arguments,
        [string]$PlainPassword
    )

    $pwFile = [System.IO.Path]::GetTempFileName()
    try {
        $acl = Get-Acl -LiteralPath $pwFile
        $acl.SetAccessRuleProtection($true, $false)
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', 'Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $pwFile -AclObject $acl

        [System.IO.File]::WriteAllText($pwFile, $PlainPassword, (New-Object System.Text.UTF8Encoding($false)))

        $fullArgs = @('-pwfile', $pwFile, '-batch') + $Arguments
        $output = Invoke-NativeAllowingStderr { & $ExePath @fullArgs 2>&1 }

        if ($LASTEXITCODE -ne 0) {
            $joined = $output -join "`n"
            if ($joined -match '(?i)host key') {
                throw ("plink failed (exit {0}): the target's SSH host key is not yet trusted by this machine (PuTTY caches trusted keys separately from Windows' own OpenSSH known_hosts). -batch refuses to prompt for an unknown host key rather than risk silently trusting the wrong one. Connect once with -KeyPath, or run plink interactively against this target once to accept its host key, then retry. Raw output: {1}" -f $LASTEXITCODE, $joined)
            }
            throw ("plink failed (exit {0}): {1}" -f $LASTEXITCODE, $joined)
        }

        return $output
    }
    finally {
        Remove-Item -LiteralPath $pwFile -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-RemoteCommand {
    param([string]$TargetComputer, [string]$Command)

    if ($script:usingPassword) {
        $plainPassword = ConvertTo-PlainText -Secure $script:CredentialPassword
        try {
            $output = Invoke-PlinkWithPasswordFile -ExePath $script:plinkPath -Arguments @('-ssh', "$script:CredentialUsername@$TargetComputer", $Command) -PlainPassword $plainPassword
        }
        finally {
            $plainPassword = $null
        }
    }
    else {
        $output = Invoke-NativeAllowingStderr { & ssh.exe -i $script:KeyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$script:CredentialUsername@$TargetComputer" $Command 2>&1 }
    }

    if ($LASTEXITCODE -ne 0) {
        throw ("Remote command failed (exit {0}): {1}" -f $LASTEXITCODE, ($output -join "`n"))
    }
    return $output
}

# Wrapped so Pester can dot-source this file (same technique already used
# by Install-ClientDebianSSH.ps1 and Uninstall-ClientWinRM.ps1) to load the
# functions above for direct unit testing without attempting a real SSH
# connection.
if ($MyInvocation.InvocationName -ne '.') {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not $ScriptRoot) {
        $ScriptRoot = (Get-Location).Path
    }
    $projectRoot = Split-Path -Parent $ScriptRoot

    $plinkPath = Join-Path -Path $projectRoot -ChildPath 'deploy\linux-client\plink.exe'
    if ($usingPassword) {
        if (-not (Test-Path -LiteralPath $plinkPath)) {
            throw "Required tool was not found: $plinkPath. See deploy\linux-client\NOTICE for how to obtain it."
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $KeyPath)) {
            throw "SSH private key was not found: $KeyPath"
        }
    }

    $hadFailure = $false
    foreach ($computer in $ComputerName) {
        try {
            Write-Host "Connecting: $computer"
            $sudoPrefix = if ($CredentialUsername -eq 'root') { '' } else { 'sudo ' }
            $uninstallCommand = Get-LinuxUninstallCommand -InstallPath $InstallPath -SudoPrefix $sudoPrefix

            Write-Host "Removing client: $computer"
            Invoke-RemoteCommand -TargetComputer $computer -Command $uninstallCommand | Out-Null

            Write-Host "Client removed: $computer"
        }
        catch {
            $hadFailure = $true
            [Console]::Error.WriteLine(("Failed to uninstall Linux client on {0}: {1}" -f $computer, $_.Exception.Message))
        }
    }

    if ($hadFailure) {
        exit 1
    }
}
