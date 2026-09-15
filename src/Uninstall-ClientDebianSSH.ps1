#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = '/opt/windows-inventory-lite',

    [Parameter()]
    [AllowEmptyString()]
    [string]$ExpectedHostKey,

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
# Space/tab are rejected too: "rm -rf $InstallPath" has no quoting around
# the variable, so "/opt/wil /usr" word-splits into two arguments on the
# remote shell despite containing no character this list used to forbid.
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
    $unsafeChars = '`', '$', '"', "'", '\', ';', '|', '&', '<', '>', '(', ')', "`r", "`n", ' ', "`t"
    foreach ($char in $unsafeChars) {
        if ($Value.Contains($char)) {
            throw "$FieldName contains a character that is not allowed here (``, `$, `", ', \, ;, |, &, <, >, (, ), whitespace, or a line break)."
        }
    }
}

# Test-PosixShellSafe only screens for shell metacharacters and whitespace -
# it has no opinion on whether the path itself is a sane place to rm -rf.
# This used to require "at least two path segments," which a bare
# top-level directory like /usr or /etc could not pass - but that check
# was defeated by traversal ("/opt/../etc" has two segments and no
# rejected character) and was too weak even without it ("/usr/bin" also
# has two segments and is still catastrophic). Now an allowlist: the value
# must be a real subdirectory under /opt/, and no path segment anywhere
# may be "." or "..". The C# server already gates this for every request
# that reaches it through the dashboard/API, but this script is also
# directly runnable on its own (see README.md's Quick Start), which
# bypasses that gate entirely.
function Test-LinuxInstallPathSafe {
    param([string]$InstallPath)
    if ([string]::IsNullOrEmpty($InstallPath) -or -not $InstallPath.StartsWith('/')) {
        throw "InstallPath must be an absolute Linux path under /opt/ (e.g. /opt/windows-inventory-lite)."
    }
    # @(...) forces this to always be an array, even with 0 or 1 elements -
    # Windows PowerShell 5.1 (unlike PS7+) has no .Count on a bare scalar.
    $allSegments = @($InstallPath.Trim('/') -split '/' | Where-Object { $_ -ne '' })
    foreach ($segment in $allSegments) {
        if ($segment -eq '..' -or $segment -eq '.') {
            throw "InstallPath must be an absolute Linux path under /opt/ (e.g. /opt/windows-inventory-lite) - a '..' or '.' path segment is rejected."
        }
    }
    if (-not $InstallPath.StartsWith('/opt/')) {
        throw "InstallPath must be an absolute Linux path under /opt/ (e.g. /opt/windows-inventory-lite) - a bare top-level directory like /usr or /etc is rejected."
    }
    $remainderSegments = @(($InstallPath.Substring('/opt/'.Length)).Trim('/') -split '/' | Where-Object { $_ -ne '' })
    if ($remainderSegments.Count -lt 1) {
        throw "InstallPath must be an absolute Linux path under /opt/ (e.g. /opt/windows-inventory-lite) - a bare /opt is rejected."
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
    Test-LinuxInstallPathSafe -InstallPath $InstallPath

    return "${SudoPrefix}systemctl disable --now wil-linux-client.timer wil-linux-client.service wil-linux-client-status.timer wil-linux-client-status.service && " +
        "${SudoPrefix}rm -f /etc/systemd/system/wil-linux-client.service /etc/systemd/system/wil-linux-client.timer /etc/systemd/system/wil-linux-client-status.service /etc/systemd/system/wil-linux-client-status.timer && " +
        "${SudoPrefix}rm -rf $InstallPath && " +
        "${SudoPrefix}rm -f /etc/wil-linux-client.env && " +
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

# Converts an OpenSSH-format RSA private key (the openssh-key-v1 container
# ssh-keygen has produced by default since OpenSSH 7.8 - what any admin's
# key looks like today) to PuTTY's own .ppk v2 format, entirely in-process
# (no external tool). plink.exe/pscp.exe cannot read an OpenSSH-format key
# directly via -i - confirmed live, "Unable to use key file ... (OpenSSH
# SSH-2 private key (new format))". puttygen.exe and Pageant were both
# investigated as alternatives and ruled out (see this project's design
# doc history for 2026-09-15's SSH key-auth work): Windows' puttygen.exe
# is GUI-only and rejects every documented command-line conversion flag;
# Pageant cannot load this key format either. PPK v2 (not the newer v3) is
# used deliberately - still fully readable by current plink/pscp, and far
# simpler to generate correctly than v3's Argon2id-based MAC key
# derivation. RSA only - other key types throw a clear, specific error
# rather than being silently mishandled. Encrypted (passphrase-protected)
# keys also throw a clear error: this project's automated key-auth pushes
# already require a passphrase-less key today (ssh.exe's own -i had no
# passphrase-prompt handling either), so this is an existing requirement,
# not a new limitation.
#
# The exact field order and MAC computation below are live-tested, not
# derived from documentation alone: a prototype using this exact logic
# converted a real key and both plink.exe and pscp.exe successfully
# authenticated against a real target using the result. The first attempt
# at the PPK private-key field order (p, q, iqmp, d) was wrong and failed
# with "Unable to load private key (createkey failed)" - the correct
# order, confirmed working, is d, p, q, iqmp.
function Convert-OpenSshKeyToPpk {
    param(
        [string]$KeyPath,
        [string]$OutputPath
    )

    function Read-SshString {
        param([byte[]]$Bytes, [ref]$Offset)
        $lenBytes = $Bytes[$Offset.Value..($Offset.Value + 3)]
        [Array]::Reverse($lenBytes)
        $len = [System.BitConverter]::ToUInt32($lenBytes, 0)
        $Offset.Value += 4
        $val = $Bytes[$Offset.Value..($Offset.Value + $len - 1)]
        $Offset.Value += $len
        return ,$val
    }

    function Write-SshString {
        param([byte[]]$Bytes)
        $lenBytes = [System.BitConverter]::GetBytes([uint32]$Bytes.Length)
        [Array]::Reverse($lenBytes)
        return $lenBytes + $Bytes
    }

    if (-not (Test-Path -LiteralPath $KeyPath)) {
        throw "SSH private key was not found: $KeyPath"
    }

    $raw = Get-Content -LiteralPath $KeyPath -Raw
    $lines = $raw -split "`n" | Where-Object { $_ -notmatch '-----BEGIN|-----END' -and $_.Trim() -ne '' }
    $blob = [Convert]::FromBase64String(($lines -join '').Trim())

    $offset = 0
    if ([System.Text.Encoding]::ASCII.GetString($blob[0..14]) -ne "openssh-key-v1`0") {
        throw "'$KeyPath' is not an OpenSSH private key in the expected openssh-key-v1 format."
    }
    $offset = 15

    $ciphername = [System.Text.Encoding]::ASCII.GetString((Read-SshString $blob ([ref]$offset)))
    [void](Read-SshString $blob ([ref]$offset))  # kdfname, unused when cipher is none
    [void](Read-SshString $blob ([ref]$offset))  # kdfoptions, unused when cipher is none
    $offset += 4  # key count (always 1 for this project's usage)

    if ($ciphername -ne 'none') {
        throw "'$KeyPath' is passphrase-protected (cipher '$ciphername'). Automated key-auth pushes require a passphrase-less private key - this is an existing requirement, not new."
    }

    $publicBlobBytes = Read-SshString $blob ([ref]$offset)

    $privSection = Read-SshString $blob ([ref]$offset)
    $po = 0
    $check1Bytes = $privSection[0..3]; [Array]::Reverse($check1Bytes)
    $check2Bytes = $privSection[4..7]; [Array]::Reverse($check2Bytes)
    if ([System.BitConverter]::ToUInt32($check1Bytes, 0) -ne [System.BitConverter]::ToUInt32($check2Bytes, 0)) {
        throw "'$KeyPath' failed an internal consistency check while parsing - the file may be corrupt."
    }
    $po = 8

    $keytype = [System.Text.Encoding]::ASCII.GetString((Read-SshString $privSection ([ref]$po)))
    if ($keytype -ne 'ssh-rsa') {
        throw "'$KeyPath' is a '$keytype' key - only RSA (ssh-rsa) keys are supported for key-based push."
    }

    [void](Read-SshString $privSection ([ref]$po))  # n - already present in $publicBlobBytes, not needed again
    [void](Read-SshString $privSection ([ref]$po))  # e - ditto
    $d = Read-SshString $privSection ([ref]$po)
    $iqmp = Read-SshString $privSection ([ref]$po)
    $p = Read-SshString $privSection ([ref]$po)
    $q = Read-SshString $privSection ([ref]$po)
    $comment = [System.Text.Encoding]::UTF8.GetString((Read-SshString $privSection ([ref]$po)))

    # PPK's own field order for RSA is d, p, q, iqmp - NOT OpenSSH's n,e,d,iqmp,p,q order.
    $privateBlobBytes = (Write-SshString $d) + (Write-SshString $p) + (Write-SshString $q) + (Write-SshString $iqmp)

    function ToBase64Lines {
        param([byte[]]$Bytes, [int]$Width = 64)
        $b64 = [Convert]::ToBase64String($Bytes)
        $lines = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $b64.Length; $i += $Width) {
            $lines.Add($b64.Substring($i, [Math]::Min($Width, $b64.Length - $i)))
        }
        return $lines
    }

    $macKey = [System.Security.Cryptography.SHA1]::Create().ComputeHash([System.Text.Encoding]::ASCII.GetBytes("putty-private-key-file-mac-key"))
    $mac = New-Object System.Security.Cryptography.HMACSHA1
    $mac.Key = $macKey
    $macData = (Write-SshString ([System.Text.Encoding]::ASCII.GetBytes("ssh-rsa"))) `
        + (Write-SshString ([System.Text.Encoding]::ASCII.GetBytes("none"))) `
        + (Write-SshString ([System.Text.Encoding]::UTF8.GetBytes($comment))) `
        + (Write-SshString $publicBlobBytes) `
        + (Write-SshString $privateBlobBytes)
    $macHex = ($mac.ComputeHash($macData) | ForEach-Object { $_.ToString("x2") }) -join ''

    $pubLines = ToBase64Lines $publicBlobBytes
    $privLines = ToBase64Lines $privateBlobBytes

    $out = New-Object System.Text.StringBuilder
    [void]$out.AppendLine("PuTTY-User-Key-File-2: ssh-rsa")
    [void]$out.AppendLine("Encryption: none")
    [void]$out.AppendLine("Comment: $comment")
    [void]$out.AppendLine("Public-Lines: $($pubLines.Count)")
    foreach ($l in $pubLines) { [void]$out.AppendLine($l) }
    [void]$out.AppendLine("Private-Lines: $($privLines.Count)")
    foreach ($l in $privLines) { [void]$out.AppendLine($l) }
    [void]$out.AppendLine("Private-MAC: $macHex")

    [System.IO.File]::WriteAllText($OutputPath, $out.ToString(), (New-Object System.Text.ASCIIEncoding))
}

# The -pwfile temp file holds the target's password in plaintext. Deleting it
# with -ErrorAction SilentlyContinue meant a genuine deletion failure (file
# locked by an AV scanner, disk full, permissions) left that credential sitting
# in %TEMP% indefinitely with nobody told. Overwrite the content with
# same-length filler first, so even a failed delete leaves no readable password,
# and warn loudly if the delete itself still fails.
function Clear-TempPasswordFile {
    [CmdletBinding()]
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {
        $length = (Get-Item -LiteralPath $Path).Length
        if ($length -gt 0) {
            [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] $length))
        }
    }
    catch {
        Write-Warning ("Could not overwrite the temporary credential file '{0}': {1}" -f $Path, $_.Exception.Message)
    }

    try {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    catch {
        Write-Warning ("Could not delete the temporary credential file '{0}' - its contents were overwritten, but delete it manually: {1}" -f $Path, $_.Exception.Message)
    }
}

function Invoke-PlinkWithAuth {
    param(
        [string]$ExePath,
        [string[]]$Arguments,
        [string]$ExpectedHostKey,
        [string]$PlainPassword,
        [string]$ConvertedKeyPath
    )

    $pwFile = $null
    try {
        $authArgs = @()
        if ($ConvertedKeyPath) {
            $authArgs = @('-i', $ConvertedKeyPath)
        }
        else {
            $pwFile = [System.IO.Path]::GetTempFileName()
            # -Path, not -LiteralPath: this script requires only PS 2.0
            # (#requires above), and Get-Acl/Set-Acl only gained -LiteralPath in
            # PS 3.0. $pwFile comes from GetTempFileName(), never
            # wildcard-shaped, so -Path's wildcard expansion is a safe
            # substitute here.
            $acl = Get-Acl -Path $pwFile
            $acl.SetAccessRuleProtection($true, $false)
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -Path $pwFile -AclObject $acl

            [System.IO.File]::WriteAllText($pwFile, $PlainPassword, (New-Object System.Text.UTF8Encoding($false)))
            $authArgs = @('-pwfile', $pwFile)
        }

        $fullArgs = $authArgs + @('-batch')
        if ($ExpectedHostKey) {
            $fullArgs += @('-hostkey', $ExpectedHostKey)
        }
        $fullArgs += $Arguments
        # Reset first: if the native command fails to launch at all, $LASTEXITCODE
        # keeps whatever the PREVIOUS native call left behind - which, after a
        # successful plink, is 0, silently turning a failed launch into a pass.
        $global:LASTEXITCODE = 0
        $output = Invoke-NativeAllowingStderr { & $ExePath @fullArgs 2>&1 }

        if ($LASTEXITCODE -ne 0) {
            $joined = $output -join "`n"
            if ($joined -match '(?i)host key') {
                throw ("plink failed (exit {0}): the target's SSH host key is not yet trusted by this machine (PuTTY caches trusted keys separately from Windows' own OpenSSH known_hosts). -batch refuses to prompt for an unknown host key rather than risk silently trusting the wrong one. Run plink interactively against this target once to accept its host key, then retry. Raw output: {1}" -f $LASTEXITCODE, $joined)
            }
            throw ("plink failed (exit {0}): {1}" -f $LASTEXITCODE, $joined)
        }

        return $output
    }
    finally {
        if ($pwFile) {
            Clear-TempPasswordFile -Path $pwFile
        }
    }
}

# Both auth modes go through plink.exe now (PuTTY, MIT-licensed - see
# deploy\linux-client\NOTICE): Windows' built-in OpenSSH client cannot do
# unattended password authentication at all, and separately cannot
# negotiate the KEX algorithms modern OpenSSH servers offer (confirmed
# live against a real Debian 13/OpenSSH 10.0p2 target) - plink already
# handles both. Key auth uses a key converted once per script run to
# PuTTY's .ppk format (see Convert-OpenSshKeyToPpk and
# $script:ConvertedKeyPath) since plink cannot read an OpenSSH-format
# key directly.
function Invoke-RemoteCommand {
    param([string]$TargetComputer, [string]$Command, [string]$ExpectedHostKey)

    if ($script:usingPassword) {
        $plainPassword = ConvertTo-PlainText -Secure $script:CredentialPassword
        try {
            $output = Invoke-PlinkWithAuth -ExePath $script:plinkPath -Arguments @('-ssh', "$script:CredentialUsername@$TargetComputer", $Command) -PlainPassword $plainPassword -ExpectedHostKey $ExpectedHostKey
        }
        finally {
            $plainPassword = $null
        }
    }
    else {
        $output = Invoke-PlinkWithAuth -ExePath $script:plinkPath -Arguments @('-ssh', "$script:CredentialUsername@$TargetComputer", $Command) -ConvertedKeyPath $script:ConvertedKeyPath -ExpectedHostKey $ExpectedHostKey
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
    # Both auth modes need plink.exe now - Windows' native OpenSSH client
    # is no longer used anywhere in this script.
    if (-not (Test-Path -LiteralPath $plinkPath)) {
        throw "Required tool was not found: $plinkPath. See deploy\linux-client\NOTICE for how to obtain it."
    }
    if (-not $usingPassword) {
        if (-not (Test-Path -LiteralPath $KeyPath)) {
            throw "SSH private key was not found: $KeyPath"
        }
    }

    $script:ConvertedKeyPath = $null
    if (-not $usingPassword) {
        $script:ConvertedKeyPath = [System.IO.Path]::GetTempFileName() + '.ppk'
        Convert-OpenSshKeyToPpk -KeyPath $KeyPath -OutputPath $script:ConvertedKeyPath
    }

    $hadFailure = $false
    try {
        foreach ($computer in $ComputerName) {
            try {
                Write-Host "Connecting: $computer"
                # -ceq, not -eq: Linux usernames are case-sensitive, unlike
                # PowerShell's default string comparison.
                $sudoPrefix = if ($CredentialUsername -ceq 'root') { '' } else { 'sudo ' }
                $uninstallCommand = Get-LinuxUninstallCommand -InstallPath $InstallPath -SudoPrefix $sudoPrefix

                Write-Host "Removing client: $computer"
                Invoke-RemoteCommand -TargetComputer $computer -Command $uninstallCommand -ExpectedHostKey $ExpectedHostKey | Out-Null

                Write-Host "Client removed: $computer"
            }
            catch {
                $hadFailure = $true
                [Console]::Error.WriteLine(("Failed to uninstall Linux client on {0}: {1}" -f $computer, $_.Exception.Message))
            }
        }
    }
    finally {
        if ($script:ConvertedKeyPath) {
            Remove-Item -LiteralPath $script:ConvertedKeyPath -Force -ErrorAction SilentlyContinue
        }
    }

    if ($hadFailure) {
        exit 1
    }
}
