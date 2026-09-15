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
    [ValidateRange(1, 1440)]
    [int]$StatusIntervalMinutes = 30,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = '/opt/windows-inventory-lite',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientBinaryPath,

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

# Absolute path on the MANAGED LINUX HOST. Must stay identical to
# WindowsInventoryLiteServer.cs's LinuxClientEnvFilePath.
$script:LinuxClientEnvFilePath = '/etc/wil-linux-client.env'

# POSIX shell metacharacters - InstallPath/ServerUrl/Token end up
# interpolated into a remote shell command string built in this script
# (see Invoke-RemoteCommand's callers), so a value containing any of
# these could inject additional commands on the TARGET machine. Rejects
# rather than attempts to safely quote/escape, matching this project's
# existing ValidateBatchSafe convention for the Windows GPO cmd path.
# Space/tab are rejected too: none of the interpolation sites below quote
# these variables, so e.g. "/opt/wil /usr" word-splits into two arguments
# on the remote shell despite containing no character this list used to
# forbid.
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
# it has no opinion on whether the path itself is a sane place to install
# into or rm -rf. This used to require "at least two path segments," which
# a bare top-level directory like /usr or /etc could not pass - but that
# check was defeated by traversal ("/opt/../etc" has two segments and no
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

# Generates the two systemd unit files that make the client run on a
# schedule: a oneshot .service (collect, POST, exit) triggered by a .timer
# (systemd owns scheduling - the client itself has no internal loop). Pure
# function of its parameters, no network/SSH - directly unit-testable.
function New-SystemdUnitFiles {
    param(
        [string]$Directory,
        [string]$InstallDirectory,
        [string]$Url,
        [string]$SharedToken,
        [int]$Hours
    )

    Test-PosixShellSafe -Value $InstallDirectory -FieldName 'InstallPath'
    Test-LinuxInstallPathSafe -InstallPath $InstallDirectory
    Test-PosixShellSafe -Value $Url -FieldName 'ServerUrl'
    Test-PosixShellSafe -Value $SharedToken -FieldName 'Token'

    $execStart = "$InstallDirectory/wil-linux-client --server-url `"$Url`""

    # The token is deliberately NOT on the ExecStart line - a command-line
    # argument is readable from /proc/<pid>/cmdline by any local user on the
    # managed host, and from this unit file itself (mode 644). It goes in a
    # mode-600 EnvironmentFile instead, mirroring the fix this project already
    # applied to the Windows service ImagePath (see docs/threat-model.md).
    # Systemd's "-" ignore-if-missing prefix is deliberately NOT used: a
    # silently-absent token file would put the client back in the "reports are
    # rejected and nobody knows why" state.
    $environmentFileLine = ''
    if ($SharedToken) {
        $environmentFileLine = "EnvironmentFile=$script:LinuxClientEnvFilePath`n"
    }

    $serviceContent = @"
[Unit]
Description=Windows Inventory Lite - Linux client (one-shot report)

[Service]
Type=oneshot
${environmentFileLine}ExecStart=$execStart
"@

    $timerContent = @"
[Unit]
Description=Runs the Windows Inventory Lite Linux client every $Hours hour(s)

[Timer]
OnBootSec=5min
OnUnitActiveSec=${Hours}h
Unit=wil-linux-client.service

[Install]
WantedBy=timers.target
"@

    $servicePath = Join-Path -Path $Directory -ChildPath 'wil-linux-client.service'
    $timerPath = Join-Path -Path $Directory -ChildPath 'wil-linux-client.timer'
    [System.IO.File]::WriteAllText($servicePath, $serviceContent, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($timerPath, $timerContent, (New-Object System.Text.UTF8Encoding($false)))

    return @{ ServicePath = $servicePath; TimerPath = $timerPath }
}

# Status-ping counterpart to New-SystemdUnitFiles above - same structure,
# but the generated service execs with --mode status against the
# merge-only endpoint, and the timer's interval is in minutes, not hours.
# Must stay byte-for-byte in sync with GenerateSystemdStatusUnitLines/
# GenerateSystemdStatusTimerLines (WindowsInventoryLiteServer.cs).
function New-SystemdStatusUnitFiles {
    param(
        [string]$Directory,
        [string]$InstallDirectory,
        [string]$Url,
        [string]$SharedToken,
        [int]$Minutes
    )

    Test-PosixShellSafe -Value $InstallDirectory -FieldName 'InstallPath'
    Test-LinuxInstallPathSafe -InstallPath $InstallDirectory
    Test-PosixShellSafe -Value $Url -FieldName 'ServerUrl'
    Test-PosixShellSafe -Value $SharedToken -FieldName 'Token'

    $execStart = "$InstallDirectory/wil-linux-client --server-url `"$Url`" --mode status"

    # Same EnvironmentFile reasoning as New-SystemdUnitFiles above.
    $environmentFileLine = ''
    if ($SharedToken) {
        $environmentFileLine = "EnvironmentFile=$script:LinuxClientEnvFilePath`n"
    }

    $serviceContent = @"
[Unit]
Description=Windows Inventory Lite - Linux client service-status ping (one-shot report)

[Service]
Type=oneshot
${environmentFileLine}ExecStart=$execStart
"@

    $timerContent = @"
[Unit]
Description=Runs the Windows Inventory Lite Linux client service-status ping every $Minutes minute(s)

[Timer]
OnBootSec=5min
OnUnitActiveSec=${Minutes}min
Unit=wil-linux-client-status.service

[Install]
WantedBy=timers.target
"@

    $servicePath = Join-Path -Path $Directory -ChildPath 'wil-linux-client-status.service'
    $timerPath = Join-Path -Path $Directory -ChildPath 'wil-linux-client-status.timer'
    [System.IO.File]::WriteAllText($servicePath, $serviceContent, (New-Object System.Text.UTF8Encoding($false)))
    [System.IO.File]::WriteAllText($timerPath, $timerContent, (New-Object System.Text.UTF8Encoding($false)))

    return @{ ServicePath = $servicePath; TimerPath = $timerPath }
}

# Writes the mode-600 counterpart to the unit files' EnvironmentFile= line.
# The 600 mode is applied on the TARGET host by the install command chain -
# this only stages the content locally. Must stay byte-for-byte in sync with
# GenerateSystemdEnvFileLines (WindowsInventoryLiteServer.cs).
# This file holds the ingestion token in plaintext on the LOCAL machine
# running this script, same class of secret as the plink -pwfile
# Invoke-PlinkWithAuth restricts - so it gets the identical
# ACL-before-content treatment here (protect + grant FullControl to only
# the current user), rather than sitting at whatever ACL $Directory
# happens to inherit. The caller is responsible for the matching secure
# delete once this file is no longer needed (Clear-TempPasswordFile, the
# same helper the plink password file already uses).
function New-SystemdEnvFile {
    param(
        [string]$Directory,
        [string]$SharedToken
    )

    Test-PosixShellSafe -Value $SharedToken -FieldName 'Token'

    $envPath = Join-Path -Path $Directory -ChildPath 'wil-linux-client.env'
    New-Item -Path $envPath -ItemType File -Force | Out-Null
    # -Path, not -LiteralPath: this script requires only PS 2.0 (#requires
    # above), and Get-Acl/Set-Acl only gained -LiteralPath in PS 3.0.
    # $envPath is always a script-built path, never wildcard-shaped, so
    # -Path's wildcard expansion is a safe substitute here.
    $acl = Get-Acl -Path $envPath
    $acl.SetAccessRuleProtection($true, $false)
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -Path $envPath -AclObject $acl

    [System.IO.File]::WriteAllText($envPath, "WIL_INGESTION_TOKEN=$SharedToken`n", (New-Object System.Text.UTF8Encoding($false)))
    return @{ EnvPath = $envPath }
}

# $ErrorActionPreference = 'Stop' (set script-wide, above) turns EVERY line
# a native command writes to stderr into a terminating error the instant
# `2>&1` merges it into the pipeline - even a perfectly normal, successful
# command that merely logs informational text to stderr (systemd's own
# "systemctl enable" prints "Created symlink ..." to stderr on SUCCESS,
# confirmed by live testing: a real install fully succeeded on the remote
# host - service running, timer active - yet was reported as a failure
# here, with that exact success message as the "error"). Native stderr
# text must be allowed to flow through as plain output and be judged by
# the command's actual exit code instead, not treated as fatal on sight.
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
        # $Bytes[$Offset.Value..($Offset.Value - 1)] for a zero-length string
        # is a DESCENDING PowerShell range (e.g. 5..4), which returns the
        # wrong byte(s) instead of an empty array - only the comment field
        # can be zero-length in practice, but handle it explicitly.
        if ($len -eq 0) {
            return ,(New-Object byte[] 0)
        }
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

    # [System.IO.File]::ReadAllText, not Get-Content -Raw: this script
    # declares #requires -Version 2.0, and -Raw is a PS 3.0+ parameter.
    $raw = [System.IO.File]::ReadAllText($KeyPath)
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

# Runs plink.exe/pscp.exe with the password supplied via a short-lived,
# current-user-only temp file (-pwfile) instead of the command line (-pw,
# visible to any other process/user on this host via Get-CimInstance
# Win32_Process/Task Manager for the connection's duration) and without any
# interactive prompt (-batch).
#
# An earlier version of this function tried to answer plink's interactive
# host-key/password prompts by watching redirected stdout/stderr and
# writing to redirected stdin. Live testing against this project's real
# Debian test fleet found that design fundamentally cannot work: plink
# writes its interactive prompts directly to the process's console (the
# same reason it can suppress password echo), not to the redirected
# stdout/stderr streams .NET's Process class exposes - so a fully
# redirected, windowless child process (CreateNoWindow = $true, as this
# function used) never surfaces the prompt text at all, and a
# StandardInput.WriteLine() answer is never actually delivered to plink's
# real prompt reader either. This was invisible to Pester (the function
# was always mocked) and even to a first pass of manual testing against a
# single already-authorized host (auth succeeded silently via the
# Windows OpenSSH ssh-agent's own loaded key, before any password prompt
# was ever needed) - it only surfaced against a second host where the
# agent key was not authorized and a real password prompt was required,
# which then hung until the function's own timeout fired every time.
# -pwfile (added in PuTTY 0.81) sidesteps the whole console-vs-redirected-
# stream problem: plink reads the password from the file directly, no
# interactive prompt involved at all. -batch then makes an unknown/
# mismatched host key a clean, immediate failure instead of a prompt this
# function has no way to answer - see Invoke-RemoteCommand's error
# handling for the operator-facing message that results.
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

    # A silent auth-mode fallback in credential-handling code is a hard
    # error, not a fallback: every real call site always supplies exactly
    # one of these two, so either state means a bug elsewhere (or a future
    # caller that forgot to pass either).
    if ([string]::IsNullOrEmpty($ConvertedKeyPath) -and [string]::IsNullOrEmpty($PlainPassword)) {
        throw "Invoke-PlinkWithAuth requires either -PlainPassword or -ConvertedKeyPath."
    }
    if (-not [string]::IsNullOrEmpty($ConvertedKeyPath) -and -not [string]::IsNullOrEmpty($PlainPassword)) {
        throw "Invoke-PlinkWithAuth requires exactly one of -PlainPassword or -ConvertedKeyPath, not both."
    }

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
        # successful plink/pscp, is 0, silently turning a failed launch into a pass.
        $global:LASTEXITCODE = 0
        $output = Invoke-NativeAllowingStderr { & $ExePath @fullArgs 2>&1 }

        if ($LASTEXITCODE -ne 0) {
            $joined = $output -join "`n"
            if ($joined -match '(?i)host key') {
                if ($ExpectedHostKey) {
                    throw ("plink/pscp failed (exit {0}): the target's SSH host key has CHANGED since it was last trusted here. This can mean the server was reinstalled or reimaged, or that something is intercepting the connection - only proceed if you can confirm this change is expected. Trust the new key from the Linux Client actions job log to update the stored fingerprint. Raw output: {1}" -f $LASTEXITCODE, $joined)
                }
                throw ("plink/pscp failed (exit {0}): the target's SSH host key is not yet trusted by this machine (PuTTY caches trusted keys separately from Windows' own OpenSSH known_hosts). -batch refuses to prompt for an unknown host key rather than risk silently trusting the wrong one. Trust this host key from the Linux Client actions job log, or connect once interactively instead. Raw output: {1}" -f $LASTEXITCODE, $joined)
            }
            throw ("plink/pscp failed (exit {0}): {1}" -f $LASTEXITCODE, $joined)
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
# unattended password authentication at all (refuses to read a password
# from non-interactive stdin), and separately cannot negotiate the KEX
# algorithms modern OpenSSH servers offer (confirmed live against a real
# Debian 13/OpenSSH 10.0p2 target) - plink already handles both. Key auth
# uses a key converted once per script run to PuTTY's .ppk format (see
# Convert-OpenSshKeyToPpk and $script:ConvertedKeyPath) since plink cannot
# read an OpenSSH-format key directly.
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

function Copy-FileToRemote {
    param([string]$TargetComputer, [string]$LocalPath, [string]$RemotePath, [string]$ExpectedHostKey)

    if ($script:usingPassword) {
        $plainPassword = ConvertTo-PlainText -Secure $script:CredentialPassword
        try {
            Invoke-PlinkWithAuth -ExePath $script:pscpPath -Arguments @($LocalPath, "${script:CredentialUsername}@${TargetComputer}:$RemotePath") -PlainPassword $plainPassword -ExpectedHostKey $ExpectedHostKey | Out-Null
        }
        finally {
            $plainPassword = $null
        }
    }
    else {
        Invoke-PlinkWithAuth -ExePath $script:pscpPath -Arguments @($LocalPath, "${script:CredentialUsername}@${TargetComputer}:$RemotePath") -ConvertedKeyPath $script:ConvertedKeyPath -ExpectedHostKey $ExpectedHostKey | Out-Null
    }
}

# Wrapped so Pester can dot-source this file (". $ScriptPath -ComputerName ...
# -CredentialUsername ... -CredentialPassword ...") to load the functions
# above for direct unit testing without attempting a real SSH connection -
# same technique used in src\Install-Client.ps1 and
# deploy\client\Deploy-ClientGpo.ps1.
if ($MyInvocation.InvocationName -ne '.') {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not $ScriptRoot) {
        $ScriptRoot = (Get-Location).Path
    }
    $projectRoot = Split-Path -Parent $ScriptRoot

    if (-not $ClientBinaryPath) {
        $ClientBinaryPath = Join-Path -Path $projectRoot -ChildPath 'build\wil-linux-client'
    }
    if (-not (Test-Path -LiteralPath $ClientBinaryPath)) {
        throw "Linux client binary was not found: $ClientBinaryPath. Run Build-LinuxClient.ps1, then re-run Install-Server.ps1 to copy the result into the Linux client package folder (done automatically when the build output is at build\wil-linux-client)."
    }

    $plinkPath = Join-Path -Path $projectRoot -ChildPath 'deploy\linux-client\plink.exe'
    $pscpPath = Join-Path -Path $projectRoot -ChildPath 'deploy\linux-client\pscp.exe'
    # Both auth modes need plink.exe/pscp.exe now - Windows' native OpenSSH
    # client is no longer used anywhere in this script (see
    # Invoke-RemoteCommand/Copy-FileToRemote and Convert-OpenSshKeyToPpk's
    # own doc comment for why).
    foreach ($requiredPuttyTool in @($plinkPath, $pscpPath)) {
        if (-not (Test-Path -LiteralPath $requiredPuttyTool)) {
            throw "Required tool was not found: $requiredPuttyTool. See deploy\linux-client\NOTICE for how to obtain it."
        }
    }
    if (-not $usingPassword) {
        if (-not (Test-Path -LiteralPath $KeyPath)) {
            throw "SSH private key was not found: $KeyPath"
        }
    }

    $script:ConvertedKeyPath = $null
    if (-not $usingPassword) {
        # [System.IO.Path]::GetTempFileName() creates an empty file at the
        # name it returns - appending '.ppk' targets a DIFFERENT path, so the
        # original placeholder must be deleted here or it leaks in %TEMP%
        # forever (only the .ppk path is ever cleaned up below).
        $tempPlaceholder = [System.IO.Path]::GetTempFileName()
        $script:ConvertedKeyPath = $tempPlaceholder + '.ppk'
        Remove-Item -LiteralPath $tempPlaceholder -Force -ErrorAction SilentlyContinue
        try {
            Convert-OpenSshKeyToPpk -KeyPath $KeyPath -OutputPath $script:ConvertedKeyPath

            # The converted .ppk is a fully decrypted RSA private key, alive
            # for the entire script run across every target in $ComputerName,
            # its path visible in process listings via -i - it gets the same
            # restricted-ACL treatment as the -pwfile temp file (see
            # Invoke-PlinkWithAuth) and the systemd env file
            # (New-SystemdEnvFile) below, rather than just inheriting
            # %TEMP%'s own ACL.
            # -Path, not -LiteralPath: this script requires only PS 2.0
            # (#requires above), and Get-Acl/Set-Acl only gained -LiteralPath
            # in PS 3.0. $script:ConvertedKeyPath is always a script-built
            # path, never wildcard-shaped, so -Path's wildcard expansion is a
            # safe substitute here.
            $acl = Get-Acl -Path $script:ConvertedKeyPath
            $acl.SetAccessRuleProtection($true, $false)
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -Path $script:ConvertedKeyPath -AclObject $acl
        }
        catch {
            # Conversion (or the ACL step) itself failed - the outer
            # try/finally below is not entered yet at this point, so this
            # narrower cleanup covers the gap. Plain delete, not
            # Clear-TempPasswordFile: the file may not exist yet or may be
            # only partially written.
            Remove-Item -LiteralPath $script:ConvertedKeyPath -Force -ErrorAction SilentlyContinue
            throw
        }
    }

    # Live testing against this project's real Debian test fleet found a
    # genuine target: connecting as root on a minimal/base install where
    # sudo is not present at all ("sudo: command not found") - an
    # unconditional "sudo " prefix would fail outright there, even though
    # root never needed elevation in the first place. Skip the prefix
    # specifically when the connecting user already IS root; a non-root
    # CredentialUsername still gets "sudo " exactly as before.
    # -ceq, not -eq: Linux usernames are case-sensitive, unlike PowerShell's
    # default string comparison - "Root" is a different (and non-existent,
    # in practice) account from "root" on the target, not an alternate
    # spelling of it.
    $sudoPrefix = if ($CredentialUsername -ceq 'root') { '' } else { 'sudo ' }

    $hadFailure = $false
    $stagingDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString())
    New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null
    # Declared here, not inside the try block below: under Set-StrictMode
    # -Version 2.0 (set script-wide), the finally block's own `if
    # ($envFile)` check would itself throw VariableNotFoundStrict - masking
    # whatever real error triggered the finally in the first place - if an
    # exception happened to strike before the try block's own assignment to
    # $envFile was reached.
    $envFile = $null
    try {
        $units = New-SystemdUnitFiles -Directory $stagingDir -InstallDirectory $InstallPath -Url $ServerUrl -SharedToken $Token -Hours $IntervalHours
        $statusUrl = $ServerUrl.TrimEnd('/') + '/service-status'
        $statusUnits = New-SystemdStatusUnitFiles -Directory $stagingDir -InstallDirectory $InstallPath -Url $statusUrl -SharedToken $Token -Minutes $StatusIntervalMinutes

        if ($Token) {
            $envFile = New-SystemdEnvFile -Directory $stagingDir -SharedToken $Token
        }

        foreach ($computer in $ComputerName) {
            try {
                Write-Host "Connecting: $computer"
                $remoteTmpDir = "/tmp/wil-linux-client-install"
                # Two bugs fixed together here:
                #
                # 1. A sudo-created staging dir is root-owned, so the following
                #    unprivileged scp/pscp copies fail on every file whenever the
                #    connecting user is not root. /tmp is world-writable, so the
                #    staging dir is created as the CONNECTING user - which works
                #    whether that user is root or not. sudo is kept only for
                #    InstallPath, which genuinely needs root.
                # 2. /tmp/wil-linux-client-install is a fixed, predictable path.
                #    A local low-privilege user on the target could pre-create it,
                #    or symlink it somewhere, and race the push to substitute files
                #    that then get sudo-mv'd into /etc/systemd/system/ and chmod
                #    755'd as an executable systemd later runs as root. "rm -rf"
                #    first removes anything pre-existing (symlink or not), and 700
                #    keeps other local users out of the fresh one.
                Invoke-RemoteCommand -TargetComputer $computer -Command "rm -rf $remoteTmpDir && mkdir -p $remoteTmpDir && chmod 700 $remoteTmpDir && ${sudoPrefix}mkdir -p $InstallPath" -ExpectedHostKey $ExpectedHostKey | Out-Null

                Write-Host "Copying client binary: $computer"
                Copy-FileToRemote -TargetComputer $computer -LocalPath $ClientBinaryPath -RemotePath "$remoteTmpDir/wil-linux-client" -ExpectedHostKey $ExpectedHostKey
                Copy-FileToRemote -TargetComputer $computer -LocalPath $units.ServicePath -RemotePath "$remoteTmpDir/wil-linux-client.service" -ExpectedHostKey $ExpectedHostKey
                Copy-FileToRemote -TargetComputer $computer -LocalPath $units.TimerPath -RemotePath "$remoteTmpDir/wil-linux-client.timer" -ExpectedHostKey $ExpectedHostKey
                Copy-FileToRemote -TargetComputer $computer -LocalPath $statusUnits.ServicePath -RemotePath "$remoteTmpDir/wil-linux-client-status.service" -ExpectedHostKey $ExpectedHostKey
                Copy-FileToRemote -TargetComputer $computer -LocalPath $statusUnits.TimerPath -RemotePath "$remoteTmpDir/wil-linux-client-status.timer" -ExpectedHostKey $ExpectedHostKey
                if ($envFile) {
                    Copy-FileToRemote -TargetComputer $computer -LocalPath $envFile.EnvPath -RemotePath "$remoteTmpDir/wil-linux-client.env" -ExpectedHostKey $ExpectedHostKey
                }

                Write-Host "Installing service: $computer"
                Test-PosixShellSafe -Value $InstallPath -FieldName 'InstallPath'
                Test-LinuxInstallPathSafe -InstallPath $InstallPath
                # chmod BEFORE the file is in place would race; chmod right after
                # the mv is the smallest window available over a single SSH command
                # chain. 600 + root ownership (the mv runs under sudo for a non-root
                # connecting user, and as root directly otherwise) is what keeps the
                # ingestion token off every other local user's radar.
                $envInstallFragment = ''
                if ($envFile) {
                    $envInstallFragment = "${sudoPrefix}mv $remoteTmpDir/wil-linux-client.env $script:LinuxClientEnvFilePath && " +
                        "${sudoPrefix}chmod 600 $script:LinuxClientEnvFilePath && "
                }
                $installCommand = "${sudoPrefix}mv $remoteTmpDir/wil-linux-client $InstallPath/wil-linux-client && " +
                    "${sudoPrefix}chmod 755 $InstallPath/wil-linux-client && " +
                    "${sudoPrefix}mv $remoteTmpDir/wil-linux-client.service /etc/systemd/system/wil-linux-client.service && " +
                    "${sudoPrefix}mv $remoteTmpDir/wil-linux-client.timer /etc/systemd/system/wil-linux-client.timer && " +
                    "${sudoPrefix}mv $remoteTmpDir/wil-linux-client-status.service /etc/systemd/system/wil-linux-client-status.service && " +
                    "${sudoPrefix}mv $remoteTmpDir/wil-linux-client-status.timer /etc/systemd/system/wil-linux-client-status.timer && " +
                    $envInstallFragment +
                    "${sudoPrefix}rm -rf $remoteTmpDir && " +
                    "${sudoPrefix}systemctl daemon-reload && " +
                    "${sudoPrefix}systemctl enable --now wil-linux-client.timer && " +
                    "${sudoPrefix}systemctl enable --now wil-linux-client-status.timer && " +
                    # enable --now on a timer that was already active (a reinstall over an
                    # existing client) does not reset OnUnitActiveSec's countdown - restart
                    # unconditionally does, so a fresh binary is scheduled promptly on its
                    # normal cadence (6h / 30min) whether this is a fresh install or a
                    # reinstall. OnBootSec=5min does NOT help here: it fires once, relative
                    # to actual machine boot, not to this restart - on a long-uptime host it
                    # never fires again this session, so without an explicit immediate run
                    # below, the fresh binary's first real report could still be up to a
                    # full 6h/30min away.
                    "${sudoPrefix}systemctl restart wil-linux-client.timer && " +
                    "${sudoPrefix}systemctl restart wil-linux-client-status.timer && " +
                    # Best-effort immediate report so an admin sees fresh data right after
                    # install/reinstall instead of waiting out the normal cadence. Wrapped in
                    # `|| true` so a transient collection failure here (e.g. dpkg momentarily
                    # locked right after other package activity) does not mark the whole
                    # install job as failed - the scheduled timers above already guarantee a
                    # real report lands on the normal cadence regardless.
                    "(${sudoPrefix}systemctl start wil-linux-client.service || true) && " +
                    "(${sudoPrefix}systemctl start wil-linux-client-status.service || true)"
                Invoke-RemoteCommand -TargetComputer $computer -Command $installCommand -ExpectedHostKey $ExpectedHostKey | Out-Null

                Write-Host "Client installed: $computer"
            }
            catch {
                $hadFailure = $true
                [Console]::Error.WriteLine(("Failed to install Linux client on {0}: {1}" -f $computer, $_.Exception.Message))
            }
        }
    }
    finally {
        # Same overwrite-then-delete treatment as the plink password file
        # (Clear-TempPasswordFile) - the ingestion token in this specific
        # file is the only genuinely sensitive content anywhere in
        # $stagingDir (the systemd unit files never embed it, by design),
        # so it alone gets the loud-on-failure secure delete before the
        # blanket recursive cleanup below silently sweeps up everything
        # else.
        if ($envFile) {
            Clear-TempPasswordFile -Path $envFile.EnvPath
        }
        Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
        if ($script:ConvertedKeyPath) {
            # Same loud-on-failure overwrite-then-delete as the plink
            # password file and the env file above - this is a decrypted RSA
            # private key, not a file a silent best-effort delete is enough
            # for.
            Clear-TempPasswordFile -Path $script:ConvertedKeyPath
        }
    }

    if ($hadFailure) {
        exit 1
    }
}
