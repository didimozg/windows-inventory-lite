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

# Windows' OpenSSH client (ssh.exe) has NO command-line option to pin a host
# key by fingerprint - verified against OpenSSH_for_Windows_10.0p2:
# "-o ExpectedHostKeyFingerprint=..." is rejected with "Bad configuration
# option". Pinning requires a known_hosts-format file plus
# -o UserKnownHostsFile / -o StrictHostKeyChecking=yes. A known_hosts line
# carries the FULL base64 public key, but this project stores only the
# SHA256:<base64> fingerprint (that is what plink's -hostkey consumes on the
# password path, and it is a one-way hash - a known_hosts line cannot be
# derived from it).
#
# So: ask the target for the keys it presents (ssh-keyscan), fingerprint them
# locally (ssh-keygen -lf), and only trust the one whose fingerprint matches
# the value the server pinned. Same trust strength as plink's -hostkey - the
# comparison happens here, before ssh.exe is allowed to trust anything - and
# it reuses the exact same stored fingerprint value and format the password
# path already uses, rather than introducing a second trust store.
#
# ssh-keygen -lf emits one line per NON-COMMENT known_hosts line, in the same
# order, with the fingerprint as whitespace-delimited field 2. Pure function
# of its inputs, no I/O - directly unit-testable, same convention as
# New-SystemdUnitFiles.
function Select-KnownHostsLineByFingerprint {
    param(
        [string[]]$KeyScanLines,
        [string[]]$FingerprintLines,
        [string]$ExpectedHostKey
    )

    if (-not $ExpectedHostKey) {
        return $null
    }

    $keyLines = @()
    foreach ($line in $KeyScanLines) {
        if ($line -and -not $line.TrimStart().StartsWith('#')) {
            $keyLines += $line
        }
    }

    $index = 0
    foreach ($fingerprintLine in $FingerprintLines) {
        if ($index -ge $keyLines.Count) {
            break
        }
        $fields = $fingerprintLine -split '\s+'
        if ($fields.Count -ge 2 -and $fields[1] -ceq $ExpectedHostKey) {
            return $keyLines[$index]
        }
        $index++
    }

    return $null
}

# Builds the ssh.exe/scp.exe host-key options. With a verified known_hosts
# file, pin hard to it: GlobalKnownHostsFile is aimed at a path that does not
# exist so the machine-wide ssh_known_hosts cannot silently satisfy the check,
# and CheckHostIP=no suppresses the unrelated address-mismatch warning.
# Without a pinned fingerprint this is a genuine first contact with a
# brand-new host, so accept-new (TOFU) is kept deliberately - the same trust
# model the credentials path already applies, not a stricter one. Pure
# function, unit-testable.
function Get-OpenSshKeyModeOptions {
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$ExpectedHostKey,
        [AllowEmptyString()]
        [AllowNull()]
        [string]$KnownHostsPath
    )

    if ($ExpectedHostKey -and $KnownHostsPath) {
        return @(
            '-o', "UserKnownHostsFile=$KnownHostsPath",
            '-o', "GlobalKnownHostsFile=$KnownHostsPath.absent",
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'CheckHostIP=no'
        )
    }

    return @('-o', 'StrictHostKeyChecking=accept-new')
}

# Execs ssh-keyscan/ssh-keygen and returns the path to a temp known_hosts file
# holding ONLY the key whose fingerprint matches $ExpectedHostKey. Throws if
# nothing matches. The throw text deliberately contains the literal words
# "host key": the server's ClassifyHostKeyFailure searches the child process
# output for that substring to decide "changed" vs "unknown", so a message
# without it would be misreported to the operator as a generic failure.
# Builds the "no keys retrieved from ssh-keyscan" failure message, folding in
# whatever ssh-keyscan wrote to stderr along the way. Found via a real fleet
# push: a target running a newer OpenSSH (Debian 13, OpenSSH 10.0) can offer
# a KEX algorithm (sntrup761x25519-sha512@openssh.com) an older Windows
# OpenSSH client build does not know, so ssh-keyscan returns zero keys and
# writes "choose_kex: unsupported KEX method ..." to stderr - previously
# discarded (the caller redirected stderr to $null), so the operator only
# ever saw a generic "host unreachable" message for a host that answered
# fine on port 22. The literal substring "host key" is deliberately replaced
# if it appears in the stderr detail: ClassifyHostKeyFailure on the server
# side greps the combined output for that exact substring to decide whether
# a failure means the target's key changed, and a diagnostic detail here
# must never accidentally trigger that classification for an unrelated
# failure (missing tool, KEX mismatch, timeout). Pure function, unit-tested.
function Format-SshKeyscanFailureMessage {
    param(
        [string]$TargetComputer,
        [string[]]$ScanErrors
    )

    $detail = ''
    if ($ScanErrors -and $ScanErrors.Count -gt 0) {
        $safeDetail = ($ScanErrors -join '; ') -replace '(?i)host key', 'host-key'
        $detail = " ssh-keyscan reported: $safeDetail"
    }
    return "Could not reach $TargetComputer on port 22 to verify its identity - the host may be unreachable, its SSH service may not be running, or a firewall may be blocking the connection.$detail"
}

function New-PinnedKnownHostsFile {
    param(
        [string]$TargetComputer,
        [string]$ExpectedHostKey
    )

    $knownHostsPath = [System.IO.Path]::GetTempFileName()
    # 2>&1, not 2>$null: a target that offers no KEX algorithm this ssh-keyscan
    # build knows (see Format-SshKeyscanFailureMessage above) produces zero key
    # lines on stdout and the actual reason on stderr - losing stderr here was
    # exactly what turned that failure into a misleading "host unreachable".
    # Native-command stderr lines redirected this way arrive as
    # ErrorRecord objects, not plain strings, so they're split back out below.
    $scanOutput = Invoke-NativeAllowingStderr { & ssh-keyscan.exe -T 10 $TargetComputer 2>&1 }
    $scanLines = @()
    $scanErrors = @()
    foreach ($item in $scanOutput) {
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $scanErrors += $item.Exception.Message
        }
        else {
            $scanLines += [string]$item
        }
    }

    $scanFile = "$knownHostsPath.scan"
    [System.IO.File]::WriteAllLines($scanFile, $scanLines, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $fingerprintOutput = Invoke-NativeAllowingStderr { & ssh-keygen.exe -lf $scanFile 2>$null }
        $fingerprintLines = @($fingerprintOutput | ForEach-Object { [string]$_ })
    }
    finally {
        Remove-Item -LiteralPath $scanFile -Force -ErrorAction SilentlyContinue
    }

    $nonCommentScanLines = @($scanLines | Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') })
    if ($nonCommentScanLines.Count -eq 0) {
        Remove-Item -LiteralPath $knownHostsPath -Force -ErrorAction SilentlyContinue
        throw (Format-SshKeyscanFailureMessage -TargetComputer $TargetComputer -ScanErrors $scanErrors)
    }

    $match = Select-KnownHostsLineByFingerprint -KeyScanLines $scanLines -FingerprintLines $fingerprintLines -ExpectedHostKey $ExpectedHostKey
    if (-not $match) {
        Remove-Item -LiteralPath $knownHostsPath -Force -ErrorAction SilentlyContinue
        throw "The target's SSH host key does not match the fingerprint trusted for this host ($ExpectedHostKey). This can mean the server was reinstalled or reimaged, or that something is intercepting the connection - only proceed if you can confirm this change is expected. Trust the new host key from the Linux Client actions job log to update the stored fingerprint."
    }

    [System.IO.File]::WriteAllLines($knownHostsPath, @($match), (New-Object System.Text.UTF8Encoding($false)))
    return $knownHostsPath
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

function Invoke-PlinkWithPasswordFile {
    param(
        [string]$ExePath,
        [string[]]$Arguments,
        [string]$PlainPassword,
        [string]$ExpectedHostKey
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

        $fullArgs = @('-pwfile', $pwFile, '-batch')
        if ($ExpectedHostKey) {
            $fullArgs += @('-hostkey', $ExpectedHostKey)
        }
        $fullArgs += $Arguments
        # Reset first: if the native command fails to launch at all, $LASTEXITCODE
        # keeps whatever the PREVIOUS native call left behind - which, after a
        # successful ssh.exe, is 0, silently turning a failed launch into a pass.
        $global:LASTEXITCODE = 0
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
        Clear-TempPasswordFile -Path $pwFile
    }
}

function Invoke-RemoteCommand {
    param([string]$TargetComputer, [string]$Command, [string]$ExpectedHostKey)

    if ($script:usingPassword) {
        $plainPassword = ConvertTo-PlainText -Secure $script:CredentialPassword
        try {
            $output = Invoke-PlinkWithPasswordFile -ExePath $script:plinkPath -Arguments @('-ssh', "$script:CredentialUsername@$TargetComputer", $Command) -PlainPassword $plainPassword -ExpectedHostKey $ExpectedHostKey
        }
        finally {
            $plainPassword = $null
        }
    }
    else {
        $knownHostsPath = $null
        try {
            if ($ExpectedHostKey) {
                $knownHostsPath = New-PinnedKnownHostsFile -TargetComputer $TargetComputer -ExpectedHostKey $ExpectedHostKey
            }
            $hostKeyOptions = Get-OpenSshKeyModeOptions -ExpectedHostKey $ExpectedHostKey -KnownHostsPath $knownHostsPath
            $global:LASTEXITCODE = 0
            $output = Invoke-NativeAllowingStderr { & ssh.exe -i $script:KeyPath -o BatchMode=yes @hostKeyOptions -o ConnectTimeout=10 "$script:CredentialUsername@$TargetComputer" $Command 2>&1 }
        }
        finally {
            if ($knownHostsPath) {
                Remove-Item -LiteralPath $knownHostsPath -Force -ErrorAction SilentlyContinue
            }
        }
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
        # This script only runs remote commands, never scp - so ssh.exe alone,
        # plus the keyscan/keygen pair when a host key is pinned.
        $requiredOpenSshTools = @('ssh.exe')
        if ($ExpectedHostKey) {
            $requiredOpenSshTools += @('ssh-keyscan.exe', 'ssh-keygen.exe')
        }
        foreach ($opensshTool in $requiredOpenSshTools) {
            if (-not (Get-Command -Name $opensshTool -ErrorAction SilentlyContinue)) {
                throw "Required tool was not found on PATH: $opensshTool. It ships with the Windows OpenSSH client feature, which SSH-key-mode connections require."
            }
        }
    }

    $hadFailure = $false
    foreach ($computer in $ComputerName) {
        try {
            Write-Host "Connecting: $computer"
            $sudoPrefix = if ($CredentialUsername -eq 'root') { '' } else { 'sudo ' }
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

    if ($hadFailure) {
        exit 1
    }
}
