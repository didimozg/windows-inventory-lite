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
# GenerateSystemdEnvFileLines (WindowsInventoryLiteServer.cs). Pure function
# of its parameters apart from the file write, same as its siblings above.
function New-SystemdEnvFile {
    param(
        [string]$Directory,
        [string]$SharedToken
    )

    Test-PosixShellSafe -Value $SharedToken -FieldName 'Token'

    $envPath = Join-Path -Path $Directory -ChildPath 'wil-linux-client.env'
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
function New-PinnedKnownHostsFile {
    param(
        [string]$TargetComputer,
        [string]$ExpectedHostKey
    )

    $knownHostsPath = [System.IO.Path]::GetTempFileName()
    $scanOutput = Invoke-NativeAllowingStderr { & ssh-keyscan.exe -T 10 $TargetComputer 2>$null }
    $scanLines = @($scanOutput | ForEach-Object { [string]$_ })

    $scanFile = "$knownHostsPath.scan"
    [System.IO.File]::WriteAllLines($scanFile, $scanLines, (New-Object System.Text.UTF8Encoding($false)))
    try {
        $fingerprintOutput = Invoke-NativeAllowingStderr { & ssh-keygen.exe -lf $scanFile 2>$null }
        $fingerprintLines = @($fingerprintOutput | ForEach-Object { [string]$_ })
    }
    finally {
        Remove-Item -LiteralPath $scanFile -Force -ErrorAction SilentlyContinue
    }

    $match = Select-KnownHostsLineByFingerprint -KeyScanLines $scanLines -FingerprintLines $fingerprintLines -ExpectedHostKey $ExpectedHostKey
    if (-not $match) {
        Remove-Item -LiteralPath $knownHostsPath -Force -ErrorAction SilentlyContinue
        throw "The target's SSH host key does not match the fingerprint trusted for this host ($ExpectedHostKey). This can mean the server was reinstalled or reimaged, or that something is intercepting the connection - only proceed if you can confirm this change is expected. Trust the new host key from the Linux Client actions job log to update the stored fingerprint."
    }

    [System.IO.File]::WriteAllLines($knownHostsPath, @($match), (New-Object System.Text.UTF8Encoding($false)))
    return $knownHostsPath
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
        $output = Invoke-NativeAllowingStderr { & $ExePath @fullArgs 2>&1 }

        if ($LASTEXITCODE -ne 0) {
            $joined = $output -join "`n"
            if ($joined -match '(?i)host key') {
                if ($ExpectedHostKey) {
                    throw ("plink/pscp failed (exit {0}): the target's SSH host key has CHANGED since it was last trusted here. This can mean the server was reinstalled or reimaged, or that something is intercepting the connection - only proceed if you can confirm this change is expected. Trust the new key from the Linux Client actions job log to update the stored fingerprint. Raw output: {1}" -f $LASTEXITCODE, $joined)
                }
                throw ("plink/pscp failed (exit {0}): the target's SSH host key is not yet trusted by this machine (PuTTY caches trusted keys separately from Windows' own OpenSSH known_hosts). -batch refuses to prompt for an unknown host key rather than risk silently trusting the wrong one. Trust this host key from the Linux Client actions job log, or connect once with -KeyPath instead. Raw output: {1}" -f $LASTEXITCODE, $joined)
            }
            throw ("plink/pscp failed (exit {0}): {1}" -f $LASTEXITCODE, $joined)
        }

        return $output
    }
    finally {
        Remove-Item -LiteralPath $pwFile -Force -ErrorAction SilentlyContinue
    }
}

# Two auth paths, since Windows' built-in OpenSSH client (ssh.exe) cannot
# do unattended password authentication at all - it refuses to read a
# password from a non-interactive/piped stdin, by design, with no way
# around it short of a different tool. Key auth uses ssh.exe (built into
# Windows 10/Server 2019+, zero new dependency); password auth uses
# bundled plink.exe (PuTTY, MIT-licensed - see deploy\linux-client\NOTICE).
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

function Copy-FileToRemote {
    param([string]$TargetComputer, [string]$LocalPath, [string]$RemotePath, [string]$ExpectedHostKey)

    if ($script:usingPassword) {
        $plainPassword = ConvertTo-PlainText -Secure $script:CredentialPassword
        try {
            Invoke-PlinkWithPasswordFile -ExePath $script:pscpPath -Arguments @($LocalPath, "${script:CredentialUsername}@${TargetComputer}:$RemotePath") -PlainPassword $plainPassword -ExpectedHostKey $ExpectedHostKey | Out-Null
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
            Invoke-NativeAllowingStderr { & scp.exe -i $script:KeyPath -o BatchMode=yes @hostKeyOptions -o ConnectTimeout=10 $LocalPath "${script:CredentialUsername}@${TargetComputer}:$RemotePath" 2>&1 } | Out-Null
        }
        finally {
            if ($knownHostsPath) {
                Remove-Item -LiteralPath $knownHostsPath -Force -ErrorAction SilentlyContinue
            }
        }
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to copy $LocalPath to ${TargetComputer}:${RemotePath} (exit $LASTEXITCODE)."
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
    if ($usingPassword) {
        foreach ($tool in @($plinkPath, $pscpPath)) {
            if (-not (Test-Path -LiteralPath $tool)) {
                throw "Required tool was not found: $tool. See deploy\linux-client\NOTICE for how to obtain it."
            }
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $KeyPath)) {
            throw "SSH private key was not found: $KeyPath"
        }
        # Host-key pinning on this path needs both of these (see
        # New-PinnedKnownHostsFile). They ship with Windows' built-in OpenSSH
        # client alongside ssh.exe, so a missing one means OpenSSH is not
        # installed - fail with that, not with an opaque error mid-push.
        if ($ExpectedHostKey) {
            foreach ($opensshTool in @('ssh-keyscan.exe', 'ssh-keygen.exe')) {
                if (-not (Get-Command -Name $opensshTool -ErrorAction SilentlyContinue)) {
                    throw "Required tool was not found on PATH: $opensshTool. It ships with the Windows OpenSSH client feature, which is required for SSH-key-mode pushes to targets with pinned fingerprints."
                }
            }
        }
    }

    # Live testing against this project's real Debian test fleet found a
    # genuine target: connecting as root on a minimal/base install where
    # sudo is not present at all ("sudo: command not found") - an
    # unconditional "sudo " prefix would fail outright there, even though
    # root never needed elevation in the first place. Skip the prefix
    # specifically when the connecting user already IS root; a non-root
    # CredentialUsername still gets "sudo " exactly as before.
    $sudoPrefix = if ($CredentialUsername -eq 'root') { '' } else { 'sudo ' }

    $hadFailure = $false
    $stagingDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString())
    New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null
    try {
        $units = New-SystemdUnitFiles -Directory $stagingDir -InstallDirectory $InstallPath -Url $ServerUrl -SharedToken $Token -Hours $IntervalHours
        $statusUrl = $ServerUrl.TrimEnd('/') + '/service-status'
        $statusUnits = New-SystemdStatusUnitFiles -Directory $stagingDir -InstallDirectory $InstallPath -Url $statusUrl -SharedToken $Token -Minutes $StatusIntervalMinutes

        $envFile = $null
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
        Remove-Item -LiteralPath $stagingDir -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($hadFailure) {
        exit 1
    }
}
