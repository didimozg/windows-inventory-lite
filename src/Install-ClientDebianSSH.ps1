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
    [ValidateNotNullOrEmpty()]
    [string]$InstallPath = '/opt/windows-inventory-lite',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ClientBinaryPath,

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

    $execStart = "$InstallDirectory/wil-linux-client --server-url `"$Url`""
    if ($SharedToken) {
        $execStart += " --token `"$SharedToken`""
    }

    $serviceContent = @"
[Unit]
Description=Windows Inventory Lite - Linux client (one-shot report)

[Service]
Type=oneshot
ExecStart=$execStart
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
                throw ("plink/pscp failed (exit {0}): the target's SSH host key is not yet trusted by this machine (PuTTY caches trusted keys separately from Windows' own OpenSSH known_hosts). -batch refuses to prompt for an unknown host key rather than risk silently trusting the wrong one. Connect once with -KeyPath, or run plink/pscp interactively against this target once to accept its host key, then retry. Raw output: {1}" -f $LASTEXITCODE, $joined)
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

function Copy-FileToRemote {
    param([string]$TargetComputer, [string]$LocalPath, [string]$RemotePath)

    if ($script:usingPassword) {
        $plainPassword = ConvertTo-PlainText -Secure $script:CredentialPassword
        try {
            Invoke-PlinkWithPasswordFile -ExePath $script:pscpPath -Arguments @($LocalPath, "${script:CredentialUsername}@${TargetComputer}:$RemotePath") -PlainPassword $plainPassword | Out-Null
        }
        finally {
            $plainPassword = $null
        }
    }
    else {
        Invoke-NativeAllowingStderr { & scp.exe -i $script:KeyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $LocalPath "${script:CredentialUsername}@${TargetComputer}:$RemotePath" 2>&1 } | Out-Null
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
        throw "Linux client binary was not found: $ClientBinaryPath. Run Build-LinuxClient.ps1 first."
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

        foreach ($computer in $ComputerName) {
            try {
                Write-Host "Connecting: $computer"
                $remoteTmpDir = "/tmp/wil-linux-client-install"
                Invoke-RemoteCommand -TargetComputer $computer -Command "${sudoPrefix}mkdir -p $InstallPath $remoteTmpDir && ${sudoPrefix}chmod 755 $remoteTmpDir" | Out-Null

                Write-Host "Copying client binary: $computer"
                Copy-FileToRemote -TargetComputer $computer -LocalPath $ClientBinaryPath -RemotePath "$remoteTmpDir/wil-linux-client"
                Copy-FileToRemote -TargetComputer $computer -LocalPath $units.ServicePath -RemotePath "$remoteTmpDir/wil-linux-client.service"
                Copy-FileToRemote -TargetComputer $computer -LocalPath $units.TimerPath -RemotePath "$remoteTmpDir/wil-linux-client.timer"

                Write-Host "Installing service: $computer"
                $installCommand = "${sudoPrefix}mv $remoteTmpDir/wil-linux-client $InstallPath/wil-linux-client && " +
                    "${sudoPrefix}chmod 755 $InstallPath/wil-linux-client && " +
                    "${sudoPrefix}mv $remoteTmpDir/wil-linux-client.service /etc/systemd/system/wil-linux-client.service && " +
                    "${sudoPrefix}mv $remoteTmpDir/wil-linux-client.timer /etc/systemd/system/wil-linux-client.timer && " +
                    "${sudoPrefix}rm -rf $remoteTmpDir && " +
                    "${sudoPrefix}systemctl daemon-reload && " +
                    "${sudoPrefix}systemctl enable --now wil-linux-client.timer"
                Invoke-RemoteCommand -TargetComputer $computer -Command $installCommand | Out-Null

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
