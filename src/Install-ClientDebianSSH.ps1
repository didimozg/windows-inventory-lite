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

. (Join-Path -Path $PSScriptRoot -ChildPath 'WilLinuxSshCommon.ps1')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:usingPassword = $PSCmdlet.ParameterSetName -eq 'Password'

# Absolute path on the MANAGED LINUX HOST. Must stay identical to
# WindowsInventoryLiteServer.cs's LinuxClientEnvFilePath.
$script:LinuxClientEnvFilePath = '/etc/wil-linux-client.env'

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

# Both auth modes go through plink.exe now (PuTTY, MIT-licensed - see
# deploy\linux-client\NOTICE): Windows' built-in OpenSSH client cannot do
# unattended password authentication at all (refuses to read a password
# from non-interactive stdin), and separately cannot negotiate the KEX
# algorithms modern OpenSSH servers offer (confirmed live against a real
# Debian 13/OpenSSH 10.0p2 target) - plink already handles both. Key auth
# uses a key converted once per script run to PuTTY's .ppk format (see
# Convert-OpenSshKeyToPpk and $script:ConvertedKeyPath) since plink cannot
# read an OpenSSH-format key directly.
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
            # The converted .ppk is a fully decrypted private key, alive
            # for the entire script run across every target in $ComputerName,
            # its path visible in process listings via -i. The empty output
            # file is created and locked down to only the current user
            # BEFORE Convert-OpenSshKeyToPpk writes the key content into it
            # (rather than restricting the ACL only after conversion
            # returns) - the same ACL-before-content ordering the -pwfile
            # temp file already uses in Invoke-PlinkWithAuth, and the
            # systemd env file (New-SystemdEnvFile) below, so the plaintext
            # key never sits at inherited %TEMP% permissions even briefly.
            # [System.IO.File]::WriteAllText inside Convert-OpenSshKeyToPpk
            # overwrites this existing file in place, which does not disturb
            # the ACL just applied to it.
            # -Path, not -LiteralPath: this script requires only PS 2.0
            # (#requires above), and Get-Acl/Set-Acl only gained -LiteralPath
            # in PS 3.0. $script:ConvertedKeyPath is always a script-built
            # path, never wildcard-shaped, so -Path's wildcard expansion is a
            # safe substitute here.
            New-Item -Path $script:ConvertedKeyPath -ItemType File -Force | Out-Null
            $acl = Get-Acl -Path $script:ConvertedKeyPath
            $acl.SetAccessRuleProtection($true, $false)
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -Path $script:ConvertedKeyPath -AclObject $acl

            Convert-OpenSshKeyToPpk -KeyPath $KeyPath -OutputPath $script:ConvertedKeyPath
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
    # Declared here, not inside the try block below: under Set-StrictMode
    # -Version 2.0 (set script-wide), the finally block's own `if
    # ($envFile)` check would itself throw VariableNotFoundStrict - masking
    # whatever real error triggered the finally in the first place - if an
    # exception happened to strike before the try block's own assignment to
    # $envFile was reached.
    $envFile = $null
    try {
        # Staging dir creation is the FIRST thing inside this try block, not
        # before it - a New-Item failure here (disk full, AV lock,
        # permissions) is now covered by this try's own finally, which
        # cleans up $script:ConvertedKeyPath. Sitting outside the try left
        # the converted key leaking on exactly that failure, the class of
        # bug this whole fix round targeted.
        $stagingDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString())
        New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null
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
            # password file and the env file above - this is a decrypted
            # private key, not a file a silent best-effort delete is enough
            # for.
            Clear-TempPasswordFile -Path $script:ConvertedKeyPath
        }
    }

    if ($hadFailure) {
        exit 1
    }
}
