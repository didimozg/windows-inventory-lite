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

# Decides which prompt answer (if any) to send next, given the buffered
# plink/pscp output seen so far and which prompts have already been
# answered. Pure function - no I/O - so this exact conditional logic (the
# source of a prior Critical bug: blindly pre-answering "y" before a
# host-key prompt that never appears on an already-trusted target, which
# then consumes the PASSWORD prompt's answer slot instead of the real
# password) can be unit-tested directly with synthetic buffer strings,
# not only indirectly through a mocked Invoke-InteractivePuttyTool.
function Get-NextPuttyPromptAction {
    param(
        [string]$BufferedOutput,
        [bool]$HostKeyAnswered,
        [bool]$PasswordSent
    )

    if (-not $HostKeyAnswered -and $BufferedOutput -match '(?i)store key in cache') {
        return 'HostKey'
    }
    if (-not $PasswordSent -and $BufferedOutput -match '(?i)password:') {
        return 'Password'
    }
    return $null
}

# Runs plink.exe/pscp.exe interactively and answers whichever prompt
# actually appears - NOT a fixed-order blind pre-answer, which breaks on
# any target whose host key this machine has already cached (PuTTY caches
# accepted keys in HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys,
# so the host-key-trust prompt only appears on a target's first-ever
# connection from this machine - on every later connection there is no
# such prompt, and blindly pre-sending "y" first would consume the
# PASSWORD prompt's answer slot instead of the real password). -batch is
# not used: it disables these prompts entirely rather than letting this
# function answer them, which would defeat the whole point - keeping the
# password off the command line (where -pw would put it, visible to any
# other process/user on this host via Get-CimInstance Win32_Process/Task
# Manager for the connection's duration - matching the principle
# Install-ClientWinRM.ps1 already applies to WinRM credentials). The
# decision of which prompt to answer is delegated to
# Get-NextPuttyPromptAction (see above) so it can be unit-tested directly.
function Invoke-InteractivePuttyTool {
    param(
        [string]$ExePath,
        [string[]]$Arguments,
        [string]$PlainPassword,
        [int]$TimeoutSeconds = 60
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $ExePath
    foreach ($arg in $Arguments) {
        [void]$psi.ArgumentList.Add($arg)
    }
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi

    $script:puttyOutputBuffer = New-Object System.Text.StringBuilder
    $script:puttyHostKeyAnswered = $false
    $script:puttyPasswordSent = $false

    $outputHandler = {
        if ($null -ne $EventArgs.Data) {
            [void]$script:puttyOutputBuffer.Append($EventArgs.Data)
            [void]$script:puttyOutputBuffer.Append("`n")
        }
    }

    $outSub = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action $outputHandler
    $errSub = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action $outputHandler

    try {
        [void]$process.Start()
        $process.BeginOutputReadLine()
        $process.BeginErrorReadLine()

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while (-not $process.HasExited) {
            if ((Get-Date) -ge $deadline) {
                try { $process.Kill() } catch { }
                throw "Timed out after $TimeoutSeconds seconds waiting for plink/pscp - the interactive prompt sequence may have differed from what this script expects. Try -KeyPath instead."
            }

            $text = $script:puttyOutputBuffer.ToString()

            switch (Get-NextPuttyPromptAction -BufferedOutput $text -HostKeyAnswered $script:puttyHostKeyAnswered -PasswordSent $script:puttyPasswordSent) {
                'HostKey' {
                    $process.StandardInput.WriteLine('y')
                    $script:puttyHostKeyAnswered = $true
                }
                'Password' {
                    $process.StandardInput.WriteLine($PlainPassword)
                    $script:puttyPasswordSent = $true
                }
            }

            Start-Sleep -Milliseconds 150
        }

        $process.WaitForExit()
    }
    finally {
        Unregister-Event -SourceIdentifier $outSub.Name -ErrorAction SilentlyContinue
        Unregister-Event -SourceIdentifier $errSub.Name -ErrorAction SilentlyContinue
        Remove-Job -Name $outSub.Name -Force -ErrorAction SilentlyContinue
        Remove-Job -Name $errSub.Name -Force -ErrorAction SilentlyContinue
    }

    $exitCode = $process.ExitCode
    $output = $script:puttyOutputBuffer.ToString()

    # Callers (Invoke-RemoteCommand, Copy-FileToRemote) check $LASTEXITCODE
    # after this call the same way they do after the ssh.exe/scp.exe key-auth
    # branch's `&` invocation; a direct Process call never sets it on its own,
    # so it must be set explicitly here or a stale value from an earlier
    # command in the caller's session would leak through.
    $global:LASTEXITCODE = $exitCode

    if ($exitCode -ne 0) {
        throw ("plink/pscp failed (exit {0}): {1}" -f $exitCode, $output)
    }

    return $output
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
            # See Invoke-InteractivePuttyTool for why the prompt is answered
            # conditionally (watching real output) instead of a fixed-order
            # blind pre-answer.
            $output = Invoke-InteractivePuttyTool -ExePath $script:plinkPath -Arguments @('-ssh', "$script:CredentialUsername@$TargetComputer", $Command) -PlainPassword $plainPassword
        }
        finally {
            $plainPassword = $null
        }
    }
    else {
        $output = & ssh.exe -i $script:KeyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$script:CredentialUsername@$TargetComputer" $Command 2>&1
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
            # See Invoke-InteractivePuttyTool for why the prompt is answered
            # conditionally (watching real output) instead of a fixed-order
            # blind pre-answer.
            Invoke-InteractivePuttyTool -ExePath $script:pscpPath -Arguments @($LocalPath, "${script:CredentialUsername}@${TargetComputer}:$RemotePath") -PlainPassword $plainPassword | Out-Null
        }
        finally {
            $plainPassword = $null
        }
    }
    else {
        & scp.exe -i $script:KeyPath -o BatchMode=yes -o StrictHostKeyChecking=accept-new $LocalPath "${script:CredentialUsername}@${TargetComputer}:$RemotePath" 2>&1 | Out-Null
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

    $hadFailure = $false
    $stagingDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.Guid]::NewGuid().ToString())
    New-Item -Path $stagingDir -ItemType Directory -Force | Out-Null
    try {
        $units = New-SystemdUnitFiles -Directory $stagingDir -InstallDirectory $InstallPath -Url $ServerUrl -SharedToken $Token -Hours $IntervalHours

        foreach ($computer in $ComputerName) {
            try {
                Write-Host "Connecting: $computer"
                $remoteTmpDir = "/tmp/wil-linux-client-install"
                Invoke-RemoteCommand -TargetComputer $computer -Command "sudo mkdir -p $InstallPath $remoteTmpDir && sudo chmod 755 $remoteTmpDir" | Out-Null

                Write-Host "Copying client binary: $computer"
                Copy-FileToRemote -TargetComputer $computer -LocalPath $ClientBinaryPath -RemotePath "$remoteTmpDir/wil-linux-client"
                Copy-FileToRemote -TargetComputer $computer -LocalPath $units.ServicePath -RemotePath "$remoteTmpDir/wil-linux-client.service"
                Copy-FileToRemote -TargetComputer $computer -LocalPath $units.TimerPath -RemotePath "$remoteTmpDir/wil-linux-client.timer"

                Write-Host "Installing service: $computer"
                $installCommand = "sudo mv $remoteTmpDir/wil-linux-client $InstallPath/wil-linux-client && " +
                    "sudo chmod 755 $InstallPath/wil-linux-client && " +
                    "sudo mv $remoteTmpDir/wil-linux-client.service /etc/systemd/system/wil-linux-client.service && " +
                    "sudo mv $remoteTmpDir/wil-linux-client.timer /etc/systemd/system/wil-linux-client.timer && " +
                    "sudo rm -rf $remoteTmpDir && " +
                    "sudo systemctl daemon-reload && " +
                    "sudo systemctl enable --now wil-linux-client.timer"
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
