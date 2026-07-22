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
            $output = & $script:plinkPath -ssh -batch -pw $plainPassword "$script:CredentialUsername@$TargetComputer" $Command 2>&1
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
            & $script:pscpPath -batch -pw $plainPassword $LocalPath "${script:CredentialUsername}@${TargetComputer}:$RemotePath" 2>&1 | Out-Null
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
