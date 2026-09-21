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

. (Join-Path -Path $PSScriptRoot -ChildPath 'WilLinuxSshCommon.ps1')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:usingPassword = $PSCmdlet.ParameterSetName -eq 'Password'

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
            # temp file already uses in Invoke-PlinkWithAuth, so the
            # plaintext key never sits at inherited %TEMP% permissions even
            # briefly. [System.IO.File]::WriteAllText inside
            # Convert-OpenSshKeyToPpk overwrites this existing file in
            # place, which does not disturb the ACL just applied to it.
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
            # Same loud-on-failure overwrite-then-delete as the plink
            # password file above - this is a decrypted private key, not
            # a file a silent best-effort delete is enough for.
            Clear-TempPasswordFile -Path $script:ConvertedKeyPath
        }
    }

    if ($hadFailure) {
        exit 1
    }
}
