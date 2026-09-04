$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Uninstall-ClientDebianSSH' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Uninstall-ClientDebianSSH.ps1'
        $securePassword = ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force
        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test' -CredentialUsername 'root' -CredentialPassword $securePassword
    }

    It 'Get-LinuxUninstallCommand builds a command that disables, removes unit files, and removes the install directory' {
        $command = Get-LinuxUninstallCommand -InstallPath '/opt/windows-inventory-lite' -SudoPrefix 'sudo '
        $command | Should -Match ([regex]::Escape('sudo systemctl disable --now wil-linux-client.timer wil-linux-client.service wil-linux-client-status.timer wil-linux-client-status.service'))
        $command | Should -Match ([regex]::Escape('sudo rm -f /etc/systemd/system/wil-linux-client.service /etc/systemd/system/wil-linux-client.timer /etc/systemd/system/wil-linux-client-status.service /etc/systemd/system/wil-linux-client-status.timer'))
        $command | Should -Match ([regex]::Escape('sudo rm -rf /opt/windows-inventory-lite'))
        $command | Should -Match ([regex]::Escape('sudo systemctl daemon-reload'))
    }

    It 'Get-LinuxUninstallCommand omits the sudo prefix when connecting as root' {
        $command = Get-LinuxUninstallCommand -InstallPath '/opt/windows-inventory-lite' -SudoPrefix ''
        $command | Should -Not -Match 'sudo'
        $command | Should -Match '^systemctl disable --now'
    }

    It 'Get-LinuxUninstallCommand rejects a shell-unsafe InstallPath' {
        { Get-LinuxUninstallCommand -InstallPath '/opt/wil; rm -rf /' -SudoPrefix 'sudo ' } | Should -Throw
    }

    It 'Get-LinuxUninstallCommand rejects an InstallPath containing a space' {
        # "rm -rf $InstallPath" has no quoting around the variable, so a
        # space-containing value would otherwise word-split into a second
        # argument on the remote shell (e.g. "/opt/wil /usr" -> rm -rf on
        # both directories).
        { Get-LinuxUninstallCommand -InstallPath '/opt/wil /usr' -SudoPrefix 'sudo ' } | Should -Throw
    }

    It 'Get-LinuxUninstallCommand rejects a bare top-level InstallPath, a path outside /opt/, or a traversal path' {
        # No shell metacharacter and no whitespace, so ValidatePosixShellSafe
        # alone would let these through into "rm -rf /etc" - this script is
        # directly runnable on its own (bypassing the C# server's own
        # IsValidLinuxInstallPath gate entirely), so it needs the same
        # /opt/-allowlist check applied here too. Asserting on the message
        # (not just -Throw) matters here specifically: a first version of
        # the predecessor check threw for the WRONG reason on a single-
        # segment path ("The property 'Count' cannot be found on this
        # object" - a Windows PowerShell 5.1 vs 7 scalar-vs-array quirk),
        # which -Throw alone would have accepted as a false-positive pass.
        $invalid = @('/etc', '/', '/home/foo', '/opt', '/opt/../etc', '/opt/./etc')
        foreach ($value in $invalid) {
            { Get-LinuxUninstallCommand -InstallPath $value -SudoPrefix 'sudo ' } | Should -Throw '*absolute Linux path under /opt/*'
        }
    }

    It 'Invoke-RemoteCommand uses ssh.exe for key auth' {
        Mock ssh.exe { $global:LASTEXITCODE = 0; return 'ok' }
        $script:usingPassword = $false
        $script:KeyPath = 'C:\fake\key.pem'
        $script:CredentialUsername = 'root'

        Invoke-RemoteCommand -TargetComputer '192.0.2.10' -Command 'echo hi'

        Should -Invoke ssh.exe -Times 1
    }
}
