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

    It 'Invoke-RemoteCommand uses ssh.exe for key auth' {
        Mock ssh.exe { $global:LASTEXITCODE = 0; return 'ok' }
        $script:usingPassword = $false
        $script:KeyPath = 'C:\fake\key.pem'
        $script:CredentialUsername = 'root'

        Invoke-RemoteCommand -TargetComputer '192.0.2.10' -Command 'echo hi'

        Should -Invoke ssh.exe -Times 1
    }
}
