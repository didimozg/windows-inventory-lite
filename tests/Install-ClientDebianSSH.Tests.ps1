$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install-ClientDebianSSH' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-ClientDebianSSH.ps1'
        $securePassword = ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force
        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test' -ServerUrl 'https://example.local/api/v1/linux/inventory' -CredentialUsername 'root' -CredentialPassword $securePassword
    }

    It 'New-SystemdUnitFiles writes a oneshot service with the correct ExecStart' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units1'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 6

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match 'Type=oneshot'
        $serviceContent | Should -Match ([regex]::Escape('ExecStart=/opt/windows-inventory-lite/wil-linux-client --server-url "https://example.local/api/v1/linux/inventory"'))
        $serviceContent | Should -Not -Match '--token'
    }

    It 'New-SystemdUnitFiles includes --token when a token is provided' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units2'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken 'secret-token' -Hours 6

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match ([regex]::Escape('--token "secret-token"'))
    }

    It 'New-SystemdUnitFiles writes a timer matching the requested interval' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units3'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 12

        $timerContent = Get-Content -LiteralPath $result.TimerPath -Raw
        $timerContent | Should -Match 'OnUnitActiveSec=12h'
        $timerContent | Should -Match 'Unit=wil-linux-client.service'
    }

    It 'Invoke-RemoteCommand uses ssh.exe for key auth' {
        Mock ssh.exe { $global:LASTEXITCODE = 0; return 'ok' }
        $script:usingPassword = $false
        $script:KeyPath = 'C:\fake\key.pem'
        $script:CredentialUsername = 'root'

        Invoke-RemoteCommand -TargetComputer '192.0.2.10' -Command 'echo hi'

        Should -Invoke ssh.exe -Times 1
    }

    It 'Invoke-RemoteCommand uses plink.exe for password auth' {
        Mock plink.exe { $global:LASTEXITCODE = 0; return 'ok' }
        $script:usingPassword = $true
        $script:plinkPath = 'plink.exe'
        $script:CredentialUsername = 'root'
        $script:CredentialPassword = (ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force)

        Invoke-RemoteCommand -TargetComputer '192.0.2.10' -Command 'echo hi'

        Should -Invoke plink.exe -Times 1
    }
}
