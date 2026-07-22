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

    It 'Invoke-RemoteCommand password auth calls Invoke-InteractivePuttyTool with plink.exe and no -pw anywhere' {
        Mock Invoke-InteractivePuttyTool { return 'ok' }
        $script:usingPassword = $true
        $script:plinkPath = 'plink.exe'
        $script:CredentialUsername = 'root'
        $script:CredentialPassword = (ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force)

        Invoke-RemoteCommand -TargetComputer '192.0.2.10' -Command 'echo hi'

        Should -Invoke Invoke-InteractivePuttyTool -Times 1 -ParameterFilter {
            $ExePath -eq 'plink.exe' -and ($Arguments -notcontains '-pw') -and ($Arguments -notcontains '-batch') -and ($PlainPassword -eq 'unused-test-password')
        }
    }

    It 'Copy-FileToRemote password auth calls Invoke-InteractivePuttyTool with pscp.exe and no -pw anywhere' {
        Mock Invoke-InteractivePuttyTool { return 'ok' }
        $script:usingPassword = $true
        $script:pscpPath = 'pscp.exe'
        $script:CredentialUsername = 'root'
        $script:CredentialPassword = (ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force)

        Copy-FileToRemote -TargetComputer '192.0.2.10' -LocalPath 'C:\fake\wil-linux-client' -RemotePath '/tmp/wil-linux-client-install/wil-linux-client'

        Should -Invoke Invoke-InteractivePuttyTool -Times 1 -ParameterFilter {
            $ExePath -eq 'pscp.exe' -and ($Arguments -notcontains '-pw') -and ($Arguments -notcontains '-batch') -and ($PlainPassword -eq 'unused-test-password')
        }
    }

    Context 'Get-NextPuttyPromptAction' {
        It 'returns HostKey when only the host-key prompt has appeared and neither flag is set' {
            $result = Get-NextPuttyPromptAction -BufferedOutput 'The server''s host key is not cached. Store key in cache?' -HostKeyAnswered $false -PasswordSent $false

            $result | Should -Be 'HostKey'
        }

        It 'returns Password when only the password prompt has appeared and neither flag is set' {
            $result = Get-NextPuttyPromptAction -BufferedOutput 'root@192.0.2.10''s password:' -HostKeyAnswered $false -PasswordSent $false

            $result | Should -Be 'Password'
        }

        It 'returns Password (not HostKey) when the buffer contains only a password prompt, as on an already-trusted target - regression test for the prior Critical bug' {
            $result = Get-NextPuttyPromptAction -BufferedOutput 'root@192.0.2.10''s password:' -HostKeyAnswered $false -PasswordSent $false

            $result | Should -Be 'Password'
            $result | Should -Not -Be 'HostKey'
        }

        It 'answers HostKey first when both prompts are present in the buffer and the host key has not been answered yet' {
            $buffer = "The server's host key is not cached. Store key in cache?`nroot@192.0.2.10's password:"

            $result = Get-NextPuttyPromptAction -BufferedOutput $buffer -HostKeyAnswered $false -PasswordSent $false

            $result | Should -Be 'HostKey'
        }

        It 'answers Password when both prompts are present in the buffer but the host key was already answered' {
            $buffer = "The server's host key is not cached. Store key in cache?`nroot@192.0.2.10's password:"

            $result = Get-NextPuttyPromptAction -BufferedOutput $buffer -HostKeyAnswered $true -PasswordSent $false

            $result | Should -Be 'Password'
        }

        It 'returns nothing once both prompts have already been answered' {
            $buffer = "The server's host key is not cached. Store key in cache?`nroot@192.0.2.10's password:"

            $result = Get-NextPuttyPromptAction -BufferedOutput $buffer -HostKeyAnswered $true -PasswordSent $true

            $result | Should -BeNullOrEmpty
        }

        It 'returns nothing when neither prompt has appeared in the buffer yet' {
            $result = Get-NextPuttyPromptAction -BufferedOutput 'Connecting to 192.0.2.10 port 22' -HostKeyAnswered $false -PasswordSent $false

            $result | Should -BeNullOrEmpty
        }
    }
}
