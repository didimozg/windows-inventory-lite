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

    It 'Invoke-RemoteCommand password auth calls Invoke-PlinkWithPasswordFile with plink.exe, no -pw/-batch in its own Arguments, and the real password' {
        Mock Invoke-PlinkWithPasswordFile { return 'ok' }
        $script:usingPassword = $true
        $script:plinkPath = 'plink.exe'
        $script:CredentialUsername = 'root'
        $script:CredentialPassword = (ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force)

        Invoke-RemoteCommand -TargetComputer '192.0.2.10' -Command 'echo hi'

        Should -Invoke Invoke-PlinkWithPasswordFile -Times 1 -ParameterFilter {
            $ExePath -eq 'plink.exe' -and ($Arguments -notcontains '-pw') -and ($Arguments -notcontains '-batch') -and ($PlainPassword -eq 'unused-test-password')
        }
    }

    It 'Copy-FileToRemote password auth calls Invoke-PlinkWithPasswordFile with pscp.exe, no -pw/-batch in its own Arguments, and the real password' {
        Mock Invoke-PlinkWithPasswordFile { return 'ok' }
        $script:usingPassword = $true
        $script:pscpPath = 'pscp.exe'
        $script:CredentialUsername = 'root'
        $script:CredentialPassword = (ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force)

        Copy-FileToRemote -TargetComputer '192.0.2.10' -LocalPath 'C:\fake\wil-linux-client' -RemotePath '/tmp/wil-linux-client-install/wil-linux-client'

        Should -Invoke Invoke-PlinkWithPasswordFile -Times 1 -ParameterFilter {
            $ExePath -eq 'pscp.exe' -and ($Arguments -notcontains '-pw') -and ($Arguments -notcontains '-batch') -and ($PlainPassword -eq 'unused-test-password')
        }
    }

    Context 'Invoke-PlinkWithPasswordFile' {
        It 'never puts the password on the plink/pscp command line, and cleans up its temp password file' {
            # A fake "plink" that just echoes what -pwfile pointed at, so the
            # test can assert on the real file content/cleanup without a
            # live SSH target - this exercises the function's own file
            # handling, not network behavior.
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo ARGS: %*' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 0' -Encoding ASCII

            $capturedPwFile = $null
            $output = Invoke-PlinkWithPasswordFile -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'echo hi') -PlainPassword 'unused-test-password'

            $output | Should -Match ([regex]::Escape('-pwfile'))
            $output | Should -Match '-batch'
            $output | Should -Not -Match ([regex]::Escape('unused-test-password'))
            if ($output -match '-pwfile\s+(\S+)') {
                $capturedPwFile = $Matches[1]
                Test-Path -LiteralPath $capturedPwFile | Should -Be $false
            }
        }

        It 'throws a clear, actionable error when plink/pscp fails on an untrusted host key under -batch' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-hostkey-fail.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo The server''s host key is not cached and -batch prevents interactive prompting 1>&2' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 1' -Encoding ASCII

            { Invoke-PlinkWithPasswordFile -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'echo hi') -PlainPassword 'unused-test-password' } |
                Should -Throw '*host key*'
        }
    }
}
