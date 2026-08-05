$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install-ClientDebianSSH' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-ClientDebianSSH.ps1'
        $securePassword = ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force
        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test' -ServerUrl 'https://example.local/api/v1/linux/inventory' -CredentialUsername 'root' -CredentialPassword $securePassword
    }

    It 'Test-PosixShellSafe throws on POSIX shell metacharacters' {
        $unsafeValues = @('/opt/wil; rm -rf /', '$(rm -rf /)', '`rm -rf /`', 'a|b', 'a&b', "line1`nline2")
        foreach ($value in $unsafeValues) {
            { Test-PosixShellSafe -Value $value -FieldName 'testField' } | Should -Throw
        }
    }

    It 'Test-PosixShellSafe does not throw on safe values, empty, or null' {
        $safeValues = @('/opt/windows-inventory-lite', 'https://server.example.local:8080/api/v1/linux/inventory', 'a1b2c3', '', $null)
        foreach ($value in $safeValues) {
            { Test-PosixShellSafe -Value $value -FieldName 'testField' } | Should -Not -Throw
        }
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

    It 'New-SystemdStatusUnitFiles writes a oneshot service with --mode status' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'status-units1'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken '' -Minutes 30

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match 'Type=oneshot'
        $serviceContent | Should -Match ([regex]::Escape('ExecStart=/opt/windows-inventory-lite/wil-linux-client --server-url "https://example.local/api/v1/linux/inventory/service-status" --mode status'))
        $serviceContent | Should -Not -Match '--token'
    }

    It 'New-SystemdStatusUnitFiles includes --token when a token is provided' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'status-units2'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken 'secret-token' -Minutes 30

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match ([regex]::Escape('--token "secret-token"'))
    }

    It 'New-SystemdStatusUnitFiles writes a timer matching the requested interval in minutes' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'status-units3'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken '' -Minutes 45

        $timerContent = Get-Content -LiteralPath $result.TimerPath -Raw
        $timerContent | Should -Match 'OnUnitActiveSec=45min'
        $timerContent | Should -Match 'Unit=wil-linux-client-status.service'
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

    Context 'Invoke-PlinkWithPasswordFile host key handling' {
        It 'passes -hostkey when ExpectedHostKey is supplied' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-hostkey-arg.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo ARGS: %*' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 0' -Encoding ASCII

            $output = Invoke-PlinkWithPasswordFile -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ExpectedHostKey 'SHA256:abc123'

            $output | Should -Match ([regex]::Escape('-hostkey'))
            $output | Should -Match ([regex]::Escape('SHA256:abc123'))
        }

        It 'does not pass -hostkey when ExpectedHostKey is empty' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-no-hostkey-arg.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo ARGS: %*' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 0' -Encoding ASCII

            $output = Invoke-PlinkWithPasswordFile -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ExpectedHostKey ''

            $output | Should -Not -Match ([regex]::Escape('-hostkey'))
        }

        It 'throws an UNKNOWN-key message when ExpectedHostKey was not supplied and plink reports a host-key failure' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-hostkey-fail-unknown.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo The server''s host key is not cached and -batch prevents interactive prompting 1>&2' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 1' -Encoding ASCII

            { Invoke-PlinkWithPasswordFile -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ExpectedHostKey '' } |
                Should -Throw '*is not yet trusted by this machine*'
        }

        It 'throws a CHANGED-key message when ExpectedHostKey was supplied and plink still reports a host-key failure' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-hostkey-fail-changed.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo WARNING - POTENTIAL SECURITY BREACH! The server''s host key does not match the one PuTTY has cached 1>&2' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 1' -Encoding ASCII

            { Invoke-PlinkWithPasswordFile -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ExpectedHostKey 'SHA256:abc123' } |
                Should -Throw '*has CHANGED since it was last trusted here*'
        }
    }

    Context 'Select-KnownHostsLineByFingerprint' {
        BeforeAll {
            # Real ssh-keyscan / ssh-keygen -lf output captured from a live host.
            # ssh-keygen -lf emits one line per NON-COMMENT known_hosts line, in
            # the same order, with the fingerprint as whitespace field 2.
            $script:scanLines = @(
                '# host.example.local:22 SSH-2.0-OpenSSH_9.2p1',
                'host.example.local ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrq',
                'host.example.local ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbml',
                'host.example.local ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLs'
            )
            $script:fingerprintLines = @(
                '3072 SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s host.example.local (RSA)',
                '256 SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM host.example.local (ECDSA)',
                '256 SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU host.example.local (ED25519)'
            )
        }

        It 'returns the single matching line and ignores the other presented keys' {
            $line = Select-KnownHostsLineByFingerprint -KeyScanLines $script:scanLines -FingerprintLines $script:fingerprintLines -ExpectedHostKey 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU'
            $line | Should -Be 'host.example.local ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLs'
        }

        It 'matches a non-final key, proving it is not just returning the last line' {
            $line = Select-KnownHostsLineByFingerprint -KeyScanLines $script:scanLines -FingerprintLines $script:fingerprintLines -ExpectedHostKey 'SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s'
            $line | Should -Be 'host.example.local ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrq'
        }

        It 'returns null when no presented key matches the pinned fingerprint' {
            $line = Select-KnownHostsLineByFingerprint -KeyScanLines $script:scanLines -FingerprintLines $script:fingerprintLines -ExpectedHostKey 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
            $line | Should -BeNullOrEmpty
        }

        It 'returns null when the target presented no keys at all' {
            $line = Select-KnownHostsLineByFingerprint -KeyScanLines @('# nothing but a comment') -FingerprintLines @() -ExpectedHostKey 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU'
            $line | Should -BeNullOrEmpty
        }
    }

    Context 'Get-OpenSshKeyModeOptions' {
        It 'pins to the supplied known_hosts file with strict checking when a fingerprint was verified' {
            $options = Get-OpenSshKeyModeOptions -ExpectedHostKey 'SHA256:abc' -KnownHostsPath 'C:\temp\kh.txt'
            ($options -join ' ') | Should -Match ([regex]::Escape('StrictHostKeyChecking=yes'))
            ($options -join ' ') | Should -Match ([regex]::Escape('UserKnownHostsFile=C:\temp\kh.txt'))
            ($options -join ' ') | Should -Not -Match ([regex]::Escape('accept-new'))
        }

        It 'falls back to first-contact accept-new when no fingerprint is pinned' {
            $options = Get-OpenSshKeyModeOptions -ExpectedHostKey '' -KnownHostsPath $null
            ($options -join ' ') | Should -Match ([regex]::Escape('StrictHostKeyChecking=accept-new'))
            ($options -join ' ') | Should -Not -Match ([regex]::Escape('UserKnownHostsFile'))
        }
    }
}
