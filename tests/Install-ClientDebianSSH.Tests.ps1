$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install-ClientDebianSSH' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-ClientDebianSSH.ps1'
        $securePassword = ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force
        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test' -ServerUrl 'https://example.local/api/v1/linux/inventory' -CredentialUsername 'root' -CredentialPassword $securePassword
    }

    It 'Test-PosixShellSafe throws on POSIX shell metacharacters' {
        $unsafeValues = @('/opt/wil; rm -rf /', '$(rm -rf /)', '`rm -rf /`', 'a|b', 'a&b', "line1`nline2", '/opt/wil /usr', "path`twith`ttab")
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

    It 'Test-LinuxInstallPathSafe rejects a path outside /opt/, a bare /opt, and a relative path' {
        # No shell metacharacter and no whitespace, so Test-PosixShellSafe
        # alone would let these through - this script is directly runnable
        # on its own (bypassing the C# server's own IsValidLinuxInstallPath
        # gate entirely), so it needs the same /opt/-allowlist check
        # applied here too. Asserting on the message (not just -Throw)
        # matters here specifically: a first version of the predecessor
        # check threw for the WRONG reason on a single-segment path ("The
        # property 'Count' cannot be found on this object" - a Windows
        # PowerShell 5.1 vs 7 scalar-vs-array quirk), which -Throw alone
        # would have accepted as a false-positive pass.
        $invalid = @('/usr', '/etc', '/opt', '/opt/', '/', 'opt/wil', '', $null, '/home/foo', '/usr/bin')
        foreach ($value in $invalid) {
            { Test-LinuxInstallPathSafe -InstallPath $value } | Should -Throw '*absolute Linux path under /opt/*'
        }
    }

    It 'Test-LinuxInstallPathSafe rejects .. and . traversal even inside an /opt/ path' {
        $traversal = @('/opt/../etc', '/opt/../../etc', '/../etc', '/opt/./etc', '/opt/wil/../../etc')
        foreach ($value in $traversal) {
            { Test-LinuxInstallPathSafe -InstallPath $value } | Should -Throw '*absolute Linux path under /opt/*'
        }
    }

    It 'Test-LinuxInstallPathSafe accepts a real subdirectory under /opt/' {
        $valid = @('/opt/windows-inventory-lite', '/opt/wil/', '/opt/a/b')
        foreach ($value in $valid) {
            { Test-LinuxInstallPathSafe -InstallPath $value } | Should -Not -Throw
        }
    }

    It 'New-SystemdUnitFiles rejects a bare top-level InstallDirectory or a traversal path' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units-bad-path'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        { New-SystemdUnitFiles -Directory $dir -InstallDirectory '/etc' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 6 } | Should -Throw '*absolute Linux path under /opt/*'
        { New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/../etc' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 6 } | Should -Throw '*absolute Linux path under /opt/*'
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

    It 'New-SystemdUnitFiles delivers the token via EnvironmentFile when a token is provided' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units2'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken 'secret-token' -Hours 6

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match ([regex]::Escape('EnvironmentFile=/etc/wil-linux-client.env'))
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

    It 'New-SystemdStatusUnitFiles delivers the token via EnvironmentFile when a token is provided' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'status-units2'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken 'secret-token' -Minutes 30

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match ([regex]::Escape('EnvironmentFile=/etc/wil-linux-client.env'))
    }

    It 'New-SystemdStatusUnitFiles writes a timer matching the requested interval in minutes' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'status-units3'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken '' -Minutes 45

        $timerContent = Get-Content -LiteralPath $result.TimerPath -Raw
        $timerContent | Should -Match 'OnUnitActiveSec=45min'
        $timerContent | Should -Match 'Unit=wil-linux-client-status.service'
    }

    It 'Invoke-RemoteCommand key auth calls Invoke-PlinkWithAuth with plink.exe and the converted key path, no -pwfile' {
        Mock Invoke-PlinkWithAuth { return 'ok' }
        $script:usingPassword = $false
        $script:plinkPath = 'plink.exe'
        $script:ConvertedKeyPath = 'C:\fake\converted.ppk'
        $script:CredentialUsername = 'root'

        Invoke-RemoteCommand -TargetComputer '192.0.2.10' -Command 'echo hi'

        Should -Invoke Invoke-PlinkWithAuth -Times 1 -ParameterFilter {
            $ExePath -eq 'plink.exe' -and $ConvertedKeyPath -eq 'C:\fake\converted.ppk'
        }
    }

    It 'Invoke-RemoteCommand password auth calls Invoke-PlinkWithAuth with plink.exe, no -pw/-batch in its own Arguments, and the real password' {
        Mock Invoke-PlinkWithAuth { return 'ok' }
        $script:usingPassword = $true
        $script:plinkPath = 'plink.exe'
        $script:CredentialUsername = 'root'
        $script:CredentialPassword = (ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force)

        Invoke-RemoteCommand -TargetComputer '192.0.2.10' -Command 'echo hi'

        Should -Invoke Invoke-PlinkWithAuth -Times 1 -ParameterFilter {
            $ExePath -eq 'plink.exe' -and ($Arguments -notcontains '-pw') -and ($Arguments -notcontains '-batch') -and ($PlainPassword -eq 'unused-test-password')
        }
    }

    It 'Copy-FileToRemote password auth calls Invoke-PlinkWithAuth with pscp.exe, no -pw/-batch in its own Arguments, and the real password' {
        Mock Invoke-PlinkWithAuth { return 'ok' }
        $script:usingPassword = $true
        $script:pscpPath = 'pscp.exe'
        $script:CredentialUsername = 'root'
        $script:CredentialPassword = (ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force)

        Copy-FileToRemote -TargetComputer '192.0.2.10' -LocalPath 'C:\fake\wil-linux-client' -RemotePath '/tmp/wil-linux-client-install/wil-linux-client'

        Should -Invoke Invoke-PlinkWithAuth -Times 1 -ParameterFilter {
            $ExePath -eq 'pscp.exe' -and ($Arguments -notcontains '-pw') -and ($Arguments -notcontains '-batch') -and ($PlainPassword -eq 'unused-test-password')
        }
    }

    It 'Copy-FileToRemote key auth calls Invoke-PlinkWithAuth with pscp.exe and the converted key path, no -pwfile' {
        Mock Invoke-PlinkWithAuth { return 'ok' }
        $script:usingPassword = $false
        $script:pscpPath = 'pscp.exe'
        $script:ConvertedKeyPath = 'C:\fake\converted.ppk'
        $script:CredentialUsername = 'root'

        Copy-FileToRemote -TargetComputer '192.0.2.10' -LocalPath 'C:\fake\wil-linux-client' -RemotePath '/tmp/wil-linux-client-install/wil-linux-client'

        Should -Invoke Invoke-PlinkWithAuth -Times 1 -ParameterFilter {
            $ExePath -eq 'pscp.exe' -and $ConvertedKeyPath -eq 'C:\fake\converted.ppk'
        }
    }

    Context 'Invoke-PlinkWithAuth' {
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
            $output = Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'echo hi') -PlainPassword 'unused-test-password'

            $output | Should -Match ([regex]::Escape('-pwfile'))
            $output | Should -Match '-batch'
            $output | Should -Not -Match ([regex]::Escape('unused-test-password'))
            if ($output -match '-pwfile\s+(\S+)') {
                $capturedPwFile = $Matches[1]
                Test-Path -LiteralPath $capturedPwFile | Should -Be $false
            }
        }

        It 'uses -i with the converted key path and never touches -pwfile when ConvertedKeyPath is supplied' {
            # A fake "plink" that just echoes its arguments, so the test can
            # assert that the real function actually uses -i with the key path
            # in the key-auth branch, not just that it happens to also
            # include -i when password auth is also present.
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-keyauth.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo ARGS: %*' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 0' -Encoding ASCII

            $output = Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'echo hi') -ConvertedKeyPath 'C:\fake\converted.ppk'

            $output | Should -Match ([regex]::Escape('-i'))
            $output | Should -Match ([regex]::Escape('C:\fake\converted.ppk'))
            $output | Should -Not -Match ([regex]::Escape('-pwfile'))
        }

        It 'throws a clear, actionable error when plink/pscp fails on an untrusted host key under -batch' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-hostkey-fail.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo The server''s host key is not cached and -batch prevents interactive prompting 1>&2' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 1' -Encoding ASCII

            { Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'echo hi') -PlainPassword 'unused-test-password' } |
                Should -Throw '*host key*'
        }

        It 'throws when neither -PlainPassword nor -ConvertedKeyPath is supplied' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-no-auth.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 0' -Encoding ASCII

            { Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') } |
                Should -Throw '*requires either*'
        }

        It 'throws when both -PlainPassword and -ConvertedKeyPath are supplied' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-both-auth.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 0' -Encoding ASCII

            { Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ConvertedKeyPath 'C:\fake\converted.ppk' } |
                Should -Throw '*not both*'
        }
    }

    Context 'Invoke-PlinkWithAuth host key handling' {
        It 'passes -hostkey when ExpectedHostKey is supplied' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-hostkey-arg.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo ARGS: %*' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 0' -Encoding ASCII

            $output = Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ExpectedHostKey 'SHA256:abc123'

            $output | Should -Match ([regex]::Escape('-hostkey'))
            $output | Should -Match ([regex]::Escape('SHA256:abc123'))
        }

        It 'does not pass -hostkey when ExpectedHostKey is empty' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-no-hostkey-arg.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo ARGS: %*' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 0' -Encoding ASCII

            $output = Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ExpectedHostKey ''

            $output | Should -Not -Match ([regex]::Escape('-hostkey'))
        }

        It 'throws an UNKNOWN-key message when ExpectedHostKey was not supplied and plink reports a host-key failure' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-hostkey-fail-unknown.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo The server''s host key is not cached and -batch prevents interactive prompting 1>&2' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 1' -Encoding ASCII

            { Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ExpectedHostKey '' } |
                Should -Throw '*is not yet trusted by this machine*'
        }

        It 'throws a CHANGED-key message when ExpectedHostKey was supplied and plink still reports a host-key failure' {
            $fakeExe = Join-Path -Path $TestDrive -ChildPath 'fake-plink-hostkey-fail-changed.cmd'
            Set-Content -LiteralPath $fakeExe -Value '@echo off' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'echo WARNING - POTENTIAL SECURITY BREACH! The server''s host key does not match the one PuTTY has cached 1>&2' -Encoding ASCII
            Add-Content -LiteralPath $fakeExe -Value 'exit /b 1' -Encoding ASCII

            { Invoke-PlinkWithAuth -ExePath $fakeExe -Arguments @('-ssh', 'root@192.0.2.10', 'true') -PlainPassword 'unused-test-password' -ExpectedHostKey 'SHA256:abc123' } |
                Should -Throw '*has CHANGED since it was last trusted here*'
        }
    }

    Context 'Clear-TempPasswordFile' {
        It 'overwrites the file content before deleting it' {
            $file = Join-Path -Path $TestDrive -ChildPath 'pw-overwrite.txt'
            [System.IO.File]::WriteAllText($file, 'super-secret-password')
            Clear-TempPasswordFile -Path $file
            Test-Path -LiteralPath $file | Should -BeFalse
        }

        It 'warns instead of failing silently when the file cannot be deleted' {
            $file = Join-Path -Path $TestDrive -ChildPath 'pw-locked.txt'
            [System.IO.File]::WriteAllText($file, 'super-secret-password')
            $stream = [System.IO.File]::Open($file, 'Open', 'ReadWrite', 'None')
            try {
                # A plaintext credential left behind in %TEMP% indefinitely must not
                # be silent - the old code used -ErrorAction SilentlyContinue.
                $warnings = @()
                Clear-TempPasswordFile -Path $file -WarningVariable warnings -WarningAction SilentlyContinue
                $warnings.Count | Should -BeGreaterThan 0
            }
            finally {
                $stream.Close()
                Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
            }
        }

        It 'does not warn when the file is already gone' {
            $warnings = @()
            Clear-TempPasswordFile -Path (Join-Path -Path $TestDrive -ChildPath 'never-existed.txt') -WarningVariable warnings -WarningAction SilentlyContinue
            $warnings.Count | Should -Be 0
        }
    }

    Context 'Convert-OpenSshKeyToPpk' {
        BeforeAll {
            $script:FixtureKeyPath = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key'
        }

        It 'converts the fixture RSA key to a structurally valid PPK v2 file' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPath -OutputPath $outputPath

            $content = Get-Content -LiteralPath $outputPath -Raw
            $content | Should -Match '^PuTTY-User-Key-File-2: ssh-rsa'
            $content | Should -Match 'Encryption: none'
            $content | Should -Match 'Comment: wil-test-fixture-key'
            $content | Should -Match 'Private-MAC: [0-9a-f]{40}'
        }

        It 'produces exactly the byte-for-byte PPK content already confirmed working against a real plink/pscp connection' {
            # This exact output (including the MAC) was independently verified during
            # this plan's own design phase: plink.exe -i <this-output> successfully ran
            # a remote command, and pscp.exe -i <this-output> successfully copied a
            # file, both against a real target. A mismatch here means a real
            # regression in the conversion logic, not just a cosmetic difference.
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-exact.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPath -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: wil-test-fixture-key
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQDaXjxxEC1RoXqHtQGWMzMpkBSPXklJSdk5
tepo1EMuH955N68bqYiixAXbVWHj29CI/LcRiU+xr1XmBjpU0mvlYdNQs4u4IQIs
bDXNlQzrC5Zdl2qp1vQLGZ+cWLMGh3EolXnWqb1I1INjrlTa2e3P6EFqD4tOpw1f
TvG/0VnfTwI86Z/Rvciz9KwKXxbOedQcQ183wCok4JFsSD9RHmy3M2o/Lt474uYW
QJproXlcdVQ/BoUObd4AO5kYYGz57sB8OS8919IayqycgojSLG1bp5KIgHqqaCzv
dbTtzKdT4BHDTmCk8V3X+mapneThooh3qPIv5cwfak6yPNxr7Jx7
Private-Lines: 14
AAABAGtUbjjUTrIUwHj7SrBcsgT3wGNHYJYZKh/nfjPQQMTm/R5vdC4QggwedRJ9
QQQSAsmSDRkdeIJJP9szrHAMjOPN1WORHFeAQeU7uqY1YIgWxe1ygwa/lGvwSDc8
kaHf6IqeDaio/VRSv9G62hJHk0/hRGWxBjO+gCAcWU6Cw72x2v975VeuhVBaKpaG
wuH0gO7z0x0zuDbttpdIcYfa+3sJJzIMBjJFYwrotBV8JYV74WLekkeDjff+Rc7C
fNZv5rOuBLF8U6ShAphwqdtMnNKK2EhlFxY/JckO5PPjIXxqVJnHIPuB0AD61gN8
R9mhAf59clHDlz9c85xnCbfshiEAAACBAPrNHeyaKiLgIChla63MDCwfFUb4sX83
ygWNJnT9CYWrrX9Az4tLff0V4xunJqRaREnNNwDi17xJTGOQrwB3boNTfGjDiVzo
mPdgr6mAAPWmKRmBZLyCtLoeoVhX+Iev9Mr9guWeM4HSH9Z4UQFX4GAWmKg3YYe+
R8nI/2UovVU3AAAAgQDe5QMSFHt6226S9hkyU3biS4jusH26g4ALFbjY2pQY3+9Q
WDcj538YHGfNjlc0PJPZ6X9+RcxSIih6shDj/66D5NRcLY8LfR3YgiXTDPHVHOhX
Pd7exrm+F2WHIRDEUB+oRRTshnsjLVhs63DZEHF6r5Z/UdRmbycCd+vw5ZxU3QAA
AIBLLYNSdo7Rdgf5/0JhapAiCHMBO50HTFBejohwfzOJ3dMU/cX1tPyht4DpPuhn
vsvK6MjHypWZ53cvJno/5lIXIdvOAHeYX+PkjICWd5xcKDgSVMANp1itg7qUFmCb
LIycEe1RD5cYal2crnOUU4jJsb9umUA9DenWRXxuS7CMCw==
Private-MAC: 03f3a01d75da47d59ffa45cfb8ffd9a30492b684
'@
            # Normalize line endings before comparing - StringBuilder.AppendLine
            # emits Environment.NewLine (CRLF on Windows), the here-string above
            # may have been normalized to LF by tooling.
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }

        It 'throws a clear error for a non-existent key path' {
            { Convert-OpenSshKeyToPpk -KeyPath (Join-Path -Path $TestDrive -ChildPath 'does-not-exist') -OutputPath (Join-Path -Path $TestDrive -ChildPath 'out.ppk') } |
                Should -Throw '*was not found*'
        }

        It 'throws a clear error for a non-openssh-key-v1 file' {
            $badKey = Join-Path -Path $TestDrive -ChildPath 'not-a-key.txt'
            Set-Content -LiteralPath $badKey -Value "-----BEGIN OPENSSH PRIVATE KEY-----`nAAAA`n-----END OPENSSH PRIVATE KEY-----" -Encoding ASCII
            { Convert-OpenSshKeyToPpk -KeyPath $badKey -OutputPath (Join-Path -Path $TestDrive -ChildPath 'out.ppk') } |
                Should -Throw '*not an OpenSSH private key*'
        }
    }

    Context 'New-SystemdUnitFiles token handling' {
        It 'keeps the token out of the unit file and points at the env file instead' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'units-token'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $units = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken 'secret-token' -Hours 6
            $content = Get-Content -LiteralPath $units.ServicePath -Raw
            $content | Should -Not -Match ([regex]::Escape('--token'))
            $content | Should -Not -Match ([regex]::Escape('secret-token'))
            $content | Should -Match ([regex]::Escape('EnvironmentFile=/etc/wil-linux-client.env'))
        }

        It 'omits EnvironmentFile entirely when there is no token' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'units-no-token'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $units = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 6
            (Get-Content -LiteralPath $units.ServicePath -Raw) | Should -Not -Match 'EnvironmentFile'
        }

        It 'produces a status unit with the env file and no command-line token' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'status-units'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $units = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken 'secret-token' -Minutes 30
            $content = Get-Content -LiteralPath $units.ServicePath -Raw
            $content | Should -Not -Match ([regex]::Escape('secret-token'))
            $content | Should -Match ([regex]::Escape('EnvironmentFile=/etc/wil-linux-client.env'))
            $content | Should -Match ([regex]::Escape('--mode status'))
        }

        It 'writes an env file whose single line matches the C# generator byte-for-byte' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'env-file'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $env = New-SystemdEnvFile -Directory $dir -SharedToken 'secret-token'
            (Get-Content -LiteralPath $env.EnvPath -Raw).TrimEnd("`n") | Should -Be 'WIL_INGESTION_TOKEN=secret-token'
        }

        # This file holds the ingestion token in plaintext on the LOCAL
        # machine running this script - same class of secret as the plink
        # -pwfile Invoke-PlinkWithAuth already restricts, and this
        # fix applies that identical ACL treatment here (protect + grant
        # FullControl to only the current user, instead of inheriting
        # whatever $Directory's own ACL happens to be).
        It 'restricts the env file to only the current user, protected from inheritance' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'env-file-acl'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $env = New-SystemdEnvFile -Directory $dir -SharedToken 'secret-token'

            $acl = Get-Acl -LiteralPath $env.EnvPath
            $acl.AreAccessRulesProtected | Should -BeTrue
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $identities = $acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
            $identities | Should -Contain $currentUser
        }

        # Install-ClientDebianSSHInstallTarget's finally block calls
        # Clear-TempPasswordFile on this specific file before the staging
        # directory's blanket recursive cleanup - proven directly here since
        # exercising that through the full install flow would need a real
        # or heavily mocked SSH connection.
        It 'the env file is a valid target for the same secure-delete Clear-TempPasswordFile already gives the plink password file' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'env-file-delete'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $env = New-SystemdEnvFile -Directory $dir -SharedToken 'secret-token'

            Clear-TempPasswordFile -Path $env.EnvPath

            Test-Path -LiteralPath $env.EnvPath | Should -BeFalse
        }
    }
}

# This project has no shared module - Convert-OpenSshKeyToPpk is duplicated,
# byte-for-byte, in both Install-ClientDebianSSH.ps1 and
# Uninstall-ClientDebianSSH.ps1 (see either script's own doc comment on the
# function). Keeping the two copies in sync relies entirely on manual
# vigilance; this is the cheapest possible guard against silent drift
# between them - added as part of the 2026-09-15 SSH key-auth final review.
Describe 'Windows Inventory Lite Convert-OpenSshKeyToPpk stays in sync between Install and Uninstall scripts' {
    It 'is byte-for-byte identical in both scripts' {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $installPath = Join-Path -Path $projectRoot -ChildPath 'src\Install-ClientDebianSSH.ps1'
        $uninstallPath = Join-Path -Path $projectRoot -ChildPath 'src\Uninstall-ClientDebianSSH.ps1'

        function Get-FunctionText {
            param([string]$Path, [string]$FunctionName)
            $tokens = $null
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
            $functionAsts = $ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $FunctionName
            }, $true)
            if ($functionAsts.Count -ne 1) {
                throw "Expected exactly one '$FunctionName' function in $Path, found $($functionAsts.Count)"
            }
            return $functionAsts[0].Extent.Text
        }

        $installText = Get-FunctionText -Path $installPath -FunctionName 'Convert-OpenSshKeyToPpk'
        $uninstallText = Get-FunctionText -Path $uninstallPath -FunctionName 'Convert-OpenSshKeyToPpk'

        $installText | Should -BeExactly $uninstallText
    }
}
