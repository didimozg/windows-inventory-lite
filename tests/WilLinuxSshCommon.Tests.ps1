$ErrorActionPreference = 'Stop'

Describe 'WilLinuxSshCommon shared functions' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        . (Join-Path -Path $script:ProjectRoot -ChildPath 'src\WilLinuxSshCommon.ps1')
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

    # Duplicate coverage of the same behavior as the two Invoke-RemoteCommand
    # tests above - Uninstall-ClientDebianSSH.Tests.ps1 carried its own
    # (key-auth only) copy before this consolidation, mirroring how the
    # underlying script duplicated the function itself. Kept as a separate
    # It to preserve the pre-consolidation test count exactly (see this
    # task's report); a future cleanup could fold it into the copy above.
    It 'Invoke-RemoteCommand key auth calls Invoke-PlinkWithAuth with plink.exe and the converted key path, no -pwfile (from Uninstall-ClientDebianSSH.Tests.ps1)' {
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

        # Drift-guard added by the WilLinuxSshCommon.ps1 extraction task: the
        # shared module must carry Install-ClientDebianSSH.ps1's CORRECT
        # host-key-changed wording, not Uninstall-ClientDebianSSH.ps1's old,
        # wrong "not yet trusted...run plink interactively" advice for the
        # same (changed-key) situation. Checking the loaded function's own
        # source text (rather than triggering a real plink failure) works
        # for any dot-sourced function and needs no fake plink executable.
        #
        # Note on the -Match strings: the brief's original illustrative
        # assertion (`Should -Not -Match 'not yet trusted'`) does not
        # actually discriminate correct from drifted wording - the CORRECT
        # function legitimately contains "not yet trusted" too, in its own
        # (different, correct) branch for a genuinely never-seen host key.
        # 'Run plink interactively' is the phrase unique to the old,
        # drifted uninstaller wording and absent from the correct version,
        # so that is what this test asserts against instead.
        It 'Invoke-PlinkWithAuth warns about a CHANGED host key, not the old "run plink interactively to accept it" advice, on a host-key mismatch' {
            $functionBody = (Get-Command Invoke-PlinkWithAuth).Definition
            $functionBody | Should -Match 'CHANGED since it was last trusted here'
            $functionBody | Should -Not -Match 'Run plink interactively'
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
            $script:FixtureKeyPathEd25519 = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key-ed25519'
            $script:FixtureKeyPathEcdsa256 = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key-ecdsa256'
            $script:FixtureKeyPathEcdsa384 = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key-ecdsa384'
            $script:FixtureKeyPathEcdsa521 = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key-ecdsa521'
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

        It 'throws a clear error naming Ed25519/ECDSA as supported for an unsupported keytype' {
            # Confirms the updated error message text, not just that SOME
            # error is thrown - the earlier RSA-only version of this
            # message would otherwise silently go stale once other
            # keytypes are actually supported.
            $badKey = Join-Path -Path $TestDrive -ChildPath 'dsa-shaped.txt'
            # A structurally valid-looking but unsupported keytype ("ssh-dss")
            # is enough to reach the switch's default branch - does not need
            # to be a real, parseable DSA key body.
            $magic = [System.Text.Encoding]::ASCII.GetBytes("openssh-key-v1`0")
            function LocalWriteSshString([byte[]]$Bytes) {
                $lenBytes = [System.BitConverter]::GetBytes([uint32]$Bytes.Length)
                [Array]::Reverse($lenBytes)
                return $lenBytes + $Bytes
            }
            $cipherName = LocalWriteSshString ([System.Text.Encoding]::ASCII.GetBytes("none"))
            $kdfName = LocalWriteSshString ([System.Text.Encoding]::ASCII.GetBytes("none"))
            $kdfOptions = LocalWriteSshString ([byte[]]@())
            $keyCount = [byte[]]@(0, 0, 0, 1)
            $publicBlob = LocalWriteSshString ([System.Text.Encoding]::ASCII.GetBytes("ssh-dss-fake-public-blob"))
            $keytypeInPriv = LocalWriteSshString ([System.Text.Encoding]::ASCII.GetBytes("ssh-dss"))
            $checkint = [byte[]]@(1, 2, 3, 4)
            $comment = LocalWriteSshString ([System.Text.Encoding]::UTF8.GetBytes("dsa-test"))
            $privSectionContent = $checkint + $checkint + $keytypeInPriv + $comment
            $privSection = LocalWriteSshString $privSectionContent
            $blob = $magic + $cipherName + $kdfName + $kdfOptions + $keyCount + $publicBlob + $privSection
            $b64 = [Convert]::ToBase64String($blob)
            $content = "-----BEGIN OPENSSH PRIVATE KEY-----`n$b64`n-----END OPENSSH PRIVATE KEY-----"
            Set-Content -LiteralPath $badKey -Value $content -Encoding ASCII

            { Convert-OpenSshKeyToPpk -KeyPath $badKey -OutputPath (Join-Path -Path $TestDrive -ChildPath 'out-dsa.ppk') } |
                Should -Throw "*only RSA (ssh-rsa), Ed25519 (ssh-ed25519), and ECDSA*"
        }

        It 'converts the fixture Ed25519 key to a structurally valid PPK v2 file' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ed25519.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEd25519 -OutputPath $outputPath

            $content = Get-Content -LiteralPath $outputPath -Raw
            $content | Should -Match '^PuTTY-User-Key-File-2: ssh-ed25519'
            $content | Should -Match 'Encryption: none'
            $content | Should -Match 'Comment: wil-test-fixture-key-ed25519'
            $content | Should -Match 'Private-MAC: [0-9a-f]{40}'
        }

        It 'produces exactly the byte-for-byte PPK content for the Ed25519 fixture (independently cross-checked against Python cryptography)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ed25519-exact.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEd25519 -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: wil-test-fixture-key-ed25519
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAICgVJpqVT+XsjHqrDOrj1l921BhZlaBURth6wRLl
CZki
Private-Lines: 1
AAAAILmYqe+IwbMUfIxtNm4QD/KkpXHd+fFaAt1XVtAEps/O
Private-MAC: 7719b93ff3838b94fc80634ec29a8d041f9067a9
'@
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }

        It 'converts the fixture ECDSA nistp256 key to a structurally valid PPK v2 file' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ecdsa256.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEcdsa256 -OutputPath $outputPath

            $content = Get-Content -LiteralPath $outputPath -Raw
            $content | Should -Match '^PuTTY-User-Key-File-2: ecdsa-sha2-nistp256'
            $content | Should -Match 'Encryption: none'
            $content | Should -Match 'Comment: wil-test-fixture-key-ecdsa256'
            $content | Should -Match 'Private-MAC: [0-9a-f]{40}'
        }

        It 'produces exactly the byte-for-byte PPK content for the ECDSA nistp256 fixture (independently cross-checked against Python cryptography)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ecdsa256-exact.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEcdsa256 -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: none
Comment: wil-test-fixture-key-ecdsa256
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBENnuG0fEuLq
vc7ghbGc2Xn7T9VsegDbbTF+4vGmyRF9TXR1/jyYUj0/BPQYVyariVlV9vzZcUbI
jc9UaBXOk+E=
Private-Lines: 1
AAAAIQDP+YM8rq1yahSpmaCWE1X23c7FzFz8UF7KyD/3XnyoMQ==
Private-MAC: 244d2dc1cb353338c54ec567697bee3627d8b6cf
'@
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }

        It 'produces exactly the byte-for-byte PPK content for the ECDSA nistp384 fixture (independently cross-checked against Python cryptography)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ecdsa384-exact.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEcdsa384 -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ecdsa-sha2-nistp384
Encryption: none
Comment: wil-test-fixture-key-ecdsa384
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBHVZxeJNdMcu
zIGf8LDNatKeqoXE62UNeUFRE3FMDUdbwPHuKYqk3tS9tgz33jOGatNtat/QDTaD
/JPlNM8E7c6lVZV1Ce7d2wvJZYZer67Yj5SLuw+4OdE0RMmb4rTWmw==
Private-Lines: 2
AAAAMCb+F4eK9MEb2eixqA0NSb0LLku3sjQwkUUQEqZb5Ox1qf/WdcUtFMWqJHdb
6r3EcA==
Private-MAC: 87a9f2e9426f81da1245b7f1d9c4a48bd525c860
'@
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }

        It 'produces exactly the byte-for-byte PPK content for the ECDSA nistp521 fixture (independently cross-checked against Python cryptography)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ecdsa521-exact.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEcdsa521 -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ecdsa-sha2-nistp521
Encryption: none
Comment: wil-test-fixture-key-ecdsa521
Public-Lines: 4
AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAC/d6MZ6mKZ
ZLLr0uqDIovBUIBZNeu+ZRzCzzJ4Y98uII/cFCS/mb2XFZ8ZP1WnhGjEk+B2ljo5
xWbnzI4j/tQ8XgEYoktZkEmMDSMukuxDHrtOyrjLSmdFSpf4oqym1otSvzG6yFAp
z9SGIu/mwjP0w8RNe7vbhchSl4Q2rVTAAMOIog==
Private-Lines: 2
AAAAQgHihvXmcmI4/0xLaI7AXiLmIah8LN9u3imegriAVWq5nri0mF/MbhdReDZO
8AbwUmcElCYARB1leRGfjH3G7zaVrA==
Private-MAC: 29743855e134adbe819b7404868b75f193c1e4d2
'@
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }

        # Duplicate coverage of the same shared function, carried over from
        # Uninstall-ClientDebianSSH.Tests.ps1's own copy of these tests (see
        # this task's report) - kept as separate Its rather than deduplicated
        # so this consolidation's before/after It-block count matches exactly.
        It 'throws a clear error naming Ed25519/ECDSA as supported for an unsupported keytype (from Uninstall-ClientDebianSSH.Tests.ps1)' {
            $badKey = Join-Path -Path $TestDrive -ChildPath 'dsa-shaped-uninstall.txt'
            $magic = [System.Text.Encoding]::ASCII.GetBytes("openssh-key-v1`0")
            function LocalWriteSshString([byte[]]$Bytes) {
                $lenBytes = [System.BitConverter]::GetBytes([uint32]$Bytes.Length)
                [Array]::Reverse($lenBytes)
                return $lenBytes + $Bytes
            }
            $cipherName = LocalWriteSshString ([System.Text.Encoding]::ASCII.GetBytes("none"))
            $kdfName = LocalWriteSshString ([System.Text.Encoding]::ASCII.GetBytes("none"))
            $kdfOptions = LocalWriteSshString ([byte[]]@())
            $keyCount = [byte[]]@(0, 0, 0, 1)
            $publicBlob = LocalWriteSshString ([System.Text.Encoding]::ASCII.GetBytes("ssh-dss-fake-public-blob"))
            $keytypeInPriv = LocalWriteSshString ([System.Text.Encoding]::ASCII.GetBytes("ssh-dss"))
            $checkint = [byte[]]@(1, 2, 3, 4)
            $comment = LocalWriteSshString ([System.Text.Encoding]::UTF8.GetBytes("dsa-test"))
            $privSectionContent = $checkint + $checkint + $keytypeInPriv + $comment
            $privSection = LocalWriteSshString $privSectionContent
            $blob = $magic + $cipherName + $kdfName + $kdfOptions + $keyCount + $publicBlob + $privSection
            $b64 = [Convert]::ToBase64String($blob)
            $content = "-----BEGIN OPENSSH PRIVATE KEY-----`n$b64`n-----END OPENSSH PRIVATE KEY-----"
            Set-Content -LiteralPath $badKey -Value $content -Encoding ASCII

            { Convert-OpenSshKeyToPpk -KeyPath $badKey -OutputPath (Join-Path -Path $TestDrive -ChildPath 'out-dsa-uninstall.ppk') } |
                Should -Throw "*only RSA (ssh-rsa), Ed25519 (ssh-ed25519), and ECDSA*"
        }

        It 'converts the fixture Ed25519 key to a structurally valid PPK v2 file (from Uninstall-ClientDebianSSH.Tests.ps1)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ed25519-uninstall.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEd25519 -OutputPath $outputPath

            $content = Get-Content -LiteralPath $outputPath -Raw
            $content | Should -Match '^PuTTY-User-Key-File-2: ssh-ed25519'
            $content | Should -Match 'Encryption: none'
            $content | Should -Match 'Comment: wil-test-fixture-key-ed25519'
            $content | Should -Match 'Private-MAC: [0-9a-f]{40}'
        }

        It 'produces exactly the byte-for-byte PPK content for the Ed25519 fixture (independently cross-checked against Python cryptography) (from Uninstall-ClientDebianSSH.Tests.ps1)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ed25519-exact-uninstall.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEd25519 -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: wil-test-fixture-key-ed25519
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAICgVJpqVT+XsjHqrDOrj1l921BhZlaBURth6wRLl
CZki
Private-Lines: 1
AAAAILmYqe+IwbMUfIxtNm4QD/KkpXHd+fFaAt1XVtAEps/O
Private-MAC: 7719b93ff3838b94fc80634ec29a8d041f9067a9
'@
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }

        It 'converts the fixture ECDSA nistp256 key to a structurally valid PPK v2 file (from Uninstall-ClientDebianSSH.Tests.ps1)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ecdsa256-uninstall.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEcdsa256 -OutputPath $outputPath

            $content = Get-Content -LiteralPath $outputPath -Raw
            $content | Should -Match '^PuTTY-User-Key-File-2: ecdsa-sha2-nistp256'
            $content | Should -Match 'Encryption: none'
            $content | Should -Match 'Comment: wil-test-fixture-key-ecdsa256'
            $content | Should -Match 'Private-MAC: [0-9a-f]{40}'
        }

        It 'produces exactly the byte-for-byte PPK content for the ECDSA nistp256 fixture (independently cross-checked against Python cryptography) (from Uninstall-ClientDebianSSH.Tests.ps1)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ecdsa256-exact-uninstall.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEcdsa256 -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ecdsa-sha2-nistp256
Encryption: none
Comment: wil-test-fixture-key-ecdsa256
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBENnuG0fEuLq
vc7ghbGc2Xn7T9VsegDbbTF+4vGmyRF9TXR1/jyYUj0/BPQYVyariVlV9vzZcUbI
jc9UaBXOk+E=
Private-Lines: 1
AAAAIQDP+YM8rq1yahSpmaCWE1X23c7FzFz8UF7KyD/3XnyoMQ==
Private-MAC: 244d2dc1cb353338c54ec567697bee3627d8b6cf
'@
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }

        It 'produces exactly the byte-for-byte PPK content for the ECDSA nistp384 fixture (independently cross-checked against Python cryptography) (from Uninstall-ClientDebianSSH.Tests.ps1)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ecdsa384-exact-uninstall.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEcdsa384 -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ecdsa-sha2-nistp384
Encryption: none
Comment: wil-test-fixture-key-ecdsa384
Public-Lines: 3
AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBHVZxeJNdMcu
zIGf8LDNatKeqoXE62UNeUFRE3FMDUdbwPHuKYqk3tS9tgz33jOGatNtat/QDTaD
/JPlNM8E7c6lVZV1Ce7d2wvJZYZer67Yj5SLuw+4OdE0RMmb4rTWmw==
Private-Lines: 2
AAAAMCb+F4eK9MEb2eixqA0NSb0LLku3sjQwkUUQEqZb5Ox1qf/WdcUtFMWqJHdb
6r3EcA==
Private-MAC: 87a9f2e9426f81da1245b7f1d9c4a48bd525c860
'@
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }

        It 'produces exactly the byte-for-byte PPK content for the ECDSA nistp521 fixture (independently cross-checked against Python cryptography) (from Uninstall-ClientDebianSSH.Tests.ps1)' {
            $outputPath = Join-Path -Path $TestDrive -ChildPath 'converted-ecdsa521-exact-uninstall.ppk'
            Convert-OpenSshKeyToPpk -KeyPath $script:FixtureKeyPathEcdsa521 -OutputPath $outputPath

            $expected = @'
PuTTY-User-Key-File-2: ecdsa-sha2-nistp521
Encryption: none
Comment: wil-test-fixture-key-ecdsa521
Public-Lines: 4
AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAC/d6MZ6mKZ
ZLLr0uqDIovBUIBZNeu+ZRzCzzJ4Y98uII/cFCS/mb2XFZ8ZP1WnhGjEk+B2ljo5
xWbnzI4j/tQ8XgEYoktZkEmMDSMukuxDHrtOyrjLSmdFSpf4oqym1otSvzG6yFAp
z9SGIu/mwjP0w8RNe7vbhchSl4Q2rVTAAMOIog==
Private-Lines: 2
AAAAQgHihvXmcmI4/0xLaI7AXiLmIah8LN9u3imegriAVWq5nri0mF/MbhdReDZO
8AbwUmcElCYARB1leRGfjH3G7zaVrA==
Private-MAC: 29743855e134adbe819b7404868b75f193c1e4d2
'@
            $actualNormalized = (Get-Content -LiteralPath $outputPath -Raw) -replace "`r`n", "`n"
            $expectedNormalized = $expected -replace "`r`n", "`n"
            $actualNormalized.TrimEnd("`n") | Should -Be $expectedNormalized.TrimEnd("`n")
        }
    }
}
