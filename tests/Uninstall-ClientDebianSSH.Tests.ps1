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

    Context 'Convert-OpenSshKeyToPpk' {
        BeforeAll {
            $script:FixtureKeyPathEd25519 = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key-ed25519'
            $script:FixtureKeyPathEcdsa256 = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key-ecdsa256'
            $script:FixtureKeyPathEcdsa384 = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key-ecdsa384'
            $script:FixtureKeyPathEcdsa521 = Join-Path -Path $script:ProjectRoot -ChildPath 'tests\fixtures\wil-test-fixture-key-ecdsa521'
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
    }
}
