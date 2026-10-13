$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Sign-ClientRelease' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Sign-ClientRelease.ps1'

        $script:Rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
        $script:PrivateKeyXml = $script:Rsa.ToXmlString($true)
        $script:PublicKeyXml = $script:Rsa.ToXmlString($false)
    }

    AfterAll {
        if ($script:Rsa) {
            $script:Rsa.Dispose()
        }
    }

    It 'throws when the binary does not exist' {
        $keyPath = Join-Path -Path $TestDrive -ChildPath 'private.xml'
        Set-Content -LiteralPath $keyPath -Value $script:PrivateKeyXml -NoNewline

        { & $script:ScriptPath -BinaryPath (Join-Path -Path $TestDrive -ChildPath 'missing.exe') -PrivateKeyPath $keyPath } | Should -Throw '*Binary not found*'
    }

    It 'throws when the private key file does not exist' {
        $binaryPath = Join-Path -Path $TestDrive -ChildPath 'app.exe'
        Set-Content -LiteralPath $binaryPath -Value 'fake binary content' -NoNewline

        { & $script:ScriptPath -BinaryPath $binaryPath -PrivateKeyPath (Join-Path -Path $TestDrive -ChildPath 'missing.xml') } | Should -Throw '*Private key file not found*'
    }

    It 'throws when the key file holds only a public key' {
        $binaryPath = Join-Path -Path $TestDrive -ChildPath 'app-pubonly.exe'
        Set-Content -LiteralPath $binaryPath -Value 'fake binary content' -NoNewline
        $publicKeyPath = Join-Path -Path $TestDrive -ChildPath 'public-only.xml'
        Set-Content -LiteralPath $publicKeyPath -Value $script:PublicKeyXml -NoNewline

        { & $script:ScriptPath -BinaryPath $binaryPath -PrivateKeyPath $publicKeyPath } | Should -Throw '*public-only*'
    }

    It 'produces a .sig file, as UTF8-without-BOM text, whose signature verifies against the matching public key' {
        $binaryPath = Join-Path -Path $TestDrive -ChildPath 'app-real.exe'
        $binaryBytes = [byte[]](1..200 | ForEach-Object { $_ % 256 })
        [System.IO.File]::WriteAllBytes($binaryPath, $binaryBytes)
        $keyPath = Join-Path -Path $TestDrive -ChildPath 'private-real.xml'
        Set-Content -LiteralPath $keyPath -Value $script:PrivateKeyXml -NoNewline

        & $script:ScriptPath -BinaryPath $binaryPath -PrivateKeyPath $keyPath

        $sigPath = "$binaryPath.sig"
        Test-Path -LiteralPath $sigPath | Should -Be $true

        $sigBytes = [System.IO.File]::ReadAllBytes($sigPath)
        # No UTF-8 BOM (EF BB BF) at the start of the file.
        ($sigBytes.Length -ge 3 -and $sigBytes[0] -eq 0xEF -and $sigBytes[1] -eq 0xBB -and $sigBytes[2] -eq 0xBF) | Should -Be $false

        $signatureBase64 = Get-Content -LiteralPath $sigPath -Raw
        $signatureBytes = [Convert]::FromBase64String($signatureBase64.Trim())

        $verifier = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        try {
            $verifier.FromXmlString($script:PublicKeyXml)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                $verifier.VerifyData($binaryBytes, $sha256, $signatureBytes) | Should -Be $true
            }
            finally {
                $sha256.Dispose()
            }
        }
        finally {
            $verifier.Dispose()
        }
    }

    It 'a signature does not verify against a different binary (tamper detection)' {
        $binaryPath = Join-Path -Path $TestDrive -ChildPath 'app-tamper.exe'
        $originalBytes = [byte[]](1..200 | ForEach-Object { $_ % 256 })
        [System.IO.File]::WriteAllBytes($binaryPath, $originalBytes)
        $keyPath = Join-Path -Path $TestDrive -ChildPath 'private-tamper.xml'
        Set-Content -LiteralPath $keyPath -Value $script:PrivateKeyXml -NoNewline

        & $script:ScriptPath -BinaryPath $binaryPath -PrivateKeyPath $keyPath
        $sigPath = "$binaryPath.sig"
        $signatureBytes = [Convert]::FromBase64String((Get-Content -LiteralPath $sigPath -Raw).Trim())

        $tamperedBytes = [byte[]](2..201 | ForEach-Object { $_ % 256 })

        $verifier = New-Object System.Security.Cryptography.RSACryptoServiceProvider
        try {
            $verifier.FromXmlString($script:PublicKeyXml)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            try {
                $verifier.VerifyData($tamperedBytes, $sha256, $signatureBytes) | Should -Be $false
            }
            finally {
                $sha256.Dispose()
            }
        }
        finally {
            $verifier.Dispose()
        }
    }
}
