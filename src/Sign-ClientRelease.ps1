#requires -Version 2.0

<#
.SYNOPSIS
Produces a detached RSA/SHA256 signature for a single built client
binary, verified by WindowsInventoryLiteClient.cs's VerifyRsaSignature
and linux-client/selfupdate.go's verifySelfUpdateSignature.

.DESCRIPTION
Run this once per binary per release (twice for the Windows client -
net35 and net40 - once for the Linux client), AFTER Build-Client.ps1/
Build-LinuxClient.ps1 produce the real binary, and BEFORE copying it
into ClientPackagePath/LinuxClientPackagePath. The private key never
touches Build-*.ps1, the server, or this repository - see
docs/self-update-signing.md for how to generate it once.

.EXAMPLE
.\Sign-ClientRelease.ps1 -BinaryPath .\build\WindowsInventoryLiteClient-net40.exe -PrivateKeyPath C:\secure\wil-self-update-private-key.xml
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BinaryPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PrivateKeyPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $BinaryPath)) {
    throw "Binary not found: $BinaryPath"
}
if (-not (Test-Path -LiteralPath $PrivateKeyPath)) {
    throw "Private key file not found: $PrivateKeyPath"
}

$privateKeyXml = Get-Content -LiteralPath $PrivateKeyPath -Raw
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
try {
    $rsa.FromXmlString($privateKeyXml)
    if ($rsa.PublicOnly) {
        throw "The key at $PrivateKeyPath is public-only - it cannot sign. Use the private key file produced by the key-generation step in docs/self-update-signing.md."
    }

    $fileBytes = [System.IO.File]::ReadAllBytes($BinaryPath)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $signatureBytes = $rsa.SignData($fileBytes, $sha256)
    }
    finally {
        $sha256.Dispose()
    }
    $signatureBase64 = [Convert]::ToBase64String($signatureBytes)

    $sigPath = $BinaryPath + '.sig'
    [System.IO.File]::WriteAllText($sigPath, $signatureBase64, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "Signed: $sigPath"
}
finally {
    $rsa.Dispose()
}
