# Self-update signing key

Client self-update integrity (SEC-C2) is verified two ways when an
admin turns on `--require-signed-self-update`: the existing SHA-256
hash (corruption only) plus an RSA/SHA256/PKCS#1v1.5 signature over the
same bytes (tampering, including a LAN MITM forging the ack that
advertises the update).

This project uses a self-managed key pair - no external CA. The
private key is generated and kept by whoever builds releases; the
public key ships inside both clients' source.

## One-time key generation

Run this ONCE, on a machine you trust, and store the resulting private
key file somewhere secure and backed up (losing it means generating a
new key pair and rebuilding+redistributing both clients with the new
public key):

```powershell
$rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
[System.IO.File]::WriteAllText('C:\secure-location\wil-self-update-private-key.xml', $rsa.ToXmlString($true))
$publicParams = $rsa.ExportParameters($false)
Write-Host "Modulus (base64): $([Convert]::ToBase64String($publicParams.Modulus))"
Write-Host "Exponent (base64): $([Convert]::ToBase64String($publicParams.Exponent))"
$rsa.Dispose()
```

Never commit the private key file to this repository. It never needs
to touch the server at runtime either - only whoever runs
`Sign-ClientRelease.ps1` needs access to it.

Copy the `Modulus (base64)` and `Exponent (base64)` values straight out
of this command's own printed output when you paste them into the
clients below - do not retype or hand-copy them from anywhere else.
This is not a hypothetical risk: an earlier placeholder constant in
this same project was hand-copied one character short, which silently
broke self-update in production while every self-test still passed
(the tests never exercised the real base64 decode path). A wrong
Modulus fails closed - clients simply refuse every signature and log a
verification failure - but "fails closed" is still a production outage
you want to avoid by copying the value programmatically instead of by
hand.

## Wiring the public key into both clients

Paste the "Modulus (base64)" value from the step above into:
- `src/client/WindowsInventoryLiteClient.cs` - the `SelfUpdatePublicKeyModulusBase64` constant near `SelfUpdateTaskName`.
- `linux-client/selfupdate.go` - the `selfUpdatePublicKeyModulusBase64` variable near `ApplySelfUpdate`.

The exponent is virtually always `65537` (`AQAB` in base64) for a
freshly generated RSA key pair - both clients already default to this
value, but double check the generated value matches before assuming so.

Rebuild both clients after updating the constant, and re-run
`--self-test`/`go test ./...` to confirm nothing else broke.

## Signing a release

After building each target binary (`Build-Client.ps1`,
`Build-LinuxClient.ps1`), before copying it into `ClientPackagePath`/
`LinuxClientPackagePath`, sign it:

```powershell
.\src\Sign-ClientRelease.ps1 -BinaryPath .\build\WindowsInventoryLiteClient-net35.exe -PrivateKeyPath C:\secure-location\wil-self-update-private-key.xml
.\src\Sign-ClientRelease.ps1 -BinaryPath .\build\WindowsInventoryLiteClient-net40.exe -PrivateKeyPath C:\secure-location\wil-self-update-private-key.xml
.\src\Sign-ClientRelease.ps1 -BinaryPath .\build\wil-linux-client -PrivateKeyPath C:\secure-location\wil-self-update-private-key.xml
```

Each produces a `<binary>.sig` file alongside the binary - copy both
the binary AND its `.sig` file into `ClientPackagePath`/
`LinuxClientPackagePath` together. The server automatically includes
the `.sig` file's content in the self-update ack whenever it exists
(`BuildWindowsClientUpdateInfo`/`BuildLinuxClientUpdateInfo`) - no
server configuration needed.

## Turning on enforcement

Both flags are client-side, install-time switches, off by default:

```
--require-https-self-update    Refuse to self-update unless ServerUrl is https
--require-signed-self-update   Refuse to self-update unless a valid signature is advertised
```

Set via `Install-Client.ps1 -RequireHttpsSelfUpdate -RequireSignedSelfUpdate`
or the equivalent GPO deployment switches. Turning on
`--require-signed-self-update` before ANY release has been signed with
the real key will permanently block self-update for that client until
a signed release is published - deploy the flag only after your first
signed release is already in `ClientPackagePath`/`LinuxClientPackagePath`.
