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

All three flags are client-side, install-time switches, off by default
(the server can never change what a client enforces - see
`ClientOptions.RequireHttpsForSelfUpdate`'s own comment in
`WindowsInventoryLiteClient.cs` for why):

```
--require-https-self-update            Require https for self-update, re-checked on every attempt
--allow-http-self-update-fallback      If https isn't available right now, fall back to http instead of refusing (ignored unless the flag above is set)
--require-signed-self-update           Refuse to self-update unless a valid signature is advertised
```

`--require-https-self-update` is evaluated fresh on every self-update
attempt (Windows client, since 0.18.0), not fixed once against the
client's own `ServerUrl` at install time: if `ServerUrl` is `http://`
but the server's ack advertises an active `httpsPort` (the server has a
certificate, whether or not it existed when this client was deployed),
the client retries the download over `https://` on that port instead -
so a fleet rolled out before a certificate existed starts using HTTPS
automatically the moment the server gets one, with no per-machine
reconfiguration needed. If no `httpsPort` is advertised, or the
opportunistic `https://` attempt itself fails (an invalid or
self-signed certificate - this client never overrides .NET's default
certificate validation, so that failure is a real TLS rejection, not a
formality), `--allow-http-self-update-fallback` decides what happens
next: unset, the client refuses (today's original "require" meaning);
set, it falls back to plain `http://` instead, matching how self-update
already behaves with neither flag set - useful for a deployment that
may never get a certificate (a lab, an isolated segment) without giving
up the "prefer encryption when it's available" benefit everywhere else.

Set via `Install-Client.ps1 -RequireHttpsSelfUpdate -AllowHttpSelfUpdateFallback -RequireSignedSelfUpdate`,
`Install-Wizard.ps1` (asks for all three directly, for every
deployment flow - local, GPO, and WinRM), or the equivalent GPO/WinRM
deployment switches (`Deploy-ClientGpo.ps1`/`Install-ClientWinRM.ps1`
accept the same three). Turning on `--require-signed-self-update`
before ANY release has been signed with the real key will permanently
block self-update for that client until a signed release is published
- deploy the flag only after your first signed release is already in
`ClientPackagePath`/`LinuxClientPackagePath`.

**Linux client scope note**: the opportunistic-HTTPS/fallback behavior
above is Windows-client-only as of this writing. The Linux client
(`linux-client/selfupdate.go`) still only has the original static
`--require-https-self-update`/`--require-signed-self-update` pair with
no dynamic httpsPort retry or fallback option - out of scope for this
round, left as a known gap for whoever picks up Linux self-update
parity next.
