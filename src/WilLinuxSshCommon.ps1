#requires -Version 2.0

# Shared by Install-ClientDebianSSH.ps1 and Uninstall-ClientDebianSSH.ps1 -
# both are copied into the same server-bin directory at install time
# (Install-Server.ps1), so dot-sourcing a shared module is safe here,
# unlike scripts that must run standalone on a target machine (see
# Install-Client.ps1/Deploy-ClientGpo.ps1, which correctly keep their own
# copies of similar small helpers for that reason).
#
# Function definitions only - no top-level side effects, no output,
# safe to dot-source from either script or a test file.

function Test-PosixShellSafe {
    param(
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Value,
        [string]$FieldName
    )
    if ([string]::IsNullOrEmpty($Value)) {
        return
    }
    $unsafeChars = '`', '$', '"', "'", '\', ';', '|', '&', '<', '>', '(', ')', "`r", "`n", ' ', "`t"
    foreach ($char in $unsafeChars) {
        if ($Value.Contains($char)) {
            throw "$FieldName contains a character that is not allowed here (``, `$, `", ', \, ;, |, &, <, >, (, ), whitespace, or a line break)."
        }
    }
}

function Test-LinuxInstallPathSafe {
    param([string]$InstallPath)
    if ([string]::IsNullOrEmpty($InstallPath) -or -not $InstallPath.StartsWith('/')) {
        throw "InstallPath must be an absolute Linux path under /opt/ (e.g. /opt/windows-inventory-lite)."
    }
    # @(...) forces this to always be an array, even with 0 or 1 elements -
    # Windows PowerShell 5.1 (unlike PS7+) has no .Count on a bare scalar.
    $allSegments = @($InstallPath.Trim('/') -split '/' | Where-Object { $_ -ne '' })
    foreach ($segment in $allSegments) {
        if ($segment -eq '..' -or $segment -eq '.') {
            throw "InstallPath must be an absolute Linux path under /opt/ (e.g. /opt/windows-inventory-lite) - a '..' or '.' path segment is rejected."
        }
    }
    if (-not $InstallPath.StartsWith('/opt/')) {
        throw "InstallPath must be an absolute Linux path under /opt/ (e.g. /opt/windows-inventory-lite) - a bare top-level directory like /usr or /etc is rejected."
    }
    $remainderSegments = @(($InstallPath.Substring('/opt/'.Length)).Trim('/') -split '/' | Where-Object { $_ -ne '' })
    if ($remainderSegments.Count -lt 1) {
        throw "InstallPath must be an absolute Linux path under /opt/ (e.g. /opt/windows-inventory-lite) - a bare /opt is rejected."
    }
}

function ConvertTo-PlainText {
    param([System.Security.SecureString]$Secure)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Invoke-NativeAllowingStderr {
    param([scriptblock]$ScriptBlock)

    $previousEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $ScriptBlock
    }
    finally {
        $ErrorActionPreference = $previousEap
    }
}

function Convert-OpenSshKeyToPpk {
    param(
        [string]$KeyPath,
        [string]$OutputPath
    )

    function Read-SshString {
        param([byte[]]$Bytes, [ref]$Offset)
        $lenBytes = $Bytes[$Offset.Value..($Offset.Value + 3)]
        [Array]::Reverse($lenBytes)
        $len = [System.BitConverter]::ToUInt32($lenBytes, 0)
        $Offset.Value += 4
        if ($len -eq 0) {
            return ,(New-Object byte[] 0)
        }
        $val = $Bytes[$Offset.Value..($Offset.Value + $len - 1)]
        $Offset.Value += $len
        return ,$val
    }

    function Write-SshString {
        param([byte[]]$Bytes)
        $lenBytes = [System.BitConverter]::GetBytes([uint32]$Bytes.Length)
        [Array]::Reverse($lenBytes)
        return $lenBytes + $Bytes
    }

    if (-not (Test-Path -LiteralPath $KeyPath)) {
        throw "SSH private key was not found: $KeyPath"
    }

    $raw = [System.IO.File]::ReadAllText((Get-Item -LiteralPath $KeyPath).FullName)
    $lines = $raw -split "`n" | Where-Object { $_ -notmatch '-----BEGIN|-----END' -and $_.Trim() -ne '' }
    $blob = [Convert]::FromBase64String(($lines -join '').Trim())

    $offset = 0
    if ([System.Text.Encoding]::ASCII.GetString($blob[0..14]) -ne "openssh-key-v1`0") {
        throw "'$KeyPath' is not an OpenSSH private key in the expected openssh-key-v1 format."
    }
    $offset = 15

    $ciphername = [System.Text.Encoding]::ASCII.GetString((Read-SshString $blob ([ref]$offset)))
    [void](Read-SshString $blob ([ref]$offset))  # kdfname, unused when cipher is none
    [void](Read-SshString $blob ([ref]$offset))  # kdfoptions, unused when cipher is none
    $offset += 4  # key count (always 1 for this project's usage)

    if ($ciphername -ne 'none') {
        throw "'$KeyPath' is passphrase-protected (cipher '$ciphername'). Automated key-auth pushes require a passphrase-less private key - this is an existing requirement, not new."
    }

    $publicBlobBytes = Read-SshString $blob ([ref]$offset)

    $privSection = Read-SshString $blob ([ref]$offset)
    $po = 0
    $check1Bytes = $privSection[0..3]; [Array]::Reverse($check1Bytes)
    $check2Bytes = $privSection[4..7]; [Array]::Reverse($check2Bytes)
    if ([System.BitConverter]::ToUInt32($check1Bytes, 0) -ne [System.BitConverter]::ToUInt32($check2Bytes, 0)) {
        throw "'$KeyPath' failed an internal consistency check while parsing - the file may be corrupt."
    }
    $po = 8

    $keytype = [System.Text.Encoding]::ASCII.GetString((Read-SshString $privSection ([ref]$po)))

    switch -Regex ($keytype) {
        '^ssh-rsa$' {
            [void](Read-SshString $privSection ([ref]$po))  # n - already present in $publicBlobBytes, not needed again
            [void](Read-SshString $privSection ([ref]$po))  # e - ditto
            $d = Read-SshString $privSection ([ref]$po)
            $iqmp = Read-SshString $privSection ([ref]$po)
            $p = Read-SshString $privSection ([ref]$po)
            $q = Read-SshString $privSection ([ref]$po)
            # PPK's own field order for RSA is d, p, q, iqmp - NOT OpenSSH's n,e,d,iqmp,p,q order.
            $privateBlobBytes = (Write-SshString $d) + (Write-SshString $p) + (Write-SshString $q) + (Write-SshString $iqmp)
        }
        '^ssh-ed25519$' {
            [void](Read-SshString $privSection ([ref]$po))  # pubkey - already present in $publicBlobBytes, not needed again
            $privkey = Read-SshString $privSection ([ref]$po)  # 64 bytes: 32-byte seed + 32-byte pubkey, concatenated
            $seed = $privkey[0..31]
            $privateBlobBytes = Write-SshString $seed
        }
        '^ecdsa-sha2-nistp(256|384|521)$' {
            [void](Read-SshString $privSection ([ref]$po))  # curve-name - already implied by $keytype/$publicBlobBytes
            [void](Read-SshString $privSection ([ref]$po))  # Q (public point) - already present in $publicBlobBytes
            $d = Read-SshString $privSection ([ref]$po)
            $privateBlobBytes = Write-SshString $d
        }
        default {
            throw "'$KeyPath' is a '$keytype' key - only RSA (ssh-rsa), Ed25519 (ssh-ed25519), and ECDSA (ecdsa-sha2-nistp256/384/521) keys are supported for key-based push."
        }
    }

    $comment = [System.Text.Encoding]::UTF8.GetString((Read-SshString $privSection ([ref]$po)))

    function ToBase64Lines {
        param([byte[]]$Bytes, [int]$Width = 64)
        $b64 = [Convert]::ToBase64String($Bytes)
        $lines = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $b64.Length; $i += $Width) {
            $lines.Add($b64.Substring($i, [Math]::Min($Width, $b64.Length - $i)))
        }
        return ,$lines
    }

    $macKey = [System.Security.Cryptography.SHA1]::Create().ComputeHash([System.Text.Encoding]::ASCII.GetBytes("putty-private-key-file-mac-key"))
    $mac = New-Object System.Security.Cryptography.HMACSHA1
    $mac.Key = $macKey
    $macData = (Write-SshString ([System.Text.Encoding]::ASCII.GetBytes($keytype))) `
        + (Write-SshString ([System.Text.Encoding]::ASCII.GetBytes("none"))) `
        + (Write-SshString ([System.Text.Encoding]::UTF8.GetBytes($comment))) `
        + (Write-SshString $publicBlobBytes) `
        + (Write-SshString $privateBlobBytes)
    $macHex = ($mac.ComputeHash($macData) | ForEach-Object { $_.ToString("x2") }) -join ''

    $pubLines = ToBase64Lines $publicBlobBytes
    $privLines = ToBase64Lines $privateBlobBytes

    $out = New-Object System.Text.StringBuilder
    [void]$out.AppendLine("PuTTY-User-Key-File-2: $keytype")
    [void]$out.AppendLine("Encryption: none")
    [void]$out.AppendLine("Comment: $comment")
    [void]$out.AppendLine("Public-Lines: $($pubLines.Count)")
    foreach ($l in $pubLines) { [void]$out.AppendLine($l) }
    [void]$out.AppendLine("Private-Lines: $($privLines.Count)")
    foreach ($l in $privLines) { [void]$out.AppendLine($l) }
    [void]$out.AppendLine("Private-MAC: $macHex")

    [System.IO.File]::WriteAllText($OutputPath, $out.ToString(), (New-Object System.Text.ASCIIEncoding))
}

function Clear-TempPasswordFile {
    [CmdletBinding()]
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {
        $length = (Get-Item -LiteralPath $Path).Length
        if ($length -gt 0) {
            [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] $length))
        }
    }
    catch {
        Write-Warning ("Could not overwrite the temporary credential file '{0}': {1}" -f $Path, $_.Exception.Message)
    }

    try {
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    catch {
        Write-Warning ("Could not delete the temporary credential file '{0}' - its contents were overwritten, but delete it manually: {1}" -f $Path, $_.Exception.Message)
    }
}

# Uses the INSTALLER's own version - it correctly distinguishes "host key
# CHANGED since last trusted" (only possible when -ExpectedHostKey was
# supplied, i.e. a record already existed) from "host key not yet
# trusted at all." The uninstaller's own prior copy collapsed both cases
# into the second, wrong message - telling an admin to just accept a key
# that may indicate a reimaged host or an active interception. That
# drift is the concrete bug this task fixes, not preserves.
function Invoke-PlinkWithAuth {
    param(
        [string]$ExePath,
        [string[]]$Arguments,
        [string]$ExpectedHostKey,
        [string]$PlainPassword,
        [string]$ConvertedKeyPath
    )

    if ([string]::IsNullOrEmpty($ConvertedKeyPath) -and [string]::IsNullOrEmpty($PlainPassword)) {
        throw "Invoke-PlinkWithAuth requires either -PlainPassword or -ConvertedKeyPath."
    }
    if (-not [string]::IsNullOrEmpty($ConvertedKeyPath) -and -not [string]::IsNullOrEmpty($PlainPassword)) {
        throw "Invoke-PlinkWithAuth requires exactly one of -PlainPassword or -ConvertedKeyPath, not both."
    }

    $pwFile = $null
    try {
        $authArgs = @()
        if ($ConvertedKeyPath) {
            $authArgs = @('-i', $ConvertedKeyPath)
        }
        else {
            $pwFile = [System.IO.Path]::GetTempFileName()
            $acl = Get-Acl -Path $pwFile
            $acl.SetAccessRuleProtection($true, $false)
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentUser, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -Path $pwFile -AclObject $acl

            [System.IO.File]::WriteAllText($pwFile, $PlainPassword, (New-Object System.Text.UTF8Encoding($false)))
            $authArgs = @('-pwfile', $pwFile)
        }

        $fullArgs = $authArgs + @('-batch')
        if ($ExpectedHostKey) {
            $fullArgs += @('-hostkey', $ExpectedHostKey)
        }
        $fullArgs += $Arguments
        $global:LASTEXITCODE = 0
        $output = Invoke-NativeAllowingStderr { & $ExePath @fullArgs 2>&1 }

        if ($LASTEXITCODE -ne 0) {
            $joined = $output -join "`n"
            if ($joined -match '(?i)host key') {
                if ($ExpectedHostKey) {
                    throw ("plink/pscp failed (exit {0}): the target's SSH host key has CHANGED since it was last trusted here. This can mean the server was reinstalled or reimaged, or that something is intercepting the connection - only proceed if you can confirm this change is expected. Trust the new key from the Linux Client actions job log to update the stored fingerprint. Raw output: {1}" -f $LASTEXITCODE, $joined)
                }
                throw ("plink/pscp failed (exit {0}): the target's SSH host key is not yet trusted by this machine (PuTTY caches trusted keys separately from Windows' own OpenSSH known_hosts). -batch refuses to prompt for an unknown host key rather than risk silently trusting the wrong one. Trust this host key from the Linux Client actions job log, or connect once interactively instead. Raw output: {1}" -f $LASTEXITCODE, $joined)
            }
            throw ("plink/pscp failed (exit {0}): {1}" -f $LASTEXITCODE, $joined)
        }

        return $output
    }
    finally {
        if ($pwFile) {
            Clear-TempPasswordFile -Path $pwFile
        }
    }
}

function Invoke-RemoteCommand {
    param([string]$TargetComputer, [string]$Command, [string]$ExpectedHostKey)

    if ($script:usingPassword) {
        $plainPassword = ConvertTo-PlainText -Secure $script:CredentialPassword
        try {
            $output = Invoke-PlinkWithAuth -ExePath $script:plinkPath -Arguments @('-ssh', "$script:CredentialUsername@$TargetComputer", $Command) -PlainPassword $plainPassword -ExpectedHostKey $ExpectedHostKey
        }
        finally {
            $plainPassword = $null
        }
    }
    else {
        $output = Invoke-PlinkWithAuth -ExePath $script:plinkPath -Arguments @('-ssh', "$script:CredentialUsername@$TargetComputer", $Command) -ConvertedKeyPath $script:ConvertedKeyPath -ExpectedHostKey $ExpectedHostKey
    }

    return $output
}
