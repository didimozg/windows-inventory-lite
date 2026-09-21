#requires -Version 2.0

# Shared by Install-Server.ps1 and New-ClientGpoPackage.ps1 - both run on
# the server host. Two call sites need genuinely different behavior for
# good reason (see -IncludeCurrentIdentity below), which is why this was
# previously two same-named functions with silently different bodies
# instead of one function with an explicit parameter for the difference.

function Set-RestrictedFileAcl {
    param(
        [string]$FilePath,

        # server-config.json (Install-Server.ps1) needs only
        # Administrators+SYSTEM - the server process itself runs as one of
        # those. Install-ClientGpo.cmd (New-ClientGpoPackage.ps1) also
        # grants the CURRENT identity, because the admin who just
        # generated the GPO package needs continued read access to
        # inspect or move the file they just created, without needing to
        # already be a member of Administrators.
        [switch]$IncludeCurrentIdentity
    )
    # Use well-known SIDs, not literal account names: 'Administrators'/'SYSTEM'
    # only resolve on English-locale Windows. The builtin groups have a
    # localized display name on non-English installs, which throws
    # IdentityNotMappedException from AddAccessRule with a literal string.
    $adminSid  = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
    # -Path, not -LiteralPath: this module requires only PS 2.0, and
    # Get-Acl/Set-Acl only gained -LiteralPath in PS 3.0. $FilePath is
    # always a script-built path, never wildcard-shaped, so -Path's
    # wildcard expansion is a safe substitute here.
    $acl = Get-Acl -Path $FilePath
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule($adminSid, 'FullControl', 'Allow')
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule($systemSid, 'FullControl', 'Allow')
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    if ($IncludeCurrentIdentity) {
        $currentSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User
        if ($currentSid -and $currentSid -ne $adminSid -and $currentSid -ne $systemSid) {
            $currentRule = New-Object System.Security.AccessControl.FileSystemAccessRule($currentSid, 'FullControl', 'Allow')
            $acl.AddAccessRule($currentRule)
        }
    }
    Set-Acl -Path $FilePath -AclObject $acl
}
