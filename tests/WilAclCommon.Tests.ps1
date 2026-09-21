$ErrorActionPreference = 'Stop'

Describe 'WilAclCommon Set-RestrictedFileAcl' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        . (Join-Path -Path $script:ProjectRoot -ChildPath 'src\WilAclCommon.ps1')
    }

    It 'grants only Administrators+SYSTEM when -IncludeCurrentIdentity is not set' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'no-current-identity.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Set-RestrictedFileAcl -FilePath $testFile

        $acl = Get-Acl -Path $testFile
        $identities = $acl.Access | ForEach-Object { $_.IdentityReference.Value }
        $currentAccount = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
        $identities | Should -Not -Contain $currentAccount
    }

    It 'also grants the current identity when -IncludeCurrentIdentity is set' {
        $testFile = Join-Path -Path $TestDrive -ChildPath 'with-current-identity.txt'
        Set-Content -LiteralPath $testFile -Value 'test'
        Set-RestrictedFileAcl -FilePath $testFile -IncludeCurrentIdentity

        $acl = Get-Acl -Path $testFile
        $identities = $acl.Access | ForEach-Object { $_.IdentityReference.Value }
        $currentAccount = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
        $identities | Should -Contain $currentAccount
    }
}
