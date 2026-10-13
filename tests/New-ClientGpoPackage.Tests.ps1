$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite New-ClientGpoPackage batch-injection guard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\New-ClientGpoPackage.ps1'
    }

    It 'rejects a ServerUrl containing a batch command separator before touching any client executable' {
        { & $script:ScriptPath -ServerUrl 'http://x & calc.exe & rem' -OutputPath (Join-Path -Path $TestDrive -ChildPath 'pkg1') -ClientNet35Path 'C:\does-not-exist-35.exe' -ClientNet40Path 'C:\does-not-exist-40.exe' } | Should -Throw '*ServerUrl*'
    }

    It 'rejects a Token containing an embedded double quote' {
        { & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -Token 'x" & calc.exe & rem "' -OutputPath (Join-Path -Path $TestDrive -ChildPath 'pkg2') -ClientNet35Path 'C:\does-not-exist-35.exe' -ClientNet40Path 'C:\does-not-exist-40.exe' } | Should -Throw '*Token*'
    }

    It 'rejects a PackageSharePath containing a line break' {
        { & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -PackageSharePath "\\share`nmalicious" -OutputPath (Join-Path -Path $TestDrive -ChildPath 'pkg3') -ClientNet35Path 'C:\does-not-exist-35.exe' -ClientNet40Path 'C:\does-not-exist-40.exe' } | Should -Throw '*PackageSharePath*'
    }

    It 'rejects an EnrollmentToken containing an embedded double quote' {
        { & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -EnrollmentToken 'x" & calc.exe & rem "' -OutputPath (Join-Path -Path $TestDrive -ChildPath 'pkg4') -ClientNet35Path 'C:\does-not-exist-35.exe' -ClientNet40Path 'C:\does-not-exist-40.exe' } | Should -Throw '*EnrollmentToken*'
    }
}

Describe 'Windows Inventory Lite New-ClientGpoPackage generated .cmd content' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\New-ClientGpoPackage.ps1'
        # Copy-Item just needs real files to copy - they are never executed by
        # this script, so a stub is enough to exercise the full generation
        # path (including the Install-ClientGpo.cmd write) without a real
        # client build.
        $script:FakeClientNet35Path = Join-Path -Path $TestDrive -ChildPath 'fake-net35.exe'
        $script:FakeClientNet40Path = Join-Path -Path $TestDrive -ChildPath 'fake-net40.exe'
        Set-Content -LiteralPath $script:FakeClientNet35Path -Value 'stub'
        Set-Content -LiteralPath $script:FakeClientNet40Path -Value 'stub'
    }

    # New-ClientGpoPackage.ps1 had no way to override the software-
    # distribution poll interval at all - every GPO package it built
    # silently used Deploy-ClientGpo.ps1's own default (6) regardless of
    # what an admin configured, unlike the WinRM push path
    # (Install-ClientWinRM.ps1), which already exposed
    # -SoftwareCheckIntervalHours.
    It 'threads -SoftwareCheckIntervalHours into the generated .cmd ARGS line' {
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'pkg-swci'
        & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -SoftwareCheckIntervalHours 3 -OutputPath $outputPath -ClientNet35Path $script:FakeClientNet35Path -ClientNet40Path $script:FakeClientNet40Path

        $cmdContent = Get-Content -LiteralPath (Join-Path -Path $outputPath -ChildPath 'Install-ClientGpo.cmd') -Raw
        $cmdContent | Should -Match 'set SOFTWARE_CHECK_INTERVAL_HOURS=3'
        $cmdContent | Should -Match '-SoftwareCheckIntervalHours %SOFTWARE_CHECK_INTERVAL_HOURS%'
    }

    It 'defaults -SoftwareCheckIntervalHours to 6 when not supplied' {
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'pkg-swci-default'
        & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -OutputPath $outputPath -ClientNet35Path $script:FakeClientNet35Path -ClientNet40Path $script:FakeClientNet40Path

        $cmdContent = Get-Content -LiteralPath (Join-Path -Path $outputPath -ChildPath 'Install-ClientGpo.cmd') -Raw
        $cmdContent | Should -Match 'set SOFTWARE_CHECK_INTERVAL_HOURS=6'
    }

    # Install-ClientGpo.cmd embeds the ingestion token in plaintext
    # (-Token "...") when one is configured, same as the server's own
    # equivalent generator (WindowsInventoryLiteServer.cs's GenerateCmdLines),
    # which already gets ApplyRestrictedConfigAcl. This script's own output
    # had no ACL restriction at all until this fix.
    It 'restricts the generated .cmd to the current identity plus Administrators/SYSTEM' {
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'pkg-acl'
        & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -Token 'real-secret-token' -OutputPath $outputPath -ClientNet35Path $script:FakeClientNet35Path -ClientNet40Path $script:FakeClientNet40Path

        $cmdPath = Join-Path -Path $outputPath -ChildPath 'Install-ClientGpo.cmd'
        $acl = Get-Acl -LiteralPath $cmdPath
        $acl.AreAccessRulesProtected | Should -BeTrue
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $sids = $acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
        $sids | Should -Contain $currentUser
    }

    # -EnrollmentToken (0.95.0) replaces -Token for a real GPO rollout - see
    # docs/threat-model.md. Embedded the same way -Token already is, as its
    # own -EnrollmentToken "..." fragment on the ARGS line.
    It 'embeds -EnrollmentToken in the generated .cmd ARGS line when supplied' {
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'pkg-enroll'
        & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -EnrollmentToken 'bootstrap-secret' -OutputPath $outputPath -ClientNet35Path $script:FakeClientNet35Path -ClientNet40Path $script:FakeClientNet40Path

        $cmdContent = Get-Content -LiteralPath (Join-Path -Path $outputPath -ChildPath 'Install-ClientGpo.cmd') -Raw
        $cmdContent | Should -Match '-EnrollmentToken "bootstrap-secret"'
    }

    It 'omits -EnrollmentToken from the generated .cmd ARGS line when not supplied' {
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'pkg-no-enroll'
        & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -OutputPath $outputPath -ClientNet35Path $script:FakeClientNet35Path -ClientNet40Path $script:FakeClientNet40Path

        $cmdContent = Get-Content -LiteralPath (Join-Path -Path $outputPath -ChildPath 'Install-ClientGpo.cmd') -Raw
        $cmdContent | Should -Not -Match '-EnrollmentToken'
    }

    # Still technically supported (a deliberate admin choice), but a client
    # starting with a real -Token never calls POST /api/v1/client/enroll
    # (TryEnrollIfNeededCore returns immediately once Token is non-empty), so
    # -EnrollmentToken has no effect whenever -Token is also embedded - this
    # must be loudly warned about, not silently accepted.
    It 'can embed both -Token and -EnrollmentToken together when both are supplied, but warns that EnrollmentToken will have no effect' {
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'pkg-both-tokens'
        $warnings = & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -Token 'real-secret-token' -EnrollmentToken 'bootstrap-secret' -OutputPath $outputPath -ClientNet35Path $script:FakeClientNet35Path -ClientNet40Path $script:FakeClientNet40Path 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }

        $cmdContent = Get-Content -LiteralPath (Join-Path -Path $outputPath -ChildPath 'Install-ClientGpo.cmd') -Raw
        $cmdContent | Should -Match '-Token "real-secret-token"'
        $cmdContent | Should -Match '-EnrollmentToken "bootstrap-secret"'
        $warnings | Should -Not -BeNullOrEmpty
        # Using the WarningRecord's own .Message, not `Out-String` - that
        # pipes through PowerShell's console formatter, which wraps long
        # warning text to the host width and can split a word (e.g. "never")
        # across the inserted line break, breaking a -Match on it.
        ($warnings | ForEach-Object { $_.Message }) -join ' ' | Should -Match 'never call POST /api/v1/client/enroll'
    }

    It 'does not warn when only -EnrollmentToken is supplied' {
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'pkg-enroll-only-no-warn'
        $warnings = & $script:ScriptPath -ServerUrl 'https://server/api/v1/inventory' -EnrollmentToken 'bootstrap-secret' -OutputPath $outputPath -ClientNet35Path $script:FakeClientNet35Path -ClientNet40Path $script:FakeClientNet40Path 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }
        $warnings | Should -BeNullOrEmpty
    }
}
