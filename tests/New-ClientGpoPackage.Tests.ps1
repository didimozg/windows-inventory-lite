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
}
