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
