$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Build-Server' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Build-Server.ps1'
    }

    It 'compiles a working server executable that passes its own self-test, and refreshes both client executables alongside it' {
        $compiler = Join-Path -Path $env:WINDIR -ChildPath 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
        if (-not (Test-Path -LiteralPath $compiler)) {
            Set-ItResult -Skipped -Because '.NET Framework 4.0 compiler not available in this environment'
            return
        }
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'wil-server-test.exe'

        # Build-Server.ps1 always rebuilds build\WindowsInventoryLiteClient-net35/40.exe
        # alongside the server (see its own comment: keeps them in sync with
        # New-ClientGpoPackage.ps1's defaults) - that path is not parameterized,
        # so this real build legitimately refreshes those two real project
        # artifacts from current source, the same side effect a developer's
        # own manual build has. Record their timestamp before, to confirm
        # the refresh actually happened.
        $clientNet35Path = Join-Path -Path $script:ProjectRoot -ChildPath 'build\WindowsInventoryLiteClient-net35.exe'
        $clientNet40Path = Join-Path -Path $script:ProjectRoot -ChildPath 'build\WindowsInventoryLiteClient-net40.exe'
        $beforeTime = Get-Date

        & $script:ScriptPath -OutputPath $outputPath

        Test-Path -LiteralPath $outputPath | Should -Be $true

        $selfTestOutput = & $outputPath --self-test
        $failLines = $selfTestOutput | Where-Object { $_ -match '^FAIL' }
        $failLines | Should -BeNullOrEmpty
        ($selfTestOutput | Where-Object { $_ -match '^PASS' }).Count | Should -BeGreaterThan 0

        Test-Path -LiteralPath $clientNet35Path | Should -Be $true
        Test-Path -LiteralPath $clientNet40Path | Should -Be $true
        (Get-Item -LiteralPath $clientNet35Path).LastWriteTime | Should -BeGreaterThan $beforeTime
        (Get-Item -LiteralPath $clientNet40Path).LastWriteTime | Should -BeGreaterThan $beforeTime
    }
}
