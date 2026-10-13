$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Build-Client' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Build-Client.ps1'
    }

    It 'rejects a -TargetFramework value outside Net35/Net40' {
        { & $script:ScriptPath -OutputPath (Join-Path -Path $TestDrive -ChildPath 'x.exe') -TargetFramework 'Net48' } | Should -Throw '*TargetFramework*'
    }

    It 'compiles a working Net40 client executable that passes its own self-test' {
        $compiler = Join-Path -Path $env:WINDIR -ChildPath 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
        if (-not (Test-Path -LiteralPath $compiler)) {
            Set-ItResult -Skipped -Because '.NET Framework 4.0 compiler not available in this environment'
            return
        }
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'wil-client-net40-test.exe'

        & $script:ScriptPath -OutputPath $outputPath -TargetFramework Net40

        Test-Path -LiteralPath $outputPath | Should -Be $true

        $selfTestOutput = & $outputPath --self-test
        $failLines = $selfTestOutput | Where-Object { $_ -match '^FAIL' }
        $failLines | Should -BeNullOrEmpty
        ($selfTestOutput | Where-Object { $_ -match '^PASS' }).Count | Should -BeGreaterThan 0
    }

    It 'compiles a working Net35 client executable that passes its own self-test' {
        $compiler = Join-Path -Path $env:WINDIR -ChildPath 'Microsoft.NET\Framework\v3.5\csc.exe'
        if (-not (Test-Path -LiteralPath $compiler)) {
            Set-ItResult -Skipped -Because '.NET Framework 3.5 compiler not available in this environment'
            return
        }
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'wil-client-net35-test.exe'

        & $script:ScriptPath -OutputPath $outputPath -TargetFramework Net35

        Test-Path -LiteralPath $outputPath | Should -Be $true

        $selfTestOutput = & $outputPath --self-test
        $failLines = $selfTestOutput | Where-Object { $_ -match '^FAIL' }
        $failLines | Should -BeNullOrEmpty
        ($selfTestOutput | Where-Object { $_ -match '^PASS' }).Count | Should -BeGreaterThan 0
    }
}
