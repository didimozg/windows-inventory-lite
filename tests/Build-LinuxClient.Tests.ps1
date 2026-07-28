$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Build-LinuxClient version sidecar' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Build-LinuxClient.ps1'
    }

    It 'writes a .version sidecar file next to the binary, matching -Version exactly' {
        if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because 'Go toolchain not available in this environment'
            return
        }
        $outputPath = Join-Path -Path $TestDrive -ChildPath 'wil-linux-client'
        & $script:ScriptPath -Version '9.9.9-test' -OutputPath $outputPath

        $versionPath = "$outputPath.version"
        Test-Path -LiteralPath $versionPath | Should -Be $true
        (Get-Content -LiteralPath $versionPath -Raw) | Should -Be '9.9.9-test'
    }
}
