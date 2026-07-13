$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite server self-tests' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ServerExePath = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLiteServer.exe'
        & (Join-Path -Path $script:ProjectRoot -ChildPath 'src\Build-Server.ps1') -OutputPath $script:ServerExePath
    }

    It 'passes the built-in request parsing, target expansion, and ZIP checks' {
        $output = & $script:ServerExePath --self-test 2>&1
        $exitCode = $LASTEXITCODE

        $output | ForEach-Object { Write-Host $_ }

        $failures = $output | Where-Object { $_ -match '^FAIL ' }
        $failures | Should -BeNullOrEmpty
        $exitCode | Should -Be 0
    }
}
