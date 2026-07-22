$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Uninstall-ClientWinRM safety guard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Uninstall-ClientWinRM.ps1'
        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test'
    }

    It 'skips removal when the target path is the shared server root with server-config.json present' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'
        $leftoverFile = Join-Path -Path $sharedRoot -ChildPath 'leftover.txt'
        Set-Content -LiteralPath $leftoverFile -Value 'stub'

        $originalProgramData = $env:ProgramData
        $env:ProgramData = $TestDrive
        try {
            & $script:RemoveClientScriptBlock -ServiceName 'NoSuchServiceForThisTest' -ClientInstallPath $sharedRoot | Out-Null
        }
        finally {
            $env:ProgramData = $originalProgramData
        }

        Test-Path -LiteralPath $sharedRoot | Should -Be $true
        Test-Path -LiteralPath $leftoverFile | Should -Be $true
    }

    It 'removes the target path when it is not the shared server root' {
        $clientOnlyRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite2\client-data'
        New-Item -Path $clientOnlyRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $clientOnlyRoot -ChildPath 'leftover.txt') -Value 'stub'

        & $script:RemoveClientScriptBlock -ServiceName 'NoSuchServiceForThisTest' -ClientInstallPath $clientOnlyRoot | Out-Null

        Test-Path -LiteralPath $clientOnlyRoot | Should -Be $false
    }
}
