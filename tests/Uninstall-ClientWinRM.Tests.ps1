$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Uninstall-ClientWinRM safety guard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Uninstall-ClientWinRM.ps1'
        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test'
    }

    It 'refuses to delete the bare shared root even when server-config.json is present (the path-allowlist guard now rejects it before the co-located-server check is ever reached)' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'
        $leftoverFile = Join-Path -Path $sharedRoot -ChildPath 'leftover.txt'
        Set-Content -LiteralPath $leftoverFile -Value 'stub'

        $originalProgramData = $env:ProgramData
        $env:ProgramData = $TestDrive
        try {
            { & $script:RemoveClientScriptBlock -ServiceName 'NoSuchServiceForThisTest' -ClientInstallPath $sharedRoot } | Should -Throw '*is not a real subdirectory of*'
        }
        finally {
            $env:ProgramData = $originalProgramData
        }

        Test-Path -LiteralPath $sharedRoot | Should -Be $true
        Test-Path -LiteralPath $leftoverFile | Should -Be $true
    }

    It 'removes the default client-data path, a real subdirectory of the allowed root rather than the root itself' {
        $originalProgramData = $env:ProgramData
        $env:ProgramData = $TestDrive
        try {
            $clientOnlyRoot = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-data'
            New-Item -Path $clientOnlyRoot -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath (Join-Path -Path $clientOnlyRoot -ChildPath 'leftover.txt') -Value 'stub'

            & $script:RemoveClientScriptBlock -ServiceName 'NoSuchServiceForThisTest' -ClientInstallPath $clientOnlyRoot | Out-Null
        }
        finally {
            $env:ProgramData = $originalProgramData
        }

        Test-Path -LiteralPath $clientOnlyRoot | Should -Be $false
    }

    It 'RemoveClientScriptBlock refuses to delete a path outside the WindowsInventoryLite root' {
        $dangerousPaths = @('C:\', 'C:\Windows', 'C:\Users', 'C:\ProgramData', (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'))
        foreach ($path in $dangerousPaths) {
            { & $script:RemoveClientScriptBlock -ServiceName 'nonexistent-service-for-test' -ClientInstallPath $path } | Should -Throw '*is not a real subdirectory of*'
        }
    }

    It 'refuses to delete a .. traversal path that resolves outside the WindowsInventoryLite root' {
        $traversalPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\..\..\Windows'
        { & $script:RemoveClientScriptBlock -ServiceName 'nonexistent-service-for-test' -ClientInstallPath $traversalPath } | Should -Throw '*is not a real subdirectory of*'
    }
}
