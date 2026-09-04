$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Uninstall-Client safety guard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Uninstall-Client.ps1'
        . $script:ScriptPath -InstallPath (Join-Path -Path $TestDrive -ChildPath 'unused') -WhatIf
    }

    It 'returns true when the path matches the shared root and server-config.json is present' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'

        Test-IsSharedServerRoot -Path $sharedRoot -SharedRoot $sharedRoot | Should -Be $true
    }

    It 'returns false when server-config.json is absent (client-only machine)' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite2'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null

        Test-IsSharedServerRoot -Path $sharedRoot -SharedRoot $sharedRoot | Should -Be $false
    }

    It 'returns false when the path is the new client-data subfolder, not the shared root itself' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite3'
        $clientData = Join-Path -Path $sharedRoot -ChildPath 'client-data'
        New-Item -Path $clientData -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'

        Test-IsSharedServerRoot -Path $clientData -SharedRoot $sharedRoot | Should -Be $false
    }

    It 'is insensitive to a trailing backslash on the path being checked' {
        $sharedRoot = Join-Path -Path $TestDrive -ChildPath 'WindowsInventoryLite4'
        New-Item -Path $sharedRoot -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $sharedRoot -ChildPath 'server-config.json') -Value '{}'

        Test-IsSharedServerRoot -Path ($sharedRoot + '\') -SharedRoot $sharedRoot | Should -Be $true
    }

    It 'Test-IsUnderAllowedInstallRoot refuses a path outside the WindowsInventoryLite root' {
        $dangerousPaths = @('C:\', 'C:\Windows', 'C:\Users', 'C:\ProgramData', (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'))
        foreach ($path in $dangerousPaths) {
            { Test-IsUnderAllowedInstallRoot -Path $path } | Should -Throw '*is not a real subdirectory of*'
        }
    }

    It 'Test-IsUnderAllowedInstallRoot allows the default client-data path, a real subdirectory of the allowed root' {
        $originalProgramData = $env:ProgramData
        $env:ProgramData = $TestDrive
        try {
            $defaultPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-data'
            { Test-IsUnderAllowedInstallRoot -Path $defaultPath } | Should -Not -Throw
        }
        finally {
            $env:ProgramData = $originalProgramData
        }
    }
}
