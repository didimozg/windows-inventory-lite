$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Uninstall-Server safety guard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Uninstall-Server.ps1'
        # -WhatIf suppresses every ShouldProcess-gated action (service stop/
        # delete, firewall rule removal, and both Remove-Item -Recurse calls,
        # which is also where Test-IsPathSafeToRemove is invoked) - safe to
        # dot-source with no real side effects, same technique already used
        # by tests/Uninstall-Client.Tests.ps1 for the identical reason.
        . $script:ScriptPath -WhatIf
    }

    It 'Test-IsPathSafeToRemove refuses a bare drive root' {
        foreach ($path in @('C:\', 'D:\')) {
            { Test-IsPathSafeToRemove -Path $path } | Should -Throw '*bare drive root*'
        }
    }

    It 'Test-IsPathSafeToRemove refuses well-known Windows system directories' {
        $systemPaths = @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ }
        foreach ($path in $systemPaths) {
            { Test-IsPathSafeToRemove -Path $path } | Should -Throw '*well-known Windows system directory*'
        }
    }

    It 'Test-IsPathSafeToRemove allows the real default install-path subdirectories' {
        $defaults = @(
            (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-bin'),
            (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-data'),
            (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-content'),
            (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-package')
        )
        foreach ($path in $defaults) {
            { Test-IsPathSafeToRemove -Path $path } | Should -Not -Throw
        }
    }

    It 'Test-IsPathSafeToRemove allows a real custom install path elsewhere on disk' {
        { Test-IsPathSafeToRemove -Path 'D:\WilServer\install' } | Should -Not -Throw
    }
}
