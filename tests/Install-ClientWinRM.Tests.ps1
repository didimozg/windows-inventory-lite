$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install-ClientWinRM safety guard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-ClientWinRM.ps1'

        # Install-ClientWinRM.ps1 validates that its package files exist before
        # any function is defined, unconditionally (that check is not part of
        # the dot-source guard) - so dot-sourcing it for testing needs a real
        # (stub) package directory to point -PackagePath at.
        $script:StubPackagePath = Join-Path -Path $TestDrive -ChildPath 'stub-package'
        New-Item -Path $script:StubPackagePath -ItemType Directory -Force | Out-Null
        foreach ($fileName in @('Deploy-ClientGpo.ps1', 'WindowsInventoryLiteClient-net35.exe', 'WindowsInventoryLiteClient-net40.exe')) {
            Set-Content -LiteralPath (Join-Path -Path $script:StubPackagePath -ChildPath $fileName) -Value 'stub'
        }

        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test' -ServerUrl 'https://example.local/api/v1/inventory' -PackagePath $script:StubPackagePath
    }

    It 'RemoveRemotePackageScriptBlock refuses to delete a path outside the WindowsInventoryLite root' {
        $dangerousPaths = @('C:\', 'C:\Windows', 'C:\Users', 'C:\ProgramData', (Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite'))
        foreach ($path in $dangerousPaths) {
            { & $script:RemoveRemotePackageScriptBlock -Path $path } | Should -Throw '*is not a real subdirectory of*'
        }
    }

    It 'refuses to delete a .. traversal path that resolves outside the WindowsInventoryLite root' {
        $traversalPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\..\..\Windows'
        { & $script:RemoveRemotePackageScriptBlock -Path $traversalPath } | Should -Throw '*is not a real subdirectory of*'
    }

    It 'removes the default WinRMDeploy path, a real subdirectory of the allowed root rather than the root itself' {
        $originalProgramData = $env:ProgramData
        $env:ProgramData = $TestDrive
        try {
            $deployPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\WinRMDeploy'
            New-Item -Path $deployPath -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath (Join-Path -Path $deployPath -ChildPath 'leftover.txt') -Value 'stub'

            & $script:RemoveRemotePackageScriptBlock -Path $deployPath | Out-Null
        }
        finally {
            $env:ProgramData = $originalProgramData
        }

        Test-Path -LiteralPath $deployPath | Should -Be $false
    }

    It 'is a no-op when the path does not exist, after passing the allowlist check' {
        $originalProgramData = $env:ProgramData
        $env:ProgramData = $TestDrive
        try {
            $missingPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\WinRMDeploy'
            { & $script:RemoveRemotePackageScriptBlock -Path $missingPath } | Should -Not -Throw
        }
        finally {
            $env:ProgramData = $originalProgramData
        }
    }
}
