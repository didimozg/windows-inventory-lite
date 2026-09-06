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

    It 'RemoteDeployScriptBlock includes -SoftwareCheckIntervalHours in the constructed argument list' {
        # RemoteDeployScriptBlock has to stay fully self-contained (it runs
        # on the REMOTE machine via Invoke-Command -Session, so it cannot
        # call back into a local helper the way Get-ClientServiceCommand's
        # equivalent test in Install-Client.Tests.ps1 does) - the only way to
        # observe the argument list it builds is to intercept its own
        # `& powershell.exe @arguments` call. A function named `powershell.exe`
        # in the function: drive resolves before the real external exe would.
        try {
            New-Item -Path 'function:powershell.exe' -Value { $script:capturedArguments = $args; $global:LASTEXITCODE = 0 } -Force | Out-Null
            & $script:RemoteDeployScriptBlock -DeployPath 'C:\deploy\Install-Client.ps1' -ClientPath 'C:\deploy\client.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SoftwareHours 3 -SharedToken '' -ForceInstall $false
        }
        finally {
            Remove-Item -Path 'function:powershell.exe' -ErrorAction SilentlyContinue
        }

        $script:capturedArguments | Should -Contain '-SoftwareCheckIntervalHours'
        $index = [array]::IndexOf($script:capturedArguments, '-SoftwareCheckIntervalHours')
        $script:capturedArguments[$index + 1] | Should -Be '3'
    }

    It 'RemoteDeployScriptBlock defaults -SoftwareCheckIntervalHours to 6 when not supplied' {
        try {
            New-Item -Path 'function:powershell.exe' -Value { $script:capturedArguments = $args; $global:LASTEXITCODE = 0 } -Force | Out-Null
            & $script:RemoteDeployScriptBlock -DeployPath 'C:\deploy\Install-Client.ps1' -ClientPath 'C:\deploy\client.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SoftwareHours 6 -SharedToken '' -ForceInstall $false
        }
        finally {
            Remove-Item -Path 'function:powershell.exe' -ErrorAction SilentlyContinue
        }

        $index = [array]::IndexOf($script:capturedArguments, '-SoftwareCheckIntervalHours')
        $script:capturedArguments[$index + 1] | Should -Be '6'
    }
}
