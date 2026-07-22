$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Deploy-ClientGpo client-data layout' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'deploy\client\Deploy-ClientGpo.ps1'
        . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
    }

    It 'Get-DesiredServiceCommand embeds --output and --debug-log-path' {
        $command = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharedToken '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $command | Should -Match '--output "C:\\ProgramData\\WindowsInventoryLite\\client-data"'
        $command | Should -Match '--debug-log-path "C:\\ProgramData\\WindowsInventoryLite\\client-data\\_logs\\debug-client\.log"'
    }

    It 'Get-DesiredServiceCommand differs between the legacy bare-root path and the new client-data path, so an already-installed client is detected as needing reinstall' {
        $legacyCommand = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharedToken '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\_logs\debug-client.log'
        $newCommand = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharedToken '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $legacyCommand | Should -Not -Be $newCommand
    }

    It 'Remove-LegacyClientFiles deletes the old bare-root exe and client-version.txt when the new path differs' {
        $script:LogPath = Join-Path -Path $TestDrive -ChildPath 'test-deploy.log'
        $legacyRoot = Join-Path -Path $TestDrive -ChildPath 'legacy'
        New-Item -Path $legacyRoot -ItemType Directory -Force | Out-Null
        $legacyExe = Join-Path -Path $legacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
        $legacyVersion = Join-Path -Path $legacyRoot -ChildPath 'client-version.txt'
        Set-Content -LiteralPath $legacyExe -Value 'stub'
        Set-Content -LiteralPath $legacyVersion -Value '0.21.3'

        Remove-LegacyClientFiles -LegacyRoot $legacyRoot -NewServicePath (Join-Path -Path $TestDrive -ChildPath 'client-data\WindowsInventoryLiteClient.exe')

        Test-Path -LiteralPath $legacyExe | Should -Be $false
        Test-Path -LiteralPath $legacyVersion | Should -Be $false
    }

    It 'Remove-LegacyClientFiles is a no-op when the new service path IS the legacy path (no migration needed)' {
        $script:LogPath = Join-Path -Path $TestDrive -ChildPath 'test-deploy2.log'
        $legacyRoot = Join-Path -Path $TestDrive -ChildPath 'legacy2'
        New-Item -Path $legacyRoot -ItemType Directory -Force | Out-Null
        $legacyExe = Join-Path -Path $legacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
        Set-Content -LiteralPath $legacyExe -Value 'stub'

        Remove-LegacyClientFiles -LegacyRoot $legacyRoot -NewServicePath $legacyExe

        Test-Path -LiteralPath $legacyExe | Should -Be $true
    }

    It 'Remove-LegacyClientFiles does not delete client-version.txt when LegacyRoot and new path directory are the same' {
        $script:LogPath = Join-Path -Path $TestDrive -ChildPath 'test-deploy3.log'
        $bareRoot = Join-Path -Path $TestDrive -ChildPath 'bare-root'
        New-Item -Path $bareRoot -ItemType Directory -Force | Out-Null
        $versionFile = Join-Path -Path $bareRoot -ChildPath 'client-version.txt'
        Set-Content -LiteralPath $versionFile -Value '0.21.3'

        # Simulate operator passing -InstallPath back to the legacy bare root
        $newServicePath = Join-Path -Path $bareRoot -ChildPath 'WindowsInventoryLiteClient.exe'

        Remove-LegacyClientFiles -LegacyRoot $bareRoot -NewServicePath $newServicePath

        # The version file should NOT have been deleted since the new path is also in the same bare root
        Test-Path -LiteralPath $versionFile | Should -Be $true
    }
}
