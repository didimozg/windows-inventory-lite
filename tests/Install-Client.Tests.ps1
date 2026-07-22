$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install-Client client-data layout' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-Client.ps1'
        . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
    }

    It 'Get-ClientServiceCommand embeds --output and --debug-log-path' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharePath '' -SharedToken '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $command | Should -Match '--output "C:\\ProgramData\\WindowsInventoryLite\\client-data"'
        $command | Should -Match '--debug-log-path "C:\\ProgramData\\WindowsInventoryLite\\client-data\\_logs\\debug-client\.log"'
    }

    It 'Get-ClientServiceCommand still includes --share and --token when provided' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharePath '\\server\drop' -SharedToken 'abc123' -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Match '--share "\\\\server\\drop"'
        $command | Should -Match '--token "abc123"'
    }

    It 'Remove-LegacyClientFiles deletes the old bare-root exe and client-version.txt when the new path differs' {
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

    It 'Remove-LegacyClientFiles is a no-op when the new service path IS the legacy path' {
        $legacyRoot = Join-Path -Path $TestDrive -ChildPath 'legacy2'
        New-Item -Path $legacyRoot -ItemType Directory -Force | Out-Null
        $legacyExe = Join-Path -Path $legacyRoot -ChildPath 'WindowsInventoryLiteClient.exe'
        Set-Content -LiteralPath $legacyExe -Value 'stub'

        Remove-LegacyClientFiles -LegacyRoot $legacyRoot -NewServicePath $legacyExe

        Test-Path -LiteralPath $legacyExe | Should -Be $true
    }
}
