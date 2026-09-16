$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install-Client client-data layout' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-Client.ps1'
        . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
    }

    It 'rejects a shell-unsafe InstallPath' {
        { . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory' -InstallPath 'C:\wil&calc.exe' } | Should -Throw '*InstallPath*'
    }

    It 'accepts a safe InstallPath' {
        { . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory' -InstallPath 'C:\ProgramData\WindowsInventoryLite\client-data' } | Should -Not -Throw
    }

    It 'Get-ClientServiceCommand embeds --output and --debug-log-path' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharePath '' -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $command | Should -Match '--output "C:\\ProgramData\\WindowsInventoryLite\\client-data"'
        $command | Should -Match '--debug-log-path "C:\\ProgramData\\WindowsInventoryLite\\client-data\\_logs\\debug-client\.log"'
    }

    It 'Get-ClientServiceCommand emits --software-check-interval-hours alongside --interval-hours' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SoftwareHours 12 -SharePath '' -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Match '--interval-hours 6'
        $command | Should -Match '--software-check-interval-hours 12'
    }

    It 'Get-ClientServiceCommand defaults --software-check-interval-hours to 6 when not supplied' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharePath '' -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Match '--software-check-interval-hours 6'
    }

    It 'Get-ClientServiceCommand still includes --share when provided' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharePath '\\server\drop' -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Match '--share "\\\\server\\drop"'
    }

    It 'Get-ClientServiceCommand never embeds the ingestion token on the command line' {
        $command = Get-ClientServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SharePath '' -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Not -Match '--token'
    }

    It 'Set-ServiceEnvironmentToken writes WIL_INGESTION_TOKEN to the Environment value' {
        # TestRegistry: is a Pester-managed scratch registry key, torn down
        # automatically after this test - real HKLM\SYSTEM is never touched.
        $registryRoot = 'TestRegistry:\Services'
        $serviceName = 'FakeService1'
        New-Item -Path (Join-Path -Path $registryRoot -ChildPath $serviceName) -Force | Out-Null
        Set-ServiceEnvironmentToken -ServiceName $serviceName -SharedToken 'abc123' -ServiceRegistryRoot $registryRoot
        $environment = (Get-ItemProperty -LiteralPath (Join-Path -Path $registryRoot -ChildPath $serviceName) -Name 'Environment').Environment
        $environment | Should -Contain 'WIL_INGESTION_TOKEN=abc123'
    }

    It 'Set-ServiceEnvironmentToken removes the Environment value when the token is empty' {
        $registryRoot = 'TestRegistry:\Services'
        $serviceName = 'FakeService2'
        New-Item -Path (Join-Path -Path $registryRoot -ChildPath $serviceName) -Force | Out-Null
        Set-ServiceEnvironmentToken -ServiceName $serviceName -SharedToken 'abc123' -ServiceRegistryRoot $registryRoot
        Set-ServiceEnvironmentToken -ServiceName $serviceName -SharedToken '' -ServiceRegistryRoot $registryRoot
        # Not using Get-ItemProperty's -Name filter: asking it for a value
        # that no longer exists throws under this project's Set-StrictMode
        # -Version 2.0 + $ErrorActionPreference = 'Stop', ignoring
        # -ErrorAction SilentlyContinue (confirmed live) - see
        # Get-ServiceEnvironmentToken's comment in Deploy-ClientGpo.ps1.
        $item = Get-ItemProperty -LiteralPath (Join-Path -Path $registryRoot -ChildPath $serviceName) -ErrorAction SilentlyContinue
        $environment = $null
        if ($item -and $item.PSObject.Properties['Environment']) {
            $environment = $item.Environment
        }
        $environment | Should -BeNullOrEmpty
    }

    It 'Set-RestrictedServiceRegistryKeyAcl removes BUILTIN\Users and grants only Administrators+SYSTEM' {
        $registryRoot = 'TestRegistry:\Services'
        $serviceName = 'FakeServiceAcl1'
        $servicePath = Join-Path -Path $registryRoot -ChildPath $serviceName
        New-Item -Path $servicePath -Force | Out-Null

        # TestRegistry: keys inherit a permissive ACL from their real parent
        # (HKCU\Software\Pester\...) that includes BUILTIN\Users - the same
        # shape the real HKLM\SYSTEM\CurrentControlSet\Services subkey has,
        # which is exactly the gap this function closes. If this ever stops
        # being true (a Pester internals change), this test would silently
        # pass for the wrong reason - the assertions below check the
        # POST-condition regardless, so that risk is contained.
        Set-RestrictedServiceRegistryKeyAcl -ServiceName $serviceName -ServiceRegistryRoot $registryRoot

        $acl = Get-Acl -Path $servicePath
        $identities = $acl.Access | ForEach-Object { $_.IdentityReference.Value }
        $identities | Should -Not -Contain 'BUILTIN\Users'
        $identities | Should -Not -Contain 'Everyone'
        $identities | Should -Not -Contain 'NT AUTHORITY\Authenticated Users'

        $adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
        $systemAccount = $systemSid.Translate([System.Security.Principal.NTAccount]).Value
        $identities | Should -Contain $adminAccount
        $identities | Should -Contain $systemAccount
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
