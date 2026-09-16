$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Deploy-ClientGpo client-data layout' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'deploy\client\Deploy-ClientGpo.ps1'
        . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
    }

    It 'rejects a shell-unsafe InstallPath' {
        { . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory' -InstallPath 'C:\wil&calc.exe' } | Should -Throw '*InstallPath*'
    }

    It 'accepts a safe InstallPath' {
        { . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory' -InstallPath 'C:\ProgramData\WindowsInventoryLite\client-data' } | Should -Not -Throw
    }

    # Install-ClientWinRM.ps1's RemoteDeployScriptBlock sets this on the
    # remote powershell.exe process it spawns instead of passing -Token
    # directly (see that script's own fix/test) - this is the receiving
    # side of that fix.
    It 'falls back to WIL_INGESTION_TOKEN when -Token is not supplied' {
        $originalToken = $env:WIL_INGESTION_TOKEN
        try {
            $env:WIL_INGESTION_TOKEN = 'token-from-environment'
            . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
            $Token | Should -Be 'token-from-environment'
        }
        finally {
            if ($null -eq $originalToken) {
                Remove-Item Env:\WIL_INGESTION_TOKEN -ErrorAction SilentlyContinue
            }
            else {
                $env:WIL_INGESTION_TOKEN = $originalToken
            }
            . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
        }
    }

    It 'prefers an explicit -Token over WIL_INGESTION_TOKEN' {
        $originalToken = $env:WIL_INGESTION_TOKEN
        try {
            $env:WIL_INGESTION_TOKEN = 'token-from-environment'
            . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory' -Token 'explicit-token'
            $Token | Should -Be 'explicit-token'
        }
        finally {
            if ($null -eq $originalToken) {
                Remove-Item Env:\WIL_INGESTION_TOKEN -ErrorAction SilentlyContinue
            }
            else {
                $env:WIL_INGESTION_TOKEN = $originalToken
            }
            . $script:ScriptPath -ServerUrl 'https://example.local/api/v1/inventory'
        }
    }

    It 'Get-DesiredServiceCommand embeds --output and --debug-log-path' {
        $command = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $command | Should -Match '--output "C:\\ProgramData\\WindowsInventoryLite\\client-data"'
        $command | Should -Match '--debug-log-path "C:\\ProgramData\\WindowsInventoryLite\\client-data\\_logs\\debug-client\.log"'
    }

    It 'Get-DesiredServiceCommand emits --software-check-interval-hours alongside --interval-hours' {
        $command = Get-DesiredServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -SoftwareHours 12 -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Match '--interval-hours 6'
        $command | Should -Match '--software-check-interval-hours 12'
    }

    It 'Get-DesiredServiceCommand defaults --software-check-interval-hours to 6 when not supplied' {
        $command = Get-DesiredServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Match '--software-check-interval-hours 6'
    }

    It 'Get-DesiredServiceCommand never embeds the ingestion token on the command line' {
        $command = Get-DesiredServiceCommand -ServicePath 'C:\x\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -OutputDirectory 'C:\x' -DebugLogPath 'C:\x\_logs\debug-client.log'
        $command | Should -Not -Match '--token'
    }

    It 'Get-DesiredServiceCommand differs between the legacy bare-root path and the new client-data path, so an already-installed client is detected as needing reinstall' {
        $legacyCommand = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -OutputDirectory 'C:\ProgramData\WindowsInventoryLite' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\_logs\debug-client.log'
        $newCommand = Get-DesiredServiceCommand -ServicePath 'C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe' -Url 'https://example.local/api/v1/inventory' -Hours 6 -OutputDirectory 'C:\ProgramData\WindowsInventoryLite\client-data' -DebugLogPath 'C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug-client.log'
        $legacyCommand | Should -Not -Be $newCommand
    }

    # Get-ExeVersion switched from 2>&1 to 2>$null: $ErrorActionPreference =
    # 'Stop' (set script-wide in Deploy-ClientGpo.ps1) combined with 2>&1 is
    # documented elsewhere in this project (Install-ClientDebianSSH.ps1's
    # Invoke-NativeAllowingStderr) as turning harmless native-command stderr
    # text into a terminating error on some PowerShell engine versions - a
    # returned $null here would make $packageVersion never equal
    # $installedVersion, forcing a reinstall on every run. This fixture
    # proves the fix: a real version on stdout plus a harmless stderr banner,
    # clean exit code, and Get-ExeVersion still returns the real version.
    It 'Get-ExeVersion returns the real version even when the target also writes harmless text to stderr' {
        $fixturePath = Join-Path -Path $TestDrive -ChildPath 'fake-client-with-stderr-noise.cmd'
        Set-Content -LiteralPath $fixturePath -Value @(
            '@echo off'
            'echo 1.2.3-test'
            'echo harmless stderr banner from a hypothetical AV/EDR hook 1>&2'
            'exit /b 0'
        )

        Get-ExeVersion -Path $fixturePath | Should -Be '1.2.3-test'
    }

    It 'Get-ServiceEnvironmentToken returns an empty string when no Environment value is set' {
        $registryRoot = 'TestRegistry:\Services'
        $serviceName = 'FakeServiceNoToken'
        New-Item -Path (Join-Path -Path $registryRoot -ChildPath $serviceName) -Force | Out-Null
        Get-ServiceEnvironmentToken -ServiceName $serviceName -ServiceRegistryRoot $registryRoot | Should -Be ''
    }

    It 'Set-ServiceEnvironmentToken then Get-ServiceEnvironmentToken round-trips the token' {
        $registryRoot = 'TestRegistry:\Services'
        $serviceName = 'FakeServiceRoundTrip'
        New-Item -Path (Join-Path -Path $registryRoot -ChildPath $serviceName) -Force | Out-Null
        Set-ServiceEnvironmentToken -ServiceName $serviceName -SharedToken 'abc123' -ServiceRegistryRoot $registryRoot
        Get-ServiceEnvironmentToken -ServiceName $serviceName -ServiceRegistryRoot $registryRoot | Should -Be 'abc123'
    }

    It 'Set-ServiceEnvironmentToken with an empty token clears a previously-set value' {
        $registryRoot = 'TestRegistry:\Services'
        $serviceName = 'FakeServiceClearToken'
        New-Item -Path (Join-Path -Path $registryRoot -ChildPath $serviceName) -Force | Out-Null
        Set-ServiceEnvironmentToken -ServiceName $serviceName -SharedToken 'abc123' -ServiceRegistryRoot $registryRoot
        Set-ServiceEnvironmentToken -ServiceName $serviceName -SharedToken '' -ServiceRegistryRoot $registryRoot
        Get-ServiceEnvironmentToken -ServiceName $serviceName -ServiceRegistryRoot $registryRoot | Should -Be ''
    }

    It 'Set-RestrictedServiceRegistryKeyAcl removes BUILTIN\Users and grants only Administrators+SYSTEM' {
        $registryRoot = 'TestRegistry:\Services'
        $serviceName = 'FakeGpoServiceAcl1'
        $servicePath = Join-Path -Path $registryRoot -ChildPath $serviceName
        New-Item -Path $servicePath -Force | Out-Null

        Set-RestrictedServiceRegistryKeyAcl -ServiceName $serviceName -ServiceRegistryRoot $registryRoot

        $acl = Get-Acl -Path $servicePath
        $identities = $acl.Access | ForEach-Object { $_.IdentityReference.Value }
        $identities | Should -Not -Contain 'BUILTIN\Users'

        $adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
        $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
        $identities | Should -Contain $adminAccount
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

    It 'Get-ServiceBinaryPath returns the WMI PathName for an existing service' {
        Mock Get-WmiObject {
            return [pscustomobject]@{ PathName = '"C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe" --server-url "https://example.local/api/v1/inventory"' }
        }

        Get-ServiceBinaryPath | Should -Be '"C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe" --server-url "https://example.local/api/v1/inventory"'
    }

    It 'Get-ServiceBinaryPath returns null when the service does not exist' {
        Mock Get-WmiObject { return $null }

        Get-ServiceBinaryPath | Should -BeNullOrEmpty
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
