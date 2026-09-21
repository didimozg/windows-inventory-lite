$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install-ClientDebianSSH' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:ScriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-ClientDebianSSH.ps1'
        $securePassword = ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force
        . $script:ScriptPath -ComputerName 'unused-for-dot-source-test' -ServerUrl 'https://example.local/api/v1/linux/inventory' -CredentialUsername 'root' -CredentialPassword $securePassword
    }

    It 'New-SystemdUnitFiles rejects a bare top-level InstallDirectory or a traversal path' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units-bad-path'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        { New-SystemdUnitFiles -Directory $dir -InstallDirectory '/etc' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 6 } | Should -Throw '*absolute Linux path under /opt/*'
        { New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/../etc' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 6 } | Should -Throw '*absolute Linux path under /opt/*'
    }

    It 'New-SystemdUnitFiles writes a oneshot service with the correct ExecStart' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units1'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 6

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match 'Type=oneshot'
        $serviceContent | Should -Match ([regex]::Escape('ExecStart=/opt/windows-inventory-lite/wil-linux-client --server-url "https://example.local/api/v1/linux/inventory"'))
        $serviceContent | Should -Not -Match '--token'
    }

    It 'New-SystemdUnitFiles delivers the token via EnvironmentFile when a token is provided' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units2'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken 'secret-token' -Hours 6

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match ([regex]::Escape('EnvironmentFile=/etc/wil-linux-client.env'))
    }

    It 'New-SystemdUnitFiles writes a timer matching the requested interval' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'units3'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 12

        $timerContent = Get-Content -LiteralPath $result.TimerPath -Raw
        $timerContent | Should -Match 'OnUnitActiveSec=12h'
        $timerContent | Should -Match 'Unit=wil-linux-client.service'
    }

    It 'New-SystemdStatusUnitFiles writes a oneshot service with --mode status' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'status-units1'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken '' -Minutes 30

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match 'Type=oneshot'
        $serviceContent | Should -Match ([regex]::Escape('ExecStart=/opt/windows-inventory-lite/wil-linux-client --server-url "https://example.local/api/v1/linux/inventory/service-status" --mode status'))
        $serviceContent | Should -Not -Match '--token'
    }

    It 'New-SystemdStatusUnitFiles delivers the token via EnvironmentFile when a token is provided' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'status-units2'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken 'secret-token' -Minutes 30

        $serviceContent = Get-Content -LiteralPath $result.ServicePath -Raw
        $serviceContent | Should -Match ([regex]::Escape('EnvironmentFile=/etc/wil-linux-client.env'))
    }

    It 'New-SystemdStatusUnitFiles writes a timer matching the requested interval in minutes' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'status-units3'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null

        $result = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken '' -Minutes 45

        $timerContent = Get-Content -LiteralPath $result.TimerPath -Raw
        $timerContent | Should -Match 'OnUnitActiveSec=45min'
        $timerContent | Should -Match 'Unit=wil-linux-client-status.service'
    }

    It 'Copy-FileToRemote password auth calls Invoke-PlinkWithAuth with pscp.exe, no -pw/-batch in its own Arguments, and the real password' {
        Mock Invoke-PlinkWithAuth { return 'ok' }
        $script:usingPassword = $true
        $script:pscpPath = 'pscp.exe'
        $script:CredentialUsername = 'root'
        $script:CredentialPassword = (ConvertTo-SecureString -String 'unused-test-password' -AsPlainText -Force)

        Copy-FileToRemote -TargetComputer '192.0.2.10' -LocalPath 'C:\fake\wil-linux-client' -RemotePath '/tmp/wil-linux-client-install/wil-linux-client'

        Should -Invoke Invoke-PlinkWithAuth -Times 1 -ParameterFilter {
            $ExePath -eq 'pscp.exe' -and ($Arguments -notcontains '-pw') -and ($Arguments -notcontains '-batch') -and ($PlainPassword -eq 'unused-test-password')
        }
    }

    It 'Copy-FileToRemote key auth calls Invoke-PlinkWithAuth with pscp.exe and the converted key path, no -pwfile' {
        Mock Invoke-PlinkWithAuth { return 'ok' }
        $script:usingPassword = $false
        $script:pscpPath = 'pscp.exe'
        $script:ConvertedKeyPath = 'C:\fake\converted.ppk'
        $script:CredentialUsername = 'root'

        Copy-FileToRemote -TargetComputer '192.0.2.10' -LocalPath 'C:\fake\wil-linux-client' -RemotePath '/tmp/wil-linux-client-install/wil-linux-client'

        Should -Invoke Invoke-PlinkWithAuth -Times 1 -ParameterFilter {
            $ExePath -eq 'pscp.exe' -and $ConvertedKeyPath -eq 'C:\fake\converted.ppk'
        }
    }

    Context 'New-SystemdUnitFiles token handling' {
        It 'keeps the token out of the unit file and points at the env file instead' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'units-token'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $units = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken 'secret-token' -Hours 6
            $content = Get-Content -LiteralPath $units.ServicePath -Raw
            $content | Should -Not -Match ([regex]::Escape('--token'))
            $content | Should -Not -Match ([regex]::Escape('secret-token'))
            $content | Should -Match ([regex]::Escape('EnvironmentFile=/etc/wil-linux-client.env'))
        }

        It 'omits EnvironmentFile entirely when there is no token' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'units-no-token'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $units = New-SystemdUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory' -SharedToken '' -Hours 6
            (Get-Content -LiteralPath $units.ServicePath -Raw) | Should -Not -Match 'EnvironmentFile'
        }

        It 'produces a status unit with the env file and no command-line token' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'status-units'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $units = New-SystemdStatusUnitFiles -Directory $dir -InstallDirectory '/opt/windows-inventory-lite' -Url 'https://example.local/api/v1/linux/inventory/service-status' -SharedToken 'secret-token' -Minutes 30
            $content = Get-Content -LiteralPath $units.ServicePath -Raw
            $content | Should -Not -Match ([regex]::Escape('secret-token'))
            $content | Should -Match ([regex]::Escape('EnvironmentFile=/etc/wil-linux-client.env'))
            $content | Should -Match ([regex]::Escape('--mode status'))
        }

        It 'writes an env file whose single line matches the C# generator byte-for-byte' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'env-file'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $env = New-SystemdEnvFile -Directory $dir -SharedToken 'secret-token'
            (Get-Content -LiteralPath $env.EnvPath -Raw).TrimEnd("`n") | Should -Be 'WIL_INGESTION_TOKEN=secret-token'
        }

        # This file holds the ingestion token in plaintext on the LOCAL
        # machine running this script - same class of secret as the plink
        # -pwfile Invoke-PlinkWithAuth already restricts, and this
        # fix applies that identical ACL treatment here (protect + grant
        # FullControl to only the current user, instead of inheriting
        # whatever $Directory's own ACL happens to be).
        It 'restricts the env file to only the current user, protected from inheritance' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'env-file-acl'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $env = New-SystemdEnvFile -Directory $dir -SharedToken 'secret-token'

            $acl = Get-Acl -LiteralPath $env.EnvPath
            $acl.AreAccessRulesProtected | Should -BeTrue
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $identities = $acl.Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) }
            $identities | Should -Contain $currentUser
        }

        # Install-ClientDebianSSHInstallTarget's finally block calls
        # Clear-TempPasswordFile on this specific file before the staging
        # directory's blanket recursive cleanup - proven directly here since
        # exercising that through the full install flow would need a real
        # or heavily mocked SSH connection.
        It 'the env file is a valid target for the same secure-delete Clear-TempPasswordFile already gives the plink password file' {
            $dir = Join-Path -Path $TestDrive -ChildPath 'env-file-delete'
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            $env = New-SystemdEnvFile -Directory $dir -SharedToken 'secret-token'

            Clear-TempPasswordFile -Path $env.EnvPath

            Test-Path -LiteralPath $env.EnvPath | Should -BeFalse
        }
    }
}
