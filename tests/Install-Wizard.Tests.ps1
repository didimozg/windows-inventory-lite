$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite Install Wizard' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $script:WizardScript = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-Wizard.ps1'
        . $script:WizardScript
    }

    It 'Install server flow resolves the expected parameters from canned answers' {
        # One answer per question in $installServerQuestions, in order:
        # Network (2), HTTPS (6), Basic Auth (3), AD sync (6), Client
        # package (2), Logging (2), Final/NoRun (1) = 22 total.
        $answers = @(
            'http://+:9090/', 'N',
            'N', '', '', '', '', 'N',
            '', 'testpass', '',
            'N', '', '', '', '', '',
            '', '',
            'N', '',
            'N'
        )
        $script:answerIndex = 0
        Mock Read-WizardAnswer {
            $value = $answers[$script:answerIndex]
            $script:answerIndex++
            return $value
        }

        $params = Read-WizardAnswers -Questions $installServerQuestions
        $params['ListenPrefix'] | Should -Be 'http://+:9090/'
        $params.ContainsKey('WebPassword') | Should -Be $true
        $params['WebPassword'] | Should -Be 'testpass'
        $params.ContainsKey('AdSyncEnabled') | Should -Be $false

        $resolved = Format-WizardCommand -ScriptName 'Install-Server.ps1' -Params $params -SecretParams @('WebPassword', 'Token', 'CertificatePfxPassword', 'AdPassword')
        $resolved | Should -Not -Match 'testpass'
        $resolved | Should -Match '\(hidden\)'
    }

    It 'Install client (local) flow requires ServerUrl' {
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Server URL*') { return 'https://example.local/api/v1/inventory' }
            return $null
        }

        $params = Read-WizardAnswers -Questions $installClientQuestions
        $params['ServerUrl'] | Should -Be 'https://example.local/api/v1/inventory'
        $params.Count | Should -Be 1
    }

    It 'Deploy client to remote machines (WinRM) flow splits comma-separated computer names' {
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Target computer names*') { return 'PC1, PC2, PC3' }
            if ($Prompt -like 'Server URL*') { return 'https://example.local/api/v1/inventory' }
            return $null
        }

        $params = Read-WizardAnswers -Questions $installClientWinRMQuestions
        $params['ComputerName'] | Should -Be @('PC1', 'PC2', 'PC3')
    }

    # Install-ClientWinRM.ps1 supports -SoftwareCheckIntervalHours (the
    # software-distribution job poll interval, independent of
    # -IntervalHours), but this flow had no question for it at all - every
    # WinRM push silently used the target script's own default regardless of
    # what an admin wanted.
    It 'Deploy client to remote machines (WinRM) flow threads a non-default SoftwareCheckIntervalHours answer through' {
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Target computer names*') { return 'PC1' }
            if ($Prompt -like 'Server URL*') { return 'https://example.local/api/v1/inventory' }
            if ($Prompt -like 'Software-distribution job poll interval*') { return '3' }
            return $null
        }

        $params = Read-WizardAnswers -Questions $installClientWinRMQuestions
        $params['SoftwareCheckIntervalHours'] | Should -Be 3
    }

    # Install-ClientWinRM.ps1 declares -CredentialPassword as
    # [System.Security.SecureString] (unlike -Token, which is [string] on
    # the same script) and $params is splatted directly at it - a plain
    # [string] value throws ParameterBindingValidationException at
    # invocation time. Blank/default answers never reach this path (they
    # short-circuit before $params[$question.Name] is even set), which is
    # exactly why this bug went unnoticed until a real credential password
    # was typed in this specific flow.
    It 'Deploy client to remote machines (WinRM) flow binds CredentialPassword as a real SecureString, not a string' {
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Target computer names*') { return 'PC1' }
            if ($Prompt -like 'Server URL*') { return 'https://example.local/api/v1/inventory' }
            if ($Prompt -like 'Inventory ingestion token*') { return 'a-real-token' }
            if ($Prompt -like 'Credential password*') { return 'p@ssw0rd' }
            return $null
        }

        $params = Read-WizardAnswers -Questions $installClientWinRMQuestions
        $params['CredentialPassword'] | Should -BeOfType [System.Security.SecureString]

        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($params['CredentialPassword'])
        try {
            [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) | Should -Be 'p@ssw0rd'
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }

        # -Token is [string] on this same target script (Install-ClientWinRM.ps1) -
        # confirms the fix is scoped to CredentialPassword only, not applied
        # blanket to every SecureString-typed question.
        $params['Token'] | Should -BeOfType [string]
    }

    It 'Uninstall server flow passes RemoveData when confirmed' {
        Mock Read-WizardAnswer { return 'y' }

        $params = Read-WizardAnswers -Questions $uninstallServerQuestions
        $params['RemoveData'] | Should -Be $true
    }

    It 'Uninstall client (local) flow leaves InstallPath unset when left blank' {
        Mock Read-WizardAnswer { return $null }

        $params = Read-WizardAnswers -Questions $uninstallClientQuestions
        $params.Count | Should -Be 0
    }

    It 'Uninstall client (remote, WinRM) flow requires ComputerName' {
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Target computer names*') { return 'TESTPC' }
            return $null
        }

        $params = Read-WizardAnswers -Questions $uninstallClientWinRMQuestions
        $params['ComputerName'] | Should -Be @('TESTPC')
    }

    # Same fix as the install-side WinRM test above, applied to
    # Uninstall-ClientWinRM.ps1's own -CredentialPassword parameter, also
    # declared [System.Security.SecureString].
    It 'Uninstall client (remote, WinRM) flow binds CredentialPassword as a real SecureString, not a string' {
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Target computer names*') { return 'TESTPC' }
            if ($Prompt -like 'Credential password*') { return 'p@ssw0rd' }
            return $null
        }

        $params = Read-WizardAnswers -Questions $uninstallClientWinRMQuestions
        $params['CredentialPassword'] | Should -BeOfType [System.Security.SecureString]
    }

    It 'Format-WizardCommand never prints a secret value in cleartext' {
        $params = @{ WebPassword = 'super-secret-value'; ListenPrefix = 'http://+:8080/' }
        $resolved = Format-WizardCommand -ScriptName 'Install-Server.ps1' -Params $params -SecretParams @('WebPassword')
        $resolved | Should -Not -Match 'super-secret-value'
        $resolved | Should -Match "ListenPrefix 'http://\+:8080/'"
    }

    It 'Read-WizardServerConfig returns null (not a throw) for a missing config file' {
        Read-WizardServerConfig -Path 'C:\this-path-does-not-exist-installer-wizard-test\server-config.json' | Should -BeNullOrEmpty
    }

    It 'Get-InstallServerMode returns Quick when no config file exists (fresh install)' {
        Get-InstallServerMode -ConfigPath 'C:\this-path-does-not-exist-installer-wizard-test\server-config.json' | Should -Be 'Quick'
    }

    It 'Get-InstallServerMode returns Skip when a config exists and the user picks the default (just refresh)' {
        $tempConfigPath = Join-Path -Path $TestDrive -ChildPath 'server-config.json'
        Set-Content -LiteralPath $tempConfigPath -Value '{"ListenPrefix":"http://+:8080/"}' -Encoding UTF8

        Mock Read-WizardAnswer { return $null }

        Get-InstallServerMode -ConfigPath $tempConfigPath | Should -Be 'Skip'
    }

    It 'Get-InstallServerMode returns Full when a config exists and the user explicitly picks full reconfigure' {
        $tempConfigPath = Join-Path -Path $TestDrive -ChildPath 'server-config.json'
        Set-Content -LiteralPath $tempConfigPath -Value '{"ListenPrefix":"http://+:8080/"}' -Encoding UTF8

        Mock Read-WizardAnswer { return '2' }

        Get-InstallServerMode -ConfigPath $tempConfigPath | Should -Be 'Full'
    }

    It 'exactly 4 install-server questions are flagged QuickInstall: ListenPrefix, OpenFirewall, WebUsername, WebPassword' {
        $quickNames = @($installServerQuestions | Where-Object { $_['QuickInstall'] } | ForEach-Object { $_.Name })
        $quickNames | Should -Be @('ListenPrefix', 'OpenFirewall', 'WebUsername', 'WebPassword')
    }

    It 'answering only the QuickInstall-flagged questions never produces a $params key from the other 17 questions' {
        $quickQuestions = @($installServerQuestions | Where-Object { $_['QuickInstall'] })
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Listen prefix*') { return 'http://+:9090/' }
            if ($Prompt -like 'Open the Windows Firewall*') { return 'y' }
            if ($Prompt -like 'Dashboard username*') { return 'admin' }
            if ($Prompt -like 'Dashboard password*') { return 'testpass' }
            return $null
        }

        $params = Read-WizardAnswers -Questions $quickQuestions

        $otherQuestionNames = @($installServerQuestions | Where-Object { -not $_['QuickInstall'] } | ForEach-Object { $_.Name } | Select-Object -Unique)
        foreach ($name in $otherQuestionNames) {
            $params.ContainsKey($name) | Should -Be $false
        }
        $params['ListenPrefix'] | Should -Be 'http://+:9090/'
        $params['OpenFirewall'] | Should -Be $true
        $params['WebUsername'] | Should -Be 'admin'
        $params['WebPassword'] | Should -Be 'testpass'
    }

    It 'Invoke-WizardAction returns false under -WhatIf without invoking the script' {
        Mock Read-WizardAnswer { return 'y' }
        $scriptRan = $false
        function script:Test-InvokeWizardActionTarget { $script:scriptRan = $true }

        $result = Invoke-WizardAction -ScriptPath 'Test-InvokeWizardActionTarget' -ScriptName 'Test-InvokeWizardActionTarget' -Params @{} -WhatIf

        $result | Should -Be $false
        $scriptRan | Should -Be $false
    }

    It 'Invoke-WizardAction returns false when the user declines to proceed' {
        Mock Read-WizardAnswer { return 'n' }
        $scriptRan = $false
        function script:Test-InvokeWizardActionTarget2 { $script:scriptRan = $true }

        $result = Invoke-WizardAction -ScriptPath 'Test-InvokeWizardActionTarget2' -ScriptName 'Test-InvokeWizardActionTarget2' -Params @{}

        $result | Should -Be $false
        $scriptRan | Should -Be $false
    }

    It 'Show-QuickInstallSummary reports the resolved port and a firewall-opened line when OpenFirewall was set' {
        $output = Show-QuickInstallSummary -Params @{ ListenPrefix = 'http://+:9090/'; OpenFirewall = $true } | Out-String

        $output | Should -Match 'http://localhost:9090/'
        $output | Should -Match 'Firewall:\s+opened for port 9090'
        $output | Should -Match 'HTTPS:\s+disabled'
        $output | Should -Match 'AD sync:\s+disabled'
    }

    It 'Show-QuickInstallSummary reports the default port 8080 and a not-opened firewall line when ListenPrefix/OpenFirewall were not answered' {
        $output = Show-QuickInstallSummary -Params @{} | Out-String

        $output | Should -Match 'http://localhost:8080/'
        $output | Should -Match 'Firewall:\s+not opened'
    }

    It 'Test-ShouldShowQuickInstallSummary returns true only when Ran is true and Mode is Quick' {
        Test-ShouldShowQuickInstallSummary -Ran $true -Mode 'Quick' | Should -Be $true
        Test-ShouldShowQuickInstallSummary -Ran $false -Mode 'Quick' | Should -Be $false
        Test-ShouldShowQuickInstallSummary -Ran $true -Mode 'Skip' | Should -Be $false
        Test-ShouldShowQuickInstallSummary -Ran $true -Mode 'Full' | Should -Be $false
    }

    It 'ConvertFrom-ClientBinPath extracts all fields from a full binPath (wizard-installed shape, with --share and --token)' {
        $binPath = '"C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory" --interval-hours 6 --share "\\server\share" --token "abc123" --output "C:\ProgramData\WindowsInventoryLite\client-data" --debug-log-path "C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug.log"'

        $result = ConvertFrom-ClientBinPath -BinPath $binPath

        $result['ServerUrl'] | Should -Be 'https://server.example.local/api/v1/inventory'
        $result['ServerSharePath'] | Should -Be '\\server\share'
        $result['Token'] | Should -Be 'abc123'
        $result['IntervalHours'] | Should -Be 6
        $result['InstallPath'] | Should -Be 'C:\ProgramData\WindowsInventoryLite\client-data'
    }

    It 'ConvertFrom-ClientBinPath extracts a partial set from a GPO-shaped binPath (no --share, no --token)' {
        $binPath = '"C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory" --interval-hours 12 --output "C:\ProgramData\WindowsInventoryLite\client-data" --debug-log-path "C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug.log"'

        $result = ConvertFrom-ClientBinPath -BinPath $binPath

        $result['ServerUrl'] | Should -Be 'https://server.example.local/api/v1/inventory'
        $result.ContainsKey('ServerSharePath') | Should -Be $false
        $result.ContainsKey('Token') | Should -Be $false
        $result['IntervalHours'] | Should -Be 12
        $result['InstallPath'] | Should -Be 'C:\ProgramData\WindowsInventoryLite\client-data'
    }

    It 'ConvertFrom-ClientBinPath preserves --software-check-interval-hours without confusing it for --interval-hours' {
        $binPath = '"C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory" --interval-hours 6 --software-check-interval-hours 12 --output "C:\ProgramData\WindowsInventoryLite\client-data" --debug-log-path "C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug.log"'

        $result = ConvertFrom-ClientBinPath -BinPath $binPath

        $result['IntervalHours'] | Should -Be 6
        $result['SoftwareCheckIntervalHours'] | Should -Be 12
    }

    It 'ConvertFrom-ClientBinPath leaves SoftwareCheckIntervalHours unset on a pre-v0.56.0 binPath' {
        $binPath = '"C:\client\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory" --interval-hours 6 --output "C:\client" --debug-log-path "C:\client\debug.log"'

        $result = ConvertFrom-ClientBinPath -BinPath $binPath

        $result.ContainsKey('SoftwareCheckIntervalHours') | Should -Be $false
    }

    It 'ConvertFrom-ClientBinPath un-escapes an embedded backslash-quote inside a value' {
        $binPath = '"C:\client\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory" --interval-hours 6 --token "has\"quote" --output "C:\client" --debug-log-path "C:\client\debug.log"'

        $result = ConvertFrom-ClientBinPath -BinPath $binPath

        $result['Token'] | Should -Be 'has"quote'
    }

    It 'ConvertFrom-ClientBinPath returns null when --server-url is absent' {
        $binPath = '"C:\client\WindowsInventoryLiteClient.exe" --interval-hours 6 --output "C:\client" --debug-log-path "C:\client\debug.log"'

        ConvertFrom-ClientBinPath -BinPath $binPath | Should -BeNullOrEmpty
    }

    It 'ConvertFrom-ClientBinPath returns null for garbage input' {
        ConvertFrom-ClientBinPath -BinPath 'not a real binpath at all' | Should -BeNullOrEmpty
    }

    It 'Get-InstallClientMode returns Full with empty Params when the service does not exist' {
        Mock Invoke-ScExe {
            return @{ Output = @('The specified service does not exist as an installed service.'); ExitCode = 1060 }
        } -ParameterFilter { $Arguments[0] -eq 'query' }

        $result = Get-InstallClientMode -ServiceName 'WindowsInventoryLiteClient'

        $result.Mode | Should -Be 'Full'
        $result.Params.Count | Should -Be 0
    }

    It 'Get-ClientServiceBinaryPath returns the WMI PathName for an existing service' {
        Mock Get-WmiObject {
            return [pscustomobject]@{ PathName = '"C:\client\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory"' }
        }

        Get-ClientServiceBinaryPath -ServiceName 'WindowsInventoryLiteClient' | Should -Be '"C:\client\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory"'
    }

    It 'Get-ClientServiceBinaryPath returns null when the service does not exist' {
        Mock Get-WmiObject { return $null }

        Get-ClientServiceBinaryPath -ServiceName 'WindowsInventoryLiteClient' | Should -BeNullOrEmpty
    }

    It 'Get-InstallClientMode returns Full when the service exists but its binPath has no --server-url' {
        Mock Invoke-ScExe {
            return @{ Output = @('SERVICE_NAME: WindowsInventoryLiteClient'); ExitCode = 0 }
        } -ParameterFilter { $Arguments[0] -eq 'query' }
        Mock Get-WmiObject {
            return [pscustomobject]@{ PathName = '"C:\client\WindowsInventoryLiteClient.exe" --output "C:\client"' }
        }

        $result = Get-InstallClientMode -ServiceName 'WindowsInventoryLiteClient'

        $result.Mode | Should -Be 'Full'
    }

    It 'Get-InstallClientMode returns Skip with the reconstructed Params when the service exists, parses, and the user accepts the default choice' {
        Mock Invoke-ScExe {
            return @{ Output = @('SERVICE_NAME: WindowsInventoryLiteClient'); ExitCode = 0 }
        } -ParameterFilter { $Arguments[0] -eq 'query' }
        Mock Get-WmiObject {
            return [pscustomobject]@{ PathName = '"C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory" --interval-hours 6 --output "C:\ProgramData\WindowsInventoryLite\client-data" --debug-log-path "C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug.log"' }
        }
        Mock Read-WizardAnswer { return $null }

        $result = Get-InstallClientMode -ServiceName 'WindowsInventoryLiteClient'

        $result.Mode | Should -Be 'Skip'
        $result.Params['ServerUrl'] | Should -Be 'https://server.example.local/api/v1/inventory'
        $result.Params['InstallPath'] | Should -Be 'C:\ProgramData\WindowsInventoryLite\client-data'
    }

    # Regression test: the ingestion token moved off the binPath into the
    # service's registry Environment value (Install-Client.ps1's
    # Set-ServiceEnvironmentToken), so a current-shape binPath (like the
    # test above) never has --token in it. Without recovering it from the
    # registry separately, "Just refresh" on a token-configured client would
    # call Install-Client.ps1 with no -Token, which unconditionally wipes
    # the existing token.
    It 'Get-InstallClientMode recovers the ingestion token from the registry Environment value when the binPath has none' {
        Mock Invoke-ScExe {
            return @{ Output = @('SERVICE_NAME: WindowsInventoryLiteClient'); ExitCode = 0 }
        } -ParameterFilter { $Arguments[0] -eq 'query' }
        Mock Get-WmiObject {
            return [pscustomobject]@{ PathName = '"C:\ProgramData\WindowsInventoryLite\client-data\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory" --interval-hours 6 --output "C:\ProgramData\WindowsInventoryLite\client-data" --debug-log-path "C:\ProgramData\WindowsInventoryLite\client-data\_logs\debug.log"' }
        }
        Mock Read-WizardAnswer { return $null }
        Mock Get-ItemProperty {
            return [pscustomobject]@{ Environment = @('WIL_INGESTION_TOKEN=recovered-token') }
        }

        $result = Get-InstallClientMode -ServiceName 'WindowsInventoryLiteClient'

        $result.Mode | Should -Be 'Skip'
        $result.Params['Token'] | Should -Be 'recovered-token'
    }

    It 'Get-InstallClientMode returns Full when the service exists, parses, and the user explicitly picks full reconfigure' {
        Mock Invoke-ScExe {
            return @{ Output = @('SERVICE_NAME: WindowsInventoryLiteClient'); ExitCode = 0 }
        } -ParameterFilter { $Arguments[0] -eq 'query' }
        Mock Get-WmiObject {
            return [pscustomobject]@{ PathName = '"C:\client\WindowsInventoryLiteClient.exe" --server-url "https://server.example.local/api/v1/inventory" --interval-hours 6 --output "C:\client" --debug-log-path "C:\client\debug.log"' }
        }
        Mock Read-WizardAnswer { return '2' }

        $result = Get-InstallClientMode -ServiceName 'WindowsInventoryLiteClient'

        $result.Mode | Should -Be 'Full'
    }

    It 'Resolve-WizardFlowParams returns SkipParams verbatim when Mode is Skip' {
        $skipParams = @{ ServerUrl = 'https://example.local/api/v1/inventory'; IntervalHours = 6 }

        $result = Resolve-WizardFlowParams -Mode 'Skip' -Questions $installClientQuestions -SkipParams $skipParams

        $result | Should -Be $skipParams
    }

    It 'Resolve-WizardFlowParams asks every question when Mode is Full, ignoring any SkipParams' {
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Server URL*') { return 'https://full.example.local/api/v1/inventory' }
            return $null
        }

        $result = Resolve-WizardFlowParams -Mode 'Full' -Questions $installClientQuestions -SkipParams @{ ServerUrl = 'https://ignored.example.local/api/v1/inventory' }

        $result['ServerUrl'] | Should -Be 'https://full.example.local/api/v1/inventory'
    }

    It 'Resolve-WizardFlowParams filters to QuickInstall-flagged questions when Mode is Quick' {
        Mock Read-WizardAnswer {
            param($Prompt, $Default, [switch]$Mandatory, [switch]$Secure)
            if ($Prompt -like 'Listen prefix*') { return 'http://+:9090/' }
            return $null
        }

        $result = Resolve-WizardFlowParams -Mode 'Quick' -Questions $installServerQuestions

        $result['ListenPrefix'] | Should -Be 'http://+:9090/'
        $result.ContainsKey('UseHttps') | Should -Be $false
    }

    It 'Resolve-WizardFlowParams defaults SkipParams to an empty hashtable when not supplied (matches the server flow''s existing Skip behavior)' {
        $result = Resolve-WizardFlowParams -Mode 'Skip' -Questions $installServerQuestions

        $result.Count | Should -Be 0
    }
}
