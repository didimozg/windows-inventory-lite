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
}
