#requires -Version 2.0

[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Single mockable prompt primitive - every question in every flow goes
# through this function, so Pester tests can Mock it to feed canned
# answers without any real console interaction.
function Read-WizardAnswer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter()]
        [string]$Default,

        [Parameter()]
        [switch]$Mandatory,

        [Parameter()]
        [switch]$Secure
    )

    $displayPrompt = if ($Default) { "$Prompt [$Default]" } else { $Prompt }

    while ($true) {
        if ($Secure) {
            $secureAnswer = Read-Host -Prompt $displayPrompt -AsSecureString
            $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureAnswer)
            try {
                $answer = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            }
            finally {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
            }
        }
        else {
            $answer = Read-Host -Prompt $displayPrompt
        }

        if ([string]::IsNullOrEmpty($answer)) {
            if ($Default) {
                return $Default
            }
            if ($Mandatory) {
                Write-Host 'This value is required.' -ForegroundColor Yellow
                continue
            }
            return $null
        }

        return $answer
    }
}

# Walks a flow's question-spec array (each entry: Name/Prompt/Type, plus
# optional Default/Mandatory/Choices) and returns a parameter hashtable
# ready to splat at the target script. Types: String, SecureString,
# Int (falls back to Default with a warning on a non-numeric answer rather
# than throwing or re-prompting - safe since no Int question in this plan
# is Mandatory), StringArray (comma-separated), ValidateSet (shows Choices,
# falls back to Default with a warning on an invalid answer rather than
# re-prompting - acceptable since every ValidateSet question in this plan
# has a safe default), Switch (its own y/N sub-prompt, never inherits
# -Default from the spec). Skips adding a key when the answer is
# empty-and-optional or equals the displayed default - lets the target
# script's own default apply rather than redundantly passing an identical
# value.
function Read-WizardAnswers {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Questions
    )

    $params = @{}
    foreach ($question in $Questions) {
        if ($question.Type -eq 'Switch') {
            $reply = Read-WizardAnswer -Prompt ($question.Prompt + ' [y/N]') -Default 'N'
            if ($reply -match '^(y|yes)$') {
                $params[$question.Name] = $true
            }
            continue
        }

        $promptText = $question.Prompt
        if ($question.Type -eq 'ValidateSet') {
            $promptText += ' (' + ($question['Choices'] -join '/') + ')'
        }

        # Bracket notation, not dot notation: under Set-StrictMode -Version 2.0,
        # dot access to a hashtable key that isn't present throws
        # PropertyNotFoundStrict, and Default/Mandatory/Choices are optional
        # per-question keys that most flows omit.
        $answer = Read-WizardAnswer -Prompt $promptText -Default $question['Default'] -Mandatory:([bool]$question['Mandatory']) -Secure:($question.Type -eq 'SecureString')
        if ($null -eq $answer -or $answer -eq $question['Default']) {
            continue
        }

        if ($question.Type -eq 'ValidateSet' -and $question['Choices'] -notcontains $answer) {
            Write-Host "Invalid choice. Using default: $($question['Default'])" -ForegroundColor Yellow
            continue
        }

        if ($question.Type -eq 'Int') {
            $intValue = 0
            if (-not [int]::TryParse($answer, [ref]$intValue)) {
                Write-Host 'Invalid number. Using default.' -ForegroundColor Yellow
                continue
            }
            $params[$question.Name] = $intValue
            continue
        }

        $params[$question.Name] = switch ($question.Type) {
            'StringArray' { @($answer -split ',\s*') }
            default { $answer }
        }
    }

    return $params
}

# Builds the human-readable equivalent command line for the confirmation
# screen. Secret-valued parameters (named in SecretParams) are shown as
# "(hidden)" rather than their real value.
function Format-WizardCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Params,

        [Parameter()]
        [string[]]$SecretParams = @()
    )

    $parts = @($ScriptName)
    foreach ($key in ($Params.Keys | Sort-Object)) {
        $value = $Params[$key]
        if ($value -is [bool]) {
            if ($value) { $parts += "-$key" }
            continue
        }
        $displayValue = if ($SecretParams -contains $key) { '(hidden)' } else { $value }
        $parts += "-$key '$displayValue'"
    }

    return ($parts -join ' ')
}

# Final step of every flow: show the resolved command, then either stop
# (under -WhatIf, via the standard ShouldProcess short-circuit - no
# interactive prompt reached) or ask for explicit confirmation and invoke
# the target script. This same ShouldProcess gate is what a Pester test
# uses to drive a flow with -WhatIf and assert on the resolved command
# without ever actually running the target script.
function Invoke-WizardAction {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,

        [Parameter(Mandatory = $true)]
        [string]$ScriptName,

        [Parameter(Mandatory = $true)]
        [hashtable]$Params,

        [Parameter()]
        [string[]]$SecretParams = @()
    )

    $resolvedCommand = Format-WizardCommand -ScriptName $ScriptName -Params $Params -SecretParams $SecretParams
    Write-Host ''
    Write-Host 'The following command will run:'
    Write-Host "  $resolvedCommand"
    Write-Host ''

    if (-not $PSCmdlet.ShouldProcess($ScriptName, 'Run')) {
        return
    }

    $confirm = Read-WizardAnswer -Prompt 'Proceed? [y/N]' -Default 'N'
    if ($confirm -notmatch '^(y|yes)$') {
        Write-Host 'Cancelled.'
        return
    }

    & $ScriptPath @Params
}

# Duplicated from Install-Server.ps1's own Read-ServerConfig (this project
# doesn't share a module between scripts - see e.g. Uninstall-Server.ps1's
# identical copy) so the wizard can detect whether a server is already
# installed. Only used for detection (does a config file exist at all) -
# not for reading individual settings out of it, since Install-Server.ps1
# itself already reloads every setting from this same file whenever a
# parameter is left unspecified, which is exactly what "just refresh, no
# questions" below relies on.
function Read-WizardServerConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $null
    }

    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction SilentlyContinue
        $serializer = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        $config = $serializer.DeserializeObject($text)
        if ($config) {
            return $config
        }
    }
    catch {
        Write-Warning "Failed to read server config: $($_.Exception.Message)"
    }

    return $null
}

# Detects an existing server install (via the default server-config.json
# location) and, if found, asks whether to just refresh (reapply the
# current settings, no questions asked) or fully reconfigure. Returns
# $true when the caller should skip the question sequence entirely and
# pass Install-Server.ps1 an empty params hashtable - relies on the same
# behavior every other blank/omitted wizard answer already relies on:
# leaving a parameter unspecified makes Install-Server.ps1 reload its
# last-saved value, so an empty hashtable is a genuine "no change" reapply,
# not a reset to the wizard's own hardcoded defaults. Detection only
# checks the default config path (the same one Uninstall-Server.ps1 falls
# back to) - a server installed at a custom -ConfigPath won't be detected,
# same limitation as every other path-override this wizard doesn't ask
# about, and simply behaves as if no install exists (asks all 22
# questions, as before).
function Test-InstallServerRefreshOnly {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    $existingConfig = Read-WizardServerConfig -Path $ConfigPath
    if (-not $existingConfig) {
        return $false
    }

    Write-Host ''
    Write-Host "An existing server installation was detected ($ConfigPath)."
    Write-Host '1. Just refresh (recommended) - reapply current settings, no questions asked'
    Write-Host '2. Full reconfigure - re-answer every question from scratch'
    $updateChoice = Read-WizardAnswer -Prompt 'Choice' -Default '1'
    return ($updateChoice -ne '2')
}

$installClientQuestions = @(
    @{ Name = 'ServerUrl'; Prompt = 'Server URL (e.g. https://server.domain.local/api/v1/inventory)'; Type = 'String'; Mandatory = $true }
    @{ Name = 'ServerSharePath'; Prompt = 'Server share path for client updates (leave blank to skip)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'Token'; Prompt = 'Inventory ingestion token (leave blank if the server has none configured)'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'IntervalHours'; Prompt = 'Collection interval in hours'; Type = 'Int'; Default = '6'; Mandatory = $false }
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'NoRun'; Prompt = 'Skip starting the service immediately after install'; Type = 'Switch' }
)

$installServerQuestions = @(
    # Network
    @{ Name = 'ListenPrefix'; Prompt = 'Listen prefix'; Type = 'String'; Default = 'http://+:8080/'; Mandatory = $false }
    @{ Name = 'OpenFirewall'; Prompt = 'Open the Windows Firewall for the listen port(s)'; Type = 'Switch' }

    # HTTPS
    @{ Name = 'UseHttps'; Prompt = 'Enable HTTPS'; Type = 'Switch' }
    @{ Name = 'HttpsPort'; Prompt = 'HTTPS port (leave blank for default)'; Type = 'Int'; Mandatory = $false }
    @{ Name = 'CertificateThumbprint'; Prompt = 'Existing certificate thumbprint in LocalMachine\My (leave blank if importing a PFX instead)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'CertificatePfxPath'; Prompt = 'PFX file to import (leave blank if using an existing certificate)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'CertificatePfxPassword'; Prompt = 'PFX password (leave blank if not importing a PFX)'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'DisableHttp'; Prompt = 'Disable plain HTTP once HTTPS is confirmed working (refused unless HTTPS is enabled)'; Type = 'Switch' }

    # Basic Auth / dashboard access
    @{ Name = 'WebUsername'; Prompt = 'Dashboard username'; Type = 'String'; Mandatory = $false }
    @{ Name = 'WebPassword'; Prompt = 'Dashboard password'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'Token'; Prompt = 'Inventory ingestion token (leave blank to auto-generate)'; Type = 'SecureString'; Mandatory = $false }

    # Active Directory description sync
    @{ Name = 'AdSyncEnabled'; Prompt = 'Enable Active Directory description sync'; Type = 'Switch' }
    @{ Name = 'AdSyncMode'; Prompt = 'AD sync mode'; Type = 'ValidateSet'; Choices = @('on-report', 'timer'); Default = 'on-report'; Mandatory = $false }
    @{ Name = 'AdSyncIntervalHours'; Prompt = 'AD sync interval in hours (only used for timer mode)'; Type = 'Int'; Default = '24'; Mandatory = $false }
    @{ Name = 'AdDomain'; Prompt = 'AD domain (leave blank to use the service account identity)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'AdUsername'; Prompt = 'AD username for explicit credentials (leave blank to use the service account identity)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'AdPassword'; Prompt = 'AD password for explicit credentials (leave blank to use the service account identity)'; Type = 'SecureString'; Mandatory = $false }

    # Client package / GPO deployment
    @{ Name = 'ClientServerUrl'; Prompt = 'Server URL clients will report to, e.g. https://server.domain.local/api/v1/inventory (leave blank to skip building a ready-to-deploy GPO package now)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'ClientIntervalHours'; Prompt = 'Client collection interval in hours'; Type = 'Int'; Default = '6'; Mandatory = $false }

    # Logging
    @{ Name = 'DebugLogEnabled'; Prompt = 'Enable debug logging'; Type = 'Switch' }
    @{ Name = 'InstallLogRetentionDays'; Prompt = 'Client-action log retention in days (leave blank for default)'; Type = 'Int'; Mandatory = $false }

    # Final
    @{ Name = 'NoRun'; Prompt = 'Skip starting the service immediately after install'; Type = 'Switch' }
)

$installClientWinRMQuestions = @(
    @{ Name = 'ComputerName'; Prompt = 'Target computer names (comma-separated)'; Type = 'StringArray'; Mandatory = $true }
    @{ Name = 'ServerUrl'; Prompt = 'Server URL (e.g. https://server.domain.local/api/v1/inventory)'; Type = 'String'; Mandatory = $true }
    @{ Name = 'Token'; Prompt = 'Inventory ingestion token (leave blank if the server has none configured)'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'IntervalHours'; Prompt = 'Collection interval in hours'; Type = 'Int'; Default = '6'; Mandatory = $false }
    @{ Name = 'CredentialUsername'; Prompt = 'Credential username (leave blank to use current user context)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'CredentialPassword'; Prompt = 'Credential password (leave blank to use current user context)'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'AddToTrustedHosts'; Prompt = 'Add target computers to WinRM TrustedHosts (needed for non-domain-joined or workgroup targets)'; Type = 'Switch' }
    @{ Name = 'Force'; Prompt = 'Overwrite an already-installed client on the target machines'; Type = 'Switch' }
)

$uninstallServerQuestions = @(
    @{ Name = 'RemoveData'; Prompt = 'Remove inventory data too (server-data and server-config.json - cannot be undone)'; Type = 'Switch' }
)

$uninstallClientQuestions = @(
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
)

$uninstallClientWinRMQuestions = @(
    @{ Name = 'ComputerName'; Prompt = 'Target computer names (comma-separated)'; Type = 'StringArray'; Mandatory = $true }
    @{ Name = 'CredentialUsername'; Prompt = 'Credential username (leave blank to use current user context)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'CredentialPassword'; Prompt = 'Credential password (leave blank to use current user context)'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'AddToTrustedHosts'; Prompt = 'Add target computers to WinRM TrustedHosts (needed for non-domain-joined or workgroup targets)'; Type = 'Switch' }
)

$flows = [ordered]@{
    '1' = @{
        Label        = 'Install server'
        ScriptName   = 'Install-Server.ps1'
        Questions    = $installServerQuestions
        SecretParams = @('WebPassword', 'Token', 'CertificatePfxPassword', 'AdPassword')
    }
    '2' = @{
        Label        = 'Install client (local)'
        ScriptName   = 'Install-Client.ps1'
        Questions    = $installClientQuestions
        SecretParams = @('Token')
    }
    '3' = @{
        Label        = 'Deploy client to remote machines (WinRM)'
        ScriptName   = 'Install-ClientWinRM.ps1'
        Questions    = $installClientWinRMQuestions
        SecretParams = @('Token', 'CredentialPassword')
    }
    '4' = @{
        Label        = 'Uninstall server'
        ScriptName   = 'Uninstall-Server.ps1'
        Questions    = $uninstallServerQuestions
        SecretParams = @()
    }
    '5' = @{
        Label        = 'Uninstall client (local)'
        ScriptName   = 'Uninstall-Client.ps1'
        Questions    = $uninstallClientQuestions
        SecretParams = @()
    }
    '6' = @{
        Label        = 'Uninstall client (remote, WinRM)'
        ScriptName   = 'Uninstall-ClientWinRM.ps1'
        Questions    = $uninstallClientWinRMQuestions
        SecretParams = @('CredentialPassword')
    }
}

function Show-WizardMenu {
    param([Parameter(Mandatory = $true)][System.Collections.Specialized.OrderedDictionary]$Flows)

    Write-Host ''
    Write-Host 'Windows Inventory Lite - Install Wizard'
    foreach ($key in $Flows.Keys) {
        Write-Host "$key. $($Flows[$key].Label)"
    }
    Write-Host '0. Exit'
}

if ($MyInvocation.InvocationName -ne '.') {
    while ($true) {
        Show-WizardMenu -Flows $flows
        $choice = Read-Host -Prompt 'Choice'

        if ($choice -eq '0') {
            break
        }

        $flow = $flows[$choice]
        if (-not $flow) {
            Write-Host 'Invalid choice.' -ForegroundColor Yellow
            continue
        }

        $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath $flow.ScriptName

        # Only the "Install server" flow has an existing-install detection
        # step - see Test-InstallServerRefreshOnly for why "just refresh"
        # means an empty params hashtable rather than a shorter question
        # list.
        $skipQuestions = $false
        if ($choice -eq '1') {
            $defaultConfigPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-config.json'
            $skipQuestions = Test-InstallServerRefreshOnly -ConfigPath $defaultConfigPath
        }

        $params = if ($skipQuestions) { @{} } else { Read-WizardAnswers -Questions $flow.Questions }
        Invoke-WizardAction -ScriptPath $scriptPath -ScriptName $flow.ScriptName -Params $params -SecretParams $flow.SecretParams
    }
}
