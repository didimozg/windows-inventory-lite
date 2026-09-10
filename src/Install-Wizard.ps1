#requires -Version 2.0

[CmdletBinding(SupportsShouldProcess = $true)]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Every flow this wizard dispatches to (all 6 menu options) creates or
# removes a Windows service, restricts an ACL under %ProgramData%, or
# modifies WinRM TrustedHosts - all of which require local admin rights.
# Checked once up front so a non-elevated run gets one clear message
# instead of reaching Read-WizardServerConfig's "Access denied" partway
# through menu option 1, which could otherwise be misread as "no server
# is installed yet" instead of "this session lacks the rights to check."
function Test-IsElevatedAdmin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

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
# than throwing or re-prompting - safe since no Int question defined below
# is Mandatory), StringArray (comma-separated), ValidateSet (shows Choices,
# falls back to Default with a warning on an invalid answer rather than
# re-prompting - acceptable since every ValidateSet question defined below
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

        # Type = 'SecureString' only ever meant "prompt with hidden input" -
        # every target script parameter it feeds (Install-Server.ps1's
        # -WebPassword/-Token/..., Install-Client.ps1's -Token,
        # Install-ClientWinRM.ps1's -Token) is itself declared [string], so
        # the plain-text $answer from above is correct for them as-is.
        # -CredentialPassword on Install-ClientWinRM.ps1/
        # Uninstall-ClientWinRM.ps1 is the one exception: it is declared
        # [System.Security.SecureString] there, and $params is splatted
        # directly at that script - a plain [string] is rejected outright
        # with a ParameterBindingValidationException, since PowerShell has no
        # implicit string-to-SecureString conversion. This previously broke
        # every WinRM flow (menu options 3 and 6) the moment a real
        # credential password was typed - blank/default answers never hit it,
        # since they short-circuit via the check above and never reach here.
        # BindAsSecureString marks just those two question definitions below.
        if ($question.Type -eq 'SecureString' -and $question['BindAsSecureString']) {
            $params[$question.Name] = ConvertTo-SecureString -String $answer -AsPlainText -Force
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
        return $false
    }

    $confirm = Read-WizardAnswer -Prompt 'Proceed? [y/N]' -Default 'N'
    if ($confirm -notmatch '^(y|yes)$') {
        Write-Host 'Cancelled.'
        return $false
    }

    & $ScriptPath @Params
    return $true
}

# Printed only right after a genuinely successful quick install (not
# cancelled, not -WhatIf - see the main loop's $ran check below) - lists
# exactly what was left at its default and where to change it, so the
# admin never has to wonder whether something is actually configured.
# Values are read back from the same $Params the wizard itself resolved
# and passed to Install-Server.ps1, not re-derived separately.
function Show-QuickInstallSummary {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Params
    )

    $listenPrefix = if ($Params.ContainsKey('ListenPrefix')) { $Params['ListenPrefix'] } else { 'http://+:8080/' }
    $port = 8080
    if ($listenPrefix -match ':(\d+)/?$') {
        $port = [int]$Matches[1]
    }
    $firewallOpened = [bool]$Params['OpenFirewall']

    # Write-Output, not Write-Host: this function's output must flow
    # through the pipeline so it can be captured (e.g. via | Out-String in
    # tests) - it still prints to the console exactly as before when the
    # main loop calls it directly and doesn't capture the result.
    Write-Output ''
    Write-Output 'Server installed and started.'
    Write-Output "Dashboard:        http://localhost:$port/"
    Write-Output 'HTTPS:            disabled - enable via Settings > Server'
    Write-Output 'AD sync:          disabled - configure via Settings > Windows'
    Write-Output 'Ingestion token:  auto-generated - rotate it via Settings > Server > Ingestion Token (regenerate only, matching the Admin Password page - the current value is not shown there, but it can be viewed in plaintext on the Client package tab when building a package)'
    Write-Output 'Client package:   not built yet - build via the Client package tab'
    if ($firewallOpened) {
        Write-Output "Firewall:         opened for port $port"
    }
    else {
        Write-Output "Firewall:         not opened - see the Windows Firewall section in Settings if clients can't reach this server"
    }
}

# Gates whether the main loop shows the post-install summary: only a
# genuinely successful ($Ran) Quick-mode install should ever print it -
# Skip and Full both behave the same here (no summary). Extracted into its
# own function so this decision is directly unit-testable, since the main
# loop itself lives inside the `-ne '.'` guard below and is never reached
# by Pester's usual dot-source-and-call pattern.
function Test-ShouldShowQuickInstallSummary {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Ran,

        [Parameter(Mandatory = $true)]
        [string]$Mode
    )

    return ($Ran -and $Mode -eq 'Quick')
}

# Decides what params hashtable a flow should pass to its target script,
# given the resolved mode. Consolidates logic that used to be inlined
# directly in the main loop (see the loop's own history) into one small,
# directly-testable function - the main loop itself lives inside the
# `-ne '.'` guard below and is never reached by Pester's usual
# dot-source-and-call pattern, so any decision left inline there is
# otherwise only provable by hand-tracing.
function Resolve-WizardFlowParams {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [object[]]$Questions,

        [Parameter()]
        [hashtable]$SkipParams = @{}
    )

    if ($Mode -eq 'Skip') {
        return $SkipParams
    }

    $effectiveQuestions = if ($Mode -eq 'Quick') { @($Questions | Where-Object { $_['QuickInstall'] }) } else { $Questions }
    return Read-WizardAnswers -Questions $effectiveQuestions
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
        # A file that exists but can't be read or parsed is not the same
        # thing as no file at all - silently falling through to $null here
        # (the exact behavior a fresh install produces) previously made an
        # existing server look uninstalled, sending this flow into "Quick
        # install" instead of offering "just refresh"/"full reconfigure"
        # against the real config. By the time this runs the caller has
        # already confirmed the process is elevated, so a real read/parse
        # failure here is genuinely unexpected and should stop the wizard,
        # not be guessed away.
        throw "Failed to read server config at '$Path': $($_.Exception.Message)"
    }

    return $null
}

# Decides how the "Install server" flow should proceed, based on whether
# server-config.json already exists at the default location:
#   'Quick' - no existing config at all (a genuinely fresh install) - the
#             caller should ask only the QuickInstall-flagged questions
#             below and let Install-Server.ps1's own defaults handle
#             everything else.
#   'Skip'  - an existing config was found and the user picked "Just
#             refresh" - the caller should pass Install-Server.ps1 an
#             empty params hashtable (every parameter left unspecified
#             reloads its last-saved value, a genuine "no change" reapply).
#   'Full'  - an existing config was found and the user explicitly picked
#             "Full reconfigure" - the caller should ask every question in
#             $installServerQuestions, exactly as this flow has always
#             worked for that choice.
# Detection only checks the default config path (the same one
# Uninstall-Server.ps1 falls back to) - a server installed at a custom
# -ConfigPath won't be detected, same limitation as every other
# path-override this wizard doesn't ask about, and is treated as 'Quick'
# (behaves as a fresh install).
function Get-InstallServerMode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    $existingConfig = Read-WizardServerConfig -Path $ConfigPath
    if (-not $existingConfig) {
        return 'Quick'
    }

    Write-Host ''
    Write-Host "An existing server installation was detected ($ConfigPath)."
    Write-Host '1. Just refresh (recommended) - reapply current settings, no questions asked'
    Write-Host '2. Full reconfigure - re-answer every question from scratch'
    $updateChoice = Read-WizardAnswer -Prompt 'Choice' -Default '1'
    if ($updateChoice -eq '2') {
        return 'Full'
    }
    return 'Skip'
}

# Extracts one --flagname "value" pair's value out of a service binPath
# string, un-escaping the \" that ConvertTo-ServiceArgValue (in
# Install-Client.ps1 and Deploy-ClientGpo.ps1) would have escaped an
# embedded literal " into when the value was originally written. Returns
# $null if the flag isn't present at all - the caller decides whether
# that's fatal (ServerUrl) or fine (ServerSharePath/Token, both optional
# on the real command line).
function Get-BinPathFlagValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BinPath,

        [Parameter(Mandatory = $true)]
        [string]$FlagName
    )

    if ($BinPath -notmatch ([regex]::Escape($FlagName) + '\s+"((?:[^"\\]|\\.)*)"')) {
        return $null
    }
    return $Matches[1] -replace '\\"', '"'
}

# Thin wrapper around sc.exe, existing purely so Pester can mock it
# directly. Mocking sc.exe itself fails under Windows PowerShell 5.1
# with "Alias is not writeable because alias sc is read-only or
# constant and cannot be written to" - "sc" is a built-in, protected
# (ReadOnly, AllScope) alias for Set-Content on this PowerShell
# version, and Pester's mocking machinery for an external/application
# command collides with it. Mocking a plain function has no such
# problem.
function Invoke-ScExe {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & sc.exe @Arguments 2>&1
    return @{ Output = $output; ExitCode = $LASTEXITCODE }
}

# Reads a service's raw binPath via WMI (Win32_Service.PathName), the same
# way Deploy-ClientGpo.ps1's own Get-ServiceBinaryPath now does too -
# duplicated rather than shared, matching this project's established
# per-script convention. Deliberately NOT sc.exe qc + a regex on
# BINARY_PATH_NAME (the original approach here): that field label is
# localized by the OS's own display language, so the regex never matches
# on a non-English Windows host - confirmed missing entirely on a live
# Russian-language machine. WMI property names are stable regardless of
# OS language, so this can't silently fail the same way.
function Get-ClientServiceBinaryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $service = Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $service) {
        return $null
    }

    return $service.PathName
}

# Reads back the ingestion token currently set on the service's registry
# Environment value - same implementation as Deploy-ClientGpo.ps1's own
# Get-ServiceEnvironmentToken, duplicated rather than shared per this
# project's established per-script convention. Needed here because the
# token no longer appears in the binPath itself (it moved to this registry
# value - see Install-Client.ps1's own Set-ServiceEnvironmentToken):
# ConvertFrom-ClientBinPath's --token parsing below can never find it
# anymore, so Get-InstallClientMode calls this separately to recover the
# current token for its "Just refresh" reconstruction.
function Get-ServiceEnvironmentToken {
    param(
        [string]$ServiceName,
        [string]$ServiceRegistryRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    )

    $servicePath = Join-Path -Path $ServiceRegistryRoot -ChildPath $ServiceName
    $item = Get-ItemProperty -LiteralPath $servicePath -ErrorAction SilentlyContinue
    if (-not $item -or -not $item.PSObject.Properties['Environment']) {
        return ''
    }
    $environment = $item.Environment
    if (-not $environment) {
        return ''
    }
    foreach ($line in $environment) {
        if ($line -like 'WIL_INGESTION_TOKEN=*') {
            return $line.Substring('WIL_INGESTION_TOKEN='.Length)
        }
    }
    return ''
}

# Reverse-parses a WindowsInventoryLiteClient service's binPath back into
# the same named parameters Install-Client.ps1 accepts. Built to handle
# both real shapes this project produces: Install-Client.ps1's own
# Get-ClientServiceCommand (may include --share) and
# Deploy-ClientGpo.ps1's Get-DesiredServiceCommand (never includes
# --share) - both use identical --flag "value" syntax for everything
# else, so a flag-based (not position-based) parser handles both without
# special-casing either one. Returns $null when --server-url can't be
# found at all - the one value Install-Client.ps1 treats as strictly
# required, and the signal the caller uses to fall back to asking every
# question instead of trusting a malformed/unrecognized binPath.
function ConvertFrom-ClientBinPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BinPath
    )

    $serverUrl = Get-BinPathFlagValue -BinPath $BinPath -FlagName '--server-url'
    if (-not $serverUrl) {
        return $null
    }

    $params = @{ ServerUrl = $serverUrl }

    $sharePath = Get-BinPathFlagValue -BinPath $BinPath -FlagName '--share'
    if ($sharePath) {
        $params['ServerSharePath'] = $sharePath
    }

    # Kept for a pre-existing service installed before the ingestion token
    # moved off the command line into the service's registry Environment
    # value (see Install-Client.ps1's Set-ServiceEnvironmentToken) - a
    # binPath from that older install still has --token in it. A
    # current-shape binPath never will; Get-InstallClientMode separately
    # calls Get-ServiceEnvironmentToken to recover the token in that case,
    # since this function only ever sees the binPath string itself.
    $token = Get-BinPathFlagValue -BinPath $BinPath -FlagName '--token'
    if ($token) {
        $params['Token'] = $token
    }

    if ($BinPath -match '--interval-hours\s+(\d+)') {
        $params['IntervalHours'] = [int]$Matches[1]
    }

    # Matched separately, and unambiguously: the shorter '--interval-hours'
    # pattern above needs two literal dashes immediately before
    # 'interval-hours', which '--software-check-interval-hours' does not
    # provide (it has 'check-' there), so neither flag can capture the
    # other's value. Without this, a wizard-driven upgrade would silently
    # drop a customized software-check interval back to the default.
    if ($BinPath -match '--software-check-interval-hours\s+(\d+)') {
        $params['SoftwareCheckIntervalHours'] = [int]$Matches[1]
    }

    if ($BinPath -match '^"((?:[^"\\]|\\.)*)"') {
        $exePath = $Matches[1] -replace '\\"', '"'
        $installPath = Split-Path -Parent $exePath
        if ($installPath) {
            $params['InstallPath'] = $installPath
        }
    }

    return $params
}

# Decides how the "Install client (local)" flow should proceed, mirroring
# Get-InstallServerMode's shape:
#   Mode = 'Full' - no existing service, or its binPath doesn't parse (no
#                   -ServerUrl found) - the caller should ask every
#                   question in $installClientQuestions, exactly as this
#                   flow has always worked. Params is always @{}.
#   Mode = 'Skip' - an existing, parseable service was found and the user
#                   picked "Just refresh" - the caller should pass Params
#                   (the reconstructed hashtable) straight to
#                   Install-Client.ps1 with no questions asked. Unlike
#                   Install-Server.ps1, Install-Client.ps1 has no
#                   config-file-reload fallback of its own (-ServerUrl is
#                   Mandatory with nothing to fall back to) - so "just
#                   refresh" here must supply real reconstructed values,
#                   not an empty hashtable the way the server flow's own
#                   Skip mode does.
function Get-InstallClientMode {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $queryResult = Invoke-ScExe -Arguments @('query', $ServiceName)
    if ($queryResult.ExitCode -ne 0) {
        return @{ Mode = 'Full'; Params = @{} }
    }

    $binPath = Get-ClientServiceBinaryPath -ServiceName $ServiceName
    if (-not $binPath) {
        return @{ Mode = 'Full'; Params = @{} }
    }

    $parsedParams = ConvertFrom-ClientBinPath -BinPath $binPath
    if (-not $parsedParams) {
        return @{ Mode = 'Full'; Params = @{} }
    }

    # ConvertFrom-ClientBinPath can only recover a token from a pre-move
    # binPath (see its own comment) - a current-shape install never has one
    # there, since it lives in the service's registry Environment value
    # instead. Without this, "Just refresh" on a token-configured client
    # would call Install-Client.ps1 with no -Token, which unconditionally
    # calls Set-ServiceEnvironmentToken with an empty value and wipes the
    # existing token.
    if (-not $parsedParams.ContainsKey('Token')) {
        $currentToken = Get-ServiceEnvironmentToken -ServiceName $ServiceName
        if ($currentToken) {
            $parsedParams['Token'] = $currentToken
        }
    }

    Write-Host ''
    Write-Host 'An existing client installation was detected.'
    Write-Host '1. Just refresh (recommended) - reapply current settings, no questions asked'
    Write-Host '2. Full reconfigure - re-answer every question from scratch'
    $updateChoice = Read-WizardAnswer -Prompt 'Choice' -Default '1'
    if ($updateChoice -eq '2') {
        return @{ Mode = 'Full'; Params = @{} }
    }
    return @{ Mode = 'Skip'; Params = $parsedParams }
}

$installClientQuestions = @(
    @{ Name = 'ServerUrl'; Prompt = 'Server URL (e.g. https://server.domain.local/api/v1/inventory)'; Type = 'String'; Mandatory = $true }
    @{ Name = 'ServerSharePath'; Prompt = 'Server share path for client updates (leave blank to skip)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'Token'; Prompt = 'Inventory ingestion token (leave blank if the server has none configured)'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'IntervalHours'; Prompt = 'Collection interval in hours'; Type = 'Int'; Default = '6'; Mandatory = $false }
    @{ Name = 'SoftwareCheckIntervalHours'; Prompt = 'Software distribution check interval in hours'; Type = 'Int'; Default = '6'; Mandatory = $false }
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'NoRun'; Prompt = 'Skip starting the service immediately after install'; Type = 'Switch' }
)

$installServerQuestions = @(
    # Network
    @{ Name = 'ListenPrefix'; Prompt = 'Listen prefix'; Type = 'String'; Default = 'http://+:8080/'; Mandatory = $false; QuickInstall = $true }
    @{ Name = 'OpenFirewall'; Prompt = 'Open the Windows Firewall for the listen port(s)'; Type = 'Switch'; QuickInstall = $true }

    # HTTPS
    @{ Name = 'UseHttps'; Prompt = 'Enable HTTPS'; Type = 'Switch' }
    @{ Name = 'HttpsPort'; Prompt = 'HTTPS port (leave blank for default)'; Type = 'Int'; Mandatory = $false }
    @{ Name = 'CertificateThumbprint'; Prompt = 'Existing certificate thumbprint in LocalMachine\My (leave blank if importing a PFX instead)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'CertificatePfxPath'; Prompt = 'PFX file to import (leave blank if using an existing certificate)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'CertificatePfxPassword'; Prompt = 'PFX password (leave blank if not importing a PFX)'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'DisableHttp'; Prompt = 'Disable plain HTTP once HTTPS is confirmed working (refused unless HTTPS is enabled)'; Type = 'Switch' }

    # Basic Auth / dashboard access
    @{ Name = 'WebUsername'; Prompt = 'Dashboard username'; Type = 'String'; Mandatory = $false; QuickInstall = $true }
    @{ Name = 'WebPassword'; Prompt = 'Dashboard password'; Type = 'SecureString'; Mandatory = $false; QuickInstall = $true }
    @{ Name = 'Token'; Prompt = 'Inventory ingestion token (leave blank to auto-generate)'; Type = 'SecureString'; Mandatory = $false }

    # Active Directory identity - configures the domain/credentials used by
    # Client actions, Client updates, and AD Computer Import. Description
    # sync itself is a separate, dashboard-only toggle (Sync Description
    # from AD) that isn't exposed here - on a fresh install it simply
    # inherits whatever this switch is set to.
    @{ Name = 'AdSyncEnabled'; Prompt = 'Configure AD User (domain/credentials for Client actions, Client updates, and AD Computer Import)'; Type = 'Switch' }
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
    @{ Name = 'SoftwareCheckIntervalHours'; Prompt = 'Software-distribution job poll interval in hours'; Type = 'Int'; Default = '6'; Mandatory = $false }
    @{ Name = 'CredentialUsername'; Prompt = 'Credential username (leave blank to use current user context)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'CredentialPassword'; Prompt = 'Credential password (leave blank to use current user context)'; Type = 'SecureString'; Mandatory = $false; BindAsSecureString = $true }
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
    @{ Name = 'CredentialPassword'; Prompt = 'Credential password (leave blank to use current user context)'; Type = 'SecureString'; Mandatory = $false; BindAsSecureString = $true }
    @{ Name = 'AddToTrustedHosts'; Prompt = 'Add target computers to WinRM TrustedHosts (needed for non-domain-joined or workgroup targets)'; Type = 'Switch' }
)

# [ordered]@{...} is a PS3.0+ syntax construct - not available on real
# PS2.0 despite this script's own "#requires -Version 2.0" declaration
# (confirmed against a genuine Windows 7/PS2.0 fleet machine). Building the
# same System.Collections.Specialized.OrderedDictionary via New-Object/.Add
# is the PS2.0-compatible equivalent; Show-WizardMenu already declares that
# exact type on its -Flows parameter and enumerates .Keys in insertion
# order to print the menu "1. Install server" .. "6. ...", so the ordering
# is load-bearing, not cosmetic.
$flows = New-Object System.Collections.Specialized.OrderedDictionary
$flows.Add('1', @{
        Label        = 'Install server'
        ScriptName   = 'Install-Server.ps1'
        Questions    = $installServerQuestions
        SecretParams = @('WebPassword', 'Token', 'CertificatePfxPassword', 'AdPassword')
    })
$flows.Add('2', @{
        Label        = 'Install client (local)'
        ScriptName   = 'Install-Client.ps1'
        Questions    = $installClientQuestions
        SecretParams = @('Token')
    })
$flows.Add('3', @{
        Label        = 'Deploy client to remote machines (WinRM)'
        ScriptName   = 'Install-ClientWinRM.ps1'
        Questions    = $installClientWinRMQuestions
        SecretParams = @('Token', 'CredentialPassword')
    })
$flows.Add('4', @{
        Label        = 'Uninstall server'
        ScriptName   = 'Uninstall-Server.ps1'
        Questions    = $uninstallServerQuestions
        SecretParams = @()
    })
$flows.Add('5', @{
        Label        = 'Uninstall client (local)'
        ScriptName   = 'Uninstall-Client.ps1'
        Questions    = $uninstallClientQuestions
        SecretParams = @()
    })
$flows.Add('6', @{
        Label        = 'Uninstall client (remote, WinRM)'
        ScriptName   = 'Uninstall-ClientWinRM.ps1'
        Questions    = $uninstallClientWinRMQuestions
        SecretParams = @('CredentialPassword')
    })

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
    if (-not (Test-IsElevatedAdmin)) {
        throw 'This script must be run from an elevated (Run as Administrator) PowerShell session.'
    }

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

        # "Install server" and "Install client (local)" are the only two
        # flows that distinguish Quick/Skip/Full - see Get-InstallServerMode
        # and Get-InstallClientMode for what each means for its own flow.
        # Every other flow keeps asking its full question list, unaffected
        # ($mode stays 'Full', $skipParams stays empty and unused).
        $mode = 'Full'
        $skipParams = @{}
        if ($choice -eq '1') {
            $defaultConfigPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-config.json'
            $mode = Get-InstallServerMode -ConfigPath $defaultConfigPath
        }
        elseif ($choice -eq '2') {
            $clientMode = Get-InstallClientMode -ServiceName 'WindowsInventoryLiteClient'
            $mode = $clientMode.Mode
            $skipParams = $clientMode.Params
        }

        $params = Resolve-WizardFlowParams -Mode $mode -Questions $flow.Questions -SkipParams $skipParams
        $ran = Invoke-WizardAction -ScriptPath $scriptPath -ScriptName $flow.ScriptName -Params $params -SecretParams $flow.SecretParams
        if (Test-ShouldShowQuickInstallSummary -Ran $ran -Mode $mode) {
            Show-QuickInstallSummary -Params $params
        }
    }
}
