# Installer Experience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an interactive console wizard (`Install-Wizard.ps1`) covering all 6 install/uninstall actions (install server, install client locally, deploy client remotely via WinRM, uninstall server, uninstall client locally, uninstall client remotely via WinRM), plus a new `Uninstall-Server.ps1` script that didn't exist before, so someone unfamiliar with the project can use the tool without knowing which of the 5 underlying scripts to run or which of their combined 58 parameters to pass.

**Architecture:** The wizard is a thin, purely additive orchestration layer. It never duplicates install/uninstall logic: it asks a fixed, curated sequence of questions per action (a data-driven array of question specs, not hand-written `Read-Host` calls per parameter), builds a parameter hashtable, shows the fully-resolved equivalent command line for confirmation (secrets redacted), and on confirmation invokes the existing target script via splatting (`& $scriptPath @params`). None of the 5 existing scripts are modified — their flag-based non-interactive invocation is completely unaffected. All prompting goes through one mockable primitive (`Read-WizardAnswer`) and the final invocation step uses the standard PowerShell `SupportsShouldProcess`/`-WhatIf` idiom (already used by `Uninstall-Client.ps1` in this codebase), which doubles as the wizard's dry-run mode and its Pester test seam.

**Tech Stack:** PowerShell 5.1-compatible (no PS7-only syntax), no new dependencies — matches every other script in this project.

## Global Constraints

- No changes to the 5 existing scripts (`Install-Server.ps1`, `Install-Client.ps1`, `Install-ClientWinRM.ps1`, `Uninstall-Client.ps1`, `Uninstall-ClientWinRM.ps1`) — the wizard only calls them, never edits their logic or parameters. Flag-based non-interactive invocation of all 5 must keep working exactly as today.
- Passwords (`WebPassword`, `Token`, `CertificatePfxPassword`, `AdPassword`, `CredentialPassword`) are collected via masked input (`Read-Host -AsSecureString`, converted to plaintext only in memory, matching how the underlying scripts already consume these values as plain strings) and are never printed in cleartext anywhere, including the confirmation screen (shown as `(hidden)`).
- **Corrected parameter count found during plan research:** the design spec quoted `Install-Server.ps1` as having 31 parameters and `Install-ClientWinRM.ps1` as having 10 — a manual miscount during brainstorming. The actual counts are 33 and 12 respectively (verified by reading the full `param()` blocks for this plan). Corrected in the design spec too; does not change any design decision, only the exact numbers below.
- **Deliberate scope narrowing for `Install-Server.ps1`'s question set (documented, not silent):** of its 33 parameters, 11 are power-user path/file overrides with sensible runtime-computed defaults (`DataPath`, `InstallPath`, `ContentPath`, `ClientPackagePath`, `ClientPackageSourcePath`, `ConfigPath`, `ServerExecutablePath`, `ClientNet35ExecutablePath`, `ClientNet40ExecutablePath`, `PackageSharePath`, `DebugLogPath`) that a first-time administrator following a wizard would not typically need to specify. The wizard asks about the remaining 22 (network, HTTPS, Basic Auth, AD sync, client package/GPO, logging, and whether to start the service immediately) and leaves the 11 path overrides to the target script's own defaults. Same principle applies to `Install-Client.ps1`'s `ClientExecutablePath` and `Install-ClientWinRM.ps1`'s `PackagePath`/`RemotePackagePath` (already has a literal default) and `KeepRemotePackage` (a debugging aid) — excluded from their respective interactive question sets for the same reason.
- PowerShell 5.1 compatible: no ternary operator, no null-coalescing (`??`), no `ForEach-Object -Parallel`, matching every other script in this project (verified by the existing `tests/ScriptSyntax.Tests.ps1` checks, which this plan's new scripts must also pass).
- Every task needs real verification evidence (Pester run, and for the wizard, a `-WhatIf` dry-run showing the resolved command), not just claimed.
- MINOR version bump required (new feature, per this workspace's versioning rule) in the final task — confirm the actual current version via `grep` before assuming a value.

---

### Task 1: New `Uninstall-Server.ps1`

**Files:**
- Create: `src/Uninstall-Server.ps1`

**Interfaces:**
- Consumes: nothing new — reuses the exact `Get-ConfigValue`/`Read-ServerConfig` pattern already defined in `src/Install-Server.ps1` (copied, since these scripts don't share a module — matches how `Invoke-ServiceControl`/`Wait-FileRelease` are already duplicated between `Install-Server.ps1` and `Install-Client.ps1` in this codebase).
- Produces: `Uninstall-Server.ps1 [-ConfigPath <string>] [-RemoveData] [-WhatIf] [-Confirm]` — Task 6 of this plan wires this into the wizard's "Uninstall server" flow.

This is a standalone, directly-runnable script — no dependency on the wizard. It must work exactly like running any of this project's existing scripts non-interactively.

- [ ] **Step 1: Write `Uninstall-Server.ps1`**

```powershell
#requires -Version 2.0

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ConfigPath,

    [Parameter()]
    [switch]$RemoveData
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-ConfigValue {
    param(
        [object]$Config,
        [string]$Name
    )

    if ($Config -and $Config.ContainsKey($Name)) {
        return $Config[$Name]
    }

    return $null
}

function Read-ServerConfig {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return @{}
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

    return @{}
}

if (-not $ConfigPath) {
    $ConfigPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-config.json'
}

$existingConfig = Read-ServerConfig -Path $ConfigPath

$installPath = Get-ConfigValue -Config $existingConfig -Name 'InstallPath'
if (-not $installPath) {
    $installPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-bin'
}

$dataPath = Get-ConfigValue -Config $existingConfig -Name 'DataPath'
if (-not $dataPath) {
    $dataPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-data'
}

$contentPath = Get-ConfigValue -Config $existingConfig -Name 'ContentPath'
if (-not $contentPath) {
    $contentPath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\server-content'
}

$clientPackagePath = Get-ConfigValue -Config $existingConfig -Name 'ClientPackagePath'
if (-not $clientPackagePath) {
    $clientPackagePath = Join-Path -Path $env:ProgramData -ChildPath 'WindowsInventoryLite\client-package'
}

$certificateThumbprint = Get-ConfigValue -Config $existingConfig -Name 'CertificateThumbprint'

$serviceName = 'WindowsInventoryLite'
$null = & sc.exe query $serviceName 2>&1
if ($LASTEXITCODE -eq 0 -and $PSCmdlet.ShouldProcess($serviceName, 'Stop and delete service')) {
    & sc.exe stop $serviceName | Out-Null
    & sc.exe delete $serviceName | Out-Null
    Start-Sleep -Seconds 2
}

# netsh silently no-ops when a named rule doesn't exist (prints "No rules
# match the specified criteria" without a nonzero exit code we could rely
# on), so this always attempts the delete rather than probing first - safe
# either way since & calls don't participate in $ErrorActionPreference.
foreach ($ruleName in @('Windows Inventory Lite Server (HTTP)', 'Windows Inventory Lite Server (HTTPS)')) {
    if ($PSCmdlet.ShouldProcess($ruleName, 'Remove firewall rule if present')) {
        & netsh.exe advfirewall firewall delete rule name="$ruleName" | Out-Null
    }
}

foreach ($path in @($installPath, $contentPath, $clientPackagePath)) {
    if ((Test-Path -LiteralPath $path) -and $PSCmdlet.ShouldProcess($path, 'Remove directory')) {
        Remove-Item -LiteralPath $path -Recurse -Force
    }
}

if ($RemoveData) {
    if ((Test-Path -LiteralPath $dataPath) -and $PSCmdlet.ShouldProcess($dataPath, 'Remove inventory data')) {
        Remove-Item -LiteralPath $dataPath -Recurse -Force
    }
    if ((Test-Path -LiteralPath $ConfigPath) -and $PSCmdlet.ShouldProcess($ConfigPath, 'Remove server configuration')) {
        Remove-Item -LiteralPath $ConfigPath -Force
    }
}
else {
    Write-Host "Inventory data preserved at: $dataPath"
    Write-Host "Server configuration preserved at: $ConfigPath"
}

if ($certificateThumbprint) {
    Write-Host "A certificate may have been imported into LocalMachine\My by this server (thumbprint $certificateThumbprint)."
    Write-Host "It was not removed automatically - it may be used by other services on this host."
    Write-Host "To remove it manually: Remove-Item Cert:\LocalMachine\My\$certificateThumbprint"
}

Write-Host "Server removed."
```

- [ ] **Step 2: Add to the Pester syntax/encoding check**

Find this in `tests/ScriptSyntax.Tests.ps1`:

```powershell
            'src\Install-Server.ps1',
            'deploy\client\Deploy-ClientGpo.ps1',
```

Replace with:

```powershell
            'src\Install-Server.ps1',
            'src\Uninstall-Server.ps1',
            'deploy\client\Deploy-ClientGpo.ps1',
```

(This adds it to the parse-check list only — the English-only/no-Cyrillic and no-PS7-syntax checks already run recursively over `src/` and pick up the new file automatically, no change needed there.)

- [ ] **Step 3: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass, including the new script now being parse-checked.

- [ ] **Step 4: Live-verify against a real install**

From a scratch directory (do not touch any real installed server), build the server, install it, then uninstall it and confirm both preserve-data and remove-data paths work:

```bash
powershell -NoProfile -Command "& '.\src\Build-Server.ps1'"
mkdir -p /tmp/wil-uninstall-server-test
powershell -NoProfile -Command "& '.\src\Install-Server.ps1' -DataPath 'C:\wil-uninstall-server-test\data' -InstallPath 'C:\wil-uninstall-server-test\bin' -ContentPath 'C:\wil-uninstall-server-test\content' -ClientPackagePath 'C:\wil-uninstall-server-test\client-package' -ConfigPath 'C:\wil-uninstall-server-test\server-config.json' -NoRun"
```

Confirm the service `WindowsInventoryLite` exists (`sc.exe query WindowsInventoryLite`), then:

```bash
powershell -NoProfile -Command "& '.\src\Uninstall-Server.ps1' -ConfigPath 'C:\wil-uninstall-server-test\server-config.json'"
```

Confirm: the service is gone (`sc.exe query WindowsInventoryLite` now fails), `bin`/`content`/`client-package` directories are removed, `data` directory and `server-config.json` are still present (default preserve-data behavior). Then re-install the same way and run with `-RemoveData`:

```bash
powershell -NoProfile -Command "& '.\src\Uninstall-Server.ps1' -ConfigPath 'C:\wil-uninstall-server-test\server-config.json' -RemoveData"
```

Confirm the `data` directory and `server-config.json` are now also removed. Clean up:

```bash
rm -rf /tmp/wil-uninstall-server-test 'C:\wil-uninstall-server-test'
```

- [ ] **Step 5: Commit**

```bash
git add src/Uninstall-Server.ps1 tests/ScriptSyntax.Tests.ps1
git commit -m "Add Uninstall-Server.ps1"
```

---

### Task 2: Wizard scaffolding + "Uninstall client (local)" flow

**Files:**
- Create: `src/Install-Wizard.ps1`

**Interfaces:**
- Consumes: `src/Uninstall-Client.ps1` (existing, unchanged).
- Produces: `Read-WizardAnswer`, `Read-WizardAnswers`, `Format-WizardCommand`, `Invoke-WizardAction` — Tasks 3-6 each add one more flow's question-spec array and one more `$flows` entry to this same file, reusing these four functions unchanged.

This task proves the whole mechanism end-to-end with the smallest possible flow (`Uninstall-Client.ps1` has exactly one optional parameter) before the later tasks add bigger, more complex flows on top of the same scaffolding.

- [ ] **Step 1: Write the wizard scaffolding and the "Uninstall client (local)" flow**

```powershell
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
# ready to splat at the target script. Types: String, SecureString, Int,
# StringArray (comma-separated), ValidateSet (shows Choices, falls back to
# Default with a warning on an invalid answer rather than re-prompting -
# acceptable since every ValidateSet question in this plan has a safe
# default), Switch (its own y/N sub-prompt, never inherits -Default from
# the spec). Skips adding a key when the answer is empty-and-optional or
# equals the displayed default - lets the target script's own default
# apply rather than redundantly passing an identical value.
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
            $promptText += ' (' + ($question.Choices -join '/') + ')'
        }

        $answer = Read-WizardAnswer -Prompt $promptText -Default $question.Default -Mandatory:([bool]$question.Mandatory) -Secure:($question.Type -eq 'SecureString')
        if ($null -eq $answer -or $answer -eq $question.Default) {
            continue
        }

        if ($question.Type -eq 'ValidateSet' -and $question.Choices -notcontains $answer) {
            Write-Host "Invalid choice. Using default: $($question.Default)" -ForegroundColor Yellow
            continue
        }

        $params[$question.Name] = switch ($question.Type) {
            'Int' { [int]$answer }
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

$uninstallClientQuestions = @(
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
)

$flows = [ordered]@{
    '5' = @{
        Label        = 'Uninstall client (local)'
        ScriptName   = 'Uninstall-Client.ps1'
        Questions    = $uninstallClientQuestions
        SecretParams = @()
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
        $params = Read-WizardAnswers -Questions $flow.Questions
        Invoke-WizardAction -ScriptPath $scriptPath -ScriptName $flow.ScriptName -Params $params -SecretParams $flow.SecretParams
    }
}
```

Note: the `if ($MyInvocation.InvocationName -ne '.')` guard around the menu loop lets Task 7's Pester tests dot-source this file (`. $wizardScriptPath`) to get access to the functions and the `$flows` table without immediately entering the interactive `while` loop - a standard PowerShell script-as-library-or-entry-point pattern. The menu keys are deliberately pre-assigned as `'5'` here (matching this flow's final position in the full 6-item menu built up across Tasks 2-6) rather than renumbered - each task adds its own entry with its own final key, avoiding needless renumbering churn across tasks.

- [ ] **Step 2: Add to the Pester syntax/encoding check**

Find this in `tests/ScriptSyntax.Tests.ps1` (this is the same list Task 1 already added `Uninstall-Server.ps1` to):

```powershell
            'src\Install-Server.ps1',
            'src\Uninstall-Server.ps1',
            'deploy\client\Deploy-ClientGpo.ps1',
```

Replace with:

```powershell
            'src\Install-Server.ps1',
            'src\Uninstall-Server.ps1',
            'src\Install-Wizard.ps1',
            'deploy\client\Deploy-ClientGpo.ps1',
```

- [ ] **Step 3: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 4: Live-verify the scaffolding end to end with `-WhatIf`**

```powershell
powershell -NoProfile -Command "& '.\src\Install-Wizard.ps1' -WhatIf"
```

At the menu, type `5`, press Enter at the `InstallPath` prompt (leave blank), confirm the output shows:
```
The following command will run:
  Uninstall-Client.ps1
```
(no `-InstallPath` since it was left blank) and that the script returns to the menu rather than actually running `Uninstall-Client.ps1` (nothing gets uninstalled - safe to run against a machine with no client installed at all, since `-WhatIf` guarantees the target script is never invoked). Type `0` to exit.

- [ ] **Step 5: Commit**

```bash
git add src/Install-Wizard.ps1 tests/ScriptSyntax.Tests.ps1
git commit -m "Add Install-Wizard.ps1 scaffolding and the Uninstall client (local) flow"
```

---

### Task 3: "Install client (local)" flow

**Files:**
- Modify: `src/Install-Wizard.ps1`

**Interfaces:**
- Consumes: `Read-WizardAnswers`/`Invoke-WizardAction` (Task 2, unchanged), `src/Install-Client.ps1` (existing, unchanged).
- Produces: nothing new.

- [ ] **Step 1: Add the question spec and `$flows` entry**

Find this in `src/Install-Wizard.ps1`:

```powershell
$uninstallClientQuestions = @(
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
)

$flows = [ordered]@{
    '5' = @{
        Label        = 'Uninstall client (local)'
        ScriptName   = 'Uninstall-Client.ps1'
        Questions    = $uninstallClientQuestions
        SecretParams = @()
    }
}
```

Replace with:

```powershell
$installClientQuestions = @(
    @{ Name = 'ServerUrl'; Prompt = 'Server URL (e.g. https://server.domain.local/api/v1/inventory)'; Type = 'String'; Mandatory = $true }
    @{ Name = 'ServerSharePath'; Prompt = 'Server share path for client updates (leave blank to skip)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'Token'; Prompt = 'Inventory ingestion token (leave blank if the server has none configured)'; Type = 'SecureString'; Mandatory = $false }
    @{ Name = 'IntervalHours'; Prompt = 'Collection interval in hours'; Type = 'Int'; Default = '6'; Mandatory = $false }
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
    @{ Name = 'NoRun'; Prompt = 'Skip starting the service immediately after install'; Type = 'Switch' }
)

$uninstallClientQuestions = @(
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
)

$flows = [ordered]@{
    '2' = @{
        Label        = 'Install client (local)'
        ScriptName   = 'Install-Client.ps1'
        Questions    = $installClientQuestions
        SecretParams = @('Token')
    }
    '5' = @{
        Label        = 'Uninstall client (local)'
        ScriptName   = 'Uninstall-Client.ps1'
        Questions    = $uninstallClientQuestions
        SecretParams = @()
    }
}
```

- [ ] **Step 2: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 3: Live-verify with `-WhatIf`**

```powershell
powershell -NoProfile -Command "& '.\src\Install-Wizard.ps1' -WhatIf"
```

Type `2`, answer `ServerUrl` with `https://example.local/api/v1/inventory`, leave everything else blank. Confirm the resolved command shows:
```
Install-Client.ps1 -ServerUrl 'https://example.local/api/v1/inventory'
```
(no other flags, since everything else was left blank). Then run it again and this time answer `Token` with some test value - confirm the resolved command shows `-Token '(hidden)'`, not the real value. Type `0` to exit both times.

- [ ] **Step 4: Commit**

```bash
git add src/Install-Wizard.ps1
git commit -m "Add Install client (local) flow to the wizard"
```

---

### Task 4: "Deploy client to remote machines (WinRM)" flow

**Files:**
- Modify: `src/Install-Wizard.ps1`

**Interfaces:**
- Consumes: `Read-WizardAnswers`/`Invoke-WizardAction` (Task 2, unchanged - this is the first flow to exercise the `StringArray` question type for `ComputerName`), `src/Install-ClientWinRM.ps1` (existing, unchanged).
- Produces: nothing new.

- [ ] **Step 1: Add the question spec and `$flows` entry**

Find this in `src/Install-Wizard.ps1`:

```powershell
$flows = [ordered]@{
    '2' = @{
        Label        = 'Install client (local)'
        ScriptName   = 'Install-Client.ps1'
        Questions    = $installClientQuestions
        SecretParams = @('Token')
    }
    '5' = @{
```

Replace with:

```powershell
$flows = [ordered]@{
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
    '5' = @{
```

Find this (immediately above the `$flows` declaration, right after `$installClientQuestions`):

```powershell
$uninstallClientQuestions = @(
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
)
```

Replace with:

```powershell
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

$uninstallClientQuestions = @(
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
)
```

Note: `PackagePath`, `RemotePackagePath`, and `KeepRemotePackage` are deliberately excluded from this question set for the same reason given in this plan's Global Constraints - `PackagePath` and `RemotePackagePath` already have sensible computed/literal defaults a first-time admin doesn't need to override, and `KeepRemotePackage` is a debugging aid, not a first-run decision.

- [ ] **Step 2: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 3: Live-verify with `-WhatIf`**

```powershell
powershell -NoProfile -Command "& '.\src\Install-Wizard.ps1' -WhatIf"
```

Type `3`, answer `ComputerName` with `PC1, PC2` (comma-separated, with a space to confirm the split handles that), `ServerUrl` with a test URL, leave the rest blank. Confirm the resolved command shows both computer names correctly split and quoted, e.g.:
```
Install-ClientWinRM.ps1 -ComputerName 'PC1' 'PC2' -ServerUrl '...'
```
(the exact array rendering from `Format-WizardCommand`'s string interpolation of an array value is acceptable as-is - this is a display-only confirmation screen, not the actual invocation, which correctly passes a real `[string[]]` via splatting regardless of how it's displayed). Type `0` to exit.

- [ ] **Step 4: Commit**

```bash
git add src/Install-Wizard.ps1
git commit -m "Add Deploy client to remote machines (WinRM) flow to the wizard"
```

---

### Task 5: "Install server" flow

**Files:**
- Modify: `src/Install-Wizard.ps1`

**Interfaces:**
- Consumes: `Read-WizardAnswers`/`Invoke-WizardAction` (Task 2, unchanged - this flow exercises every question `Type` the scaffolding supports, including `ValidateSet` for `AdSyncMode`), `src/Install-Server.ps1` (existing, unchanged).
- Produces: nothing new.

This is the largest single flow (22 questions, out of `Install-Server.ps1`'s 33 total parameters - see this plan's Global Constraints for which 11 are deliberately excluded and why).

- [ ] **Step 1: Add the question spec and `$flows` entry**

Find this in `src/Install-Wizard.ps1`:

```powershell
$installClientWinRMQuestions = @(
```

Replace with:

```powershell
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
```

Find this:

```powershell
$flows = [ordered]@{
    '2' = @{
```

Replace with:

```powershell
$flows = [ordered]@{
    '1' = @{
        Label        = 'Install server'
        ScriptName   = 'Install-Server.ps1'
        Questions    = $installServerQuestions
        SecretParams = @('WebPassword', 'Token', 'CertificatePfxPassword', 'AdPassword')
    }
    '2' = @{
```

- [ ] **Step 2: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 3: Live-verify with `-WhatIf`**

```powershell
powershell -NoProfile -Command "& '.\src\Install-Wizard.ps1' -WhatIf"
```

Type `1`, leave every question blank except: answer `y` to `AdSyncEnabled`'s switch prompt, then leave `AdSyncMode` blank (should resolve to the default, not appear in the printed command), then answer `WebPassword` with a test value. Confirm the resolved command:
- Shows `-AdSyncEnabled` (a bare switch, no value).
- Does NOT show `-AdSyncMode` at all (left at its default).
- Shows `-WebPassword '(hidden)'`, never the real value.
- Shows no other flags (everything else was left blank).

Run it again, this time typing an invalid value at the `AdSyncMode` prompt (e.g. `bogus`) - confirm the wizard prints the "Invalid choice. Using default" warning and the resolved command still doesn't include `-AdSyncMode`. Type `0` to exit both times.

- [ ] **Step 4: Commit**

```bash
git add src/Install-Wizard.ps1
git commit -m "Add Install server flow to the wizard"
```

---

### Task 6: "Uninstall server" and "Uninstall client (remote, WinRM)" flows

**Files:**
- Modify: `src/Install-Wizard.ps1`

**Interfaces:**
- Consumes: `Read-WizardAnswers`/`Invoke-WizardAction` (Task 2, unchanged), `src/Uninstall-Server.ps1` (Task 1, unchanged), `src/Uninstall-ClientWinRM.ps1` (existing, unchanged).
- Produces: nothing new. This is the last flow-adding task - after this, all 6 menu entries (`'1'` through `'6'`) exist.

- [ ] **Step 1: Add both question specs and both `$flows` entries**

Find this in `src/Install-Wizard.ps1`:

```powershell
$uninstallClientQuestions = @(
    @{ Name = 'InstallPath'; Prompt = 'Client install path (leave blank for default)'; Type = 'String'; Mandatory = $false }
)
```

Replace with:

```powershell
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
```

Find this:

```powershell
    '5' = @{
        Label        = 'Uninstall client (local)'
        ScriptName   = 'Uninstall-Client.ps1'
        Questions    = $uninstallClientQuestions
        SecretParams = @()
    }
}
```

Replace with:

```powershell
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
```

- [ ] **Step 2: Run the Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass.

- [ ] **Step 3: Live-verify with `-WhatIf`**

```powershell
powershell -NoProfile -Command "& '.\src\Install-Wizard.ps1' -WhatIf"
```

Confirm the menu now shows all 6 items in order (1-6) plus `0. Exit`. Type `4`, answer `y` to the data-removal question - confirm the resolved command shows `Uninstall-Server.ps1 -RemoveData`. Type `6`, answer `ComputerName` with a test value, leave the rest blank - confirm the resolved command shows `Uninstall-ClientWinRM.ps1 -ComputerName 'TESTPC'`. Type `0` to exit.

- [ ] **Step 4: Commit**

```bash
git add src/Install-Wizard.ps1
git commit -m "Add Uninstall server and Uninstall client (remote, WinRM) flows to the wizard"
```

---

### Task 7: Pester Mock tests, README update, version bump, final verification

**Files:**
- Modify: `tests/ScriptSyntax.Tests.ps1` (new `Install-Wizard.Tests.ps1` file, not an edit to this one - see Step 1)
- Create: `tests/Install-Wizard.Tests.ps1`
- Modify: `README.md`, `README_RU.md`
- Modify: `src/server/WindowsInventoryLiteServer.cs`, `src/client/WindowsInventoryLiteClient.cs` (`Program.ProductVersion`)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Write `tests/Install-Wizard.Tests.ps1`**

One test per menu flow (6 total), each mocking `Read-WizardAnswer` with a canned sequence of return values, running the corresponding flow with `-WhatIf`, and asserting the resolved command via a captured `Write-Host` output or by directly testing `Format-WizardCommand`/`Read-WizardAnswers` with the same canned answers (simpler and more robust than capturing console output - test the units, not the printed text):

```powershell
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
}
```

- [ ] **Step 2: Run the new tests directly to confirm they pass in isolation**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests\Install-Wizard.Tests.ps1 -Output Detailed`
Expected: all 7 `It` blocks pass.

- [ ] **Step 3: Run the full Pester suite**

Run: `Import-Module Pester -MinimumVersion 5.0 -Force; Invoke-Pester -Path .\tests -Output Detailed`
Expected: all tests pass, including the new `Install-Wizard.Tests.ps1` file alongside the existing suites.

- [ ] **Step 4: Add a README section**

In `README.md`, find the `## Server Installation` heading and add a new subsection immediately before it:

```markdown
## Interactive Install Wizard

For a first-time setup, run `src/Install-Wizard.ps1` with no parameters for a menu-driven walkthrough of installing or removing the server, a local client, or clients on remote machines via WinRM - it asks one question at a time and shows the exact command it's about to run before doing anything. Everyone else can keep using the flag-based scripts below directly; the wizard only calls them, it doesn't replace them.

Use `-WhatIf` to walk through the questions and see the resolved command without actually running anything.
```

In `README_RU.md`, find the equivalent Russian section (`## Установка сервера` or its local heading) and add the natural Russian equivalent, matching this file's existing tone and terminology (not a literal translation) - read the surrounding sections first to match established terms for "мастер"/"установка"/etc. if this file already uses them elsewhere.

- [ ] **Step 5: Bump the version**

Run: `grep -n "ProductVersion = " src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs` to confirm the current version (expected `"0.12.0"` as of this plan's writing - if it differs, bump a MINOR version from the actual current value instead). Update both to the next MINOR version (patch reset to 0) - identical value in both files.

- [ ] **Step 6: Add the CHANGELOG entry**

Add a new `## [<new-version>] - 2026-07-17` section at the top of `CHANGELOG.md`, after `## [Unreleased]`, matching the file's existing entry format:

```markdown
### Added

- `Install-Wizard.ps1` - an interactive console menu covering all install/uninstall actions (server, local client, remote client via WinRM, and their uninstalls), for administrators unfamiliar with the project's flag-based scripts. Supports `-WhatIf` to preview the resolved command before running anything.
- `Uninstall-Server.ps1` - previously only client-side uninstall scripts existed; this adds the missing server-side counterpart. Preserves inventory data and configuration by default; `-RemoveData` opts into full removal.
```

- [ ] **Step 7: Full rebuild and verification**

```powershell
.\src\Build-Server.ps1
.\src\Build-Client.ps1 -TargetFramework Net35 -OutputPath '.\build\WindowsInventoryLiteClient-net35.exe'
.\src\Build-Client.ps1 -TargetFramework Net40 -OutputPath '.\build\WindowsInventoryLiteClient-net40.exe'
.\build\WindowsInventoryLiteServer.exe --self-test
Import-Module Pester -MinimumVersion 5.0 -Force
Invoke-Pester -Path .\tests -Output Detailed
.\build\WindowsInventoryLiteServer.exe --version
```

Expected: all three builds succeed, self-test suite all `PASS` with exit code 0 (this version bump touches no self-test-relevant code, so the count should be unchanged from before this task), Pester all green (now including `Install-Wizard.Tests.ps1`'s 7 `It` blocks), printed version matches the new bumped value.

- [ ] **Step 8: Final combined live verification**

Using the full 6-flow wizard, in one session, confirm the menu shows all 6 correctly-labeled items in order, and spot-check two flows end-to-end with `-WhatIf` (one install flow, one uninstall flow) to confirm the whole thing reads naturally as a first-time user would experience it - not just individually-correct fragments.

- [ ] **Step 9: Commit**

```bash
git add tests/Install-Wizard.Tests.ps1 README.md README_RU.md src/server/WindowsInventoryLiteServer.cs src/client/WindowsInventoryLiteClient.cs CHANGELOG.md
git commit -m "Add wizard tests, docs, and bump version for Installer Experience"
```
