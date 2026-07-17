# Design: Installer Experience

Status: approved, ready for implementation planning
Date: 2026-07-17

## Purpose

`windows-inventory-lite` is administered entirely through flag-based PowerShell scripts: `Install-Server.ps1` (31 parameters covering network, HTTPS/certificate, Basic Auth, AD sync, logging), `Install-Client.ps1` (6 parameters), `Install-ClientWinRM.ps1` (10 parameters, remote deployment to multiple machines), and `Uninstall-Client.ps1`/`Uninstall-ClientWinRM.ps1`. This is workable for someone who already knows the project, but not for "any person unfamiliar with the project," as originally requested. This design adds an interactive console wizard that walks a first-time administrator through installing or removing any part of the system without needing to already know which script or which flags to use.

## Scope

In scope:
- A new `Install-Wizard.ps1` entry-point script presenting a menu of 6 actions (install server, install client locally, deploy client remotely via WinRM, uninstall server, uninstall client locally, uninstall client remotely via WinRM), interactively collecting the parameters each underlying action needs, then invoking the corresponding existing script.
- A new `Uninstall-Server.ps1` script — this did not exist before (only client-side uninstall scripts exist today). Mirrors the existing `Uninstall-Client.ps1`'s pattern (`SupportsShouldProcess`, `sc.exe stop`/`sc.exe delete`).
- Adding both new scripts to the existing `tests/ScriptSyntax.Tests.ps1` checks (parse validation, English-only/no-PS7-syntax checks already run recursively over `src/`).
- A `Mock`-testable answer-collection seam and a `-WhatIf` dry-run mode on the wizard, both existing PowerShell idioms already used elsewhere in this project (`Uninstall-Client.ps1` already uses `SupportsShouldProcess`).

Out of scope:
- Any change to the 5 existing scripts' (`Install-Server.ps1`, `Install-Client.ps1`, `Install-ClientWinRM.ps1`, `Uninstall-Client.ps1`, `Uninstall-ClientWinRM.ps1`) own parameters, validation, or install/uninstall logic. The wizard is purely an additive interactive front end that calls them unchanged — flag-based non-interactive invocation of all 5 keeps working exactly as it does today, so no existing automation/CI usage is affected.
- A GUI (WPF/WinForms) installer — considered and explicitly rejected (see Mechanism below).
- Any change to `New-ClientGpoPackage.ps1`, `Build-*.ps1`, or `Collect-WindowsInventoryLite.ps1` — not part of the install/uninstall flow the wizard covers.
- Deleting the imported TLS certificate from the `LocalMachine\My` store during server uninstall — deliberately left alone (see Uninstall-Server.ps1 below), since it may be an org-issued certificate used elsewhere on the host.

## Mechanism: why an interactive console wizard, not a GUI

Three approaches were considered for how the wizard collects answers:

- **A. Sequential `Read-Host` prompts** (chosen): works in any PowerShell console, including headless Windows Server Core installs and plain WinRM sessions with no GUI subsystem present. No new dependency — the whole project is already PowerShell-only.
- **B. `Out-GridView` menus**: friendlier visually, but requires the ISE/WPF GUI subsystem, which is not present on Server Core or a bare WinRM session — a real risk for a Windows Server administration tool.
- **C. Arrow-key-navigated TUI** (reading raw console keys via `$Host.UI.RawUI`): the richest experience, but breaks under redirected/piped input (scripted or automated invocation), and needs meaningfully more code to handle terminal-width and non-interactive-host edge cases.

A is the only option that works unconditionally across this project's actual deployment targets (including headless servers), and needs no new technology in a project that is deliberately PowerShell-only end to end.

A full GUI installer (WPF/WinForms) was also considered and rejected: it would require build tooling and a UI-testing story this project doesn't have, and doesn't fit a project whose entire stack today is PowerShell scripts with no compiled UI layer — the interactive-console approach delivers the same "usable by someone unfamiliar with the project" goal without introducing that.

## Mechanism: architecture

`Install-Wizard.ps1` is a **thin orchestration layer only**. It never re-implements install/uninstall logic:

1. Present the top-level menu.
2. Based on the chosen action, ask a fixed sequence of questions — one at a time, showing the underlying script's own default value in the prompt where one exists (e.g. `Listen prefix [http://+:8080/]:`), and clearly marking which questions are optional (empty answer = don't pass that parameter, let the underlying script apply its own default).
3. Build a parameter hashtable from the collected answers.
4. Show a confirmation screen: the fully-resolved equivalent command line for the chosen script (e.g. `Install-Server.ps1 -ListenPrefix 'http://+:8080/' -DataPath 'C:\...' -UseHttps`), with any password-type value replaced by `(hidden)` rather than the real value — never printed in cleartext.
5. On confirmation (or unconditionally under `-WhatIf`, see Testing below), invoke the underlying script via splatting: `& $scriptPath @params`. Output flows through exactly as if the script had been run directly — the wizard does not intercept, wrap, or reformat it.
6. If the underlying script throws (its own `ValidateNotNullOrEmpty`/`ValidateRange`/`throw` calls — validation logic is never duplicated in the wizard), the wizard catches the error, shows it, and lets the user redo just the offending answer rather than restarting the whole flow.

Passwords (`WebPassword`, `AdPassword`, `CertificatePfxPassword`, `CredentialPassword`) are collected via `Read-Host -AsSecureString` and converted to plaintext only at the point of building the parameter hashtable passed to the target script (matching how the underlying scripts already expect them) — never echoed to the console, never appearing in cleartext on the confirmation screen.

## Mechanism: menu and flows

```
Windows Inventory Lite — Install Wizard
1. Install server
2. Install client (local)
3. Deploy client to remote machines (WinRM)
4. Uninstall server
5. Uninstall client (local)
6. Uninstall client (remote, WinRM)
0. Exit
```

Each of the 6 numbered choices maps to one underlying script (`Install-Server.ps1`, `Install-Client.ps1`, `Install-ClientWinRM.ps1`, the new `Uninstall-Server.ps1`, `Uninstall-Client.ps1`, `Uninstall-ClientWinRM.ps1`) and one fixed question sequence covering that script's parameters, in the order that makes most sense for a first-time user (e.g. for server install: network/listen prefix first, then HTTPS, then Basic Auth credentials, then AD sync, then logging/firewall — grouped by concern, not alphabetically by flag name).

## Mechanism: new `Uninstall-Server.ps1`

No server-side uninstall script exists today (only `Uninstall-Client.ps1`/`Uninstall-ClientWinRM.ps1`). This design adds one, mirroring `Uninstall-Client.ps1`'s existing pattern (`[CmdletBinding(SupportsShouldProcess = $true)]`, `sc.exe stop`/`sc.exe delete` for the service, `Remove-Item` for directories, each step gated by `ShouldProcess`).

By default, removes:
- The `WindowsInventoryLite` service.
- The `server-bin`, `server-content`, and `client-package` directories under `%ProgramData%\WindowsInventoryLite\`.
- The firewall rules `Windows Inventory Lite Server (HTTP)`/`Windows Inventory Lite Server (HTTPS)`, if present (created only when `Install-Server.ps1 -OpenFirewall` was used).

By default, does **not** remove:
- `server-data` (the accumulated inventory reports for the whole fleet) or `server-config.json` — destructive and hard to undo; kept unless the operator explicitly opts in via a new `-RemoveData` switch. This lets an operator reinstall the server without losing collected history.
- Any certificate imported into `LocalMachine\My` — it may be an org-issued certificate used by other services on the host, not something this tool should delete unilaterally. If `server-config.json`'s saved `CertificateThumbprint` indicates this project imported it, the script prints the thumbprint and a one-line reminder of how to remove it manually (`Remove-Item Cert:\LocalMachine\My\<thumbprint>`) rather than doing it automatically.

The wizard's "Uninstall server" flow asks `Remove inventory data too? [y/N]` (default no) as an explicit interactive question, rather than only relying on a command-line flag a first-time user wouldn't know to pass.

## Mechanism: testing

**Syntax/encoding**: both new scripts are added to `tests/ScriptSyntax.Tests.ps1`'s existing parse-check path list; the English-only/no-Cyrillic and no-PS7-syntax checks already run recursively over `src/` and cover them automatically with no test-file change needed.

**Functional testing of the interactive flow.** Bare `Read-Host` calls are hard to drive from a test. Two complementary mechanisms, both idiomatic PowerShell (nothing bespoke):

1. All prompting goes through one wrapper function (`Read-WizardAnswer`, thin wrapper over `Read-Host`/`Read-Host -AsSecureString`) rather than calling `Read-Host` directly at each call site. Pester's built-in `Mock` can then intercept `Read-WizardAnswer` and feed a canned sequence of answers, exactly the tool Pester already provides for this exact scenario.
2. The wizard supports `-WhatIf` (the same `SupportsShouldProcess`/`ShouldProcess` idiom `Uninstall-Client.ps1` already uses in this codebase) on its final "invoke the target script" step: with `-WhatIf`, the wizard runs the full question sequence, builds and prints the resolved equivalent command on the confirmation screen, and **stops there** — it never calls the target script. This is both a genuinely useful safety feature (a cautious admin can preview exactly what will run before committing) and the natural test seam: a Pester test mocks `Read-WizardAnswer` with canned answers for one flow, runs the wizard with `-WhatIf`, and asserts the printed resolved command has the right target script and parameters, with no password values in cleartext.

One test per menu flow (6 total): feed canned answers via the mock, run with `-WhatIf`, assert the resolved command is correct for that flow.

## Open questions

None outstanding. All design decisions were confirmed with the user during brainstorming (2026-07-17): interactive console wizard over a GUI (headless Server Core compatibility, no new stack), plain sequential `Read-Host` prompts over `Out-GridView`/TUI (works everywhere, no GUI subsystem dependency), single unified entry point covering all 6 flows including server uninstall (discovered mid-brainstorm that no server uninstall script existed at all), and safe-by-default data handling for server uninstall (`server-data` preserved unless `-RemoveData` is explicitly passed, and the wizard asks about it explicitly rather than relying on the operator knowing the flag exists).
