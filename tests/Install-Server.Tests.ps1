$ErrorActionPreference = 'Stop'

# Install-Server.ps1 has no if ($MyInvocation.InvocationName -ne '.')
# gate (unlike Install-Wizard.ps1/Deploy-ClientGpo.ps1) - dot-sourcing
# it would run a real install. New-RandomToken and Resolve-InstallToken
# are both pure, side-effect-free functions with no dependency on
# anything else in the script, so this extracts and defines only those
# two directly from the real file's AST, proving the tests exercise the
# actual shipped source rather than a hand-copied duplicate that could
# drift out of sync.
Describe 'Windows Inventory Lite Install-Server ingestion token resolution' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $scriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-Server.ps1'
        $scriptContent = Get-Content -LiteralPath $scriptPath -Raw
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptContent, [ref]$tokens, [ref]$errors)
        $targetNames = @('New-RandomToken', 'Resolve-InstallToken')
        $functionAsts = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $targetNames -contains $node.Name
        }, $true)
        if ($functionAsts.Count -ne 2) {
            throw "Expected to find both New-RandomToken and Resolve-InstallToken in Install-Server.ps1, found $($functionAsts.Count)"
        }
        foreach ($functionAst in $functionAsts) {
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }
    }

    It 'New-RandomToken returns a 64-character lowercase hex string' {
        $token = New-RandomToken

        $token | Should -Match '^[0-9a-f]{64}$'
    }

    It 'New-RandomToken returns a different value on each call' {
        $first = New-RandomToken
        $second = New-RandomToken

        $first | Should -Not -Be $second
    }

    It 'Resolve-InstallToken prefers an explicit token over a saved one' {
        $result = Resolve-InstallToken -ExplicitToken 'explicit-value' -SavedToken 'saved-value'

        $result | Should -Be 'explicit-value'
    }

    It 'Resolve-InstallToken falls back to the saved token when no explicit value is given' {
        $result = Resolve-InstallToken -ExplicitToken '' -SavedToken 'saved-value'

        $result | Should -Be 'saved-value'
    }

    It 'Resolve-InstallToken generates a new random token when neither explicit nor saved values exist' {
        $result = Resolve-InstallToken -ExplicitToken '' -SavedToken ''

        $result | Should -Match '^[0-9a-f]{64}$'
    }

    It 'Resolve-InstallToken generates a different value on repeated calls with no explicit or saved token' {
        $first = Resolve-InstallToken -ExplicitToken '' -SavedToken ''
        $second = Resolve-InstallToken -ExplicitToken '' -SavedToken ''

        $first | Should -Not -Be $second
    }
}

# Same AST-extraction approach as above, applied to the functions that
# guard config-file ACL ordering (3e) and install-path validation (3c-PS).
# Write-ServerConfig depends on Set-RestrictedFileAcl and ConvertTo-JsonString,
# so all three are extracted together; Test-BatchSafeValue is independent.
Describe 'Windows Inventory Lite Install-Server config and validation helpers' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        $scriptPath = Join-Path -Path $script:ProjectRoot -ChildPath 'src\Install-Server.ps1'
        $scriptContent = Get-Content -LiteralPath $scriptPath -Raw
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptContent, [ref]$tokens, [ref]$errors)
        $targetNames = @('Write-ServerConfig', 'Set-RestrictedFileAcl', 'ConvertTo-JsonString', 'Test-BatchSafeValue')
        $functionAsts = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $targetNames -contains $node.Name
        }, $true)
        if ($functionAsts.Count -ne 4) {
            throw "Expected to find Write-ServerConfig, Set-RestrictedFileAcl, ConvertTo-JsonString, and Test-BatchSafeValue in Install-Server.ps1, found $($functionAsts.Count)"
        }
        foreach ($functionAst in $functionAsts) {
            . ([scriptblock]::Create($functionAst.Extent.Text))
        }
    }

    Context 'Write-ServerConfig ACL ordering' {
        It 'restricts the config file before any secret is written into it' {
            # Install-Server.ps1 already requires full Administrator privileges to
            # run for real (it calls sc.exe create), so Write-ServerConfig hardening
            # the file to Administrators+SYSTEM before writing into it does not add
            # any new privilege requirement - it just moves an existing one earlier.
            # A non-admin account (as this test process may be, depending on the
            # environment) can still create and restrict the file, but can no longer
            # write into it afterward. Branch on elevation so the test asserts
            # something real either way, instead of silently no-op'ing on a
            # non-admin box: elevated runs get the full happy-path assertion,
            # non-elevated runs prove the ACL is enforced by observing the expected
            # throw, plus an independent check of Set-RestrictedFileAcl itself.
            $isElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            $configPath = Join-Path -Path $TestDrive -ChildPath 'acl-order\server-config.json'

            if ($isElevated) {
                Write-ServerConfig -Path $configPath -Config @{ Token = 'a-secret-value' }

                # The file must exist and be readable back - the point of the test is
                # that Write-ServerConfig itself performs the hardening, so there is no
                # window where a DPAPI-scoped secret sits under inherited ProgramData
                # permissions.
                (Get-Content -LiteralPath $configPath -Raw) | Should -Match 'a-secret-value'
                $acl = Get-Acl -LiteralPath $configPath
                $acl.AreAccessRulesProtected | Should -BeTrue
            }
            else {
                # Write-ServerConfig hardens the file to Administrators+SYSTEM before
                # writing the JSON into it, so a non-admin caller (this process) can no
                # longer complete the write. The throw itself is meaningful: a no-op or
                # broken ACL would let the write through and would NOT throw here.
                { Write-ServerConfig -Path $configPath -Config @{ Token = 'a-secret-value' } } | Should -Throw

                # Independently verify Set-RestrictedFileAcl's own ACL-setting behavior
                # against a plain throwaway scratch file, since the throw above means a
                # non-elevated run never reaches an ACL assertion via Write-ServerConfig's
                # own output file (this process can restrict the file, just not then
                # write into it - which is exactly the behavior under test).
                $scratchPath = Join-Path -Path $TestDrive -ChildPath 'scratch.txt'
                New-Item -Path $scratchPath -ItemType File -Force | Out-Null
                Set-RestrictedFileAcl -FilePath $scratchPath
                $scratchAcl = Get-Acl -LiteralPath $scratchPath
                $scratchAcl.AreAccessRulesProtected | Should -BeTrue
            }
        }
    }

    Context 'Test-BatchSafeValue coverage' {
        It 'rejects a LinuxClientPackagePath containing a cmd.exe metacharacter' {
            { Test-BatchSafeValue -Value 'C:\pkg & calc.exe' -FieldName 'LinuxClientPackagePath' } | Should -Throw
        }

        It 'accepts an ordinary ProgramData path' {
            { Test-BatchSafeValue -Value 'C:\ProgramData\WindowsInventoryLite\linux-client-package' -FieldName 'LinuxClientPackagePath' } | Should -Not -Throw
        }
    }
}

# Install-Server.ps1 falls back to the git-tracked linux-client/prebuilt/
# binary on machines without the Go toolchain (see the "No Go toolchain"
# branch there) - this only helps if that committed binary is actually kept
# current. Nothing else catches a version bumped in Build-LinuxClient.ps1
# without a matching rebuild+recommit, since the fallback path only runs on
# a machine without Go, where nobody would notice a stale version until an
# admin happens to compare it against the dashboard.
Describe 'Committed Linux client prebuilt binary stays in sync with Build-LinuxClient.ps1' {
    It 'wil-linux-client.version matches the script''s own default -Version' {
        $projectRoot = Split-Path -Parent $PSScriptRoot
        $buildScriptContent = Get-Content -LiteralPath (Join-Path -Path $projectRoot -ChildPath 'src\Build-LinuxClient.ps1') -Raw
        if ($buildScriptContent -notmatch "\`$Version\s*=\s*'([^']+)'") {
            throw "Could not find a `$Version default in Build-LinuxClient.ps1 - has its param() block changed shape?"
        }
        $scriptDefaultVersion = $Matches[1]

        $versionFilePath = Join-Path -Path $projectRoot -ChildPath 'linux-client\prebuilt\wil-linux-client.version'
        Test-Path -LiteralPath $versionFilePath | Should -Be $true -Because 'linux-client/prebuilt/wil-linux-client.version should be committed to the repo'
        $committedVersion = (Get-Content -LiteralPath $versionFilePath -Raw).Trim()

        $committedVersion | Should -Be $scriptDefaultVersion -Because 'the committed prebuilt binary must be rebuilt and recommitted whenever Build-LinuxClient.ps1''s default -Version changes, or machines without Go will silently keep shipping an old client'
    }
}
