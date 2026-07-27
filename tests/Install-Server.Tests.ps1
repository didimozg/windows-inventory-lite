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
