$ErrorActionPreference = 'Stop'

Describe 'Windows Inventory Lite project' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
    }

    It 'parses PowerShell scripts' {
        $paths = @(
            'src\Collect-WindowsInventoryLite.ps1',
            'src\Build-Client.ps1',
            'src\Build-Server.ps1',
            'src\New-ClientGpoPackage.ps1',
            'src\Install-Client.ps1',
            'src\Install-ClientWinRM.ps1',
            'src\Uninstall-Client.ps1',
            'src\Uninstall-ClientWinRM.ps1',
            'src\Build-InventoryIndex.ps1',
            'src\Install-Server.ps1',
            'deploy\client\Deploy-ClientGpo.ps1',
            'examples\install-server.ps1',
            'examples\install-client.ps1',
            'examples\run-client-once.ps1'
        ) | ForEach-Object { Join-Path -Path $script:ProjectRoot -ChildPath $_ }

        foreach ($path in $paths) {
            $tokens = $null
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
            $errors | Should -BeNullOrEmpty
        }
    }

    It 'keeps source, dashboard, and examples in English' {
        $paths = @(
            'src',
            'deploy',
            'server',
            'examples',
            'tests'
        ) | ForEach-Object { Join-Path -Path $script:ProjectRoot -ChildPath $_ }

        foreach ($path in $paths) {
            Get-ChildItem -LiteralPath $path -Recurse -File | ForEach-Object {
                # Explicit UTF8: on a non-Latin default system codepage, Get-Content's
                # encoding auto-detection misreads UTF8-without-BOM multi-byte
                # sequences (e.g. an em dash) as unrelated codepoints, some of which
                # land in the Cyrillic range and produce a false positive here.
                (Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8) | Should -Not -Match '\p{IsCyrillic}'
            }
        }
    }

    It 'does not require PowerShell 7 syntax' {
        Get-ChildItem -LiteralPath (Join-Path -Path $script:ProjectRoot -ChildPath 'src') -Filter '*.ps1' -Recurse | ForEach-Object {
            $text = Get-Content -LiteralPath $_.FullName -Raw
            $text | Should -Not -Match 'ForEach-Object\s+-Parallel'
        }
    }
}
