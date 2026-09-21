$ErrorActionPreference = 'Stop'

Describe 'WilWinRmCommon shared functions' {
    BeforeAll {
        $script:ProjectRoot = Split-Path -Parent $PSScriptRoot
        . (Join-Path -Path $script:ProjectRoot -ChildPath 'src\WilWinRmCommon.ps1')
    }

    # Add-TargetToTrustedHosts/Remove-TargetFromTrustedHosts mutate the real
    # WSMan:\localhost\Client\TrustedHosts on whatever machine runs this test
    # (no per-test-sandboxable equivalent exists), so only the pure,
    # side-effect-free validation this fix added is covered here -
    # TrustedHosts is itself comma-delimited and WSMan treats * and ? as
    # wildcards, so a target containing any of those could inject an
    # unintended entry (including one that trusts every host) instead of
    # being added as the single literal hostname/IP this function assumes.
    It 'Test-ValidTrustedHostsEntry accepts a plain hostname or IPv4 literal' {
        Test-ValidTrustedHostsEntry -TargetComputer 'PC-001' | Should -Be $true
        Test-ValidTrustedHostsEntry -TargetComputer '192.168.1.10' | Should -Be $true
    }

    It 'Test-ValidTrustedHostsEntry rejects a comma, wildcard, whitespace, or empty value' {
        $invalid = @('PC-001,*', 'good,evil', '*', 'PC?', 'PC 001', '', $null)
        foreach ($value in $invalid) {
            Test-ValidTrustedHostsEntry -TargetComputer $value | Should -Be $false
        }
    }

    # Duplicate coverage of the same shared function, carried over from
    # Uninstall-ClientWinRM.Tests.ps1's own copy of this test (both scripts
    # defined byte-identical copies of Test-ValidTrustedHostsEntry before
    # this consolidation) - kept as a separate It so this consolidation's
    # before/after It-block count matches exactly, same approach used by the
    # WilLinuxSshCommon.ps1 extraction.
    It 'Test-ValidTrustedHostsEntry accepts a plain hostname or IPv4 literal (from Uninstall-ClientWinRM.Tests.ps1)' {
        Test-ValidTrustedHostsEntry -TargetComputer 'PC-001' | Should -Be $true
        Test-ValidTrustedHostsEntry -TargetComputer '192.168.1.10' | Should -Be $true
    }

    It 'Test-ValidTrustedHostsEntry rejects a comma, wildcard, whitespace, or empty value (from Uninstall-ClientWinRM.Tests.ps1)' {
        $invalid = @('PC-001,*', 'good,evil', '*', 'PC?', 'PC 001', '', $null)
        foreach ($value in $invalid) {
            Test-ValidTrustedHostsEntry -TargetComputer $value | Should -Be $false
        }
    }
}
