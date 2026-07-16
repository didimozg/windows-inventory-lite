#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$serverDir = Join-Path -Path $PSScriptRoot -ChildPath 'server'
$serverSources = @(Get-ChildItem -Path $serverDir -Filter '*.cs' | ForEach-Object { $_.FullName })

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $projectRoot -ChildPath 'build\WindowsInventoryLiteServer.exe'
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}

$compilerCandidates = @(
    (Join-Path -Path $env:WINDIR -ChildPath 'Microsoft.NET\Framework\v4.0.30319\csc.exe'),
    (Join-Path -Path $env:WINDIR -ChildPath 'Microsoft.NET\Framework\v3.5\csc.exe')
)

$compiler = $null
foreach ($candidate in $compilerCandidates) {
    if (Test-Path -LiteralPath $candidate) {
        $compiler = $candidate
        break
    }
}

if (-not $compiler) {
    throw 'C# compiler was not found. Enable .NET Framework 3.5 or install a Windows SDK on the build host.'
}

& $compiler `
    /nologo `
    /target:exe `
    /optimize+ `
    /out:$OutputPath `
    /reference:System.dll `
    /reference:System.Core.dll `
    /reference:System.ServiceProcess.dll `
    /reference:System.Web.Extensions.dll `
    $serverSources

if ($LASTEXITCODE -ne 0) {
    # Without this check the script printed "Server executable: ..." even
    # after a failed compile, silently leaving a stale exe in place - this
    # is exactly the kind of confusion that once led a code reviewer (who
    # could not run the build themselves) to report a false-positive
    # "Critical: server does not compile" finding. AdLookupService.cs's use
    # of System.DirectoryServices.ActiveDirectory.Domain resolves via the
    # C# compiler's default response file (csc.rsp), not an explicit
    # /reference here - do not add one for it by bare filename, csc cannot
    # locate that specific assembly that way in this environment and the
    # build breaks with CS0006 (verified the hard way).
    throw "csc.exe failed with exit code $LASTEXITCODE - see errors above."
}

Write-Host "Server executable: $OutputPath"
