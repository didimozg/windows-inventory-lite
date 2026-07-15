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

Write-Host "Server executable: $OutputPath"
