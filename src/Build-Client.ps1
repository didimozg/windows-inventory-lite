#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateSet('Net35', 'Net40')]
    [string]$TargetFramework = 'Net40'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$clientSource = Join-Path -Path $PSScriptRoot -ChildPath 'client\WindowsInventoryLiteClient.cs'

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $projectRoot -ChildPath 'build\WindowsInventoryLiteClient.exe'
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}

if ($TargetFramework -eq 'Net35') {
    $frameworkRoots = @((Join-Path -Path $env:WINDIR -ChildPath 'Microsoft.NET\Framework\v3.5\csc.exe'))
}
else {
    $frameworkRoots = @((Join-Path -Path $env:WINDIR -ChildPath 'Microsoft.NET\Framework\v4.0.30319\csc.exe'))
}

$compiler = $null
foreach ($candidate in $frameworkRoots) {
    if (Test-Path -LiteralPath $candidate) {
        $compiler = $candidate
        break
    }
}

if (-not $compiler) {
    throw "C# compiler was not found for target $TargetFramework."
}

& $compiler `
    /nologo `
    /target:exe `
    /optimize+ `
    /out:$OutputPath `
    /reference:System.dll `
    /reference:System.Core.dll `
    /reference:System.Management.dll `
    /reference:System.ServiceProcess.dll `
    /reference:System.Web.Extensions.dll `
    $clientSource

if ($LASTEXITCODE -ne 0) {
    throw "csc.exe failed with exit code $LASTEXITCODE - see errors above."
}

Write-Host "Client executable: $OutputPath"
Write-Host "Compiler: $compiler"
Write-Host "Target framework: $TargetFramework"
