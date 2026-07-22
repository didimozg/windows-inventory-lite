#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Version = '0.1.0',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptRoot) {
    $ScriptRoot = (Get-Location).Path
}
$projectRoot = Split-Path -Parent $ScriptRoot
$sourceDir = Join-Path -Path $projectRoot -ChildPath 'linux-client'

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    throw "Go toolchain not found on PATH. Install Go (https://go.dev/dl/) to build the Linux client."
}

if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $projectRoot -ChildPath 'build\wil-linux-client'
}

$outputDir = Split-Path -Parent $OutputPath
if (-not (Test-Path -LiteralPath $outputDir)) {
    New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
}

$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
$env:CGO_ENABLED = '0'

Push-Location $sourceDir
try {
    & go build -ldflags "-X main.ClientVersion=$Version" -o $OutputPath .
    if ($LASTEXITCODE -ne 0) {
        throw "go build failed with exit code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
    Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
}

Write-Host "Linux client built: $OutputPath"
Write-Host "Version: $Version"
