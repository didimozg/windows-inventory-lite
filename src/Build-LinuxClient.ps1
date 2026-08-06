#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Version = '0.1.4',

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
elseif (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    # A relative -OutputPath must be resolved against the CALLER's current
    # directory now, before Push-Location below changes it to $sourceDir -
    # otherwise a relative path silently gets rewritten as though it were
    # relative to linux-client/ instead (e.g. "linux-client\prebuilt\..."
    # becomes "linux-client\linux-client\prebuilt\..."), and go build
    # writes to a path nobody asked for while the script still reports
    # success at the originally-intended (never-populated) location.
    $OutputPath = [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location).Path -ChildPath $OutputPath))
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
    # -trimpath strips the local build machine's absolute source paths
    # (e.g. C:\Users\<name>\...) from the compiled binary's embedded debug
    # info - without it, anyone inspecting the binary (`strings` or a
    # panic/stack trace) sees the exact filesystem layout, including the
    # Windows username, of whichever machine built it. This binary is
    # committed to the repo (linux-client/prebuilt/), so that would leak
    # into the public history on every rebuild.
    & go build -trimpath -ldflags "-X main.ClientVersion=$Version" -o $OutputPath .
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

# The built binary is a Linux ELF executable - the Windows-hosted server
# cannot read a PE version resource from it (that's how GetExeVersion
# reads the Windows client's own version) and should not try to execute a
# foreign-OS binary just to ask its version. This sidecar file is the
# server's only source of truth for "what version is currently built" for
# the Linux client update-detection endpoint.
$versionSidecarPath = "$OutputPath.version"
[System.IO.File]::WriteAllText($versionSidecarPath, $Version, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "Linux client built: $OutputPath"
Write-Host "Version: $Version"
Write-Host "Version sidecar: $versionSidecarPath"
