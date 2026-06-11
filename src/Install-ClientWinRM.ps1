#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ServerUrl,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Token,

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$IntervalHours = 6,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$PackagePath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RemotePackagePath = 'C:\ProgramData\WindowsInventoryLite\WinRMDeploy',

    [Parameter()]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CredentialUsername,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CredentialPassword,

    [Parameter()]
    [switch]$AddToTrustedHosts,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$KeepRemotePackage
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDirectory) {
    $scriptDirectory = (Get-Location).Path
}
$projectRoot = Split-Path -Parent $scriptDirectory
if (-not $PackagePath) {
    $PackagePath = Join-Path -Path $projectRoot -ChildPath 'dist\gpo-client'
}
elseif (-not [System.IO.Path]::IsPathRooted($PackagePath)) {
    $PackagePath = Join-Path -Path $projectRoot -ChildPath $PackagePath
}

$deployPath = Join-Path -Path $PackagePath -ChildPath 'Deploy-ClientGpo.ps1'
$clientNet35Path = Join-Path -Path $PackagePath -ChildPath 'WindowsInventoryLiteClient-net35.exe'
$clientNet40Path = Join-Path -Path $PackagePath -ChildPath 'WindowsInventoryLiteClient-net40.exe'

foreach ($path in @($deployPath, $clientNet35Path, $clientNet40Path)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required package file was not found: $path"
    }
}

$hadFailure = $false

if (-not $Credential -and $CredentialUsername -and $CredentialPassword) {
    $securePassword = ConvertTo-SecureString -String $CredentialPassword -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($CredentialUsername, $securePassword)
}

function New-InventorySession {
    param([string]$TargetComputer)

    if ($Credential) {
        return New-PSSession -ComputerName $TargetComputer -Credential $Credential
    }

    return New-PSSession -ComputerName $TargetComputer
}

function Add-TargetToTrustedHosts {
    param([string]$TargetComputer)

    $current = ''
    try {
        $item = Get-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop
        $current = [string]$item.Value
    }
    catch {
        throw "Failed to read WinRM TrustedHosts. Run this script on a host with WinRM client support."
    }

    if ($current -eq '*') {
        return
    }

    $items = @()
    if ($current) {
        $items = @($current.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }

    foreach ($item in $items) {
        if ($item -ieq $TargetComputer) {
            return
        }
    }

    $items += $TargetComputer
    Set-Item -LiteralPath WSMan:\localhost\Client\TrustedHosts -Value ($items -join ',') -Force | Out-Null
}

function Test-IpAddress {
    param([string]$Value)

    $address = $null
    return [System.Net.IPAddress]::TryParse($Value, [ref]$address)
}

function Get-RemoteClientPackagePath {
    param([System.Management.Automation.Runspaces.PSSession]$Session)

    $versionText = Invoke-Command -Session $Session -ScriptBlock {
        $version = [Environment]::OSVersion.Version
        return ('{0}.{1}' -f $version.Major, $version.Minor)
    }

    if ($versionText -eq '6.1') {
        return $clientNet35Path
    }

    return $clientNet40Path
}

function Copy-FileOverWinRM {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$LocalPath,
        [string]$RemotePath
    )

    $remoteDirectory = Split-Path -Parent $RemotePath
    Invoke-Command -Session $Session -ScriptBlock {
        param([string]$Path)

        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
    } -ArgumentList $remoteDirectory

    Invoke-Command -Session $Session -ScriptBlock {
        param([string]$Path)

        if (Test-Path -LiteralPath $Path) {
            Remove-Item -LiteralPath $Path -Force
        }
    } -ArgumentList $RemotePath

    $bytes = [System.IO.File]::ReadAllBytes($LocalPath)
    $chunkSize = 49152
    $offset = 0

    while ($offset -lt $bytes.Length) {
        $remaining = $bytes.Length - $offset
        $count = [Math]::Min($chunkSize, $remaining)
        $chunk = New-Object byte[] $count
        [Array]::Copy($bytes, $offset, $chunk, 0, $count)
        $encoded = [Convert]::ToBase64String($chunk)

        Invoke-Command -Session $Session -ScriptBlock {
            param(
                [string]$Path,
                [string]$Content
            )

            $chunkBytes = [Convert]::FromBase64String($Content)
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write)
            try {
                $stream.Write($chunkBytes, 0, $chunkBytes.Length)
            }
            finally {
                $stream.Close()
            }
        } -ArgumentList $RemotePath, $encoded

        $offset += $count
    }
}

function Invoke-RemoteDeploy {
    param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$RemoteDeployPath,
        [string]$RemoteClientPath
    )

    Invoke-Command -Session $Session -ScriptBlock {
        param(
            [string]$DeployPath,
            [string]$ClientPath,
            [string]$Url,
            [int]$Hours,
            [string]$SharedToken,
            [bool]$ForceInstall
        )

        $arguments = @(
            '-NoProfile',
            '-ExecutionPolicy',
            'Bypass',
            '-File',
            $DeployPath,
            '-ServerUrl',
            $Url,
            '-IntervalHours',
            ([string]$Hours),
            '-PackageClientPath',
            $ClientPath
        )

        if ($SharedToken) {
            $arguments += '-Token'
            $arguments += $SharedToken
        }

        if ($ForceInstall) {
            $arguments += '-Force'
        }

        & powershell.exe @arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Remote deploy script failed with exit code $LASTEXITCODE."
        }
    } -ArgumentList $RemoteDeployPath, $RemoteClientPath, $ServerUrl, $IntervalHours, $Token, ([bool]$Force)
}

foreach ($computer in $ComputerName) {
    $session = $null
    try {
        Write-Host "Connecting: $computer"
        if ($AddToTrustedHosts -or ($Credential -and (Test-IpAddress -Value $computer))) {
            Write-Host "Adding TrustedHosts entry: $computer"
            Add-TargetToTrustedHosts -TargetComputer $computer
        }
        $session = New-InventorySession -TargetComputer $computer

        $selectedClientPath = Get-RemoteClientPackagePath -Session $session
        $remoteDeployPath = Join-Path -Path $RemotePackagePath -ChildPath 'Deploy-ClientGpo.ps1'
        $remoteClientPath = Join-Path -Path $RemotePackagePath -ChildPath (Split-Path -Leaf $selectedClientPath)

        Write-Host "Copying deploy script: $computer"
        Copy-FileOverWinRM -Session $session -LocalPath $deployPath -RemotePath $remoteDeployPath

        Write-Host "Copying client package: $computer"
        Copy-FileOverWinRM -Session $session -LocalPath $selectedClientPath -RemotePath $remoteClientPath

        Write-Host "Installing client service: $computer"
        Invoke-RemoteDeploy -Session $session -RemoteDeployPath $remoteDeployPath -RemoteClientPath $remoteClientPath

        if (-not $KeepRemotePackage) {
            Invoke-Command -Session $session -ScriptBlock {
                param([string]$Path)

                if (Test-Path -LiteralPath $Path) {
                    Remove-Item -LiteralPath $Path -Recurse -Force
                }
            } -ArgumentList $RemotePackagePath
        }

        Write-Host "Client installed: $computer"
    }
    catch {
        $hadFailure = $true
        Write-Error ("Failed to install client on {0}: {1}" -f $computer, $_.Exception.Message)
    }
    finally {
        if ($session) {
            Remove-PSSession -Session $session
        }
    }
}

if ($hadFailure) {
    exit 1
}
