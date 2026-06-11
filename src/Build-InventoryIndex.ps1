#requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DropPath = 'C:\ProgramData\WindowsInventoryLite\drop',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DashboardDataPath = 'C:\inetpub\WindowsInventoryLite\data'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $DropPath)) {
    New-Item -Path $DropPath -ItemType Directory -Force | Out-Null
}

if (-not (Test-Path -LiteralPath $DashboardDataPath)) {
    New-Item -Path $DashboardDataPath -ItemType Directory -Force | Out-Null
}

$clients = New-Object System.Collections.Generic.List[object]
Get-ChildItem -LiteralPath $DropPath -Filter '*.json' -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne 'inventory-index.json' } |
    Sort-Object Name |
    ForEach-Object {
        try {
            $raw = Get-Content -LiteralPath $_.FullName -Raw
            $client = $raw | ConvertFrom-Json
            $client | Add-Member -MemberType NoteProperty -Name sourceFile -Value $_.Name -Force
            $client | Add-Member -MemberType NoteProperty -Name sourceUpdatedAt -Value $_.LastWriteTimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') -Force
            $clients.Add($client)
        }
        catch {
            Write-Warning "Skipping invalid inventory file $($_.FullName): $($_.Exception.Message)"
        }
    }

$index = [pscustomobject]@{
    schemaVersion = '1.0'
    generatedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    clientCount = $clients.Count
    clients = $clients
}

$indexPath = Join-Path -Path $DashboardDataPath -ChildPath 'inventory-index.json'
$index | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $indexPath -Encoding UTF8
Write-Host "Inventory index: $indexPath"
