#requires -Version 2.0

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ServerSharePath,

    [Parameter()]
    [switch]$SkipSoftware
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot

function Resolve-InventoryPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return Join-Path -Path $ProjectRoot -ChildPath $Path
}

function New-InventoryObject {
    param([hashtable]$Properties)

    $object = New-Object PSObject
    foreach ($key in $Properties.Keys) {
        $object | Add-Member -MemberType NoteProperty -Name $key -Value $Properties[$key]
    }

    return $object
}

function ConvertTo-JsonString {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return 'null'
    }

    $text = [string]$Value
    $builder = New-Object System.Text.StringBuilder
    [void]$builder.Append('"')

    foreach ($char in $text.ToCharArray()) {
        switch ($char) {
            '"' { [void]$builder.Append('\"') }
            '\' { [void]$builder.Append('\\') }
            ([char]8) { [void]$builder.Append('\b') }
            ([char]9) { [void]$builder.Append('\t') }
            ([char]10) { [void]$builder.Append('\n') }
            ([char]12) { [void]$builder.Append('\f') }
            ([char]13) { [void]$builder.Append('\r') }
            default {
                $code = [int][char]$char
                if ($code -lt 32) {
                    [void]$builder.Append(('\u{0:x4}' -f $code))
                }
                else {
                    [void]$builder.Append($char)
                }
            }
        }
    }

    [void]$builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-JsonValue {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return 'null'
    }

    if ($Value -is [bool]) {
        if ($Value) { return 'true' }
        return 'false'
    }

    if ($Value -is [byte] -or $Value -is [int16] -or $Value -is [int32] -or $Value -is [int64] -or
        $Value -is [single] -or $Value -is [double] -or $Value -is [decimal]) {
        return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)
    }

    if ($Value -is [datetime]) {
        return ConvertTo-JsonString -Value $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    if ($Value -is [System.Collections.IDictionary]) {
        $items = New-Object System.Collections.ArrayList
        foreach ($key in $Value.Keys) {
            [void]$items.Add((ConvertTo-JsonString -Value $key) + ':' + (ConvertTo-JsonValue -Value $Value[$key]))
        }
        return '{' + (($items.ToArray()) -join ',') + '}'
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $items = New-Object System.Collections.ArrayList
        foreach ($item in $Value) {
            [void]$items.Add((ConvertTo-JsonValue -Value $item))
        }
        return '[' + (($items.ToArray()) -join ',') + ']'
    }

    if ($Value -is [psobject]) {
        $items = New-Object System.Collections.ArrayList
        foreach ($property in $Value.PSObject.Properties) {
            [void]$items.Add((ConvertTo-JsonString -Value $property.Name) + ':' + (ConvertTo-JsonValue -Value $property.Value))
        }
        return '{' + (($items.ToArray()) -join ',') + '}'
    }

    return ConvertTo-JsonString -Value $Value
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Get-ObjectPropertyValue {
    param(
        [Parameter()]
        [AllowNull()]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }

    return $null
}

function ConvertTo-InstallDateText {
    param(
        [Parameter()]
        [AllowNull()]
        [string]$Value
    )

    # Uninstall registry InstallDate values are an 8-digit YYYYMMDD string
    # (e.g. "20251013"), not a normal date. Reformat to dd.MM.yyyy; leave
    # anything that does not match that shape untouched.
    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -ne 8 -or $Value -notmatch '^\d{8}$') {
        return $Value
    }

    $year = $Value.Substring(0, 4)
    $month = [int]$Value.Substring(4, 2)
    $day = [int]$Value.Substring(6, 2)

    if ($month -lt 1 -or $month -gt 12 -or $day -lt 1 -or $day -gt 31) {
        return $Value
    }

    return '{0:d2}.{1:d2}.{2}' -f $day, $month, $year
}

function Invoke-InventoryWmiQuery {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Query
    )

    try {
        if (Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue) {
            return @(Get-WmiObject -Query $Query -ErrorAction Stop)
        }

        if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
            return @(Get-CimInstance -Query $Query -ErrorAction Stop)
        }
    }
    catch {
        return @()
    }

    throw 'Neither Get-WmiObject nor Get-CimInstance is available on this host.'
}

function Get-InventoryWmiClass {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ClassName
    )

    try {
        if (Get-Command -Name Get-WmiObject -ErrorAction SilentlyContinue) {
            return @(Get-WmiObject -Class $ClassName -ErrorAction Stop)
        }

        if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
            return @(Get-CimInstance -ClassName $ClassName -ErrorAction Stop)
        }
    }
    catch {
        return @()
    }

    throw 'Neither Get-WmiObject nor Get-CimInstance is available on this host.'
}

function Get-InstalledSoftware {
    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $items = New-Object System.Collections.ArrayList
    $seen = @{}
    foreach ($path in $registryPaths) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue |
            Where-Object {
                (Get-ObjectPropertyValue -InputObject $_ -Name 'DisplayName') -and
                (Get-ObjectPropertyValue -InputObject $_ -Name 'SystemComponent') -ne 1 -and
                -not (Get-ObjectPropertyValue -InputObject $_ -Name 'ParentKeyName') -and
                -not (Get-ObjectPropertyValue -InputObject $_ -Name 'ReleaseType') -and
                ((Get-ObjectPropertyValue -InputObject $_ -Name 'UninstallString') -or (Get-ObjectPropertyValue -InputObject $_ -Name 'QuietUninstallString'))
            } |
            ForEach-Object {
                $name = [string](Get-ObjectPropertyValue -InputObject $_ -Name 'DisplayName')
                $version = [string](Get-ObjectPropertyValue -InputObject $_ -Name 'DisplayVersion')
                $publisher = [string](Get-ObjectPropertyValue -InputObject $_ -Name 'Publisher')
                $key = ('{0}|{1}|{2}' -f $name, $version, $publisher).ToLowerInvariant()
                if ($seen.ContainsKey($key)) {
                    return
                }
                $seen[$key] = $true

                $software = New-InventoryObject -Properties @{
                    name = $name
                    version = $version
                    publisher = $publisher
                    installDate = ConvertTo-InstallDateText -Value ([string](Get-ObjectPropertyValue -InputObject $_ -Name 'InstallDate'))
                }
                [void]$items.Add($software)
            }
    }

    return @($items | Sort-Object name, version -Unique)
}

function Get-WindowsActivationState {
    try {
        $products = Invoke-InventoryWmiQuery -Query "SELECT Name, LicenseStatus, PartialProductKey FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL" |
            Where-Object { $_.Name -like '*Windows*' }

        $activated = @($products | Where-Object { $_.LicenseStatus -eq 1 })
        return New-InventoryObject -Properties @{
            activated = ($activated.Count -gt 0)
            product = [string](@($activated | Select-Object -First 1).Name)
        }
    }
    catch {
        return New-InventoryObject -Properties @{
            activated = $false
            product = $null
            error = $_.Exception.Message
        }
    }
}

function Get-OfficeActivationState {
    try {
        $products = Invoke-InventoryWmiQuery -Query "SELECT Name, ApplicationID, LicenseStatus, PartialProductKey FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL" |
            Where-Object { $_.ApplicationID -eq '0ff1ce15-a989-479d-af46-f275c6370663' -or $_.Name -like '*Office*' }

        $activated = @($products | Where-Object { $_.LicenseStatus -eq 1 })
        return New-InventoryObject -Properties @{
            activated = ($activated.Count -gt 0)
            product = [string](@($activated | Select-Object -First 1).Name)
        }
    }
    catch {
        return New-InventoryObject -Properties @{
            activated = $false
            product = $null
            error = $_.Exception.Message
        }
    }
}

function Get-OfficeVersion {
    $clickToRunPath = 'HKLM:\Software\Microsoft\Office\ClickToRun\Configuration'
    $version = Get-RegistryValue -Path $clickToRunPath -Name 'VersionToReport'
    $productIds = Get-RegistryValue -Path $clickToRunPath -Name 'ProductReleaseIds'

    if ($version -or $productIds) {
        return New-InventoryObject -Properties @{
            name = [string]$productIds
            version = [string]$version
            source = 'ClickToRun'
        }
    }

    $officeSoftware = @(Get-InstalledSoftware | Where-Object {
            $_.name -match 'Microsoft (Office|365 Apps)' -and $_.name -notmatch 'Proof|Language|Update|Runtime|Tools'
        } | Select-Object -First 1)

    if ($officeSoftware.Count -gt 0) {
        return New-InventoryObject -Properties @{
            name = [string]$officeSoftware[0].name
            version = [string]$officeSoftware[0].version
            source = 'UninstallRegistry'
        }
    }

    return New-InventoryObject -Properties @{
        name = $null
        version = $null
        source = $null
    }
}

function Get-OperatingSystemInfo {
    $os = Get-InventoryWmiClass -ClassName Win32_OperatingSystem | Select-Object -First 1
    return New-InventoryObject -Properties @{
        caption = [string](Get-ObjectPropertyValue -InputObject $os -Name 'Caption')
        version = [string](Get-ObjectPropertyValue -InputObject $os -Name 'Version')
        buildNumber = [string](Get-ObjectPropertyValue -InputObject $os -Name 'BuildNumber')
        architecture = [string](Get-ObjectPropertyValue -InputObject $os -Name 'OSArchitecture')
        installDate = [string](Get-ObjectPropertyValue -InputObject $os -Name 'InstallDate')
    }
}

function Get-ComputerInventory {
    $computerSystem = Get-InventoryWmiClass -ClassName Win32_ComputerSystem | Select-Object -First 1
    $bios = Get-InventoryWmiClass -ClassName Win32_BIOS | Select-Object -First 1
    $software = @()

    if (-not $SkipSoftware) {
        $software = @(Get-InstalledSoftware)
    }

    return New-InventoryObject -Properties @{
        schemaVersion = '1.0'
        collectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        computerName = [string]$env:COMPUTERNAME
        domain = [string](Get-ObjectPropertyValue -InputObject $computerSystem -Name 'Domain')
        manufacturer = [string](Get-ObjectPropertyValue -InputObject $computerSystem -Name 'Manufacturer')
        model = [string](Get-ObjectPropertyValue -InputObject $computerSystem -Name 'Model')
        serialNumber = [string](Get-ObjectPropertyValue -InputObject $bios -Name 'SerialNumber')
        os = Get-OperatingSystemInfo
        office = Get-OfficeVersion
        activation = New-InventoryObject -Properties @{
            windows = Get-WindowsActivationState
            office = Get-OfficeActivationState
        }
        software = $software
    }
}

function Save-Inventory {
    param(
        [object]$Inventory,
        [string]$Path
    )

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }

    $json = ConvertTo-JsonValue -Value $Inventory
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))
}

$computerFileName = ($env:COMPUTERNAME -replace '[^A-Za-z0-9_.-]', '_') + '.json'
if (-not $OutputPath) {
    $OutputPath = Join-Path -Path $env:ProgramData -ChildPath ('WindowsInventoryLite\' + $computerFileName)
}
else {
    $OutputPath = Resolve-InventoryPath -Path $OutputPath
}

$inventory = Get-ComputerInventory
Save-Inventory -Inventory $inventory -Path $OutputPath
Write-Host "Local inventory file: $OutputPath"

if ($ServerSharePath) {
    $targetPath = Join-Path -Path $ServerSharePath -ChildPath $computerFileName
    Save-Inventory -Inventory $inventory -Path $targetPath
    Write-Host "Server inventory file: $targetPath"
}

return $inventory
