$ErrorActionPreference = 'Stop'

.\src\Build-Client.ps1 -OutputPath '.\build\WindowsInventoryLiteClient.exe'
.\build\WindowsInventoryLiteClient.exe --once --output '.\output' --server-url 'http://inventory.example.local:8080/api/v1/inventory'
