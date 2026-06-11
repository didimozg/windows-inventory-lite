@echo off
setlocal

set PACKAGE_ROOT=\\fileserver.example.local\software\windows-inventory-lite
set SERVER_URL=http://inventory.example.local:8080/api/v1/inventory
set INTERVAL_HOURS=6
set DEPLOY_SCRIPT=%PACKAGE_ROOT%\Deploy-ClientGpo.ps1
set WAIT_SECONDS=90

:WAIT_PACKAGE
if exist "%DEPLOY_SCRIPT%" goto RUN_DEPLOY
if "%WAIT_SECONDS%"=="0" exit /b 2
ping -n 2 127.0.0.1 >nul
set /a WAIT_SECONDS-=1
goto WAIT_PACKAGE

:RUN_DEPLOY
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%DEPLOY_SCRIPT%" -ServerUrl "%SERVER_URL%" -IntervalHours %INTERVAL_HOURS%

exit /b %ERRORLEVEL%
