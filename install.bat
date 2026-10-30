@echo off
setlocal
echo ==============================================================================
echo  CYBERGLASS - Offline Windows Installer
echo ==============================================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
if errorlevel 1 (
    echo [!] CyberGlass installation encountered an error [exit code: %ERRORLEVEL%].
    exit /b %ERRORLEVEL%
)
