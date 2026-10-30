@echo off
setlocal
echo ==============================================================================
echo  CYBERGLASS - Next-Gen SIEM & Data Fusion Platform
echo  Starting Server and Launching Web UI at http://localhost:9401...
echo ==============================================================================

:: Locate binary
set SERVER_EXE=
if exist "%~dp0target\debug\cyberglass-server.exe" set SERVER_EXE=%~dp0target\debug\cyberglass-server.exe
if not defined SERVER_EXE if exist "%~dp0target\release\cyberglass-server.exe" set SERVER_EXE=%~dp0target\release\cyberglass-server.exe
if not defined SERVER_EXE if exist "%~dp0bin\cyberglass-server.exe" set SERVER_EXE=%~dp0bin\cyberglass-server.exe
if not defined SERVER_EXE if exist "%LOCALAPPDATA%\CyberGlass\bin\cyberglass-server.exe" set SERVER_EXE=%LOCALAPPDATA%\CyberGlass\bin\cyberglass-server.exe

if not defined SERVER_EXE (
    echo [ERROR] cyberglass-server.exe not found! Please run .\install.bat first.
    exit /b 1
)

echo [+] Starting CyberGlass Server from: %SERVER_EXE%
echo [+] Opening Web UI in default browser: http://localhost:9401
start "" http://localhost:9401
"%SERVER_EXE%" --config "%~dp0config\cyberglass.toml" %*
