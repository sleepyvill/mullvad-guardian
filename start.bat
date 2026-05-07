@echo off
REM Mullvad Guardian Web UI Launcher for Windows

echo.
echo ============================================================================
echo   Mullvad Guardian Web UI
echo ============================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed. Please install Python 3.10 or higher.
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Check if requests is installed
python -c "import requests" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing required package: requests
    pip install requests
)

REM Check if Mullvad CLI is available
where mullvad >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Mullvad CLI not found. Please install Mullvad VPN.
    echo Download from: https://mullvad.net/download
    echo.
)

REM Start the server
echo [INFO] Starting web server...
echo.
python server.py
