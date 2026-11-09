@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo   NetSentinel - Network Intrusion Detection System
echo   Starting the local SOC dashboard server...
echo ======================================================================

start "NetSentinel SOC Server" cmd /k ""%~dp0run_python.bat" "%~dp0server.py" 8080"
timeout /t 2 >nul 2>&1
start "" "http://localhost:8080/"
