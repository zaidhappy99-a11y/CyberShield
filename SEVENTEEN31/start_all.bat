@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo   Launching NetSentinel Complete NIDS and SOC Environment
echo ======================================================================

:: Launch Dashboard Server in separate window
start "NetSentinel SOC Server" cmd /k "start_soc_dashboard.bat"

:: Wait 2 seconds for server startup
timeout /t 2 >nul 2>&1

:: Open default browser to the Cyber SOC Dashboard
start http://localhost:8080/

echo.
echo [INFO] SOC Dashboard launched at http://localhost:8080/
echo [INFO] You can trigger attack simulations directly from the web interface
echo        or execute 'start_detector.bat' from another terminal.
echo.
pause
