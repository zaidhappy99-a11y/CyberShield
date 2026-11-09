@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo   NetSentinel - Hybrid Network Intrusion Detection System
echo   Starting SOC Dashboard and Analytics Server...
echo ======================================================================

:: Check if Java is installed and compiled
where java >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    if exist "backend\bin\com\netsentinel\NetSentinelServer.class" (
        echo [INFO] Launching Java SOC Backend on port 8080...
        java -cp backend\bin com.netsentinel.NetSentinelServer 8080
        exit /b 0
    )
)

:: Otherwise run Python Bridge Server (serves identical REST API and Dashboard)
echo [INFO] Launching NetSentinel Server via Python Bridge on port 8080...
call "%~dp0run_python.bat" "%~dp0detector\bridge_server.py" 8080
pause
