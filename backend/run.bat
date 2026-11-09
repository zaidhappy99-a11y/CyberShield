@echo off
setlocal
cd /d "%~dp0"

echo =========================================================
echo   Starting NetSentinel Java SOC Server...
echo =========================================================

where java >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] 'java' was not found on your system PATH.
    echo Please install Java Runtime Environment or JDK.
    pause
    exit /b 1
)

if not exist bin\com\netsentinel\NetSentinelServer.class (
    echo [INFO] Binaries not found. Running build.bat first...
    call build.bat
)

java -cp bin com.netsentinel.NetSentinelServer 8080
pause
