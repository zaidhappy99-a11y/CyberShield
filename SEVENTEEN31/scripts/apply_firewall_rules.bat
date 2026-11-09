@echo off
:: NetSentinel Windows Defender Firewall Sync Script
:: Run as Administrator to apply all active quarantine rules
echo ======================================================================
echo   NetSentinel Active Defense - Synchronizing Windows Defender Firewall
echo ======================================================================
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] This script requires Administrator privileges.
    echo Right-click this file and select 'Run as administrator'.
    pause
    exit /b 1
)
echo [INFO] Applying active block rules...


echo ======================================================================
echo   [SUCCESS] Windows Defender Firewall rules synchronized successfully!
echo ======================================================================
pause