@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo   CyberShield Landing + NetSentinel SOC (unified server)
echo   http://localhost:8080/  -> landing page, login/register, then
echo   the NetSentinel app at http://localhost:8080/app/
echo ======================================================================

:: Unified Flask server: marketing site at / and NetSentinel app at /app/
:: (shares /api/* on the same origin; forwards to the Java backend on
:: NETSENTINEL_JAVA_URL when that is running, with demo data fallback).
echo [INFO] Launching unified landing + NetSentinel server on port 8080...
echo [INFO] (Quit with Ctrl+C. Leave this window open while you browse.)
call "%~dp0run_python.bat" "%~dp0backend_server.py"
pause
