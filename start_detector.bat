@echo off
setlocal
cd /d "%~dp0"

echo ======================================================================
echo   NetSentinel - Network Detection Engine and Attack Simulator
echo ======================================================================

call "%~dp0run_python.bat" "%~dp0detector\attack_simulator.py"
pause
