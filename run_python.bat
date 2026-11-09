@echo off
setlocal

:: If MySQL Workbench python exists, use it reliably
if exist "C:\Program Files\MySQL\MySQL Workbench 8.0\swb\shell\lib\Python3.13\python.exe" (
    "C:\Program Files\MySQL\MySQL Workbench 8.0\swb\shell\lib\Python3.13\python.exe" %*
    exit /b %ERRORLEVEL%
)

:: Try python launcher py.exe
py --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    py %*
    exit /b %ERRORLEVEL%
)

:: Try python.exe
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    python %*
    exit /b %ERRORLEVEL%
)

:: Fallback via PowerShell resolver
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_python.ps1" %*
exit /b %ERRORLEVEL%
