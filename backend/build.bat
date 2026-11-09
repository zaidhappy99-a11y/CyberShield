@echo off
setlocal
cd /d "%~dp0"

echo =========================================================
echo   Compiling NetSentinel Java SOC Server...
echo =========================================================

where javac >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] 'javac' was not found on your system PATH.
    echo Please install Java JDK (e.g., Eclipse Temurin or Oracle JDK 17/21).
    pause
    exit /b 1
)

if not exist bin mkdir bin

javac -encoding UTF-8 -d bin src\com\netsentinel\*.java
if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] NetSentinel Java backend compiled successfully into bin/
) else (
    echo [FAIL] Compilation failed with errors.
)

pause
