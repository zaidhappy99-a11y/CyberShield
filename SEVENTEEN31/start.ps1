# NetSentinel - Native Windows PowerShell Launcher
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  NetSentinel - Network Intrusion Detection System" -ForegroundColor Cyan
Write-Host "  Launching Cyber SOC Dashboard..." -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$htmlPath = Join-Path $scriptDir "web\index.html"

# Open Dashboard in default Windows browser (Edge/Chrome)
Write-Host "[1] Opening SOC Dashboard in browser..." -ForegroundColor Green
Start-Process $htmlPath

# Check if local Python is available to start backend listener
$pyPath = "C:\Program Files\MySQL\MySQL Workbench 8.0\swb\shell\lib\Python3.13\python.exe"
if (Test-Path $pyPath) {
    Write-Host "[2] Starting Detection Engine listener on port 8080..." -ForegroundColor Green
    $serverScript = Join-Path $scriptDir "server.py"
    Start-Process -FilePath $pyPath -ArgumentList "-u `"$serverScript`" 8080" -WindowStyle Minimized
}

Write-Host "`n[SUCCESS] NetSentinel is running! Check your browser window." -ForegroundColor Yellow
