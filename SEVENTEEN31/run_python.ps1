# PowerShell helper to invoke Python automatically
$candidates = @(
    "python",
    "py",
    "C:\Program Files\MySQL\MySQL Workbench 8.0\swb\shell\lib\Python3.13\python.exe",
    "C:\Program Files\MySQL\MySQL Shell 8.0\lib\Python3.13\Lib\venv\scripts\nt\python.exe"
)

$target = $null
foreach ($c in $candidates) {
    try {
        $test = & $c -c "print('OK')" 2>$null
        if ($test -eq "OK") {
            $target = $c
            break
        }
    } catch {}
}

if (-not $target) {
    Write-Error "No working Python interpreter found."
    exit 1
}

& $target $args
exit $LASTEXITCODE
