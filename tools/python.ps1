# Resolve real Python rather than the nonfunctional WindowsApps execution alias.
$ErrorActionPreference = 'Stop'
$projectPython = @(
    "$env:LOCALAPPDATA\Python\pythoncore-3.13-64\python.exe",
    "$env:LOCALAPPDATA\Python\pythoncore-3.14-64\python.exe"
    "$env:USERPROFILE\AppData\Local\Python\pythoncore-3.13-64\python.exe"
    "$env:USERPROFILE\AppData\Local\Python\pythoncore-3.14-64\python.exe"
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $projectPython) {
    $projectPython = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $projectPython -or $projectPython -like '*WindowsApps*') {
        throw 'No usable Python found. Supply an installed Python 3.11+ executable.'
    }
}
& $projectPython @args
exit $LASTEXITCODE
