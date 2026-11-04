param([switch]$Verify)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$exe = Join-Path $projectRoot 'local/pc-core/choice-debug/KamaitachiChoiceDebug.exe'
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { & (Join-Path $PSScriptRoot 'build_choice_debug_window.ps1') }
if (-not $Verify) {
    Start-Process -FilePath $exe -WorkingDirectory $projectRoot
    return
}
$started = [DateTime]::UtcNow
$process = Start-Process -FilePath $exe -WorkingDirectory $projectRoot -ArgumentList '--verify' -PassThru
if (-not $process.WaitForExit(60000)) {
    # The Process object still refers to our original process handle.
    $process.Kill()
    $process.WaitForExit()
    throw "Window verifier exceeded 60 seconds (owned PID $($process.Id))"
}
$reportPath = Join-Path $projectRoot 'analysis/native-core/choice-debug-window.json'
if ($process.ExitCode -ne 0) { throw "Window verifier failed (owned PID $($process.Id), exit $($process.ExitCode)); see $reportPath" }
$report = Get-Content -Raw -LiteralPath $reportPath | ConvertFrom-Json
if ($report.status -ne 'passed') { throw "Window verifier reported $($report.status)" }
$record = [ordered]@{ started_utc=$started.ToString('o'); ended_utc=[DateTime]::UtcNow.ToString('o')
    owned_pid=$process.Id; exited=$process.HasExited; exit_code=$process.ExitCode
    executable_sha256=(Get-FileHash -LiteralPath $exe).Hash; report_sha256=(Get-FileHash -LiteralPath $reportPath).Hash
    capture_sha256=(Get-FileHash -LiteralPath (Join-Path $projectRoot $report.capture)).Hash; checks=$report.checks }
[IO.File]::WriteAllText((Join-Path $projectRoot 'analysis/native-core/choice-debug-window-run.json'),($record | ConvertTo-Json))
$record
