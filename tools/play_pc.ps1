$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$player = Join-Path $projectRoot 'local/pc-core/player/KamaitachiX3.exe'
if (-not (Test-Path -LiteralPath $player -PathType Leaf)) { throw 'Build tools/build_game_window.ps1 first.' }
Start-Process -FilePath $player -WorkingDirectory $projectRoot
