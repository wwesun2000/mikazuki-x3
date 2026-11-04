@echo off
setlocal
if not "%~1"=="" set "KX3_ISO=%~f1"
if not exist "%~dp0local\pc-core\player\KamaitachiX3.exe" (
  echo Build the native Windows player with tools\build_game_window.ps1 first.
  pause
  exit /b 2
)
start "" /d "%~dp0." "%~dp0local\pc-core\player\KamaitachiX3.exe"
exit /b %errorlevel%
