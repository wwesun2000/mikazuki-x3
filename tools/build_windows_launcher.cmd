@echo off
setlocal
cd /d "%~dp0\.."
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo Visual Studio Build Tools with C++ are required.
    exit /b 1
)
set "VSROOT="
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
if not defined VSROOT (
    echo Visual Studio x64 C++ tools were not found.
    exit /b 1
)
call "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
if not exist "build\public-launcher" mkdir "build\public-launcher"
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /EHsc /O2 /Fo"build\public-launcher\portable_launcher.obj" /Fe"build\public-launcher\MikazukiX3.exe" "port\platform\windows\portable_launcher.cpp" /link /SUBSYSTEM:WINDOWS user32.lib
exit /b %ERRORLEVEL%
