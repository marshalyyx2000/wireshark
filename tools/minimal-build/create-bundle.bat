@echo off
setlocal EnableExtensions
cd /d "%~dp0"
echo === Creating portable Wireshark Industrial SDK bundle ===
echo This copies source, Qt, third-party libs, NSIS, Git, Python, CMake, and
echo the VS Build Tools bootstrapper into a single directory (~5 GB).
echo.
if not defined POWERSHELL_EXECUTABLE set "POWERSHELL_EXECUTABLE=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
"%POWERSHELL_EXECUTABLE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0make-bundle.ps1" %*
set "RC=%ERRORLEVEL%"
if %RC% NEQ 0 (
  echo BUNDLE_FAILED exit=%RC%
  exit /b %RC%
)
echo BUNDLE_OK
exit /b 0
