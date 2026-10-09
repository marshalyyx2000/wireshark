@echo off
setlocal EnableExtensions
cd /d "%~dp0"
call "%~dp0env.bat"
echo === Creating portable green package (no install, isolated profile) ===
if not defined POWERSHELL_EXECUTABLE set "POWERSHELL_EXECUTABLE=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
"%POWERSHELL_EXECUTABLE%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0make-green-package.ps1" %*
set "RC=%ERRORLEVEL%"
if %RC% NEQ 0 (
  echo GREEN_FAILED exit=%RC%
  exit /b %RC%
)
echo GREEN_OK
exit /b 0
