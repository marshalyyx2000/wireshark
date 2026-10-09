@echo off
setlocal EnableExtensions
cd /d "%~dp0"
echo === Creating portable Wireshark Industrial SDK bundle ===
echo Copies source + portable .git (full history by default), Qt, third-party,
echo NSIS, Git, Python, CMake, and the VS Build Tools bootstrapper (~5 GB+).
echo Pass -ShallowGit for a smaller .git; -SkipInstaller if NSIS exe is missing.
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
