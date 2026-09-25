@echo off
setlocal EnableExtensions
call "%~dp0env.bat" || exit /b 1

if not defined VSDEVCMD (
  echo ERROR: VsDevCmd.bat not found. Set VSDEVCMD to your VS 2022 VsDevCmd.bat path.
  exit /b 1
)
if not exist "%WIRESHARK_BUILD_DIR%\CMakeCache.txt" (
  echo ERROR: Build dir not configured: %WIRESHARK_BUILD_DIR%
  echo Run tools\minimal-build\configure.bat first.
  exit /b 1
)
if not exist "%MAKENSIS_EXECUTABLE%" (
  echo ERROR: makensis not found: %MAKENSIS_EXECUTABLE%
  echo Set MAKENSIS_EXECUTABLE to your makensis.exe path.
  exit /b 1
)

call "%VSDEVCMD%" -arch=amd64 -host_arch=amd64
if errorlevel 1 exit /b 1

cd /d "%WIRESHARK_BUILD_DIR%"
if errorlevel 1 exit /b 1

echo === wireshark_nsis_prep ===
cmake --build . --config %WIRESHARK_BUILD_CONFIG% --target wireshark_nsis_prep --parallel
if errorlevel 1 exit /b 1

echo === wireshark_nsis ===
cmake --build . --config %WIRESHARK_BUILD_CONFIG% --target wireshark_nsis --parallel
if errorlevel 1 exit /b 1

set "INSTALLER=%WIRESHARK_BUILD_DIR%\packaging\nsis\Wireshark-4.7.4-x64.exe"
if not exist "%INSTALLER%" (
  echo ERROR: installer not found: %INSTALLER%
  exit /b 1
)

"%POWERSHELL_EXECUTABLE%" -NoProfile -Command ^
  "$i=Get-Item -LiteralPath '%INSTALLER%'; Write-Host ('INSTALLER=' + $i.FullName); Write-Host ('SIZE_BYTES=' + $i.Length); Write-Host ('SIZE_MB={0:N2}' -f ($i.Length/1MB)); if ($i.Length -gt 30MB) { Write-Host 'WARNING: installer exceeds 30 MB target'; exit 2 }"
set "PS_EXIT=%ERRORLEVEL%"
if %PS_EXIT% EQU 2 exit /b 2
if %PS_EXIT% NEQ 0 exit /b %PS_EXIT%
exit /b 0
