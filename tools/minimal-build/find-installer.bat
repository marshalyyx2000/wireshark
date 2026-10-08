@echo off
REM Sets INSTALLER to the first NSIS *.exe under %WIRESHARK_BUILD_DIR%\packaging\nsis
setlocal EnableExtensions
set "INSTALLER="
if not defined WIRESHARK_BUILD_DIR (
  echo ERROR: WIRESHARK_BUILD_DIR not set
  exit /b 1
)
set "NSIS_DIR=%WIRESHARK_BUILD_DIR%\packaging\nsis"
if not exist "%NSIS_DIR%" (
  echo ERROR: NSIS output dir missing: %NSIS_DIR%
  exit /b 1
)
for %%F in ("%NSIS_DIR%\*.exe") do (
  set "INSTALLER=%%~fF"
  goto :found
)
echo ERROR: no installer exe in %NSIS_DIR%
exit /b 1

:found
endlocal & set "INSTALLER=%INSTALLER%"
exit /b 0
