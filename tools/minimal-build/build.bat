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

call "%VSDEVCMD%" -arch=amd64 -host_arch=amd64
if errorlevel 1 exit /b 1

cd /d "%WIRESHARK_BUILD_DIR%"
if errorlevel 1 exit /b 1

echo === build wireshark / tshark / dumpcap [%WIRESHARK_BUILD_CONFIG%] ===
cmake --build . --config %WIRESHARK_BUILD_CONFIG% --target wireshark -- /nodeReuse:false /m:8
if errorlevel 1 exit /b 1
cmake --build . --config %WIRESHARK_BUILD_CONFIG% --target tshark -- /nodeReuse:false /m:8
if errorlevel 1 exit /b 1
cmake --build . --config %WIRESHARK_BUILD_CONFIG% --target dumpcap -- /nodeReuse:false /m:8
if errorlevel 1 exit /b 1
cmake --build . --config %WIRESHARK_BUILD_CONFIG% --target copy_data_files -- /nodeReuse:false /m:8
if errorlevel 1 exit /b 1

set "RUN_DIR=%WIRESHARK_BUILD_DIR%\run\%WIRESHARK_BUILD_CONFIG%"
echo === verify staging colorfilters ===
findstr /I /C:"hsrp" /C:"@Routing@" "%RUN_DIR%\colorfilters" >nul 2>&1
if not errorlevel 1 (
  echo ERROR: staging colorfilters still references hsrp/Routing
  exit /b 1
)
echo colorfilters OK
echo RUN_DIR=%RUN_DIR%
exit /b 0
