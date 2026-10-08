@echo off
REM Shared defaults for ENABLE_MINIMAL_BUILD Windows builds.
REM Override any variable before calling configure/build/package scripts.

if not defined WIRESHARK_SRC_DIR (
  set "WIRESHARK_SRC_DIR=%~dp0..\.."
)
for %%I in ("%WIRESHARK_SRC_DIR%") do set "WIRESHARK_SRC_DIR=%%~fI"

if not defined WIRESHARK_BUILD_DIR set "WIRESHARK_BUILD_DIR=C:\Development\wsbuild-industrial"
if not defined WIRESHARK_BASE_DIR set "WIRESHARK_BASE_DIR=C:\Development\wireshark-third-party"
if not defined CMAKE_PREFIX_PATH set "CMAKE_PREFIX_PATH=C:\Development\Qt\6.10.3\msvc2022_64"
if not defined MAKENSIS_EXECUTABLE set "MAKENSIS_EXECUTABLE=C:\Development\NSIS-Tool\tools\makensis.exe"
if not defined POWERSHELL_EXECUTABLE set "POWERSHELL_EXECUTABLE=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
if not defined WIRESHARK_BUILD_CONFIG set "WIRESHARK_BUILD_CONFIG=RelWithDebInfo"

if not defined VSDEVCMD (
  if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" (
    set "VSDEVCMD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
  ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" (
    set "VSDEVCMD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
  ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" (
    set "VSDEVCMD=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
  ) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat" (
    set "VSDEVCMD=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\Common7\Tools\VsDevCmd.bat"
  )
)

REM Portable bundle tools (set by use-bundle-env.bat) take precedence over system installs.
if defined BUNDLE_GIT_DIR if exist "%BUNDLE_GIT_DIR%\cmd" (
  set "PATH=%BUNDLE_GIT_DIR%\cmd;%BUNDLE_GIT_DIR%\bin;%PATH%"
) else if exist "%ProgramFiles%\Git\cmd" (
  set "PATH=%ProgramFiles%\Git\cmd;%ProgramFiles%\Git\bin;%PATH%"
)
if defined BUNDLE_PYTHON_DIR if exist "%BUNDLE_PYTHON_DIR%\python.exe" (
  set "PATH=%BUNDLE_PYTHON_DIR%;%BUNDLE_PYTHON_DIR%\Scripts;%PATH%"
)
if defined BUNDLE_CMAKE_DIR if exist "%BUNDLE_CMAKE_DIR%\bin\cmake.exe" (
  set "PATH=%BUNDLE_CMAKE_DIR%\bin;%PATH%"
)

call "%~dp0fix-msbuild-env.bat"

set "PYTHONUTF8=1"
set "PLATFORM=x64"
