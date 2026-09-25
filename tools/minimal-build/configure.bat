@echo off
setlocal EnableExtensions
call "%~dp0env.bat" || exit /b 1

if not defined VSDEVCMD (
  echo ERROR: VsDevCmd.bat not found. Set VSDEVCMD to your VS 2022 VsDevCmd.bat path.
  exit /b 1
)
if not exist "%CMAKE_PREFIX_PATH%\bin\qmake.exe" if not exist "%CMAKE_PREFIX_PATH%\bin\qt-cmake.bat" (
  echo WARNING: Qt prefix looks missing: %CMAKE_PREFIX_PATH%
)
if not exist "%WIRESHARK_BASE_DIR%" (
  echo ERROR: WIRESHARK_BASE_DIR does not exist: %WIRESHARK_BASE_DIR%
  exit /b 1
)
if not exist "%MAKENSIS_EXECUTABLE%" (
  echo WARNING: makensis not found at %MAKENSIS_EXECUTABLE% ^(NSIS packaging will fail later^)
)

call "%VSDEVCMD%" -arch=amd64 -host_arch=amd64
if errorlevel 1 exit /b 1

if not exist "%WIRESHARK_BUILD_DIR%" mkdir "%WIRESHARK_BUILD_DIR%"
cd /d "%WIRESHARK_BUILD_DIR%"
if errorlevel 1 exit /b 1

echo === configure ENABLE_MINIMAL_BUILD ===
echo SRC=%WIRESHARK_SRC_DIR%
echo BUILD=%WIRESHARK_BUILD_DIR%
echo QT=%CMAKE_PREFIX_PATH%
echo BASE=%WIRESHARK_BASE_DIR%

cmake -G "Visual Studio 17 2022" -A x64 ^
  -DENABLE_MINIMAL_BUILD=ON ^
  -DENABLE_LUA=OFF -DENABLE_GNUTLS=OFF -DENABLE_KERBEROS=OFF -DENABLE_SMI=OFF ^
  -DENABLE_SPEEXDSP=OFF -DENABLE_SBC=OFF -DENABLE_BCG729=OFF -DENABLE_AMRNB=OFF ^
  -DENABLE_AMRWB=OFF -DENABLE_ILBC=OFF -DENABLE_OPUS=OFF -DENABLE_SPANDSP=OFF ^
  -DENABLE_NGHTTP2=OFF -DENABLE_NGHTTP3=OFF -DENABLE_SNAPPY=OFF -DENABLE_BROTLI=OFF ^
  -DENABLE_MINIZIP=OFF -DENABLE_MINIZIPNG=OFF -DENABLE_PLUGINS=OFF -DENABLE_WINSPARKLE=OFF ^
  -DBUILD_androiddump=OFF -DBUILD_sshdump=OFF -DBUILD_ciscodump=OFF -DBUILD_dpauxmon=OFF ^
  -DBUILD_randpktdump=OFF -DBUILD_wifidump=OFF -DBUILD_etwdump=OFF -DBUILD_udpdump=OFF ^
  -DBUILD_sharkd=OFF -DBUILD_mmdbresolve=OFF -DBUILD_rawshark=OFF -DBUILD_capinfos=OFF ^
  -DBUILD_captype=OFF -DBUILD_mergecap=OFF -DBUILD_editcap=OFF -DBUILD_reordercap=OFF ^
  -DBUILD_text2pcap=OFF -DBUILD_randpkt=OFF -DBUILD_dftest=OFF -DBUILD_dcerpcidl2wrs=OFF ^
  -DBUILD_tshark=ON -DBUILD_dumpcap=ON -DBUILD_wireshark=ON ^
  -DWIRESHARK_BASE_DIR="%WIRESHARK_BASE_DIR%" ^
  -DCMAKE_PREFIX_PATH="%CMAKE_PREFIX_PATH%" ^
  -DPOWERSHELL_EXECUTABLE="%POWERSHELL_EXECUTABLE%" ^
  -DMAKENSIS_EXECUTABLE="%MAKENSIS_EXECUTABLE%" ^
  -DENABLE_LTO=ON ^
  "%WIRESHARK_SRC_DIR%"
set "CMAKE_EXIT=%ERRORLEVEL%"
echo CMAKE_EXIT=%CMAKE_EXIT%
exit /b %CMAKE_EXIT%
