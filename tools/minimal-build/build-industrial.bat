@echo off
REM ============================================================================
REM Wireshark Industrial (ENABLE_MINIMAL_BUILD) - configure + build + NSIS.
REM
REM   Source : F:\software\temp\wireshark-industrial   (Binyao 0.10.0)
REM   Build  : C:\Development\wsbuild-industrial
REM   Output : C:\Development\wsbuild-industrial\packaging\nsis\Binyao-0.10.0-x64.exe
REM
REM Two environment hazards are handled here:
REM  1) The parent environment defines BOTH "NO_PROXY" and "no_proxy" (plus the
REM     HTTP(S)_PROXY pair). MSBuild's CL.exe task copies the environment into a
REM     case-insensitive hashtable, so the lowercase duplicate makes it throw
REM     "System.ArgumentException: an item with the same key has already been
REM     added" -> error MSB6001 on every compile. Clearing the lowercase copies
REM     fixes it.
REM  2) MSBuild node reuse leaves orphaned worker nodes that keep touching the
REM     build tree after the build command returns. /nodeReuse:false prevents it.
REM ============================================================================
setlocal

set "SRC=F:\software\temp\wireshark-industrial"
set "BUILD=C:\Development\wsbuild-industrial"
set "CFG=RelWithDebInfo"
set "VSDEVCMD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
set "QT=C:\Development\Qt\6.10.3\msvc2022_64"
set "BASE=C:\Development\wireshark-third-party"
set "MAKENSIS=C:/Development/NSIS-Tool/tools/makensis.exe"

REM --- 1) kill the duplicate-case proxy variables that crash MSBuild ---------
set "no_proxy="
set "http_proxy="
set "https_proxy="
set "all_proxy="
set "ftp_proxy="
set "PYTHONUTF8=1"
set "PLATFORM=x64"

call "%VSDEVCMD%" -arch=amd64 -host_arch=amd64
if errorlevel 1 (echo VSDEVCMD_FAILED & exit /b 1)

if not exist "%BUILD%" mkdir "%BUILD%"
cd /d "%BUILD%"
if errorlevel 1 (echo BUILD_DIR_MISSING & exit /b 1)

echo ==== CONFIGURE ====
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
  -DWIRESHARK_BASE_DIR=%BASE% ^
  -DCMAKE_PREFIX_PATH=%QT% ^
  -DPOWERSHELL_EXECUTABLE=C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe ^
  -DMAKENSIS_EXECUTABLE=%MAKENSIS% ^
  -DENABLE_LTO=ON ^
  "%SRC%"
if errorlevel 1 (echo CONFIGURE_FAILED & exit /b 1)
echo CONFIGURE_OK

echo ==== BUILD wireshark ====
cmake --build . --config %CFG% --target wireshark -- /nodeReuse:false /m:8
if errorlevel 1 (echo BUILD_WIRESHARK_FAILED & exit /b 1)
echo BUILD_WIRESHARK_OK

echo ==== BUILD tshark ====
cmake --build . --config %CFG% --target tshark -- /nodeReuse:false /m:8
if errorlevel 1 (echo BUILD_TSHARK_FAILED & exit /b 1)
echo BUILD_TSHARK_OK

echo ==== BUILD dumpcap ====
cmake --build . --config %CFG% --target dumpcap -- /nodeReuse:false /m:8
if errorlevel 1 (echo BUILD_DUMPCAP_FAILED & exit /b 1)
echo BUILD_DUMPCAP_OK

echo ==== NSIS PREP ====
cmake --build . --config %CFG% --target wireshark_nsis_prep -- /nodeReuse:false /m:8
if errorlevel 1 (echo NSIS_PREP_FAILED & exit /b 1)
echo NSIS_PREP_OK

echo ==== NSIS PACKAGE ====
cmake --build . --config %CFG% --target wireshark_nsis -- /nodeReuse:false /m:8
if errorlevel 1 (echo NSIS_FAILED & exit /b 1)
echo NSIS_OK

echo ==== DONE ====
for %%F in ("%BUILD%\packaging\nsis\*.exe") do echo PKG %%~nxF %%~zF
endlocal
