@echo off
setlocal EnableExtensions EnableDelayedExpansion
call "%~dp0env.bat" || exit /b 1

set "RUN_DIR=%WIRESHARK_BUILD_DIR%\run\%WIRESHARK_BUILD_CONFIG%"
set "TSHARK=%RUN_DIR%\tshark.exe"
set "DUMPCAP=%RUN_DIR%\dumpcap.exe"
set "WIRESHARK=%RUN_DIR%\Wireshark.exe"
set "INSTALLER=%WIRESHARK_BUILD_DIR%\packaging\nsis\Wireshark-4.7.6-x64.exe"
set "FAIL=0"

echo === smoke-check [%RUN_DIR%] ===

if not exist "%TSHARK%" (
  echo FAIL: missing %TSHARK%
  set "FAIL=1"
) else (
  "%TSHARK%" -v >nul 2>&1
  if errorlevel 1 (
    echo FAIL: tshark -v
    set "FAIL=1"
  ) else (
    echo OK: tshark -v
  )
)

if not exist "%DUMPCAP%" (
  echo FAIL: missing %DUMPCAP%
  set "FAIL=1"
) else (
  "%DUMPCAP%" -v >nul 2>&1
  if errorlevel 1 (
    echo FAIL: dumpcap -v
    set "FAIL=1"
  ) else (
    echo OK: dumpcap -v
  )
)

if not exist "%WIRESHARK%" (
  echo FAIL: missing %WIRESHARK%
  set "FAIL=1"
) else (
  "%WIRESHARK%" -v >nul 2>&1
  if errorlevel 1 (
    echo FAIL: Wireshark -v
    set "FAIL=1"
  ) else (
    echo OK: Wireshark -v
  )
)

if exist "%TSHARK%" (
  set "PROTO_OUT=%TEMP%\ws-min-protocols.txt"
  set "PROTO_ERR=%TEMP%\ws-min-protocols.err"
  "%TSHARK%" -G protocols >"!PROTO_OUT!" 2>"!PROTO_ERR!"
  findstr /I /C:"OOPS" /C:"doesn't exist" "!PROTO_ERR!" >nul 2>&1
  if not errorlevel 1 (
    echo FAIL: tshark -G protocols reported OOPS / missing dissector table
    type "!PROTO_ERR!"
    set "FAIL=1"
  ) else (
    echo OK: no OOPS / missing dissector table in stderr
  )
  "%POWERSHELL_EXECUTABLE%" -NoProfile -Command ^
    "$rows=Get-Content -LiteralPath '!PROTO_OUT!' | ForEach-Object { ($_ -split [char]9)[2] };" ^
    "$need=@('mms','goose','sv','iec60870_104','mbtcp');" ^
    "$bad=@('http','dns','tls','wlan','lua');" ^
    "$missing=@($need | Where-Object { $_ -notin $rows });" ^
    "$leaks=@($bad | Where-Object { $_ -in $rows });" ^
    "if($missing.Count){ Write-Host ('FAIL: missing protocols: '+($missing -join ', ')); exit 1 };" ^
    "Write-Host 'OK: industrial protocols present';" ^
    "if($leaks.Count){ Write-Host ('FAIL: unexpected protocols: '+($leaks -join ', ')); exit 2 };" ^
    "Write-Host 'OK: http/dns/tls/wlan/lua absent'; exit 0"
  set "PS_PROTO=%ERRORLEVEL%"
  if !PS_PROTO! EQU 1 set "FAIL=1"
  if !PS_PROTO! EQU 2 set "FAIL=1"
  if !PS_PROTO! GTR 2 (
    echo FAIL: protocol list check script error
    set "FAIL=1"
  )
)

if exist "%RUN_DIR%\colorfilters" (
  findstr /I /C:"hsrp" /C:"@Routing@" "%RUN_DIR%\colorfilters" >nul 2>&1
  if not errorlevel 1 (
    echo FAIL: colorfilters still has hsrp/Routing
    set "FAIL=1"
  ) else (
    echo OK: colorfilters minimal
  )
)

if exist "%INSTALLER%" (
  "%POWERSHELL_EXECUTABLE%" -NoProfile -Command ^
    "$i=Get-Item -LiteralPath '%INSTALLER%'; $mb=[math]::Round($i.Length/1MB,2); Write-Host ('OK: installer {0} ({1} MB)' -f $i.FullName,$mb); if ($i.Length -gt 30MB) { Write-Host 'FAIL: installer > 30 MB'; exit 1 }"
  if errorlevel 1 set "FAIL=1"
) else (
  echo WARN: installer not built yet: %INSTALLER%
)

if "!FAIL!"=="1" (
  echo === smoke-check FAILED ===
  exit /b 1
)
echo === smoke-check PASSED ===
exit /b 0
