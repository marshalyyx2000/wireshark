# Create a portable "green" package from the industrial staging dir.
# Does not install to Program Files and isolates profiles via WIRESHARK_APPDATA.
# NOTE: Keep this .ps1 ASCII-only so Windows PowerShell 5.x (GBK default) never
# mojibakes folder/zip names. Chinese UI strings are built via Unicode escapes.
param(
    [string]$BuildDir = $(if ($env:WIRESHARK_BUILD_DIR) { $env:WIRESHARK_BUILD_DIR } else { 'C:\Development\wsbuild-industrial' }),
    [string]$Config = $(if ($env:WIRESHARK_BUILD_CONFIG) { $env:WIRESHARK_BUILD_CONFIG } else { 'RelWithDebInfo' }),
    [string]$OutDir = $(if ($env:WIRESHARK_GREEN_DIR) { $env:WIRESHARK_GREEN_DIR } else { '' }),
    [string]$PackageId = 'Binyao',
    [string]$Version = '0.10.5',
    [switch]$NoZip
)

$ErrorActionPreference = 'Stop'

# Product display name: U+5BBE U+5C27 ("Bin Yao" brand), never literal UTF-8 in this file.
$ProductName = ([char]0x5BBE).ToString() + ([char]0x5C27).ToString()

function Robo-Copy([string]$Src, [string]$Dst, [string[]]$Extra = @()) {
    if (-not (Test-Path -LiteralPath $Src)) {
        throw "Source not found: $Src"
    }
    New-Item -ItemType Directory -Force -Path $Dst | Out-Null
    $rcArgs = @($Src, $Dst, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NC', '/NS', '/NP') + $Extra
    & robocopy @rcArgs | Out-Null
    $code = $LASTEXITCODE
    if ($code -ge 8) {
        throw "robocopy failed ($code): $Src -> $Dst"
    }
}

function Write-Utf8Bom([string]$Path, [string]$Text) {
    $enc = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

function Write-Ascii([string]$Path, [string]$Text) {
    $enc = New-Object System.Text.ASCIIEncoding
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}

$run = Join-Path $BuildDir "run\$Config"
if (-not (Test-Path -LiteralPath (Join-Path $run 'Wireshark.exe'))) {
    throw "Staging Wireshark.exe not found under: $run`nBuild first: tools\minimal-build\build.bat"
}

if (-not $OutDir) {
    # ASCII-only path: avoids Explorer/zip mojibake on Chinese Windows.
    $OutDir = "C:\Development\$PackageId-$Version-green"
}

Write-Host "=== Green package ==="
Write-Host "Source : $run"
Write-Host "Output : $OutDir"

if (Test-Path -LiteralPath $OutDir) {
    Write-Host "Removing existing output..."
    Remove-Item -LiteralPath $OutDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Robo-Copy $run $OutDir @(
    '/XF', '*.pdb', '*.lib', '*.ilk', '*.exp', '*.obj',
    'fuzzshark.exe', 'idl2wrs.exe', 'lemon.exe', 'uninstall.exe'
)

$dataDir = Join-Path $OutDir 'Data'
$profileDir = Join-Path $dataDir 'profile'
$tempDir = Join-Path $dataDir 'temp'
New-Item -ItemType Directory -Force -Path $profileDir, $tempDir | Out-Null

$launcher = @"
@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM Isolate config/plugins from any system-installed Wireshark.
set "WIRESHARK_APPDATA=%~dp0Data\profile"
if not exist "%WIRESHARK_APPDATA%" mkdir "%WIRESHARK_APPDATA%"

set "TEMP=%~dp0Data\temp"
set "TMP=%~dp0Data\temp"
if not exist "%TEMP%" mkdir "%TEMP%"

start "" "%~dp0Wireshark.exe" %*
"@
Write-Ascii (Join-Path $OutDir 'Run.bat') $launcher

$runTshark = @"
@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "WIRESHARK_APPDATA=%~dp0Data\profile"
if not exist "%WIRESHARK_APPDATA%" mkdir "%WIRESHARK_APPDATA%"
"%~dp0tshark.exe" %*
"@
Write-Ascii (Join-Path $OutDir 'tshark.bat') $runTshark

# README body is ASCII + Unicode product chars from [char] escapes (safe).
$readme = @"
$ProductName $Version - portable (no install)
============================================

How to run
----------
1. Unzip to any folder.
2. Double-click Run.bat
3. Do not run a system installer; this folder is self-contained.

Isolation from installed Wireshark
----------------------------------
The launcher sets WIRESHARK_APPDATA to Data\profile under this folder.
Settings/plugins/recent files will NOT go to %APPDATA%\Wireshark,
so an existing Wireshark install is left alone.

Notes
-----
- Open/analyze pcap: no extra driver needed.
- Live capture: Npcap must already be installed on the machine.
- If VCRUNTIME/MSVCP DLL is missing: install Microsoft Visual C++
  2015-2022 x64 redistributable.
- Always start via Run.bat. Opening Wireshark.exe directly uses the
  system profile directory and may share config with an installed copy.

Layout
------
  Run.bat             recommended launcher (profile isolated)
  Wireshark.exe
  tshark.exe / tshark.bat
  dumpcap.exe
  Data\profile\       portable config (auto-created)
  Data\temp\          temp files
"@
Write-Utf8Bom (Join-Path $OutDir 'README.txt') $readme

$files = Get-ChildItem -LiteralPath $OutDir -Recurse -File
$sizeMB = [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1MB, 1)
Write-Host ("Files  : {0}" -f $files.Count)
Write-Host ("Size   : {0} MB" -f $sizeMB)

$zipPath = "$OutDir.zip"
if (-not $NoZip) {
    if (Test-Path -LiteralPath $zipPath) {
        Remove-Item -LiteralPath $zipPath -Force
    }
    Write-Host "Zipping: $zipPath"
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zipPath -CompressionLevel Optimal
    $zipMB = [math]::Round((Get-Item -LiteralPath $zipPath).Length / 1MB, 1)
    Write-Host ("Zip    : {0} MB" -f $zipMB)
}

Write-Host "GREEN_OK"
Write-Host "Folder : $OutDir"
if (-not $NoZip) {
    Write-Host "Zip    : $zipPath"
}
Write-Host "Run    : $(Join-Path $OutDir 'Run.bat')"
