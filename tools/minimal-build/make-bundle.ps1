# Assemble a self-contained Wireshark Industrial bundle directory.
# Includes: installer + runtime + source + compile deps (Qt/3rdparty/NSIS) + scripts.
# VS Build Tools is NOT copied (not relocatable); bootstrapper + install script are included.

$ErrorActionPreference = 'Stop'
$Version = '4.7.6'
$BundleRoot = if ($env:WIRESHARK_BUNDLE_DIR) { $env:WIRESHARK_BUNDLE_DIR } else {
    "C:\Development\Wireshark-Industrial-Bundle-$Version"
}

$Src       = if ($env:WIRESHARK_SRC_DIR) { $env:WIRESHARK_SRC_DIR } else { 'F:\software\temp\wireshark' }
$BuildDir  = if ($env:WIRESHARK_BUILD_DIR) { $env:WIRESHARK_BUILD_DIR } else { 'C:\Development\wsbuild-min' }
$QtDir     = if ($env:CMAKE_PREFIX_PATH) { $env:CMAKE_PREFIX_PATH } else { 'C:\Development\Qt\6.10.3\msvc2022_64' }
$BaseDir   = if ($env:WIRESHARK_BASE_DIR) { $env:WIRESHARK_BASE_DIR } else { 'C:\Development\wireshark-third-party' }
$NsisDir   = 'C:\Development\NSIS-Tool'
$NsisAlt   = 'C:\Development\nsis-3.12'
$Installed = 'C:\Program Files\Wireshark'
$Installer = Join-Path $BuildDir "packaging\nsis\Wireshark-$Version-x64.exe"
$VsBoot    = 'C:\Development\vs_BuildTools.exe'

function Robo-Copy($from, $to, $extraArgs = @()) {
    if (-not (Test-Path -LiteralPath $from)) {
        Write-Warning "SKIP missing: $from"
        return
    }
    New-Item -ItemType Directory -Force -Path $to | Out-Null
    $args = @($from, $to, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/nc', '/ns', '/np', '/R:1', '/W:1') + $extraArgs
    & robocopy @args | Out-Null
    $code = $LASTEXITCODE
    if ($code -ge 8) { throw "robocopy failed ($code): $from -> $to" }
    Write-Host "OK  $from"
}

Write-Host "=== Bundle root: $BundleRoot ==="
if (Test-Path -LiteralPath $BundleRoot) {
    Write-Host "Removing existing bundle..."
    Remove-Item -LiteralPath $BundleRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $BundleRoot | Out-Null

# --- 01 installer / install env ---
$d01 = Join-Path $BundleRoot '01-installer'
New-Item -ItemType Directory -Force -Path $d01 | Out-Null
if (-not (Test-Path -LiteralPath $Installer)) { throw "Installer not found: $Installer" }
Copy-Item -LiteralPath $Installer -Destination (Join-Path $d01 (Split-Path $Installer -Leaf)) -Force
$npcap = Join-Path $BaseDir 'wireshark-x64-libs\npcap-1.88.exe'
$usbpcap = Join-Path $BaseDir 'wireshark-x64-libs\USBPcapSetup-1.5.4.0.exe'
if (Test-Path $npcap) { Copy-Item $npcap $d01 -Force }
if (Test-Path $usbpcap) { Copy-Item $usbpcap $d01 -Force }

@'
@echo off
setlocal
cd /d "%~dp0"
echo Installing Wireshark 4.7.6 (silent)...
start /wait "" "Wireshark-4.7.6-x64.exe" /S /desktopicon=yes
if errorlevel 1 echo Wireshark installer exit=%ERRORLEVEL%
if exist "npcap-1.88.exe" (
  echo.
  echo Npcap requires interactive install. Launching...
  start /wait "" "npcap-1.88.exe"
)
echo Done. Wireshark is under "%ProgramFiles%\Wireshark"
pause
'@ | Set-Content -LiteralPath (Join-Path $d01 'install-all.bat') -Encoding ASCII

# --- 02 runtime ---
$d02 = Join-Path $BundleRoot '02-runtime'
if (Test-Path $Installed) {
    Robo-Copy $Installed $d02 @('/XF', '*.pdb')
} else {
    $run = Join-Path $BuildDir 'run\RelWithDebInfo'
    Robo-Copy $run $d02 @('/XF', '*.pdb')
}
@'
@echo off
cd /d "%~dp0"
start "" "Wireshark.exe"
'@ | Set-Content -LiteralPath (Join-Path $d02 'run-wireshark.bat') -Encoding ASCII

# --- 03 source ---
$d03 = Join-Path $BundleRoot '03-source\wireshark'
Robo-Copy $Src $d03 @(
    '/XD', '.vs', 'wsbuild-min', 'wsbuild64', 'build', 'out',
    'CMakeFiles', '__pycache__',
    '/XF', '*.obj', '*.pdb', '*.ilk', '*.exp'
)

# --- 04 compile env ---
$d04 = Join-Path $BundleRoot '04-compile-env'
New-Item -ItemType Directory -Force -Path $d04 | Out-Null
Robo-Copy $QtDir (Join-Path $d04 'Qt\6.10.3\msvc2022_64')
Robo-Copy $BaseDir (Join-Path $d04 'wireshark-third-party')
if (Test-Path $NsisDir) {
    Robo-Copy $NsisDir (Join-Path $d04 'NSIS')
} elseif (Test-Path $NsisAlt) {
    Robo-Copy $NsisAlt (Join-Path $d04 'NSIS')
}
if (Test-Path $VsBoot) {
    Copy-Item $VsBoot (Join-Path $d04 'vs_BuildTools.exe') -Force
}

@'
@echo off
setlocal
cd /d "%~dp0"
set "BOOT=%~dp0vs_BuildTools.exe"
if not exist "%BOOT%" (
  echo ERROR: vs_BuildTools.exe missing in this folder.
  echo Download from https://aka.ms/vs/17/release/vs_BuildTools.exe
  exit /b 1
)
echo Installing VS 2022 Build Tools (C++ / Windows SDK / CMake)...
"%BOOT%" --quiet --wait --norestart --noUpdateInstaller ^
  --add Microsoft.VisualStudio.Workload.VCTools ^
  --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
  --add Microsoft.VisualStudio.Component.Windows11SDK.22621 ^
  --add Microsoft.VisualStudio.Component.VC.CMake.Project ^
  --includeRecommended
echo EXIT=%ERRORLEVEL%
'@ | Set-Content -LiteralPath (Join-Path $d04 'install-vs-buildtools.bat') -Encoding ASCII

# --- 05 scripts (relative to bundle) ---
$d05 = Join-Path $BundleRoot '05-scripts'
New-Item -ItemType Directory -Force -Path $d05 | Out-Null
Copy-Item (Join-Path $Src 'tools\minimal-build\*.bat') $d05 -Force
Copy-Item (Join-Path $Src 'tools\minimal-build\README.md') $d05 -Force
Copy-Item (Join-Path $Src 'tools\minimal-build\make-bundle.ps1') $d05 -Force -ErrorAction SilentlyContinue

@'
@echo off
REM Bundle-local environment overrides (call before configure/build/package).
set "BUNDLE_ROOT=%~dp0.."
for %%I in ("%BUNDLE_ROOT%") do set "BUNDLE_ROOT=%%~fI"

set "WIRESHARK_SRC_DIR=%BUNDLE_ROOT%\03-source\wireshark"
set "WIRESHARK_BUILD_DIR=%BUNDLE_ROOT%\06-build\wsbuild-min"
set "WIRESHARK_BASE_DIR=%BUNDLE_ROOT%\04-compile-env\wireshark-third-party"
set "CMAKE_PREFIX_PATH=%BUNDLE_ROOT%\04-compile-env\Qt\6.10.3\msvc2022_64"
set "WIRESHARK_BUILD_CONFIG=RelWithDebInfo"

if exist "%BUNDLE_ROOT%\04-compile-env\NSIS\tools\makensis.exe" (
  set "MAKENSIS_EXECUTABLE=%BUNDLE_ROOT%\04-compile-env\NSIS\tools\makensis.exe"
) else if exist "%BUNDLE_ROOT%\04-compile-env\NSIS\makensis.exe" (
  set "MAKENSIS_EXECUTABLE=%BUNDLE_ROOT%\04-compile-env\NSIS\makensis.exe"
)

if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" (
  set "VSDEVCMD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" (
  set "VSDEVCMD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
)

echo BUNDLE_ROOT=%BUNDLE_ROOT%
echo SRC=%WIRESHARK_SRC_DIR%
echo BUILD=%WIRESHARK_BUILD_DIR%
echo QT=%CMAKE_PREFIX_PATH%
echo BASE=%WIRESHARK_BASE_DIR%
echo NSIS=%MAKENSIS_EXECUTABLE%
'@ | Set-Content -LiteralPath (Join-Path $d05 'use-bundle-env.bat') -Encoding ASCII

@'
@echo off
setlocal
call "%~dp0use-bundle-env.bat" || exit /b 1
call "%~dp0configure.bat" || exit /b 1
call "%~dp0build.bat" || exit /b 1
call "%~dp0package-nsis.bat" || exit /b 1
echo.
echo Installer should be under:
echo   %WIRESHARK_BUILD_DIR%\packaging\nsis\
dir /b "%WIRESHARK_BUILD_DIR%\packaging\nsis\Wireshark-*.exe" 2>nul
'@ | Set-Content -LiteralPath (Join-Path $d05 'build-all-from-bundle.bat') -Encoding ASCII

# --- README ---
$readme = @"
Wireshark Industrial Bundle $Version
====================================

目录说明
--------
01-installer\     安装环境：NSIS 安装包 + Npcap/USBPcap + install-all.bat
02-runtime\       运行环境：已安装的 Wireshark 文件树（可直接 run-wireshark.bat）
03-source\        源码（含工业协议增强的 Wireshark $Version 树）
04-compile-env\   编译依赖：Qt 6.10.3 msvc2022_64、wireshark-third-party、NSIS、
                  VS Build Tools 引导安装程序（install-vs-buildtools.bat）
05-scripts\       精简构建脚本；先 call use-bundle-env.bat 再 configure/build/package
06-build\         （可选）本地编译输出目录，由脚本自动创建

快速使用
--------
1) 仅运行：
     02-runtime\run-wireshark.bat
   或安装到系统：
     01-installer\install-all.bat

2) 在新机器上编译：
     a. 以管理员运行 04-compile-env\install-vs-buildtools.bat（首次）
     b. 安装 Python 3、Git（若尚未安装）
     c. cmd 中：
          cd /d ...\05-scripts
          build-all-from-bundle.bat

说明
----
- Visual Studio Build Tools 体积大且不宜直接拷贝，故以官方引导安装器形式提供。
- 本包体积主要来自 Qt 与第三方库；运行只需 01/02。
- 当前产品版本：$Version
"@
Set-Content -LiteralPath (Join-Path $BundleRoot 'README.txt') -Value $readme -Encoding UTF8

# size summary
Write-Host ''
Write-Host '=== Bundle size by folder ==='
Get-ChildItem -LiteralPath $BundleRoot -Directory | ForEach-Object {
    $sum = (Get-ChildItem $_.FullName -Recurse -File -EA SilentlyContinue | Measure-Object Length -Sum).Sum
    '{0,8:N2} GB  {1}' -f ($sum / 1GB), $_.Name
}
$total = (Get-ChildItem $BundleRoot -Recurse -File -EA SilentlyContinue | Measure-Object Length -Sum).Sum
Write-Host ('TOTAL  {0:N2} GB' -f ($total / 1GB))
Write-Host "BUNDLE_DIR=$BundleRoot"
