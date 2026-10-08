# Assemble a self-contained Wireshark Industrial (宾尧) portable SDK.
# Includes: installer + runtime + source + compile deps + portable Git/Python/CMake + scripts.
# VS Build Tools is NOT copied (not relocatable); official bootstrapper is bundled instead.
#
# Usage:
#   powershell -File tools\minimal-build\make-bundle.ps1
#   $env:WIRESHARK_BUNDLE_DIR = 'D:\Binyao-SDK'; .\make-bundle.ps1
#   .\make-bundle.ps1 -SkipInstaller   # skip 01-installer if not built yet

param(
    [switch]$SkipInstaller,
    # Include full git history (~2 GB for this worktree's common repo). Default is a
    # portable shallow clone sufficient for vcs_version.h / make-version.py.
    [switch]$FullGit
)

$ErrorActionPreference = 'Stop'

function Read-CMakeValue {
    param([string]$File, [string]$Name)
    if (-not (Test-Path -LiteralPath $File)) { return $null }
    $pattern = 'set\(' + $Name + '\s+"([^"]+)"\)'
    $literal = $null
    $fallback = $null
    foreach ($line in Get-Content -LiteralPath $File) {
        if ($line -match $pattern) {
            if ($Matches[1] -notmatch '\$\{') {
                $literal = $Matches[1]
            } else {
                $fallback = $Matches[1]
            }
        }
    }
    if ($literal) { return $literal }
    return $fallback
}

function Robo-Copy {
    param(
        [string]$From,
        [string]$To,
        [string[]]$ExtraArgs = @()
    )
    if (-not (Test-Path -LiteralPath $From)) {
        Write-Warning "SKIP missing: $From"
        return $false
    }
    New-Item -ItemType Directory -Force -Path $To | Out-Null
    $args = @($From, $To, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/nc', '/ns', '/np', '/R:1', '/W:1') + $ExtraArgs
    & robocopy @args | Out-Null
    $code = $LASTEXITCODE
    if ($code -ge 8) { throw "robocopy failed ($code): $From -> $To" }
    Write-Host "OK  $From"
    return $true
}

function Find-FirstPath {
    param([string[]]$Candidates)
    foreach ($p in $Candidates) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    return $null
}

function Find-Installer {
    param([string]$NsisDir)
    if (-not (Test-Path -LiteralPath $NsisDir)) { return $null }
    $exes = Get-ChildItem -LiteralPath $NsisDir -Filter '*.exe' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
    if ($exes.Count -eq 0) { return $null }
    return $exes[0].FullName
}

function Find-GitExe {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Git\cmd\git.exe'),
        'git.exe'
    )
    foreach ($c in $candidates) {
        if ($c -eq 'git.exe') {
            $cmd = Get-Command git.exe -ErrorAction SilentlyContinue
            if ($cmd) { return $cmd.Source }
        } elseif (Test-Path -LiteralPath $c) {
            return $c
        }
    }
    return $null
}

function Embed-PortableGit {
    param(
        [string]$SrcRoot,
        [string]$DestRoot,
        [switch]$FullHistory
    )
    $git = Find-GitExe
    if (-not $git) {
        Write-Warning "git.exe not found — 03-source will have no .git (vcs_version.h may fall back)"
        return
    }

    $destGit = Join-Path $DestRoot '.git'
    if (Test-Path -LiteralPath $destGit) {
        # Worktree leaves a .git *file* pointing at the original machine — remove it.
        Remove-Item -LiteralPath $destGit -Recurse -Force
    }

    Push-Location -LiteralPath $SrcRoot
    try {
        $head = & $git rev-parse HEAD
        $branch = & $git branch --show-current
        $commonDir = & $git rev-parse --path-format=absolute --git-common-dir
    } finally {
        Pop-Location
    }
    if (-not $head) { throw "Cannot resolve HEAD in $SrcRoot" }

    Write-Host "Embedding portable .git (HEAD=$head branch=$branch FullGit=$FullHistory)..."

    if ($FullHistory -and (Test-Path -LiteralPath $commonDir)) {
        Robo-Copy $commonDir $destGit @('/XD', 'worktrees', 'modules') | Out-Null
        # Convert shared/common repo copy into a normal worktree-backed .git
        & $git --git-dir=$destGit config --bool core.bare false
        & $git --git-dir=$destGit config core.worktree $DestRoot
        if ($branch) {
            Set-Content -LiteralPath (Join-Path $destGit 'HEAD') -Value "ref: refs/heads/$branch" -Encoding ASCII -NoNewline
            Set-Content -LiteralPath (Join-Path $destGit 'HEAD') -Value "ref: refs/heads/$branch`n" -Encoding ASCII
        } else {
            Set-Content -LiteralPath (Join-Path $destGit 'HEAD') -Value "$head`n" -Encoding ASCII
        }
    } else {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('ws-bundle-git-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        try {
            $cloneArgs = @('clone', '--no-local', '--no-checkout', '--depth', '100')
            if ($branch) {
                $cloneArgs += @('--single-branch', '--branch', $branch)
            }
            $cloneArgs += @($SrcRoot, $tmp)
            & $git @cloneArgs
            if ($LASTEXITCODE -ne 0) { throw "git clone failed ($LASTEXITCODE) for portable .git" }
            # Tags help make-version.py's `git describe --match v[1-9]*`
            & $git -C $tmp fetch --tags --depth 100 2>$null | Out-Null
            Move-Item -LiteralPath (Join-Path $tmp '.git') -Destination $destGit -Force
            & $git --git-dir=$destGit config --bool core.bare false
            & $git --git-dir=$destGit config core.worktree $DestRoot
        } finally {
            if (Test-Path -LiteralPath $tmp) {
                Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Sanity: make-version.py only needs --git-dir operations
    $check = & $git --git-dir=$destGit rev-parse HEAD
    $desc = & $git --git-dir=$destGit describe --abbrev=12 --long --always --match 'v[1-9]*' 2>$null
    Write-Host "OK  portable .git HEAD=$check describe=$desc"
}

function Ensure-VsBootstrapper {
    param([string]$DestPath)
    if (Test-Path -LiteralPath $DestPath) { return $DestPath }
    $candidates = @(
        'C:\Development\vs_BuildTools.exe',
        "$env:USERPROFILE\Downloads\vs_BuildTools.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) {
            Copy-Item -LiteralPath $c -Destination $DestPath -Force
            Write-Host "OK  copied VS bootstrapper from $c"
            return $DestPath
        }
    }
    Write-Host "Downloading VS 2022 Build Tools bootstrapper (~4 MB)..."
    $url = 'https://aka.ms/vs/17/release/vs_BuildTools.exe'
    Invoke-WebRequest -Uri $url -OutFile $DestPath -UseBasicParsing
    Write-Host "OK  downloaded $url"
    return $DestPath
}

# --- resolve version / product from CMakeLists.txt ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DefaultSrc = (Resolve-Path (Join-Path $ScriptDir '..\..')).Path
$Src = if ($env:WIRESHARK_SRC_DIR) { $env:WIRESHARK_SRC_DIR } else { $DefaultSrc }
$CMakeLists = Join-Path $Src 'CMakeLists.txt'
$Version = Read-CMakeValue $CMakeLists 'PROJECT_VERSION'
if (-not $Version) { $Version = '0.10.3' }
$ProductName = Read-CMakeValue $CMakeLists 'MINIMAL_PRODUCT_NAME'
if (-not $ProductName) { $ProductName = '宾尧' }

$BundleRoot = if ($env:WIRESHARK_BUNDLE_DIR) {
    $env:WIRESHARK_BUNDLE_DIR
} else {
    "C:\Development\Wireshark-Industrial-Bundle-$Version"
}

$BuildDir  = if ($env:WIRESHARK_BUILD_DIR) { $env:WIRESHARK_BUILD_DIR } else { 'C:\Development\wsbuild-industrial' }
$QtDir     = if ($env:CMAKE_PREFIX_PATH) { $env:CMAKE_PREFIX_PATH } else { 'C:\Development\Qt\6.10.3\msvc2022_64' }
$BaseDir   = if ($env:WIRESHARK_BASE_DIR) { $env:WIRESHARK_BASE_DIR } else { 'C:\Development\wireshark-third-party' }
$NsisSrc   = Find-FirstPath @('C:\Development\NSIS-Tool', 'C:\Development\nsis-3.12')
$Installed = 'C:\Program Files\Wireshark'
$Installer = Find-Installer (Join-Path $BuildDir 'packaging\nsis')

$GitSrc = Find-FirstPath @(
    $env:BUNDLE_GIT_SRC,
    "${env:ProgramFiles}\Git"
)
$PythonSrc = Find-FirstPath @(
    $env:BUNDLE_PYTHON_SRC,
    $env:PYTHON_HOME,
    "$env:LOCALAPPDATA\Programs\Python\Python313",
    "$env:LOCALAPPDATA\Programs\Python\Python312",
    "$env:LOCALAPPDATA\Programs\Python\Python311",
    'C:\Python313',
    'C:\Python312',
    'C:\Python311'
)
$CmakeSrc = Find-FirstPath @(
    $env:BUNDLE_CMAKE_SRC,
    "${env:ProgramFiles}\CMake"
)

Write-Host "=== Wireshark Industrial Portable SDK ==="
Write-Host "Product : $ProductName"
Write-Host "Version : $Version"
Write-Host "Source  : $Src"
Write-Host "Bundle  : $BundleRoot"
Write-Host ""

if (Test-Path -LiteralPath $BundleRoot) {
    Write-Host "Removing existing bundle..."
    Remove-Item -LiteralPath $BundleRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $BundleRoot | Out-Null

# --- 01 installer ---
$d01 = Join-Path $BundleRoot '01-installer'
New-Item -ItemType Directory -Force -Path $d01 | Out-Null
if ($Installer) {
    $instName = Split-Path $Installer -Leaf
    Copy-Item -LiteralPath $Installer -Destination (Join-Path $d01 $instName) -Force
    Write-Host "OK  installer $instName"
} elseif (-not $SkipInstaller) {
    Write-Warning "Installer not found under $BuildDir\packaging\nsis — run build-industrial.bat first, or pass -SkipInstaller"
}
$npcap = Join-Path $BaseDir 'wireshark-x64-libs\npcap-1.88.exe'
$usbpcap = Join-Path $BaseDir 'wireshark-x64-libs\USBPcapSetup-1.5.4.0.exe'
if (Test-Path $npcap) { Copy-Item $npcap $d01 -Force }
if (Test-Path $usbpcap) { Copy-Item $usbpcap $d01 -Force }

$installBat = @"
@echo off
setlocal
cd /d "%~dp0"
for %%F in (*.exe) do (
  if /I not "%%~nxF"=="npcap-1.88.exe" if /I not "%%~nxF"=="USBPcapSetup-1.5.4.0.exe" (
    echo Installing $ProductName $Version (silent)...
    start /wait "" "%%~nxF" /S /desktopicon=yes
    if errorlevel 1 echo Installer exit=%%ERRORLEVEL%%
    goto :npcap
  )
)
echo ERROR: no product installer exe found in this folder.
pause
exit /b 1
:npcap
if exist "npcap-1.88.exe" (
  echo.
  echo Npcap requires interactive install. Launching...
  start /wait "" "npcap-1.88.exe"
)
echo Done. Product is under "%ProgramFiles%\Wireshark"
pause
"@
Set-Content -LiteralPath (Join-Path $d01 'install-all.bat') -Value $installBat -Encoding ASCII

# --- 02 runtime ---
$d02 = Join-Path $BundleRoot '02-runtime'
if (Test-Path $Installed) {
    Robo-Copy $Installed $d02 @('/XF', '*.pdb') | Out-Null
} else {
    $run = Join-Path $BuildDir 'run\RelWithDebInfo'
    Robo-Copy $run $d02 @('/XF', '*.pdb') | Out-Null
}
@'
@echo off
cd /d "%~dp0"
start "" "Wireshark.exe"
'@ | Set-Content -LiteralPath (Join-Path $d02 'run-wireshark.bat') -Encoding ASCII

# --- 03 source ---
$d03 = Join-Path $BundleRoot '03-source\wireshark'
Robo-Copy $Src $d03 @(
    '/XD', '.vs', 'wsbuild-min', 'wsbuild-industrial', 'wsbuild64', 'build', 'out',
    'CMakeFiles', '__pycache__', '.git',
    '/XF', '*.obj', '*.pdb', '*.ilk', '*.exp'
) | Out-Null

# --- 04 compile env ---
$d04 = Join-Path $BundleRoot '04-compile-env'
New-Item -ItemType Directory -Force -Path $d04 | Out-Null
Robo-Copy $QtDir (Join-Path $d04 'Qt\6.10.3\msvc2022_64') | Out-Null
Robo-Copy $BaseDir (Join-Path $d04 'wireshark-third-party') | Out-Null
if ($NsisSrc) {
    Robo-Copy $NsisSrc (Join-Path $d04 'NSIS') | Out-Null
}
if ($GitSrc) {
    Robo-Copy $GitSrc (Join-Path $d04 'Git') | Out-Null
} else {
    Write-Warning "Git not found — set BUNDLE_GIT_SRC or install Git for portable bundle"
}
if ($PythonSrc) {
    Robo-Copy $PythonSrc (Join-Path $d04 'Python') | Out-Null
} else {
    Write-Warning "Python not found — set BUNDLE_PYTHON_SRC or install Python 3.11+"
}
if ($CmakeSrc) {
    Robo-Copy $CmakeSrc (Join-Path $d04 'CMake') | Out-Null
} else {
    Write-Warning "CMake not found — VS Build Tools can supply cmake after install-vs-buildtools.bat"
}
$vsDest = Join-Path $d04 'vs_BuildTools.exe'
Ensure-VsBootstrapper $vsDest | Out-Null

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
echo This may take 10-30 minutes. Run as Administrator if prompted.
"%BOOT%" --quiet --wait --norestart --noUpdateInstaller ^
  --add Microsoft.VisualStudio.Workload.VCTools ^
  --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 ^
  --add Microsoft.VisualStudio.Component.Windows11SDK.22621 ^
  --add Microsoft.VisualStudio.Component.VC.CMake.Project ^
  --includeRecommended
echo EXIT=%ERRORLEVEL%
if errorlevel 1 (
  echo VS install failed. Try running this script as Administrator.
  exit /b %ERRORLEVEL%
)
echo VS Build Tools installed. Re-open cmd and run 05-scripts\build-all-from-bundle.bat
'@ | Set-Content -LiteralPath (Join-Path $d04 'install-vs-buildtools.bat') -Encoding ASCII

# --- 05 scripts ---
$d05 = Join-Path $BundleRoot '05-scripts'
New-Item -ItemType Directory -Force -Path $d05 | Out-Null
Copy-Item (Join-Path $Src 'tools\minimal-build\*.bat') $d05 -Force
Copy-Item (Join-Path $Src 'tools\minimal-build\*.ps1') $d05 -Force -ErrorAction SilentlyContinue
Copy-Item (Join-Path $Src 'tools\minimal-build\README.md') $d05 -Force -ErrorAction SilentlyContinue

@'
@echo off
REM Bundle-local environment overrides (call before configure/build/package).
set "BUNDLE_ROOT=%~dp0.."
for %%I in ("%BUNDLE_ROOT%") do set "BUNDLE_ROOT=%%~fI"

set "WIRESHARK_SRC_DIR=%BUNDLE_ROOT%\03-source\wireshark"
set "WIRESHARK_BUILD_DIR=%BUNDLE_ROOT%\06-build\wsbuild-industrial"
set "WIRESHARK_BASE_DIR=%BUNDLE_ROOT%\04-compile-env\wireshark-third-party"
set "CMAKE_PREFIX_PATH=%BUNDLE_ROOT%\04-compile-env\Qt\6.10.3\msvc2022_64"
set "WIRESHARK_BUILD_CONFIG=RelWithDebInfo"

set "BUNDLE_GIT_DIR=%BUNDLE_ROOT%\04-compile-env\Git"
set "BUNDLE_PYTHON_DIR=%BUNDLE_ROOT%\04-compile-env\Python"
set "BUNDLE_CMAKE_DIR=%BUNDLE_ROOT%\04-compile-env\CMake"

if exist "%BUNDLE_ROOT%\04-compile-env\NSIS\tools\makensis.exe" (
  set "MAKENSIS_EXECUTABLE=%BUNDLE_ROOT%\04-compile-env\NSIS\tools\makensis.exe"
) else if exist "%BUNDLE_ROOT%\04-compile-env\NSIS\makensis.exe" (
  set "MAKENSIS_EXECUTABLE=%BUNDLE_ROOT%\04-compile-env\NSIS\makensis.exe"
)

if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" (
  set "VSDEVCMD=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat"
) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" (
  set "VSDEVCMD=%ProgramFiles%\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" (
  set "VSDEVCMD=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
)

echo BUNDLE_ROOT=%BUNDLE_ROOT%
echo SRC=%WIRESHARK_SRC_DIR%
echo BUILD=%WIRESHARK_BUILD_DIR%
echo QT=%CMAKE_PREFIX_PATH%
echo BASE=%WIRESHARK_BASE_DIR%
echo NSIS=%MAKENSIS_EXECUTABLE%
echo GIT=%BUNDLE_GIT_DIR%
echo PYTHON=%BUNDLE_PYTHON_DIR%
echo CMAKE=%BUNDLE_CMAKE_DIR%
'@ | Set-Content -LiteralPath (Join-Path $d05 'use-bundle-env.bat') -Encoding ASCII

@'
@echo off
setlocal EnableExtensions
call "%~dp0use-bundle-env.bat" || exit /b 1
call "%~dp0configure.bat" || exit /b 1
call "%~dp0build.bat" || exit /b 1
call "%~dp0package-nsis.bat" || exit /b 1
echo.
echo === Build complete ===
echo Installer:
dir /b "%WIRESHARK_BUILD_DIR%\packaging\nsis\*.exe" 2>nul
'@ | Set-Content -LiteralPath (Join-Path $d05 'build-all-from-bundle.bat') -Encoding ASCII

# --- root setup / build shortcuts ---
@'
@echo off
echo ============================================
echo  Wireshark Industrial Portable SDK Setup
echo  Product: 宾尧
echo ============================================
echo.
echo Step 1: Install VS 2022 Build Tools (first time only, ~10-30 min)
echo         Run as Administrator if UAC prompts.
echo.
pause
call "%~dp004-compile-env\install-vs-buildtools.bat"
if errorlevel 1 exit /b 1
echo.
echo Step 2: Build installer
echo.
pause
call "%~dp005-scripts\build-all-from-bundle.bat"
'@ | Set-Content -LiteralPath (Join-Path $BundleRoot 'SETUP.bat') -Encoding ASCII

@'
@echo off
call "%~dp005-scripts\build-all-from-bundle.bat"
'@ | Set-Content -LiteralPath (Join-Path $BundleRoot 'BUILD.bat') -Encoding ASCII

# --- README ---
$readme = @"
Wireshark Industrial Portable SDK ($ProductName $Version)
========================================================

本目录为完整可移植开发/运行环境，可拷贝到另一台 Windows x64 机器上使用。
目标机器仅需：Windows 10/11 x64、管理员权限（首次安装 VS 时）、网络（仅 VS 引导安装器需要）。

目录说明
--------
01-installer\     安装包 + Npcap/USBPcap + install-all.bat（静默安装产品）
02-runtime\       免安装运行目录（run-wireshark.bat）
03-source\        完整源码（宾尧工业协议增强版）
04-compile-env\   编译依赖：Qt、第三方库、NSIS、便携 Git/Python/CMake、VS 引导安装器
05-scripts\       构建脚本（use-bundle-env.bat + build-all-from-bundle.bat）
06-build\         本地编译输出（脚本自动创建）

新机器快速上手
--------------
1. 将整个目录拷贝到目标机（建议路径不含中文空格，如 D:\Binyao-SDK）
2. 双击根目录 SETUP.bat（或手动执行下面两步）：
   a. 以管理员运行 04-compile-env\install-vs-buildtools.bat（仅首次，约 10-30 分钟）
   b. cmd 中：cd /d <本目录>\05-scripts && build-all-from-bundle.bat
3. 安装包输出：<本目录>\06-build\wsbuild-industrial\packaging\nsis\*.exe
4. 或直接运行：02-runtime\run-wireshark.bat

仅重新编译（已安装 VS）
-----------------------
双击根目录 BUILD.bat
或：05-scripts\build-all-from-bundle.bat

仅安装到系统
------------
01-installer\install-all.bat

体积说明
--------
- 主要占用：Qt (~2.4 GB) + 第三方库 (~0.6 GB) + Git/Python/CMake (~1.5 GB)
- VS Build Tools 不在包内完整拷贝（无法搬迁），以官方引导安装器提供
- 打包脚本：03-source\wireshark\tools\minimal-build\make-bundle.ps1

环境变量（打包时可覆盖）
------------------------
WIRESHARK_BUNDLE_DIR   输出目录
WIRESHARK_SRC_DIR      源码路径
WIRESHARK_BUILD_DIR    构建目录（读取已有安装包）
BUNDLE_GIT_SRC         Git 安装路径
BUNDLE_PYTHON_SRC      Python 安装路径
BUNDLE_CMAKE_SRC       CMake 安装路径
"@
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText((Join-Path $BundleRoot 'README.txt'), $readme, $utf8Bom)

Write-Host ''
Write-Host '=== Bundle size by folder ==='
Get-ChildItem -LiteralPath $BundleRoot -Directory | ForEach-Object {
    $sum = (Get-ChildItem $_.FullName -Recurse -File -EA SilentlyContinue | Measure-Object Length -Sum).Sum
    '{0,8:N2} GB  {1}' -f ($sum / 1GB), $_.Name
}
$total = (Get-ChildItem $BundleRoot -Recurse -File -EA SilentlyContinue | Measure-Object Length -Sum).Sum
Write-Host ('TOTAL  {0:N2} GB' -f ($total / 1GB))
Write-Host "BUNDLE_DIR=$BundleRoot"
