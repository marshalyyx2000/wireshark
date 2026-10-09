# Assemble a self-contained Wireshark Industrial (宾尧) portable SDK.
# Includes: installer + runtime + source (with portable .git) + compile deps +
# portable Git/Python/CMake + scripts.
# VS Build Tools is NOT copied (not relocatable); official bootstrapper is bundled instead.
#
# Usage:
#   powershell -File tools\minimal-build\make-bundle.ps1
#   $env:WIRESHARK_BUNDLE_DIR = 'D:\Binyao-SDK'; .\make-bundle.ps1
#   .\make-bundle.ps1 -SkipInstaller   # skip 01-installer if not built yet
#   .\make-bundle.ps1 -ShallowGit      # smaller .git (depth 100); default is full history

param(
    [switch]$SkipInstaller,
    # Smaller portable .git (depth 100). Default is full history for commit/push on new PCs.
    [switch]$ShallowGit
)

$ErrorActionPreference = 'Stop'
$FullGit = -not $ShallowGit

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

function Get-SourceRemotes {
    param([string]$SrcRoot, [string]$GitExe)
    $map = [ordered]@{}
    Push-Location -LiteralPath $SrcRoot
    try {
        $names = & $GitExe remote
        foreach ($name in $names) {
            $name = $name.Trim()
            if (-not $name) { continue }
            $url = & $GitExe remote get-url $name 2>$null
            if ($url) { $map[$name] = $url.Trim() }
        }
    } finally {
        Pop-Location
    }
    return $map
}

function Sync-GitRemotes {
    param(
        [string]$DestRoot,
        [string]$GitExe,
        [System.Collections.IDictionary]$Remotes
    )
    if (-not $Remotes -or $Remotes.Count -eq 0) {
        Write-Warning "No remotes to sync into $DestRoot"
        return
    }
    Push-Location -LiteralPath $DestRoot
    try {
        $existing = @(& $GitExe remote 2>$null)
        foreach ($name in @($existing)) {
            $name = "$name".Trim()
            if ($name) { & $GitExe remote remove $name 2>$null | Out-Null }
        }
        foreach ($name in $Remotes.Keys) {
            $url = $Remotes[$name]
            & $GitExe remote add $name $url
            if ($LASTEXITCODE -ne 0) { throw "git remote add $name failed" }
            Write-Host "OK  remote $name -> $url"
        }
    } finally {
        Pop-Location
    }
}

function Embed-PortableGit {
    param(
        [string]$SrcRoot,
        [string]$DestRoot,
        [switch]$FullHistory,
        [System.Collections.IDictionary]$Remotes
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
        & $git --git-dir=$destGit config --bool core.bare false
        # Do NOT set core.worktree to an absolute path — breaks after copy to another PC.
        & $git --git-dir=$destGit config --unset-all core.worktree 2>$null | Out-Null
        if ($branch) {
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
            & $git -C $tmp fetch --tags --depth 100 2>$null | Out-Null
            Move-Item -LiteralPath (Join-Path $tmp '.git') -Destination $destGit -Force
            & $git --git-dir=$destGit config --bool core.bare false
            & $git --git-dir=$destGit config --unset-all core.worktree 2>$null | Out-Null
        } finally {
            if (Test-Path -LiteralPath $tmp) {
                Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Relocate-safe: drop machine-specific absolute paths from copied config
    & $git --git-dir=$destGit config --unset-all core.worktree 2>$null | Out-Null
    & $git --git-dir=$destGit config --unset extensions.worktreeConfig 2>$null | Out-Null

    Sync-GitRemotes -DestRoot $DestRoot -GitExe $git -Remotes $Remotes

    Push-Location -LiteralPath $DestRoot
    try {
        if ($branch) {
            # git writes "Reset branch ..." to stderr; do not treat as terminating error.
            $prevEap = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            & $git -c advice.detachedHead=false checkout -B $branch HEAD *>$null
            if ($LASTEXITCODE -ne 0) {
                & $git symbolic-ref HEAD "refs/heads/$branch" *>$null
            }
            $ErrorActionPreference = $prevEap
        }
        # Shared worktree common-dir copies bring another worktree's index.
        # Mixed reset rebuilds the index from HEAD against this working tree.
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        & $git reset HEAD *>$null
        $ErrorActionPreference = $prevEap

        $check = & $git rev-parse HEAD
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $desc = & $git describe --abbrev=12 --long --always --match 'v[1-9]*' 2>$null
        $status = & $git status --porcelain
        $curBranch = & $git branch --show-current
        $ErrorActionPreference = $prevEap
        Write-Host "OK  portable .git HEAD=$check describe=$desc branch=$curBranch"
        if ($status) {
            $n = @($status).Count
            Write-Host "OK  working tree has $n uncommitted change(s) (copied with sources)"
        } else {
            Write-Host "OK  git status clean"
        }
        # Fail if still a worktree gitfile
        if (-not (Test-Path -LiteralPath (Join-Path $DestRoot '.git\HEAD'))) {
            throw "Embedded .git is not a directory repo under $DestRoot"
        }
    } finally {
        Pop-Location
    }
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
if (-not $Version) { $Version = '0.10.5' }
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

$gitForRemotes = Find-GitExe
$SourceRemotes = @{}
if ($gitForRemotes) {
    $SourceRemotes = Get-SourceRemotes -SrcRoot $Src -GitExe $gitForRemotes
}

Write-Host "=== Wireshark Industrial Portable SDK ==="
Write-Host "Product : $ProductName"
Write-Host "Version : $Version"
Write-Host "Source  : $Src"
Write-Host "Bundle  : $BundleRoot"
Write-Host "FullGit : $FullGit"
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
$runRel = Join-Path $BuildDir 'run\RelWithDebInfo'
$installedExe = Join-Path $Installed 'Wireshark.exe'
$runExe = Join-Path $runRel 'Wireshark.exe'
# Prefer build output when Program Files install is missing/stub (common on build PCs).
if ((Test-Path -LiteralPath $runExe)) {
    Robo-Copy $runRel $d02 @('/XF', '*.pdb') | Out-Null
} elseif ((Test-Path -LiteralPath $installedExe)) {
    Robo-Copy $Installed $d02 @('/XF', '*.pdb') | Out-Null
} else {
    Write-Warning "No runtime found at $runRel or $Installed — 02-runtime will be empty"
    New-Item -ItemType Directory -Force -Path $d02 | Out-Null
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

Embed-PortableGit -SrcRoot $Src -DestRoot $d03 -FullHistory:$FullGit -Remotes $SourceRemotes

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

REM Prefer portable tools on PATH
if exist "%BUNDLE_GIT_DIR%\cmd\git.exe" set "PATH=%BUNDLE_GIT_DIR%\cmd;%BUNDLE_GIT_DIR%\bin;%PATH%"
if exist "%BUNDLE_PYTHON_DIR%\python.exe" set "PATH=%BUNDLE_PYTHON_DIR%;%BUNDLE_PYTHON_DIR%\Scripts;%PATH%"
if exist "%BUNDLE_CMAKE_DIR%\bin\cmake.exe" set "PATH=%BUNDLE_CMAKE_DIR%\bin;%PATH%"

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

@'
@echo off
REM Open a cmd shell in 03-source\wireshark with bundle PATH (Git/Python/CMake).
setlocal EnableExtensions
call "%~dp0use-bundle-env.bat" || exit /b 1
if not exist "%WIRESHARK_SRC_DIR%\.git\HEAD" (
  echo ERROR: portable .git missing under "%WIRESHARK_SRC_DIR%"
  echo Re-run create-bundle.bat on the build machine.
  pause
  exit /b 1
)
cd /d "%WIRESHARK_SRC_DIR%"
echo.
echo === Development shell ===
echo SRC=%CD%
git status -sb
echo.
echo Remotes:
git remote -v
echo.
echo Tips:
echo   git add ... ^&^& git commit -m "msg"
echo   git push -u github HEAD
echo   Or run: ..\..\05-scripts\setup-github.bat
echo.
cmd /k
'@ | Set-Content -LiteralPath (Join-Path $d05 'DEV.bat') -Encoding ASCII

@'
@echo off
REM Check remotes and print GitHub auth / push instructions. Does NOT store credentials.
setlocal EnableExtensions
call "%~dp0use-bundle-env.bat" || exit /b 1
cd /d "%WIRESHARK_SRC_DIR%" || exit /b 1

echo === GitHub setup for portable SDK ===
echo SRC=%CD%
echo.

if not exist ".git\HEAD" (
  echo ERROR: no .git directory. Bundle was built without Embed-PortableGit.
  exit /b 1
)

echo --- remotes ---
git remote -v
echo.

git rev-parse --abbrev-ref HEAD >nul 2>&1
if errorlevel 1 (
  echo WARNING: detached HEAD or broken git. Try: git checkout industrial-4.7.6-upstream
) else (
  for /f "delims=" %%B in ('git rev-parse --abbrev-ref HEAD') do echo Branch: %%B
)
echo.

git config --get user.name >nul 2>&1
if errorlevel 1 (
  echo Git user.name is not set. Example:
  echo   git config --global user.name "Your Name"
) else (
  for /f "delims=" %%N in ('git config --get user.name') do echo user.name=%%N
)
git config --get user.email >nul 2>&1
if errorlevel 1 (
  echo Git user.email is not set. Example:
  echo   git config --global user.email "you@example.com"
) else (
  for /f "delims=" %%E in ('git config --get user.email') do echo user.email=%%E
)
echo.

echo --- authenticate on THIS machine (credentials are NOT in the bundle) ---
echo Option A - GitHub CLI:
echo   gh auth login
echo Option B - HTTPS + Personal Access Token:
echo   When git push asks for password, paste a PAT ^(not account password^)
echo Option C - SSH:
echo   git remote set-url github git@github.com:USER/wireshark.git
echo.

echo --- push current branch ---
echo   git push -u github HEAD
echo.
echo Prefer remote name "github" ^(https://github.com/marshalyyx2000/wireshark.git^).
echo "origin" usually points at upstream wireshark/wireshark — do not push industrial work there
echo unless you intend to.
echo.
pause
'@ | Set-Content -LiteralPath (Join-Path $d05 'setup-github.bat') -Encoding ASCII

# --- root setup / build / dev shortcuts ---
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

@'
@echo off
call "%~dp005-scripts\DEV.bat"
'@ | Set-Content -LiteralPath (Join-Path $BundleRoot 'DEV.bat') -Encoding ASCII

@'
@echo off
call "%~dp005-scripts\setup-github.bat"
'@ | Set-Content -LiteralPath (Join-Path $BundleRoot 'setup-github.bat') -Encoding ASCII

# --- README ---
$gitMode = if ($FullGit) { 'full history (default)' } else { 'shallow depth=100 (-ShallowGit)' }
$readme = @"
Wireshark Industrial Portable SDK ($ProductName $Version)
========================================================

本目录为完整可移植开发/运行/编译环境，可拷贝到另一台「什么都没有」的 Windows x64 机器上：
安装 VS Build Tools → 编译并生成 NSIS 安装包 → 在 03-source 内开发并 git push 到 GitHub。

目标机器需要：Windows 10/11 x64、管理员权限（首次装 VS）、网络（VS 引导安装器下载组件）。
GitHub 登录凭据不会打进本包，迁机后需在新机器上自行登录。

目录说明
--------
01-installer\     安装包 + Npcap/USBPcap + install-all.bat
02-runtime\       免安装运行目录（run-wireshark.bat）
03-source\        完整源码 + 可搬迁的 .git（含 remote，Git 模式: $gitMode）
04-compile-env\   Qt、第三方库、NSIS、便携 Git/Python/CMake、vs_BuildTools.exe
05-scripts\       use-bundle-env / build-all-from-bundle / DEV / setup-github
06-build\         本地编译输出（首次构建时创建）

新机器：编译打包
----------------
1. 将整个目录拷贝到目标机（建议 ASCII 路径，如 D:\Binyao-SDK）
2. 双击 SETUP.bat
   a. 管理员运行 04-compile-env\install-vs-buildtools.bat（仅首次，约 10–30 分钟，需联网）
   b. 执行 05-scripts\build-all-from-bundle.bat
3. 安装包：06-build\wsbuild-industrial\packaging\nsis\*.exe
4. 或直接运行：02-runtime\run-wireshark.bat / 01-installer\install-all.bat

仅重新编译（已装 VS）
--------------------
双击 BUILD.bat

新机器：开发并提交到 GitHub
--------------------------
1. 双击 DEV.bat（打开源码目录 cmd，PATH 含便携 Git）
2. 双击 setup-github.bat，按提示配置 user.name / user.email，并完成本机登录：
     gh auth login
   或使用 HTTPS PAT / SSH
3. 修改代码后：
     git add ...
     git commit -m "..."
     git push -u github HEAD
4. 默认 remote「github」指向工业仓库；「origin」多为上游 wireshark/wireshark，勿误推。

体积说明
--------
- Qt ~2.4 GB + third-party ~0.6 GB + Git/Python/CMake ~0.5–1.5 GB + 源码/.git
- FullGit 会显著增大（取决于本机仓库历史）
- VS Build Tools 不以完整目录搬迁，仅提供官方引导安装器

打包命令（在开发机上）
--------------------
  tools\minimal-build\create-bundle.bat
  tools\minimal-build\create-bundle.bat -ShallowGit
  tools\minimal-build\create-bundle.bat -SkipInstaller

环境变量
--------
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
