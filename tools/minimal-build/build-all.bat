@echo off
setlocal EnableExtensions
REM Configure + build + NSIS package for ENABLE_MINIMAL_BUILD.
call "%~dp0configure.bat"
if errorlevel 1 exit /b 1
call "%~dp0build.bat"
if errorlevel 1 exit /b 1
call "%~dp0package-nsis.bat"
if errorlevel 1 exit /b 1
echo === DONE ===
exit /b 0
