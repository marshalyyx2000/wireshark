@echo off
REM ============================================================================
REM 宾尧 Wireshark Industrial — configure + build + NSIS (ENABLE_MINIMAL_BUILD)
REM Uses shared env/configure/build/package scripts. Override paths via env vars.
REM ============================================================================
setlocal EnableExtensions
call "%~dp0env.bat" || exit /b 1
call "%~dp0build-all.bat"
exit /b %ERRORLEVEL%
