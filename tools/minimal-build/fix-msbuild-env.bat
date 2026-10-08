@echo off
REM MSBuild's CL task treats the environment as case-insensitive. Duplicate proxy
REM variables (NO_PROXY vs no_proxy) cause MSB6001 / ArgumentException during compile.
set "no_proxy="
set "http_proxy="
set "https_proxy="
set "all_proxy="
set "ftp_proxy="
