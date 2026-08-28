@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify-remediator.ps1"
exit /b %ERRORLEVEL%
