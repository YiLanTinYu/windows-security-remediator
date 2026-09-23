@echo off
setlocal

fltmc >nul 2>&1
if errorlevel 1 (
    set "FTP_RECEIVER_LAUNCHER=%~f0"
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath $env:FTP_RECEIVER_LAUNCHER -Verb RunAs"
    if errorlevel 1 pause
    exit /b
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-FTP-Receiver.ps1"
if errorlevel 1 pause
