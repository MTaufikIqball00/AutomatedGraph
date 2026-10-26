@echo off
chcp 65001 >nul
title Automated GraphRAG - Enterprise Launcher
cd /d "%~dp0"

echo ====================================================================
echo   AUTOMATED GRAPHRAG - WINDOWS LAUNCHER
echo ====================================================================

if not exist ".env" (
    if exist ".env.example" (
        copy /Y ".env.example" ".env" >nul
        echo [INFO] File .env dibuat otomatis dari .env.example
    )
)

python launch.py %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Aplikasi berhenti dengan kode error %ERRORLEVEL%.
    pause
)
