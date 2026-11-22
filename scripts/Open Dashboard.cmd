@echo off
cd /d "%~dp0"
if not exist "ai-redteam.exe" (
    echo ai-redteam.exe was not found in this folder.
    pause
    exit /b 1
)
"%~dp0ai-redteam.exe" --dashboard
if errorlevel 1 pause
