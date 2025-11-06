@echo off
REM PromptSniffer Windows Launcher
REM Run this as Administrator for best results

REM Change to the directory where this batch file is located
cd /d "%~dp0"

title PromptSniffer - LLM Prompt Monitor

echo.
echo ============================================================
echo                      PromptSniffer
echo              Network-Wide LLM Prompt Monitor
echo ============================================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running as Administrator
) else (
    echo [WARNING] Not running as Administrator
    echo For network-wide monitoring, right-click and "Run as Administrator"
    echo.
)

REM Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/
    pause
    exit /b 1
)

REM Check if config exists
if not exist config.json (
    echo [ERROR] config.json not found
    echo Run setup first: python setup.py
    pause
    exit /b 1
)

REM Check if setup was run
if not exist requirements.txt (
    echo [ERROR] requirements.txt not found
    echo Run setup first: python setup.py
    pause
    exit /b 1
)

echo.
echo Starting PromptSniffer...
echo Press Ctrl+C to stop
echo.

REM Run PromptSniffer
python run.py

pause
