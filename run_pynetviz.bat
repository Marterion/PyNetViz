@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo Failed to create virtual environment. Install Python 3.11+ and try again.
        pause
        exit /b 1
    )
)

if not exist ".venv\Scripts\flet.exe" (
    echo Installing dependencies...
    ".venv\Scripts\pip.exe" install -r requirements.txt
    if errorlevel 1 (
        echo Failed to install dependencies.
        pause
        exit /b 1
    )
)

echo Starting PyNetViz...
".venv\Scripts\python.exe" main.py

if errorlevel 1 (
    echo PyNetViz exited with an error.
    pause
    exit /b 1
)

endlocal