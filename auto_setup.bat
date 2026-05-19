@echo off
echo =========================================================
echo    AI-NIDS Vanguard - Auto Environment Setup
echo =========================================================
echo.
echo Step 1: Checking Python installation...

python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python is NOT installed or not in PATH!
    echo Automatically installing Python 3.11 using Windows Winget...
    echo (Please wait a few minutes and type 'Y' if prompted)
    echo.
    winget install -e --id Python.Python.3.11 --accept-package-agreements --accept-source-agreements
    
    echo.
    echo ---------------------------------------------------------
    echo Python installation finished!
    echo IMPORTANT: Windows needs to refresh its environment.
    echo Please CLOSE this black window, and double-click 
    echo auto_setup.bat again to continue!
    echo ---------------------------------------------------------
    pause
    exit
) else (
    echo Python is installed!
    python --version
)

echo.
echo Step 2: Installing project dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

echo.
echo =========================================================
echo Awesome! Setup is fully complete!
echo You can now close this window and double-click start.bat
echo =========================================================
pause
