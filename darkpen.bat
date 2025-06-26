@echo off
echo ========================================
echo    DarkPen - AI-Powered Pentest Platform
echo ========================================
echo.

echo Checking if WSL is available...
wsl --status >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: WSL is not installed or not available.
    echo.
    echo Please install WSL first:
    echo 1. Open PowerShell as Administrator
    echo 2. Run: wsl --install
    echo 3. Restart your computer
    echo 4. Try running this script again
    echo.
    pause
    exit /b 1
)

echo WSL is available. Starting DarkPen...
echo.

echo If this is your first time running DarkPen, you may need to:
echo 1. Install dependencies: sudo apt install -y python3-pyqt5 nmap nikto
echo 2. Clone the repository: git clone https://github.com/tatah005/darkpen.git
echo 3. Navigate to the directory: cd darkpen
echo.

wsl bash -c "cd ~/darkpen && ./darkpen.sh"

echo.
echo DarkPen has been closed.
pause 