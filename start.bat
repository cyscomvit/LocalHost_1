@echo off
echo ========================================
echo   CTOP University - Development Startup
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

REM Check if Node.js is installed
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed or not in PATH
    echo Please install Node.js and try again
    pause
    exit /b 1
)

REM Setup Backend
echo [SETUP] Configuring backend...
cd backend

REM Create virtual environment if it doesn't exist
if not exist "venv\" (
    echo [SETUP] Creating virtual environment in backend...
    python -m venv venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        cd ..
        pause
        exit /b 1
    )
    echo [SUCCESS] Virtual environment created
) else (
    echo [INFO] Virtual environment already exists
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment
    cd ..
    pause
    exit /b 1
)

REM Install/update backend dependencies
echo [SETUP] Installing backend dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install backend dependencies
    cd ..
    pause
    exit /b 1
)
echo [SUCCESS] Backend dependencies installed
cd ..

REM Install/update frontend dependencies
echo.
echo [SETUP] Installing frontend dependencies...
cd frontend
call npm install
if errorlevel 1 (
    echo [ERROR] Failed to install frontend dependencies
    cd ..
    pause
    exit /b 1
)
cd ..
echo [SUCCESS] Frontend dependencies installed

REM Start backend server in new window
echo.
echo [STARTING] Launching backend server on port 5000...
start "CTOP Backend Server" cmd /k "cd /d %CD%\backend && venv\Scripts\activate.bat && python app.py"

REM Wait a moment for backend to initialize
timeout /t 3 /nobreak >nul

REM Start frontend server in new window
echo [STARTING] Launching frontend server on port 3000...
start "CTOP Frontend Server" cmd /k "cd /d %CD%\frontend && npm start"

echo.
echo ========================================
echo   Servers Started Successfully!
echo ========================================
echo.
echo Backend:  http://localhost:5000
echo Frontend: http://localhost:3000
echo.
echo Press any key to stop all servers...
pause >nul

REM Kill the servers when user presses a key
echo.
echo [STOPPING] Shutting down servers...
taskkill /FI "WindowTitle eq CTOP Backend Server*" /T /F >nul 2>&1
taskkill /FI "WindowTitle eq CTOP Frontend Server*" /T /F >nul 2>&1
echo [SUCCESS] Servers stopped
pause
