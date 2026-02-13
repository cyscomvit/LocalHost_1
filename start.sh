#!/bin/bash

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================"
echo -e "  CTOP University - Development Startup"
echo -e "========================================${NC}"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python 3 is not installed${NC}"
    echo "Please install Python 3.8+ and try again"
    exit 1
fi

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}[ERROR] Node.js is not installed${NC}"
    echo "Please install Node.js and try again"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

# Setup Backend
echo -e "${YELLOW}[SETUP] Configuring backend...${NC}"
cd backend

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}[SETUP] Creating virtual environment in backend...${NC}"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}[ERROR] Failed to create virtual environment${NC}"
        cd ..
        exit 1
    fi
    echo -e "${GREEN}[SUCCESS] Virtual environment created${NC}"
else
    echo -e "${BLUE}[INFO] Virtual environment already exists${NC}"
fi

# Activate virtual environment
echo -e "${BLUE}[INFO] Activating virtual environment...${NC}"
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Failed to activate virtual environment${NC}"
    cd ..
    exit 1
fi

# Install/update backend dependencies
echo -e "${YELLOW}[SETUP] Installing backend dependencies...${NC}"
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Failed to install backend dependencies${NC}"
    cd ..
    exit 1
fi
echo -e "${GREEN}[SUCCESS] Backend dependencies installed${NC}"
cd ..

# Install/update frontend dependencies
echo
echo -e "${YELLOW}[SETUP] Installing frontend dependencies...${NC}"
cd frontend
npm install
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR] Failed to install frontend dependencies${NC}"
    exit 1
fi
cd ..
echo -e "${GREEN}[SUCCESS] Frontend dependencies installed${NC}"

# Create log directory
mkdir -p logs

# Function to cleanup on exit
cleanup() {
    echo
    echo -e "${YELLOW}[STOPPING] Shutting down servers...${NC}"
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null
    echo -e "${GREEN}[SUCCESS] Servers stopped${NC}"
    deactivate 2>/dev/null
    exit 0
}

# Set up trap to catch Ctrl+C
trap cleanup SIGINT SIGTERM

# Start backend server
echo
echo -e "${YELLOW}[STARTING] Launching backend server on port 5000...${NC}"
cd backend
source venv/bin/activate
python app.py > ../logs/backend.log 2>&1 &
BACKEND_PID=$!
cd ..

# Wait for backend to initialize
sleep 3

# Start frontend server
echo -e "${YELLOW}[STARTING] Launching frontend server on port 3000...${NC}"
cd frontend
npm start > ../logs/frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

# Wait a moment for servers to start
sleep 2

echo
echo -e "${GREEN}========================================"
echo -e "  Servers Started Successfully!"
echo -e "========================================${NC}"
echo
echo -e "Backend:  ${BLUE}http://localhost:5000${NC}"
echo -e "Frontend: ${BLUE}http://localhost:3000${NC}"
echo
echo -e "Logs:"
echo -e "  Backend:  logs/backend.log"
echo -e "  Frontend: logs/frontend.log"
echo
echo -e "${YELLOW}Press Ctrl+C to stop all servers${NC}"
echo

# Wait for user to press Ctrl+C
wait $BACKEND_PID $FRONTEND_PID
