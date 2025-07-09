#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color
CYAN='\033[0;36m'

echo -e "${BLUE}💀 DarkPen - Installation Script${NC}"
echo -e "${CYAN}=============================${NC}\n"

# Check Python version
echo -e "${BLUE}Checking Python version...${NC}"
if command -v python3 >/dev/null 2>&1; then
    python3 --version
else
    echo -e "${RED}Python 3 is not installed. Please install Python 3.8 or higher.${NC}"
    exit 1
fi

# Check if pip is installed
echo -e "\n${BLUE}Checking pip installation...${NC}"
if command -v pip3 >/dev/null 2>&1; then
    echo -e "${GREEN}pip3 is installed${NC}"
else
    echo -e "${RED}pip3 is not installed. Installing pip3...${NC}"
    sudo apt-get update
    sudo apt-get install -y python3-pip
fi

# Install system dependencies
echo -e "\n${BLUE}Installing system dependencies...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    # Debian/Ubuntu
    sudo apt-get update
    sudo apt-get install -y python3-pyqt5 nmap nikto sqlmap
elif command -v dnf >/dev/null 2>&1; then
    # Red Hat/Fedora
    sudo dnf install -y python3-qt5 nmap nikto sqlmap
else
    echo -e "${RED}Unsupported package manager. Please install the required dependencies manually:${NC}"
    echo "- PyQt5"
    echo "- nmap"
    echo "- nikto"
    echo "- sqlmap"
fi

# Create virtual environment
echo -e "\n${BLUE}Setting up virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo -e "\n${BLUE}Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo -e "\n${BLUE}Creating necessary directories...${NC}"
mkdir -p scans
mkdir -p logs
mkdir -p data

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo -e "\n${BLUE}Creating .env file...${NC}"
    cp .env.example .env
    echo -e "${GREEN}Created .env file. Please edit it with your settings.${NC}"
fi

# Set execute permissions
echo -e "\n${BLUE}Setting execute permissions...${NC}"
chmod +x main.py
chmod +x darkpen.sh
chmod +x launch_darkpen.py
chmod +x run.py
chmod +x start_gui.sh

# Install desktop entry if possible
if [ -d ~/.local/share/applications ]; then
    echo -e "\n${BLUE}Installing desktop entry...${NC}"
    # Update the desktop entry with the correct path
    sed -i "s|/home/mike/AI-Pentest-Platform|$(pwd)|g" darkpen.desktop
    cp darkpen.desktop ~/.local/share/applications/
    echo -e "${GREEN}Desktop entry installed! You can now launch DarkPen from your applications menu.${NC}"
fi

echo -e "\n${GREEN}Installation complete! 🎉${NC}"
echo -e "\nTo start DarkPen, use one of these methods:"
echo -e "1. ${CYAN}./darkpen.sh${NC} (Recommended - Shell launcher)"
echo -e "2. ${CYAN}python3 launch_darkpen.py${NC} (Python launcher)"
echo -e "3. ${CYAN}python3 run.py${NC} (Direct execution)"
echo -e "4. ${CYAN}./start_gui.sh${NC} (With virtual environment)"
echo -e "\n${RED}Note: Make sure to edit the .env file with your settings before running the application.${NC}"
