#!/bin/bash

echo "🌐 DarkPen Installation Script"
echo "-----------------------------"

# Check Python version
echo "Checking Python version..."
if command -v python3 &>/dev/null; then
    python3 --version
else
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check for required system tools
echo "Checking for required system tools..."
TOOLS=("nmap" "nikto" "sqlite3")
MISSING_TOOLS=()

for tool in "${TOOLS[@]}"; do
    if ! command -v $tool &>/dev/null; then
        MISSING_TOOLS+=($tool)
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo "❌ Missing required tools: ${MISSING_TOOLS[*]}"
    echo "Please install them using your package manager:"
    echo "Debian/Ubuntu: sudo apt install ${MISSING_TOOLS[*]}"
    echo "Arch Linux: sudo pacman -S ${MISSING_TOOLS[*]}"
    echo "RHEL/CentOS: sudo dnf install ${MISSING_TOOLS[*]}"
    exit 1
fi

# Create virtual environment
echo "Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p data/logs
mkdir -p data/reports

# Copy configuration files
echo "Setting up configuration..."
if [ ! -f config/settings.ini ]; then
    cp config/settings.example.ini config/settings.ini
    echo "Created settings.ini - please edit with your configuration"
fi

# Set up database
echo "Initializing database..."
python3 -c "from core.database_manager import DatabaseManager; DatabaseManager().init_db()"

echo "✅ Installation complete!"
echo "To start DarkPen, run:"
echo "source venv/bin/activate"
echo "python run.py" 