#!/bin/bash

# DarkPen Quick Start Script
# This script helps you get DarkPen running quickly

echo "🎯 DarkPen Quick Start"
echo "======================"
echo ""

# Check if we're in the right directory
if [ ! -f "main.py" ]; then
    echo "❌ Error: Please run this script from the DarkPen directory"
    echo "   cd darkpen"
    echo "   ./quick_start.sh"
    exit 1
fi

echo "✅ DarkPen directory found"
echo ""

# Check Python version
python_version=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then
    echo "✅ Python $python_version found (>= $required_version required)"
else
    echo "❌ Python $python_version found, but $required_version or higher is required"
    echo "   Please upgrade Python and try again"
    exit 1
fi

echo ""

# Check if dependencies are installed
echo "🔍 Checking dependencies..."

# Check PyQt5
if python3 -c "import PyQt5" 2>/dev/null; then
    echo "✅ PyQt5 is installed"
else
    echo "⚠️  PyQt5 not found. Installing..."
    pip3 install PyQt5
fi

# Check other Python dependencies
if [ -f "requirements.txt" ]; then
    echo "📦 Installing Python dependencies..."
    pip3 install -r requirements.txt
fi

echo ""

# Check system tools
echo "🔧 Checking system tools..."

# Check Nmap
if command -v nmap &> /dev/null; then
    echo "✅ Nmap is installed"
else
    echo "⚠️  Nmap not found. Please install it:"
    echo "   sudo apt install nmap"
fi

# Check Nikto
if command -v nikto &> /dev/null; then
    echo "✅ Nikto is installed"
else
    echo "⚠️  Nikto not found. Please install it:"
    echo "   sudo apt install nikto"
fi

# Check Metasploit
if command -v msfconsole &> /dev/null; then
    echo "✅ Metasploit Framework is installed"
else
    echo "⚠️  Metasploit Framework not found. Please install it:"
    echo "   sudo apt install metasploit-framework"
fi

echo ""

# Make scripts executable
echo "🔧 Making scripts executable..."
chmod +x *.sh 2>/dev/null
chmod +x *.py 2>/dev/null

echo ""

# Check if database exists
if [ ! -f "data/darkpen.db" ]; then
    echo "🗄️  Initializing database..."
    mkdir -p data
    python3 -c "from core.database_manager import DatabaseManager; DatabaseManager().initialize_database()" 2>/dev/null || echo "⚠️  Database initialization may need to be done manually"
fi

echo ""

# Success message
echo "🎉 DarkPen is ready to use!"
echo ""
echo "🚀 To start DarkPen, run one of these commands:"
echo "   ./darkpen.sh          (Recommended)"
echo "   python3 main.py       (Direct execution)"
echo "   python3 demo_mode.py  (Demo mode for presentations)"
echo ""
echo "📚 For more information:"
echo "   - README.md           (Complete documentation)"
echo "   - WINDOWS_SETUP.md    (Windows installation)"
echo "   - CONTRIBUTING.md     (How to contribute)"
echo ""
echo "🌐 Repository: https://github.com/tatah005/darkpen"
echo "📞 Issues: https://github.com/tatah005/darkpen/issues"
echo ""
echo "🛡️  Remember: Use DarkPen responsibly and only on authorized systems!" 