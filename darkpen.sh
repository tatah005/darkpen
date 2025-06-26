#!/bin/bash

# DarkPen - AI-Powered Penetration Testing Platform
# Launcher script for easy startup

echo "🚀 Starting DarkPen - AI-Powered Penetration Testing Platform..."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is not installed"
    exit 1
fi

# Check if we're in a virtual environment
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "📦 Using virtual environment: $VIRTUAL_ENV"
else
    echo "💡 Tip: Consider using a virtual environment for better dependency management"
fi

# Run the application
python3 launch_darkpen.py

# Check exit status
if [ $? -eq 0 ]; then
    echo "✅ DarkPen closed successfully"
else
    echo "❌ DarkPen encountered an error"
    exit 1
fi 