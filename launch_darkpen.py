#!/usr/bin/env python3
"""
DarkPen - AI-Powered Penetration Testing Platform
Launcher script for easy startup
"""

import sys
import os

def main():
    # Add the current directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    try:
        from PyQt5.QtWidgets import QApplication
        from gui.darkpen_main import DarkPenMain
        
        print("🚀 Starting DarkPen - AI-Powered Penetration Testing Platform...")
        
        app = QApplication(sys.argv)
        app.setApplicationName("DarkPen")
        app.setApplicationVersion("1.0.0")
        
        window = DarkPenMain()
        window.show()
        
        print("✅ DarkPen is now running!")
        print("🔍 Use the tabs to access different scanning tools")
        
        sys.exit(app.exec_())
        
    except ImportError as e:
        print(f"❌ Error: Missing dependency - {e}")
        print("💡 Try running: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting DarkPen: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 