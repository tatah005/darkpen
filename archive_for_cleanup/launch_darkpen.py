#!/usr/bin/env python3
"""
DarkPen - AI-Powered Penetration Testing Platform
Launcher script for easy startup
"""

import sys
import os
import subprocess

def check_display_available():
    """Check if a display is available for GUI"""
    # Check if DISPLAY is set
    display = os.environ.get('DISPLAY')
    if not display:
        return False
    
    # Check if we can connect to X server
    try:
        result = subprocess.run(['xset', 'q'], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False

def check_metasploit():
    """Check if Metasploit is available"""
    try:
        result = subprocess.run(['msfconsole', '--version'], 
                              capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except:
        return False

def main():
    # Add the current directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    
    print("🚀 Starting DarkPen - AI-Powered Penetration Testing Platform...")
    
    # --- BYPASSING METASPLOIT CHECK FOR GUI LAUNCH ---
    # if not check_metasploit():
    #     print("❌ Metasploit Framework not found")
    #     print("   Please install Metasploit Framework to use DarkPen")
    #     return
    print("✅ [Bypass] Skipping Metasploit check for GUI launch")
    
    # Check if display is available
    if not check_display_available():
        print("❌ No display available - launching CLI version")
        print("   Starting DarkPen CLI...")
        try:
            subprocess.run([sys.executable, 'darkpen_cli.py'])
        except KeyboardInterrupt:
            print("\n👋 CLI closed")
        except Exception as e:
            print(f"❌ CLI error: {e}")
        return
    
    print("✅ Display available - attempting GUI launch")
    
    try:
        from PyQt5.QtWidgets import QApplication
        from gui.darkpen_main import DarkPenMain
        
        app = QApplication(sys.argv)
        app.setApplicationName("DarkPen")
        app.setApplicationVersion("1.0.0")
        
        window = DarkPenMain()
        window.show()
        
        print("✅ DarkPen GUI is now running!")
        print("🔍 Use the tabs to access different scanning tools")
        
        sys.exit(app.exec_())
        
    except ImportError as e:
        print(f"❌ Error: Missing dependency - {e}")
        print("💡 Try running: pip install -r requirements.txt")
        print("🔄 Falling back to CLI version...")
        try:
            subprocess.run([sys.executable, 'darkpen_cli.py'])
        except Exception as cli_error:
            print(f"❌ CLI also failed: {cli_error}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error starting DarkPen GUI: {e}")
        print("🔄 Falling back to CLI version...")
        try:
            subprocess.run([sys.executable, 'darkpen_cli.py'])
        except Exception as cli_error:
            print(f"❌ CLI also failed: {cli_error}")
        sys.exit(1)

if __name__ == "__main__":
    main() 