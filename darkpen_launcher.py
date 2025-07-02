#!/usr/bin/env python3
"""
DarkPen Launcher - Automatically chooses between GUI and CLI based on environment
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
    """Main launcher function"""
    print("🚀 DarkPen Launcher")
    print("=" * 50)
    
    # Check Metasploit
    if check_metasploit():
        print("✅ Metasploit Framework detected")
    else:
        print("❌ Metasploit Framework not found")
        print("   Please install Metasploit Framework to use DarkPen")
        return
    
    # Check display
    if check_display_available():
        print("✅ Display available - launching GUI version")
        print("   Starting DarkPen GUI...")
        
        # Launch GUI version
        try:
            subprocess.run([sys.executable, 'launch_darkpen.py'])
        except KeyboardInterrupt:
            print("\n👋 GUI closed")
        except Exception as e:
            print(f"❌ GUI error: {e}")
            print("   Falling back to CLI version...")
            launch_cli()
    else:
        print("❌ No display available - launching CLI version")
        print("   Starting DarkPen CLI...")
        launch_cli()

def launch_cli():
    """Launch the CLI version"""
    try:
        subprocess.run([sys.executable, 'darkpen_cli.py'])
    except KeyboardInterrupt:
        print("\n👋 CLI closed")
    except Exception as e:
        print(f"❌ CLI error: {e}")

if __name__ == "__main__":
    main() 