#!/usr/bin/env python3
"""
DarkPen GUI Runner - Tries multiple ways to launch the GUI
"""

import sys
import os
import subprocess
import time

def try_gui_launch():
    """Try different methods to launch the GUI"""
    print("🚀 DarkPen GUI Launcher")
    print("=" * 40)
    
    # Method 1: Try with virtual display
    print("1️⃣  Trying with virtual display...")
    try:
        result = subprocess.run(['xvfb-run', '-a', 'python3', 'darkpen_main.py'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ GUI launched successfully with virtual display!")
            return True
    except Exception as e:
        print(f"❌ Virtual display failed: {e}")
    
    # Method 2: Try with DISPLAY=:0
    print("2️⃣  Trying with DISPLAY=:0...")
    try:
        env = os.environ.copy()
        env['DISPLAY'] = ':0'
        result = subprocess.run(['python3', 'darkpen_main.py'], 
                              env=env, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ GUI launched successfully with DISPLAY=:0!")
            return True
    except Exception as e:
        print(f"❌ DISPLAY=:0 failed: {e}")
    
    # Method 3: Try with DISPLAY=:1
    print("3️⃣  Trying with DISPLAY=:1...")
    try:
        env = os.environ.copy()
        env['DISPLAY'] = ':1'
        result = subprocess.run(['python3', 'darkpen_main.py'], 
                              env=env, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ GUI launched successfully with DISPLAY=:1!")
            return True
    except Exception as e:
        print(f"❌ DISPLAY=:1 failed: {e}")
    
    print("❌ All GUI methods failed")
    print("💡 The GUI requires a proper display environment")
    print("   Try running in a desktop environment or use X11 forwarding")
    return False

if __name__ == "__main__":
    try_gui_launch() 