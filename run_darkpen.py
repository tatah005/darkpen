#!/usr/bin/env python3
"""
Simple DarkPen Runner - Forces CLI mode and demonstrates functionality
"""

import sys
import os
import subprocess

def main():
    print("🚀 DarkPen - AI-Powered Penetration Testing Platform")
    print("=" * 60)
    print("Starting CLI version...")
    print()
    
    # Run the CLI version
    try:
        subprocess.run([sys.executable, 'darkpen_cli.py'])
    except KeyboardInterrupt:
        print("\n👋 DarkPen closed")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main() 