#!/usr/bin/env python3
"""
DarkPen Demo - Shows the application functionality
"""

import sys
import os

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.metasploit_integration import MetasploitManager, ModuleType

def demo_darkpen():
    """Demonstrate DarkPen functionality"""
    print("🚀 DarkPen - AI-Powered Penetration Testing Platform")
    print("=" * 60)
    print()
    
    # Initialize Metasploit manager
    manager = MetasploitManager()
    
    # Check availability
    print("📊 System Status:")
    print(f"   Metasploit: {'🟢 Available' if manager.is_available() else '🔴 Not Found'}")
    if manager.is_available():
        version = manager.get_version()
        print(f"   Version: {version}")
    print()
    
    # Show common modules
    print("📚 Common Modules Available:")
    common_modules = [
        "exploit/windows/smb/ms17_010_eternalblue",
        "exploit/windows/smb/ms08_067_netapi", 
        "auxiliary/scanner/smb/smb_login",
        "exploit/unix/ftp/vsftpd_234_backdoor",
        "exploit/linux/samba/samba_symlink_traversal",
        "exploit/unix/misc/distcc_exec",
        "exploit/unix/webapp/wordpress_admin_shell_upload",
        "exploit/multi/http/joomla_comfields_sqli_rce",
        "exploit/unix/webapp/drupal_drupalgeddon2",
        "exploit/cisco/ios_shell"
    ]
    
    for i, module in enumerate(common_modules, 1):
        print(f"   {i:2d}. {module}")
    
    print()
    print("🔧 Available Commands:")
    print("   modules    - List available modules")
    print("   search     - Search for specific modules")
    print("   select     - Select a module")
    print("   target     - Set target information")
    print("   check      - Check if target is vulnerable")
    print("   exploit    - Run the exploit")
    print("   sessions   - List active sessions")
    print("   help       - Show help information")
    print("   quit       - Exit DarkPen CLI")
    print()
    print("✅ DarkPen is fully functional and ready to use!")
    print("   Run: python3 darkpen_cli.py to start the interactive CLI")
    print("   Run: python3 run_darkpen.py for a simple launcher")

if __name__ == "__main__":
    demo_darkpen() 