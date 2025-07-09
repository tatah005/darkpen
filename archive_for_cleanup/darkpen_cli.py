#!/usr/bin/env python3
"""
DarkPen CLI - Fast Command Line Interface for DarkPen
Runs without GUI display requirements
"""

import sys
import os
import json
import time
from datetime import datetime

# Add the project root to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.metasploit_integration import MetasploitManager, ModuleType

class DarkPenCLI:
    """Fast Command Line Interface for DarkPen"""
    
    def __init__(self):
        self.metasploit_manager = MetasploitManager()
        self.current_module = None
        self.current_target = None
        self.current_port = "80"
        
        # Pre-defined common modules for fast access
        self.common_modules = [
            "exploit/windows/smb/ms17_010_eternalblue",
            "exploit/windows/smb/ms08_067_netapi", 
            "auxiliary/scanner/smb/smb_login",
            "exploit/unix/ftp/vsftpd_234_backdoor",
            "exploit/linux/samba/samba_symlink_traversal",
            "exploit/unix/misc/distcc_exec",
            "exploit/unix/webapp/wordpress_admin_shell_upload",
            "exploit/multi/http/joomla_comfields_sqli_rce",
            "exploit/unix/webapp/drupal_drupalgeddon2",
            "exploit/cisco/ios_shell",
            "exploit/multi/http/struts2_content_type_ognl",
            "exploit/multi/http/struts2_dev_mode",
            "exploit/multi/http/tomcat_mgr_upload",
            "exploit/multi/http/tomcat_jsp_upload_bypass",
            "exploit/multi/http/php_cgi_arg_injection"
        ]
        
    def print_banner(self):
        """Print the DarkPen banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    🚀 DarkPen CLI 🚀                        ║
║              AI-Powered Penetration Testing Platform         ║
║                    Command Line Interface                    ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def print_status(self):
        """Print current status"""
        print(f"\n📊 Current Status:")
        print(f"   Metasploit: {'🟢 Available' if self.metasploit_manager.is_available() else '🔴 Not Found'}")
        if self.metasploit_manager.is_available():
            version = self.metasploit_manager.get_version()
            print(f"   Version: {version}")
        print(f"   Current Module: {self.current_module or 'None'}")
        print(f"   Current Target: {self.current_target or 'None'}")
        print(f"   Current Port: {self.current_port}")
        
    def list_modules(self):
        """List common modules (fast)"""
        print("\n📚 Common Modules (Fast Access):")
        print("─" * 80)
        
        # Group modules by category
        categories = {
            "Windows": [],
            "Linux/Unix": [],
            "Web Applications": [],
            "Network Devices": [],
            "Other": []
        }
        
        for module in self.common_modules:
            if 'windows' in module.lower():
                categories["Windows"].append(module)
            elif any(os in module.lower() for os in ['linux', 'unix']):
                categories["Linux/Unix"].append(module)
            elif any(web in module.lower() for web in ['web', 'http', 'php', 'asp', 'jsp', 'tomcat', 'struts']):
                categories["Web Applications"].append(module)
            elif any(net in module.lower() for net in ['cisco', 'router', 'switch', 'network']):
                categories["Network Devices"].append(module)
            else:
                categories["Other"].append(module)
        
        # Display modules by category
        for category, module_list in categories.items():
            if module_list:
                print(f"\n🔹 {category}:")
                for i, module in enumerate(module_list, 1):
                    print(f"   {i:2d}. {module}")
        
        print(f"\n💡 Tip: Use 'search <term>' to search for specific modules")
        print(f"💡 Tip: Use 'select <number>' or 'select <module_name>' to choose")
                    
    def select_module(self):
        """Select a module (fast)"""
        print("\n📋 Common Modules:")
        for i, module in enumerate(self.common_modules, 1):
            print(f"   {i:2d}. {module}")
            
        try:
            choice = input(f"\nSelect module (1-{len(self.common_modules)}) or enter module name: ").strip()
            
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(self.common_modules):
                    self.current_module = self.common_modules[idx]
                else:
                    print("❌ Invalid selection")
                    return
            else:
                # User entered module name directly
                if choice in self.common_modules:
                    self.current_module = choice
                else:
                    print(f"❌ Module '{choice}' not found in common modules")
                    print("   Use 'search <term>' to find other modules")
                    return
                    
            print(f"✅ Selected module: {self.current_module}")
            
        except (ValueError, KeyboardInterrupt):
            print("\n❌ Selection cancelled")
    
    def search_modules(self, query):
        """Search for specific modules"""
        if not query:
            print("❌ Please provide a search term")
            return
            
        print(f"\n🔍 Searching for modules containing '{query}'...")
        print("   This may take a moment...")
        
        try:
            modules = self.metasploit_manager.search_modules(query, ModuleType.EXPLOIT)
        except Exception as e:
            print(f"⚠️  Search timeout or error: {e}")
            print("   Using common modules...")
            modules = [m for m in self.common_modules if query.lower() in m.lower()]
        
        if not modules:
            print(f"❌ No modules found containing '{query}'")
            return
            
        print(f"\n📚 Found {len(modules)} matching modules:")
        for i, module in enumerate(modules[:20], 1):
            print(f"   {i:2d}. {module}")
        if len(modules) > 20:
            print(f"   ... and {len(modules) - 20} more")
            
    def set_target(self):
        """Set target information"""
        print("\n🎯 Target Configuration:")
        
        target = input("Enter target IP/hostname: ").strip()
        if target:
            self.current_target = target
            
        port = input(f"Enter port (default: {self.current_port}): ").strip()
        if port:
            self.current_port = port
            
        print(f"✅ Target set to: {self.current_target}:{self.current_port}")
        
    def check_module(self):
        """Check if target is vulnerable"""
        if not self.current_module:
            print("❌ No module selected. Use 'select' first.")
            return
            
        if not self.current_target:
            print("❌ No target set. Use 'target' first.")
            return
            
        print(f"\n🔍 Checking {self.current_module} against {self.current_target}:{self.current_port}...")
        
        result = self.metasploit_manager.check_module(self.current_module, self.current_target, self.current_port)
        
        if result['success']:
            print(f"✅ {result['message']}")
            if 'details' in result:
                print("\n📋 Details:")
                details = result['details']
                lines = details.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ['vulnerable', 'safe', 'check', 'target', 'port', 'error']):
                        print(f"   {line.strip()}")
        else:
            print(f"❌ {result['message']}")
            
    def run_exploit(self):
        """Run the exploit"""
        if not self.current_module:
            print("❌ No module selected. Use 'select' first.")
            return
            
        if not self.current_target:
            print("❌ No target set. Use 'target' first.")
            return
            
        print(f"\n🚀 Running {self.current_module} against {self.current_target}:{self.current_port}...")
        print("⚠️  This will attempt to exploit the target!")
        
        confirm = input("Are you sure you want to proceed? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("❌ Exploit cancelled")
            return
            
        # Get payload
        payload = input("Enter payload (default: windows/meterpreter/reverse_tcp): ").strip()
        if not payload:
            payload = "windows/meterpreter/reverse_tcp"
            
        result = self.metasploit_manager.run_exploit(
            self.current_module, 
            self.current_target, 
            self.current_port, 
            payload
        )
        
        if result['success']:
            print(f"✅ {result['message']}")
            if 'details' in result:
                print("\n📋 Details:")
                details = result['details']
                lines = details.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ['session', 'meterpreter', 'exploit', 'success', 'failed']):
                        print(f"   {line.strip()}")
        else:
            print(f"❌ {result['message']}")
            
    def list_sessions(self):
        """List active sessions"""
        print("\n🔗 Active Sessions:")
        sessions = self.metasploit_manager.get_active_sessions()
        
        if not sessions:
            print("   No active sessions")
            return
            
        print("─" * 80)
        print(f"{'ID':<5} {'Type':<15} {'Target':<20} {'Tunnel':<15} {'Info'}")
        print("─" * 80)
        
        for session in sessions:
            print(f"{session.id:<5} {session.type:<15} {session.target:<20} {session.tunnel:<15} {session.info}")
            
    def show_help(self):
        """Show help information"""
        help_text = """
📖 DarkPen CLI Commands:

   status     - Show current status
   modules    - List common modules (fast)
   search     - Search for specific modules
   select     - Select a module
   target     - Set target information
   check      - Check if target is vulnerable
   exploit    - Run the exploit
   sessions   - List active sessions
   help       - Show this help
   quit       - Exit DarkPen CLI

💡 Tips:
   - Use 'modules' for fast listing of common modules
   - Use 'search <term>' to find specific modules
   - Use 'select <number>' to choose from common modules
   - Use 'target' to set the target IP and port
   - Use 'check' to test vulnerability before exploitation
   - Use 'exploit' to run the actual attack
        """
        print(help_text)
        
    def run(self):
        """Main CLI loop"""
        self.print_banner()
        self.print_status()
        
        while True:
            try:
                print("\n" + "─" * 80)
                command = input("DarkPen> ").strip()
                
                if command in ['quit', 'exit', 'q']:
                    print("👋 Goodbye!")
                    break
                elif command in ['help', 'h', '?']:
                    self.show_help()
                elif command in ['status', 's']:
                    self.print_status()
                elif command in ['modules', 'list', 'ls']:
                    self.list_modules()
                elif command.startswith('search '):
                    query = command[7:].strip()
                    self.search_modules(query)
                elif command in ['select', 'sel']:
                    self.select_module()
                elif command in ['target', 't']:
                    self.set_target()
                elif command in ['check', 'c']:
                    self.check_module()
                elif command in ['exploit', 'run', 'e']:
                    self.run_exploit()
                elif command in ['sessions', 'sess']:
                    self.list_sessions()
                elif command == '':
                    continue
                else:
                    print(f"❌ Unknown command: {command}")
                    print("   Type 'help' for available commands")
                    
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")

def main():
    """Main entry point"""
    try:
        cli = DarkPenCLI()
        cli.run()
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 