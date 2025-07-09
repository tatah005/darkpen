#!/usr/bin/env python3
"""
Test script for Metasploit integration
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.metasploit_integration import MetasploitManager, ModuleType

def test_metasploit_integration():
    """Test the Metasploit integration"""
    print("🔍 Testing Metasploit Integration...")
    
    # Initialize manager
    manager = MetasploitManager()
    
    # Check if Metasploit is available
    if not manager.is_available():
        print("❌ Metasploit not found!")
        return False
    
    print(f"✅ Metasploit found at: {manager.msfconsole_path}")
    
    # Get version
    version = manager.get_version()
    if version:
        print(f"📋 Version: {version}")
    
    # Search for modules
    print("\n🔍 Searching for exploit modules...")
    modules = manager.search_modules("", ModuleType.EXPLOIT)
    if modules:
        print(f"✅ Found {len(modules)} exploit modules")
        print("📋 Sample modules:")
        for i, module in enumerate(modules[:5]):
            print(f"   {i+1}. {module}")
    else:
        print("⚠️ No exploit modules found")
    
    # Test module info
    if modules:
        print(f"\n📋 Getting info for module: {modules[0]}")
        module_info = manager.get_module_info(modules[0])
        if module_info:
            print(f"✅ Module info retrieved:")
            print(f"   Name: {module_info.name}")
            print(f"   Type: {module_info.type.value}")
            print(f"   Description: {module_info.description[:100]}...")
            print(f"   Rank: {module_info.rank}")
        else:
            print("❌ Failed to get module info")
    
    # Test check functionality (with a safe target)
    print(f"\n🔍 Testing module check (safe target)...")
    if modules:
        result = manager.check_module(modules[0], "127.0.0.1", "80")
        print(f"✅ Check result: {result['message']}")
    
    print("\n✅ Metasploit integration test completed!")
    return True

if __name__ == "__main__":
    test_metasploit_integration() 