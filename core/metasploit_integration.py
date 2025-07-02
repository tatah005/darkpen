"""
Metasploit Framework Integration Module
Provides comprehensive integration with Metasploit Framework for DarkPen
"""

import subprocess
import tempfile
import os
import json
import re
import threading
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class ModuleType(Enum):
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"
    POST = "post"
    PAYLOAD = "payload"
    ENCODER = "encoder"
    NOPS = "nops"

@dataclass
class ModuleInfo:
    """Information about a Metasploit module"""
    name: str
    type: ModuleType
    description: str
    rank: str
    author: str
    references: List[str]
    targets: List[str]
    options: Dict[str, Dict]
    platform: List[str]
    arch: List[str]

@dataclass
class SessionInfo:
    """Information about an active session"""
    id: int
    type: str
    target: str
    tunnel: str
    info: str
    platform: str
    arch: str

class MetasploitManager:
    """Comprehensive Metasploit Framework integration manager"""
    
    def __init__(self):
        self.msfconsole_path = self._find_msfconsole()
        self.current_module = None
        self.current_options = {}
        self.active_sessions = []
        self._session_lock = threading.Lock()
        
    def _find_msfconsole(self) -> Optional[str]:
        """Find msfconsole executable"""
        possible_paths = [
            '/usr/bin/msfconsole',
            '/opt/metasploit-framework/bin/msfconsole',
            'msfconsole'  # If in PATH
        ]
        
        for path in possible_paths:
            if os.path.exists(path) or self._check_command(path):
                return path
        return None
    
    def _check_command(self, command: str) -> bool:
        """Check if a command exists and is executable"""
        try:
            result = subprocess.run([command, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def is_available(self) -> bool:
        """Check if Metasploit is available"""
        return self.msfconsole_path is not None
    
    def get_version(self) -> Optional[str]:
        """Get Metasploit Framework version"""
        if not self.msfconsole_path:
            return None
        
        try:
            # Use a simpler approach - just check if msfconsole works
            result = subprocess.run([self.msfconsole_path, '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                # Try to extract version from stdout
                output = result.stdout.strip()
                if 'Framework Version:' in output:
                    for line in output.split('\n'):
                        if 'Framework Version:' in line:
                            return line.replace('Framework Version:', '').strip()
                return "6.4.61-dev"  # Default version if we can't parse it
            else:
                # If stdout is empty, try stderr
                if result.stderr.strip():
                    output = result.stderr.strip()
                    if 'Framework Version:' in output:
                        for line in output.split('\n'):
                            if 'Framework Version:' in line:
                                return line.replace('Framework Version:', '').strip()
                return "6.4.61-dev"  # Default version
        except Exception as e:
            return "6.4.61-dev"  # Default version on error
    
    def search_modules(self, query: str = "", module_type: Optional[ModuleType] = None) -> List[str]:
        """Search for modules with caching to avoid timeouts"""
        if not self.msfconsole_path:
            return []
        
        # Use a cache file to avoid repeated slow searches
        cache_file = "/tmp/darkpen_modules_cache.json"
        
        try:
            # Try to load from cache first
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    cached_modules = json.load(f)
                    if cached_modules:
                        # Filter based on query and type
                        filtered_modules = []
                        for module in cached_modules:
                            if query and query.lower() not in module.lower():
                                continue
                            if module_type and module_type.value not in module:
                                continue
                            filtered_modules.append(module)
                        return filtered_modules[:50]  # Limit results
            
            # If no cache or cache is empty, do a quick search
            search_cmd = "search"
            if query:
                search_cmd += f" {query}"
            if module_type:
                search_cmd += f" type:{module_type.value}"
            
            # Use a shorter timeout and limit results
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                rc_content = f"""
{search_cmd}
exit
"""
                f.write(rc_content)
                rc_file = f.name
            
            result = subprocess.run([
                self.msfconsole_path, '-r', rc_file, '-q'
            ], capture_output=True, text=True, timeout=30)  # Reduced timeout
            
            os.unlink(rc_file)
            
            if result.returncode == 0:
                modules = []
                for line in result.stdout.split('\n'):
                    if any(t.value in line for t in ModuleType):
                        parts = line.split()
                        if len(parts) >= 2:
                            modules.append(parts[1])
                
                # Cache the results
                try:
                    with open(cache_file, 'w') as f:
                        json.dump(modules, f)
                except:
                    pass  # Ignore cache write errors
                
                return modules[:50]  # Limit to 50 modules
        except Exception as e:
            print(f"Search error: {e}")
            # Return some common modules as fallback
            return self._get_fallback_modules()
        return []
    
    def _get_fallback_modules(self) -> List[str]:
        """Return common modules as fallback when search fails"""
        return [
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
    
    def get_module_info(self, module_name: str) -> Optional[ModuleInfo]:
        """Get detailed information about a module"""
        if not self.msfconsole_path:
            return None
        
        try:
            # Create a temporary resource file to get module info
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                rc_content = f"""
use {module_name}
info
exit
"""
                f.write(rc_content)
                rc_file = f.name
            
            result = subprocess.run([
                self.msfconsole_path, '-r', rc_file, '-q'
            ], capture_output=True, text=True, timeout=30)
            
            os.unlink(rc_file)
            
            if result.returncode == 0:
                return self._parse_module_info(result.stdout, module_name)
        except:
            pass
        return None
    
    def _parse_module_info(self, output: str, module_name: str) -> ModuleInfo:
        """Parse module information from msfconsole output"""
        lines = output.split('\n')
        
        # Extract basic info
        description = ""
        rank = "normal"
        author = ""
        references = []
        targets = []
        options = {}
        platform = []
        arch = []
        
        in_options = False
        in_targets = False
        
        for line in lines:
            line = line.strip()
            
            if "Description:" in line:
                description = line.split("Description:", 1)[1].strip()
            elif "Rank:" in line:
                rank = line.split("Rank:", 1)[1].strip()
            elif "Author:" in line:
                author = line.split("Author:", 1)[1].strip()
            elif "References:" in line:
                in_options = False
                in_targets = False
            elif "Targets:" in line:
                in_options = False
                in_targets = True
            elif "Options:" in line:
                in_options = True
                in_targets = False
            elif in_options and "=" in line:
                parts = line.split("=", 1)
                if len(parts) == 2:
                    opt_name = parts[0].strip()
                    opt_value = parts[1].strip()
                    options[opt_name] = {"value": opt_value, "required": "required" in line.lower()}
            elif in_targets and line and not line.startswith("--"):
                targets.append(line)
            elif line.startswith("Platform:"):
                platform_str = line.split("Platform:", 1)[1].strip()
                platform = [p.strip() for p in platform_str.split(",")]
            elif line.startswith("Arch:"):
                arch_str = line.split("Arch:", 1)[1].strip()
                arch = [a.strip() for a in arch_str.split(",")]
        
        # Determine module type
        module_type = ModuleType.EXPLOIT
        for t in ModuleType:
            if t.value in module_name:
                module_type = t
                break
        
        return ModuleInfo(
            name=module_name,
            type=module_type,
            description=description,
            rank=rank,
            author=author,
            references=references,
            targets=targets,
            options=options,
            platform=platform,
            arch=arch
        )
    
    def check_module(self, module_name: str, target: str, port: str = "80") -> Dict:
        """Check if a module can be used against a target"""
        if not self.msfconsole_path:
            return {'success': False, 'message': 'Metasploit not found'}
        
        try:
            # Create a temporary resource file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                rc_content = f"""
use {module_name}
set RHOSTS {target}
set RPORT {port}
check
exit
"""
                f.write(rc_content)
                rc_file = f.name
            
            result = subprocess.run([
                self.msfconsole_path, '-r', rc_file, '-q'
            ], capture_output=True, text=True, timeout=60)
            
            os.unlink(rc_file)
            
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'vulnerable' in output:
                    return {
                        'success': True, 
                        'message': 'Target appears vulnerable', 
                        'details': result.stdout,
                        'vulnerable': True
                    }
                elif 'safe' in output or 'not vulnerable' in output:
                    return {
                        'success': True, 
                        'message': 'Target appears safe', 
                        'details': result.stdout,
                        'vulnerable': False
                    }
                else:
                    return {
                        'success': True, 
                        'message': 'Check completed', 
                        'details': result.stdout,
                        'vulnerable': None
                    }
            else:
                return {'success': False, 'message': f'Error: {result.stderr}'}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'message': 'Check timed out'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def run_exploit(self, module_name: str, target: str, port: str, payload: str, 
                   lhost: str = "127.0.0.1", lport: str = "4444", 
                   options: Dict = None) -> Dict:
        """Run an exploit against a target"""
        if not self.msfconsole_path:
            return {'success': False, 'message': 'Metasploit not found'}
        
        try:
            # Create a temporary resource file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                rc_content = f"""
use {module_name}
set RHOSTS {target}
set RPORT {port}
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
"""
                
                # Add custom options
                if options:
                    for key, value in options.items():
                        rc_content += f"set {key} {value}\n"
                
                rc_content += """
exploit -j
sessions -l
exit
"""
                f.write(rc_content)
                rc_file = f.name
            
            result = subprocess.run([
                self.msfconsole_path, '-r', rc_file, '-q'
            ], capture_output=True, text=True, timeout=120)
            
            os.unlink(rc_file)
            
            if result.returncode == 0:
                output = result.stdout
                if 'meterpreter session' in output.lower() or 'session' in output.lower():
                    # Parse session information
                    sessions = self._parse_sessions(output)
                    with self._session_lock:
                        self.active_sessions.extend(sessions)
                    
                    return {
                        'success': True, 
                        'message': 'Exploit successful! Session created.', 
                        'details': output,
                        'sessions': sessions
                    }
                else:
                    return {
                        'success': True, 
                        'message': 'Exploit completed', 
                        'details': output
                    }
            else:
                return {'success': False, 'message': f'Error: {result.stderr}'}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'message': 'Exploit timed out'}
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def _parse_sessions(self, output: str) -> List[SessionInfo]:
        """Parse session information from msfconsole output"""
        sessions = []
        lines = output.split('\n')
        
        for line in lines:
            if re.match(r'\s*\d+\s+', line):  # Session line starts with number
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        session_id = int(parts[0])
                        session_type = parts[1]
                        target = parts[2]
                        tunnel = parts[3]
                        info = " ".join(parts[4:])
                        
                        sessions.append(SessionInfo(
                            id=session_id,
                            type=session_type,
                            target=target,
                            tunnel=tunnel,
                            info=info,
                            platform="",
                            arch=""
                        ))
                    except (ValueError, IndexError):
                        continue
        
        return sessions
    
    def get_active_sessions(self) -> List[SessionInfo]:
        """Get list of active sessions"""
        with self._session_lock:
            return self.active_sessions.copy()
    
    def interact_session(self, session_id: int) -> Dict:
        """Interact with a session"""
        if not self.msfconsole_path:
            return {'success': False, 'message': 'Metasploit not found'}
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                rc_content = f"""
sessions -i {session_id}
exit
"""
                f.write(rc_content)
                rc_file = f.name
            
            result = subprocess.run([
                self.msfconsole_path, '-r', rc_file, '-q'
            ], capture_output=True, text=True, timeout=30)
            
            os.unlink(rc_file)
            
            return {
                'success': True,
                'message': 'Session interaction completed',
                'details': result.stdout
            }
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def terminate_session(self, session_id: int) -> Dict:
        """Terminate a session"""
        if not self.msfconsole_path:
            return {'success': False, 'message': 'Metasploit not found'}
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                rc_content = f"""
sessions -k {session_id}
exit
"""
                f.write(rc_content)
                rc_file = f.name
            
            result = subprocess.run([
                self.msfconsole_path, '-r', rc_file, '-q'
            ], capture_output=True, text=True, timeout=30)
            
            os.unlink(rc_file)
            
            # Remove from active sessions
            with self._session_lock:
                self.active_sessions = [s for s in self.active_sessions if s.id != session_id]
            
            return {
                'success': True,
                'message': f'Session {session_id} terminated',
                'details': result.stdout
            }
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def generate_payload(self, payload_type: str, options: Dict) -> Dict:
        """Generate a payload"""
        if not self.msfconsole_path:
            return {'success': False, 'message': 'Metasploit not found'}
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                rc_content = f"""
use {payload_type}
"""
                
                for key, value in options.items():
                    rc_content += f"set {key} {value}\n"
                
                rc_content += """
generate
exit
"""
                f.write(rc_content)
                rc_file = f.name
            
            result = subprocess.run([
                self.msfconsole_path, '-r', rc_file, '-q'
            ], capture_output=True, text=True, timeout=60)
            
            os.unlink(rc_file)
            
            if result.returncode == 0:
                # Extract payload from output
                payload = self._extract_payload(result.stdout)
                return {
                    'success': True,
                    'payload': payload,
                    'details': result.stdout
                }
            else:
                return {'success': False, 'message': f'Error: {result.stderr}'}
                
        except Exception as e:
            return {'success': False, 'message': f'Error: {str(e)}'}
    
    def _extract_payload(self, output: str) -> str:
        """Extract payload from msfvenom output"""
        lines = output.split('\n')
        payload_lines = []
        in_payload = False
        
        for line in lines:
            if 'buf =' in line or 'payload =' in line:
                in_payload = True
            elif in_payload and line.strip():
                if line.strip().startswith('"') or line.strip().startswith("'"):
                    payload_lines.append(line.strip())
                else:
                    break
        
        return '\n'.join(payload_lines) 