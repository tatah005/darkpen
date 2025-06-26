import os
import time
from typing import Optional, Dict, List, Tuple
from pymetasploit3.msfrpc import MsfRpcClient
from .logger import DarkPenLogger
from .config_manager import ConfigManager

class MetasploitManager:
    def __init__(self):
        self.logger = DarkPenLogger().get_logger('metasploit')
        self.config = ConfigManager()
        self.client = None
        self.connected = False
        
    def connect(self) -> bool:
        """Connect to MSF RPC server"""
        try:
            msf_config = self.config.get('tools.metasploit', {})
            password = self.config.get_encrypted('tools.metasploit.password')
            
            if not password:
                self.logger.error("Metasploit password not configured")
                return False
                
            self.client = MsfRpcClient(
                password,
                server=msf_config.get('host', 'localhost'),
                port=msf_config.get('port', 55553),
                ssl=msf_config.get('ssl', True),
                verify=msf_config.get('verify_ssl', False)
            )
            
            # Test connection
            self.client.cores.version
            self.connected = True
            self.logger.info("Connected to Metasploit RPC server")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Metasploit RPC: {str(e)}")
            self.connected = False
            return False
            
    def ensure_connected(self) -> bool:
        """Ensure connection to MSF RPC server"""
        if not self.connected:
            return self.connect()
        return True
        
    def search_exploits(self, query: str) -> List[Dict]:
        """Search for exploits"""
        if not self.ensure_connected():
            return []
            
        try:
            results = self.client.modules.exploits
            filtered = []
            
            for exploit in results:
                if query.lower() in exploit.lower():
                    info = self.client.modules.use('exploit', exploit)
                    filtered.append({
                        'name': exploit,
                        'rank': info.get('rank'),
                        'description': info.get('description'),
                        'references': info.get('references', []),
                        'targets': info.get('targets', []),
                        'payload_types': info.get('compatible_payloads', [])
                    })
                    
            return filtered
            
        except Exception as e:
            self.logger.error(f"Error searching exploits: {str(e)}")
            return []
            
    def get_exploit_info(self, exploit_name: str) -> Optional[Dict]:
        """Get detailed information about an exploit"""
        if not self.ensure_connected():
            return None
            
        try:
            exploit = self.client.modules.use('exploit', exploit_name)
            return {
                'name': exploit_name,
                'rank': exploit.get('rank'),
                'description': exploit.get('description'),
                'authors': exploit.get('authors', []),
                'references': exploit.get('references', []),
                'targets': exploit.get('targets', []),
                'payload_types': exploit.get('compatible_payloads', []),
                'options': exploit.get('options', {})
            }
        except Exception as e:
            self.logger.error(f"Error getting exploit info: {str(e)}")
            return None
            
    def get_payload_info(self, payload_name: str) -> Optional[Dict]:
        """Get detailed information about a payload"""
        if not self.ensure_connected():
            return None
            
        try:
            payload = self.client.modules.use('payload', payload_name)
            return {
                'name': payload_name,
                'description': payload.get('description'),
                'authors': payload.get('authors', []),
                'options': payload.get('options', {})
            }
        except Exception as e:
            self.logger.error(f"Error getting payload info: {str(e)}")
            return None
            
    def execute_exploit(self, exploit_name: str, payload_name: str, 
                       options: Dict) -> Tuple[bool, Optional[str]]:
        """Execute an exploit with specified payload and options"""
        if not self.ensure_connected():
            return False, "Not connected to Metasploit"
            
        try:
            # Create console
            console_id = self.client.consoles.console().get('id')
            
            # Set up exploit
            self.client.modules.use('exploit', exploit_name)
            for key, value in options.get('exploit', {}).items():
                self.client.modules.execute('exploit', exploit_name, {key: value})
                
            # Set up payload
            self.client.modules.use('payload', payload_name)
            for key, value in options.get('payload', {}).items():
                self.client.modules.execute('payload', payload_name, {key: value})
                
            # Execute
            self.client.consoles.console(console_id).write(
                f"use exploit/{exploit_name}\n"
                f"set payload {payload_name}\n"
                "exploit -j\n"
            )
            
            # Wait for execution
            time.sleep(2)
            result = self.client.consoles.console(console_id).read()
            
            # Check for success
            if "opened successfully" in result['data'].lower():
                self.logger.info(f"Exploit {exploit_name} executed successfully")
                return True, result['data']
            else:
                self.logger.warning(f"Exploit {exploit_name} execution failed")
                return False, result['data']
                
        except Exception as e:
            self.logger.error(f"Error executing exploit: {str(e)}")
            return False, str(e)
            
    def list_sessions(self) -> List[Dict]:
        """List active sessions"""
        if not self.ensure_connected():
            return []
            
        try:
            sessions = self.client.sessions.list
            return [
                {
                    'id': sid,
                    'type': session['type'],
                    'tunnel_local': session.get('tunnel_local'),
                    'tunnel_peer': session.get('tunnel_peer'),
                    'via_exploit': session.get('via_exploit'),
                    'via_payload': session.get('via_payload'),
                    'info': session.get('info', ''),
                    'workspace': session.get('workspace', ''),
                    'target_host': session.get('target_host'),
                    'username': session.get('username'),
                    'uuid': session.get('uuid'),
                    'exploit_uuid': session.get('exploit_uuid')
                }
                for sid, session in sessions.items()
            ]
        except Exception as e:
            self.logger.error(f"Error listing sessions: {str(e)}")
            return []
            
    def interact_session(self, session_id: int, command: str) -> Optional[str]:
        """Send command to a session"""
        if not self.ensure_connected():
            return None
            
        try:
            session = self.client.sessions.session(session_id)
            return session.run_with_output(command)
        except Exception as e:
            self.logger.error(f"Error interacting with session: {str(e)}")
            return None
            
    def stop_session(self, session_id: int) -> bool:
        """Stop a session"""
        if not self.ensure_connected():
            return False
            
        try:
            self.client.sessions.session(session_id).stop()
            return True
        except Exception as e:
            self.logger.error(f"Error stopping session: {str(e)}")
            return False 