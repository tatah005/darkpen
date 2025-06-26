from typing import Dict, List, Optional
import subprocess
import json
import threading
from dataclasses import dataclass
import nmap
from metasploit.msfrpc import MsfRpcClient

@dataclass
class ScanResult:
    timestamp: str
    target: str
    tool: str
    findings: Dict
    risk_level: str
    recommendations: List[str]

class ToolsManager:
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.msf_client = None
        self.current_workspace = "default"
        
    def connect_msf(self, password: str, host: str = "127.0.0.1", port: int = 55553) -> bool:
        """Connect to Metasploit RPC server"""
        try:
            self.msf_client = MsfRpcClient(password, server=host, port=port)
            return True
        except Exception as e:
            print(f"Failed to connect to MSF: {e}")
            return False

    def get_msf_exploits(self, search_term: str = "") -> List[Dict]:
        """Get available Metasploit exploits"""
        if not self.msf_client:
            return []
        
        exploits = []
        try:
            if search_term:
                results = self.msf_client.modules.exploits.search(search_term)
            else:
                results = self.msf_client.modules.exploits
            
            for exploit in results:
                info = self.msf_client.modules.exploits[exploit].info
                exploits.append({
                    'name': exploit,
                    'description': info.get('description', ''),
                    'rank': info.get('rank', ''),
                    'references': info.get('references', []),
                    'targets': info.get('targets', [])
                })
        except Exception as e:
            print(f"Error getting exploits: {e}")
        
        return exploits

    def get_msf_payloads(self, platform: str = "") -> List[Dict]:
        """Get available Metasploit payloads"""
        if not self.msf_client:
            return []
        
        payloads = []
        try:
            if platform:
                results = self.msf_client.modules.payloads.search(platform)
            else:
                results = self.msf_client.modules.payloads
            
            for payload in results:
                info = self.msf_client.modules.payloads[payload].info
                payloads.append({
                    'name': payload,
                    'description': info.get('description', ''),
                    'platform': info.get('platform', ''),
                    'arch': info.get('arch', ''),
                    'author': info.get('author', [])
                })
        except Exception as e:
            print(f"Error getting payloads: {e}")
        
        return payloads

    def run_exploit(self, exploit_name: str, payload: str, options: Dict) -> Dict:
        """Run a Metasploit exploit"""
        if not self.msf_client:
            return {'success': False, 'message': 'Not connected to MSF'}
        
        try:
            # Create exploit instance
            exploit = self.msf_client.modules.use('exploit', exploit_name)
            
            # Set options
            for key, value in options.items():
                exploit[key] = value
            
            # Set payload
            exploit.execute(payload=payload)
            
            return {'success': True, 'message': 'Exploit launched successfully'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def scan_target(self, target: str, scan_type: str = "basic") -> ScanResult:
        """Perform a scan using nmap"""
        scan_types = {
            "basic": "-sV -sC",
            "full": "-sV -sC -A -p-",
            "quick": "-F",
            "udp": "-sU",
            "vuln": "-sV --script vuln"
        }
        
        args = scan_types.get(scan_type, scan_types["basic"])
        
        try:
            self.nmap_scanner.scan(target, arguments=args)
            
            findings = {
                'ports': self.nmap_scanner[target].get('tcp', {}),
                'os': self.nmap_scanner[target].get('osmatch', []),
                'hostnames': self.nmap_scanner[target].get('hostnames', []),
                'status': self.nmap_scanner[target].get('status', {})
            }
            
            # Determine risk level based on open ports and services
            risk_level = self._assess_risk(findings)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(findings)
            
            return ScanResult(
                timestamp=self.nmap_scanner.get_nmap_last_output(),
                target=target,
                tool="nmap",
                findings=findings,
                risk_level=risk_level,
                recommendations=recommendations
            )
        except Exception as e:
            print(f"Scan error: {e}")
            return None

    def _assess_risk(self, findings: Dict) -> str:
        """Assess the risk level based on scan findings"""
        high_risk_ports = {21, 23, 445, 3389}  # FTP, Telnet, SMB, RDP
        open_ports = findings.get('ports', {}).keys()
        
        if any(port in high_risk_ports for port in open_ports):
            return "HIGH"
        elif len(open_ports) > 10:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_recommendations(self, findings: Dict) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        ports = findings.get('ports', {})
        
        for port, data in ports.items():
            service = data.get('name', '')
            
            if port == 21 and service == 'ftp':
                recommendations.append("Consider replacing FTP with SFTP or FTPS")
            elif port == 23 and service == 'telnet':
                recommendations.append("Disable Telnet and use SSH instead")
            elif port == 445:
                recommendations.append("Ensure SMB is properly configured and patched")
            elif port == 3389:
                recommendations.append("Use Network Level Authentication for RDP")
                
        return recommendations

    def get_active_sessions(self) -> List[Dict]:
        """Get active Metasploit sessions"""
        if not self.msf_client:
            return []
        
        try:
            sessions = self.msf_client.sessions.list
            return [
                {
                    'id': sid,
                    'type': session.get('type', ''),
                    'tunnel': session.get('tunnel_local', ''),
                    'target': session.get('target_host', ''),
                    'info': session.get('info', '')
                }
                for sid, session in sessions.items()
            ]
        except Exception as e:
            print(f"Error getting sessions: {e}")
            return []

    def generate_payload(self, payload_type: str, options: Dict) -> Dict:
        """Generate a Metasploit payload"""
        if not self.msf_client:
            return {'success': False, 'message': 'Not connected to MSF'}
        
        try:
            # Create payload instance
            payload = self.msf_client.modules.use('payload', payload_type)
            
            # Set options
            for key, value in options.items():
                payload[key] = value
            
            # Generate
            generated = payload.generate()
            
            return {
                'success': True,
                'payload': generated,
                'message': 'Payload generated successfully'
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def start_msf_handler(self, payload_type: str, options: Dict) -> Dict:
        """Start a Metasploit handler"""
        if not self.msf_client:
            return {'success': False, 'message': 'Not connected to MSF'}
        
        try:
            # Create handler
            handler = self.msf_client.modules.use('exploit', 'multi/handler')
            handler.execute(payload=payload_type, **options)
            
            return {'success': True, 'message': 'Handler started successfully'}
        except Exception as e:
            return {'success': False, 'message': str(e)} 