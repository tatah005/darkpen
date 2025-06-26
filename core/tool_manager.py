import os
import json
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
from pymetasploit3.msfrpc import MsfRpcClient
from zapv2 import ZAPv2
import paramiko
import scapy.all as scapy

class ToolManager:
    def __init__(self):
        self.tools = {
            'metasploit': {
                'enabled': False,
                'config': {
                    'host': 'localhost',
                    'port': 55553,
                    'user': 'msf',
                    'password': ''
                },
                'client': None
            },
            'burp': {
                'enabled': False,
                'config': {
                    'host': 'localhost',
                    'port': 1337,
                    'api_key': ''
                },
                'client': None
            },
            'zap': {
                'enabled': False,
                'config': {
                    'host': 'localhost',
                    'port': 8080,
                    'api_key': ''
                },
                'client': None
            },
            'wireshark': {
                'enabled': False,
                'config': {
                    'interface': 'eth0',
                    'capture_filter': ''
                },
                'process': None
            }
        }

    def configure_tool(self, tool_name: str, config: Dict) -> bool:
        """Configure a specific tool with the provided settings"""
        if tool_name not in self.tools:
            return False

        self.tools[tool_name]['config'].update(config)
        return self._initialize_tool(tool_name)

    def _initialize_tool(self, tool_name: str) -> bool:
        """Initialize connection to a specific tool"""
        try:
            if tool_name == 'metasploit':
                return self._init_metasploit()
            elif tool_name == 'zap':
                return self._init_zap()
            elif tool_name == 'burp':
                return self._init_burp()
            elif tool_name == 'wireshark':
                return self._init_wireshark()
            return False
        except Exception as e:
            print(f"Error initializing {tool_name}: {str(e)}")
            return False

    def _init_metasploit(self) -> bool:
        """Initialize Metasploit connection"""
        try:
            config = self.tools['metasploit']['config']
            self.tools['metasploit']['client'] = MsfRpcClient(
                config['password'],
                server=config['host'],
                port=config['port'],
                username=config['user']
            )
            self.tools['metasploit']['enabled'] = True
            return True
        except Exception:
            self.tools['metasploit']['enabled'] = False
            return False

    def _init_zap(self) -> bool:
        """Initialize OWASP ZAP connection"""
        try:
            config = self.tools['zap']['config']
            self.tools['zap']['client'] = ZAPv2(
                apikey=config['api_key'],
                proxies={'http': f"http://{config['host']}:{config['port']}",
                        'https': f"http://{config['host']}:{config['port']}"}
            )
            self.tools['zap']['enabled'] = True
            return True
        except Exception:
            self.tools['zap']['enabled'] = False
            return False

    def _init_burp(self) -> bool:
        """Initialize Burp Suite connection"""
        try:
            # Implementation would depend on Burp's REST API
            config = self.tools['burp']['config']
            # Placeholder for Burp initialization
            self.tools['burp']['enabled'] = True
            return True
        except Exception:
            self.tools['burp']['enabled'] = False
            return False

    def _init_wireshark(self) -> bool:
        """Initialize Wireshark capture"""
        try:
            config = self.tools['wireshark']['config']
            # Check if tshark is available
            subprocess.run(['tshark', '--version'], capture_output=True, check=True)
            self.tools['wireshark']['enabled'] = True
            return True
        except Exception:
            self.tools['wireshark']['enabled'] = False
            return False

    def start_capture(self, tool_name: str, target: str, options: Dict) -> Dict:
        """Start a capture/scan with the specified tool"""
        if not self.tools.get(tool_name, {}).get('enabled', False):
            return {'status': 'error', 'message': f'{tool_name} is not enabled'}

        try:
            if tool_name == 'metasploit':
                return self._run_metasploit_module(target, options)
            elif tool_name == 'zap':
                return self._run_zap_scan(target, options)
            elif tool_name == 'burp':
                return self._run_burp_scan(target, options)
            elif tool_name == 'wireshark':
                return self._start_packet_capture(target, options)
            else:
                return {'status': 'error', 'message': 'Unknown tool'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def stop_capture(self, tool_name: str) -> Dict:
        """Stop a running capture/scan"""
        if not self.tools.get(tool_name, {}).get('enabled', False):
            return {'status': 'error', 'message': f'{tool_name} is not enabled'}

        try:
            if tool_name == 'wireshark':
                return self._stop_packet_capture()
            elif tool_name in ['zap', 'burp', 'metasploit']:
                return self._stop_tool_scan(tool_name)
            else:
                return {'status': 'error', 'message': 'Unknown tool'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _run_metasploit_module(self, target: str, options: Dict) -> Dict:
        """Run a Metasploit module"""
        try:
            client = self.tools['metasploit']['client']
            if not client:
                return {'status': 'error', 'message': 'Metasploit not connected'}

            # Set up the exploit
            exploit = client.modules.use('exploit', options.get('module'))
            exploit['RHOSTS'] = target
            for key, value in options.get('parameters', {}).items():
                exploit[key] = value

            # Run the exploit
            result = exploit.execute()
            return {
                'status': 'success',
                'job_id': result.get('job_id'),
                'message': 'Module executed successfully'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _run_zap_scan(self, target: str, options: Dict) -> Dict:
        """Run a ZAP scan"""
        try:
            zap = self.tools['zap']['client']
            if not zap:
                return {'status': 'error', 'message': 'ZAP not connected'}

            # Start spidering
            scan_id = zap.spider.scan(target)
            
            return {
                'status': 'success',
                'scan_id': scan_id,
                'message': 'ZAP scan started successfully'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _run_burp_scan(self, target: str, options: Dict) -> Dict:
        """Run a Burp Suite scan"""
        try:
            # Implementation would depend on Burp's REST API
            return {
                'status': 'success',
                'message': 'Burp scan started successfully'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _start_packet_capture(self, target: str, options: Dict) -> Dict:
        """Start a packet capture with tshark"""
        try:
            config = self.tools['wireshark']['config']
            output_file = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            
            # Build capture filter
            capture_filter = f"host {target}"
            if options.get('port'):
                capture_filter += f" and port {options['port']}"
            
            # Start tshark process
            cmd = [
                'tshark',
                '-i', config['interface'],
                '-f', capture_filter,
                '-w', output_file
            ]
            
            self.tools['wireshark']['process'] = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return {
                'status': 'success',
                'output_file': output_file,
                'message': 'Packet capture started successfully'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _stop_packet_capture(self) -> Dict:
        """Stop a running packet capture"""
        try:
            process = self.tools['wireshark'].get('process')
            if process:
                process.terminate()
                process.wait()
                self.tools['wireshark']['process'] = None
                return {'status': 'success', 'message': 'Packet capture stopped'}
            return {'status': 'error', 'message': 'No capture running'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _stop_tool_scan(self, tool_name: str) -> Dict:
        """Stop a running scan for ZAP, Burp, or Metasploit"""
        try:
            if tool_name == 'zap':
                self.tools['zap']['client'].spider.stop_all_scans()
                self.tools['zap']['client'].ascan.stop_all_scans()
            elif tool_name == 'metasploit':
                client = self.tools['metasploit']['client']
                if client:
                    client.jobs.stop_all()
            # Implementation for Burp would go here
            
            return {'status': 'success', 'message': f'{tool_name} scan stopped'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def get_tool_status(self, tool_name: str) -> Dict:
        """Get the current status of a tool"""
        if tool_name not in self.tools:
            return {'status': 'error', 'message': 'Unknown tool'}

        tool = self.tools[tool_name]
        return {
            'enabled': tool['enabled'],
            'config': tool['config'],
            'connected': bool(tool.get('client') or tool.get('process'))
        }

    def get_scan_results(self, tool_name: str, scan_id: Optional[str] = None) -> Dict:
        """Get results from a tool's scan"""
        if not self.tools.get(tool_name, {}).get('enabled', False):
            return {'status': 'error', 'message': f'{tool_name} is not enabled'}

        try:
            if tool_name == 'zap':
                return self._get_zap_results(scan_id)
            elif tool_name == 'metasploit':
                return self._get_metasploit_results(scan_id)
            elif tool_name == 'burp':
                return self._get_burp_results(scan_id)
            elif tool_name == 'wireshark':
                return self._get_packet_capture_results()
            else:
                return {'status': 'error', 'message': 'Unknown tool'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _get_zap_results(self, scan_id: Optional[str]) -> Dict:
        """Get ZAP scan results"""
        try:
            zap = self.tools['zap']['client']
            if not zap:
                return {'status': 'error', 'message': 'ZAP not connected'}

            alerts = zap.core.alerts()
            return {
                'status': 'success',
                'alerts': alerts,
                'message': 'Retrieved ZAP results successfully'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _get_metasploit_results(self, job_id: Optional[str]) -> Dict:
        """Get Metasploit results"""
        try:
            client = self.tools['metasploit']['client']
            if not client:
                return {'status': 'error', 'message': 'Metasploit not connected'}

            if job_id:
                job_info = client.jobs.info(job_id)
                return {
                    'status': 'success',
                    'job_info': job_info,
                    'message': 'Retrieved Metasploit results successfully'
                }
            else:
                return {
                    'status': 'success',
                    'jobs': client.jobs.list,
                    'message': 'Retrieved all Metasploit jobs'
                }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _get_burp_results(self, scan_id: Optional[str]) -> Dict:
        """Get Burp Suite results"""
        # Implementation would depend on Burp's REST API
        return {
            'status': 'success',
            'message': 'Burp results retrieved successfully'
        }

    def _get_packet_capture_results(self) -> Dict:
        """Get packet capture results"""
        try:
            process = self.tools['wireshark'].get('process')
            if process:
                return {
                    'status': 'running',
                    'message': 'Packet capture still running'
                }
            return {
                'status': 'success',
                'message': 'Packet capture completed'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)} 