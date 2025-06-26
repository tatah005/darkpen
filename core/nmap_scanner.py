import nmap
import json
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import logging
import os

@dataclass
class ScanResult:
    target: str
    open_ports: List[int]
    services: Dict[int, Dict[str, Any]]
    vulnerabilities: List[str]
    raw_data: Dict[str, Any]

class NmapScanner:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            self.logger.error(f"Failed to initialize nmap: {e}")
            raise
    
    def scan(self, target: str, ports: str = '1-1024', arguments: str = '-sV') -> ScanResult:
        """Perform Nmap scan with specified arguments"""
        try:
            self.logger.info(f"Starting scan of {target} with arguments: {arguments}")
            
            # Check if we need sudo
            if any(arg in arguments for arg in ['-sS', '-sW', '-sU', '-sO']):
                if os.geteuid() != 0:
                    raise PermissionError("Root privileges required for this scan type")
            
            # Perform the scan
            scan_data = self.nm.scan(hosts=target, ports=ports, arguments=arguments)
            
            if not scan_data or 'scan' not in scan_data:
                raise ValueError("No scan results returned")
            
            # Extract scan results
            if target not in scan_data['scan']:
                raise ValueError(f"No results for target {target}")
            
            host_data = scan_data['scan'][target]
            open_ports = []
            services = {}
            
            # Get protocols (tcp, udp, etc.)
            for proto in host_data.get('tcp', {}).keys():
                port_data = host_data['tcp'][proto]
                if port_data['state'] == 'open':
                    open_ports.append(int(proto))
                    services[int(proto)] = {
                        'name': port_data.get('name', 'unknown'),
                        'product': port_data.get('product', ''),
                        'version': port_data.get('version', ''),
                        'extrainfo': port_data.get('extrainfo', ''),
                        'state': port_data.get('state', '')
                    }
            
            # Analyze for vulnerabilities
            vulnerabilities = self._analyze_results(services)
            
            return ScanResult(
                target=target,
                open_ports=open_ports,
                services=services,
                vulnerabilities=vulnerabilities,
                raw_data=scan_data
            )
            
        except nmap.PortScannerError as e:
            self.logger.error(f"Nmap scan error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise

    def _analyze_results(self, services: Dict[int, Dict[str, Any]]) -> List[str]:
        """Analyze scan results for potential vulnerabilities"""
        vulns = []
        
        for port, service in services.items():
            service_name = service.get('name', '').lower()
            version = service.get('version', '')
            product = service.get('product', '')
            
            # Check for common vulnerabilities
            if service_name == 'ssh' and version:
                if '7.' in version:
                vulns.append(f"Potential SSH vulnerability (CVE-2023-38408) on port {port}")
                if '6.6' in version:
                    vulns.append(f"OpenSSH < 6.7 vulnerability on port {port}")
            
            if 'http' in service_name:
                if 'Apache' in product:
                    if '2.4.49' in version:
                vulns.append(f"Apache Path Traversal (CVE-2021-41773) on port {port}")
                    if version.startswith('2.4.') and int(version.split('.')[2]) < 50:
                        vulns.append(f"Apache < 2.4.50 potential vulnerabilities on port {port}")
            
            # Check for dangerous services
            dangerous_services = {
                'telnet': 'Telnet service (clear text protocol)',
                'ftp': 'FTP service (consider using SFTP)',
                'rsh': 'Remote Shell service (insecure)',
                'rlogin': 'Remote Login service (insecure)',
                'rexec': 'Remote Execution service (insecure)'
            }
            
            if service_name in dangerous_services:
                vulns.append(f"{dangerous_services[service_name]} on port {port}")
        
        return vulns

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Test the scanner
    scanner = NmapScanner()
    try:
        result = scanner.scan("127.0.0.1", arguments="-F -sV")
    print(json.dumps(result.__dict__, indent=2))
    except Exception as e:
        print(f"Scan failed: {e}")
