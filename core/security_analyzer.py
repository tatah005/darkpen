import re
from datetime import datetime
from typing import Dict, List
import nmap
import subprocess
import json

class SecurityAnalyzer:
    def __init__(self):
        self.nmap_scanner = nmap.PortScanner()
        self.current_scan = None
        self.scan_history = []
    
    def run_nmap_scan(self, target, scan_type="quick"):
        """Run an Nmap scan with specified parameters"""
        scan_args = {
            "quick": "-sV -T4 -F",
            "full": "-sV -T4 -p-",
            "vulnerability": "-sV -T4 -F --script vuln",
            "custom": "-sV -T4 -p- --script vuln,auth,default"
        }
        
        try:
            scan_result = self.nmap_scanner.scan(
                hosts=target,
                arguments=scan_args.get(scan_type, scan_args["quick"])
            )
            
            # Format and store scan results
            formatted_result = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'scan_type': scan_type,
                'results': scan_result
            }
            
            self.scan_history.append(formatted_result)
            return formatted_result
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'scan_type': scan_type
            }
    
    def run_nikto_scan(self, target):
        """Run Nikto web vulnerability scan"""
        try:
            cmd = ["nikto", "-h", target, "-Format", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'tool': 'nikto',
                'results': json.loads(result.stdout) if result.stdout else {}
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'tool': 'nikto'
            }
    
    def run_sqlmap_scan(self, target):
        """Run SQLMap database testing"""
        try:
            cmd = ["sqlmap", "-u", target, "--batch", "--random-agent", "--json-output"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'tool': 'sqlmap',
                'results': json.loads(result.stdout) if result.stdout else {}
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'tool': 'sqlmap'
            }
    
    def run_ffuf_scan(self, target, wordlist="common.txt"):
        """Run FFUF web fuzzing scan"""
        try:
            cmd = ["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-o", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            return {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'tool': 'ffuf',
                'wordlist': wordlist,
                'results': json.loads(result.stdout) if result.stdout else {}
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'target': target,
                'tool': 'ffuf'
            }
    
    def analyze_ports(self, scan_results):
        """Analyze open ports and services"""
        ports_analysis = {
            'open_ports': [],
            'services': {},
            'potential_risks': []
        }
        
        if 'scan' in scan_results:
            for host in scan_results['scan'].values():
                if 'tcp' in host:
                    for port, data in host['tcp'].items():
                        if data['state'] == 'open':
                            ports_analysis['open_ports'].append(port)
                            ports_analysis['services'][port] = data['name']
                            
                            # Check for common risky services
                            if data['name'] in ['ftp', 'telnet', 'rsh']:
                                ports_analysis['potential_risks'].append(
                                    f"Insecure service {data['name']} running on port {port}"
                                )
        
        return ports_analysis
    
    def get_scan_history(self):
        """Return formatted scan history"""
        return [{
            'timestamp': scan['timestamp'],
            'target': scan['target'],
            'tool': scan.get('tool', 'nmap'),
            'type': scan.get('scan_type', 'N/A'),
            'status': 'Error' if 'error' in scan else 'Complete'
        } for scan in self.scan_history]

    @staticmethod
    def get_risk_level(results: Dict) -> str:
        """Determine risk level based on scan results"""
        if not results:
            return "Unknown"
            
        vulnerabilities = results.get('vulnerabilities', [])
        services = results.get('services', {})
        
        # Check for critical vulnerabilities
        for vuln in vulnerabilities:
            if "critical" in vuln.lower():
                return "Critical"
                
        # Check for high-risk services and vulnerabilities
        high_risk_services = {
            'ftp': ['21'],
            'telnet': ['23'],
            'smtp': ['25'],
            'dns': ['53'],
            'http': ['80', '8080'],
            'pop3': ['110'],
            'rpc': ['111'],
            'smb': ['139', '445'],
            'snmp': ['161'],
            'ldap': ['389'],
            'https': ['443'],
            'mssql': ['1433'],
            'mysql': ['3306'],
            'rdp': ['3389']
        }
        
        high_risk_count = 0
        medium_risk_count = 0
        
        # Analyze open ports and services
        for port, service_info in services.items():
            service_name = service_info.get('name', '').lower()
            
            # Check if service is in high-risk list
            for risk_service, risk_ports in high_risk_services.items():
                if service_name == risk_service or port in risk_ports:
                    high_risk_count += 1
                    break
            
            # Check for version information
            if service_info.get('version'):
                # Old versions are considered medium risk
                if any(x in service_info['version'].lower() for x in ['1.', '2.0', '3.0', 'beta']):
                    medium_risk_count += 1
        
        # Check for high-risk vulnerabilities
        for vuln in vulnerabilities:
            if "high" in vuln.lower():
                high_risk_count += 1
            elif "medium" in vuln.lower():
                medium_risk_count += 1
        
        # Determine overall risk level
        if high_risk_count > 2:
            return "High"
        elif high_risk_count > 0 or medium_risk_count > 2:
            return "Medium"
        elif medium_risk_count > 0:
            return "Low"
        else:
            return "Info"

    @staticmethod
    def analyze_scan_results(results: Dict) -> str:
        """Generate a detailed analysis of scan results"""
        if not results:
            return "No scan results available."
        
        analysis = []
        
        # Add scan overview
        analysis.append("SCAN OVERVIEW")
        analysis.append(f"Target: {results.get('target', 'Unknown')}")
        analysis.append(f"Scan Type: {results.get('scan_type', 'Unknown')}")
        analysis.append(f"Timestamp: {results.get('scan_time', 'Unknown')}")
        analysis.append("")
        
        # Analyze open ports and services
        open_ports = results.get('open_ports', [])
        services = results.get('services', {})
        if open_ports:
            analysis.append(f"OPEN PORTS AND SERVICES ({len(open_ports)} found)")
            for port in open_ports:
                service_info = services.get(str(port), {})
                service_str = f"Port {port}: {service_info.get('name', 'unknown')}"
                if service_info.get('product'):
                    service_str += f" - {service_info['product']}"
                if service_info.get('version'):
                    service_str += f" ({service_info['version']})"
                analysis.append(service_str)
            analysis.append("")
        
        # Analyze OS detection results
        os_info = results.get('os_info', [])
        if os_info:
            analysis.append("OPERATING SYSTEM DETECTION")
            for os in os_info:
                analysis.append(f"- {os}")
            analysis.append("")
        
        # Analyze vulnerabilities
        vulnerabilities = results.get('vulnerabilities', [])
        if vulnerabilities:
            analysis.append(f"VULNERABILITIES ({len(vulnerabilities)} found)")
            severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            
            for vuln in vulnerabilities:
                if "critical" in vuln.lower():
                    severity_count['Critical'] += 1
                elif "high" in vuln.lower():
                    severity_count['High'] += 1
                elif "medium" in vuln.lower():
                    severity_count['Medium'] += 1
                else:
                    severity_count['Low'] += 1
                analysis.append(f"- {vuln}")
            
            analysis.append("\nVulnerability Summary:")
            for severity, count in severity_count.items():
                if count > 0:
                    analysis.append(f"{severity}: {count}")
            analysis.append("")
        
        # Add recommendations
        analysis.append("RECOMMENDATIONS")
        if vulnerabilities:
            analysis.append("- Immediate attention required for critical and high-risk vulnerabilities")
            analysis.append("- Consider implementing security patches and updates")
            analysis.append("- Review and possibly disable unnecessary services")
        else:
            analysis.append("- Continue monitoring for new vulnerabilities")
            analysis.append("- Maintain regular security updates")
            analysis.append("- Consider periodic security assessments")
        
        return "\n".join(analysis)

    @staticmethod
    def _is_outdated_version(service: Dict) -> bool:
        """Check if service version is outdated"""
        name = service.get('name', '').lower()
        version = service.get('version', '')
        
        outdated_versions = {
            'apache': ['2.4.49', '2.4.50'],
            'nginx': ['1.13', '1.14'],
            'openssh': ['7.2', '7.3'],
            'vsftpd': ['2.3.4'],
        }
        
        for service_name, versions in outdated_versions.items():
            if service_name in name and any(version.startswith(v) for v in versions):
                return True
        return False

    @staticmethod
    def _generate_recommendations(results: Dict) -> List[str]:
        """Generate specific security recommendations based on scan results"""
        recommendations = []
        services = results.get('services', {})
        
        # Service-specific recommendations
        for port, service in services.items():
            name = service.get('name', '').lower()
            version = service.get('version', '')
            
            if name == 'ssh':
                recommendations.append("Ensure SSH is using strong ciphers and key exchange algorithms")
                if version and SecurityAnalyzer._is_outdated_version(service):
                    recommendations.append(f"Upgrade SSH server (current version: {version})")
            
            elif name in ['http', 'https']:
                recommendations.append("Implement Web Application Firewall (WAF)")
                recommendations.append("Enable HTTPS with strong TLS configuration")
                if 'apache' in service.get('product', '').lower():
                    recommendations.append("Configure Apache security headers")
                elif 'nginx' in service.get('product', '').lower():
                    recommendations.append("Configure Nginx security headers")
            
            elif name == 'ftp':
                recommendations.append("Consider replacing FTP with SFTP")
                recommendations.append("Ensure FTP is configured to use TLS")
        
        # General recommendations
        if len(results.get('open_ports', [])) > 10:
            recommendations.append("Review and close unnecessary open ports")
        
        if not results.get('os_info'):
            recommendations.append("Consider implementing OS fingerprint obfuscation")
        
        return recommendations 