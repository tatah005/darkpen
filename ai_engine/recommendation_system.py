import json
from typing import Dict, List, Tuple
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime

class SecurityAnalyzer:
    @staticmethod
    def get_risk_level(results: Dict) -> str:
        """Calculate overall risk level based on scan results"""
        risk_score = 0
        
        # Check for critical services
        critical_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 3389: 'RDP'}
        for port in results.get('open_ports', []):
            if port in critical_ports:
                risk_score += 2
        
        # Check for web services
        web_services = [s for s in results.get('services', {}).values() 
                       if s.get('name', '').lower() in ['http', 'https']]
        if web_services:
            risk_score += 2
        
        # Check for vulnerabilities
        vuln_count = len(results.get('vulnerabilities', []))
        risk_score += vuln_count * 3
        
        # Check for outdated services
        for service in results.get('services', {}).values():
            if SecurityAnalyzer._is_outdated_version(service):
                risk_score += 2
        
        # Return risk level based on score
        if risk_score >= 10:
            return "Critical"
        elif risk_score >= 7:
            return "High"
        elif risk_score >= 4:
            return "Medium"
        elif risk_score >= 1:
            return "Low"
        return "Info"
    
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
    def analyze_scan_results(results: Dict) -> str:
        """Generate detailed AI analysis of scan results"""
        analysis = []
        
        # Analyze open ports and services
        open_ports = results.get('open_ports', [])
        services = results.get('services', {})
        
        if not open_ports:
            analysis.append("🔒 No open ports were detected. The target may be protected by a firewall or offline.")
        else:
            analysis.append(f"🔍 Found {len(open_ports)} open ports.")
            
            # Analyze critical services
            critical_services = []
            for port in open_ports:
                service = services.get(str(port), {})
                service_name = service.get('name', '').lower()
                
                if service_name in ['ftp', 'telnet', 'rsh']:
                    critical_services.append(f"{service_name.upper()} on port {port}")
                elif service_name == 'ssh' and port != 22:
                    critical_services.append(f"SSH on non-standard port {port}")
            
            if critical_services:
                analysis.append("\n⚠️ Critical Services Detected:")
                analysis.extend([f"  - {service}" for service in critical_services])
        
        # Analyze web services
        web_services = []
        for port, service in services.items():
            if service.get('name', '').lower() in ['http', 'https']:
                server = service.get('product', 'Unknown')
                version = service.get('version', 'Unknown')
                web_services.append(f"{server} {version} on port {port}")
        
        if web_services:
            analysis.append("\n🌐 Web Services:")
            analysis.extend([f"  - {service}" for service in web_services])
            
            # Web service recommendations
            analysis.append("\nRecommended Web Tests:")
            analysis.append("  - Run directory enumeration (gobuster, dirsearch)")
            analysis.append("  - Check for common web vulnerabilities (SQLi, XSS)")
            analysis.append("  - Verify SSL/TLS configuration if HTTPS is used")
        
        # Analyze vulnerabilities
        vulns = results.get('vulnerabilities', [])
        if vulns:
            analysis.append(f"\n🚨 Found {len(vulns)} potential vulnerabilities:")
            for vuln in vulns:
                analysis.append(f"  - {vuln}")
        
        # OS detection analysis
        os_info = results.get('os_info', [])
        if os_info:
            analysis.append("\n💻 Operating System Detection:")
            analysis.extend([f"  - {os}" for os in os_info])
        
        # Generate recommendations
        analysis.append("\n📋 Recommendations:")
        recommendations = SecurityAnalyzer._generate_recommendations(results)
        analysis.extend([f"  - {rec}" for rec in recommendations])
        
        return "\n".join(analysis)
    
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

class AIRecommendationEngine:
    def __init__(self, db_path: str = 'data/vulnerabilities.db'):
        self.db_path = Path(db_path)
        self._init_db()
    
    def _init_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                cve_id TEXT,
                description TEXT,
                severity TEXT,
                recommendation TEXT,
                context TEXT,
                timestamp TEXT
            )
        ''')
        conn.commit()
        conn.close()
    
    def analyze_scan_results(self, scan_data: Dict) -> List[Dict]:
        """Analyze scan results and provide AI-powered recommendations"""
        recommendations = []
        
        # Service-based recommendations
        for port, service in scan_data.get('services', {}).items():
            service_name = service.get('name', '').lower()
            product = service.get('product', '').lower()
            version = service.get('version', '')
            
            # Web application tests
            if service_name in ['http', 'https']:
                recommendations.extend([
                    {
                        'type': 'web_scan',
                        'tool': 'nikto',
                        'command': f'nikto -h {scan_data["target"]} -p {port}',
                        'reason': f'Web service ({product} {version}) detected on port {port}'
                    },
                    {
                        'type': 'directory_scan',
                        'tool': 'gobuster',
                        'command': f'gobuster dir -u http://{scan_data["target"]}:{port} -w /usr/share/wordlists/dirb/common.txt',
                        'reason': 'Enumerate web directories'
                    }
                ])
            
            # SSH testing
            elif service_name == 'ssh':
                recommendations.append({
                        'type': 'brute_force',
                        'tool': 'metasploit',
                        'module': 'auxiliary/scanner/ssh/ssh_login',
                    'options': {
                        'RHOSTS': scan_data["target"],
                        'RPORT': port
                    },
                    'reason': f'SSH service ({product} {version}) detected'
                })
            
            # Database services
            elif service_name in ['mysql', 'postgresql', 'mssql']:
                recommendations.append({
                    'type': 'database_scan',
                    'tool': 'metasploit',
                    'module': f'auxiliary/scanner/{service_name}/{service_name}_login',
                    'options': {
                        'RHOSTS': scan_data["target"],
                        'RPORT': port
                    },
                    'reason': f'Database service {service_name.upper()} detected'
                })
        
        return recommendations
    
    def store_vulnerability(self, vulnerability: Dict):
        """Store vulnerability in database with AI-generated hash ID"""
        vuln_hash = hashlib.sha256(
            f"{vulnerability['cve_id']}{vulnerability['description']}".encode()
        ).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO vulnerabilities 
            (id, cve_id, description, severity, recommendation, context, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            vuln_hash,
            vulnerability.get('cve_id'),
            vulnerability.get('description'),
            vulnerability.get('severity'),
            vulnerability.get('recommendation'),
            json.dumps(vulnerability.get('context', {})),
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()

if __name__ == "__main__":
    engine = AIRecommendationEngine()
    sample_scan = {
        "target": "192.168.1.1",
        "open_ports": [22, 80, 443],
        "services": {
            "22": {"name": "ssh", "product": "OpenSSH", "version": "7.9"},
            "80": {"name": "http", "product": "Apache", "version": "2.4.49"}
        }
    }
    print(engine.analyze_scan_results(sample_scan))
