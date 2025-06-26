import json
import re
from datetime import datetime
from typing import Dict, List, Tuple

class AIAnalyzer:
    def __init__(self):
        self.vulnerability_patterns = {
            'open_ports': {
                'pattern': r'(\d+)/tcp\s+open',
                'risk_level': 'medium',
                'description': 'Open ports detected. These could be potential entry points.'
            },
            'default_credentials': {
                'pattern': r'(admin|root|password|123456)',
                'risk_level': 'high',
                'description': 'Default or weak credentials detected.'
            },
            'sql_injection': {
                'pattern': r'(SQL|mysql|postgresql)\s+injection',
                'risk_level': 'critical',
                'description': 'SQL injection vulnerability detected.'
            },
            'xss': {
                'pattern': r'(XSS|cross-site\s+scripting)',
                'risk_level': 'high',
                'description': 'Cross-site scripting vulnerability detected.'
            }
        }
        
        self.risk_levels = {
            'low': 25,
            'medium': 50,
            'high': 75,
            'critical': 100
        }
        
        # Common security misconfigurations
        self.security_checks = [
            ('telnet', 23, 'Telnet service detected - Insecure protocol'),
            ('ftp', 21, 'FTP service detected - Consider using SFTP'),
            ('smtp', 25, 'SMTP service exposed - Verify if necessary'),
            ('dns', 53, 'DNS service exposed - Check for zone transfer vulnerabilities'),
            ('http', 80, 'HTTP service without TLS - Consider enabling HTTPS'),
            ('rpc', 111, 'RPC service exposed - Potential security risk'),
            ('netbios', 139, 'NetBIOS service exposed - Windows file sharing risk'),
            ('smb', 445, 'SMB service exposed - Check for EternalBlue vulnerability')
        ]

    def analyze_service(self, service_name, version, port):
        findings = []
        
        # Check for known vulnerable versions
        for category, services in self.vulnerability_patterns.items():
            for service, data in services.items():
                if service.lower() in service_name.lower():
                    if 'versions' in data:
                        for vuln_version in data['versions']:
                            if version and vuln_version in version:
                                findings.append({
                                    'severity': 'HIGH',
                                    'message': data['message'],
                                    'details': f'Version {version} is known to be vulnerable'
                                })
                    
                    if 'ports' in data and port in data['ports']:
                        findings.append({
                            'severity': 'MEDIUM',
                            'message': data['message'],
                            'details': f'Service exposed on port {port}'
                        })
        
        # Check for security misconfigurations
        for check_service, check_port, message in self.security_checks:
            if check_service in service_name.lower() and port == check_port:
                findings.append({
                    'severity': 'WARNING',
                    'message': message,
                    'details': f'Service {service_name} on port {port}'
                })
        
        # Web application specific checks
        if 'http' in service_name.lower():
            findings.extend(self._analyze_web_service(port, version))
        
        return findings
    
    def _analyze_web_service(self, port, version):
        findings = []
        
        # Check for non-standard HTTP ports
        if port not in [80, 443, 8080, 8443]:
            findings.append({
                'severity': 'INFO',
                'message': 'Web service on non-standard port',
                'details': f'Web service running on port {port}'
            })
        
        # Check for SSL/TLS
        if port == 80:
            findings.append({
                'severity': 'MEDIUM',
                'message': 'Web service without SSL/TLS',
                'details': 'Consider enabling HTTPS for secure communication'
            })
        
        return findings
    
    def analyze_scan_results(self, scan_data):
        """Analyze scan results and return AI insights"""
        findings = []
        total_risk_score = 0
        num_findings = 0
        
        # Analyze each vulnerability pattern
        for vuln_type, pattern in self.vulnerability_patterns.items():
            if pattern['pattern'] in str(scan_data):
                findings.append({
                    'type': vuln_type,
                    'risk_level': pattern['risk_level'],
                    'description': pattern['description']
                })
                total_risk_score += self.risk_levels[pattern['risk_level']]
                num_findings += 1
        
        # Calculate average risk score
        risk_score = total_risk_score / len(self.risk_levels) if num_findings > 0 else 0
        
        # Generate analysis report
        report = "🔍 AI Analysis Report\n\n"
        
        if findings:
            report += "🚨 Vulnerabilities Detected:\n\n"
        for finding in findings:
                report += f"• {finding['type'].replace('_', ' ').title()}\n"
                report += f"  Risk Level: {finding['risk_level'].upper()}\n"
                report += f"  {finding['description']}\n\n"
        else:
            report += "✅ No immediate vulnerabilities detected.\n\n"
        
        report += "\n🤖 AI Recommendations:\n"
        if findings:
            report += "1. Address identified vulnerabilities immediately\n"
            report += "2. Implement security patches and updates\n"
            report += "3. Review access controls and authentication mechanisms\n"
        else:
            report += "1. Continue regular security monitoring\n"
            report += "2. Keep systems and software up to date\n"
            report += "3. Maintain security best practices\n"
        
        return {
            'report': report,
            'risk_score': risk_score,
            'findings': findings
        }
    
    def get_mitigation_steps(self, vulnerability_type):
        """Get specific mitigation steps for a vulnerability type"""
        mitigations = {
            'open_ports': [
                "Review and close unnecessary ports",
                "Implement firewall rules",
                "Use port knocking for sensitive services"
            ],
            'default_credentials': [
                "Change all default passwords",
                "Implement strong password policy",
                "Use multi-factor authentication"
            ],
            'sql_injection': [
                "Use prepared statements",
                "Implement input validation",
                "Update database access layer"
            ],
            'xss': [
                "Implement content security policy",
                "Sanitize user input",
                "Use modern framework XSS protection"
            ]
        }
        return mitigations.get(vulnerability_type, ["No specific mitigation steps available"])