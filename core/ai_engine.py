import json
import requests
from typing import Dict, List, Optional
from datetime import datetime
import hashlib
from pathlib import Path
import sqlite3
import re
import math

class ExploitationPath:
    def __init__(self, name: str, difficulty: str, success_rate: float, steps: List[str], tools: List[str]):
        self.name = name
        self.difficulty = difficulty
        self.success_rate = success_rate
        self.steps = steps
        self.tools = tools

class SecurityRisk:
    def __init__(self, name: str, severity: str, cvss: float, description: str, mitigation: List[str]):
        self.name = name
        self.severity = severity
        self.cvss = cvss
        self.description = description
        self.mitigation = mitigation

class VulnerabilityDatabase:
    def __init__(self, db_path: str = 'data/vuln_db.sqlite'):
        self.db_path = Path(db_path)
        self._init_db()
        
    def _init_db(self):
        """Initialize the vulnerability database"""
        parent = self.db_path.parent
        if str(parent) and str(parent) != '.' and not parent.exists():
            parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Only create tables if they don't exist
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                cve_id TEXT,
                description TEXT,
                severity TEXT,
                cvss_score REAL,
                affected_software TEXT,
                recommendation TEXT,
                ref_links TEXT,
                last_updated TEXT,
                exploit_available BOOLEAN,
                exploit_complexity TEXT,
                exploit_reliability REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id TEXT PRIMARY KEY,
                target TEXT,
                timestamp TEXT,
                findings TEXT,
                risk_score REAL,
                exploitation_paths TEXT,
                security_posture TEXT,
                attack_surface TEXT,
                statistics TEXT,
                recommendations TEXT
            )
        ''')
        
        # Create indices for faster lookups
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_software ON vulnerabilities(affected_software)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_target ON scan_history(target)')
        
        conn.commit()
        conn.close()

class AIEngine:
    def __init__(self):
        self.vuln_db = VulnerabilityDatabase()
        self.cached_threat_data = {}
        self.cached_exploits = {}
        
        # Common attack vectors and their patterns
        self.attack_vectors = {
            'web': {
                'ports': [80, 443, 8080, 8443],
                'services': ['http', 'https', 'apache', 'nginx'],
                'vulns': ['sql_injection', 'xss', 'rce', 'file_inclusion']
            },
            'database': {
                'ports': [3306, 5432, 1433, 1521],
                'services': ['mysql', 'postgresql', 'mssql', 'oracle'],
                'vulns': ['weak_credentials', 'buffer_overflow', 'privilege_escalation']
            },
            'remote_access': {
                'ports': [22, 23, 3389],
                'services': ['ssh', 'telnet', 'rdp'],
                'vulns': ['brute_force', 'default_credentials', 'protocol_vulnerabilities']
            }
        }
        
        self.vulnerability_patterns = {
            'sql_injection': ['sql', 'injection', 'database'],
            'xss': ['cross-site', 'script', 'xss'],
            'rce': ['remote', 'execution', 'rce', 'command'],
            'file_inclusion': ['include', 'lfi', 'rfi', 'path'],
            'authentication': ['auth', 'login', 'credential'],
            'information_disclosure': ['information', 'disclosure', 'leak'],
            'configuration': ['config', 'setup', 'default'],
            'ssl': ['ssl', 'tls', 'certificate']
        }
        
    def analyze_service(self, service_info: Dict) -> Dict:
        """Enhanced service analysis with exploitation paths"""
        findings = {
            'vulnerabilities': [],
            'exploitation_paths': [],
            'security_recommendations': [],
            'risk_metrics': {
                'exposure_level': 0.0,
                'attack_surface': 0.0,
                'exploit_likelihood': 0.0
            }
        }
        
        service_name = service_info.get('name', '').lower()
        version = service_info.get('version', '')
        port = service_info.get('port')
        
        # Check vulnerabilities and generate exploitation paths
        if version:
            vulns = self._check_version_vulnerabilities(service_name, version)
            findings['vulnerabilities'].extend(vulns)
            
            # Generate exploitation paths for found vulnerabilities
            for vuln in vulns:
                exploit_path = self._generate_exploitation_path(service_name, version, vuln)
                if exploit_path:
                    findings['exploitation_paths'].append(exploit_path)
        
        # Enhanced misconfiguration checks
        misconfigs = self._check_misconfigurations(service_name, port)
        findings['vulnerabilities'].extend(misconfigs)
        
        # Real-time threat intelligence
        threats = self._check_threat_intelligence(service_name, version)
        findings['vulnerabilities'].extend(threats)
        
        # Calculate risk metrics
        findings['risk_metrics'] = self._calculate_risk_metrics(
            findings['vulnerabilities'],
            service_name,
            port
        )
        
        # Generate detailed security recommendations
        findings['security_recommendations'] = self._generate_security_recommendations(
            service_name,
            findings['vulnerabilities'],
            findings['risk_metrics']
        )
        
        return findings
    
    def _generate_exploitation_path(self, service: str, version: str, vulnerability: Dict) -> Optional[ExploitationPath]:
        """Generate detailed exploitation path for a vulnerability"""
        if service in self.attack_vectors:
            vector = self.attack_vectors[service]
            
            # Check if Metasploit module exists
            msf_module = self._find_metasploit_module(service, version, vulnerability)
            
            if msf_module:
                return ExploitationPath(
                    name=f"Metasploit: {msf_module['name']}",
                    difficulty="Medium" if msf_module['rank'] >= 'good' else "High",
                    success_rate=self._calculate_success_rate(msf_module['rank']),
                    steps=[
                        f"1. Start Metasploit Framework",
                        f"2. use {msf_module['path']}",
                        f"3. set RHOSTS <target>",
                        f"4. set payload {msf_module['default_payload']}",
                        f"5. exploit"
                    ],
                    tools=["Metasploit Framework"]
                )
            
            # Manual exploitation path
            return ExploitationPath(
                name=f"Manual Exploitation: {vulnerability['description']}",
                difficulty="High",
                success_rate=0.6,
                steps=[
                    "1. Verify vulnerability existence",
                    "2. Set up local testing environment",
                    "3. Develop custom exploit",
                    "4. Test exploit in controlled environment",
                    "5. Execute with caution"
                ],
                tools=["Custom scripts", "Debug tools", "Network analyzers"]
            )
        
        return None
    
    def _calculate_risk_metrics(self, vulnerabilities: List[Dict], service: str, port: int) -> Dict:
        """Calculate detailed risk metrics"""
        exposure = 0.0
        attack_surface = 0.0
        exploit_likelihood = 0.0
        
        # Calculate exposure based on port and service
        if port < 1024:
            exposure += 0.3  # Common ports increase exposure
        if service in ['http', 'https', 'ftp', 'ssh']:
            exposure += 0.2  # Common services increase exposure
            
        # Calculate attack surface
        attack_surface = len(vulnerabilities) * 0.1
        if service in self.attack_vectors:
            attack_surface += 0.3  # Known attack vectors increase attack surface
            
        # Calculate exploit likelihood
        for vuln in vulnerabilities:
            if vuln.get('exploit_available', False):
                exploit_likelihood += 0.4
            if vuln.get('severity') == 'Critical':
                exploit_likelihood += 0.3
            elif vuln.get('severity') == 'High':
                exploit_likelihood += 0.2
                
        return {
            'exposure_level': min(1.0, exposure),
            'attack_surface': min(1.0, attack_surface),
            'exploit_likelihood': min(1.0, exploit_likelihood)
        }
    
    def _generate_security_recommendations(self, service: str, vulnerabilities: List[Dict], risk_metrics: Dict) -> List[Dict]:
        """Generate detailed security recommendations"""
        recommendations = []
        
        # Immediate actions for critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical']
        if critical_vulns:
            recommendations.append({
                'priority': 'Immediate',
                'title': 'Critical Vulnerability Mitigation',
                'steps': [
                    f"Patch {v['description']}" for v in critical_vulns
                ],
                'timeline': '24-48 hours'
            })
        
        # Service-specific hardening
        if service in ['http', 'https']:
            recommendations.append({
                'priority': 'High',
                'title': 'Web Service Hardening',
                'steps': [
                    'Implement WAF',
                    'Enable HTTPS with strong ciphers',
                    'Set secure headers',
                    'Remove unnecessary HTTP methods'
                ],
                'timeline': '1 week'
            })
        
        # Risk-based recommendations
        if risk_metrics['exposure_level'] > 0.7:
            recommendations.append({
                'priority': 'High',
                'title': 'Exposure Reduction',
                'steps': [
                    'Implement network segmentation',
                    'Set up reverse proxy',
                    'Configure strict firewall rules'
                ],
                'timeline': '1-2 weeks'
            })
        
        return recommendations
    
    def analyze_scan_results(self, scan_data: Dict) -> Dict:
        """Analyze scan results with optimized processing and transparent scoring"""
        if not scan_data or not scan_data.get('services'):
            return {}
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'target': scan_data.get('target', 'unknown'),
            'scan_type': scan_data.get('scan_type', 'unknown'),
            'findings': [],
            'risk_metrics': {
                'overall_risk': 0.0,
                'attack_surface': 0.0,
                'critical_findings': 0,
                'score_breakdown': {}
            },
            'recommendations': [],
            'explanation': ''
        }
        # Process all services at once
        services = scan_data['services']
        for port, service in services.items():
            finding = {
                'service': service.get('name', '').lower(),
                'port': port,
                'version': service.get('version', ''),
                'risk_level': 'Low',
                'attack_vectors': [],
                'immediate_actions': []
            }
            # Quick service analysis
            if finding['service'] in self.attack_vectors:
                vector = self.attack_vectors[finding['service']]
                if int(port) in vector['ports']:
                    finding['risk_level'] = 'Medium'
                    finding['attack_vectors'] = self._get_quick_attack_vectors(finding['service'], port)
                    finding['immediate_actions'] = self._get_quick_actions(finding['service'])
            analysis['findings'].append(finding)
        # Calculate overall metrics with breakdown
        critical_services = ['mysql', 'mssql', 'postgresql', 'mongodb']
        exposed_web = any(f['service'] in ['http', 'https'] for f in analysis['findings'])
        exposed_db = any(f['service'] in critical_services for f in analysis['findings'])
        score_breakdown = {}
        if exposed_db:
            analysis['risk_metrics']['overall_risk'] = 0.8
            analysis['risk_metrics']['critical_findings'] += 1
            score_breakdown['Database Exposure'] = 0.8
        elif exposed_web:
            analysis['risk_metrics']['overall_risk'] = 0.6
            score_breakdown['Web Exposure'] = 0.6
        else:
            score_breakdown['No Critical Exposure'] = 0.2
        analysis['risk_metrics']['attack_surface'] = len(analysis['findings']) * 0.1
        score_breakdown['Attack Surface'] = analysis['risk_metrics']['attack_surface']
        analysis['risk_metrics']['score_breakdown'] = score_breakdown
        # Add actionable recommendations
        recs = []
        if exposed_db:
            recs.append("🔴 Secure exposed database services (MySQL, MSSQL, PostgreSQL, MongoDB)")
        if exposed_web:
            recs.append("🟡 Harden web services (HTTP/HTTPS): patch, use WAF, secure headers")
        if not recs:
            recs.append("🟢 No critical exposures detected. Maintain regular patching and monitoring.")
        analysis['recommendations'] = recs
        # Add transparent explanation
        explanation = "Risk score is based on detected services. "
        for k, v in score_breakdown.items():
            explanation += f"{k}: {v}. "
        analysis['explanation'] = explanation
        return analysis
        
    def _get_quick_attack_vectors(self, service: str, port: int) -> List[Dict]:
        """Return pre-defined attack vectors for quick analysis"""
        vectors = []
        
        if service in ['http', 'https']:
            vectors.append({
                'name': 'Web Scan',
                'tools': ['gobuster', 'nikto'],
                'commands': [f'gobuster dir -u http://TARGET:{port}/ -w common.txt']
            })
        elif service == 'ssh':
            vectors.append({
                'name': 'SSH Test',
                'tools': ['hydra'],
                'commands': [f'hydra -L users.txt -P passes.txt TARGET ssh -s {port}']
            })
        elif service in ['mysql', 'postgresql', 'mssql']:
            vectors.append({
                'name': 'DB Test',
                'tools': ['nmap'],
                'commands': [f'nmap -p{port} -sV --script={service}-brute TARGET']
            })
            
        return vectors
        
    def _get_quick_actions(self, service: str) -> List[str]:
        """Return immediate actions for quick analysis"""
        actions = []
        
        if service in ['http', 'https']:
            actions = ['Check default creds', 'Verify SSL', 'Check sensitive files']
        elif service == 'ssh':
            actions = ['Verify auth config', 'Check root login', 'Review users']
        elif service in ['mysql', 'postgresql', 'mssql']:
            actions = ['Check anon access', 'Verify binding', 'Review privileges']
            
        return actions
    
    def _store_analysis(self, analysis: Dict):
        """Store analysis results in database"""
        analysis_id = hashlib.sha256(
            f"{analysis['target']}{analysis['timestamp']}".encode()
        ).hexdigest()
        
        conn = sqlite3.connect(self.vuln_db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO scan_history 
            (id, target, timestamp, findings, risk_score, exploitation_paths, security_posture)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            analysis_id,
            analysis['target'],
            analysis['timestamp'],
            json.dumps(analysis['findings']),
            analysis['risk_metrics']['overall_risk'],
            json.dumps(analysis['exploitation_paths']),
            json.dumps(analysis['security_posture'])
        ))
        
        conn.commit()
        conn.close()
    
    def get_historical_analysis(self, target: str) -> List[Dict]:
        """Get historical analysis for a target"""
        conn = sqlite3.connect(self.vuln_db.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scan_history 
            WHERE target = ? 
            ORDER BY timestamp DESC
        ''', (target,))
        
        history = []
        for row in cursor.fetchall():
            history.append({
                'id': row[0],
                'target': row[1],
                'timestamp': row[2],
                'findings': json.loads(row[3]),
                'risk_score': row[4],
                'exploitation_paths': json.loads(row[5]),
                'security_posture': json.loads(row[6])
            })
        
        conn.close()
        return history

    def analyze_vulnerability(self, description):
        """Analyze vulnerability description and return categorized results"""
        description = description.lower()
        
        # Determine category
        category = 'general'
        for cat, patterns in self.vulnerability_patterns.items():
            if any(pattern in description for pattern in patterns):
                category = cat
                break
        
        # Determine severity
        severity = self._assess_severity(description)
        
        # Generate analysis
        return {
            'category': category,
            'severity': severity,
            'type': self._get_vulnerability_type(category),
            'impact': self._assess_impact(severity),
            'complexity': self._assess_complexity(description)
        }
        
    def _assess_severity(self, description):
        """Assess vulnerability severity based on description"""
        description = description.lower()
        
        # Critical patterns
        if any(x in description for x in [
            'remote code execution',
            'sql injection',
            'authentication bypass',
            'arbitrary file upload'
        ]):
            return 'Critical'
            
        # High severity patterns
        elif any(x in description for x in [
            'cross-site scripting',
            'information disclosure',
            'directory traversal',
            'weak encryption'
        ]):
            return 'High'
            
        # Medium severity patterns
        elif any(x in description for x in [
            'misconfiguration',
            'information leakage',
            'deprecated',
            'outdated'
        ]):
            return 'Medium'
            
        return 'Low'
        
    def _get_vulnerability_type(self, category):
        """Map category to vulnerability type"""
        type_mapping = {
            'sql_injection': 'injection',
            'xss': 'client_side',
            'rce': 'code_execution',
            'file_inclusion': 'file_system',
            'authentication': 'authentication',
            'information_disclosure': 'information',
            'configuration': 'configuration',
            'ssl': 'cryptographic'
        }
        return type_mapping.get(category, 'general')
        
    def _assess_impact(self, severity):
        """Assess potential impact based on severity"""
        impact_levels = {
            'Critical': 0.9,
            'High': 0.7,
            'Medium': 0.5,
            'Low': 0.3
        }
        return impact_levels.get(severity, 0.1)
        
    def _assess_complexity(self, description):
        """Assess exploitation complexity"""
        description = description.lower()
        
        # High complexity indicators
        if any(x in description for x in [
            'complex',
            'chained',
            'multiple steps',
            'specific condition'
        ]):
            return 0.8
            
        # Medium complexity indicators
        elif any(x in description for x in [
            'requires',
            'specific',
            'under certain'
        ]):
            return 0.5
            
        return 0.3  # Default to low complexity 