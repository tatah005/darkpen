#!/usr/bin/env python3
"""
Enhanced AI Engine for DarkPen - Advanced Machine Learning Integration
"""

import json
import sqlite3
import hashlib
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import requests
import re
from pathlib import Path

# For advanced AI features
try:
    import tensorflow as tf
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

@dataclass
class VulnerabilityPrediction:
    """AI prediction for vulnerability likelihood"""
    service: str
    version: str
    cve_likelihood: float
    exploit_available: bool
    risk_score: float
    confidence: float
    recommended_actions: List[str]

@dataclass
class AttackPath:
    """AI-generated attack path"""
    path_id: str
    target: str
    steps: List[Dict]
    success_probability: float
    complexity: str
    time_estimate: str
    tools_needed: List[str]
    risk_level: str

class EnhancedAIEngine:
    """Advanced AI engine with machine learning capabilities"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.db_path = Path("data/enhanced_ai.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize ML models
        self.vulnerability_classifier = None
        self.risk_predictor = None
        self.text_vectorizer = None
        
        # Load or train models
        self._initialize_models()
        
        # Initialize database
        self._init_database()
        
        # Load threat intelligence
        self.threat_intel = self._load_threat_intelligence()
        
    def _initialize_models(self):
        """Initialize machine learning models"""
        if not TENSORFLOW_AVAILABLE:
            print("⚠️ TensorFlow not available - using rule-based analysis")
            return
            
        try:
            # Load pre-trained models or train new ones
            self.vulnerability_classifier = self._load_or_train_vulnerability_model()
            self.risk_predictor = self._load_or_train_risk_model()
            self.text_vectorizer = TfidfVectorizer(max_features=1000)
            
            print("✅ ML models initialized successfully")
        except Exception as e:
            print(f"⚠️ ML model initialization failed: {e}")
    
    def _load_or_train_vulnerability_model(self):
        """Load or train vulnerability prediction model"""
        model_path = Path("models/vulnerability_classifier.h5")
        
        if model_path.exists():
            return tf.keras.models.load_model(str(model_path))
        else:
            # Train a simple neural network for vulnerability prediction
            model = tf.keras.Sequential([
                tf.keras.layers.Dense(64, activation='relu', input_shape=(50,)),
                tf.keras.layers.Dropout(0.2),
                tf.keras.layers.Dense(32, activation='relu'),
                tf.keras.layers.Dropout(0.2),
                tf.keras.layers.Dense(1, activation='sigmoid')
            ])
            
            model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
            
            # Save model for future use
            model_path.parent.mkdir(exist_ok=True)
            model.save(str(model_path))
            
            return model
    
    def _load_or_train_risk_model(self):
        """Load or train risk assessment model"""
        return RandomForestClassifier(n_estimators=100, random_state=42)
    
    def _init_database(self):
        """Initialize enhanced AI database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables for AI data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_predictions (
                id TEXT PRIMARY KEY,
                target TEXT,
                service TEXT,
                version TEXT,
                prediction_type TEXT,
                prediction_data TEXT,
                confidence REAL,
                timestamp TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_paths (
                id TEXT PRIMARY KEY,
                target TEXT,
                path_data TEXT,
                success_rate REAL,
                complexity TEXT,
                tools_used TEXT,
                timestamp TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id TEXT PRIMARY KEY,
                threat_type TEXT,
                indicators TEXT,
                severity TEXT,
                description TEXT,
                timestamp TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_threat_intelligence(self) -> Dict:
        """Load threat intelligence from multiple sources"""
        threats = {
            'recent_cves': [],
            'active_exploits': [],
            'threat_actors': [],
            'attack_patterns': []
        }
        
        try:
            # Load from local database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM threat_intelligence ORDER BY timestamp DESC LIMIT 100')
            for row in cursor.fetchall():
                threat_data = json.loads(row[2])  # indicators
                threats[row[1]].append(threat_data)
            
            conn.close()
            
        except Exception as e:
            print(f"⚠️ Failed to load threat intelligence: {e}")
        
        return threats
    
    def analyze_target_intelligence(self, target: str, scan_results: Dict) -> Dict:
        """Advanced target intelligence analysis"""
        analysis = {
            'target_profile': self._build_target_profile(target, scan_results),
            'vulnerability_predictions': [],
            'attack_paths': [],
            'risk_assessment': {},
            'ai_recommendations': [],
            'threat_context': {}
        }
        
        # Analyze each service with ML
        for port, service in scan_results.get('services', {}).items():
            prediction = self._predict_vulnerabilities(service, port)
            analysis['vulnerability_predictions'].append(prediction)
            
            # Generate attack paths
            attack_path = self._generate_attack_path(target, service, port)
            if attack_path:
                analysis['attack_paths'].append(attack_path)
        
        # Advanced risk assessment
        analysis['risk_assessment'] = self._assess_advanced_risks(scan_results)
        
        # AI-powered recommendations
        analysis['ai_recommendations'] = self._generate_ai_recommendations(analysis)
        
        # Threat context analysis
        analysis['threat_context'] = self._analyze_threat_context(target, scan_results)
        
        return analysis
    
    def _build_target_profile(self, target: str, scan_results: Dict) -> Dict:
        """Build comprehensive target profile"""
        profile = {
            'target': target,
            'exposed_services': len(scan_results.get('services', {})),
            'service_types': {},
            'version_distribution': {},
            'security_posture': 'unknown',
            'attack_surface': 0.0
        }
        
        services = scan_results.get('services', {})
        
        # Analyze service types
        for port, service in services.items():
            service_name = service.get('name', '').lower()
            version = service.get('version', '')
            
            if service_name not in profile['service_types']:
                profile['service_types'][service_name] = 0
            profile['service_types'][service_name] += 1
            
            if version and version not in profile['version_distribution']:
                profile['version_distribution'][version] = 0
            profile['version_distribution'][version] += 1
        
        # Calculate attack surface
        critical_services = ['ssh', 'ftp', 'telnet', 'mysql', 'postgresql', 'mssql']
        web_services = ['http', 'https']
        
        attack_surface = 0.0
        for service_name in profile['service_types']:
            if service_name in critical_services:
                attack_surface += 0.3
            elif service_name in web_services:
                attack_surface += 0.2
            else:
                attack_surface += 0.1
        
        profile['attack_surface'] = min(attack_surface, 1.0)
        
        # Assess security posture
        if profile['attack_surface'] > 0.7:
            profile['security_posture'] = 'poor'
        elif profile['attack_surface'] > 0.4:
            profile['security_posture'] = 'moderate'
        else:
            profile['security_posture'] = 'good'
        
        return profile
    
    def _predict_vulnerabilities(self, service: Dict, port: str) -> VulnerabilityPrediction:
        """Use ML to predict vulnerabilities"""
        service_name = service.get('name', '').lower()
        version = service.get('version', '')
        
        # Feature extraction
        features = self._extract_service_features(service_name, version, port)
        
        # ML prediction if available
        if self.vulnerability_classifier and TENSORFLOW_AVAILABLE:
            try:
                # Convert features to model input
                feature_vector = self._vectorize_features(features)
                cve_likelihood = float(self.vulnerability_classifier.predict(feature_vector)[0][0])
            except:
                cve_likelihood = self._rule_based_cve_prediction(service_name, version)
        else:
            cve_likelihood = self._rule_based_cve_prediction(service_name, version)
        
        # Check for available exploits
        exploit_available = self._check_exploit_availability(service_name, version)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(service_name, version, port, cve_likelihood)
        
        # Generate recommendations
        recommendations = self._generate_service_recommendations(service_name, version, risk_score)
        
        return VulnerabilityPrediction(
            service=service_name,
            version=version,
            cve_likelihood=cve_likelihood,
            exploit_available=exploit_available,
            risk_score=risk_score,
            confidence=0.85,  # ML confidence
            recommended_actions=recommendations
        )
    
    def _extract_service_features(self, service_name: str, version: str, port: str) -> Dict:
        """Extract features for ML model"""
        features = {
            'service_name': service_name,
            'version': version,
            'port': int(port),
            'is_web_service': service_name in ['http', 'https'],
            'is_database': service_name in ['mysql', 'postgresql', 'mssql', 'mongodb'],
            'is_remote_access': service_name in ['ssh', 'telnet', 'rsh'],
            'is_file_service': service_name in ['ftp', 'smb', 'nfs'],
            'port_risk': self._assess_port_risk(int(port)),
            'version_age': self._calculate_version_age(version),
            'has_known_vulns': self._check_known_vulnerabilities(service_name, version)
        }
        return features
    
    def _vectorize_features(self, features: Dict) -> np.ndarray:
        """Convert features to ML model input"""
        # Simple feature vector (in practice, you'd use proper encoding)
        vector = [
            features['port_risk'],
            features['version_age'],
            features['has_known_vulns'],
            features['is_web_service'],
            features['is_database'],
            features['is_remote_access'],
            features['is_file_service']
        ]
        
        # Pad to 50 features (model input size)
        while len(vector) < 50:
            vector.append(0.0)
        
        return np.array([vector])
    
    def _rule_based_cve_prediction(self, service_name: str, version: str) -> float:
        """Rule-based CVE prediction when ML is not available"""
        base_likelihood = 0.1
        
        # Service-specific adjustments
        if service_name in ['http', 'https']:
            base_likelihood += 0.2
        elif service_name in ['ssh', 'ftp']:
            base_likelihood += 0.15
        elif service_name in ['mysql', 'postgresql']:
            base_likelihood += 0.25
        
        # Version-specific adjustments
        if version:
            if 'old' in version.lower() or 'deprecated' in version.lower():
                base_likelihood += 0.3
            elif any(year in version for year in ['2015', '2016', '2017']):
                base_likelihood += 0.2
        
        return min(base_likelihood, 1.0)
    
    def _check_exploit_availability(self, service_name: str, version: str) -> bool:
        """Check if exploits are available for this service/version"""
        # This would integrate with exploit databases
        exploit_patterns = {
            'http': ['apache', 'nginx', 'iis'],
            'ssh': ['openssh', 'dropbear'],
            'ftp': ['vsftpd', 'proftpd'],
            'mysql': ['mysql'],
            'postgresql': ['postgresql']
        }
        
        for service, patterns in exploit_patterns.items():
            if service_name == service:
                for pattern in patterns:
                    if pattern in version.lower():
                        return True
        
        return False
    
    def _calculate_risk_score(self, service_name: str, version: str, port: str, cve_likelihood: float) -> float:
        """Calculate comprehensive risk score"""
        risk_score = cve_likelihood
        
        # Port risk
        port_risk = self._assess_port_risk(int(port))
        risk_score += port_risk * 0.2
        
        # Service risk
        service_risk = self._assess_service_risk(service_name)
        risk_score += service_risk * 0.3
        
        # Version risk
        version_risk = self._assess_version_risk(version)
        risk_score += version_risk * 0.2
        
        return min(risk_score, 1.0)
    
    def _assess_port_risk(self, port: int) -> float:
        """Assess risk based on port number"""
        high_risk_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        medium_risk_ports = [135, 139, 445, 1433, 1521, 3306, 5432, 6379, 8080, 8443]
        
        if port in high_risk_ports:
            return 0.8
        elif port in medium_risk_ports:
            return 0.5
        else:
            return 0.2
    
    def _assess_service_risk(self, service_name: str) -> float:
        """Assess risk based on service type"""
        high_risk = ['telnet', 'ftp', 'rsh', 'rlogin']
        medium_risk = ['ssh', 'http', 'https', 'mysql', 'postgresql']
        
        if service_name in high_risk:
            return 0.9
        elif service_name in medium_risk:
            return 0.6
        else:
            return 0.3
    
    def _assess_version_risk(self, version: str) -> float:
        """Assess risk based on version age and known issues"""
        if not version:
            return 0.5
        
        # Check for known vulnerable versions
        vulnerable_versions = [
            '2.4.49', '2.4.50',  # Apache
            '1.13', '1.14',      # Nginx
            '7.2', '7.3',        # OpenSSH
            '2.3.4'              # vsftpd
        ]
        
        for vuln_ver in vulnerable_versions:
            if vuln_ver in version:
                return 0.9
        
        return 0.3
    
    def _generate_service_recommendations(self, service_name: str, version: str, risk_score: float) -> List[str]:
        """Generate AI-powered recommendations for service"""
        recommendations = []
        
        if risk_score > 0.7:
            recommendations.append("🔴 HIGH RISK: Immediate action required")
            recommendations.append("Consider disabling this service if not essential")
            recommendations.append("Implement strict access controls")
        
        elif risk_score > 0.4:
            recommendations.append("🟡 MEDIUM RISK: Review and secure")
            recommendations.append("Update to latest version if possible")
            recommendations.append("Implement monitoring and logging")
        
        else:
            recommendations.append("🟢 LOW RISK: Standard security practices")
            recommendations.append("Keep service updated")
            recommendations.append("Monitor for unusual activity")
        
        # Service-specific recommendations
        if service_name in ['http', 'https']:
            recommendations.extend([
                "Enable WAF protection",
                "Implement proper SSL/TLS configuration",
                "Regular security scans"
            ])
        elif service_name == 'ssh':
            recommendations.extend([
                "Use key-based authentication",
                "Disable root login",
                "Change default port"
            ])
        elif service_name in ['mysql', 'postgresql']:
            recommendations.extend([
                "Use strong authentication",
                "Encrypt network traffic",
                "Restrict network access"
            ])
        
        return recommendations
    
    def _generate_attack_path(self, target: str, service: Dict, port: str) -> Optional[AttackPath]:
        """Generate AI-powered attack path"""
        service_name = service.get('name', '').lower()
        version = service.get('version', '')
        
        # Define attack steps based on service
        steps = self._define_attack_steps(service_name, version, port)
        
        if not steps:
            return None
        
        # Calculate success probability
        success_prob = self._calculate_attack_success_probability(service_name, version, steps)
        
        # Determine complexity
        complexity = self._assess_attack_complexity(steps)
        
        # Estimate time
        time_estimate = self._estimate_attack_time(steps)
        
        # Identify tools needed
        tools_needed = self._identify_attack_tools(steps)
        
        # Assess risk level
        risk_level = self._assess_attack_risk_level(success_prob, complexity)
        
        return AttackPath(
            path_id=hashlib.md5(f"{target}{service_name}{port}".encode()).hexdigest(),
            target=target,
            steps=steps,
            success_probability=success_prob,
            complexity=complexity,
            time_estimate=time_estimate,
            tools_needed=tools_needed,
            risk_level=risk_level
        )
    
    def _define_attack_steps(self, service_name: str, version: str, port: str) -> List[Dict]:
        """Define attack steps for a service"""
        steps = []
        
        if service_name in ['http', 'https']:
            steps = [
                {'step': 1, 'action': 'Reconnaissance', 'tool': 'nmap', 'description': 'Port and service enumeration'},
                {'step': 2, 'action': 'Directory Enumeration', 'tool': 'gobuster', 'description': 'Find hidden directories'},
                {'step': 3, 'action': 'Vulnerability Scan', 'tool': 'nikto', 'description': 'Web vulnerability assessment'},
                {'step': 4, 'action': 'Exploitation', 'tool': 'metasploit', 'description': 'Attempt exploit modules'}
            ]
        elif service_name == 'ssh':
            steps = [
                {'step': 1, 'action': 'Banner Grabbing', 'tool': 'nmap', 'description': 'Get SSH version information'},
                {'step': 2, 'action': 'User Enumeration', 'tool': 'hydra', 'description': 'Identify valid users'},
                {'step': 3, 'action': 'Password Attack', 'tool': 'hydra', 'description': 'Brute force authentication'},
                {'step': 4, 'action': 'Key-based Attack', 'tool': 'ssh', 'description': 'Attempt key-based access'}
            ]
        elif service_name in ['mysql', 'postgresql']:
            steps = [
                {'step': 1, 'action': 'Service Detection', 'tool': 'nmap', 'description': 'Confirm database service'},
                {'step': 2, 'action': 'Authentication Test', 'tool': 'metasploit', 'description': 'Test default credentials'},
                {'step': 3, 'action': 'Enumeration', 'tool': 'metasploit', 'description': 'Enumerate databases and users'},
                {'step': 4, 'action': 'Data Extraction', 'tool': 'metasploit', 'description': 'Extract sensitive data'}
            ]
        
        return steps
    
    def _calculate_attack_success_probability(self, service_name: str, version: str, steps: List[Dict]) -> float:
        """Calculate probability of successful attack"""
        base_probability = 0.3
        
        # Service-specific adjustments
        if service_name in ['http', 'https']:
            base_probability += 0.2  # Web services often have vulnerabilities
        elif service_name == 'ssh':
            base_probability += 0.1  # SSH is generally secure
        elif service_name in ['mysql', 'postgresql']:
            base_probability += 0.15  # Databases can be misconfigured
        
        # Version-specific adjustments
        if version:
            if any(year in version for year in ['2015', '2016', '2017']):
                base_probability += 0.2  # Older versions more vulnerable
        
        # Step complexity adjustment
        complexity_factor = len(steps) * 0.05
        base_probability -= complexity_factor
        
        return max(0.1, min(base_probability, 0.9))
    
    def _assess_attack_complexity(self, steps: List[Dict]) -> str:
        """Assess attack complexity"""
        if len(steps) <= 2:
            return "Low"
        elif len(steps) <= 4:
            return "Medium"
        else:
            return "High"
    
    def _estimate_attack_time(self, steps: List[Dict]) -> str:
        """Estimate time required for attack"""
        total_time = len(steps) * 15  # 15 minutes per step average
        
        if total_time <= 30:
            return f"{total_time} minutes"
        elif total_time <= 120:
            return f"{total_time//60} hours"
        else:
            return f"{total_time//60} hours"
    
    def _identify_attack_tools(self, steps: List[Dict]) -> List[str]:
        """Identify tools needed for attack"""
        tools = set()
        for step in steps:
            if 'tool' in step:
                tools.add(step['tool'])
        return list(tools)
    
    def _assess_attack_risk_level(self, success_prob: float, complexity: str) -> str:
        """Assess risk level of attack"""
        if success_prob > 0.7 and complexity == "Low":
            return "High"
        elif success_prob > 0.5:
            return "Medium"
        else:
            return "Low"
    
    def _assess_advanced_risks(self, scan_results: Dict) -> Dict:
        """Advanced risk assessment using multiple factors"""
        risks = {
            'overall_risk': 0.0,
            'attack_surface': 0.0,
            'vulnerability_density': 0.0,
            'exposure_level': 0.0,
            'critical_findings': 0,
            'risk_factors': []
        }
        
        services = scan_results.get('services', {})
        
        if not services:
            return risks
        
        # Calculate attack surface
        risks['attack_surface'] = len(services) * 0.1
        
        # Count critical services
        critical_services = ['ssh', 'ftp', 'telnet', 'mysql', 'postgresql', 'mssql']
        critical_count = sum(1 for service in services.values() 
                           if service.get('name', '').lower() in critical_services)
        
        risks['critical_findings'] = critical_count
        
        # Calculate exposure level
        web_services = sum(1 for service in services.values() 
                          if service.get('name', '').lower() in ['http', 'https'])
        
        risks['exposure_level'] = (critical_count * 0.3) + (web_services * 0.2)
        
        # Calculate overall risk
        risks['overall_risk'] = (
            risks['attack_surface'] * 0.3 +
            risks['exposure_level'] * 0.4 +
            (critical_count * 0.1)
        )
        
        risks['overall_risk'] = min(risks['overall_risk'], 1.0)
        
        # Identify risk factors
        if critical_count > 0:
            risks['risk_factors'].append(f"{critical_count} critical services exposed")
        
        if web_services > 0:
            risks['risk_factors'].append(f"{web_services} web services accessible")
        
        if len(services) > 10:
            risks['risk_factors'].append("Large attack surface")
        
        return risks
    
    def _generate_ai_recommendations(self, analysis: Dict) -> List[str]:
        """Generate comprehensive AI recommendations"""
        recommendations = []
        
        target_profile = analysis.get('target_profile', {})
        risk_assessment = analysis.get('risk_assessment', {})
        vulnerability_predictions = analysis.get('vulnerability_predictions', [])
        
        # Overall security posture recommendations
        security_posture = target_profile.get('security_posture', 'unknown')
        
        if security_posture == 'poor':
            recommendations.append("🔴 CRITICAL: Target has poor security posture")
            recommendations.append("Immediate security review and hardening required")
            recommendations.append("Consider implementing defense-in-depth strategy")
        
        elif security_posture == 'moderate':
            recommendations.append("🟡 MODERATE: Target needs security improvements")
            recommendations.append("Implement additional security controls")
            recommendations.append("Regular security assessments recommended")
        
        else:
            recommendations.append("🟢 GOOD: Target has reasonable security posture")
            recommendations.append("Maintain current security practices")
            recommendations.append("Regular monitoring and updates recommended")
        
        # High-risk vulnerability recommendations
        high_risk_vulns = [v for v in vulnerability_predictions if v.risk_score > 0.7]
        if high_risk_vulns:
            recommendations.append(f"⚠️ {len(high_risk_vulns)} high-risk vulnerabilities detected")
            for vuln in high_risk_vulns:
                recommendations.append(f"  • {vuln.service}: {vuln.recommended_actions[0]}")
        
        # Attack path recommendations
        attack_paths = analysis.get('attack_paths', [])
        if attack_paths:
            high_prob_paths = [p for p in attack_paths if p.success_probability > 0.6]
            if high_prob_paths:
                recommendations.append(f"🎯 {len(high_prob_paths)} high-probability attack paths identified")
                recommendations.append("Implement additional defenses for these vectors")
        
        return recommendations
    
    def _analyze_threat_context(self, target: str, scan_results: Dict) -> Dict:
        """Analyze threat context and intelligence"""
        context = {
            'threat_actors': [],
            'attack_campaigns': [],
            'vulnerability_trends': [],
            'defense_recommendations': []
        }
        
        # This would integrate with threat intelligence feeds
        # For now, provide basic analysis
        
        services = scan_results.get('services', {})
        
        # Check for common attack patterns
        if any(service.get('name', '').lower() in ['http', 'https'] for service in services.values()):
            context['attack_campaigns'].append({
                'name': 'Web Application Attacks',
                'description': 'Common web application vulnerabilities',
                'severity': 'Medium'
            })
        
        if any(service.get('name', '').lower() in ['ssh', 'ftp'] for service in services.values()):
            context['attack_campaigns'].append({
                'name': 'Credential Attacks',
                'description': 'Brute force and credential stuffing',
                'severity': 'High'
            })
        
        # Generate defense recommendations
        context['defense_recommendations'] = [
            'Implement network segmentation',
            'Use strong authentication mechanisms',
            'Regular security monitoring',
            'Keep systems updated',
            'Implement intrusion detection'
        ]
        
        return context
    
    def get_ai_summary(self, analysis: Dict) -> str:
        """Generate AI summary of analysis"""
        target_profile = analysis.get('target_profile', {})
        risk_assessment = analysis.get('risk_assessment', {})
        vulnerability_predictions = analysis.get('vulnerability_predictions', [])
        
        summary = f"""
🤖 AI Analysis Summary for {target_profile.get('target', 'Unknown Target')}

📊 Target Profile:
   • Security Posture: {target_profile.get('security_posture', 'Unknown').upper()}
   • Exposed Services: {target_profile.get('exposed_services', 0)}
   • Attack Surface: {target_profile.get('attack_surface', 0):.1%}

⚠️ Risk Assessment:
   • Overall Risk: {risk_assessment.get('overall_risk', 0):.1%}
   • Critical Findings: {risk_assessment.get('critical_findings', 0)}
   • Risk Factors: {', '.join(risk_assessment.get('risk_factors', []))}

🔍 Vulnerability Analysis:
   • High-Risk Vulnerabilities: {len([v for v in vulnerability_predictions if v.risk_score > 0.7])}
   • Medium-Risk Vulnerabilities: {len([v for v in vulnerability_predictions if 0.4 < v.risk_score <= 0.7])}
   • Exploits Available: {len([v for v in vulnerability_predictions if v.exploit_available])}

🎯 Attack Paths:
   • Total Paths: {len(analysis.get('attack_paths', []))}
   • High-Probability Paths: {len([p for p in analysis.get('attack_paths', []) if p.success_probability > 0.6])}

💡 AI Recommendations:
   • {len(analysis.get('ai_recommendations', []))} actionable recommendations provided
   • Focus on high-risk vulnerabilities first
   • Implement defense-in-depth strategy
"""
        
        return summary

# Usage example
if __name__ == "__main__":
    # Initialize enhanced AI engine
    ai_engine = EnhancedAIEngine()
    
    # Example scan results
    scan_results = {
        'target': '192.168.1.100',
        'services': {
            '22': {'name': 'ssh', 'version': 'OpenSSH 7.2'},
            '80': {'name': 'http', 'version': 'Apache 2.4.49'},
            '3306': {'name': 'mysql', 'version': 'MySQL 5.7'}
        }
    }
    
    # Run advanced analysis
    analysis = ai_engine.analyze_target_intelligence('192.168.1.100', scan_results)
    
    # Print AI summary
    print(ai_engine.get_ai_summary(analysis)) 