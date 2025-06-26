from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QPushButton, QComboBox, QLineEdit, QTextEdit,
                           QProgressBar, QFrame, QSplitter, QTableWidget,
                           QTableWidgetItem, QTabWidget, QScrollArea)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QPalette, QFont, QPixmap
import subprocess
import re
from .cyberpunk_theme import COLORS, STYLES, FONTS, LAYOUT
from core.ai_engine import AIEngine
from datetime import datetime
from typing import List, Dict
import nmap

class NmapScanThread(QThread):
    output_received = pyqtSignal(str)
    scan_complete = pyqtSignal()
    
    def __init__(self, target, options):
        super().__init__()
        self.target = target
        self.options = options
        self.process = None
        
    def run(self):
        try:
            # Build nmap command
            cmd = ['nmap']
            cmd.extend(self.options)
            cmd.append(self.target)
            
            self.output_received.emit(f"[*] Running Nmap scan: {' '.join(cmd)}")
            
            # Start the process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            # Process output in real-time
            while True:
                output = self.process.stdout.readline()
                if output == '' and self.process.poll() is not None:
                    break
                if output:
                    self.output_received.emit(output.strip())
            
            # Process any errors
            for error in self.process.stderr:
                if error:
                    self.output_received.emit(f"[!] Error: {error.strip()}")
            
            self.scan_complete.emit()
            
        except Exception as e:
            self.output_received.emit(f"[!] Scan Error: {str(e)}")
            self.scan_complete.emit()
    
    def stop(self):
        if self.process:
            try:
                self.process.terminate()
                self.output_received.emit("[!] Scan stopped by user")
            except Exception as e:
                self.output_received.emit(f"[!] Error stopping scan: {str(e)}")

class TerminalOutput(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setStyleSheet(STYLES['terminal'])
        
    def append_output(self, text):
        # Format different types of output
        if text.startswith('[*]'):
            # Info messages in cyan
            text = f'<span style="color: {COLORS["text_secondary"]};">{text}</span>'
        elif text.startswith('[+]'):
            # Success messages in neon green
            text = f'<span style="color: {COLORS["neon_green"]};">{text}</span>'
        elif text.startswith('[!]'):
            # Warning/error messages in red
            text = f'<span style="color: {COLORS["warning_red"]};">{text}</span>'
        elif 'open' in text.lower():
            # Open ports in green
            text = f'<span style="color: {COLORS["neon_green"]};">{text}</span>'
        elif 'filtered' in text.lower():
            # Filtered ports in yellow
            text = f'<span style="color: {COLORS["cyber_yellow"]};">{text}</span>'
            
        self.append(text)
        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())

class AIStatusWidget(QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['panel_bg']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 15px;
                padding: 10px;
            }}
        """)
        
        layout = QHBoxLayout(self)
        
        # AI Status Icon
        self.status_icon = QLabel("🧠")
        self.status_icon.setStyleSheet("font-size: 24px;")
        layout.addWidget(self.status_icon)
        
        # AI Status Text
        self.status_text = QLabel("AI Assistant Ready")
        self.status_text.setStyleSheet(f"""
            color: {COLORS['neon_green']};
            font-size: 16px;
            font-weight: bold;
        """)
        layout.addWidget(self.status_text)
        
        layout.addStretch()
        
        # Pulse Animation Effect
        self.pulse_timer = QTimer(self)
        self.pulse_timer.timeout.connect(self.pulse_effect)
        self.pulse_timer.start(1000)  # Pulse every second
        
    def pulse_effect(self):
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['panel_bg']};
                border: 2px solid {COLORS['neon_green']};
                border-radius: 15px;
                padding: 10px;
            }}
        """)
        QTimer.singleShot(500, self.reset_style)
        
    def reset_style(self):
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['panel_bg']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 15px;
                padding: 10px;
            }}
        """)
        
    def set_analyzing(self):
        self.status_icon.setText("⚡")
        self.status_text.setText("AI Analyzing...")
        self.status_text.setStyleSheet(f"color: {COLORS['cyber_purple']}; font-size: 16px; font-weight: bold;")
        
    def set_ready(self):
        self.status_icon.setText("🧠")
        self.status_text.setText("AI Assistant Ready")
        self.status_text.setStyleSheet(f"color: {COLORS['neon_green']}; font-size: 16px; font-weight: bold;")

class AIAnalysisPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.current_analysis = {}
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # AI Status
        status_frame = QFrame()
        status_frame.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {COLORS['cyber_purple']}, stop:1 {COLORS['electric_blue']});
                border-radius: 10px;
                padding: 10px;
            }}
        """)
        status_layout = QHBoxLayout(status_frame)
        
        self.ai_status = QLabel("🤖 AI Ready")
        self.ai_status.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        status_layout.addWidget(self.ai_status)
        
        layout.addWidget(status_frame)
        
        # Create tabs
        self.tabs = QTabWidget()
        
        # Analysis Tab
        analysis_tab = QWidget()
        analysis_layout = QVBoxLayout(analysis_tab)
        
        self.findings_text = QTextEdit()
        self.findings_text.setReadOnly(True)
        self.findings_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['background']};
                color: {COLORS['neon_green']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 10px;
                padding: 10px;
                font-family: 'Consolas';
            }}
        """)
        analysis_layout.addWidget(self.findings_text)
        
        # Attack Path Tab
        attack_tab = QWidget()
        attack_layout = QVBoxLayout(attack_tab)
        
        self.attack_text = QTextEdit()
        self.attack_text.setReadOnly(True)
        self.attack_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['background']};
                color: {COLORS['warning_red']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 10px;
                padding: 10px;
                font-family: 'Consolas';
            }}
        """)
        attack_layout.addWidget(self.attack_text)
        
        # Defense Tab
        defense_tab = QWidget()
        defense_layout = QVBoxLayout(defense_tab)
        
        self.defense_text = QTextEdit()
        self.defense_text.setReadOnly(True)
        self.defense_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['background']};
                color: {COLORS['cyber_yellow']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 10px;
                padding: 10px;
                font-family: 'Consolas';
            }}
        """)
        defense_layout.addWidget(self.defense_text)
        
        # Add tabs
        self.tabs.addTab(analysis_tab, "🔍 Analysis")
        self.tabs.addTab(attack_tab, "⚡ Attack Paths")
        self.tabs.addTab(defense_tab, "🛡️ Defense")
        
        layout.addWidget(self.tabs)
        
    def update_analysis(self, analysis: dict):
        """Update the analysis with new data"""
        self.ai_status.setText("🤖 AI Analyzing...")
        
        # Clear previous content
        self.findings_text.clear()
        self.attack_text.clear()
        self.defense_text.clear()
        
        if not analysis or not analysis.get('findings'):
            self.findings_text.append("No services detected yet...")
            return
            
        # Update findings
        self.findings_text.append("🔍 Service Analysis:\n")
        for finding in analysis['findings']:
            service = finding['service']
            port = finding['port']
            version = finding['version']
            risk = finding['risk_level']
            
            # Format the finding with color based on risk
            if risk == 'High':
                color = COLORS['warning_red']
            elif risk == 'Medium':
                color = COLORS['cyber_yellow']
            else:
                color = COLORS['neon_green']
                
            self.findings_text.append(
                f'<span style="color: {color}">'
                f"[+] {service.upper()} on port {port}"
                f"</span>"
            )
            
            if version:
                self.findings_text.append(f"    Version: {version}")
            
            for action in finding.get('immediate_actions', []):
                self.findings_text.append(f"    • {action}")
            
            self.findings_text.append("")
        
        # Update attack vectors with more detailed information
        self.attack_text.append("⚡ Attack Vectors:\n")
        for finding in analysis['findings']:
            service = finding['service']
            port = finding['port']
            
            # Get attack vectors for this service
            vectors = self._get_quick_attack_vectors(service, port)
            
            if vectors:
                self.attack_text.append(f"\n[*] {service.upper()} ({port}/tcp):")
                for vector in vectors:
                    self.attack_text.append(f"\n  → {vector['name']}")
                    
                    # Show recommended tools
                    self.attack_text.append("    Tools:")
                    for tool in vector['tools']:
                        self.attack_text.append(f"    • {tool}")
                    
                    # Show example commands
                    self.attack_text.append("    Commands:")
                    for cmd in vector['commands']:
                        # Replace TARGET with actual target IP/hostname
                        cmd = cmd.replace('TARGET', analysis.get('target', 'TARGET'))
                        self.attack_text.append(f"    $ {cmd}")
                    
                    self.attack_text.append("")  # Add spacing between vectors
        
        # Update defense recommendations
        self.defense_text.append("🛡️ Security Recommendations:\n")
        seen_services = set()
        for finding in analysis['findings']:
            service = finding['service']
            if service not in seen_services:
                actions = self._get_quick_actions(service)
                if actions:
                    self.defense_text.append(f"\n[!] {service.upper()} Hardening:")
                    for action in actions:
                        self.defense_text.append(f"    • {action}")
                    seen_services.add(service)
        
        # Update risk metrics if available
        if 'risk_metrics' in analysis:
            metrics = analysis['risk_metrics']
            self.findings_text.append("\n📊 Risk Assessment:")
            self.findings_text.append(f"    • Overall Risk: {metrics['overall_risk']:.1%}")
            self.findings_text.append(f"    • Attack Surface: {metrics['attack_surface']:.1%}")
            self.findings_text.append(f"    • Critical Findings: {metrics['critical_findings']}")
        
        self.ai_status.setText("🤖 Analysis Complete")
        
    def _get_service_insights(self, service_name: str, version: str) -> List[str]:
        """Get insights for specific services"""
        insights = []
        service_name = service_name.lower()
        
        if service_name in ['http', 'https']:
            insights.append("Web service detected - Check for web vulnerabilities")
            insights.append("Consider running: gobuster, nikto, whatweb")
            if version != 'unknown':
                insights.append(f"Version info available - Check for CVEs: {version}")
                
        elif service_name in ['ssh']:
            insights.append("SSH service - Check for weak authentication")
            if version != 'unknown':
                insights.append(f"Version: {version} - Research known vulnerabilities")
                
        elif service_name in ['ftp']:
            insights.append("FTP service - Check for anonymous access")
            insights.append("Test for weak credentials")
            
        elif service_name in ['smb', 'microsoft-ds']:
            insights.append("SMB service - Check for known vulnerabilities")
            insights.append("Test for null sessions and weak shares")
            
        elif service_name in ['mysql', 'postgresql', 'mssql']:
            insights.append("Database service - Check for weak credentials")
            insights.append("Test for unauthorized access")
            
        return insights
        
    def _get_attack_vectors(self, service_name: str, port: str) -> List[Dict]:
        """Get potential attack vectors for a service"""
        vectors = []
        service_name = service_name.lower()
        
        if service_name in ['http', 'https']:
            vectors.append({
                'name': 'Web Application Scanning',
                'tools': ['gobuster', 'nikto', 'whatweb', 'burpsuite'],
                'steps': [
                    'Directory enumeration',
                    'Check for common vulnerabilities',
                    'Test for SQL injection',
                    'Look for sensitive files',
                    'Test for XSS vulnerabilities'
                ]
            })
            
        elif service_name == 'ssh':
            vectors.append({
                'name': 'SSH Authentication Testing',
                'tools': ['hydra', 'nmap', 'metasploit'],
                'steps': [
                    'Check for weak passwords',
                    'Test for known vulnerabilities',
                    'Attempt key-based auth bypass',
                    'Check for misconfiguration'
                ]
            })
            
        elif service_name == 'ftp':
            vectors.append({
                'name': 'FTP Service Testing',
                'tools': ['hydra', 'nmap', 'metasploit'],
                'steps': [
                    'Try anonymous login',
                    'Brute force credentials',
                    'Check for write access',
                    'Look for sensitive files'
                ]
            })
            
        elif service_name in ['smb', 'microsoft-ds']:
            vectors.append({
                'name': 'SMB Assessment',
                'tools': ['enum4linux', 'smbclient', 'nmap', 'metasploit'],
                'steps': [
                    'Enumerate shares',
                    'Check null sessions',
                    'Test for weak authentication',
                    'Look for sensitive data'
                ]
            })
            
        elif service_name in ['mysql', 'postgresql', 'mssql']:
            vectors.append({
                'name': 'Database Assessment',
                'tools': ['sqlmap', 'hydra', 'nmap', 'metasploit'],
                'steps': [
                    'Test default credentials',
                    'Check for anonymous access',
                    'Attempt SQL injection',
                    'Enumerate database info'
                ]
            })
            
        return vectors
        
    def _get_defense_recommendations(self, service_name: str) -> List[str]:
        """Get security recommendations for a service"""
        recommendations = []
        service_name = service_name.lower()
        
        if service_name in ['http', 'https']:
            recommendations.extend([
                'Enable WAF (Web Application Firewall)',
                'Implement proper input validation',
                'Use HTTPS with strong TLS configuration',
                'Remove unnecessary HTTP methods',
                'Keep web server software updated',
                'Implement rate limiting'
            ])
            
        elif service_name == 'ssh':
            recommendations.extend([
                'Use strong password policy',
                'Implement key-based authentication',
                'Disable root login',
                'Change default port',
                'Use fail2ban for brute force protection'
            ])
            
        elif service_name == 'ftp':
            recommendations.extend([
                'Disable anonymous access',
                'Use SFTP instead of FTP',
                'Implement strong authentication',
                'Restrict file permissions',
                'Enable TLS encryption'
            ])
            
        elif service_name in ['smb', 'microsoft-ds']:
            recommendations.extend([
                'Disable SMBv1',
                'Require SMB signing',
                'Implement proper access controls',
                'Regular security patches',
                'Monitor file access'
            ])
            
        elif service_name in ['mysql', 'postgresql', 'mssql']:
            recommendations.extend([
                'Use strong authentication',
                'Encrypt network traffic',
                'Regular security updates',
                'Implement proper access controls',
                'Enable audit logging'
            ])
            
        return recommendations

    def _get_quick_actions(self, service_name: str) -> List[str]:
        """Get quick security actions for a service"""
        actions = []
        service_name = service_name.lower()
        
        # Common security actions for different services
        if service_name in ['http', 'https']:
            actions.extend([
                "Enable HTTPS and redirect HTTP to HTTPS",
                "Implement proper access controls",
                "Use secure headers (HSTS, CSP, etc.)",
                "Keep web server software updated",
                "Remove unnecessary services and modules"
            ])
            
        elif service_name == 'ssh':
            actions.extend([
                "Use strong password policy",
                "Implement key-based authentication",
                "Disable root login",
                "Change default port",
                "Use fail2ban for brute force protection"
            ])
            
        elif service_name == 'ftp':
            actions.extend([
                "Use SFTP instead of FTP",
                "Disable anonymous access",
                "Implement strong authentication",
                "Restrict file permissions",
                "Enable TLS encryption"
            ])
            
        elif service_name in ['smb', 'microsoft-ds']:
            actions.extend([
                "Disable SMBv1",
                "Require SMB signing",
                "Implement proper access controls",
                "Regular security patches",
                "Monitor file access"
            ])
            
        elif service_name in ['mysql', 'postgresql', 'mssql']:
            actions.extend([
                "Use strong authentication",
                "Encrypt network traffic",
                "Regular security updates",
                "Implement proper access controls",
                "Enable audit logging"
            ])
            
        # Default actions for unknown services
        if not actions:
            actions.extend([
                "Review service necessity",
                "Implement access controls",
                "Monitor service activity",
                "Keep software updated",
                "Use encryption where possible"
            ])
            
        return actions
        
    def _get_quick_attack_vectors(self, service_name: str, port: str) -> List[Dict]:
        """Get quick attack vectors for a service"""
        vectors = []
        service_name = service_name.lower()
        
        if service_name in ['http', 'https']:
            vectors.append({
                'name': 'Web Application Scanning',
                'tools': ['gobuster', 'nikto', 'whatweb', 'burpsuite'],
                'commands': [
                    f'gobuster dir -u http://TARGET:{port} -w /usr/share/wordlists/dirb/common.txt',
                    f'nikto -h TARGET -p {port}',
                    f'whatweb http://TARGET:{port}'
                ]
            })
            
        elif service_name == 'ssh':
            vectors.append({
                'name': 'SSH Authentication Testing',
                'tools': ['hydra', 'nmap', 'metasploit'],
                'commands': [
                    f'hydra -L users.txt -P pass.txt TARGET ssh -s {port}',
                    f'nmap -p{port} -sV --script ssh-* TARGET'
                ]
            })
            
        elif service_name == 'ftp':
            vectors.append({
                'name': 'FTP Service Testing',
                'tools': ['hydra', 'nmap'],
                'commands': [
                    'ftp TARGET',
                    f'hydra -L users.txt -P pass.txt TARGET ftp -s {port}',
                    f'nmap -p{port} -sV --script ftp-* TARGET'
                ]
            })
            
        elif service_name in ['smb', 'microsoft-ds']:
            vectors.append({
                'name': 'SMB Assessment',
                'tools': ['enum4linux', 'smbclient', 'nmap'],
                'commands': [
                    'enum4linux TARGET',
                    'smbclient -L //TARGET',
                    f'nmap -p{port} -sV --script smb-* TARGET'
                ]
            })
            
        elif service_name in ['mysql', 'postgresql', 'mssql']:
            vectors.append({
                'name': 'Database Assessment',
                'tools': ['sqlmap', 'nmap'],
                'commands': [
                    f'nmap -p{port} -sV --script mysql-* TARGET',
                    f'nmap -p{port} -sV --script ms-sql-* TARGET',
                    f'nmap -p{port} -sV --script pgsql-* TARGET'
                ]
            })
            
        return vectors

class NmapPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ai_engine = AIEngine()
        self.setup_ui()
        self.scan_thread = None
        self.scan_results = []
        self.current_target = None
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(LAYOUT['margin'])
        
        # Create main splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Scan configuration and output
        left_panel = QFrame()
        left_panel.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS['panel_bg']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 15px;
                padding: 15px;
            }}
        """)
        left_layout = QVBoxLayout(left_panel)
        
        # Target input
        target_layout = QHBoxLayout()
        target_label = QLabel("🎯 Target:")
        target_label.setStyleSheet(f"""
            color: {COLORS['text_primary']};
            font-size: 14px;
            font-weight: bold;
        """)
        target_layout.addWidget(target_label)
        
        self.target_input = QLineEdit()
        self.target_input.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 10px;
                padding: 8px 15px;
                font-size: 14px;
            }}
            QLineEdit:focus {{
                border-color: {COLORS['neon_green']};
            }}
        """)
        self.target_input.setPlaceholderText("Enter IP or hostname (e.g. 192.168.1.1)")
        target_layout.addWidget(self.target_input)
        
        left_layout.addLayout(target_layout)
        
        # Scan options
        options_label = QLabel("🔧 Scan Options:")
        options_label.setStyleSheet(f"color: {COLORS['text_primary']};")
        left_layout.addWidget(options_label)
        
        self.scan_type = QComboBox()
        self.scan_type.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 10px;
                padding: 8px 15px;
                font-size: 14px;
            }}
            QComboBox::drop-down {{
                border: none;
            }}
            QComboBox::down-arrow {{
                image: url(resources/down_arrow.png);
                width: 12px;
                height: 12px;
            }}
        """)
        self.scan_type.addItems([
            "Quick Scan (-T4 -F)",
            "Full Scan (-sS -sV -O)",
            "Intense Scan (-T4 -A -v)",
            "Vulnerability Scan (-sV --script vuln)",
            "Custom"
        ])
        left_layout.addWidget(self.scan_type)
        
        # Custom options
        self.custom_options = QLineEdit()
        self.custom_options.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 10px;
                padding: 8px 15px;
                font-size: 14px;
            }}
        """)
        self.custom_options.setPlaceholderText("Custom Nmap options")
        self.custom_options.setEnabled(False)
        left_layout.addWidget(self.custom_options)
        
        self.scan_type.currentTextChanged.connect(self.on_scan_type_changed)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("▶ Start Scan")
        self.start_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['neon_green']};
                color: {COLORS['panel_bg']};
                border: none;
                border-radius: 15px;
                padding: 12px 25px;
                font-weight: bold;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {COLORS['cyber_purple']};
            }}
        """)
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("⏹ Stop")
        self.stop_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['red']};
                color: {COLORS['panel_bg']};
                border: none;
                border-radius: 15px;
                padding: 12px 25px;
                font-weight: bold;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: #ff4444;
            }}
        """)
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        
        left_layout.addLayout(button_layout)
        
        # Terminal output
        terminal_label = QLabel("🖥️ Scan Output")
        terminal_label.setStyleSheet(f"""
            color: {COLORS['text_primary']};
            font-size: 16px;
            font-weight: bold;
            margin-top: 15px;
        """)
        left_layout.addWidget(terminal_label)
        
        self.terminal = TerminalOutput()
        left_layout.addWidget(self.terminal)
        
        splitter.addWidget(left_panel)
        
        # Right panel - AI Analysis
        self.ai_panel = AIAnalysisPanel()
        splitter.addWidget(self.ai_panel)
        
        # Set splitter sizes (40% left, 60% right)
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
    def on_scan_type_changed(self, scan_type):
        self.custom_options.setEnabled(scan_type == "Custom")
        
    def get_scan_options(self):
        scan_type = self.scan_type.currentText()
        
        if scan_type == "Quick Scan (-T4 -F)":
            return ["-T4", "-F"]
        elif scan_type == "Full Scan (-sS -sV -O)":
            return ["-sS", "-sV", "-O"]
        elif scan_type == "Intense Scan (-T4 -A -v)":
            return ["-T4", "-A", "-v"]
        elif scan_type == "Vulnerability Scan (-sV --script vuln)":
            return ["-sV", "--script", "vuln"]
        else:  # Custom
            return self.custom_options.text().split()
        
    def start_scan(self):
        target = self.target_input.text()
        if not target:
            self.terminal.append_output("[!] Please enter a target")
            return
            
        self.current_target = target
        options = self.get_scan_options()
        
        self.terminal.append_output(f"[*] Starting Nmap scan on target: {target}")
        self.terminal.append_output(f"[*] Options: {' '.join(options)}")
        
        # Clear previous results
        self.scan_results = []
        
        # Disable/enable buttons
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Start scan in separate thread
        if self.scan_thread is not None:
            try:
                self.scan_thread.output_received.disconnect()
                self.scan_thread.scan_complete.disconnect()
            except:
                pass
        
        self.scan_thread = NmapScanThread(target, options)
        self.scan_thread.output_received.connect(self.handle_output)
        self.scan_thread.scan_complete.connect(self.scan_finished)
        
        # Start the thread
        self.scan_thread.start()
        
    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.terminal.append_output("[!] Scan stopped by user")
        
            # Save stopped scan to database
            try:
                from core.database_manager import DatabaseManager
                db = DatabaseManager()
                
                # Parse partial results
                parsed_results = self._parse_scan_results()
                
                # Save to database with stopped status
                scan_id = db.add_scan(
                    tool_name="Nmap",
                    target=self.current_target,
                    status="Stopped",
                    results=parsed_results,
                    ai_analysis="Scan was stopped by user"
                )
                
                self.terminal.append_output(f"[✓] Stopped scan saved to database (ID: {scan_id})")
                
            except Exception as e:
                self.terminal.append_output(f"[!] Failed to save stopped scan to database: {str(e)}")
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
    def scan_finished(self):
        self.terminal.append_output("[✓] Scan completed!")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Save scan results to database
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            
            # Parse the scan results
            parsed_results = self._parse_scan_results()
            
            # Create AI analysis summary
            ai_analysis = ""
            if parsed_results.get('findings'):
                ai_analysis = f"Found {len(parsed_results['findings'])} services. "
                if parsed_results.get('risk_metrics'):
                    risk = parsed_results['risk_metrics']
                    ai_analysis += f"Overall risk: {risk.get('overall_risk', 0):.2f}. "
                    ai_analysis += f"Critical findings: {risk.get('critical_findings', 0)}."
            
            # Save to database
            scan_id = db.add_scan(
                tool_name="Nmap",
                target=self.current_target,
                status="Success",
                results=parsed_results,
                ai_analysis=ai_analysis
            )
            
            self.terminal.append_output(f"[✓] Scan saved to database (ID: {scan_id})")
            
            # Add vulnerabilities if any high-risk services found
            for finding in parsed_results.get('findings', []):
                if finding.get('risk_level') == 'High':
                    db.add_vulnerability(
                        scan_id=scan_id,
                        name=f"High-risk service: {finding['service']}",
                        severity="High",
                        description=f"Service {finding['service']} on port {finding['port']} may pose security risks",
                        recommendation=f"Review and secure {finding['service']} service on port {finding['port']}"
                    )
                    
        except Exception as e:
            self.terminal.append_output(f"[!] Failed to save scan to database: {str(e)}")
        
    def handle_output(self, output):
        self.terminal.append_output(output)
        self.scan_results.append(output)
        
        # Try to parse and update AI analysis in real-time
        if 'open' in output and 'tcp' in output:
            self.terminal.append_output("[*] AI: Analyzing new service...")
            parsed_results = self._parse_scan_results()
            if parsed_results['services']:
                analysis = self.ai_engine.analyze_scan_results(parsed_results)
                self.ai_panel.update_analysis(analysis)
        
    def _parse_scan_results(self):
        """Parse Nmap output into structured format"""
        parsed = {
            'target': self.current_target,
            'scan_type': self.scan_type.currentText(),
            'services': {},
            'os_info': [],
            'findings': []  # Add findings list
        }
        
        current_port = None
        
        for line in self.scan_results:
            # Debug output for every line
            self.terminal.append_output(f"[DEBUG] Processing: {line}")
            
            # Try different port patterns
            port_patterns = [
                r'(\d+)/tcp\s+open\s+(\S+)',  # Basic pattern
                r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)',  # With extra info
                r'PORT\s+STATE\s+SERVICE',  # Header line
                r'(\d+)/tcp\s+open'  # Just port open
            ]
            
            for pattern in port_patterns:
                match = re.search(pattern, line)
                if match:
                    if len(match.groups()) >= 2:
                        current_port = match.group(1)
                        service_name = match.group(2)
                        
                        # Add to services
                        parsed['services'][current_port] = {
                            'name': service_name,
                            'version': '',
                            'product': '',
                            'extra': match.group(3) if len(match.groups()) > 2 else ''
                        }
                        
                        # Add to findings
                        finding = {
                            'service': service_name,
                            'port': current_port,
                            'version': '',
                            'risk_level': self._assess_risk_level(service_name),
                            'immediate_actions': []
                        }
                        parsed['findings'].append(finding)
                        
                        self.terminal.append_output(f"[*] AI: Found {service_name} on port {current_port}")
                    break
            
            # Version detection
            if current_port:
                service = parsed['services'].get(current_port)
                if service:
                    # Check for version info
                    if any(x in line for x in ['VERSION:', 'Service Info:']):
                        version_match = re.search(r'VERSION:\s*([^;\n]+)', line)
                        if version_match:
                            version = version_match.group(1).strip()
                            service['version'] = version
                            # Update version in findings too
                            for finding in parsed['findings']:
                                if finding['port'] == current_port:
                                    finding['version'] = version
                            self.terminal.append_output(f"[*] AI: Version info: {version}")
                    
                    # Additional service information
                    elif '|' in line and '_' not in line:
                        info = line.split('|')[1].strip()
                        if info:
                            service['extra'] = info
                            self.terminal.append_output(f"[*] AI: Extra info: {info}")
        
        # Calculate risk metrics
        if parsed['findings']:
            risk_metrics = self._calculate_risk_metrics(parsed['findings'])
            parsed['risk_metrics'] = risk_metrics
        
        # Debug output of found services
        if parsed['services']:
            self.terminal.append_output(f"[DEBUG] Found services: {list(parsed['services'].keys())}")
        
        return parsed
        
    def _assess_risk_level(self, service_name: str) -> str:
        """Assess the risk level of a service"""
        high_risk = ['mysql', 'mssql', 'postgresql', 'mongodb', 'redis', 'telnet', 'ftp']
        medium_risk = ['ssh', 'smtp', 'dns', 'http']
        
        service_name = service_name.lower()
        if service_name in high_risk:
            return 'High'
        elif service_name in medium_risk:
            return 'Medium'
        return 'Low'
        
    def _calculate_risk_metrics(self, findings: List[Dict]) -> Dict:
        """Calculate risk metrics based on findings"""
        total_services = len(findings)
        high_risk = sum(1 for f in findings if f['risk_level'] == 'High')
        medium_risk = sum(1 for f in findings if f['risk_level'] == 'Medium')
        
        # Calculate weighted risk
        risk_weights = {'High': 1.0, 'Medium': 0.5, 'Low': 0.2}
        total_risk = sum(risk_weights[f['risk_level']] for f in findings)
        
        return {
            'overall_risk': total_risk / (total_services * 1.0) if total_services > 0 else 0,
            'attack_surface': (high_risk + medium_risk * 0.5) / total_services if total_services > 0 else 0,
            'critical_findings': high_risk
        } 