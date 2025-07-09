from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QPushButton, QComboBox, QLineEdit, QTextEdit,
                           QProgressBar, QFrame, QSplitter, QTableWidget,
                           QTableWidgetItem, QTabWidget, QScrollArea, QCheckBox)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QPalette, QFont
import subprocess
import re
from datetime import datetime
from typing import List, Dict
from .cyberpunk_theme import COLORS, STYLES, FONTS, LAYOUT
from core.ai_engine import AIEngine

class NiktoScanThread(QThread):
    output_received = pyqtSignal(str)
    scan_complete = pyqtSignal()
    
    def __init__(self, target, options):
        super().__init__()
        self.target = target
        self.options = options
        self.process = None
        
    def run(self):
        try:
            # Build Nikto command with enhanced options
            cmd = ['nikto']
            
            # Add target
            if not self.target.startswith(('http://', 'https://')):
                self.target = 'http://' + self.target
            cmd.extend(['-h', self.target])
            
            # Add selected options with enhanced functionality
            for option in self.options:
                if option == "Tuning":
                    # Full scan with all checks
                    cmd.extend(['-Tuning', '123456789abcx'])
                elif option == "SSL":
                    # Force SSL mode (do not add -sslcheck)
                    cmd.append('-ssl')
                elif option == "Verbose":
                    # Enhanced verbosity for better AI analysis
                    cmd.extend(['-Display', 'V'])
                elif option == "evasion":
                    # Advanced evasion techniques
                    cmd.extend(['-evasion', '123'])  # Multiple evasion methods
            # Add output format for better parsing
            # (Permanently removed '-Format', 'csv' to prevent output file format error)
            # Add additional useful options (remove -vhost, -Show, -sslcheck)
            cmd.extend([
                '-nointeractive',  # Non-interactive mode
                '-Plugins', 'ALL',  # Enable all plugins
                '-timeout', '30',   # Reasonable timeout
                '-useragent', 'Mozilla/5.0',  # Common user agent
            ])
            
            self.output_received.emit(f"[*] Running enhanced Nikto scan: {' '.join(cmd)}")
            self.output_received.emit(f"[*] Target: {self.target}")
            
            # Start the process with enhanced output handling
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            # Process output in real-time with improved parsing
            while True:
                output = self.process.stdout.readline()
                if output == '' and self.process.poll() is not None:
                    break
                if output:
                    clean_output = output.strip()
                    if clean_output:
                        # Enhanced output processing
                        if "+" in clean_output:  # Nikto finding
                            self.output_received.emit(f"[+] {clean_output}")
                        elif "- " in clean_output:  # Nikto info
                            self.output_received.emit(f"[*] {clean_output}")
                        elif "ERROR:" in clean_output:  # Error
                            self.output_received.emit(f"[!] {clean_output}")
                        else:
                            self.output_received.emit(clean_output)
            
            # Process any errors with better error handling
            for error in self.process.stderr:
                if error:
                    error = error.strip()
                    if "ERROR:" in error:
                        self.output_received.emit(f"[!] Critical: {error}")
                    elif "WARNING:" in error:
                        self.output_received.emit(f"[!] Warning: {error}")
                    else:
                        self.output_received.emit(f"[*] Info: {error}")
            
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
        self.setFont(QFont('Consolas', 10))
        
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

class VulnerabilityPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.current_analysis = {}
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Create tabs
        self.tabs = QTabWidget()
        
        # Findings Tab
        findings_tab = QWidget()
        findings_layout = QVBoxLayout(findings_tab)
        
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
        findings_layout.addWidget(self.findings_text)
        
        # Recommendations Tab
        recom_tab = QWidget()
        recom_layout = QVBoxLayout(recom_tab)
        
        self.recom_text = QTextEdit()
        self.recom_text.setReadOnly(True)
        self.recom_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['background']};
                color: {COLORS['cyber_yellow']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 10px;
                padding: 10px;
                font-family: 'Consolas';
            }}
        """)
        recom_layout.addWidget(self.recom_text)
        
        # Add tabs
        self.tabs.addTab(findings_tab, "🔍 Findings")
        self.tabs.addTab(recom_tab, "🛡️ Recommendations")
        
        layout.addWidget(self.tabs)
        
    def update_analysis(self, findings: List[Dict]):
        """Update the analysis with new findings and enhanced insights"""
        self.findings_text.clear()
        self.recom_text.clear()

        if not findings:
            self.findings_text.append("No vulnerabilities detected yet...")
            self.recom_text.append("<b>🛡️ No recommendations available.</b>")
            return

        # Update findings with enhanced formatting
        self.findings_text.append("🔍 <b>Vulnerability Analysis</b>\n")

        # Group findings by severity
        severity_groups = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': []
        }
        type_groups = {}
        for finding in findings:
            severity = finding.get('severity', 'Low')
            severity_groups[severity].append(finding)
            ftype = finding.get('type', 'general')
            if ftype not in type_groups:
                type_groups[ftype] = []
            type_groups[ftype].append(finding)

        # Display findings by severity
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity_groups[severity]:
                # Set color based on severity
                if severity == 'Critical':
                    color = COLORS['warning_red']
                    icon = '⚠️'
                elif severity == 'High':
                    color = '#FF4444'  # Bright red
                    icon = '🔴'
                elif severity == 'Medium':
                    color = COLORS['cyber_yellow']
                    icon = '🟡'
                else:
                    color = COLORS['neon_green']
                    icon = '🟢'

                self.findings_text.append(
                    f'<span style="color: {color}; font-size: 16px; font-weight: bold;">'
                    f"{icon} {severity} Severity Findings ({len(severity_groups[severity])})"
                    f"</span>\n"
                )

                for finding in severity_groups[severity]:
                    # Format finding details
                    title = finding.get('title', 'Unknown Issue')
                    osvdb = finding.get('osvdb', '')
                    details = finding.get('details', '').strip()

                    self.findings_text.append(
                        f'<span style="color: {color}; font-weight: bold;">➤ {title}</span>'
                    )

                    if osvdb:
                        self.findings_text.append(f"  <b>OSVDB-{osvdb}</b>")

                    if details:
                        self.findings_text.append(f"  <i>Details:</i> {details}")

                    # Add server info if available
                    if 'server_info' in finding:
                        self.findings_text.append(f"  <i>Server:</i> {finding['server_info']}")

                    self.findings_text.append("<br>")  # Add spacing

        # Update recommendations with enhanced insights
        self.recom_text.append("<b>🛡️ Security Recommendations</b><br><br>")
        self.recom_text.append("<i>Below are actionable steps and best practices based on the findings above. Address high and critical issues first for maximum impact.</i><br><br>")

        # Track seen categories to avoid duplicates
        seen_categories = set()
        for ftype, findings_of_type in type_groups.items():
            if ftype not in seen_categories:
                seen_categories.add(ftype)
                # Get specific recommendations for this type
                attack_recs = self._get_attack_recommendations({'type': ftype})
                mitigation_steps = self._get_mitigation_steps({'type': ftype})
                section_icon = '🛡️'
                if ftype == 'ssl':
                    section_icon = '🔒'
                elif ftype == 'xss':
                    section_icon = '💥'
                elif ftype == 'injection':
                    section_icon = '💉'
                elif ftype == 'headers':
                    section_icon = '📑'
                elif ftype == 'cookies':
                    section_icon = '🍪'
                elif ftype == 'info_disclosure':
                    section_icon = '🔎'
                elif ftype == 'auth':
                    section_icon = '🔑'
                elif ftype == 'outdated':
                    section_icon = '⏳'
                elif ftype == 'shellshock':
                    section_icon = '💣'
                elif ftype == 'general':
                    section_icon = '🛡️'
                self.recom_text.append(f"<b>{section_icon} {ftype.upper()} Recommendations:</b><br>")
                if attack_recs:
                    self.recom_text.append("<b>🎯 Testing Steps:</b><ul>")
                    for rec in attack_recs:
                        self.recom_text.append(f"<li>{rec}</li>")
                    self.recom_text.append("</ul>")
                if mitigation_steps:
                    self.recom_text.append("<b>🛡️ Mitigation Steps:</b><ul>")
                    for step in mitigation_steps:
                        self.recom_text.append(f"<li>{step}</li>")
                    self.recom_text.append("</ul>")
                if not (attack_recs or mitigation_steps):
                    # Show generic best practices if no specific recs
                    self.recom_text.append("<b>🛡️ Best Practices:</b><ul>")
                    self.recom_text.append("<li>Review service necessity</li><li>Implement access controls</li><li>Monitor service activity</li><li>Keep software updated</li><li>Use encryption where possible</li></ul>")
                self.recom_text.append("<hr>")

        # If no recommendations were added, show a generic section
        if len(seen_categories) == 0:
            self.recom_text.append("<b>🛡️ General Recommendations:</b><ul>")
            self.recom_text.append("<li>Review service necessity</li><li>Implement access controls</li><li>Monitor service activity</li><li>Keep software updated</li><li>Use encryption where possible</li></ul>")

        # Friendly summary/call-to-action
        if findings:
            self.recom_text.append("<br><b>✅ Take action on the above recommendations to improve your security posture!</b>")

        # Add overall risk assessment
        total_findings = len(findings)
        critical_count = len(severity_groups['Critical'])
        high_count = len(severity_groups['High'])
        medium_count = len(severity_groups['Medium'])

        risk_score = ((critical_count * 100) + (high_count * 50) + (medium_count * 25)) / (total_findings * 100) if total_findings > 0 else 0

        self.findings_text.append("<br><b>📊 Risk Assessment:</b>")
        self.findings_text.append(f"  • Total Findings: {total_findings}")
        self.findings_text.append(f"  • Critical Issues: {critical_count}")
        self.findings_text.append(f"  • High Issues: {high_count}")
        self.findings_text.append(f"  • Medium Issues: {medium_count}")
        self.findings_text.append(f"  • Overall Risk Score: {risk_score:.1%}")
        
    def _get_attack_recommendations(self, finding: dict) -> List[str]:
        """Get attack recommendations based on finding type"""
        category = finding.get('type', 'general')
        recommendations = []
        
        if category == 'ssl':
            recommendations.extend([
                "Run SSLScan for detailed cipher analysis",
                "Check for Heartbleed vulnerability",
                "Test SSL/TLS downgrade attacks",
                "Verify certificate chain"
            ])
        elif category == 'injection':
            recommendations.extend([
                "Use SQLMap for SQL injection testing",
                "Test command injection with special characters",
                "Verify input validation bypass",
                "Check for blind injection points"
            ])
        elif category == 'xss':
            recommendations.extend([
                "Test reflected XSS vectors",
                "Check for DOM-based XSS",
                "Verify stored XSS possibilities",
                "Test XSS filter bypass"
            ])
        
        return recommendations
        
    def _get_mitigation_steps(self, finding: dict) -> List[str]:
        """Get mitigation steps based on finding type"""
        category = finding.get('type', 'general')
        steps = []
        
        if category == 'ssl':
            steps.extend([
                "Upgrade to latest TLS version",
                "Disable weak cipher suites",
                "Implement HSTS",
                "Use strong certificates"
            ])
        elif category == 'injection':
            steps.extend([
                "Implement input validation",
                "Use parameterized queries",
                "Apply WAF rules",
                "Regular security audits"
            ])
        elif category == 'xss':
            steps.extend([
                "Implement CSP headers",
                "Use proper output encoding",
                "Apply XSS filters",
                "Validate all input"
            ])
        
        return steps

class NiktoPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ai_engine = AIEngine()
        self.setup_ui()
        self.scan_thread = None
        self.scan_results = []
        self.current_target = None
        self.current_findings = []
        
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
        self.target_input.setPlaceholderText("Enter URL (e.g. http://example.com)")
        target_layout.addWidget(self.target_input)
        
        left_layout.addLayout(target_layout)
        
        # Scan options
        options_label = QLabel("🔧 Scan Options:")
        options_label.setStyleSheet(f"""
            color: {COLORS['text_primary']};
            font-size: 14px;
            font-weight: bold;
            margin-top: 10px;
        """)
        left_layout.addWidget(options_label)
        
        # Option checkboxes
        self.options = []
        for option in ["Tuning", "SSL", "Verbose", "evasion"]:
            checkbox = QCheckBox(option)
            checkbox.setStyleSheet(f"""
                QCheckBox {{
                    color: {COLORS['text_primary']};
                    font-size: 13px;
                }}
                QCheckBox::indicator {{
                    width: 18px;
                    height: 18px;
                }}
                QCheckBox::indicator:unchecked {{
                    border: 2px solid {COLORS['electric_blue']};
                    background: {COLORS['panel_bg']};
                }}
                QCheckBox::indicator:checked {{
                    border: 2px solid {COLORS['neon_green']};
                    background: {COLORS['neon_green']};
                }}
            """)
            left_layout.addWidget(checkbox)
            self.options.append(checkbox)
        
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

        # Right panel - Vulnerability Analysis and AI Interpreter
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setSpacing(LAYOUT['margin'])

        self.vuln_panel = VulnerabilityPanel()
        right_layout.addWidget(self.vuln_panel)

        # AI Interpreter Panel
        self.interpreter_label = QLabel("🤖 <b>AI Interpreter</b>")
        self.interpreter_label.setStyleSheet(f"color: {COLORS['cyber_yellow']}; font-size: 16px; font-weight: bold;")
        right_layout.addWidget(self.interpreter_label)
        self.interpreter_text = QTextEdit()
        self.interpreter_text.setReadOnly(True)
        self.interpreter_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['background']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 10px;
                padding: 10px;
                font-family: 'Consolas';
            }}
        """)
        right_layout.addWidget(self.interpreter_text)

        splitter.addWidget(right_panel)
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
    def update_interpreter(self, findings):
        """Generate and display a natural language interpretation of the findings."""
        if not findings:
            self.interpreter_text.setHtml("<i>No findings to interpret yet.</i>")
            return
        # Count by severity
        sev_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        type_count = {}
        for f in findings:
            sev = f.get('severity', 'Low')
            sev_count[sev] = sev_count.get(sev, 0) + 1
            ftype = f.get('type', 'general')
            type_count[ftype] = type_count.get(ftype, 0) + 1
        total = len(findings)
        summary = f"<b>Scan Interpretation:</b><br>"
        summary += f"<b>Total Findings:</b> {total}<br>"
        summary += f"<b>Critical:</b> {sev_count['Critical']} | <b>High:</b> {sev_count['High']} | <b>Medium:</b> {sev_count['Medium']} | <b>Low:</b> {sev_count['Low']}<br><br>"
        if sev_count['Critical'] > 0:
            summary += "<b>⚠️ Critical issues detected!</b> Immediate action is required to address these vulnerabilities.<br>"
        elif sev_count['High'] > 0:
            summary += "<b>🔴 High risk issues found.</b> Prioritize remediation of these findings.<br>"
        elif sev_count['Medium'] > 0:
            summary += "<b>🟡 Medium risk issues present.</b> Review and address as part of your security process.<br>"
        else:
            summary += "<b>🟢 No high or critical risks detected.</b> Maintain good security hygiene.<br>"
        # List most common finding types
        if type_count:
            summary += "<br><b>Most common finding types:</b><ul>"
            for t, c in sorted(type_count.items(), key=lambda x: -x[1]):
                summary += f"<li><b>{t.title()}</b>: {c} finding(s)</li>"
            summary += "</ul>"
        # Call to action
        if sev_count['Critical'] > 0 or sev_count['High'] > 0:
            summary += "<br><b>🚨 Recommended: Address critical and high findings immediately. See the recommendations panel for prioritized actions.</b>"
        elif sev_count['Medium'] > 0:
            summary += "<br><b>🟡 Recommended: Review and address medium findings soon.</b>"
        else:
            summary += "<br><b>✅ Your target appears to have a good security posture. Continue regular monitoring and updates.</b>"
        self.interpreter_text.setHtml(summary)

    def start_scan(self):
        target = self.target_input.text()
        if not target:
            self.terminal.append_output("[!] Please enter a target URL")
            return
            
        self.current_target = target
        selected_options = [opt.text() for opt in self.options if opt.isChecked()]
        
        self.terminal.append_output(f"[*] Starting Nikto scan on target: {target}")
        self.terminal.append_output(f"[*] Selected options: {', '.join(selected_options)}")
        
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
        
        self.scan_thread = NiktoScanThread(target, selected_options)
        self.scan_thread.output_received.connect(self.handle_output)
        self.scan_thread.scan_complete.connect(self.scan_finished)
        
        # Start the thread
        self.scan_thread.start()
        
        self.terminal.append_output("[*] Scan started - waiting for results...")
        
    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.terminal.append_output("[!] Scan stopped by user")
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
    def handle_output(self, output):
        """Handle output from nikto scan with enhanced AI analysis and robust parsing"""
        self.terminal.append_output(output)
        self.scan_results.append(output)

        # Try to parse and update findings in real-time with AI analysis
        finding = self._parse_finding(output)
        if finding:
            # Get AI analysis for the finding
            try:
                ai_analysis = self.ai_engine.analyze_vulnerability(finding['title'])
                finding.update(ai_analysis)
                finding['ai_recommendations'] = self._get_ai_recommendations(finding)
                finding['attack_vectors'] = self._get_attack_vectors(finding)
                finding['defense_strategies'] = self._get_defense_strategies(finding)
            except Exception as e:
                finding['ai_error'] = f"AI analysis error: {str(e)}"
            self.current_findings.append(finding)
            self.vuln_panel.update_analysis(self.current_findings)
            self.update_interpreter(self.current_findings)
    
    def _parse_finding(self, output):
        """Parse finding with enhanced robustness for various Nikto output formats and categorize findings for recommendations"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'raw_output': output
        }
        # Try to parse JSON output
        try:
            if output.strip().startswith('{') or output.strip().startswith('['):
                import json
                data = json.loads(output)
                if isinstance(data, dict) and 'id' in data:
                    finding['title'] = data.get('id', 'Nikto Finding')
                    finding['details'] = data.get('description', '')
                elif isinstance(data, list) and data:
                    finding['title'] = data[0].get('id', 'Nikto Finding')
                    finding['details'] = data[0].get('description', '')
                return finding
        except Exception:
            pass
        # Try to parse CSV output
        if ',' in output and output.count(',') >= 2:
            parts = output.split(',')
            finding['title'] = parts[1].strip() if len(parts) > 1 else output
            finding['details'] = ','.join(parts[2:]).strip() if len(parts) > 2 else ''
            return finding
        # Enhanced: Parse Nikto findings (lines starting with '+')
        if output.strip().startswith('+'):
            title = output.strip()[1:].strip()
            finding['title'] = title
            finding['details'] = title
            # Categorize finding
            title_lower = title.lower()
            if 'x-frame-options' in title_lower or 'strict-transport-security' in title_lower or 'content-security-policy' in title_lower:
                finding['type'] = 'headers'
                finding['severity'] = 'Medium'
            elif 'ssl' in title_lower or 'tls' in title_lower or 'certificate' in title_lower:
                finding['type'] = 'ssl'
                finding['severity'] = 'Medium'
            elif 'xss' in title_lower or 'cross-site scripting' in title_lower:
                finding['type'] = 'xss'
                finding['severity'] = 'High'
            elif 'sql injection' in title_lower or 'sql-injection' in title_lower:
                finding['type'] = 'injection'
                finding['severity'] = 'Critical'
            elif 'cookie' in title_lower:
                finding['type'] = 'cookies'
                finding['severity'] = 'Medium'
            elif 'directory indexing' in title_lower or 'index of /' in title_lower:
                finding['type'] = 'info_disclosure'
                finding['severity'] = 'Medium'
            elif 'admin' in title_lower or 'login' in title_lower:
                finding['type'] = 'auth'
                finding['severity'] = 'Medium'
            elif 'debug' in title_lower or 'trace' in title_lower:
                finding['type'] = 'info_disclosure'
                finding['severity'] = 'Medium'
            elif 'outdated' in title_lower or 'obsolete' in title_lower:
                finding['type'] = 'outdated'
                finding['severity'] = 'High'
            elif 'shellshock' in title_lower:
                finding['type'] = 'shellshock'
                finding['severity'] = 'Critical'
            elif 'exposure' in title_lower or 'disclosure' in title_lower:
                finding['type'] = 'info_disclosure'
                finding['severity'] = 'Medium'
            else:
                finding['type'] = 'general'
                finding['severity'] = 'Low'
            return finding
        # Fallback: parse as plain text
        if '+ ' in output or 'OSVDB' in output:
            finding['title'] = output.split(': ', 1)[1] if ': ' in output else output
        else:
            finding['title'] = output
        finding['type'] = 'general'
        finding['severity'] = 'Low'
        return finding
    
    def _get_ai_recommendations(self, finding):
        """Get AI-powered recommendations based on finding type and severity"""
        recommendations = []
        
        if finding.get('severity') == 'Critical':
            recommendations.extend([
                'Immediate patching required',
                'Monitor for exploitation attempts',
                'Implement additional security controls'
            ])
        
        category = finding.get('category', 'general')
        if category == 'injection':
            recommendations.extend([
                'Review input validation',
                'Implement WAF rules',
                'Add security headers'
            ])
        elif category == 'authentication':
            recommendations.extend([
                'Enable MFA',
                'Review password policies',
                'Audit access controls'
            ])
            
        return recommendations
    
    def _get_attack_vectors(self, finding):
        """Get AI-suggested attack vectors for testing"""
        vectors = []
        
        category = finding.get('category', 'general')
        if category == 'sql_injection':
            vectors.extend([
                {'tool': 'sqlmap', 'command': f"sqlmap -u {self.current_target} --batch"},
                {'tool': 'manual', 'payload': "' OR '1'='1"}
            ])
        elif category == 'xss':
            vectors.extend([
                {'tool': 'xssstrike', 'command': f"xssstrike -u {self.current_target}"},
                {'tool': 'manual', 'payload': "<script>alert(1)</script>"}
            ])
            
        return vectors
    
    def _get_defense_strategies(self, finding):
        """Get AI-suggested defense strategies"""
        strategies = []
        
        severity = finding.get('severity', 'Low')
        category = finding.get('category', 'general')
        
        if severity in ['Critical', 'High']:
            strategies.extend([
                'Implement virtual patching',
                'Enable enhanced monitoring',
                'Consider access restrictions'
            ])
        
        if category == 'injection':
            strategies.extend([
                'Deploy WAF with custom rules',
                'Implement input sanitization',
                'Regular code reviews'
            ])
        elif category == 'information_disclosure':
            strategies.extend([
                'Review error handling',
                'Implement security headers',
                'Regular security assessments'
            ])
            
        return strategies
        
    def scan_finished(self):
        self.terminal.append_output("[✓] Scan completed!")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        # Final analysis with robust parsing
        findings = self._parse_scan_results()
        if not findings:
            self.terminal.append_output("[!] No findings detected or output could not be parsed.")
        self.vuln_panel.update_analysis(findings)
        self.update_interpreter(findings)
        # --- Save to database for history ---
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            ai_analysis = self.interpreter_text.toPlainText() if hasattr(self, 'interpreter_text') else ''
            scan_id = db.add_scan(
                tool_name="Nikto",
                target=self.current_target if self.current_target else (self.target_input.text() if hasattr(self, 'target_input') else 'Unknown'),
                status="Success",
                results=findings,
                ai_analysis=ai_analysis
            )
            self.terminal.append_output(f"[✓] Scan saved to database (ID: {scan_id})")
        except Exception as e:
            self.terminal.append_output(f"[!] Failed to save scan to database: {str(e)}")
        
    def _parse_scan_results(self):
        """Parse Nikto output into structured findings with enhanced robustness"""
        findings = []
        for line in self.scan_results:
            finding = self._parse_finding(line)
            if finding and finding.get('title'):
                findings.append(finding)
        # Sort findings by severity if available
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        findings.sort(key=lambda x: severity_order.get(x.get('severity', 'Low'), 4))
        return findings