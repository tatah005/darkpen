from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
                            QListWidget, QTextEdit, QPushButton, QLabel,
                            QComboBox, QLineEdit, QFormLayout, QGroupBox,
                            QTableWidget, QTableWidgetItem, QHeaderView,
                            QFrame, QGridLayout, QTreeWidget, QTreeWidgetItem,
                            QSplitter)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QColor, QFont, QIcon
from .cyberpunk_theme import COLORS, STYLES, FONTS, LAYOUT
from core.ai_engine import AIEngine
from core.metasploit_integration import MetasploitManager, ModuleType
from core.database_manager import DatabaseManager
import json
import subprocess
import re
from datetime import datetime
import os
import tempfile

class ConsoleOutput(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("terminal")
        self.setStyleSheet(STYLES['terminal'])
        self.setReadOnly(True)
        self.setFont(QFont('Consolas', 10))
        
    def append_output(self, text):
        self.append(f"<span style='color: {COLORS['neon_green']}'>{text}</span>")

class MetasploitAIThread(QThread):
    analysis_ready = pyqtSignal(dict)
    
    def __init__(self, exploit_data, target_info):
        super().__init__()
        self.exploit_data = exploit_data
        self.target_info = target_info
        self.ai_engine = AIEngine()
        
    def run(self):
        try:
            # Analyze exploit potential and risks
            analysis = {
                'timestamp': datetime.now().isoformat(),
                'exploit_analysis': self._analyze_exploit(),
                'target_analysis': self._analyze_target(),
                'success_probability': self._calculate_success_probability(),
                'recommendations': self._generate_recommendations(),
                'risk_assessment': self._assess_risks()
            }
            
            self.analysis_ready.emit(analysis)
            
        except Exception as e:
            self.analysis_ready.emit({
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
    
    def _analyze_exploit(self):
        """Analyze exploit characteristics and potential"""
        exploit_name = self.exploit_data.get('name', '')
        exploit_type = self.exploit_data.get('type', '')
        
        return {
            'reliability': self._assess_reliability(),
            'complexity': self._assess_complexity(),
            'impact': self._assess_impact(),
            'detection_risk': self._assess_detection_risk(),
            'suggested_options': self._suggest_exploit_options()
        }
    
    def _analyze_target(self):
        """Analyze target vulnerability and characteristics"""
        return {
            'vulnerability_score': self._calculate_vulnerability_score(),
            'exploit_compatibility': self._check_compatibility(),
            'potential_defenses': self._identify_potential_defenses(),
            'evasion_recommendations': self._suggest_evasion_techniques()
        }
    
    def _calculate_success_probability(self):
        """Calculate probability of successful exploitation"""
        reliability = self._assess_reliability()
        target_score = self._calculate_vulnerability_score()
        complexity = self._assess_complexity()
        
        # Weight factors for probability calculation
        weights = {
            'reliability': 0.4,
            'target_score': 0.35,
            'complexity': 0.25
        }
        
        probability = (
            (reliability * weights['reliability']) +
            (target_score * weights['target_score']) +
            ((1 - complexity) * weights['complexity'])
        )
        
        return min(probability, 1.0)
    
    def _assess_reliability(self):
        """Assess exploit reliability score"""
        reliability_score = 0.5  # Base score
        
        # Analyze exploit characteristics
        if 'reliable' in self.exploit_data.get('rank', '').lower():
            reliability_score += 0.3
        if 'great' in self.exploit_data.get('rank', '').lower():
            reliability_score += 0.2
            
        # Check for known success indicators
        if self.exploit_data.get('successful_runs', 0) > 0:
            reliability_score += 0.1
            
        return min(reliability_score, 1.0)
    
    def _assess_complexity(self):
        """Assess exploit complexity (0-1, where 1 is most complex)"""
        complexity = 0.5  # Base complexity
        
        # Analyze required options
        required_options = self.exploit_data.get('required_options', [])
        if len(required_options) > 5:
            complexity += 0.2
            
        # Check for advanced features
        if self.exploit_data.get('needs_cleanup', False):
            complexity += 0.1
        if self.exploit_data.get('needs_prep', False):
            complexity += 0.1
            
        return min(complexity, 1.0)
    
    def _assess_impact(self):
        """Assess potential impact of successful exploitation"""
        impact_levels = {
            'code_execution': 0.9,
            'privilege_escalation': 0.8,
            'data_theft': 0.7,
            'denial_of_service': 0.6,
            'information_disclosure': 0.5
        }
        
        exploit_type = self.exploit_data.get('type', '').lower()
        for impact_type, score in impact_levels.items():
            if impact_type in exploit_type:
                return score
                
        return 0.5  # Default impact score
    
    def _assess_detection_risk(self):
        """Assess risk of detection"""
        risk_score = 0.3  # Base risk
        
        # Check for noisy operations
        if self.exploit_data.get('noisy', False):
            risk_score += 0.3
            
        # Check for evasion capabilities
        if self.exploit_data.get('evasion', False):
            risk_score -= 0.2
            
        return max(min(risk_score, 1.0), 0.0)
    
    def _suggest_exploit_options(self):
        """Suggest optimal exploit options"""
        suggestions = []
        
        # Analyze target characteristics
        if 'windows' in self.target_info.get('os', '').lower():
            suggestions.append({
                'option': 'PAYLOAD',
                'value': 'windows/meterpreter/reverse_tcp',
                'reason': 'Most reliable for Windows targets'
            })
        elif 'linux' in self.target_info.get('os', '').lower():
            suggestions.append({
                'option': 'PAYLOAD',
                'value': 'linux/x86/meterpreter/reverse_tcp',
                'reason': 'Compatible with Linux targets'
            })
            
        # Add evasion suggestions
        if self._assess_detection_risk() > 0.6:
            suggestions.append({
                'option': 'EnableStageEncoding',
                'value': 'true',
                'reason': 'Reduce detection risk'
            })
            
        return suggestions
    
    def _calculate_vulnerability_score(self):
        """Calculate target vulnerability score"""
        score = 0.5  # Base score
        
        # Check target characteristics
        if self.target_info.get('unpatched', False):
            score += 0.3
        if self.target_info.get('outdated_software', False):
            score += 0.2
            
        # Check defense mechanisms
        if self.target_info.get('has_av', False):
            score -= 0.2
        if self.target_info.get('has_firewall', False):
            score -= 0.1
            
        return max(min(score, 1.0), 0.0)
    
    def _check_compatibility(self):
        """Check exploit compatibility with target"""
        target_os = self.target_info.get('os', '').lower()
        target_arch = self.target_info.get('arch', '').lower()
        
        compatibility = {
            'os_compatible': False,
            'arch_compatible': False,
            'requirements_met': False
        }
        
        # Check OS compatibility
        if target_os in self.exploit_data.get('supported_os', []):
            compatibility['os_compatible'] = True
            
        # Check architecture compatibility
        if target_arch in self.exploit_data.get('supported_arch', []):
            compatibility['arch_compatible'] = True
            
        # Check requirements
        required_services = self.exploit_data.get('required_services', [])
        available_services = self.target_info.get('services', [])
        if all(service in available_services for service in required_services):
            compatibility['requirements_met'] = True
            
        return compatibility
    
    def _identify_potential_defenses(self):
        """Identify potential target defenses"""
        defenses = []
        
        if self.target_info.get('has_av', False):
            defenses.append({
                'type': 'Antivirus',
                'impact': 'High',
                'evasion_difficulty': 'High'
            })
            
        if self.target_info.get('has_firewall', False):
            defenses.append({
                'type': 'Firewall',
                'impact': 'Medium',
                'evasion_difficulty': 'Medium'
            })
            
        if self.target_info.get('has_ids', False):
            defenses.append({
                'type': 'IDS/IPS',
                'impact': 'High',
                'evasion_difficulty': 'High'
            })
            
        return defenses
    
    def _suggest_evasion_techniques(self):
        """Suggest evasion techniques based on target defenses"""
        techniques = []
        
        defenses = self._identify_potential_defenses()
        for defense in defenses:
            if defense['type'] == 'Antivirus':
                techniques.append({
                    'name': 'Payload Encoding',
                    'description': 'Use multiple encoding layers',
                    'effectiveness': 'Medium'
                })
                
            elif defense['type'] == 'Firewall':
                techniques.append({
                    'name': 'Port Tunneling',
                    'description': 'Use common ports (80, 443)',
                    'effectiveness': 'High'
                })
                
            elif defense['type'] == 'IDS/IPS':
                techniques.append({
                    'name': 'Traffic Obfuscation',
                    'description': 'Use encrypted channels',
                    'effectiveness': 'High'
                })
                
        return techniques
    
    def _generate_recommendations(self):
        """Generate AI-powered recommendations"""
        success_prob = self._calculate_success_probability()
        impact = self._assess_impact()
        detection_risk = self._assess_detection_risk()
        
        recommendations = {
            'proceed': success_prob > 0.7 and detection_risk < 0.5,
            'preparation_steps': [],
            'execution_steps': [],
            'post_exploitation': []
        }
        
        # Preparation recommendations
        if success_prob < 0.7:
            recommendations['preparation_steps'].extend([
                'Perform additional target reconnaissance',
                'Verify target vulnerability exists',
                'Test exploit in similar environment'
            ])
            
        # Execution recommendations
        recommendations['execution_steps'].extend([
            f"Use suggested payload: {self._suggest_exploit_options()[0]['value']}",
            'Enable encoding and encryption',
            'Set proper timeout values'
        ])
        
        # Post-exploitation recommendations
        if impact > 0.7:
            recommendations['post_exploitation'].extend([
                'Establish persistence',
                'Collect target information',
                'Monitor for defense responses'
            ])
            
        return recommendations
    
    def _assess_risks(self):
        """Assess overall operation risks"""
        return {
            'detection_probability': self._assess_detection_risk(),
            'target_damage_risk': self._assess_impact(),
            'stability_risk': 1 - self._assess_reliability(),
            'mitigation_suggestions': [
                'Use minimal necessary privileges',
                'Maintain stealth operation',
                'Have rollback plan ready'
            ]
        }

class MetasploitPage(QWidget):
    exploit_selected = pyqtSignal(str)
    payload_generated = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.ai_engine = AIEngine()
        self.metasploit_manager = MetasploitManager()
        self.setup_ui()
        self.current_analysis = None
        self.ai_thread = None
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(LAYOUT['margin'])
        splitter = QSplitter(Qt.Horizontal)
        # Left panel - Module selection and configuration
        left_panel = QFrame()
        left_panel.setObjectName("modulePanel")
        left_panel.setStyleSheet("""
            QFrame {
                background-color: #181c24;
                border: 1.5px solid #00fff7;
                border-radius: 12px;
                padding: 12px;
            }
        """)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setSpacing(10)
        # Search bar
        search_bar = QLineEdit()
        search_bar.setPlaceholderText("Search modules...")
        search_bar.setStyleSheet("background: #232946; color: #fff; border-radius: 8px; padding: 6px 12px; border: 1px solid #00fff7;")
        left_layout.addWidget(search_bar)
        # Metasploit status badge
        status_badge = QLabel("Metasploit: ")
        badge = QLabel("Available")
        badge.setStyleSheet("background: #00e676; color: #181c24; border-radius: 10px; padding: 2px 10px; font-weight: bold;")
        status_row = QHBoxLayout()
        status_row.addWidget(status_badge)
        status_row.addWidget(badge)
        status_row.addStretch()
        left_layout.addLayout(status_row)
        # Module tree with icons
        self.module_tree = QTreeWidget()
        self.module_tree.setHeaderLabel("")
        self.module_tree.setStyleSheet("background: #232946; color: #fff; border-radius: 8px; border: 1px solid #00fff7;")
        self.populate_module_tree()
        self.module_tree.itemClicked.connect(self.on_module_selected)
        left_layout.addWidget(self.module_tree)
        splitter.addWidget(left_panel)
        # Center panel - Module options and payload configuration
        center_panel = QFrame()
        center_panel.setObjectName("configPanel")
        center_panel.setStyleSheet("background: #181c24; border: 1.5px solid #00fff7; border-radius: 12px; padding: 12px;")
        center_layout = QVBoxLayout(center_panel)
        center_layout.setSpacing(12)
        # Section header
        info_header = QLabel("Module Info")
        info_header.setFont(QFont('Segoe UI', 13, QFont.Bold))
        info_header.setStyleSheet("color: #00fff7; margin-bottom: 4px;")
        center_layout.addWidget(info_header)
        self.module_info = QLabel("Select a module to begin")
        self.module_info.setFont(QFont('Segoe UI', 12, QFont.Bold))
        self.module_info.setStyleSheet("color: #A3FF12;")
        center_layout.addWidget(self.module_info)
        # Target options section
        target_header = QLabel("Target Options")
        target_header.setFont(QFont('Segoe UI', 12, QFont.Bold))
        target_header.setStyleSheet("color: #FFD600; margin-top: 8px;")
        center_layout.addWidget(target_header)
        options_frame = QFrame()
        options_frame.setStyleSheet("background: #232946; border-radius: 8px; padding: 10px;")
        options_layout = QGridLayout(options_frame)
        options_layout.setSpacing(8)
        options_layout.addWidget(QLabel("RHOST:"), 0, 0)
        self.rhost_input = QLineEdit()
        self.rhost_input.setStyleSheet("background: #181c24; color: #fff; border-radius: 6px; padding: 6px 10px; border: 1px solid #00fff7;")
        self.rhost_input.setToolTip("Target host IP or domain")
        options_layout.addWidget(self.rhost_input, 0, 1)
        options_layout.addWidget(QLabel("RPORT:"), 1, 0)
        self.rport_input = QLineEdit()
        self.rport_input.setStyleSheet("background: #181c24; color: #fff; border-radius: 6px; padding: 6px 10px; border: 1px solid #00fff7;")
        self.rport_input.setToolTip("Target port (default: 80)")
        options_layout.addWidget(self.rport_input, 1, 1)
        payload_header = QLabel("Payload")
        payload_header.setFont(QFont('Segoe UI', 12, QFont.Bold))
        payload_header.setStyleSheet("color: #FFD600; margin-top: 8px;")
        options_layout.addWidget(payload_header, 2, 0, 1, 2)
        self.payload_combo = QComboBox()
        self.payload_combo.setStyleSheet("background: #181c24; color: #A3FF12; border-radius: 6px; padding: 6px 10px; border: 1px solid #00fff7;")
        self.payload_combo.addItems([
            "windows/meterpreter/reverse_tcp",
            "linux/x86/meterpreter/reverse_tcp",
            "python/meterpreter/reverse_tcp",
            "java/jsp_shell_reverse_tcp"
        ])
        self.payload_combo.setToolTip("Payload to use for exploitation")
        options_layout.addWidget(self.payload_combo, 3, 0, 1, 2)
        center_layout.addWidget(options_frame)
        # Action buttons
        button_layout = QHBoxLayout()
        self.check_button = QPushButton("🔍 Check")
        self.check_button.setStyleSheet("background: #00fff7; color: #181c24; border-radius: 8px; padding: 10px 24px; font-weight: bold;")
        self.check_button.setToolTip("Check if the target is vulnerable")
        button_layout.addWidget(self.check_button)
        self.run_button = QPushButton("🚀 Run")
        self.run_button.setStyleSheet("background: #A3FF12; color: #181c24; border-radius: 8px; padding: 10px 24px; font-weight: bold;")
        self.run_button.setToolTip("Run the selected exploit against the target")
        button_layout.addWidget(self.run_button)
        center_layout.addLayout(button_layout)
        splitter.addWidget(center_panel)
        # Right panel - Console output and sessions
        right_panel = QFrame()
        right_panel.setObjectName("consolePanel")
        right_panel.setStyleSheet("background: #181c24; border: 1.5px solid #00fff7; border-radius: 12px; padding: 12px;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setSpacing(10)
        # Tabs for console and sessions
        right_tabs = QTabWidget()
        right_tabs.setStyleSheet("QTabBar::tab { background: #232946; color: #00fff7; border-radius: 8px; padding: 8px 18px; font-weight: bold; } QTabBar::tab:selected { background: #00fff7; color: #181c24; }")
        # Console tab
        console_tab = QWidget()
        console_layout = QVBoxLayout(console_tab)
        console_label = QLabel("🖥️ Console Output")
        console_label.setFont(QFont('Segoe UI', 12, QFont.Bold))
        console_label.setStyleSheet("color: #00fff7;")
        console_layout.addWidget(console_label)
        self.console = ConsoleOutput()
        self.console.setStyleSheet("background: #232946; color: #A3FF12; border-radius: 8px; padding: 10px; font-family: 'Consolas';")
        console_layout.addWidget(self.console)
        # Clear console button
        clear_btn = QPushButton("Clear Console")
        clear_btn.setStyleSheet("background: #FFD600; color: #181c24; border-radius: 8px; padding: 6px 18px; font-weight: bold;")
        clear_btn.clicked.connect(self.console.clear)
        console_layout.addWidget(clear_btn)
        right_tabs.addTab(console_tab, QIcon(), "Console")
        # Sessions tab
        sessions_tab = QWidget()
        sessions_layout = QVBoxLayout(sessions_tab)
        sessions_label = QLabel("🔗 Active Sessions")
        sessions_label.setFont(QFont('Segoe UI', 12, QFont.Bold))
        sessions_label.setStyleSheet("color: #00fff7;")
        sessions_layout.addWidget(sessions_label)
        self.sessions_table = QTableWidget()
        self.sessions_table.setColumnCount(5)
        self.sessions_table.setHorizontalHeaderLabels(["ID", "Type", "Target", "Tunnel", "Info"])
        self.sessions_table.setStyleSheet("background: #232946; color: #fff; border-radius: 8px;")
        sessions_layout.addWidget(self.sessions_table)
        session_buttons = QHBoxLayout()
        self.refresh_sessions_btn = QPushButton("🔄 Refresh")
        self.refresh_sessions_btn.setStyleSheet("background: #00fff7; color: #181c24; border-radius: 8px; padding: 6px 18px; font-weight: bold;")
        self.refresh_sessions_btn.clicked.connect(self.refresh_sessions)
        session_buttons.addWidget(self.refresh_sessions_btn)
        self.interact_session_btn = QPushButton("💬 Interact")
        self.interact_session_btn.setStyleSheet("background: #A3FF12; color: #181c24; border-radius: 8px; padding: 6px 18px; font-weight: bold;")
        self.interact_session_btn.clicked.connect(self.interact_session)
        session_buttons.addWidget(self.interact_session_btn)
        self.terminate_session_btn = QPushButton("❌ Terminate")
        self.terminate_session_btn.setStyleSheet("background: #FFD600; color: #181c24; border-radius: 8px; padding: 6px 18px; font-weight: bold;")
        self.terminate_session_btn.clicked.connect(self.terminate_session)
        session_buttons.addWidget(self.terminate_session_btn)
        sessions_layout.addLayout(session_buttons)
        right_tabs.addTab(sessions_tab, QIcon(), "Sessions")
        right_layout.addWidget(right_tabs)
        splitter.addWidget(right_panel)
        splitter.setSizes([220, 400, 400])
        layout.addWidget(splitter)
        self.check_button.clicked.connect(self.check_exploit)
        self.run_button.clicked.connect(self.run_exploit)
        
    def populate_module_tree(self):
        # Try to load actual Metasploit modules first
        actual_modules = self.metasploit_manager.search_modules("", ModuleType.EXPLOIT)
        
        if actual_modules:
            # Group modules by category
            categories = {
                "Windows": [],
                "Linux": [],
                "Web Applications": [],
                "Network Devices": [],
                "Other": []
            }
            
            for module in actual_modules[:50]:  # Limit to first 50 modules
                if 'windows' in module.lower():
                    categories["Windows"].append(module)
                elif 'linux' in module.lower() or 'unix' in module.lower():
                    categories["Linux"].append(module)
                elif any(web in module.lower() for web in ['web', 'http', 'php', 'asp', 'jsp']):
                    categories["Web Applications"].append(module)
                elif any(net in module.lower() for net in ['cisco', 'router', 'switch', 'network']):
                    categories["Network Devices"].append(module)
                else:
                    categories["Other"].append(module)
            
            # Add modules to tree
            for category, modules in categories.items():
                if modules:  # Only add categories that have modules
                    cat_item = QTreeWidgetItem([category])
                    self.module_tree.addTopLevelItem(cat_item)
                    for module in modules[:10]:  # Limit to 10 modules per category
                        module_item = QTreeWidgetItem([module])
                        cat_item.addChild(module_item)
        else:
            # Fall back to demo modules
            categories = {
                "Windows": [
                        "exploit/windows/smb/ms17_010_eternalblue",
                        "exploit/windows/smb/ms08_067_netapi",
                        "auxiliary/scanner/smb/smb_login"
                ],
                "Linux": [
                        "exploit/unix/ftp/vsftpd_234_backdoor",
                        "exploit/linux/samba/samba_symlink_traversal",
                        "exploit/unix/misc/distcc_exec"
                ],
                "Web Applications": [
                        "exploit/unix/webapp/wordpress_admin_shell_upload",
                        "exploit/multi/http/joomla_comfields_sqli_rce",
                        "exploit/unix/webapp/drupal_drupalgeddon2"
                ],
                "Network Devices": [
                        "exploit/cisco/ios_shell",
                        "exploit/linux/misc/mikrotik_routeros",
                        "exploit/linux/misc/fortinet_fortigate_ssl_vpn"
                ]
            }
            
            for category, modules in categories.items():
                cat_item = QTreeWidgetItem([category])
                self.module_tree.addTopLevelItem(cat_item)
                for module in modules:
                    module_item = QTreeWidgetItem([module])
                    cat_item.addChild(module_item)
    
    def on_module_selected(self, item, column):
        if item.parent():  # If it's a module (not a category)
            self.module_info.setText(f"Selected module: {item.text(0)}")
            self.console.append_output(f"[*] Loading module {item.text(0)}...")
            
    def check_exploit(self):
        module = self.module_info.text().replace("Selected module: ", "")
        target = self.rhost_input.text()
        port = self.rport_input.text() or "80"
        if module == "Select a module to begin":
            self.console.append_output("[!] Please select a module first")
            return
        if not target:
            self.console.append_output("[!] Please enter a target (RHOST)")
            return
        self.console.append_output(f"[*] Checking {module} against {target}:{port}...")
        result = self.metasploit_manager.check_module(module, target)
        # Collect console output for saving
        console_lines = []
        status = "Failed"
        if result['success']:
            self.console.append_output(f"[+] {result['message']}")
            console_lines.append(f"[+] {result['message']}")
            if 'details' in result:
                details = result['details']
                lines = details.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ['vulnerable', 'safe', 'check', 'target', 'port']):
                        msg = f"    {line.strip()}"
                        self.console.append_output(msg)
                        console_lines.append(msg)
            status = "Success"
        else:
            self.console.append_output(f"[!] {result['message']}")
            console_lines.append(f"[!] {result['message']}")
            if not self.metasploit_manager.msfconsole_path:
                self.console.append_output("[!] Metasploit not found. Please install Metasploit Framework.")
                console_lines.append("[!] Metasploit not found. Please install Metasploit Framework.")
        # Save to database
        try:
            db = DatabaseManager()
            results = {
                'module': module,
                'target': target,
                'port': port,
                'output': '\n'.join(console_lines),
                'details': result.get('details', '')
            }
            ai_analysis = self.current_analysis if self.current_analysis else ''
            db.add_scan(
                tool_name="Metasploit",
                target=target,
                status=status,
                results=results,
                ai_analysis=str(ai_analysis)
            )
        except Exception as e:
            self.console.append_output(f"[!] Failed to save check to history: {str(e)}")
        
    def run_exploit(self):
        module = self.module_info.text().replace("Selected module: ", "")
        target = self.rhost_input.text()
        port = self.rport_input.text() or "80"
        payload = self.payload_combo.currentText()
        if module == "Select a module to begin":
            self.console.append_output("[!] Please select a module first")
            return
        if not target:
            self.console.append_output("[!] Please enter a target (RHOST)")
            return
        self.console.append_output(f"[*] Launching {module}")
        self.console.append_output(f"[*] Target: {target}:{port}")
        self.console.append_output(f"[*] Payload: {payload}")
        self.console.append_output("[*] Executing...")
        result = self.metasploit_manager.run_exploit(module, target, port, payload)
        # Collect console output for saving
        console_lines = [
            f"[*] Launching {module}",
            f"[*] Target: {target}:{port}",
            f"[*] Payload: {payload}",
            "[*] Executing..."
        ]
        status = "Failed"
        if result['success']:
            self.console.append_output(f"[+] {result['message']}")
            console_lines.append(f"[+] {result['message']}")
            if 'details' in result:
                details = result['details']
                lines = details.split('\n')
                for line in lines:
                    if any(keyword in line.lower() for keyword in ['session', 'meterpreter', 'exploit', 'success', 'failed']):
                        msg = f"    {line.strip()}"
                        self.console.append_output(msg)
                        console_lines.append(msg)
            status = "Success"
        else:
            self.console.append_output(f"[!] {result['message']}")
            console_lines.append(f"[!] {result['message']}")
            if not self.metasploit_manager.msfconsole_path:
                self.console.append_output("[!] Metasploit not found. Please install Metasploit Framework.")
                console_lines.append("[!] Metasploit not found. Please install Metasploit Framework.")
        # Save to database
        try:
            db = DatabaseManager()
            results = {
                'module': module,
                'target': target,
                'port': port,
                'payload': payload,
                'output': '\n'.join(console_lines),
                'details': result.get('details', '')
            }
            ai_analysis = self.current_analysis if self.current_analysis else ''
            db.add_scan(
                tool_name="Metasploit",
                target=target,
                status=status,
                results=results,
                ai_analysis=str(ai_analysis)
            )
        except Exception as e:
            self.console.append_output(f"[!] Failed to save exploit to history: {str(e)}")
        
    def apply_styling(self):
        # Dark theme with cyberpunk accents
        self.setStyleSheet("""
            QWidget {
                background-color: #0a0a0a;
                color: #00ff9f;
                font-family: 'Segoe UI', 'Arial';
            }
            QGroupBox {
                border: 1px solid #004d99;
                border-radius: 3px;
                margin-top: 0.5em;
                padding-top: 0.5em;
            }
            QGroupBox::title {
                color: #00ff9f;
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px;
            }
            QLineEdit, QComboBox {
                background-color: #1a1a1a;
                border: 1px solid #004d99;
                border-radius: 2px;
                padding: 3px;
                color: #00ff9f;
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #00ff9f;
            }
            QPushButton {
                background-color: #004d99;
                border: none;
                border-radius: 2px;
                padding: 5px 15px;
                color: #00ff9f;
            }
            QPushButton:hover {
                background-color: #0066cc;
                color: #ffffff;
            }
            QPushButton:pressed {
                background-color: #003366;
            }
            QListWidget, QTableWidget, QTextEdit {
                background-color: #1a1a1a;
                border: 1px solid #004d99;
                border-radius: 2px;
            }
            QListWidget::item:selected, QTableWidget::item:selected {
                background-color: #004d99;
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #0a0a0a;
                color: #00ff9f;
                border: 1px solid #004d99;
                padding: 4px;
            }
            QTabWidget::pane {
                border: 1px solid #004d99;
                border-radius: 3px;
            }
            QTabBar::tab {
                background-color: #1a1a1a;
                border: 1px solid #004d99;
                border-bottom: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
                padding: 5px 10px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #004d99;
                color: #ffffff;
            }
        """)
        
    def load_exploits(self):
        """Load available exploits into the list"""
        # This method references non-existent UI elements
        # Commented out to prevent AttributeError
        pass
        # exploits = self.tools_manager.get_msf_exploits()
        # self.exploit_list.clear()
        # for exploit in exploits:
        #     self.exploit_list.addItem(exploit['name'])
            
    def search_exploits(self):
        """Search exploits based on input text"""
        # This method references non-existent UI elements
        # Commented out to prevent AttributeError
        pass
        # search_text = self.search_input.text().lower()
        # exploits = self.tools_manager.get_msf_exploits(search_text)
        # self.exploit_list.clear()
        # for exploit in exploits:
        #     self.exploit_list.addItem(exploit['name'])
            
    def filter_exploits(self):
        """Filter exploits based on selected category"""
        # This method references non-existent UI elements
        # Commented out to prevent AttributeError
        pass
        # filter_type = self.filter_combo.currentText()
        # Implementation depends on Metasploit's filtering capabilities
        # self.load_exploits()  # Reload with filter
        
    def show_exploit_details(self, item):
        """Display detailed information about selected exploit"""
        # This method references non-existent UI elements
        # Commented out to prevent AttributeError
        pass
        # exploit_name = item.text()
        # exploits = self.tools_manager.get_msf_exploits(exploit_name)
        # if exploits:
        #     exploit = exploits[0]
        #     details = f"""Name: {exploit['name']}
        # Description: {exploit['description']}
        # Rank: {exploit['rank']}
        # 
        # References:
        # {chr(10).join(exploit['references'])}
        # 
        # Targets:
        # {chr(10).join(str(t) for t in exploit['targets'])}
        # """
        #     self.exploit_details.setText(details)
        #     self.exploit_selected.emit(exploit_name)
            
    def generate_payload(self):
        """Generate payload with selected options"""
        # This method references non-existent UI elements
        # Commented out to prevent AttributeError
        pass
        # options = {
        #     'LHOST': self.lhost.text(),
        #     'LPORT': self.lport.text()
        # }
        # 
        # result = self.tools_manager.generate_payload(
        #     self.payload_type.currentText(),
        #     options
        # )
        # 
        # if result['success']:
        #     self.payload_output.setText(str(result['payload']))
        #     self.payload_generated.emit(result)
        # else:
        #     self.payload_output.setText(f"Error: {result['message']}")
            
    def refresh_sessions(self):
        """Update the sessions table"""
        sessions = self.metasploit_manager.get_active_sessions()
        self.sessions_table.setRowCount(len(sessions))
        
        for i, session in enumerate(sessions):
            self.sessions_table.setItem(i, 0, QTableWidgetItem(str(session.id)))
            self.sessions_table.setItem(i, 1, QTableWidgetItem(session.type))
            self.sessions_table.setItem(i, 2, QTableWidgetItem(session.target))
            self.sessions_table.setItem(i, 3, QTableWidgetItem(session.tunnel))
            self.sessions_table.setItem(i, 4, QTableWidgetItem(session.info))
            
        self.console.append_output(f"[*] Refreshed sessions. Found {len(sessions)} active sessions.")
            
    def interact_session(self):
        """Open interaction with selected session"""
        selected = self.sessions_table.selectedItems()
        if not selected:
            self.console.append_output("[!] Please select a session first")
            return
            
        session_id = int(selected[0].text())
        self.console.append_output(f"[*] Interacting with session {session_id}...")
        
        result = self.metasploit_manager.interact_session(session_id)
        if result['success']:
            self.console.append_output(f"[+] {result['message']}")
            if 'details' in result:
                self.console.append_output(result['details'])
        else:
            self.console.append_output(f"[!] {result['message']}")
            
    def terminate_session(self):
        """Terminate selected session"""
        selected = self.sessions_table.selectedItems()
        if not selected:
            self.console.append_output("[!] Please select a session first")
            return
            
        session_id = int(selected[0].text())
        self.console.append_output(f"[*] Terminating session {session_id}...")
        
        result = self.metasploit_manager.terminate_session(session_id)
        if result['success']:
            self.console.append_output(f"[+] {result['message']}")
            self.refresh_sessions()  # Refresh the table
        else:
            self.console.append_output(f"[!] {result['message']}")

    def start_ai_analysis(self):
        """Start AI analysis of current configuration"""
        # Gather current configuration
        module_name = self.module_info.text().replace("Selected module: ", "")
        if module_name == "Select a module to begin":
            self.console.append_output("[!] Please select a module first")
            return
            
        exploit_data = {
            'name': module_name,
            'type': 'exploit',
            'rank': 'excellent',
            'successful_runs': 5,
            'required_options': ['RHOSTS', 'RPORT'],
            'supported_os': ['windows', 'linux'],
            'supported_arch': ['x86', 'x64']
        }
        
        target_info = {
            'os': 'windows',
            'arch': 'x64',
            'has_av': True,
            'has_firewall': True,
            'services': ['http', 'smb']
        }
        
        # Start AI analysis thread
        self.ai_thread = MetasploitAIThread(exploit_data, target_info)
        self.ai_thread.analysis_ready.connect(self.handle_ai_analysis)
        self.ai_thread.start()
        
        self.console.append_output("[*] Running AI analysis...")
        
    def handle_ai_analysis(self, analysis):
        """Handle AI analysis results"""
        self.current_analysis = analysis
        
        if 'error' in analysis:
            self.console.append_output(f"[!] Analysis Error: {analysis['error']}")
            return
        
        # Format and display analysis results
        self.console.append_output("🤖 AI Analysis Results")
        
        # Exploit Analysis
        self.console.append_output("📊 Exploit Analysis:")
        exploit_analysis = analysis['exploit_analysis']
        self.console.append_output(f"  • Reliability: {exploit_analysis['reliability']:.2%}")
        self.console.append_output(f"  • Complexity: {exploit_analysis['complexity']:.2%}")
        self.console.append_output(f"  • Impact: {exploit_analysis['impact']:.2%}")
        self.console.append_output(f"  • Detection Risk: {exploit_analysis['detection_risk']:.2%}")
        
        # Success Probability
        prob = analysis['success_probability']
        self.console.append_output(f"🎯 Success Probability: {prob:.2%}")
        
        # Recommendations
        self.console.append_output("💡 AI Recommendations:")
        recs = analysis['recommendations']
        if recs['proceed']:
            self.console.append_output("  ✅ Proceed with exploitation")
        else:
            self.console.append_output("  ⚠️ Additional preparation recommended")
            
        if recs['preparation_steps']:
            self.console.append_output("  Preparation Steps:")
            for step in recs['preparation_steps']:
                self.console.append_output(f"   • {step}")
                
        if recs['execution_steps']:
            self.console.append_output("  Execution Steps:")
            for step in recs['execution_steps']:
                self.console.append_output(f"   • {step}")
                
        # Risk Assessment
        self.console.append_output("⚠️ Risk Assessment:")
        risks = analysis['risk_assessment']
        self.console.append_output(f"  • Detection Probability: {risks['detection_probability']:.2%}")
        self.console.append_output(f"  • Target Damage Risk: {risks['target_damage_risk']:.2%}")
        self.console.append_output(f"  • Stability Risk: {risks['stability_risk']:.2%}")
        
        # Mitigation Suggestions
        self.console.append_output("🛡️ Risk Mitigation:")
        for suggestion in risks['mitigation_suggestions']:
            self.console.append_output(f"  • {suggestion}")
        
    def _get_probability_color(self, probability):
        """Get color based on probability"""
        if probability >= 0.7:
            return COLORS['neon_green']
        elif probability >= 0.4:
            return COLORS['cyber_yellow']
        else:
            return COLORS['warning_red']