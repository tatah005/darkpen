from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit, QTextEdit, QComboBox, QFrame, QSplitter, QTabWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont
import subprocess
from .cyberpunk_theme import COLORS, STYLES, LAYOUT

class SqlmapScanThread(QThread):
    output_received = pyqtSignal(str)
    scan_complete = pyqtSignal()

    def __init__(self, target, options):
        super().__init__()
        self.target = target
        self.options = options
        self.process = None

    def run(self):
        try:
            cmd = ['sqlmap', '-u', self.target, '--batch']
            if self.options.get('risk'):
                cmd.extend(['--risk', self.options['risk']])
            if self.options.get('level'):
                cmd.extend(['--level', self.options['level']])
            if self.options.get('tech'):  # e.g. "BEUSTQ"
                cmd.extend(['--technique', self.options['tech']])
            if self.options.get('dbs'):
                cmd.append('--dbs')
            if self.options.get('tables'):
                cmd.append('--tables')
            if self.options.get('dump'):
                cmd.append('--dump')
            self.output_received.emit(f"[*] Running sqlmap: {' '.join(cmd)}")
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            while True:
                output = self.process.stdout.readline()
                if output == '' and self.process.poll() is not None:
                    break
                if output:
                    self.output_received.emit(output.strip())
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

class SqlmapAIAnalysisPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        # AI Status bar (styled like Nmap)
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
        # Tabs
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

    def update_analysis(self, findings, attacks, defenses):
        self.ai_status.setText("🤖 AI Analysis Complete")
        self.findings_text.setText(findings)
        self.attack_text.setText(attacks)
        self.defense_text.setText(defenses)

    def reset(self):
        self.ai_status.setText("🤖 AI Ready")
        self.findings_text.clear()
        self.attack_text.clear()
        self.defense_text.clear()

class SqlmapPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.scan_thread = None
        self.scan_results = []
        self.current_target = None

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)
        # Main splitter
        splitter = QSplitter(Qt.Horizontal)
        # Left panel (styled QFrame)
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
        left_layout.setSpacing(8)
        # Target input
        target_layout = QHBoxLayout()
        target_label = QLabel("🎯 Target URL:")
        target_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 14px; font-weight: bold;")
        target_layout.addWidget(target_label)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("http://example.com/page.php?id=1")
        self.target_input.setStyleSheet(STYLES['input_fields'])
        target_layout.addWidget(self.target_input)
        left_layout.addLayout(target_layout)
        # Scan options
        options_label = QLabel("🔧 Scan Options:")
        options_label.setStyleSheet(f"color: {COLORS['text_primary']};")
        left_layout.addWidget(options_label)
        options_layout = QHBoxLayout()
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["1 (Default)", "2", "3"])
        self.risk_combo.setToolTip("Risk level: 1 (default), 2, 3")
        options_layout.addWidget(QLabel("Risk:"))
        options_layout.addWidget(self.risk_combo)
        self.level_combo = QComboBox()
        self.level_combo.addItems(["1 (Default)", "2", "3", "4", "5"])
        self.level_combo.setToolTip("Level: 1 (default) to 5 (most tests)")
        options_layout.addWidget(QLabel("Level:"))
        options_layout.addWidget(self.level_combo)
        self.tech_combo = QComboBox()
        self.tech_combo.addItems(["All", "B", "E", "U", "S", "T", "Q"])
        self.tech_combo.setToolTip("Injection techniques: B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline Query")
        options_layout.addWidget(QLabel("Tech:"))
        options_layout.addWidget(self.tech_combo)
        left_layout.addLayout(options_layout)
        # Checkboxes for common actions
        actions_layout = QHBoxLayout()
        self.dbs_btn = QPushButton("--dbs")
        self.dbs_btn.setCheckable(True)
        self.dbs_btn.setToolTip("Enumerate databases")
        actions_layout.addWidget(self.dbs_btn)
        self.tables_btn = QPushButton("--tables")
        self.tables_btn.setCheckable(True)
        self.tables_btn.setToolTip("Enumerate tables")
        actions_layout.addWidget(self.tables_btn)
        self.dump_btn = QPushButton("--dump")
        self.dump_btn.setCheckable(True)
        self.dump_btn.setToolTip("Dump table data")
        actions_layout.addWidget(self.dump_btn)
        left_layout.addLayout(actions_layout)
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("▶ Start Scan")
        self.start_button.setStyleSheet(STYLES['buttons'])
        self.start_button.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_button)
        self.stop_button = QPushButton("⏹ Stop")
        self.stop_button.setStyleSheet(STYLES['buttons'])
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.stop_button)
        left_layout.addLayout(button_layout)
        # Terminal label
        terminal_label = QLabel("🖥️ Scan Output")
        terminal_label.setStyleSheet(f"color: {COLORS['text_primary']}; font-size: 16px; font-weight: bold; margin-top: 10px;")
        left_layout.addWidget(terminal_label)
        # Terminal output
        self.terminal = QTextEdit()
        self.terminal.setReadOnly(True)
        self.terminal.setStyleSheet(STYLES['terminal'])
        self.terminal.setFont(QFont('Consolas', 10))
        left_layout.addWidget(self.terminal)
        splitter.addWidget(left_panel)
        # Right panel (AI analysis)
        self.ai_panel = SqlmapAIAnalysisPanel()
        splitter.addWidget(self.ai_panel)
        splitter.setSizes([600, 400])
        layout.addWidget(splitter)

    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.terminal.append("[!] Please enter a target URL")
            return
        self.current_target = target
        options = {
            'risk': self.risk_combo.currentText().split()[0],
            'level': self.level_combo.currentText().split()[0],
            'tech': self.tech_combo.currentText() if self.tech_combo.currentText() != "All" else None,
            'dbs': self.dbs_btn.isChecked(),
            'tables': self.tables_btn.isChecked(),
            'dump': self.dump_btn.isChecked()
        }
        self.terminal.append(f"[*] Starting sqlmap scan on: {target}")
        self.terminal.append(f"[*] Options: {options}")
        self.scan_results = []
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        if self.scan_thread is not None:
            try:
                self.scan_thread.output_received.disconnect()
                self.scan_thread.scan_complete.disconnect()
            except:
                pass
        self.scan_thread = SqlmapScanThread(target, options)
        self.scan_thread.output_received.connect(self.handle_output)
        self.scan_thread.scan_complete.connect(self.scan_finished)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.terminal.append("[!] Scan stopped by user")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def handle_output(self, output):
        if '[!]' in output or 'error' in output.lower():
            self.terminal.append(f'<span style="color: {COLORS["warning_red"]};">{output}</span>')
        else:
            self.terminal.append(output)
        self.scan_results.append(output)
        # AI analysis: findings, attack vectors, defenses
        findings, attacks, defenses = self._ai_analyze_sqlmap_output('\n'.join(self.scan_results))
        self.ai_panel.update_analysis(findings, attacks, defenses)

    def scan_finished(self):
        self.terminal.append("[✓] Scan completed!")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.ai_panel.ai_status.setText("🤖 AI Ready")
        # Save scan to database for history
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            # Compose results (basic)
            results = {'raw_output': '\n'.join(self.scan_results)}
            ai_analysis = self.ai_panel.findings_text.toPlainText()
            scan_id = db.add_scan(
                tool_name="SQLMap",
                target=self.current_target,
                status="Success",
                results=results,
                ai_analysis=ai_analysis
            )
            self.terminal.append(f"[✓] Scan saved to database (ID: {scan_id})")
        except Exception as e:
            self.terminal.append(f"[!] Failed to save scan to database: {str(e)}")

    def _ai_analyze_sqlmap_output(self, output):
        # Demo: look for SQLi findings, suggest attacks/defenses
        findings = []
        attacks = []
        defenses = []
        if "sql injection" in output.lower() or "vulnerable" in output.lower():
            findings.append("🚨 SQL Injection vulnerability detected!")
            attacks.append("• Use sqlmap to enumerate databases\n• Try manual payloads: ' OR '1'='1\n• Test for stacked queries")
            defenses.append("• Sanitize all user inputs\n• Use parameterized queries\n• Apply least privilege to DB users\n• Enable WAF for web apps")
        elif "no injection" in output.lower() or "not vulnerable" in output.lower():
            findings.append("✅ No SQL injection vulnerabilities found.")
            attacks.append("• Continue monitoring\n• Try different parameters or endpoints")
            defenses.append("• Review input validation regularly\n• Keep frameworks up to date")
        else:
            findings.append("No clear findings yet. Scan in progress or inconclusive.")
            attacks.append("• Await scan completion\n• Review results manually if needed")
            defenses.append("• Await scan completion\n• Review results manually if needed")
        return ('\n'.join(findings), '\n'.join(attacks), '\n'.join(defenses)) 