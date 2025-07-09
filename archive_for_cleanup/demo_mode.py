#!/usr/bin/env python3
"""
DarkPen Demo Mode - Shows the interface without requiring security tools
Perfect for supervisors who want to see the UI without full setup
"""

import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QVBoxLayout, QWidget, QTextEdit, QPushButton, QLabel, QHBoxLayout, QLineEdit, QComboBox, QMessageBox
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont, QIcon

class DemoNmapPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("🔍 Nmap Scanner - Demo Mode")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        # Demo notice
        notice = QLabel("⚠️ This is demo mode. No actual scanning will be performed.")
        notice.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(notice)
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit("example.com")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        # Scan type
        scan_layout = QHBoxLayout()
        scan_layout.addWidget(QLabel("Scan Type:"))
        self.scan_type = QComboBox()
        self.scan_type.addItems(["Quick Scan", "Full Scan", "Intense Scan", "Vulnerability Scan"])
        scan_layout.addWidget(self.scan_type)
        layout.addLayout(scan_layout)
        
        # Start button
        self.start_btn = QPushButton("🚀 Start Demo Scan")
        self.start_btn.clicked.connect(self.start_demo_scan)
        layout.addWidget(self.start_btn)
        
        # Results area
        self.results = QTextEdit()
        self.results.setPlaceholderText("Scan results will appear here...")
        layout.addWidget(self.results)
        
        self.setLayout(layout)
    
    def start_demo_scan(self):
        self.results.clear()
        self.start_btn.setEnabled(False)
        self.start_btn.setText("⏳ Scanning...")
        
        # Simulate scan progress
        demo_results = f"""
🎯 Demo Scan Results for {self.target_input.text()}

📊 Scan Type: {self.scan_type.currentText()}
⏱️ Duration: 2.5 seconds
🔍 Status: Completed

📋 Discovered Services:
├── Port 22/tcp: SSH (OpenSSH 8.2p1)
├── Port 80/tcp: HTTP (Apache 2.4.41)
├── Port 443/tcp: HTTPS (Apache 2.4.41)
└── Port 3306/tcp: MySQL (MySQL 8.0.26)

🤖 AI Analysis:
├── Overall Risk Level: Medium (0.45)
├── Attack Surface: Moderate
├── Critical Findings: 1
└── Recommendations: 
    - Secure SSH configuration
    - Update Apache to latest version
    - Review MySQL access controls

🔒 Vulnerabilities Found:
└── Medium: Default SSH configuration
    - Description: SSH service uses default settings
    - Recommendation: Harden SSH configuration

✅ Demo completed successfully!
        """
        
        # Simulate typing effect
        QTimer.singleShot(1000, lambda: self.simulate_typing(demo_results))
    
    def simulate_typing(self, text):
        self.results.setText(text)
        self.start_btn.setEnabled(True)
        self.start_btn.setText("🚀 Start Demo Scan")

class DemoNiktoPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("🌐 Nikto Web Scanner - Demo Mode")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        notice = QLabel("⚠️ This is demo mode. No actual scanning will be performed.")
        notice.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(notice)
        
        # URL input
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("Target URL:"))
        self.url_input = QLineEdit("https://example.com")
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        
        # Start button
        self.start_btn = QPushButton("🌐 Start Web Vulnerability Scan")
        self.start_btn.clicked.connect(self.start_demo_scan)
        layout.addWidget(self.start_btn)
        
        # Results
        self.results = QTextEdit()
        self.results.setPlaceholderText("Web vulnerability scan results will appear here...")
        layout.addWidget(self.results)
        
        self.setLayout(layout)
    
    def start_demo_scan(self):
        self.results.clear()
        self.start_btn.setEnabled(False)
        self.start_btn.setText("⏳ Scanning...")
        
        demo_results = f"""
🌐 Web Vulnerability Scan Results for {self.url_input.text()}

📊 Scan Summary:
├── Duration: 45 seconds
├── Requests: 1,247
├── Vulnerabilities Found: 3
└── Risk Level: Low

🔍 Discovered Issues:

1. 🟡 Information Disclosure
   - Server: Apache/2.4.41 (Ubuntu)
   - Risk: Low
   - Description: Server version information exposed
   - Recommendation: Hide server version in headers

2. 🟡 Missing Security Headers
   - Issue: X-Frame-Options header missing
   - Risk: Low
   - Description: Site vulnerable to clickjacking
   - Recommendation: Add X-Frame-Options header

3. 🟢 Directory Listing
   - Path: /images/
   - Risk: Low
   - Description: Directory listing enabled
   - Recommendation: Disable directory listing

🤖 AI Analysis:
├── Overall Security Score: 7.5/10
├── Critical Issues: 0
├── Medium Issues: 0
└── Low Issues: 3

✅ Demo completed successfully!
        """
        
        QTimer.singleShot(1500, lambda: self.simulate_typing(demo_results))
    
    def simulate_typing(self, text):
        self.results.setText(text)
        self.start_btn.setEnabled(True)
        self.start_btn.setText("🌐 Start Web Vulnerability Scan")

class DemoMetasploitPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("⚡ Metasploit + AI - Demo Mode")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        notice = QLabel("⚠️ This is demo mode. No actual exploitation will be performed.")
        notice.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(notice)
        
        # Target selection
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit("192.168.1.100")
        target_layout.addWidget(self.target_input)
        layout.addLayout(target_layout)
        
        # Exploit selection
        exploit_layout = QHBoxLayout()
        exploit_layout.addWidget(QLabel("Recommended Exploit:"))
        self.exploit_combo = QComboBox()
        self.exploit_combo.addItems([
            "exploit/multi/handler",
            "exploit/unix/ssh/sshexec",
            "exploit/windows/smb/ms17_010_eternalblue"
        ])
        exploit_layout.addWidget(self.exploit_combo)
        layout.addLayout(exploit_layout)
        
        # Execute button
        self.execute_btn = QPushButton("⚡ Execute Demo Exploit")
        self.execute_btn.clicked.connect(self.execute_demo)
        layout.addWidget(self.execute_btn)
        
        # Results
        self.results = QTextEdit()
        self.results.setPlaceholderText("Exploitation results will appear here...")
        layout.addWidget(self.results)
        
        self.setLayout(layout)
    
    def execute_demo(self):
        self.results.clear()
        self.execute_btn.setEnabled(False)
        self.execute_btn.setText("⏳ Executing...")
        
        demo_results = f"""
⚡ Metasploit Exploitation Demo for {self.target_input.text()}

🎯 Exploit: {self.exploit_combo.currentText()}

📊 Execution Summary:
├── Status: Successful (Demo)
├── Session Created: Yes
├── Privilege Level: User
└── Duration: 3.2 seconds

🔧 Exploitation Steps:
1. ✅ Target validation
2. ✅ Exploit module loaded
3. ✅ Payload configured
4. ✅ Exploit executed
5. ✅ Session established

🤖 AI Analysis:
├── Exploit Success Probability: 85%
├── Risk Assessment: Medium
├── Post-Exploitation Path: Available
└── Recommendations:
    - Perform privilege escalation
    - Gather system information
    - Establish persistence

📋 Session Information:
├── Session ID: 1
├── Type: shell
├── Platform: linux
└── Architecture: x64

✅ Demo completed successfully!
        """
        
        QTimer.singleShot(2000, lambda: self.simulate_typing(demo_results))
    
    def simulate_typing(self, text):
        self.results.setText(text)
        self.execute_btn.setEnabled(True)
        self.execute_btn.setText("⚡ Execute Demo Exploit")

class DemoHistoryPage(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        title = QLabel("📜 Scan History - Demo Mode")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        notice = QLabel("⚠️ This is demo mode. Showing sample scan history.")
        notice.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(notice)
        
        # Demo history
        self.history = QTextEdit()
        demo_history = """
📜 Sample Scan History

🔍 Recent Scans:
├── 2025-01-27 14:30:15 | Nmap | example.com | ✅ Success
├── 2025-01-27 13:45:22 | Nikto | https://test.com | ✅ Success  
├── 2025-01-27 12:15:08 | Metasploit | 192.168.1.100 | ✅ Success
├── 2025-01-27 11:30:45 | Nmap | scanme.org | ✅ Success
└── 2025-01-27 10:45:12 | Nikto | https://demo.com | ✅ Success

📊 Statistics:
├── Total Scans: 5
├── Successful: 5
├── Failed: 0
└── Average Duration: 2.3 minutes

🎯 Quick Actions:
├── Export All Results (JSON)
├── Generate Report (PDF)
├── Filter by Tool
└── Search Scans

✅ Demo history loaded successfully!
        """
        self.history.setText(demo_history)
        layout.addWidget(self.history)
        
        self.setLayout(layout)

class DarkPenDemo(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("DarkPen - AI-Powered Penetration Testing Platform (Demo Mode)")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Title
        title = QLabel("💀 DarkPen - AI-Powered Penetration Testing Platform")
        title.setFont(QFont("Arial", 20, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #00ff9f; margin: 10px;")
        layout.addWidget(title)
        
        # Demo notice
        demo_notice = QLabel("🎭 DEMO MODE - This is a demonstration of the DarkPen interface")
        demo_notice.setAlignment(Qt.AlignCenter)
        demo_notice.setStyleSheet("color: orange; font-weight: bold; font-size: 14px; margin: 5px;")
        layout.addWidget(demo_notice)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # Add demo pages
        self.nmap_page = DemoNmapPage()
        self.tabs.addTab(self.nmap_page, "🔍 Nmap Scanner")
        
        self.nikto_page = DemoNiktoPage()
        self.tabs.addTab(self.nikto_page, "🌐 Nikto Web Scanner")
        
        self.metasploit_page = DemoMetasploitPage()
        self.tabs.addTab(self.metasploit_page, "⚡ Metasploit + AI")
        
        self.history_page = DemoHistoryPage()
        self.tabs.addTab(self.history_page, "📜 History")
        
        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Demo Mode - Ready")

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("DarkPen Demo")
    app.setApplicationVersion("1.0.0")
    
    # Set dark theme
    app.setStyleSheet("""
        QMainWindow {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QTabWidget::pane {
            border: 1px solid #555555;
            background-color: #2b2b2b;
        }
        QTabBar::tab {
            background-color: #3b3b3b;
            color: #ffffff;
            padding: 8px 16px;
            margin-right: 2px;
        }
        QTabBar::tab:selected {
            background-color: #00ff9f;
            color: #000000;
        }
        QTextEdit {
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #555555;
        }
        QPushButton {
            background-color: #00ff9f;
            color: #000000;
            border: none;
            padding: 8px 16px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #00cc7f;
        }
        QPushButton:disabled {
            background-color: #555555;
            color: #888888;
        }
        QLineEdit, QComboBox {
            background-color: #1e1e1e;
            color: #ffffff;
            border: 1px solid #555555;
            padding: 5px;
        }
    """)
    
    window = DarkPenDemo()
    window.show()
    
    print("🚀 DarkPen Demo Mode Started!")
    print("✅ Your supervisor can now see the interface")
    print("💡 This is a demonstration - no actual scanning occurs")
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 