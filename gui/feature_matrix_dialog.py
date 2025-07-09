from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTableWidget, QTableWidgetItem, QScrollArea, QWidget, QHBoxLayout, QLabel
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap

class FeatureMatrixDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Feature Matrix")
        self.setMinimumSize(500, 300)
        self.setModal(True)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        # Add icon and header
        header_layout = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(self.style().standardIcon(self.style().SP_FileDialogInfoView).pixmap(32, 32))
        header_layout.addWidget(icon_label)
        header = QLabel("<b>Feature Matrix</b>")
        header.setStyleSheet("font-size: 18px; color: #4FC3F7;")
        header_layout.addWidget(header)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        # Friendly intro
        intro = QLabel("<i>See what DarkPen can do and what's coming soon!</i>")
        intro.setStyleSheet("color: #b0b0b0; font-size: 13px;")
        layout.addWidget(intro)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Feature", "Status"])
        features = [
            ("Nmap Scanning", "✅ Fully Implemented"),
            ("Nikto Web Scanning", "✅ Fully Implemented"),
            ("SQLMap Integration", "✅ Fully Implemented"),
            ("Metasploit Module", "✅ Implemented (Requires Metasploit, May Timeout)"),
            ("AI Rule Engine", "✅ Advanced AI Analysis (Basic, Enhanced Coming Soon)"),
            ("History Filtering & Management", "✅ Fully Implemented"),
            ("Export (JSON, CSV, PDF)", "✅ Fully Implemented"),
            ("Compliance Mapping", "✅ Fully Implemented"),
            ("Feature Matrix", "✅ This Dialog!"),
            ("Disclaimer & Responsible Use", "✅ Fully Implemented"),
            ("Dark Theme / Cyberpunk UI", "✅ Fully Implemented"),
            ("Modular Scanner Tabs", "✅ Fully Implemented"),
            ("Custom Scan Options", "✅ Fully Implemented"),
            ("Cloud Sync", "🚧 Planned (Future Release)"),
            ("Real-time Collaboration", "🚧 Planned (Future Release)"),
            ("Enhanced AI Integration (LLM, Threat Intel)", "🚧 Planned (Next Major Release)"),
            ("Vulnerability Auto-Remediation", "🚧 Planned"),
            ("Plugin/Extension System", "🚧 Planned"),
            ("Mobile App Companion", "🚧 Planned"),
        ]
        table.setRowCount(len(features))
        for i, (feature, status) in enumerate(features):
            table.setItem(i, 0, QTableWidgetItem(feature))
            table.setItem(i, 1, QTableWidgetItem(status))
        table.resizeColumnsToContents()
        table.setStyleSheet("font-size: 13px;")
        content_layout.addWidget(table)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        self.setLayout(layout)
        self.setStyleSheet("background-color: #232946; border-radius: 16px;") 