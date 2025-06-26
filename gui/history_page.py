from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTableWidget, QTableWidgetItem, QComboBox,
                            QFrame, QHeaderView, QMessageBox, QTextEdit, QFileDialog)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from datetime import datetime
import json
from .cyberpunk_theme import COLORS, STYLES, FONTS, LAYOUT

class SimpleHistoryTable(QTableWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_table()
        
    def setup_table(self):
        self.setColumnCount(4)
        self.setHorizontalHeaderLabels([
            "Date", "Tool", "Target", "Status"
        ])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.setStyleSheet(STYLES['table'])
        self.setFont(QFont('Segoe UI', 10))
        
    def add_scan(self, timestamp, tool, target, status):
        row = self.rowCount()
        self.insertRow(row)
        
        # Format timestamp
        if timestamp:
            date_str = timestamp.strftime("%Y-%m-%d %H:%M")
        else:
            date_str = "Unknown"
        
        # Set status color
        status_color = {
            'Success': COLORS['neon_green'],
            'Failed': COLORS['warning_red'],
            'Running': COLORS['electric_blue'],
            'Stopped': COLORS['cyber_yellow']
        }.get(status, COLORS['text_primary'])
        
        # Add items
        items = [
            QTableWidgetItem(date_str),
            QTableWidgetItem(tool),
            QTableWidgetItem(target),
            QTableWidgetItem(status)
        ]
        
        for col, item in enumerate(items):
            if col == 3:  # Status column
                item.setForeground(QColor(status_color))
            self.setItem(row, col, item)

class SimpleHistoryPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.load_history()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header_label = QLabel("📜 Scan History")
        header_label.setFont(QFont('Segoe UI', 16, QFont.Bold))
        header_label.setStyleSheet(f"color: {COLORS['text_primary']}; margin: 10px;")
        layout.addWidget(header_label)
        
        # Simple filter
        filter_layout = QHBoxLayout()
        
        filter_label = QLabel("Filter by Tool:")
        filter_label.setFont(QFont('Segoe UI', 10))
        filter_layout.addWidget(filter_label)
        
        self.tool_filter = QComboBox()
        self.tool_filter.setStyleSheet(STYLES['combo_box'])
        self.tool_filter.addItems(["All Tools", "Nmap", "Nikto", "Metasploit"])
        self.tool_filter.currentTextChanged.connect(self.apply_filter)
        filter_layout.addWidget(self.tool_filter)
        
        filter_layout.addStretch()
        
        # Refresh button
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setStyleSheet(STYLES['buttons'])
        self.refresh_btn.clicked.connect(self.load_history)
        filter_layout.addWidget(self.refresh_btn)
        
        layout.addLayout(filter_layout)
        
        # History table
        self.history_table = SimpleHistoryTable()
        self.history_table.itemClicked.connect(self.show_details)
        layout.addWidget(self.history_table)
        
        # Details panel
        details_frame = QFrame()
        details_frame.setStyleSheet(STYLES['content_panel'])
        details_layout = QVBoxLayout(details_frame)
        
        details_label = QLabel("📋 Scan Details")
        details_label.setFont(QFont('Segoe UI', 12, QFont.Bold))
        details_label.setStyleSheet(f"color: {COLORS['text_primary']};")
        details_layout.addWidget(details_label)
        
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet(STYLES['terminal'])
        self.details_text.setMaximumHeight(150)
        details_layout.addWidget(self.details_text)
        
        layout.addWidget(details_frame)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.export_btn = QPushButton("💾 Export Full Data")
        self.export_btn.setStyleSheet(STYLES['buttons'])
        self.export_btn.clicked.connect(self.export_history)
        button_layout.addWidget(self.export_btn)
        
        self.clear_btn = QPushButton("🗑️ Clear All")
        self.clear_btn.setStyleSheet(STYLES['buttons'])
        self.clear_btn.clicked.connect(self.clear_history)
        button_layout.addWidget(self.clear_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)

    def load_history(self):
        """Load scan history from database"""
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            history = db.get_scan_history()
            self.update_table(history)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load history: {str(e)}")

    def update_table(self, history_data):
        """Update the history table with provided data"""
        self.history_table.setRowCount(0)
        for scan in history_data:
            self.history_table.add_scan(
                scan.timestamp,
                scan.tool_name,
                scan.target,
                scan.status
            )

    def apply_filter(self):
        """Apply tool filter"""
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            history = db.get_scan_history()
            
            tool_filter = self.tool_filter.currentText()
            if tool_filter != "All Tools":
                filtered_history = [scan for scan in history if scan.tool_name == tool_filter]
            else:
                filtered_history = history
            
            self.update_table(filtered_history)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to filter history: {str(e)}")

    def show_details(self, item):
        """Show comprehensive details for selected scan"""
        row = item.row()
        timestamp = self.history_table.item(row, 0).text()
        tool = self.history_table.item(row, 1).text()
        target = self.history_table.item(row, 2).text()
        status = self.history_table.item(row, 3).text()
        
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            
            # Get the scan ID from the database
            history = db.get_scan_history()
            if row < len(history):
                scan = history[row]
                scan_details = db.get_scan_details(scan.id)
                
                details = f"""📅 Date: {timestamp}
🔧 Tool: {tool}
🎯 Target: {target}
📊 Status: {status}

"""
                
                # Add scan results if available
                if scan_details and 'results' in scan_details:
                    results = scan_details['results']
                    if isinstance(results, dict):
                        details += "🔍 SCAN RESULTS:\n"
                        details += "=" * 50 + "\n"
                        
                        # Show services found
                        if 'services' in results and results['services']:
                            details += "\n🌐 SERVICES FOUND:\n"
                            for port, service_info in results['services'].items():
                                details += f"  Port {port}: {service_info.get('name', 'unknown')}\n"
                                if service_info.get('version'):
                                    details += f"    Version: {service_info['version']}\n"
                                if service_info.get('product'):
                                    details += f"    Product: {service_info['product']}\n"
                        
                        # Show findings
                        if 'findings' in results and results['findings']:
                            details += "\n🎯 FINDINGS:\n"
                            for finding in results['findings']:
                                risk_color = {
                                    'High': '🔴',
                                    'Medium': '🟡', 
                                    'Low': '🟢'
                                }.get(finding.get('risk_level', 'Low'), '⚪')
                                
                                details += f"  {risk_color} {finding.get('service', 'Unknown')} on port {finding.get('port', 'Unknown')}\n"
                                if finding.get('version'):
                                    details += f"    Version: {finding['version']}\n"
                                if finding.get('risk_level'):
                                    details += f"    Risk Level: {finding['risk_level']}\n"
                        
                        # Show risk metrics
                        if 'risk_metrics' in results:
                            metrics = results['risk_metrics']
                            details += "\n📊 RISK ASSESSMENT:\n"
                            details += f"  Overall Risk: {metrics.get('overall_risk', 0):.1%}\n"
                            details += f"  Attack Surface: {metrics.get('attack_surface', 0):.1%}\n"
                            details += f"  Critical Findings: {metrics.get('critical_findings', 0)}\n"
                
                # Add vulnerabilities
                if scan_details and 'vulnerabilities' in scan_details:
                    vulns = scan_details['vulnerabilities']
                    if vulns:
                        details += "\n🚨 VULNERABILITIES:\n"
                        details += "=" * 50 + "\n"
                        for vuln in vulns:
                            details += f"🔴 {vuln.get('name', 'Unknown vulnerability')}\n"
                            details += f"   Severity: {vuln.get('severity', 'Unknown')}\n"
                            details += f"   Description: {vuln.get('description', 'No description')}\n"
                            details += f"   Recommendation: {vuln.get('recommendation', 'No recommendation')}\n\n"
                
                # Add AI analysis
                if scan.ai_analysis:
                    details += "\n🤖 AI ANALYSIS:\n"
                    details += "=" * 50 + "\n"
                    details += scan.ai_analysis
                
        except Exception as e:
            details = f"""📅 Date: {timestamp}
🔧 Tool: {tool}
🎯 Target: {target}
📊 Status: {status}

This scan was performed using {tool} on {target}.
Status: {status}

For detailed results, check the scan output in the respective tool tab.

Error loading detailed results: {str(e)}"""
        
        self.details_text.setText(details)

    def export_history(self):
        """Export scan history to JSON file with full scan results"""
        try:
            from core.database_manager import DatabaseManager
            db = DatabaseManager()
            history = db.get_scan_history()
            
            # Convert Scan objects to detailed dictionaries for JSON export
            history_data = []
            for scan in history:
                # Get detailed scan information
                scan_details = db.get_scan_details(scan.id)
                
                # Parse results if they exist
                scan_results = {}
                if scan.results:
                    try:
                        if isinstance(scan.results, str):
                            scan_results = json.loads(scan.results)
                        else:
                            scan_results = scan.results
                    except:
                        scan_results = {"raw_results": str(scan.results)}
                
                # Build detailed export data
                export_item = {
                    'id': scan.id,
                    'date': scan.timestamp.isoformat() if scan.timestamp else None,
                    'tool': scan.tool_name,
                    'target': scan.target,
                    'status': scan.status,
                    'ai_analysis': scan.ai_analysis,
                    'scan_results': scan_results,
                    'vulnerabilities': []
                }
                
                # Add vulnerabilities if they exist
                if scan_details and 'vulnerabilities' in scan_details:
                    export_item['vulnerabilities'] = scan_details['vulnerabilities']
                
                history_data.append(export_item)
            
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Full Scan History", "full_scan_history.json", "JSON Files (*.json)"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(history_data, f, indent=2)
                QMessageBox.information(self, "Success", f"Full scan history exported to {filename}")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to export: {str(e)}")

    def clear_history(self):
        """Clear all scan history"""
        reply = QMessageBox.question(
            self, "Confirm Clear",
            "Are you sure you want to clear all scan history?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                from core.database_manager import DatabaseManager
                db = DatabaseManager()
                db.clear_history()
                self.history_table.setRowCount(0)
                self.details_text.clear()
                QMessageBox.information(self, "Success", "History cleared")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to clear: {str(e)}")

# Use the simple version as the main class
HistoryPage = SimpleHistoryPage 