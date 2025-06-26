from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget
from PyQt5.QtCore import Qt
import sys
from gui.nmap_page import NmapPage
from gui.nikto_page import NiktoPage
from gui.metasploit_page import MetasploitPage
from gui.history_page import HistoryPage
from gui.cyberpunk_theme import COLORS, STYLES

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DarkPen - AI-Powered Penetration Testing Platform")
        self.setStyleSheet(f"background-color: {COLORS['background']};")
        self.setup_ui()

    def setup_ui(self):
        # Create tab widget
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 2px solid {COLORS['electric_blue']};
                border-radius: 5px;
                background: {COLORS['background']};
            }}
            QTabBar::tab {{
                background: {COLORS['panel_bg']};
                color: {COLORS['text_primary']};
                border: 2px solid {COLORS['electric_blue']};
                border-bottom: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                padding: 8px 15px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background: {COLORS['cyber_purple']};
                color: white;
                margin-bottom: -2px;
            }}
        """)
        
        # Add pages
        self.nmap_page = NmapPage()
        self.tabs.addTab(self.nmap_page, "🔍 Nmap Scanner")
        
        self.nikto_page = NiktoPage()
        self.tabs.addTab(self.nikto_page, "🌐 Nikto Web Scanner")
        
        self.metasploit_page = MetasploitPage()
        self.tabs.addTab(self.metasploit_page, "⚡ Metasploit + AI")
        
        self.history_page = HistoryPage()
        self.tabs.addTab(self.history_page, "📜 History")
        
        self.setCentralWidget(self.tabs)
        self.resize(1200, 800)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())