import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget, QToolBar, QAction
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from gui.nikto_page import NiktoPage
from gui.nmap_page import NmapPage
from gui.metasploit_page import MetasploitPage
from gui.history_page import HistoryPage
from gui.cyberpunk_theme import COLORS, STYLES

class DarkPenMain(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DarkPen - AI-Powered Penetration Testing Platform")
        self.setup_ui()
        
    def setup_ui(self):
        # Set window properties
        self.setMinimumSize(1200, 800)
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS['background']};
            }}
        """)
        
        # Create central stacked widget
        self.central_widget = QStackedWidget()
        self.setCentralWidget(self.central_widget)
        
        # Create tool pages
        self.nmap_page = NmapPage()
        self.nikto_page = NiktoPage()
        self.metasploit_page = MetasploitPage()
        self.history_page = HistoryPage()
        
        # Add pages to stacked widget
        self.central_widget.addWidget(self.nmap_page)
        self.central_widget.addWidget(self.nikto_page)
        self.central_widget.addWidget(self.metasploit_page)
        self.central_widget.addWidget(self.history_page)
        
        # Create toolbar
        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setStyleSheet(f"""
            QToolBar {{
                background-color: {COLORS['panel_bg']};
                border-bottom: 2px solid {COLORS['electric_blue']};
                padding: 5px;
            }}
            QToolButton {{
                color: {COLORS['text_primary']};
                background-color: transparent;
                border: none;
                padding: 8px;
                margin: 0 5px;
                font-size: 14px;
            }}
            QToolButton:hover {{
                background-color: {COLORS['cyber_purple']};
                border-radius: 5px;
            }}
        """)
        
        # Add tool buttons with icons
        nmap_action = QAction("🔍 Nmap Scanner", self)
        nmap_action.setStatusTip("Network mapper and port scanner")
        nmap_action.triggered.connect(lambda: self.central_widget.setCurrentWidget(self.nmap_page))
        self.toolbar.addAction(nmap_action)
        
        nikto_action = QAction("🌐 Nikto + AI", self)
        nikto_action.setStatusTip("AI-powered web vulnerability scanner")
        nikto_action.triggered.connect(lambda: self.central_widget.setCurrentWidget(self.nikto_page))
        self.toolbar.addAction(nikto_action)
        
        metasploit_action = QAction("⚡ Metasploit + AI", self)
        metasploit_action.setStatusTip("AI-enhanced exploitation framework")
        metasploit_action.triggered.connect(lambda: self.central_widget.setCurrentWidget(self.metasploit_page))
        self.toolbar.addAction(metasploit_action)
        
        history_action = QAction("📜 History", self)
        history_action.setStatusTip("View scan history and analysis")
        history_action.triggered.connect(lambda: self.central_widget.setCurrentWidget(self.history_page))
        self.toolbar.addAction(history_action)
        
        self.addToolBar(self.toolbar)
        
        # Set initial page
        self.central_widget.setCurrentWidget(self.nmap_page)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DarkPenMain()
    window.show()
    sys.exit(app.exec_()) 