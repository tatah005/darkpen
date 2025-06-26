import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QStackedWidget
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor
from .nmap_page import NmapPage
from .nikto_page import NiktoPage
from .metasploit_page import MetasploitPage
from .history_page import HistoryPage
from .cyberpunk_theme import COLORS, STYLES

class DarkPenMain(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DarkPen - AI-Powered Pentest Platform")
        self.setMinimumSize(1200, 800)
        
        # Apply cyberpunk theme
        self.setStyleSheet(STYLES['main_window'])
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Create toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)
        
        # Create buttons for each tool
        self.nmap_btn = self.create_tool_button("🔍 Nmap Scanner", "nmap")
        self.nikto_btn = self.create_tool_button("🌐 Nikto + AI", "nikto")
        self.metasploit_btn = self.create_tool_button("⚡ Metasploit + AI", "metasploit")
        self.history_btn = self.create_tool_button("📜 History", "history")
        
        # Add buttons to toolbar
        toolbar.addWidget(self.nmap_btn)
        toolbar.addWidget(self.nikto_btn)
        toolbar.addWidget(self.metasploit_btn)
        toolbar.addWidget(self.history_btn)
        toolbar.addStretch()
        
        # Create stacked widget for pages
        self.stacked_widget = QStackedWidget()
        
        # Create pages
        self.nmap_page = NmapPage()
        self.nikto_page = NiktoPage()
        self.metasploit_page = MetasploitPage()
        self.history_page = HistoryPage()
        
        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.nmap_page)
        self.stacked_widget.addWidget(self.nikto_page)
        self.stacked_widget.addWidget(self.metasploit_page)
        self.stacked_widget.addWidget(self.history_page)
        
        # Add widgets to main layout
        layout.addLayout(toolbar)
        layout.addWidget(self.stacked_widget)
        
        # Connect signals
        self.nmap_btn.clicked.connect(lambda: self.switch_page(0))
        self.nikto_btn.clicked.connect(lambda: self.switch_page(1))
        self.metasploit_btn.clicked.connect(lambda: self.switch_page(2))
        self.history_btn.clicked.connect(lambda: self.switch_page(3))
        
        # Show Nmap page by default
        self.switch_page(0)
    
    def create_tool_button(self, text, name):
        btn = QPushButton(text)
        btn.setObjectName(name)
        btn.setMinimumHeight(40)
        btn.setFont(QFont("Roboto", 10))
        btn.setStyleSheet(STYLES['buttons'])
        return btn
    
    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        # Update button styles
        for btn in [self.nmap_btn, self.nikto_btn, self.metasploit_btn, self.history_btn]:
            btn.setStyleSheet(STYLES['buttons'])
        current_btn = [self.nmap_btn, self.nikto_btn, self.metasploit_btn, self.history_btn][index]
        current_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['cyber_purple']};
                color: {COLORS['background']};
                border: none;
                border-radius: 10px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 14px;
            }}
        """)

def main():
    app = QApplication(sys.argv)
    window = DarkPenMain()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 