from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QIcon
import sys

class DisclaimerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Important Notice")
        self.setModal(True)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.setMinimumWidth(400)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        # Add icon
        icon_label = QLabel()
        icon = QPixmap(48, 48)
        icon.fill(Qt.transparent)
        icon_label.setPixmap(self.style().standardIcon(self.style().SP_MessageBoxWarning).pixmap(48, 48))
        icon_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_label)
        # Friendly message
        label = QLabel(
            "<b>Welcome to DarkPen!</b><br><br>"
            "<span style='font-size:13px;'>Please use this tool responsibly.<br>"
            "Only test systems you own or have permission for.<br>"
            "Unauthorized use may be illegal.<br><br>"
            "By clicking <b>I Agree</b>, you confirm you understand and accept these terms.<br>"
            "Happy and safe testing! 🛡️</span>"
        )
        label.setAlignment(Qt.AlignCenter)
        label.setWordWrap(True)
        layout.addWidget(label)
        # Buttons
        button_layout = QHBoxLayout()
        agree_btn = QPushButton("I Agree")
        agree_btn.setStyleSheet("background-color: #4CAF50; color: white; border-radius: 8px; padding: 8px 20px;")
        agree_btn.clicked.connect(self.accept)
        exit_btn = QPushButton("Exit")
        exit_btn.setStyleSheet("background-color: #e53935; color: white; border-radius: 8px; padding: 8px 20px;")
        exit_btn.clicked.connect(self.reject)
        button_layout.addWidget(agree_btn)
        button_layout.addWidget(exit_btn)
        layout.addLayout(button_layout)
        self.setLayout(layout)
        self.setStyleSheet("background-color: #232946; border-radius: 16px;")

    def exit_app(self):
        QApplication.instance().quit() 