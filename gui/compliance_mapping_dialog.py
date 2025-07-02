from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QScrollArea, QWidget, QHBoxLayout
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap

class ComplianceMappingDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Compliance Mapping")
        self.setMinimumSize(400, 300)
        self.setModal(True)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        # Add icon and header
        header_layout = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(self.style().standardIcon(self.style().SP_DialogHelpButton).pixmap(32, 32))
        header_layout.addWidget(icon_label)
        header = QLabel("<b>Compliance Mapping</b>")
        header.setStyleSheet("font-size: 18px; color: #4FC3F7;")
        header_layout.addWidget(header)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        # Friendly intro
        intro = QLabel("<i>See how DarkPen aligns with major security standards:</i>")
        intro.setStyleSheet("color: #b0b0b0; font-size: 13px;")
        layout.addWidget(intro)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        content = QWidget()
        content_layout = QVBoxLayout(content)
        mapping_text = (
            "<ul style='font-size:14px;'>"
            "<li><b>OWASP ASVS v4</b> – Security configuration mapped to port and service detection.</li>"
            "<li><b>NIST CSF</b> – Risk assessment through the AI engine.</li>"
            "<li><b>ISO 27001</b> – Asset management and vulnerability detection alignment.</li>"
            "</ul>"
        )
        label = QLabel(mapping_text)
        label.setWordWrap(True)
        content_layout.addWidget(label)
        scroll.setWidget(content)
        layout.addWidget(scroll)
        self.setLayout(layout)
        self.setStyleSheet("background-color: #232946; border-radius: 16px;") 