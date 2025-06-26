#!/usr/bin/env python3
import sys
from PyQt5.QtWidgets import QApplication
from gui.darkpen_main import DarkPenMain

def main():
    app = QApplication(sys.argv)
    window = DarkPenMain()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main() 