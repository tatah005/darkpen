#!/bin/bash
# Kali Linux Dependency Installer

set -e

error_handler() {
    echo "Error occurred in script at line: ${1}"
    echo "Error status: ${2}"
    exit 1
}

trap 'error_handler ${LINENO} $?' ERR

echo "[+] Updating package list"
sudo apt update -qq

echo "[+] Installing core dependencies"
sudo apt install -y -qq \
    python3.11 \
    python3.11-venv \
    nmap \
    metasploit-framework \
    nikto \
    sqlmap \
    python3-pyqt5 \
    python3-pyqt5.qtsql

echo "[+] Setting up Metasploit RPC"
sudo systemctl start postgresql
msfdb init
echo -e "msfpassword\nmsfpassword" | msfdb init

echo "[+] Creating desktop shortcut"
cat << 'DESKTOP' > ~/Desktop/AI-Pentest-Platform.desktop
[Desktop Entry]
Version=1.0
Type=Application
Name=AI Pentest Platform
Comment=AI-Driven Penetration Testing Suite
Exec=/bin/bash -c "cd $(pwd) && source venv/bin/activate && python gui/main_window.py"
Icon=kalilinux
Terminal=false
Categories=Security;
DESKTOP

chmod +x ~/Desktop/AI-Pentest-Platform.desktop

echo "[+] Installation complete!"
echo "  - To start the GUI: ./start_gui.sh"
echo "  - To run tests: ./run_tests.sh"
