# 🎯 DarkPen - AI-Powered Penetration Testing Platform

A comprehensive, AI-enhanced penetration testing platform built with Python and PyQt5, featuring advanced network scanning, web vulnerability assessment, exploitation capabilities, and robust scan history management.

![DarkPen](https://img.shields.io/badge/DarkPen-AI%20Powered%20Pentest%20Platform-00ff9f?style=for-the-badge&logo=python)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![PyQt5](https://img.shields.io/badge/PyQt5-GUI%20Framework-green?style=for-the-badge&logo=qt)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![GitHub](https://img.shields.io/badge/GitHub-Public%20Repository-brightgreen?style=for-the-badge&logo=github)

---

## 🌟 Features

### 🔍 **Nmap, Nikto, SQLMap, Metasploit — All-in-One Scanning**
- Advanced network, web, and database vulnerability scanning
- **All scans are reliably saved to the database and history panel**
- Real-time scan output with AI-powered interpretation and actionable advice
- Multiple scan types and options for each tool
- Automated vulnerability detection, risk assessment, and recommendations
- Robust error handling: every scan (including errors or partial results) is recorded

### 🤖 **AI Interpreter Panels**
- Every tool (Nmap, Nikto, SQLMap, Metasploit) features a visually engaging AI Interpreter panel
- Natural language summaries, risk callouts, and next steps for every scan result
- Actionable, human-friendly advice for all outcomes (success, failure, errors, no session, etc.)
- Consistent, modern UI with cyberpunk-inspired design

### 📜 **History & Export**
- **History panel always reflects all completed scans**
- Advanced filtering and search (by tool, target, date, etc.)
- Export scan history and results as **JSON, CSV, or PDF**
- Detailed scan results, vulnerabilities, and AI analysis always available for review

### 🛡️ **Recommendations & Risk Summaries**
- Every scan provides prioritized, actionable recommendations
- Risk and severity clearly called out with icons and color
- Friendly summaries and next steps for every finding

### 🏗️ **Modular & Extensible**
- Easily add new tools or integrations with consistent history/AI support
- Robust database logic and error handling for all scan types
- Modern, maintainable codebase

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Kali Linux or similar penetration testing distribution
- Root privileges (for certain scan types)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/tatah005/darkpen.git
cd darkpen
```

2. **Install dependencies**
   ```bash
# Install system dependencies
sudo apt-get update
sudo apt-get install -y python3-pyqt5 nmap nikto metasploit-framework

# Install Python dependencies
pip3 install -r requirements.txt
```

3. **Launch DarkPen** (Choose one method)

   **Method 1: Using the launcher script (Recommended)**
   ```bash
   ./darkpen.sh
   ```

   **Method 2: Using Python launcher**
   ```bash
   python3 launch_darkpen.py
   ```

   **Method 3: Direct Python execution**
   ```bash
   python3 run.py
   ```

   **Method 4: Using the shell script with virtual environment**
   ```bash
   ./start_gui.sh
   ```

### Docker Installation

```bash
# Build and run with Docker Compose
cd deployment
docker-compose up --build
```

### Windows Installation

For Windows users, see [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for detailed instructions.

---

## 📋 Usage Guide

- **Every scan is automatically saved to the database and history panel.**
- Review, filter, and export all scan results from the History tab.
- Each tool tab features an AI Interpreter panel for instant, actionable summaries.
- All recommendations and risk assessments are tailored to your scan results.

### Network Scanning
1. Open the **Nmap Scanner** tab
2. Enter target IP or hostname
3. Select scan type (Quick, Full, Intense, etc.)
4. Click **Start Scan**
5. View real-time results and AI analysis

### Web Vulnerability Assessment
1. Navigate to **Nikto Web Scanner**
2. Enter target URL
3. Configure scan options
4. Start web vulnerability scan
5. Review AI-enhanced findings

### Exploitation
1. Use **Metasploit + AI** tab
2. Select target from scan history
3. Choose recommended exploits
4. Execute with AI guidance
5. Monitor results and sessions

### History Management
1. Access **History** tab
2. Filter scans by tool, date, or status
3. Click on any scan for detailed results
4. Export comprehensive reports
5. Manage vulnerability findings

---

## 📊 Export Features

- Export scan history and results as **JSON, CSV, or PDF** from the History panel
- Exports include:
  - Complete scan results
  - Service details and versions
  - Vulnerability findings
  - AI analysis and recommendations
  - Risk metrics and assessments
  - Exploitation paths

---

## 🧩 Extending DarkPen / Adding New Tools

- To add a new scanner or tool:
  1. Create a new page in `gui/` for the tool UI
  2. Integrate scan logic in `core/` (see `nmap_scanner.py`, `database_manager.py`)
  3. Use `db.add_scan(...)` to save results to the database/history
  4. Add an AI Interpreter panel for natural language summaries
  5. Results will automatically appear in the History panel and be exportable
- See existing tool pages for examples and patterns

---

## 🛠️ Troubleshooting

**Q: Why don’t I see my scan in history?**
- All completed scans (including errors) are now saved. If a scan does not appear:
  - Ensure the scan completed (check for errors in the terminal output)
  - Check for database errors in the UI or logs
  - Make sure you are using the platform’s UI (not running tools manually)

**Q: How do I export my scan results?**
- Go to the History tab and use the export buttons (JSON, CSV, PDF)

**Q: How do I get actionable advice for my findings?**
- Every tool tab features an AI Interpreter panel with tailored recommendations and risk summaries

---

## 🏗️ Architecture

```
DarkPen/
├── core/                   # Core application logic
│   ├── ai_engine.py       # AI analysis engine
│   ├── database_manager.py # Database operations
│   ├── nmap_scanner.py    # Nmap integration
│   └── metasploit_client.py # Metasploit integration
├── gui/                    # User interface
│   ├── nmap_page.py       # Nmap scanner interface
│   ├── nikto_page.py      # Nikto scanner interface
│   ├── metasploit_page.py # Metasploit interface
│   ├── history_page.py    # History management
│   └── cyberpunk_theme.py # UI styling
├── data/                   # Database and scan data
├── deployment/             # Docker and deployment files
├── docs/                   # Documentation
└── main.py                 # Application entry point
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to DarkPen.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📞 Support

- **GitHub Issues**: [Report bugs or request features](https://github.com/tatah005/darkpen/issues)
- **Documentation**: Check the [docs/](docs/) directory for detailed guides
- **Community**: Join discussions in GitHub Discussions

## 🚀 Roadmap

- [ ] Web-based interface
- [ ] Cloud deployment options
- [ ] Additional vulnerability scanners
- [ ] Enhanced AI capabilities
- [ ] Mobile application
- [ ] Integration with more security tools

## ⭐ Star History

If you find DarkPen useful, please consider giving it a star on GitHub!

---

**Made with ❤️ for the cybersecurity community — now with full AI-powered scan history and guidance!**

**Repository**: https://github.com/tatah005/darkpen 