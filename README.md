# 🎯 DarkPen - AI-Powered Penetration Testing Platform

A comprehensive, AI-enhanced penetration testing platform built with Python and PyQt5, featuring advanced network scanning, web vulnerability assessment, and exploitation capabilities.

![DarkPen](https://img.shields.io/badge/DarkPen-AI%20Powered%20Pentest%20Platform-00ff9f?style=for-the-badge&logo=python)
![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![PyQt5](https://img.shields.io/badge/PyQt5-GUI%20Framework-green?style=for-the-badge&logo=qt)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

## 🌟 Features

### 🔍 **Nmap Scanner**
- Advanced network reconnaissance and port scanning
- Real-time scan output with AI analysis
- Multiple scan types (Quick, Full, Intense, Vulnerability, Custom)
- Automated vulnerability detection and risk assessment
- Service version detection and analysis

### 🌐 **Nikto Web Scanner**
- Web application vulnerability scanning
- AI-powered analysis of web security findings
- Comprehensive web security assessment
- Automated reporting and recommendations

### ⚡ **Metasploit + AI**
- Integration with Metasploit Framework
- AI-enhanced exploitation recommendations
- Automated exploit selection and execution
- Post-exploitation analysis

### 📜 **History Management**
- Complete scan history tracking
- Advanced filtering and search capabilities
- Comprehensive export functionality (JSON)
- Detailed scan results with AI analysis
- Vulnerability tracking and management

### 🤖 **AI Engine**
- Intelligent vulnerability analysis
- Automated risk assessment
- Exploitation path recommendations
- Security posture evaluation
- Real-time threat intelligence

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Kali Linux or similar penetration testing distribution
- Root privileges (for certain scan types)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/darkpen.git
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

## 📋 Usage Guide

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

## 🔧 Configuration

### Database Configuration
The application uses SQLite by default. Database files are stored in the `data/` directory.

### AI Engine Configuration
AI analysis settings can be configured in `core/ai_engine.py`.

### Scan Options
Customize scan parameters in the respective scanner modules:
- Nmap options: `gui/nmap_page.py`
- Nikto options: `gui/nikto_page.py`
- Metasploit options: `gui/metasploit_page.py`

## 📊 Export Features

### Comprehensive JSON Export
Export includes:
- Complete scan results
- Service details and versions
- Vulnerability findings
- AI analysis and recommendations
- Risk metrics and assessments
- Exploitation paths

### Sample Export Structure
```json
{
  "id": 1,
  "date": "2025-06-26T02:08:11.178999",
  "tool": "Nmap",
  "target": "example.com",
  "status": "Success",
  "ai_analysis": "Found 5 services. Overall risk: 0.45.",
  "scan_results": {
    "services": {
      "80": {"name": "http", "version": "Apache/2.4.41"},
      "443": {"name": "https", "version": "Apache/2.4.41"}
    },
    "findings": [
      {"service": "http", "port": "80", "risk_level": "Medium"}
    ],
    "risk_metrics": {
      "overall_risk": 0.45,
      "attack_surface": 0.67,
      "critical_findings": 2
    }
  },
  "vulnerabilities": [
    {
      "name": "High-risk service: ssh",
      "severity": "High",
      "description": "SSH service may pose security risks",
      "recommendation": "Review and secure SSH service"
    }
  ]
}
```

## 🛡️ Security Considerations

- **Legal Use Only**: This tool is for authorized penetration testing only
- **Responsible Disclosure**: Report vulnerabilities to system owners
- **Network Permissions**: Ensure you have permission to scan target networks
- **Data Protection**: Secure scan results and sensitive information

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is designed for authorized penetration testing and security research only. Users are responsible for ensuring they have proper authorization before scanning any systems. The developers are not responsible for any misuse of this software.

## 🆘 Support

- **Issues**: Report bugs and feature requests via GitHub Issues
- **Documentation**: Check the `docs/` directory for detailed guides
- **Community**: Join our discussions for help and collaboration

## 🎯 Roadmap

- [ ] Additional scanner integrations (Nessus, OpenVAS)
- [ ] Advanced AI capabilities (machine learning models)
- [ ] Web-based interface
- [ ] Team collaboration features
- [ ] Advanced reporting and analytics
- [ ] Integration with SIEM systems

---

**Made with ❤️ for the cybersecurity community**

*DarkPen - Where AI meets penetration testing* 