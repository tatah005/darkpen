# 🪟 Windows Setup Guide for DarkPen

## Quick Setup for Windows Users

### Prerequisites
- Windows 10/11 (version 2004 or higher)
- Administrator access

### Method 1: WSL (Windows Subsystem for Linux) - RECOMMENDED

#### Step 1: Install WSL
Open PowerShell as Administrator and run:
```powershell
wsl --install
```

#### Step 2: Restart Your Computer
After installation, restart your computer.

#### Step 3: Set Up Ubuntu
When you restart, Ubuntu will automatically install. Create a username and password when prompted.

#### Step 4: Update Ubuntu
```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 5: Install Required Tools
```bash
sudo apt install -y python3 python3-pip git
sudo apt install -y python3-pyqt5 nmap nikto metasploit-framework
```

#### Step 6: Clone and Run DarkPen
```bash
git clone https://github.com/tatah005/darkpen.git
cd darkpen
./darkpen.sh
```

### Method 2: Docker (Alternative)

#### Step 1: Install Docker Desktop
Download and install Docker Desktop from: https://www.docker.com/products/docker-desktop/

#### Step 2: Run DarkPen in Docker
```bash
# Open PowerShell or Command Prompt
git clone https://github.com/tatah005/darkpen.git
cd darkpen
docker-compose up --build
```

### Method 3: Virtual Machine

#### Step 1: Install VirtualBox
Download VirtualBox from: https://www.virtualbox.org/

#### Step 2: Download Kali Linux
Download Kali Linux ISO from: https://www.kali.org/get-kali/

#### Step 3: Create VM and Install Kali
1. Create a new VM in VirtualBox
2. Install Kali Linux
3. Clone and run DarkPen inside Kali

## 🎯 Quick Demo for Supervisors

If your supervisor just wants to see the interface quickly:

### Option A: Screenshots and Videos
- Take screenshots of the main interface
- Record a short demo video showing the features
- Share the GitHub repository link

### Option B: Remote Demo
- Use TeamViewer, AnyDesk, or Microsoft Teams
- Share your screen and demonstrate the tool
- Show the different scanning capabilities

### Option C: Web Interface (Future Enhancement)
- Consider adding a web-based interface
- Deploy to a cloud service
- Share a URL for easy access

## 📋 What Your Supervisor Will See

DarkPen includes:
- 🔍 **Nmap Scanner**: Network reconnaissance
- 🌐 **Nikto Web Scanner**: Web vulnerability assessment  
- ⚡ **Metasploit Integration**: Exploitation capabilities
- 📊 **AI Analysis**: Intelligent vulnerability assessment
- 📜 **History Management**: Scan results and reporting

## 🆘 Troubleshooting

### WSL Issues
```bash
# If WSL doesn't start
wsl --shutdown
wsl --start
```

### GUI Issues on WSL
```bash
# Install X Server for Windows (VcXsrv)
# Then run:
export DISPLAY=:0
./darkpen.sh
```

### Permission Issues
```bash
# Make scripts executable
chmod +x *.sh
```

## 📞 Support

If your supervisor encounters issues:
1. Check the main README.md
2. Open an issue on GitHub
3. Contact the development team

---

**Note**: WSL is the recommended method as it provides the most native experience while running on Windows. 