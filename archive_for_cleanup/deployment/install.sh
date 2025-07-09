#!/bin/bash

# Exit on error
set -e

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}🔒 DarkPen Installer${NC}"
echo -e "${CYAN}===================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}❌ Error: Please run as root${NC}"
    echo -e "${YELLOW}Try: sudo $0${NC}"
    exit 1
fi

# Check Docker installation
if ! command -v docker &> /dev/null || ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Error: Docker or Docker Compose not found${NC}"
    echo -e "${YELLOW}Please install Docker and Docker Compose first${NC}"
    exit 1
fi

# Create installation directory
INSTALL_DIR="/opt/darkpen"
mkdir -p "$INSTALL_DIR"

# Download DarkPen
echo -e "${GREEN}📥 Downloading DarkPen...${NC}"
if command -v curl &> /dev/null; then
    curl -L "https://darkpen.io/downloads/darkpen-1.0.0.tar.gz" -o "$INSTALL_DIR/darkpen.tar.gz"
    curl -L "https://darkpen.io/downloads/darkpen-1.0.0.tar.gz.sha256" -o "$INSTALL_DIR/darkpen.tar.gz.sha256"
else
    wget "https://darkpen.io/downloads/darkpen-1.0.0.tar.gz" -O "$INSTALL_DIR/darkpen.tar.gz"
    wget "https://darkpen.io/downloads/darkpen-1.0.0.tar.gz.sha256" -O "$INSTALL_DIR/darkpen.tar.gz.sha256"
fi

# Verify checksum
echo -e "${GREEN}🔍 Verifying download...${NC}"
cd "$INSTALL_DIR"
sha256sum -c darkpen.tar.gz.sha256

# Extract archive
echo -e "${GREEN}📦 Extracting files...${NC}"
tar xzf darkpen.tar.gz

# Run deployment script
echo -e "${GREEN}🚀 Running deployment...${NC}"
cd darkpen-1.0.0
./deployment/deploy.sh

# Create desktop entry
cat > /usr/share/applications/darkpen.desktop << EOL
[Desktop Entry]
Name=DarkPen
Comment=AI-Powered Penetration Testing Platform
Exec=xdg-open http://localhost:8080
Icon=${INSTALL_DIR}/darkpen-1.0.0/resources/icons/darkpen.png
Terminal=false
Type=Application
Categories=Security;Network;
EOL

echo -e "\n${GREEN}✅ DarkPen installation complete!${NC}"
echo -e "${CYAN}Access DarkPen at: http://localhost:8080${NC}"
echo -e "${CYAN}A desktop shortcut has been created.${NC}" 