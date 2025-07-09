#!/bin/bash

# Exit on error
set -e

VERSION=$(cat VERSION)
RELEASE_DIR="releases/darkpen-${VERSION}"

# Create release directory structure
mkdir -p "${RELEASE_DIR}"

# Copy necessary files
cp -r darkpen "${RELEASE_DIR}/"
cp -r deployment "${RELEASE_DIR}/"
cp -r config "${RELEASE_DIR}/"
cp requirements.txt "${RELEASE_DIR}/"
cp README.md "${RELEASE_DIR}/"
cp LICENSE "${RELEASE_DIR}/"
cp VERSION "${RELEASE_DIR}/"

# Create data and logs directories
mkdir -p "${RELEASE_DIR}/data"
mkdir -p "${RELEASE_DIR}/logs"

# Create example env file
cat > "${RELEASE_DIR}/.env.example" << EOL
# Database configuration
DB_PASSWORD=change_this_password

# Metasploit configuration
MSF_PASSWORD=change_this_password

# JWT configuration
JWT_SECRET=change_this_long_secret_key
EOL

# Create archive
cd releases
tar -czf "darkpen-${VERSION}.tar.gz" "darkpen-${VERSION}"
zip -r "darkpen-${VERSION}.zip" "darkpen-${VERSION}"

# Generate checksums
sha256sum "darkpen-${VERSION}.tar.gz" > "darkpen-${VERSION}.tar.gz.sha256"
sha256sum "darkpen-${VERSION}.zip" > "darkpen-${VERSION}.zip.sha256"

echo "Release packages created:"
echo "- darkpen-${VERSION}.tar.gz"
echo "- darkpen-${VERSION}.zip"
echo "- SHA256 checksums generated" 