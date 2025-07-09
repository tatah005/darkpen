# DarkPen - AI-Powered Penetration Testing Platform

DarkPen is a comprehensive penetration testing platform that combines traditional security tools with AI-powered analysis capabilities.

## Download

You can download DarkPen in two formats:
1. `.tar.gz` archive (recommended for Linux/macOS)
2. `.zip` archive (recommended for Windows)

Visit our [Releases page](https://github.com/yourusername/darkpen/releases) to download the latest version.

### Verifying Downloads

Each release includes SHA256 checksums. To verify your download:

```bash
# For .tar.gz
sha256sum -c darkpen-1.0.0.tar.gz.sha256

# For .zip
sha256sum -c darkpen-1.0.0.zip.sha256
```

## Features

- Network scanning with Nmap integration
- Web vulnerability scanning with Nikto
- Metasploit framework integration
- AI-powered analysis and recommendations
- Beautiful cyberpunk-styled UI
- Secure configuration management
- Automated backups and logging
- Comprehensive reporting

## Requirements

- Docker and Docker Compose
- 4GB RAM minimum (8GB recommended)
- 20GB free disk space
- Linux/Unix-based system (tested on Ubuntu 20.04+)

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/darkpen.git
   cd darkpen
   ```

2. Deploy using the automated script:
   ```bash
   ./deployment/deploy.sh
   ```

3. Access the application at http://localhost:8080

## Manual Deployment

1. Set required environment variables:
   ```bash
   export DB_PASSWORD=your_db_password
   export MSF_PASSWORD=your_msf_password
   export JWT_SECRET=your_jwt_secret
   ```

2. Create .env file:
   ```bash
   cp .env.example .env
   # Edit .env with your values
   ```

3. Build and start services:
   ```bash
   docker-compose -f deployment/docker-compose.yml build
   docker-compose -f deployment/docker-compose.yml up -d
   ```

## Security Considerations

- Change default passwords immediately
- Use strong passwords for all services
- Keep the system and dependencies updated
- Monitor logs regularly
- Back up data periodically
- Use HTTPS in production
- Configure firewall rules

## Troubleshooting

1. Check service status:
   ```bash
   docker-compose -f deployment/docker-compose.yml ps
   ```

2. View logs:
   ```bash
   docker-compose -f deployment/docker-compose.yml logs -f
   ```

3. Restart services:
   ```bash
   docker-compose -f deployment/docker-compose.yml restart
   ```

## License

MIT License - See LICENSE file for details

## Support

For issues and feature requests, please use the GitHub issue tracker. 