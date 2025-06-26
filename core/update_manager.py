import os
import json
import requests
import hashlib
import subprocess
from typing import Optional, Dict, Tuple
from pathlib import Path
from datetime import datetime
from packaging import version
from .logger import DarkPenLogger
from .config_manager import ConfigManager
from .backup_manager import BackupManager

class UpdateManager:
    def __init__(self):
        self.logger = DarkPenLogger().get_logger('update')
        self.config = ConfigManager()
        self.backup = BackupManager()
        
        # Version information
        self.current_version = "1.0.0"  # This should match your actual version
        self.version_file = Path('version.json')
        self._load_version_info()
        
    def _load_version_info(self):
        """Load version information from file"""
        if self.version_file.exists():
            try:
                with open(self.version_file, 'r') as f:
                    info = json.load(f)
                    self.current_version = info.get('version', self.current_version)
            except Exception as e:
                self.logger.error(f"Error loading version info: {str(e)}")
                
    def _save_version_info(self):
        """Save version information to file"""
        try:
            with open(self.version_file, 'w') as f:
                json.dump({
                    'version': self.current_version,
                    'last_update': datetime.now().isoformat()
                }, f, indent=4)
        except Exception as e:
            self.logger.error(f"Error saving version info: {str(e)}")
            
    def check_for_updates(self) -> Tuple[bool, Optional[str], Optional[str]]:
        """Check for available updates"""
        try:
            # This would normally check a remote API
            # For now, we'll simulate it
            latest_version = self._get_latest_version()
            
            if not latest_version:
                return False, None, "Failed to fetch latest version"
                
            current = version.parse(self.current_version)
            latest = version.parse(latest_version)
            
            if latest > current:
                self.logger.info(f"Update available: {self.current_version} -> {latest_version}")
                return True, latest_version, None
            else:
                self.logger.info("No updates available")
                return False, latest_version, None
                
        except Exception as e:
            self.logger.error(f"Error checking for updates: {str(e)}")
            return False, None, str(e)
            
    def _get_latest_version(self) -> Optional[str]:
        """Get latest version from remote server"""
        try:
            # This would normally be a real API endpoint
            # For demonstration, we'll return a hardcoded version
            return "1.0.1"
        except Exception as e:
            self.logger.error(f"Error fetching latest version: {str(e)}")
            return None
            
    def download_update(self, version: str) -> Tuple[bool, Optional[str]]:
        """Download update package"""
        try:
            # This would normally download from a remote server
            # For demonstration, we'll simulate it
            self.logger.info(f"Downloading update {version}")
            return True, None
        except Exception as e:
            self.logger.error(f"Error downloading update: {str(e)}")
            return False, str(e)
            
    def verify_update(self, version: str) -> Tuple[bool, Optional[str]]:
        """Verify update package integrity"""
        try:
            # This would normally verify checksums
            # For demonstration, we'll simulate it
            self.logger.info(f"Verifying update {version}")
            return True, None
        except Exception as e:
            self.logger.error(f"Error verifying update: {str(e)}")
            return False, str(e)
            
    def install_update(self, version: str) -> Tuple[bool, Optional[str]]:
        """Install update package"""
        try:
            # Create backup before updating
            if not self.backup.create_backup(f"pre_update_{version}"):
                return False, "Failed to create backup"
                
            # This would normally install the update
            # For demonstration, we'll simulate it
            self.logger.info(f"Installing update {version}")
            
            # Update version information
            self.current_version = version
            self._save_version_info()
            
            return True, None
            
        except Exception as e:
            self.logger.error(f"Error installing update: {str(e)}")
            return False, str(e)
            
    def rollback_update(self, version: str) -> Tuple[bool, Optional[str]]:
        """Rollback to previous version"""
        try:
            backup_name = f"pre_update_{version}"
            if not self.backup.restore_backup(backup_name):
                return False, "Failed to restore backup"
                
            # Restore version information
            self._load_version_info()
            
            self.logger.info(f"Rolled back update {version}")
            return True, None
            
        except Exception as e:
            self.logger.error(f"Error rolling back update: {str(e)}")
            return False, str(e)
            
    def check_dependencies(self) -> Dict[str, bool]:
        """Check if all required dependencies are installed"""
        dependencies = {
            'nmap': self._check_command('nmap --version'),
            'nikto': self._check_command('nikto -Version'),
            'metasploit': self._check_command('msfconsole -v'),
            'sqlite3': self._check_command('sqlite3 -version')
        }
        
        for dep, installed in dependencies.items():
            if installed:
                self.logger.info(f"Dependency check passed: {dep}")
            else:
                self.logger.warning(f"Dependency check failed: {dep}")
                
        return dependencies
        
    def _check_command(self, command: str) -> bool:
        """Check if a command is available"""
        try:
            subprocess.run(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True
            )
            return True
        except:
            return False
            
    def auto_update(self) -> Tuple[bool, Optional[str]]:
        """Perform automatic update if enabled"""
        if not self.config.get('updates.auto_update', False):
            return False, "Auto-update is disabled"
            
        update_available, latest_version, error = self.check_for_updates()
        if error:
            return False, error
            
        if not update_available:
            return False, "No updates available"
            
        # Download and verify update
        success, error = self.download_update(latest_version)
        if not success:
            return False, error
            
        success, error = self.verify_update(latest_version)
        if not success:
            return False, error
            
        # Install update
        success, error = self.install_update(latest_version)
        if not success:
            return False, error
            
        self.logger.info(f"Auto-update successful: {latest_version}")
        return True, None 