import os
import shutil
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
import tarfile
from .logger import DarkPenLogger
from .config_manager import ConfigManager

class BackupManager:
    def __init__(self):
        self.logger = DarkPenLogger().get_logger('backup')
        self.config = ConfigManager()
        
        # Setup backup directories
        self.backup_dir = Path('data/backups')
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
    def create_backup(self, backup_name: Optional[str] = None) -> bool:
        """Create a full backup of the application data"""
        try:
            # Generate backup name if not provided
            if not backup_name:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_name = f'darkpen_backup_{timestamp}'
            
            backup_path = self.backup_dir / backup_name
            backup_path.mkdir(exist_ok=True)
            
            # Backup database
            self._backup_database(backup_path)
            
            # Backup configuration
            self._backup_config(backup_path)
            
            # Backup logs
            self._backup_logs(backup_path)
            
            # Create archive
            self._create_archive(backup_path)
            
            # Clean up temporary directory
            shutil.rmtree(backup_path)
            
            self.logger.info(f"Backup created successfully: {backup_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {str(e)}")
            return False
            
    def restore_backup(self, backup_name: str) -> bool:
        """Restore from a backup"""
        try:
            backup_archive = self.backup_dir / f"{backup_name}.tar.gz"
            if not backup_archive.exists():
                self.logger.error(f"Backup archive not found: {backup_name}")
                return False
                
            # Create temporary directory for extraction
            temp_dir = self.backup_dir / "temp_restore"
            temp_dir.mkdir(exist_ok=True)
            
            # Extract archive
            with tarfile.open(backup_archive, 'r:gz') as tar:
                tar.extractall(temp_dir)
                
            # Restore database
            self._restore_database(temp_dir)
            
            # Restore configuration
            self._restore_config(temp_dir)
            
            # Clean up
            shutil.rmtree(temp_dir)
            
            self.logger.info(f"Backup restored successfully: {backup_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup restoration failed: {str(e)}")
            return False
            
    def list_backups(self) -> List[Dict]:
        """List available backups"""
        backups = []
        for backup_file in self.backup_dir.glob('*.tar.gz'):
            try:
                stat = backup_file.stat()
                backups.append({
                    'name': backup_file.stem,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime),
                    'path': str(backup_file)
                })
            except Exception as e:
                self.logger.error(f"Error reading backup {backup_file}: {str(e)}")
                
        return sorted(backups, key=lambda x: x['created'], reverse=True)
        
    def delete_backup(self, backup_name: str) -> bool:
        """Delete a backup"""
        try:
            backup_file = self.backup_dir / f"{backup_name}.tar.gz"
            if backup_file.exists():
                backup_file.unlink()
                self.logger.info(f"Backup deleted: {backup_name}")
                return True
            else:
                self.logger.error(f"Backup not found: {backup_name}")
                return False
        except Exception as e:
            self.logger.error(f"Error deleting backup {backup_name}: {str(e)}")
            return False
            
    def _backup_database(self, backup_path: Path):
        """Backup the SQLite database"""
        db_path = Path(self.config.get('database.path'))
        if db_path.exists():
            shutil.copy2(db_path, backup_path / 'darkpen.db')
            
    def _backup_config(self, backup_path: Path):
        """Backup configuration files"""
        config_dir = Path('config')
        if config_dir.exists():
            shutil.copytree(config_dir, backup_path / 'config', dirs_exist_ok=True)
            
    def _backup_logs(self, backup_path: Path):
        """Backup log files"""
        logs_dir = Path('data/logs')
        if logs_dir.exists():
            shutil.copytree(logs_dir, backup_path / 'logs', dirs_exist_ok=True)
            
    def _create_archive(self, backup_path: Path):
        """Create a compressed archive of the backup"""
        archive_name = f"{backup_path.name}.tar.gz"
        with tarfile.open(self.backup_dir / archive_name, 'w:gz') as tar:
            tar.add(backup_path, arcname=backup_path.name)
            
    def _restore_database(self, restore_path: Path):
        """Restore the database from backup"""
        backup_db = restore_path / backup_path.name / 'darkpen.db'
        target_db = Path(self.config.get('database.path'))
        if backup_db.exists():
            target_db.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup_db, target_db)
            
    def _restore_config(self, restore_path: Path):
        """Restore configuration from backup"""
        backup_config = restore_path / backup_path.name / 'config'
        if backup_config.exists():
            shutil.copytree(backup_config, Path('config'), dirs_exist_ok=True)
            
    def cleanup_old_backups(self, keep_days: int = 30) -> int:
        """Clean up backups older than specified days"""
        deleted_count = 0
        cutoff_date = datetime.now().timestamp() - (keep_days * 24 * 60 * 60)
        
        for backup_file in self.backup_dir.glob('*.tar.gz'):
            try:
                if backup_file.stat().st_ctime < cutoff_date:
                    backup_file.unlink()
                    deleted_count += 1
            except Exception as e:
                self.logger.error(f"Error cleaning up backup {backup_file}: {str(e)}")
                
        if deleted_count > 0:
            self.logger.info(f"Cleaned up {deleted_count} old backups")
            
        return deleted_count 