import os
import json
from pathlib import Path
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet

class ConfigManager:
    def __init__(self):
        self.config_dir = Path('config')
        self.config_file = self.config_dir / 'settings.json'
        self.key_file = self.config_dir / '.key'
        self._config = {}
        self._fernet = None
        
        # Create config directory if it doesn't exist
        self.config_dir.mkdir(exist_ok=True)
        
        # Initialize encryption key
        self._init_encryption()
        
        # Load or create default configuration
        self.load_config()
        
    def _init_encryption(self):
        """Initialize or load encryption key"""
        if not self.key_file.exists():
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
        else:
            with open(self.key_file, 'rb') as f:
                key = f.read()
        self._fernet = Fernet(key)
        
    def _encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        return self._fernet.encrypt(data.encode()).decode()
        
    def _decrypt(self, data: str) -> str:
        """Decrypt sensitive data"""
        return self._fernet.decrypt(data.encode()).decode()
        
    def load_config(self):
        """Load configuration from file or create default"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self._config = json.load(f)
        else:
            self._config = self._get_default_config()
            self.save_config()
            
    def save_config(self):
        """Save current configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(self._config, f, indent=4)

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration settings"""
        return {
            'general': {
                'debug_mode': False,
                'log_level': 'INFO',
                'theme': 'cyberpunk',
                'language': 'en'
            },
            'database': {
                'path': 'data/darkpen.db',
                'backup_enabled': True,
                'backup_interval': 24  # hours
            },
            'tools': {
                'nmap': {
                    'path': 'nmap',
                    'default_args': '-sV -sC',
                    'timeout': 300
                },
                'nikto': {
                    'path': 'nikto',
                    'default_args': '-Format json',
                    'timeout': 600
                },
                'metasploit': {
                    'host': 'localhost',
                    'port': 55553,
                    'ssl': True,
                    'verify_ssl': False,
                    'timeout': 30
                }
            },
            'ai': {
                'enabled': True,
                'model': 'gpt-3.5-turbo',
                'max_tokens': 2000,
                'temperature': 0.7
            },
            'security': {
                'require_auth': True,
                'session_timeout': 30,  # minutes
                'max_login_attempts': 3,
                'password_policy': {
                    'min_length': 12,
                    'require_numbers': True,
                    'require_special': True,
                    'require_uppercase': True
                }
            },
            'updates': {
                'check_on_startup': True,
                'auto_update': False,
                'update_channel': 'stable'
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key"""
        try:
            keys = key.split('.')
            value = self._config
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
            
    def set(self, key: str, value: Any):
        """Set configuration value"""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            config = config.setdefault(k, {})
        config[keys[-1]] = value
        self.save_config()
        
    def set_encrypted(self, key: str, value: str):
        """Set encrypted configuration value"""
        encrypted_value = self._encrypt(value)
        self.set(key, encrypted_value)
        
    def get_encrypted(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get decrypted configuration value"""
        encrypted_value = self.get(key)
        if encrypted_value is None:
            return default
        try:
            return self._decrypt(encrypted_value)
        except:
            return default

    def get_tool_config(self, tool_name: str) -> Optional[Dict]:
        """Get configuration for a specific tool"""
        return self._config.get('tools', {}).get(tool_name)

    def update_tool_config(self, tool_name: str, config: Dict) -> bool:
        """Update configuration for a specific tool"""
        try:
            if tool_name in self._config.get('tools', {}):
                self._config['tools'][tool_name].update(config)
                return self.save_config()
            return False
        except Exception as e:
            print(f"Error updating tool config: {str(e)}")
            return False

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        try:
            # First check environment variables
            env_key = os.getenv(f"{service.upper()}_API_KEY")
            if env_key:
                return env_key
            
            # Then check configuration
            if service == 'ai':
                return self._config.get('ai', {}).get('api_key')
            elif service in self._config.get('tools', {}):
                return self._config['tools'][service].get('api_key')
            return None
        except Exception as e:
            print(f"Error getting API key: {str(e)}")
            return None

    def set_api_key(self, service: str, api_key: str) -> bool:
        """Set API key for a service"""
        try:
            # Store in environment file
            with open(self.env_file, 'a') as f:
                f.write(f"\n{service.upper()}_API_KEY={api_key}")
            
            # Update configuration
            if service == 'ai':
                self._config['ai']['api_key'] = api_key
            elif service in self._config.get('tools', {}):
                self._config['tools'][service]['api_key'] = api_key
            
            return self.save_config()
        except Exception as e:
            print(f"Error setting API key: {str(e)}")
            return False

    def get_reporting_config(self) -> Dict:
        """Get reporting configuration"""
        return self._config.get('reporting', {})

    def update_reporting_config(self, config: Dict) -> bool:
        """Update reporting configuration"""
        try:
            self._config['reporting'].update(config)
            return self.save_config()
        except Exception as e:
            print(f"Error updating reporting config: {str(e)}")
            return False

    def get_security_config(self) -> Dict:
        """Get security configuration"""
        return self._config.get('security', {})

    def update_security_config(self, config: Dict) -> bool:
        """Update security configuration"""
        try:
            self._config['security'].update(config)
            return self.save_config()
        except Exception as e:
            print(f"Error updating security config: {str(e)}")
            return False

    def get_ai_config(self) -> Dict:
        """Get AI configuration"""
        return self._config.get('ai', {})

    def update_ai_config(self, config: Dict) -> bool:
        """Update AI configuration"""
        try:
            self._config['ai'].update(config)
            return self.save_config()
        except Exception as e:
            print(f"Error updating AI config: {str(e)}")
            return False

    def get_database_config(self) -> Dict:
        """Get database configuration"""
        return self._config.get('database', {})

    def update_database_config(self, config: Dict) -> bool:
        """Update database configuration"""
        try:
            self._config['database'].update(config)
            return self.save_config()
        except Exception as e:
            print(f"Error updating database config: {str(e)}")
            return False

    def get_update_config(self) -> Dict:
        """Get update configuration"""
        return self._config.get('updates', {})

    def update_update_config(self, config: Dict) -> bool:
        """Update update configuration"""
        try:
            self._config['updates'].update(config)
            return self.save_config()
        except Exception as e:
            print(f"Error updating update config: {str(e)}")
            return False

    def reset_config(self) -> bool:
        """Reset configuration to defaults"""
        try:
            self._config = self._get_default_config()
            return self.save_config()
        except Exception as e:
            print(f"Error resetting config: {str(e)}")
            return False

    def backup_config(self) -> bool:
        """Create a backup of the current configuration"""
        try:
            backup_file = self.config_dir / f"config_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(backup_file, 'w') as f:
                json.dump(self._config, f, indent=4)
            return True
        except Exception as e:
            print(f"Error backing up config: {str(e)}")
            return False

    def restore_config(self, backup_file: str) -> bool:
        """Restore configuration from a backup file"""
        try:
            with open(backup_file, 'r') as f:
                saved_config = json.load(f)
                self._merge_config(saved_config)
            return self.save_config()
        except Exception as e:
            print(f"Error restoring config: {str(e)}")
            return False 