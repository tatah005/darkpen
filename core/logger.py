import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

class DarkPenLogger:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DarkPenLogger, cls).__new__(cls)
            cls._instance._initialize_logger()
        return cls._instance
    
    def _initialize_logger(self):
        """Initialize the logger with proper configuration"""
        # Create logs directory if it doesn't exist
        log_dir = Path('data/logs')
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up the main logger
        self.logger = logging.getLogger('darkpen')
        self.logger.setLevel(logging.DEBUG)
        
        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s - %(message)s'
        )
        console_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s'
        )
        
        # File handler for debug logs
        debug_handler = logging.handlers.RotatingFileHandler(
            log_dir / 'debug.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        debug_handler.setLevel(logging.DEBUG)
        debug_handler.setFormatter(file_formatter)
        
        # File handler for error logs
        error_handler = logging.handlers.RotatingFileHandler(
            log_dir / 'error.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_formatter)
        
        # Add handlers to logger
        self.logger.addHandler(debug_handler)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(console_handler)
        
        # Create tool-specific loggers
        self.tool_loggers = {}
        for tool in ['nmap', 'nikto', 'metasploit']:
            tool_logger = logging.getLogger(f'darkpen.{tool}')
            tool_logger.setLevel(logging.DEBUG)
            
            # Tool-specific file handler
            tool_handler = logging.handlers.RotatingFileHandler(
                log_dir / f'{tool}.log',
                maxBytes=5*1024*1024,  # 5MB
                backupCount=3
            )
            tool_handler.setFormatter(file_formatter)
            tool_logger.addHandler(tool_handler)
            self.tool_loggers[tool] = tool_logger
    
    def get_logger(self, name: Optional[str] = None) -> logging.Logger:
        """Get a logger instance"""
        if name:
            return logging.getLogger(f'darkpen.{name}')
        return self.logger
    
    def get_tool_logger(self, tool_name: str) -> logging.Logger:
        """Get a tool-specific logger"""
        return self.tool_loggers.get(tool_name, self.logger)
    
    def log_scan_start(self, tool: str, target: str):
        """Log scan start event"""
        logger = self.get_tool_logger(tool)
        logger.info(f"Starting {tool} scan against {target}")
        
    def log_scan_end(self, tool: str, target: str, status: str):
        """Log scan end event"""
        logger = self.get_tool_logger(tool)
        logger.info(f"Finished {tool} scan against {target} with status: {status}")
        
    def log_vulnerability(self, tool: str, target: str, vuln_type: str, severity: str):
        """Log vulnerability finding"""
        logger = self.get_tool_logger(tool)
        logger.warning(
            f"Found {severity} severity {vuln_type} vulnerability on {target}"
        )
        
    def log_error(self, tool: str, error: str, details: Optional[str] = None):
        """Log error event"""
        logger = self.get_tool_logger(tool)
        if details:
            logger.error(f"{tool} error: {error}\nDetails: {details}")
        else:
            logger.error(f"{tool} error: {error}")
            
    def log_ai_analysis(self, tool: str, target: str, analysis_type: str):
        """Log AI analysis event"""
        logger = self.get_tool_logger(tool)
        logger.info(f"Performing {analysis_type} analysis on {target} results")
        
    def log_config_change(self, component: str, change: str):
        """Log configuration change"""
        self.logger.info(f"Configuration change in {component}: {change}")
        
    def log_user_action(self, user: str, action: str):
        """Log user action"""
        self.logger.info(f"User {user} performed action: {action}")
        
    def log_system_event(self, event_type: str, details: str):
        """Log system event"""
        self.logger.info(f"System event ({event_type}): {details}")
        
    def log_backup_event(self, event_type: str, status: str, details: Optional[str] = None):
        """Log backup/restore event"""
        if details:
            self.logger.info(f"Backup {event_type}: {status} - {details}")
        else:
            self.logger.info(f"Backup {event_type}: {status}")
            
    def log_update_check(self, current_version: str, latest_version: str, status: str):
        """Log update check event"""
        self.logger.info(
            f"Update check - Current: {current_version}, "
            f"Latest: {latest_version}, Status: {status}"
        ) 