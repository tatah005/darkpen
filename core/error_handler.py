from typing import Optional, Dict, Any
from enum import Enum
from .logger import DarkPenLogger

class ErrorType(Enum):
    DATABASE = "database"
    NETWORK = "network"
    AUTHENTICATION = "auth"
    CONFIGURATION = "config"
    TOOL = "tool"
    PERMISSION = "permission"
    VALIDATION = "validation"
    SYSTEM = "system"

class DarkPenError(Exception):
    def __init__(self, error_type: ErrorType, message: str, details: Optional[Dict] = None):
        self.error_type = error_type
        self.message = message
        self.details = details or {}
        super().__init__(self.message)

class ErrorHandler:
    def __init__(self):
        self.logger = DarkPenLogger().get_logger('error')
        
    def handle_error(self, error: Exception) -> Dict[str, Any]:
        """Handle different types of errors and return appropriate response"""
        if isinstance(error, DarkPenError):
            return self._handle_darkpen_error(error)
        return self._handle_generic_error(error)
        
    def _handle_darkpen_error(self, error: DarkPenError) -> Dict[str, Any]:
        """Handle application-specific errors"""
        self.logger.error(
            f"{error.error_type.value.upper()} Error: {error.message}",
            extra=error.details
        )
        
        return {
            'success': False,
            'error_type': error.error_type.value,
            'message': error.message,
            'details': error.details
        }
        
    def _handle_generic_error(self, error: Exception) -> Dict[str, Any]:
        """Handle generic Python exceptions"""
        error_type = ErrorType.SYSTEM
        if isinstance(error, (ConnectionError, TimeoutError)):
            error_type = ErrorType.NETWORK
        elif isinstance(error, (PermissionError, OSError)):
            error_type = ErrorType.PERMISSION
        elif isinstance(error, ValueError):
            error_type = ErrorType.VALIDATION
            
        self.logger.error(
            f"{error_type.value.upper()} Error: {str(error)}",
            exc_info=True
        )
        
        return {
            'success': False,
            'error_type': error_type.value,
            'message': str(error),
            'details': {
                'type': error.__class__.__name__
            }
        }
        
    def create_error(self, error_type: ErrorType, message: str, 
                    details: Optional[Dict] = None) -> DarkPenError:
        """Create a new DarkPenError"""
        return DarkPenError(error_type, message, details)

# Global error handler instance
error_handler = ErrorHandler() 