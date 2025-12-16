"""
Comprehensive logging infrastructure for CyMind platform.
Provides structured logging with security-aware filtering and performance monitoring.
"""

import logging
import logging.handlers
import os
import sys
import json
import traceback
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

from .config import get_config


class LogLevel(Enum):
    """Supported logging levels."""
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class SensitiveDataFilter(logging.Filter):
    """Filter to remove sensitive information from log records."""
    
    SENSITIVE_PATTERNS = [
        'password', 'passwd', 'secret', 'token', 'key', 'api_key',
        'authorization', 'auth', 'credential', 'private', 'confidential'
    ]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter sensitive data from log records."""
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self._sanitize_message(record.msg)
        
        if hasattr(record, 'args') and record.args:
            record.args = tuple(self._sanitize_arg(arg) for arg in record.args)
        
        return True
    
    def _sanitize_message(self, message: str) -> str:
        """Sanitize sensitive data in log messages."""
        # This is a simple implementation - in production, use more sophisticated patterns
        for pattern in self.SENSITIVE_PATTERNS:
            if pattern.lower() in message.lower():
                # Replace potential sensitive values with asterisks
                import re
                # Look for key=value or key:value patterns
                pattern_regex = rf'({pattern}[=:]\s*)([^\s,\]}}]+)'
                message = re.sub(pattern_regex, r'\1***', message, flags=re.IGNORECASE)
        
        return message
    
    def _sanitize_arg(self, arg: Any) -> Any:
        """Sanitize sensitive data in log arguments."""
        if isinstance(arg, dict):
            return {k: '***' if any(p in k.lower() for p in self.SENSITIVE_PATTERNS) else v 
                   for k, v in arg.items()}
        elif isinstance(arg, str):
            return self._sanitize_message(arg)
        return arg


class StructuredFormatter(logging.Formatter):
    """Structured JSON formatter for log records."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as structured JSON."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


class PerformanceLogger:
    """Logger for performance metrics and monitoring."""
    
    def __init__(self, logger_name: str = 'cymind.performance'):
        self.logger = logging.getLogger(logger_name)
    
    def log_scan_performance(self, scan_id: str, scan_type: str, 
                           duration: float, target_count: int) -> None:
        """Log scan performance metrics."""
        self.logger.info(
            "Scan performance metrics",
            extra={
                'metric_type': 'scan_performance',
                'scan_id': scan_id,
                'scan_type': scan_type,
                'duration_seconds': duration,
                'target_count': target_count,
                'targets_per_second': target_count / duration if duration > 0 else 0
            }
        )
    
    def log_api_performance(self, endpoint: str, method: str, 
                          duration: float, status_code: int) -> None:
        """Log API endpoint performance metrics."""
        self.logger.info(
            "API performance metrics",
            extra={
                'metric_type': 'api_performance',
                'endpoint': endpoint,
                'method': method,
                'duration_seconds': duration,
                'status_code': status_code
            }
        )
    
    def log_database_performance(self, operation: str, table: str, 
                               duration: float, record_count: int) -> None:
        """Log database operation performance metrics."""
        self.logger.info(
            "Database performance metrics",
            extra={
                'metric_type': 'database_performance',
                'operation': operation,
                'table': table,
                'duration_seconds': duration,
                'record_count': record_count
            }
        )


class SecurityLogger:
    """Logger for security-related events."""
    
    def __init__(self, logger_name: str = 'cymind.security'):
        self.logger = logging.getLogger(logger_name)
    
    def log_authentication_attempt(self, username: str, success: bool, 
                                 ip_address: str) -> None:
        """Log authentication attempts."""
        level = logging.INFO if success else logging.WARNING
        self.logger.log(
            level,
            f"Authentication {'successful' if success else 'failed'} for user {username}",
            extra={
                'event_type': 'authentication',
                'username': username,
                'success': success,
                'ip_address': ip_address
            }
        )
    
    def log_authorization_failure(self, username: str, resource: str, 
                                action: str, ip_address: str) -> None:
        """Log authorization failures."""
        self.logger.warning(
            f"Authorization failed for user {username} accessing {resource}",
            extra={
                'event_type': 'authorization_failure',
                'username': username,
                'resource': resource,
                'action': action,
                'ip_address': ip_address
            }
        )
    
    def log_suspicious_activity(self, description: str, ip_address: str, 
                              details: Optional[Dict[str, Any]] = None) -> None:
        """Log suspicious security events."""
        self.logger.error(
            f"Suspicious activity detected: {description}",
            extra={
                'event_type': 'suspicious_activity',
                'description': description,
                'ip_address': ip_address,
                'details': details or {}
            }
        )


class LoggingManager:
    """Manages logging configuration and setup for the CyMind platform."""
    
    def __init__(self):
        self.configured = False
        self.loggers: Dict[str, logging.Logger] = {}
        self.performance_logger = None
        self.security_logger = None
    
    def setup_logging(self) -> None:
        """Set up logging configuration based on application config."""
        if self.configured:
            return
        
        config = get_config()
        logging_config = config.logging
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, logging_config.level.upper()))
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Create formatters
        if config.environment.value == 'production':
            formatter = StructuredFormatter()
        else:
            formatter = logging.Formatter(logging_config.format)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(SensitiveDataFilter())
        root_logger.addHandler(console_handler)
        
        # File handler (if configured)
        if logging_config.file_path:
            self._setup_file_handler(root_logger, logging_config, formatter)
        
        # Set up specialized loggers
        self._setup_specialized_loggers()
        
        self.configured = True
    
    def _setup_file_handler(self, logger: logging.Logger, 
                          logging_config, formatter) -> None:
        """Set up rotating file handler for logging."""
        # Ensure log directory exists
        log_path = Path(logging_config.file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            logging_config.file_path,
            maxBytes=logging_config.max_file_size,
            backupCount=logging_config.backup_count
        )
        file_handler.setFormatter(formatter)
        file_handler.addFilter(SensitiveDataFilter())
        logger.addHandler(file_handler)
    
    def _setup_specialized_loggers(self) -> None:
        """Set up specialized loggers for different purposes."""
        # Performance logger
        self.performance_logger = PerformanceLogger()
        
        # Security logger
        self.security_logger = SecurityLogger()
        
        # Module-specific loggers
        module_loggers = [
            'cymind.scanner',
            'cymind.recon',
            'cymind.vulnerability',
            'cymind.ai_assistant',
            'cymind.plugins',
            'cymind.reports',
            'cymind.api'
        ]
        
        for logger_name in module_loggers:
            self.loggers[logger_name] = logging.getLogger(logger_name)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance for the specified name."""
        if not self.configured:
            self.setup_logging()
        
        if name not in self.loggers:
            self.loggers[name] = logging.getLogger(name)
        
        return self.loggers[name]
    
    def get_performance_logger(self) -> PerformanceLogger:
        """Get the performance logger instance."""
        if not self.configured:
            self.setup_logging()
        return self.performance_logger
    
    def get_security_logger(self) -> SecurityLogger:
        """Get the security logger instance."""
        if not self.configured:
            self.setup_logging()
        return self.security_logger


# Global logging manager instance
_logging_manager: Optional[LoggingManager] = None


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the specified name."""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    return _logging_manager.get_logger(name)


def get_performance_logger() -> PerformanceLogger:
    """Get the performance logger instance."""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    return _logging_manager.get_performance_logger()


def get_security_logger() -> SecurityLogger:
    """Get the security logger instance."""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    return _logging_manager.get_security_logger()


def setup_logging() -> None:
    """Initialize the logging system."""
    global _logging_manager
    if _logging_manager is None:
        _logging_manager = LoggingManager()
    _logging_manager.setup_logging()