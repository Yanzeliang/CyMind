"""
Enhanced configuration management system for CyMind platform.
Provides centralized configuration with validation and environment-specific settings.
"""

import os
import json
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""
    pass


class Environment(Enum):
    """Supported deployment environments."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    url: str = "sqlite:///cymind.db"
    pool_size: int = 10
    max_overflow: int = 20
    echo: bool = False


@dataclass
class LoggingConfig:
    """Logging configuration settings."""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: Optional[str] = None
    log_dir: str = "logs"  # 添加log_dir属性
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5


@dataclass
class SecurityConfig:
    """Security-related configuration settings."""
    secret_key: str = ""
    jwt_expiration_hours: int = 24
    max_login_attempts: int = 5
    session_timeout_minutes: int = 30


@dataclass
class ScannerConfig:
    """Scanner module configuration settings."""
    max_concurrent_scans: int = 5
    default_timeout_seconds: int = 300
    retry_attempts: int = 3
    retry_delay_seconds: int = 5


@dataclass
class AIConfig:
    """AI Assistant configuration settings."""
    enabled: bool = False
    api_key: str = ""
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 1000
    temperature: float = 0.7


@dataclass
class PluginConfig:
    """Plugin system configuration settings."""
    plugin_directory: str = "plugins"
    auto_discovery: bool = True
    sandbox_enabled: bool = True
    max_execution_time: int = 300


@dataclass
class CyMindConfig:
    """Main configuration class for CyMind platform."""
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    host: str = "localhost"
    port: int = 5000
    
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    plugins: PluginConfig = field(default_factory=PluginConfig)


class ConfigManager:
    """Manages configuration loading, validation, and access."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._get_default_config_path()
        self._config: Optional[CyMindConfig] = None
        self._load_config()
    
    def _get_default_config_path(self) -> str:
        """Get the default configuration file path."""
        env = os.getenv("CYMIND_ENV", "development")
        return f"config/{env}.yaml"
    
    def _load_config(self) -> None:
        """Load configuration from file and environment variables."""
        # Start with default configuration
        config_dict = {}
        
        # Load from file if it exists
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                if self.config_path.endswith('.yaml') or self.config_path.endswith('.yml'):
                    config_dict = yaml.safe_load(f) or {}
                else:
                    config_dict = json.load(f)
        
        # Override with environment variables
        config_dict = self._apply_env_overrides(config_dict)
        
        # Create configuration object
        self._config = self._dict_to_config(config_dict)
        
        # Validate configuration
        self._validate_config()
    
    def _apply_env_overrides(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides to configuration."""
        env_mappings = {
            'CYMIND_DEBUG': ('debug', bool),
            'CYMIND_HOST': ('host', str),
            'CYMIND_PORT': ('port', int),
            'CYMIND_DB_URL': ('database.url', str),
            'CYMIND_LOG_LEVEL': ('logging.level', str),
            'CYMIND_SECRET_KEY': ('security.secret_key', str),
            'CYMIND_AI_ENABLED': ('ai.enabled', bool),
            'CYMIND_AI_API_KEY': ('ai.api_key', str),
        }
        
        for env_var, (config_path, value_type) in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                # Convert value to appropriate type
                if value_type == bool:
                    env_value = env_value.lower() in ('true', '1', 'yes', 'on')
                elif value_type == int:
                    env_value = int(env_value)
                
                # Set nested configuration value
                self._set_nested_value(config_dict, config_path, env_value)
        
        return config_dict
    
    def _set_nested_value(self, config_dict: Dict[str, Any], path: str, value: Any) -> None:
        """Set a nested configuration value using dot notation."""
        keys = path.split('.')
        current = config_dict
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value
    
    def _dict_to_config(self, config_dict: Dict[str, Any]) -> CyMindConfig:
        """Convert dictionary to CyMindConfig object."""
        # Handle environment enum
        env_str = config_dict.get('environment', 'development')
        if isinstance(env_str, str):
            config_dict['environment'] = Environment(env_str)
        
        # Create nested configuration objects
        nested_configs = {
            'database': DatabaseConfig,
            'logging': LoggingConfig,
            'security': SecurityConfig,
            'scanner': ScannerConfig,
            'ai': AIConfig,
            'plugins': PluginConfig,
        }
        
        for key, config_class in nested_configs.items():
            if key in config_dict and isinstance(config_dict[key], dict):
                config_dict[key] = config_class(**config_dict[key])
        
        return CyMindConfig(**config_dict)
    
    def _validate_config(self) -> None:
        """Validate the loaded configuration."""
        if not self._config:
            raise ConfigValidationError("Configuration not loaded")
        
        # Validate required fields
        if self._config.environment == Environment.PRODUCTION:
            if not self._config.security.secret_key:
                raise ConfigValidationError("Secret key is required in production")
        
        # Validate port range
        if not (1 <= self._config.port <= 65535):
            raise ConfigValidationError(f"Invalid port number: {self._config.port}")
        
        # Validate logging level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self._config.logging.level.upper() not in valid_levels:
            raise ConfigValidationError(f"Invalid logging level: {self._config.logging.level}")
        
        # Validate scanner configuration
        if self._config.scanner.max_concurrent_scans <= 0:
            raise ConfigValidationError("max_concurrent_scans must be positive")
        
        # Validate AI configuration
        if self._config.ai.enabled and not self._config.ai.api_key:
            raise ConfigValidationError("AI API key is required when AI is enabled")
    
    @property
    def config(self) -> CyMindConfig:
        """Get the current configuration."""
        if not self._config:
            raise RuntimeError("Configuration not loaded")
        return self._config
    
    def reload(self) -> None:
        """Reload configuration from file."""
        self._load_config()
    
    def save_config(self, config_path: Optional[str] = None) -> None:
        """Save current configuration to file."""
        path = config_path or self.config_path
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Convert config to dictionary
        config_dict = self._config_to_dict()
        
        # Save to file
        with open(path, 'w') as f:
            if path.endswith('.yaml') or path.endswith('.yml'):
                yaml.dump(config_dict, f, default_flow_style=False)
            else:
                json.dump(config_dict, f, indent=2)
    
    def _config_to_dict(self) -> Dict[str, Any]:
        """Convert CyMindConfig object to dictionary."""
        if not self._config:
            return {}
        
        result = {
            'environment': self._config.environment.value,
            'debug': self._config.debug,
            'host': self._config.host,
            'port': self._config.port,
        }
        
        # Convert nested objects to dictionaries
        nested_objects = {
            'database': self._config.database,
            'logging': self._config.logging,
            'security': self._config.security,
            'scanner': self._config.scanner,
            'ai': self._config.ai,
            'plugins': self._config.plugins,
        }
        
        for key, obj in nested_objects.items():
            result[key] = obj.__dict__
        
        return result


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None


def get_config() -> CyMindConfig:
    """Get the global configuration instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.config


def reload_config() -> None:
    """Reload the global configuration."""
    global _config_manager
    if _config_manager is not None:
        _config_manager.reload()


def init_config(config_path: Optional[str] = None) -> None:
    """Initialize the global configuration manager."""
    global _config_manager
    _config_manager = ConfigManager(config_path)