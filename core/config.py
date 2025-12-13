"""
CyMind 配置管理
统一的配置管理系统
"""

import os
import json
import yaml
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from core.exceptions import ConfigurationError


@dataclass
class DatabaseConfig:
    """数据库配置"""
    url: str = "sqlite:///cymind.db"
    echo: bool = False
    pool_size: int = 10
    max_overflow: int = 20


@dataclass
class ScannerConfig:
    """扫描器配置"""
    max_concurrent_scans: int = 5
    default_timeout: int = 300
    nmap_path: str = "nmap"
    nuclei_path: str = "nuclei"
    subfinder_path: str = "subfinder"
    gobuster_path: str = "gobuster"


@dataclass
class AIConfig:
    """AI助手配置"""
    enabled: bool = False
    provider: str = "openai"  # openai, local, azure
    api_key: Optional[str] = None
    api_base: Optional[str] = None
    model: str = "gpt-3.5-turbo"
    max_tokens: int = 2048
    temperature: float = 0.7


@dataclass
class SecurityConfig:
    """安全配置"""
    secret_key: str = "change-me-in-production"
    session_timeout: int = 3600  # 1 hour
    max_login_attempts: int = 5
    password_min_length: int = 8
    enable_csrf: bool = True
    enable_rate_limiting: bool = True


@dataclass
class LoggingConfig:
    """日志配置"""
    level: str = "INFO"
    log_dir: str = "logs"
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    enable_console: bool = True


@dataclass
class ReportConfig:
    """报告配置"""
    template_dir: str = "templates/reports"
    output_dir: str = "reports"
    default_template: str = "default"
    enable_pdf: bool = True
    pdf_engine: str = "weasyprint"


@dataclass
class PluginConfig:
    """插件配置"""
    plugin_dir: str = "plugins"
    enable_plugins: bool = True
    auto_load: bool = True
    sandbox_enabled: bool = True


@dataclass
class CyMindConfig:
    """CyMind 主配置"""
    debug: bool = False
    host: str = "127.0.0.1"
    port: int = 5000
    
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    ai: AIConfig = field(default_factory=AIConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    plugin: PluginConfig = field(default_factory=PluginConfig)


class ConfigManager:
    """配置管理器"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or self._find_config_file()
        self.config = CyMindConfig()
        self._load_config()
    
    def _find_config_file(self) -> Optional[str]:
        """查找配置文件"""
        possible_files = [
            "cymind.yaml",
            "cymind.yml", 
            "config.yaml",
            "config.yml",
            "cymind.json",
            "config.json"
        ]
        
        for filename in possible_files:
            if os.path.exists(filename):
                return filename
        
        return None
    
    def _load_config(self):
        """加载配置"""
        # 首先从环境变量加载
        self._load_from_env()
        
        # 然后从配置文件加载（如果存在）
        if self.config_file and os.path.exists(self.config_file):
            self._load_from_file()
    
    def _load_from_env(self):
        """从环境变量加载配置"""
        env_mappings = {
            "CYMIND_DEBUG": ("debug", bool),
            "CYMIND_HOST": ("host", str),
            "CYMIND_PORT": ("port", int),
            
            # 数据库配置
            "CYMIND_DB_URL": ("database.url", str),
            "CYMIND_DB_ECHO": ("database.echo", bool),
            
            # 扫描器配置
            "CYMIND_MAX_SCANS": ("scanner.max_concurrent_scans", int),
            "CYMIND_SCAN_TIMEOUT": ("scanner.default_timeout", int),
            "NMAP_PATH": ("scanner.nmap_path", str),
            "NUCLEI_PATH": ("scanner.nuclei_path", str),
            
            # AI配置
            "CYMIND_AI_ENABLED": ("ai.enabled", bool),
            "CYMIND_AI_PROVIDER": ("ai.provider", str),
            "CYMIND_AI_API_KEY": ("ai.api_key", str),
            "CYMIND_AI_MODEL": ("ai.model", str),
            
            # 安全配置
            "CYMIND_SECRET_KEY": ("security.secret_key", str),
            "CYMIND_SESSION_TIMEOUT": ("security.session_timeout", int),
            
            # 日志配置
            "CYMIND_LOG_LEVEL": ("logging.level", str),
            "CYMIND_LOG_DIR": ("logging.log_dir", str),
        }
        
        for env_var, (config_path, value_type) in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                try:
                    if value_type == bool:
                        value = env_value.lower() in ("true", "1", "yes", "on")
                    elif value_type == int:
                        value = int(env_value)
                    else:
                        value = env_value
                    
                    self._set_nested_attr(self.config, config_path, value)
                except (ValueError, TypeError) as e:
                    raise ConfigurationError(f"Invalid value for {env_var}: {env_value}") from e
    
    def _load_from_file(self):
        """从配置文件加载"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                if self.config_file.endswith(('.yaml', '.yml')):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            self._update_config_from_dict(data)
            
        except (FileNotFoundError, json.JSONDecodeError, yaml.YAMLError) as e:
            raise ConfigurationError(f"Failed to load config file {self.config_file}: {e}") from e
    
    def _update_config_from_dict(self, data: Dict[str, Any]):
        """从字典更新配置"""
        def update_nested(obj, updates):
            for key, value in updates.items():
                if hasattr(obj, key):
                    attr = getattr(obj, key)
                    if hasattr(attr, '__dict__') and isinstance(value, dict):
                        update_nested(attr, value)
                    else:
                        setattr(obj, key, value)
        
        update_nested(self.config, data)
    
    def _set_nested_attr(self, obj, path: str, value):
        """设置嵌套属性"""
        parts = path.split('.')
        for part in parts[:-1]:
            obj = getattr(obj, part)
        setattr(obj, parts[-1], value)
    
    def get_config(self) -> CyMindConfig:
        """获取配置对象"""
        return self.config
    
    def validate_config(self) -> bool:
        """验证配置"""
        errors = []
        
        # 验证必需的配置
        if not self.config.security.secret_key or self.config.security.secret_key == "change-me-in-production":
            if not self.config.debug:
                errors.append("Security secret key must be set in production")
        
        # 验证AI配置
        if self.config.ai.enabled and not self.config.ai.api_key:
            errors.append("AI API key is required when AI is enabled")
        
        # 验证路径
        paths_to_check = [
            ("scanner.nmap_path", self.config.scanner.nmap_path),
            ("scanner.nuclei_path", self.config.scanner.nuclei_path),
        ]
        
        for path_name, path_value in paths_to_check:
            if not self._check_executable(path_value):
                errors.append(f"Executable not found: {path_name} = {path_value}")
        
        if errors:
            raise ConfigurationError(f"Configuration validation failed: {'; '.join(errors)}")
        
        return True
    
    def _check_executable(self, path: str) -> bool:
        """检查可执行文件是否存在"""
        import shutil
        return shutil.which(path) is not None
    
    def save_config(self, file_path: Optional[str] = None):
        """保存配置到文件"""
        output_file = file_path or self.config_file or "cymind.yaml"
        
        # 转换配置为字典
        config_dict = self._config_to_dict(self.config)
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                if output_file.endswith(('.yaml', '.yml')):
                    yaml.dump(config_dict, f, default_flow_style=False, indent=2)
                else:
                    json.dump(config_dict, f, indent=2)
        except Exception as e:
            raise ConfigurationError(f"Failed to save config to {output_file}: {e}") from e
    
    def _config_to_dict(self, obj) -> Dict[str, Any]:
        """将配置对象转换为字典"""
        if hasattr(obj, '__dict__'):
            result = {}
            for key, value in obj.__dict__.items():
                if hasattr(value, '__dict__'):
                    result[key] = self._config_to_dict(value)
                else:
                    result[key] = value
            return result
        return obj


# 全局配置管理器实例
_config_manager: Optional[ConfigManager] = None


def get_config() -> CyMindConfig:
    """获取全局配置"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager.get_config()


def init_config(config_file: Optional[str] = None) -> ConfigManager:
    """初始化配置管理器"""
    global _config_manager
    _config_manager = ConfigManager(config_file)
    return _config_manager