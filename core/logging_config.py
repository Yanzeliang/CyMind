"""
CyMind 日志配置
统一的日志配置和管理
"""

import logging
import logging.handlers
import os
from datetime import datetime
from typing import Optional


class CyMindLogger:
    """CyMind 日志管理器"""
    
    def __init__(self, log_dir: str = "logs", log_level: str = "INFO"):
        self.log_dir = log_dir
        self.log_level = getattr(logging, log_level.upper())
        self._setup_logging()
    
    def _setup_logging(self):
        """设置日志配置"""
        # 创建日志目录
        os.makedirs(self.log_dir, exist_ok=True)
        
        # 创建根日志器
        self.logger = logging.getLogger("cymind")
        self.logger.setLevel(self.log_level)
        
        # 清除现有处理器
        self.logger.handlers.clear()
        
        # 创建格式器
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # 文件处理器 - 应用日志
        app_log_file = os.path.join(self.log_dir, "cymind.log")
        file_handler = logging.handlers.RotatingFileHandler(
            app_log_file, maxBytes=10*1024*1024, backupCount=5
        )
        file_handler.setLevel(self.log_level)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # 错误日志文件
        error_log_file = os.path.join(self.log_dir, "error.log")
        error_handler = logging.handlers.RotatingFileHandler(
            error_log_file, maxBytes=10*1024*1024, backupCount=5
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        self.logger.addHandler(error_handler)
        
        # 扫描日志文件
        scan_log_file = os.path.join(self.log_dir, "scan.log")
        scan_handler = logging.handlers.RotatingFileHandler(
            scan_log_file, maxBytes=10*1024*1024, backupCount=5
        )
        scan_handler.setLevel(logging.INFO)
        scan_handler.setFormatter(formatter)
        
        # 创建扫描专用日志器
        scan_logger = logging.getLogger("cymind.scan")
        scan_logger.addHandler(scan_handler)
        scan_logger.setLevel(logging.INFO)
    
    def get_logger(self, name: str = None) -> logging.Logger:
        """获取日志器"""
        if name:
            return logging.getLogger(f"cymind.{name}")
        return self.logger
    
    def log_scan_event(self, event_type: str, target: str, details: dict = None):
        """记录扫描事件"""
        scan_logger = logging.getLogger("cymind.scan")
        message = f"[{event_type}] Target: {target}"
        if details:
            message += f" - Details: {details}"
        scan_logger.info(message)
    
    def log_error_with_context(self, error: Exception, context: dict = None):
        """记录带上下文的错误"""
        error_message = f"Error: {str(error)}"
        if context:
            error_message += f" - Context: {context}"
        self.logger.error(error_message, exc_info=True)


# 全局日志管理器实例
_logger_instance: Optional[CyMindLogger] = None


def setup_logging(log_dir: str = "logs", log_level: str = "INFO") -> CyMindLogger:
    """设置全局日志配置"""
    global _logger_instance
    _logger_instance = CyMindLogger(log_dir, log_level)
    return _logger_instance


def get_logger(name: str = None) -> logging.Logger:
    """获取日志器"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = CyMindLogger()
    return _logger_instance.get_logger(name)


def log_scan_event(event_type: str, target: str, details: dict = None):
    """记录扫描事件"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = CyMindLogger()
    _logger_instance.log_scan_event(event_type, target, details)


def log_error_with_context(error: Exception, context: dict = None):
    """记录带上下文的错误"""
    global _logger_instance
    if _logger_instance is None:
        _logger_instance = CyMindLogger()
    _logger_instance.log_error_with_context(error, context)