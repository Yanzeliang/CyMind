"""
CyMind 错误处理系统
统一的错误处理和恢复机制
"""

import traceback
import functools
from typing import Dict, Any, Callable, Optional, Type
from datetime import datetime
from core.exceptions import *
from core.logging_config import get_logger, log_error_with_context


class ErrorHandler:
    """错误处理器"""
    
    def __init__(self):
        self.logger = get_logger("error_handler")
        self.error_counts = {}
        self.recovery_strategies = {}
    
    def handle_validation_error(self, error: ValidationError) -> Dict[str, Any]:
        """处理验证错误"""
        self.logger.warning(f"Validation error: {error.message} (field: {error.field})")
        
        return {
            "status": "error",
            "error_type": "validation",
            "message": error.message,
            "field": error.field,
            "code": error.error_code
        }
    
    def handle_resource_error(self, error: ResourceError) -> Dict[str, Any]:
        """处理资源错误"""
        self.logger.error(f"Resource error: {error.message} (type: {error.resource_type})")
        
        # 尝试恢复策略
        recovery_action = self._get_recovery_action("resource", error.resource_type)
        
        return {
            "status": "error",
            "error_type": "resource",
            "message": error.message,
            "resource_type": error.resource_type,
            "code": error.error_code,
            "recovery_action": recovery_action
        }
    
    def handle_tool_error(self, error: ToolError) -> Dict[str, Any]:
        """处理外部工具错误"""
        self.logger.error(f"Tool error: {error.message} (tool: {error.tool_name})")
        
        # 记录工具错误次数
        tool_key = f"tool_{error.tool_name}"
        self.error_counts[tool_key] = self.error_counts.get(tool_key, 0) + 1
        
        return {
            "status": "error",
            "error_type": "tool",
            "message": error.message,
            "tool_name": error.tool_name,
            "code": error.error_code,
            "error_count": self.error_counts[tool_key]
        }
    
    def handle_business_error(self, error: BusinessError) -> Dict[str, Any]:
        """处理业务逻辑错误"""
        self.logger.warning(f"Business error: {error.message} (operation: {error.operation})")
        
        return {
            "status": "error",
            "error_type": "business",
            "message": error.message,
            "operation": error.operation,
            "code": error.error_code
        }
    
    def handle_critical_error(self, error: CriticalError) -> Dict[str, Any]:
        """处理严重错误"""
        self.logger.critical(f"Critical error: {error.message} (component: {error.component})")
        
        # 通知管理员
        self.notify_admin(error)
        
        return {
            "status": "error",
            "error_type": "critical",
            "message": "A critical error occurred. Please contact support.",
            "component": error.component,
            "code": error.error_code,
            "timestamp": datetime.now().isoformat()
        }
    
    def log_error(self, error: Exception, context: Dict[str, Any] = None) -> None:
        """记录错误"""
        log_error_with_context(error, context)
        
        # 更新错误统计
        error_type = type(error).__name__
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
    
    def notify_admin(self, error: CriticalError) -> None:
        """通知管理员严重错误"""
        # 这里可以集成邮件、Slack、钉钉等通知系统
        self.logger.critical(f"ADMIN NOTIFICATION: {error.message}")
        
        # 可以在这里添加实际的通知逻辑
        # 例如：发送邮件、调用webhook等
    
    def retry_operation(self, operation: Callable, max_retries: int = 3, 
                       delay: float = 1.0, backoff: float = 2.0) -> Any:
        """重试操作"""
        import time
        
        last_exception = None
        current_delay = delay
        
        for attempt in range(max_retries + 1):
            try:
                return operation()
            except Exception as e:
                last_exception = e
                self.logger.warning(f"Operation failed (attempt {attempt + 1}/{max_retries + 1}): {e}")
                
                if attempt < max_retries:
                    time.sleep(current_delay)
                    current_delay *= backoff
                else:
                    self.logger.error(f"Operation failed after {max_retries + 1} attempts")
        
        raise last_exception
    
    def _get_recovery_action(self, error_type: str, resource_type: str = None) -> Optional[str]:
        """获取恢复操作建议"""
        recovery_map = {
            "resource": {
                "disk": "Free up disk space or change output directory",
                "memory": "Reduce concurrent operations or restart application",
                "network": "Check network connectivity and retry",
                "database": "Check database connection and restart if needed"
            },
            "tool": {
                "nmap": "Ensure nmap is installed and accessible",
                "nuclei": "Update nuclei templates and check installation",
                "subfinder": "Check subfinder configuration and API keys"
            }
        }
        
        if error_type in recovery_map:
            if resource_type and resource_type in recovery_map[error_type]:
                return recovery_map[error_type][resource_type]
            return "Check system resources and configuration"
        
        return None
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """获取错误统计"""
        return {
            "error_counts": self.error_counts.copy(),
            "total_errors": sum(self.error_counts.values()),
            "timestamp": datetime.now().isoformat()
        }
    
    def reset_error_counts(self) -> None:
        """重置错误计数"""
        self.error_counts.clear()
        self.logger.info("Error counts reset")


def error_handler_decorator(error_handler: ErrorHandler = None):
    """错误处理装饰器"""
    if error_handler is None:
        error_handler = ErrorHandler()
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ValidationError as e:
                return error_handler.handle_validation_error(e)
            except ResourceError as e:
                return error_handler.handle_resource_error(e)
            except ToolError as e:
                return error_handler.handle_tool_error(e)
            except BusinessError as e:
                return error_handler.handle_business_error(e)
            except CriticalError as e:
                return error_handler.handle_critical_error(e)
            except Exception as e:
                # 未预期的错误
                error_handler.log_error(e, {"function": func.__name__, "args": args, "kwargs": kwargs})
                return {
                    "status": "error",
                    "error_type": "unexpected",
                    "message": "An unexpected error occurred",
                    "code": "UNEXPECTED_ERROR"
                }
        return wrapper
    return decorator


def with_retry(max_retries: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """重试装饰器"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            error_handler = ErrorHandler()
            operation = lambda: func(*args, **kwargs)
            return error_handler.retry_operation(operation, max_retries, delay, backoff)
        return wrapper
    return decorator


# 全局错误处理器实例
_global_error_handler: Optional[ErrorHandler] = None


def get_error_handler() -> ErrorHandler:
    """获取全局错误处理器"""
    global _global_error_handler
    if _global_error_handler is None:
        _global_error_handler = ErrorHandler()
    return _global_error_handler