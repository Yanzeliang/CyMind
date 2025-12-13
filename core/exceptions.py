"""
CyMind 异常定义
定义系统中使用的所有自定义异常
"""


class CyMindException(Exception):
    """CyMind 基础异常类"""
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class ValidationError(CyMindException):
    """数据验证异常"""
    def __init__(self, message: str, field: str = None):
        super().__init__(message, "VALIDATION_ERROR")
        self.field = field


class ResourceError(CyMindException):
    """资源相关异常"""
    def __init__(self, message: str, resource_type: str = None):
        super().__init__(message, "RESOURCE_ERROR")
        self.resource_type = resource_type


class ToolError(CyMindException):
    """外部工具异常"""
    def __init__(self, message: str, tool_name: str = None):
        super().__init__(message, "TOOL_ERROR")
        self.tool_name = tool_name


class BusinessError(CyMindException):
    """业务逻辑异常"""
    def __init__(self, message: str, operation: str = None):
        super().__init__(message, "BUSINESS_ERROR")
        self.operation = operation


class CriticalError(CyMindException):
    """严重错误异常"""
    def __init__(self, message: str, component: str = None):
        super().__init__(message, "CRITICAL_ERROR")
        self.component = component


class AuthenticationError(CyMindException):
    """认证异常"""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, "AUTH_ERROR")


class AuthorizationError(CyMindException):
    """授权异常"""
    def __init__(self, message: str = "Access denied"):
        super().__init__(message, "AUTHZ_ERROR")


class PluginError(CyMindException):
    """插件异常"""
    def __init__(self, message: str, plugin_name: str = None):
        super().__init__(message, "PLUGIN_ERROR")
        self.plugin_name = plugin_name


class DatabaseError(CyMindException):
    """数据库异常"""
    def __init__(self, message: str, operation: str = None):
        super().__init__(message, "DATABASE_ERROR")
        self.operation = operation


class ConfigurationError(CyMindException):
    """配置异常"""
    def __init__(self, message: str, config_key: str = None):
        super().__init__(message, "CONFIG_ERROR")
        self.config_key = config_key