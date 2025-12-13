"""
CyMind 核心接口定义
定义所有模块的抽象基类和接口
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from enum import Enum


class ScanType(Enum):
    """扫描类型枚举"""
    PORT_SCAN = "port_scan"
    SUBDOMAIN_ENUM = "subdomain_enum"
    VULNERABILITY_SCAN = "vulnerability_scan"
    WEB_DIRECTORY_SCAN = "web_directory_scan"
    SERVICE_FINGERPRINT = "service_fingerprint"
    SSL_ANALYSIS = "ssl_analysis"


class ScanStatus(Enum):
    """扫描状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReportFormat(Enum):
    """报告格式枚举"""
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"
    JSON = "json"


class Severity(Enum):
    """漏洞严重程度枚举"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# 数据传输对象 (DTOs)
class TargetDTO:
    """目标数据传输对象"""
    def __init__(self, id: Optional[int] = None, name: str = "", 
                 url: Optional[str] = None, ip: Optional[str] = None,
                 type: str = "website", tags: List[str] = None,
                 created_at: Optional[datetime] = None,
                 updated_at: Optional[datetime] = None,
                 user_id: Optional[int] = None):
        self.id = id
        self.name = name
        self.url = url
        self.ip = ip
        self.type = type
        self.tags = tags or []
        self.created_at = created_at
        self.updated_at = updated_at
        self.user_id = user_id


class ScanTaskDTO:
    """扫描任务数据传输对象"""
    def __init__(self, id: Optional[str] = None, target_id: int = None,
                 scan_type: ScanType = None, status: ScanStatus = ScanStatus.PENDING,
                 config: Dict = None, started_at: Optional[datetime] = None,
                 completed_at: Optional[datetime] = None, user_id: Optional[int] = None):
        self.id = id
        self.target_id = target_id
        self.scan_type = scan_type
        self.status = status
        self.config = config or {}
        self.started_at = started_at
        self.completed_at = completed_at
        self.user_id = user_id


class ScanResultDTO:
    """扫描结果数据传输对象"""
    def __init__(self, id: Optional[int] = None, task_id: str = None,
                 target_id: int = None, scan_type: ScanType = None,
                 result_data: Dict = None, severity: Severity = Severity.INFO,
                 created_at: Optional[datetime] = None):
        self.id = id
        self.task_id = task_id
        self.target_id = target_id
        self.scan_type = scan_type
        self.result_data = result_data or {}
        self.severity = severity
        self.created_at = created_at


class ValidationResult:
    """验证结果类"""
    def __init__(self, is_valid: bool = True, errors: List[str] = None):
        self.is_valid = is_valid
        self.errors = errors or []


# 核心接口定义
class ITargetManager(ABC):
    """目标管理器接口"""
    
    @abstractmethod
    def add_target(self, target_data: Dict) -> TargetDTO:
        """添加新目标"""
        pass
    
    @abstractmethod
    def update_target(self, target_id: int, updates: Dict) -> TargetDTO:
        """更新目标信息"""
        pass
    
    @abstractmethod
    def delete_target(self, target_id: int) -> bool:
        """删除目标"""
        pass
    
    @abstractmethod
    def get_targets(self, filters: Dict = None) -> List[TargetDTO]:
        """获取目标列表"""
        pass
    
    @abstractmethod
    def get_target_by_id(self, target_id: int) -> Optional[TargetDTO]:
        """根据ID获取目标"""
        pass
    
    @abstractmethod
    def import_from_csv(self, file_path: str) -> List[TargetDTO]:
        """从CSV文件导入目标"""
        pass
    
    @abstractmethod
    def export_to_csv(self, target_ids: List[int]) -> str:
        """导出目标到CSV文件"""
        pass
    
    @abstractmethod
    def validate_target(self, target_data: Dict) -> ValidationResult:
        """验证目标数据"""
        pass


class IScanner(ABC):
    """扫描器接口"""
    
    @abstractmethod
    def start_scan(self, target: TargetDTO, scan_config: Dict) -> ScanTaskDTO:
        """启动扫描任务"""
        pass
    
    @abstractmethod
    def get_scan_status(self, task_id: str) -> ScanTaskDTO:
        """获取扫描状态"""
        pass
    
    @abstractmethod
    def cancel_scan(self, task_id: str) -> bool:
        """取消扫描任务"""
        pass
    
    @abstractmethod
    def get_scan_results(self, task_id: str) -> List[ScanResultDTO]:
        """获取扫描结果"""
        pass
    
    @abstractmethod
    def register_scanner(self, scanner_type: ScanType, scanner_class: type) -> None:
        """注册扫描器"""
        pass


class IReporter(ABC):
    """报告生成器接口"""
    
    @abstractmethod
    def generate_report(self, scan_results: List[ScanResultDTO], 
                       template: str, format: ReportFormat) -> str:
        """生成报告"""
        pass
    
    @abstractmethod
    def save_report(self, report_content: str, file_path: str) -> None:
        """保存报告到文件"""
        pass
    
    @abstractmethod
    def get_templates(self) -> List[str]:
        """获取可用模板列表"""
        pass
    
    @abstractmethod
    def create_template(self, template_data: Dict) -> str:
        """创建新模板"""
        pass
    
    @abstractmethod
    def generate_summary(self, scan_results: List[ScanResultDTO]) -> Dict:
        """生成报告摘要"""
        pass


class IAIAssistant(ABC):
    """AI助手接口"""
    
    @abstractmethod
    def analyze_vulnerabilities(self, scan_results: List[ScanResultDTO]) -> Dict:
        """分析漏洞"""
        pass
    
    @abstractmethod
    def generate_exploit_suggestions(self, vulnerability: Dict) -> List[Dict]:
        """生成利用建议"""
        pass
    
    @abstractmethod
    def create_executive_summary(self, scan_results: List[ScanResultDTO]) -> str:
        """创建执行摘要"""
        pass
    
    @abstractmethod
    def chat_interface(self, user_input: str, context: Dict) -> str:
        """聊天接口"""
        pass
    
    @abstractmethod
    def recommend_scan_strategy(self, target: TargetDTO) -> Dict:
        """推荐扫描策略"""
        pass


class IPluginSystem(ABC):
    """插件系统接口"""
    
    @abstractmethod
    def register_plugin(self, plugin: 'Plugin') -> bool:
        """注册插件"""
        pass
    
    @abstractmethod
    def execute_plugin(self, plugin_name: str, params: Dict) -> Dict:
        """执行插件"""
        pass
    
    @abstractmethod
    def get_plugins(self) -> List['Plugin']:
        """获取插件列表"""
        pass
    
    @abstractmethod
    def validate_plugin(self, plugin_path: str) -> ValidationResult:
        """验证插件"""
        pass
    
    @abstractmethod
    def uninstall_plugin(self, plugin_name: str) -> bool:
        """卸载插件"""
        pass


class ISessionManager(ABC):
    """会话管理器接口"""
    
    @abstractmethod
    def create_session(self, user_id: int) -> str:
        """创建用户会话"""
        pass
    
    @abstractmethod
    def validate_session(self, session_id: str) -> bool:
        """验证会话"""
        pass
    
    @abstractmethod
    def get_user_from_session(self, session_id: str) -> Optional[int]:
        """从会话获取用户ID"""
        pass
    
    @abstractmethod
    def associate_task(self, session_id: str, task_id: str) -> None:
        """关联任务到会话"""
        pass
    
    @abstractmethod
    def cleanup_session(self, session_id: str) -> None:
        """清理会话"""
        pass


class IVulnerabilityDatabase(ABC):
    """漏洞数据库接口"""
    
    @abstractmethod
    def load_cve_database(self) -> bool:
        """加载CVE数据库"""
        pass
    
    @abstractmethod
    def match_vulnerabilities(self, service_info: Dict) -> List[Dict]:
        """匹配漏洞"""
        pass
    
    @abstractmethod
    def update_database(self) -> bool:
        """更新数据库"""
        pass
    
    @abstractmethod
    def get_vulnerability_details(self, cve_id: str) -> Optional[Dict]:
        """获取漏洞详情"""
        pass
    
    @abstractmethod
    def search_vulnerabilities(self, query: str) -> List[Dict]:
        """搜索漏洞"""
        pass


# 插件基类
class Plugin(ABC):
    """插件基类"""
    
    def __init__(self, name: str, version: str, description: str):
        self.name = name
        self.version = version
        self.description = description
    
    @abstractmethod
    def execute(self, params: Dict) -> Dict:
        """执行插件"""
        pass
    
    @abstractmethod
    def validate_params(self, params: Dict) -> ValidationResult:
        """验证参数"""
        pass
    
    @abstractmethod
    def get_config_schema(self) -> Dict:
        """获取配置模式"""
        pass