"""
测试核心结构和接口
验证新的项目结构是否正确设置
"""

import pytest
import os
import tempfile
from core.config import ConfigManager, CyMindConfig
from core.logging_config import setup_logging, get_logger
from core.error_handler import ErrorHandler
from core.exceptions import ValidationError, ConfigurationError
from core.interfaces import TargetDTO, ScanTaskDTO, ValidationResult


class TestCoreStructure:
    """测试核心结构"""
    
    def test_config_manager_initialization(self):
        """测试配置管理器初始化"""
        config_manager = ConfigManager()
        config = config_manager.get_config()
        
        assert isinstance(config, CyMindConfig)
        assert config.host == "127.0.0.1"
        assert config.port == 5000
        assert config.database.url == "sqlite:///cymind.db"
    
    def test_config_from_env(self, monkeypatch):
        """测试从环境变量加载配置"""
        # 临时移动配置文件
        import shutil
        backup_file = None
        if os.path.exists("cymind.yaml"):
            backup_file = "cymind.yaml.backup"
            shutil.move("cymind.yaml", backup_file)
        
        try:
            monkeypatch.setenv("CYMIND_HOST", "0.0.0.0")
            monkeypatch.setenv("CYMIND_PORT", "8080")
            monkeypatch.setenv("CYMIND_DEBUG", "false")
            
            # 创建配置管理器
            config_manager = ConfigManager()
            config = config_manager.get_config()
            
            assert config.host == "0.0.0.0"
            assert config.port == 8080
            assert config.debug is False
        finally:
            # 恢复配置文件
            if backup_file and os.path.exists(backup_file):
                shutil.move(backup_file, "cymind.yaml")
    
    def test_logging_setup(self):
        """测试日志设置"""
        with tempfile.TemporaryDirectory() as temp_dir:
            logger_manager = setup_logging(log_dir=temp_dir, log_level="DEBUG")
            logger = get_logger("test")
            
            assert logger is not None
            logger.info("Test log message")
            
            # 检查日志文件是否创建
            log_files = os.listdir(temp_dir)
            assert len(log_files) > 0
    
    def test_error_handler(self):
        """测试错误处理器"""
        error_handler = ErrorHandler()
        
        # 测试验证错误处理
        validation_error = ValidationError("Invalid input", "email")
        result = error_handler.handle_validation_error(validation_error)
        
        assert result["status"] == "error"
        assert result["error_type"] == "validation"
        assert result["message"] == "Invalid input"
        assert result["field"] == "email"
    
    def test_dto_classes(self):
        """测试数据传输对象"""
        # 测试 TargetDTO
        target = TargetDTO(
            name="Test Target",
            url="https://example.com",
            ip="192.168.1.1",
            type="website"
        )
        
        assert target.name == "Test Target"
        assert target.url == "https://example.com"
        assert target.ip == "192.168.1.1"
        assert target.type == "website"
        assert target.tags == []
    
    def test_validation_result(self):
        """测试验证结果类"""
        # 有效结果
        valid_result = ValidationResult(is_valid=True)
        assert valid_result.is_valid is True
        assert valid_result.errors == []
        
        # 无效结果
        invalid_result = ValidationResult(is_valid=False, errors=["Error 1", "Error 2"])
        assert invalid_result.is_valid is False
        assert len(invalid_result.errors) == 2
    
    def test_config_validation(self):
        """测试配置验证"""
        config_manager = ConfigManager()
        
        # 在调试模式下，跳过工具路径验证
        config_manager.config.debug = True
        
        # 临时禁用工具路径检查
        original_check = config_manager._check_executable
        config_manager._check_executable = lambda x: True
        
        try:
            assert config_manager.validate_config() is True
        finally:
            config_manager._check_executable = original_check
    
    def test_directory_structure(self):
        """测试目录结构是否正确创建"""
        expected_dirs = [
            "core",
            "tests",
            "tests/property_tests"
        ]
        
        for dir_path in expected_dirs:
            assert os.path.exists(dir_path), f"Directory {dir_path} should exist"
            assert os.path.isdir(dir_path), f"{dir_path} should be a directory"
    
    def test_required_files(self):
        """测试必需文件是否存在"""
        required_files = [
            "core/__init__.py",
            "core/interfaces.py",
            "core/exceptions.py",
            "core/logging_config.py",
            "core/config.py",
            "core/error_handler.py",
            "tests/__init__.py",
            "tests/conftest.py",
            "tests/property_tests/__init__.py",
            "tests/property_tests/strategies.py",
            "requirements.txt",
            "cymind.yaml.example",
            "run.py"
        ]
        
        for file_path in required_files:
            assert os.path.exists(file_path), f"File {file_path} should exist"
            assert os.path.isfile(file_path), f"{file_path} should be a file"


if __name__ == "__main__":
    pytest.main([__file__])