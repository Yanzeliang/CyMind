"""
Pytest 配置文件
定义测试夹具和配置
"""

import pytest
import tempfile
import os
import shutil
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base
from core.logging_config import setup_logging


@pytest.fixture(scope="session")
def test_db():
    """测试数据库夹具"""
    # 创建临时数据库
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test.db")
    engine = create_engine(f"sqlite:///{db_path}")
    
    # 创建表
    Base.metadata.create_all(engine)
    
    # 创建会话
    Session = sessionmaker(bind=engine)
    
    yield Session
    
    # 清理
    shutil.rmtree(temp_dir)


@pytest.fixture(scope="session")
def test_logger():
    """测试日志夹具"""
    temp_dir = tempfile.mkdtemp()
    logger = setup_logging(log_dir=temp_dir, log_level="DEBUG")
    
    yield logger
    
    # 清理
    shutil.rmtree(temp_dir)


@pytest.fixture
def sample_target_data():
    """示例目标数据"""
    return {
        "name": "Test Target",
        "url": "example.com",
        "ip": "192.168.1.1",
        "type": "website",
        "tags": ["test", "example"]
    }


@pytest.fixture
def sample_scan_config():
    """示例扫描配置"""
    return {
        "timeout": 300,
        "threads": 10,
        "aggressive": False,
        "custom_ports": [80, 443, 8080]
    }


@pytest.fixture
def temp_csv_file():
    """临时CSV文件夹具"""
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
    temp_file.write("name,url,ip,type\n")
    temp_file.write("Test1,test1.com,1.1.1.1,website\n")
    temp_file.write("Test2,test2.com,2.2.2.2,api\n")
    temp_file.close()
    
    yield temp_file.name
    
    # 清理
    os.unlink(temp_file.name)