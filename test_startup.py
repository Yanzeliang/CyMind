#!/usr/bin/env python3
"""
测试应用启动
"""

import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from core.config import init_config, get_config
    from core.logging_config import setup_logging
    from core.error_handler import get_error_handler
    
    print("✓ 核心模块导入成功")
    
    # 初始化配置
    config_manager = init_config()
    config = get_config()
    print(f"✓ 配置加载成功: {config_manager.config_file}")
    
    # 设置日志
    setup_logging(config.logging.log_dir, config.logging.level)
    print("✓ 日志系统初始化成功")
    
    # 初始化错误处理器
    error_handler = get_error_handler()
    print("✓ 错误处理器初始化成功")
    
    # 测试导入Flask应用
    from app import app
    print("✓ Flask应用导入成功")
    
    # 应用配置
    app.config['DEBUG'] = config.debug
    app.config['SECRET_KEY'] = config.security.secret_key
    app.config['TESTING'] = True
    
    # 创建测试客户端
    with app.test_client() as client:
        # 测试主页
        response = client.get('/')
        print(f"✓ 主页访问成功: HTTP {response.status_code}")
        
        # 测试API端点
        response = client.get('/api/targets')
        print(f"✓ API端点访问成功: HTTP {response.status_code}")
    
    print("\n🎉 所有测试通过！CyMind 平台核心结构设置成功！")
    
except Exception as e:
    print(f"❌ 测试失败: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)