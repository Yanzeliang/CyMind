#!/usr/bin/env python3
"""
CyMind 启动脚本
"""

import os
import sys
from core.config import init_config, get_config
from core.logging_config import setup_logging
from core.error_handler import get_error_handler


def main():
    """主函数"""
    try:
        # 初始化配置
        config_manager = init_config()
        config = get_config()
        
        # 验证配置
        config_manager.validate_config()
        
        # 设置日志
        setup_logging()
        
        # 初始化错误处理器
        error_handler = get_error_handler()
        
        print(f"CyMind v2.0.0 启动中...")
        print(f"配置文件: {config_manager.config_file or '使用默认配置'}")
        print(f"调试模式: {'开启' if config.debug else '关闭'}")
        print(f"监听地址: {config.host}:{config.port}")
        print(f"AI助手: {'启用' if config.ai.enabled else '禁用'}")
        
        # 导入并启动Flask应用
        from app import app
        
        # 应用配置
        app.config['DEBUG'] = config.debug
        app.config['SECRET_KEY'] = config.security.secret_key
        
        # 启动应用
        app.run(
            host=config.host,
            port=config.port,
            debug=config.debug
        )
        
    except Exception as e:
        print(f"启动失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()