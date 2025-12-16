#!/usr/bin/env python3
"""
CyMind Web服务器启动脚本
在本地启动Web界面供用户访问
"""

import sys
import os
import webbrowser
import time
import threading
from datetime import datetime

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_startup_info():
    """打印启动信息"""
    print("""
🧠 CyMind v2.0.0 - 自动化渗透测试平台
═══════════════════════════════════════

🚀 正在启动Web服务器...
    """)

def open_browser_delayed():
    """延迟打开浏览器"""
    time.sleep(2)  # 等待服务器启动
    try:
        webbrowser.open('http://127.0.0.1:5000')
        print("🌐 浏览器已自动打开")
    except:
        print("🌐 请手动打开浏览器访问: http://127.0.0.1:5000")

def main():
    """主函数"""
    try:
        print_startup_info()
        
        # 初始化核心系统
        from core.config import init_config, get_config
        from core.logging_config import setup_logging
        from core.error_handler import get_error_handler
        
        print("⚙️ 初始化配置系统...")
        config_manager = init_config()
        config = get_config()
        
        # 确保config_manager不为None
        if config_manager is None:
            from core.config import ConfigManager
            config_manager = ConfigManager()
        
        print("📝 设置日志系统...")
        setup_logging()
        
        print("🛡️ 初始化错误处理...")
        error_handler = get_error_handler()
        
        # 导入Flask应用
        from app import app
        
        print("🌐 配置Web应用...")
        app.config['DEBUG'] = config.debug
        app.config['SECRET_KEY'] = config.security.secret_key
        
        # 显示启动信息
        print(f"""
✅ 系统初始化完成！

📊 配置信息:
   • 配置文件: {getattr(config_manager, 'config_file', None) or '使用默认配置'}
   • 调试模式: {'开启' if config.debug else '关闭'}
   • 监听地址: {config.host}:{config.port}
   • 数据库: {config.database.url}
   • AI助手: {'启用' if config.ai.enabled else '禁用'}
   • 日志级别: {config.logging.level}

🌐 Web界面地址: http://{config.host}:{config.port}

📋 可用功能:
   • 目标管理 - 添加和管理扫描目标
   • 端口扫描 - 使用Nmap进行端口扫描
   • 扫描历史 - 查看历史扫描结果
   • 报告生成 - 生成扫描报告

🔧 API端点:
   • GET  /api/targets     - 获取目标列表
   • POST /api/targets     - 添加新目标
   • POST /api/scan        - 启动扫描
   • GET  /api/history     - 获取扫描历史

⚠️ 注意事项:
   • 这是开发版本，仅用于演示和测试
   • 请确保已安装nmap工具进行端口扫描
   • 按 Ctrl+C 停止服务器

🕐 启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """)
        
        # 在后台线程中打开浏览器
        browser_thread = threading.Thread(target=open_browser_delayed)
        browser_thread.daemon = True
        browser_thread.start()
        
        print("🚀 启动Web服务器...")
        print("=" * 50)
        
        # 启动Flask应用
        app.run(
            host=config.host,
            port=8080,  # 临时硬编码端口
            debug=config.debug,
            use_reloader=False  # 避免重复启动
        )
        
    except KeyboardInterrupt:
        print("\n\n👋 服务器已停止")
        print("感谢使用 CyMind 平台！")
    except Exception as e:
        print(f"\n❌ 启动失败: {e}")
        print("\n🔧 故障排除:")
        print("1. 检查端口5000是否被占用")
        print("2. 确认所有依赖已正确安装")
        print("3. 检查配置文件cymind.yaml")
        sys.exit(1)

if __name__ == "__main__":
    main()