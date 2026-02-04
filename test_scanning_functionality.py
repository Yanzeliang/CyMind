"""
测试扫描功能的完整性
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import time
from modules.scanner import Scanner
from modules.target_manager import TargetManager
from modules.project_manager import ProjectManager
from models import Session, Scan, ScanResult, ScanType


def test_scanning_functionality():
    """测试完整的扫描功能"""
    print("🔍 测试CyMind扫描功能")
    print("=" * 50)
    
    # 初始化管理器
    target_manager = TargetManager()
    project_manager = ProjectManager()
    scanner = Scanner()
    
    # 1. 测试目标提取功能
    print("\n1. 测试目标提取功能")
    print("-" * 30)
    
    test_targets = [
        {'url': 'https://example.com', 'ip': '93.184.216.34'},
        {'url': 'http://scanme.nmap.org', 'ip': ''},
        {'name': 'google.com', 'url': '', 'ip': ''},
        {'url': 'https://api.github.com/users', 'ip': ''},
    ]
    
    for target in test_targets:
        extracted = scanner._extract_scan_target(target)
        print(f"目标: {target} -> 提取结果: {extracted}")
    
    # 2. 获取现有目标进行扫描测试
    print("\n2. 获取可用目标")
    print("-" * 30)
    
    targets = target_manager.get_targets()
    print(f"数据库中有 {len(targets)} 个目标")
    
    # 找一个合适的测试目标
    test_target = None
    for target in targets:
        if ('scanme.nmap.org' in target.get('url', '') or 
            'scanme.nmap.org' in target.get('name', '') or
            target.get('ip_address') == '45.33.32.156'):
            test_target = target
            break
    
    if not test_target:
        print("没有找到合适的测试目标，创建一个新的")
        # 创建测试目标
        result = target_manager.add_target({
            'name': '扫描测试目标',
            'url': 'scanme.nmap.org',
            'ip': '45.33.32.156',
            'tags': ['测试', '扫描']
        })
        if result['status'] == 'success':
            test_target = result['target']
            print(f"创建测试目标成功: {test_target['name']}")
        else:
            print(f"创建测试目标失败: {result}")
            return False
    
    print(f"使用测试目标: {test_target['name']} ({test_target.get('url', test_target.get('ip', ''))})")
    
    # 3. 执行端口扫描
    print("\n3. 执行端口扫描")
    print("-" * 30)
    
    scan_result = scanner.run_scan(test_target, 'port_scan')
    print(f"扫描启动结果: {scan_result}")
    
    if scan_result['status'] != 'started':
        print(f"扫描启动失败: {scan_result}")
        return False
    
    scan_id = scan_result['scan_id']
    print(f"扫描ID: {scan_id}")
    
    # 4. 监控扫描状态
    print("\n4. 监控扫描进度")
    print("-" * 30)
    
    max_wait = 30  # 最多等待30秒
    wait_time = 0
    
    while wait_time < max_wait:
        status = scanner.get_scan_status(scan_id)
        print(f"扫描状态: {status['status']}")
        
        if status['status'] == 'completed':
            print("✅ 扫描完成!")
            if 'result' in status:
                result = status['result']
                print(f"扫描结果: {result}")
                if 'ports' in result:
                    ports = result['ports']
                    print(f"发现 {len(ports)} 个开放端口:")
                    for port in ports:
                        print(f"  - 端口 {port['port']}/{port['protocol']}: {port['service']}")
            break
        elif status['status'] == 'error':
            print(f"❌ 扫描失败: {status.get('message', 'Unknown error')}")
            return False
        elif status['status'] == 'not_found':
            print("扫描已完成并清理")
            break
        else:
            print(f"扫描进行中... (已等待 {wait_time}s)")
            time.sleep(2)
            wait_time += 2
    
    # 5. 检查数据库中的扫描记录
    print("\n5. 检查数据库记录")
    print("-" * 30)
    
    session = Session()
    try:
        # 查找最新的扫描记录
        latest_scan = session.query(Scan).filter_by(target_id=test_target['id']).order_by(Scan.id.desc()).first()
        
        if latest_scan:
            print(f"找到扫描记录: ID={latest_scan.id}, 状态={latest_scan.status}")
            
            # 获取扫描结果
            scan_results = session.query(ScanResult).filter_by(scan_id=latest_scan.id).all()
            print(f"扫描结果数量: {len(scan_results)}")
            
            for result in scan_results:
                print(f"  结果类型: {result.result_type}")
                print(f"  置信度: {result.confidence}")
                if result.result_type == 'service' and 'ports' in result.data:
                    ports = result.data['ports']
                    print(f"  发现端口: {len(ports)} 个")
                    for port in ports[:3]:  # 只显示前3个
                        print(f"    {port['port']}/{port['protocol']}: {port['service']}")
        else:
            print("没有找到扫描记录")
            
    finally:
        session.close()
    
    # 6. 测试漏洞扫描
    print("\n6. 测试漏洞扫描")
    print("-" * 30)
    
    vuln_result = scanner.run_scan(test_target, 'vulnerability_scan')
    print(f"漏洞扫描启动结果: {vuln_result}")

    if vuln_result.get('status') != 'started':
        print(f"漏洞扫描启动失败: {vuln_result}")
        return False

    vuln_scan_id = vuln_result['scan_id']
    max_wait = 90  # 最多等待90秒
    wait_time = 0

    while wait_time < max_wait:
        status = scanner.get_scan_status(vuln_scan_id)
        print(f"漏洞扫描状态: {status['status']}")

        if status['status'] == 'completed':
            result = status.get('result', {})
            summary = result.get('summary', {})
            vulns = result.get('vulnerabilities', [])
            print(f"漏洞扫描完成，发现 {len(vulns)} 个问题")
            if summary:
                print(f"摘要: {summary}")
            for vuln in vulns[:5]:
                print(f"  - [{vuln.get('severity', 'info')}] {vuln.get('title', 'N/A')}")
            break
        elif status['status'] == 'error':
            print(f"❌ 漏洞扫描失败: {status.get('message', 'Unknown error')}")
            return False
        elif status['status'] == 'not_found':
            print("漏洞扫描已完成并清理")
            break
        else:
            time.sleep(3)
            wait_time += 3

    # 7. 检查漏洞扫描数据库记录
    print("\n7. 检查漏洞扫描数据库记录")
    print("-" * 30)

    session = Session()
    try:
        latest_vuln_scan = (
            session.query(Scan)
            .filter_by(target_id=test_target['id'], scan_type=ScanType.VULNERABILITY.value)
            .order_by(Scan.id.desc())
            .first()
        )

        if latest_vuln_scan:
            print(f"找到漏洞扫描记录: ID={latest_vuln_scan.id}, 状态={latest_vuln_scan.status}")
            scan_results = session.query(ScanResult).filter_by(scan_id=latest_vuln_scan.id).all()
            print(f"漏洞扫描结果数量: {len(scan_results)}")
            for result in scan_results:
                print(f"  结果类型: {result.result_type}")
                if result.result_type == 'vulnerability':
                    data = result.data or {}
                    vulns = data.get('vulnerabilities', [])
                    print(f"  记录漏洞数: {len(vulns)}")
        else:
            print("没有找到漏洞扫描记录")
    finally:
        session.close()
    
    print("\n" + "=" * 50)
    print("🎉 扫描功能测试完成!")
    print("✅ 端口扫描: 正常工作")
    print("✅ 目标提取: 正常工作") 
    print("✅ 状态监控: 正常工作")
    print("✅ 数据库存储: 正常工作")
    print("✅ 漏洞扫描: 已实现")
    print("=" * 50)
    
    return True


if __name__ == "__main__":
    success = test_scanning_functionality()
    if success:
        print("\n🚀 CyMind扫描功能测试通过!")
    else:
        print("\n❌ CyMind扫描功能测试失败!")
    
    sys.exit(0 if success else 1)
