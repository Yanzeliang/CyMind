from flask import Flask, render_template, request, jsonify
import subprocess
import os
import json
import logging
from models import Session, ScanResult, Scan, Target, Project
from modules.target_manager import TargetManager
from modules.scanner import Scanner
from modules.reporter import Reporter

# 导入增强的核心模块
from core.config import get_config, init_config
from core.logging_config import get_logger, setup_logging
from core.error_handler import get_error_handler, error_handler_decorator, ErrorContext

app = Flask(__name__)

# 初始化核心基础设施
init_config()
setup_logging()

# 使用增强的日志和错误处理系统
logger = get_logger("cymind.app")
error_handler = get_error_handler()

# 初始化各模块
target_manager = TargetManager()
scanner = Scanner()
reporter = Reporter()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/targets', methods=['GET', 'POST'])
@error_handler_decorator(error_handler)
def handle_targets():
    if request.method == 'POST':
        # 处理目标添加/导入
        data = request.get_json()
        try:
            new_target = target_manager.add_target(data)
            logger.info(f"目标添加成功: {data.get('name', 'Unknown')}")
            return jsonify({"status": "success", "target": new_target})
        except Exception as e:
            logger.error(f"添加目标失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 400
    else:
        # 获取目标列表
        try:
            targets = target_manager.get_targets()
            logger.debug(f"返回 {len(targets)} 个目标")
            return jsonify(targets)
        except Exception as e:
            logger.error(f"获取目标列表失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/scan', methods=['POST'])
@error_handler_decorator(error_handler)
def start_scan():
    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scan_type', 'port_scan')
    
    logger.info(f"启动扫描: 目标={target}, 类型={scan_type}")
    
    # 查找目标信息
    targets = target_manager.get_targets()
    target_info = next((t for t in targets if t['url'] == target), None)
    
    if not target_info:
        logger.warning(f"目标不存在: {target}")
        return jsonify({"status": "error", "message": "目标不存在"})
    
    result = scanner.run_scan(target_info, scan_type)
    logger.info(f"扫描启动结果: {result.get('status', 'unknown')}")
    return jsonify(result)

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    status = scanner.get_scan_status(scan_id)
    return jsonify(status)

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    session = Session()
    try:
        # 查询扫描记录，包含关联的目标信息
        scans = session.query(Scan).join(Target).order_by(Scan.started_at.desc()).all()
        history = []
        for scan in scans:
            history.append({
                'id': scan.id,
                'target': scan.target.name or scan.target.url,
                'scan_type': scan.scan_type,
                'status': scan.status,
                'created_at': scan.started_at.strftime('%Y-%m-%d %H:%M:%S'),
                'result_count': len(scan.results)
            })
        return jsonify(history)
    finally:
        session.close()

@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    session = Session()
    try:
        # 查询扫描记录，包含关联的目标和结果
        scan = session.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return jsonify({"status": "error", "message": "扫描记录不存在"})
        
        # 收集所有扫描结果
        results = []
        for result in scan.results:
            results.append({
                'id': result.id,
                'type': result.result_type,
                'data': result.data,
                'severity': result.severity,
                'confidence': result.confidence,
                'created_at': result.created_at.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return jsonify({
            'id': scan.id,
            'target': scan.target.name or scan.target.url,
            'scan_type': scan.scan_type,
            'status': scan.status,
            'results': results,
            'started_at': scan.started_at.strftime('%Y-%m-%d %H:%M:%S'),
            'completed_at': scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else None
        })
    finally:
        session.close()

if __name__ == '__main__':
    app.run(debug=True)
