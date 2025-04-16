from flask import Flask, render_template, request, jsonify
import subprocess
import os
import json
import logging
from models import Session, ScanResult
from modules.target_manager import TargetManager
from modules.scanner import Scanner
from modules.reporter import Reporter

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# 初始化各模块
target_manager = TargetManager()
scanner = Scanner()
reporter = Reporter()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/targets', methods=['GET', 'POST'])
def handle_targets():
    if request.method == 'POST':
        # 处理目标添加/导入
        data = request.get_json()
        target_manager.add_target(data)
        return jsonify({"status": "success"})
    else:
        # 获取目标列表
        return jsonify(target_manager.get_targets())

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scan_type', 'port_scan')
    
    # 查找目标信息
    targets = target_manager.get_targets()
    target_info = next((t for t in targets if t['url'] == target), None)
    
    if not target_info:
        return jsonify({"status": "error", "message": "目标不存在"})
    
    result = scanner.run_scan(target_info, scan_type)
    return jsonify(result)

@app.route('/api/scan/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    status = scanner.get_scan_status(scan_id)
    return jsonify(status)

@app.route('/api/history', methods=['GET'])
def get_scan_history():
    session = Session()
    results = session.query(ScanResult).order_by(ScanResult.created_at.desc()).all()
    history = []
    for result in results:
        history.append({
            'id': result.id,
            'target': result.target,
            'scan_type': result.scan_type,
            'created_at': result.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    return jsonify(history)

@app.route('/api/history/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    session = Session()
    result = session.query(ScanResult).filter_by(id=scan_id).first()
    if not result:
        return jsonify({"status": "error", "message": "记录不存在"})
    return jsonify({
        'id': result.id,
        'target': result.target,
        'scan_type': result.scan_type,
        'result': json.loads(result.result),
        'created_at': result.created_at.strftime('%Y-%m-%d %H:%M:%S')
    })

if __name__ == '__main__':
    app.run(debug=True)
