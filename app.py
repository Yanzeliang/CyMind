from flask import Flask, render_template, request, jsonify
import subprocess
import os
import json
import logging
from models import Session, ScanResult, Scan, Target, Project
from modules.target_manager import TargetManager
from modules.project_manager import ProjectManager
from modules.scanner import Scanner
from modules.reporter import Reporter
from modules.recon_module import ReconModule

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
project_manager = ProjectManager()
scanner = Scanner()
reporter = Reporter()
recon_module = ReconModule()

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

# Project Management API Endpoints
@app.route('/api/projects', methods=['GET', 'POST'])
@error_handler_decorator(error_handler)
def handle_projects():
    if request.method == 'POST':
        # 创建新项目
        data = request.get_json()
        try:
            result = project_manager.create_project(data)
            if result['status'] == 'success':
                logger.info(f"项目创建成功: {data.get('name', 'Unknown')}")
                return jsonify(result)
            else:
                logger.warning(f"项目创建失败: {result.get('message', 'Unknown error')}")
                return jsonify(result), 400
        except Exception as e:
            logger.error(f"创建项目时发生错误: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    else:
        # 获取项目列表
        try:
            include_archived = request.args.get('include_archived', 'false').lower() == 'true'
            projects = project_manager.get_projects(include_archived=include_archived)
            logger.debug(f"返回 {len(projects)} 个项目")
            return jsonify(projects)
        except Exception as e:
            logger.error(f"获取项目列表失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/projects/<int:project_id>', methods=['GET', 'PUT', 'DELETE'])
@error_handler_decorator(error_handler)
def handle_project(project_id):
    if request.method == 'GET':
        # 获取项目详情
        try:
            project = project_manager.get_project(project_id)
            if project:
                return jsonify(project)
            else:
                return jsonify({"status": "error", "message": "项目不存在"}), 404
        except Exception as e:
            logger.error(f"获取项目详情失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    
    elif request.method == 'PUT':
        # 更新项目
        data = request.get_json()
        try:
            result = project_manager.update_project(project_id, data)
            if result['status'] == 'success':
                logger.info(f"项目更新成功: ID={project_id}")
                return jsonify(result)
            else:
                logger.warning(f"项目更新失败: {result.get('message', 'Unknown error')}")
                return jsonify(result), 400
        except Exception as e:
            logger.error(f"更新项目时发生错误: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    
    elif request.method == 'DELETE':
        # 删除项目
        try:
            force = request.args.get('force', 'false').lower() == 'true'
            result = project_manager.delete_project(project_id, force=force)
            if result['status'] == 'success':
                logger.info(f"项目删除成功: ID={project_id}")
                return jsonify(result)
            else:
                logger.warning(f"项目删除失败: {result.get('message', 'Unknown error')}")
                return jsonify(result), 400
        except Exception as e:
            logger.error(f"删除项目时发生错误: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/projects/<int:project_id>/archive', methods=['POST'])
@error_handler_decorator(error_handler)
def archive_project(project_id):
    try:
        result = project_manager.archive_project(project_id)
        if result['status'] == 'success':
            logger.info(f"项目归档成功: ID={project_id}")
            return jsonify(result)
        else:
            logger.warning(f"项目归档失败: {result.get('message', 'Unknown error')}")
            return jsonify(result), 400
    except Exception as e:
        logger.error(f"归档项目时发生错误: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/projects/<int:project_id>/restore', methods=['POST'])
@error_handler_decorator(error_handler)
def restore_project(project_id):
    try:
        result = project_manager.restore_project(project_id)
        if result['status'] == 'success':
            logger.info(f"项目恢复成功: ID={project_id}")
            return jsonify(result)
        else:
            logger.warning(f"项目恢复失败: {result.get('message', 'Unknown error')}")
            return jsonify(result), 400
    except Exception as e:
        logger.error(f"恢复项目时发生错误: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/projects/statistics', methods=['GET'])
@error_handler_decorator(error_handler)
def get_project_statistics():
    try:
        stats = project_manager.get_project_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"获取项目统计失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# Enhanced Target Management API Endpoints
@app.route('/api/projects/<int:project_id>/targets', methods=['GET', 'POST'])
@error_handler_decorator(error_handler)
def handle_project_targets(project_id):
    if request.method == 'POST':
        # 向项目添加目标
        data = request.get_json()
        try:
            result = target_manager.add_target(data, project_id)
            if result.get('status') == 'success':
                logger.info(f"目标添加到项目成功: project_id={project_id}")
                return jsonify(result)
            else:
                logger.warning(f"目标添加失败: {result.get('message', 'Unknown error')}")
                return jsonify(result), 400
        except Exception as e:
            logger.error(f"添加目标到项目时发生错误: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    else:
        # 获取项目的目标列表
        try:
            include_metadata = request.args.get('include_metadata', 'false').lower() == 'true'
            targets = target_manager.get_targets(project_id=project_id, include_metadata=include_metadata)
            logger.debug(f"返回项目 {project_id} 的 {len(targets)} 个目标")
            return jsonify(targets)
        except Exception as e:
            logger.error(f"获取项目目标列表失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/targets/<int:target_id>', methods=['GET', 'PUT', 'DELETE'])
@error_handler_decorator(error_handler)
def handle_target(target_id):
    if request.method == 'GET':
        # 获取目标详情
        try:
            target = target_manager.get_target_by_id(target_id)
            if target:
                return jsonify(target)
            else:
                return jsonify({"status": "error", "message": "目标不存在"}), 404
        except Exception as e:
            logger.error(f"获取目标详情失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    
    elif request.method == 'PUT':
        # 更新目标
        data = request.get_json()
        try:
            result = target_manager.update_target(target_id, data)
            if result['status'] == 'success':
                logger.info(f"目标更新成功: ID={target_id}")
                return jsonify(result)
            else:
                logger.warning(f"目标更新失败: {result.get('message', 'Unknown error')}")
                return jsonify(result), 400
        except Exception as e:
            logger.error(f"更新目标时发生错误: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500
    
    elif request.method == 'DELETE':
        # 删除目标
        try:
            result = target_manager.delete_target(target_id)
            if result['status'] == 'success':
                logger.info(f"目标删除成功: ID={target_id}")
                return jsonify(result)
            else:
                logger.warning(f"目标删除失败: {result.get('message', 'Unknown error')}")
                return jsonify(result), 400
        except Exception as e:
            logger.error(f"删除目标时发生错误: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/targets/search', methods=['GET'])
@error_handler_decorator(error_handler)
def search_targets():
    try:
        query = request.args.get('q', '')
        project_id = request.args.get('project_id', type=int)
        
        results = target_manager.search_targets(query, project_id)
        logger.debug(f"搜索目标: query='{query}', 找到 {len(results)} 个结果")
        return jsonify(results)
    except Exception as e:
        logger.error(f"搜索目标失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/targets/statistics', methods=['GET'])
@error_handler_decorator(error_handler)
def get_target_statistics():
    try:
        project_id = request.args.get('project_id', type=int)
        stats = target_manager.get_target_statistics(project_id)
        return jsonify(stats)
    except Exception as e:
        logger.error(f"获取目标统计失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/targets/bulk-import', methods=['POST'])
@error_handler_decorator(error_handler)
def bulk_import_targets():
    try:
        data = request.get_json()
        targets_data = data.get('targets', [])
        project_id = data.get('project_id')
        
        result = target_manager.bulk_import_targets(targets_data, project_id)
        logger.info(f"批量导入完成: 成功={result['success']}, 失败={result['failed']}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"批量导入目标失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# Comprehensive Reconnaissance API Endpoints
@app.route('/api/recon/tools', methods=['GET'])
@error_handler_decorator(error_handler)
def get_available_recon_tools():
    """Get list of available reconnaissance tools"""
    try:
        tools = recon_module.list_available_tools()
        logger.debug(f"返回 {len(tools)} 个可用的侦察工具")
        return jsonify(tools)
    except Exception as e:
        logger.error(f"获取可用侦察工具失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/recon/comprehensive', methods=['POST'])
@error_handler_decorator(error_handler)
def start_comprehensive_recon():
    """Start comprehensive reconnaissance scan"""
    try:
        data = request.get_json()
        target_id = data.get('target_id')
        tools = data.get('tools')  # Optional, will use defaults if not provided
        
        # Get target information
        target = target_manager.get_target_by_id(target_id)
        if not target:
            return jsonify({"status": "error", "message": "目标不存在"}), 404
        
        # Start comprehensive reconnaissance
        result = recon_module.run_comprehensive_recon(target, tools)
        
        if result['status'] == 'started':
            logger.info(f"综合侦察启动成功: target_id={target_id}, scan_id={result['scan_id']}")
        else:
            logger.warning(f"综合侦察启动失败: {result.get('message', 'Unknown error')}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"启动综合侦察失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/recon/scan/<scan_id>', methods=['GET'])
@error_handler_decorator(error_handler)
def get_recon_scan_status(scan_id):
    """Get reconnaissance scan status and results"""
    try:
        status = recon_module.get_scan_status(scan_id)
        
        if status['status'] == 'not_found':
            return jsonify({"status": "error", "message": "扫描不存在"}), 404
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"获取侦察扫描状态失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/recon/subdomain', methods=['POST'])
@error_handler_decorator(error_handler)
def start_subdomain_enumeration():
    """Start subdomain enumeration for a specific target"""
    try:
        data = request.get_json()
        target_id = data.get('target_id')
        
        # Get target information
        target = target_manager.get_target_by_id(target_id)
        if not target:
            return jsonify({"status": "error", "message": "目标不存在"}), 404
        
        # Extract domain from target
        domain = target.get('url', '').replace('https://', '').replace('http://', '').split('/')[0]
        if not domain:
            domain = target.get('name', '')
        
        if not domain:
            return jsonify({"status": "error", "message": "无法确定目标域名"}), 400
        
        # Run subdomain enumeration
        results = recon_module._run_subdomain_enumeration(domain)
        
        logger.info(f"子域名枚举完成: domain={domain}, 发现 {len(results)} 个子域名")
        return jsonify({
            "status": "completed",
            "domain": domain,
            "subdomains": results,
            "count": len(results)
        })
        
    except Exception as e:
        logger.error(f"子域名枚举失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/recon/services', methods=['POST'])
@error_handler_decorator(error_handler)
def start_service_fingerprinting():
    """Start service fingerprinting for a specific target"""
    try:
        data = request.get_json()
        target_id = data.get('target_id')
        
        # Get target information
        target = target_manager.get_target_by_id(target_id)
        if not target:
            return jsonify({"status": "error", "message": "目标不存在"}), 404
        
        # Extract host information
        host = target.get('url', '').replace('https://', '').replace('http://', '').split('/')[0]
        if not host:
            host = target.get('name', '')
        
        ip = target.get('ip_address')
        
        if not host and not ip:
            return jsonify({"status": "error", "message": "无法确定目标主机"}), 400
        
        # Run service fingerprinting
        results = recon_module._run_service_fingerprinting(host, ip)
        
        logger.info(f"服务指纹识别完成: host={host}, 发现 {len(results)} 个服务")
        return jsonify({
            "status": "completed",
            "host": host,
            "ip": ip,
            "services": results,
            "count": len(results)
        })
        
    except Exception as e:
        logger.error(f"服务指纹识别失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/recon/dns', methods=['POST'])
@error_handler_decorator(error_handler)
def start_dns_analysis():
    """Start DNS analysis for a specific target"""
    try:
        data = request.get_json()
        target_id = data.get('target_id')
        
        # Get target information
        target = target_manager.get_target_by_id(target_id)
        if not target:
            return jsonify({"status": "error", "message": "目标不存在"}), 404
        
        # Extract domain from target
        domain = target.get('url', '').replace('https://', '').replace('http://', '').split('/')[0]
        if not domain:
            domain = target.get('name', '')
        
        if not domain:
            return jsonify({"status": "error", "message": "无法确定目标域名"}), 400
        
        # Run DNS analysis
        results = recon_module._run_dns_analysis(domain)
        
        logger.info(f"DNS分析完成: domain={domain}")
        return jsonify({
            "status": "completed",
            "domain": domain,
            "dns_results": results
        })
        
    except Exception as e:
        logger.error(f"DNS分析失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/recon/technology', methods=['POST'])
@error_handler_decorator(error_handler)
def start_technology_identification():
    """Start technology stack identification for a specific target"""
    try:
        data = request.get_json()
        target_id = data.get('target_id')
        
        # Get target information
        target = target_manager.get_target_by_id(target_id)
        if not target:
            return jsonify({"status": "error", "message": "目标不存在"}), 404
        
        # Get target URL
        url = target.get('url')
        if not url:
            # Try to construct URL from name or IP
            host = target.get('name') or target.get('ip_address')
            if host:
                url = f"http://{host}"
            else:
                return jsonify({"status": "error", "message": "无法确定目标URL"}), 400
        
        # Run technology identification
        results = recon_module._run_technology_identification(url)
        
        logger.info(f"技术栈识别完成: url={url}")
        return jsonify({
            "status": "completed",
            "url": url,
            "technology_results": results
        })
        
    except Exception as e:
        logger.error(f"技术栈识别失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/recon/cleanup', methods=['POST'])
@error_handler_decorator(error_handler)
def cleanup_completed_recon_scans():
    """Clean up completed reconnaissance scans from memory"""
    try:
        recon_module.cleanup_completed_scans()
        logger.info("已清理完成的侦察扫描")
        return jsonify({"status": "success", "message": "清理完成"})
    except Exception as e:
        logger.error(f"清理侦察扫描失败: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
