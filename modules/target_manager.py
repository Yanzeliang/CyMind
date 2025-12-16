import csv
import json
import logging
import ipaddress
import re
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse
from models import (
    Session, Project, Target, TargetType, ProjectStatus, 
    DataValidator, db_manager
)
from core.error_handler import error_handler_decorator, get_error_handler
from core.logging_config import get_logger

logger = get_logger("cymind.target_manager")
error_handler = get_error_handler()


class TargetManager:
    def __init__(self):
        self.validator = DataValidator()
        # 确保有一个默认项目
        self._ensure_default_project()
        
    @error_handler_decorator(error_handler)
    def _ensure_default_project(self):
        """确保存在默认项目"""
        session = Session()
        try:
            # 查找或创建默认项目
            default_project = session.query(Project).filter_by(name="默认项目").first()
            if not default_project:
                logger.info("创建默认项目")
                default_project = Project(
                    name="默认项目",
                    description="用于存放未分类的扫描目标",
                    status=ProjectStatus.ACTIVE.value
                )
                session.add(default_project)
                session.commit()
                
                # 添加默认测试目标
                test_target = Target(
                    project_id=default_project.id,
                    name="NMAP测试目标",
                    url="scanme.nmap.org",
                    ip_address="45.33.32.156",
                    target_type=TargetType.DOMAIN.value,
                    tags=["测试", "公开"]
                )
                session.add(test_target)
                session.commit()
                logger.info("默认项目和测试目标创建完成")
        except Exception as e:
            session.rollback()
            logger.error(f"创建默认项目失败: {e}")
            raise
        finally:
            session.close()
        
    @error_handler_decorator(error_handler)
    def add_target(self, target_data: Dict, project_id: Optional[int] = None) -> Dict:
        """
        添加单个目标到指定项目
        
        Args:
            target_data: 目标数据字典
            project_id: 项目ID，如果为None则使用默认项目
        
        Returns:
            包含目标信息的字典
        """
        logger.info(f"添加目标: {target_data.get('name', 'Unknown')}")
        
        if isinstance(target_data, str):
            try:
                target_data = json.loads(target_data)
            except json.JSONDecodeError:
                logger.error("目标数据JSON格式无效")
                raise ValueError("无效的目标数据格式")
        
        # 验证目标数据
        validation_errors = self._validate_target_data(target_data)
        if validation_errors:
            logger.warning(f"目标数据验证失败: {validation_errors}")
            raise ValueError(f"目标数据验证失败: {', '.join(validation_errors)}")
        
        session = Session()
        try:
            # 获取项目
            if project_id:
                project = session.query(Project).filter_by(id=project_id).first()
                if not project:
                    logger.error(f"项目不存在: ID={project_id}")
                    raise ValueError(f"项目不存在: {project_id}")
            else:
                # 获取默认项目
                project = session.query(Project).filter_by(name="默认项目").first()
                if not project:
                    self._ensure_default_project()
                    project = session.query(Project).filter_by(name="默认项目").first()
            
            # 检查重复目标
            existing_target = self._check_duplicate_target(session, target_data, project.id)
            if existing_target:
                logger.warning(f"目标已存在: {existing_target.name}")
                return {
                    'status': 'warning',
                    'message': '目标已存在',
                    'existing_target': {
                        'id': existing_target.id,
                        'name': existing_target.name,
                        'url': existing_target.url,
                        'ip_address': existing_target.ip_address
                    }
                }
            
            # 处理和验证目标数据
            processed_data = self._process_target_data(target_data)
            
            # 创建新目标
            target = Target(
                project_id=project.id,
                name=processed_data['name'],
                url=processed_data.get('url', ''),
                ip_address=processed_data.get('ip_address', ''),
                target_type=processed_data['target_type'],
                target_metadata=processed_data.get('metadata', {}),
                tags=processed_data.get('tags', [])
            )
            
            session.add(target)
            session.commit()
            session.refresh(target)
            
            logger.info(f"目标添加成功: ID={target.id}, Name={target.name}")
            
            return {
                'status': 'success',
                'target': {
                    'id': target.id,
                    'name': target.name,
                    'url': target.url,
                    'ip_address': target.ip_address,
                    'type': target.target_type,
                    'tags': target.tags or [],
                    'project_id': target.project_id,
                    'created_at': target.created_at.strftime('%Y-%m-%d %H:%M:%S')
                }
            }
        except Exception as e:
            session.rollback()
            logger.error(f"添加目标失败: {e}")
            raise
        finally:
            session.close()
    
    def _validate_target_data(self, target_data: Dict) -> List[str]:
        """验证目标数据"""
        errors = []
        
        if not isinstance(target_data, dict):
            errors.append("目标数据必须是字典")
            return errors
        
        # 检查必需字段
        if not target_data.get('url') and not target_data.get('ip'):
            errors.append("目标必须包含URL或IP地址")
        
        # 验证URL格式
        if target_data.get('url'):
            if not self._is_valid_url(target_data['url']):
                errors.append("URL格式无效")
        
        # 验证IP地址格式
        if target_data.get('ip'):
            if not self._is_valid_ip(target_data['ip']):
                errors.append("IP地址格式无效")
        
        # 验证目标名称
        name = target_data.get('name', '').strip()
        if len(name) > 255:
            errors.append("目标名称不能超过255个字符")
        
        return errors
    
    def _is_valid_url(self, url: str) -> bool:
        """验证URL格式"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _is_valid_ip(self, ip: str) -> bool:
        """验证IP地址格式"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _check_duplicate_target(self, session, target_data: Dict, project_id: int) -> Optional[Target]:
        """检查重复目标"""
        query = session.query(Target).filter_by(project_id=project_id)
        
        if target_data.get('url'):
            existing = query.filter_by(url=target_data['url']).first()
            if existing:
                return existing
        
        if target_data.get('ip'):
            existing = query.filter_by(ip_address=target_data['ip']).first()
            if existing:
                return existing
        
        return None
    
    def _process_target_data(self, target_data: Dict) -> Dict:
        """处理和标准化目标数据"""
        processed = {}
        
        # 处理名称
        if target_data.get('name'):
            processed['name'] = target_data['name'].strip()
        else:
            # 自动生成名称
            if target_data.get('url'):
                parsed = urlparse(target_data['url'])
                processed['name'] = parsed.netloc or target_data['url']
            elif target_data.get('ip'):
                processed['name'] = f"IP-{target_data['ip']}"
            else:
                processed['name'] = "未命名目标"
        
        # 处理URL
        if target_data.get('url'):
            url = target_data['url'].strip()
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            processed['url'] = url
        
        # 处理IP地址
        if target_data.get('ip'):
            processed['ip_address'] = target_data['ip'].strip()
        
        # 确定目标类型
        processed['target_type'] = self._determine_target_type(target_data)
        
        # 处理标签
        if target_data.get('tags'):
            if isinstance(target_data['tags'], str):
                processed['tags'] = [tag.strip() for tag in target_data['tags'].split(',') if tag.strip()]
            elif isinstance(target_data['tags'], list):
                processed['tags'] = [str(tag).strip() for tag in target_data['tags'] if str(tag).strip()]
            else:
                processed['tags'] = []
        else:
            processed['tags'] = []
        
        # 处理元数据
        metadata = {}
        if target_data.get('description'):
            metadata['description'] = target_data['description']
        if target_data.get('priority'):
            metadata['priority'] = target_data['priority']
        if target_data.get('notes'):
            metadata['notes'] = target_data['notes']
        
        processed['metadata'] = metadata
        
        return processed
    
    def _determine_target_type(self, target_data: Dict) -> str:
        """智能确定目标类型"""
        # 如果明确指定了类型
        if target_data.get('type'):
            return self._map_target_type(target_data['type'])
        
        # 根据数据自动判断
        if target_data.get('url'):
            url = target_data['url'].lower()
            if '/api/' in url or url.endswith('/api'):
                return TargetType.URL.value
            else:
                return TargetType.DOMAIN.value
        elif target_data.get('ip'):
            # 检查是否是网络段
            if '/' in target_data['ip']:
                return TargetType.NETWORK.value
            else:
                return TargetType.IP.value
        
        return TargetType.DOMAIN.value
    
    def _map_target_type(self, type_str: str) -> str:
        """映射目标类型"""
        type_mapping = {
            'website': TargetType.DOMAIN.value,
            'domain': TargetType.DOMAIN.value,
            'api': TargetType.URL.value,
            'url': TargetType.URL.value,
            'network': TargetType.NETWORK.value,
            'service': TargetType.IP.value,
            'ip': TargetType.IP.value
        }
        return type_mapping.get(type_str.lower(), TargetType.DOMAIN.value)
    
    @error_handler_decorator(error_handler)
    def bulk_import_targets(self, targets_data: List[Dict], project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        批量导入目标
        
        Args:
            targets_data: 目标数据列表
            project_id: 项目ID，如果为None则使用默认项目
        
        Returns:
            导入结果统计
        """
        logger.info(f"开始批量导入 {len(targets_data)} 个目标")
        
        results = {
            'total': len(targets_data),
            'success': 0,
            'failed': 0,
            'duplicates': 0,
            'errors': []
        }
        
        for i, target_data in enumerate(targets_data):
            try:
                result = self.add_target(target_data, project_id)
                if result.get('status') == 'success':
                    results['success'] += 1
                elif result.get('status') == 'warning':
                    results['duplicates'] += 1
                else:
                    results['failed'] += 1
                    results['errors'].append(f"目标 {i+1}: {result.get('message', '未知错误')}")
            except Exception as e:
                results['failed'] += 1
                results['errors'].append(f"目标 {i+1}: {str(e)}")
                logger.error(f"导入目标 {i+1} 失败: {e}")
        
        logger.info(f"批量导入完成: 成功={results['success']}, 失败={results['failed']}, 重复={results['duplicates']}")
        return results
    
    @error_handler_decorator(error_handler)
    def import_from_csv(self, file_path: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        从CSV文件导入目标
        
        Args:
            file_path: CSV文件路径
            project_id: 项目ID
        
        Returns:
            导入结果统计
        """
        logger.info(f"从CSV文件导入目标: {file_path}")
        
        try:
            targets_data = []
            with open(file_path, mode='r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    targets_data.append(row)
            
            return self.bulk_import_targets(targets_data, project_id)
            
        except FileNotFoundError:
            logger.error(f"CSV文件不存在: {file_path}")
            raise ValueError(f"文件不存在: {file_path}")
        except Exception as e:
            logger.error(f"读取CSV文件失败: {e}")
            raise ValueError(f"读取CSV文件失败: {e}")
    
    @error_handler_decorator(error_handler)
    def import_from_text(self, text_content: str, project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        从文本内容导入目标（每行一个URL/IP）
        
        Args:
            text_content: 文本内容
            project_id: 项目ID
        
        Returns:
            导入结果统计
        """
        logger.info("从文本内容导入目标")
        
        lines = text_content.strip().split('\n')
        targets_data = []
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 简单解析：如果是IP地址格式，作为IP处理，否则作为URL处理
            if self._is_valid_ip(line):
                targets_data.append({'ip': line})
            else:
                targets_data.append({'url': line})
        
        return self.bulk_import_targets(targets_data, project_id)
    
    @error_handler_decorator(error_handler)
    def get_targets(self, project_id: Optional[int] = None, include_metadata: bool = False) -> List[Dict]:
        """
        获取目标列表
        
        Args:
            project_id: 项目ID，如果为None则获取所有目标
            include_metadata: 是否包含元数据
        
        Returns:
            目标列表
        """
        logger.debug(f"获取目标列表: project_id={project_id}")
        
        session = Session()
        try:
            query = session.query(Target)
            
            if project_id:
                query = query.filter_by(project_id=project_id)
            
            targets = query.order_by(Target.created_at.desc()).all()
            
            result = []
            for target in targets:
                target_dict = {
                    'id': target.id,
                    'name': target.name,
                    'url': target.url,
                    'ip': target.ip_address,
                    'type': target.target_type,
                    'tags': target.tags or [],
                    'project_id': target.project_id,
                    'created_at': target.created_at.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                if include_metadata and target.target_metadata:
                    target_dict['metadata'] = target.target_metadata
                
                result.append(target_dict)
            
            logger.debug(f"返回 {len(result)} 个目标")
            return result
        except Exception as e:
            logger.error(f"获取目标列表失败: {e}")
            return []
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def get_target_by_id(self, target_id: int) -> Optional[Dict]:
        """
        根据ID获取目标详情
        
        Args:
            target_id: 目标ID
        
        Returns:
            目标详情字典或None
        """
        logger.debug(f"获取目标详情: ID={target_id}")
        
        session = Session()
        try:
            target = session.query(Target).filter_by(id=target_id).first()
            if target:
                return {
                    'id': target.id,
                    'name': target.name,
                    'url': target.url,
                    'ip_address': target.ip_address,
                    'type': target.target_type,
                    'tags': target.tags or [],
                    'project_id': target.project_id,
                    'metadata': target.target_metadata or {},
                    'created_at': target.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'scan_count': len(target.scans) if hasattr(target, 'scans') else 0
                }
            
            logger.warning(f"目标不存在: ID={target_id}")
            return None
        except Exception as e:
            logger.error(f"获取目标详情失败: {e}")
            return None
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def update_target(self, target_id: int, update_data: Dict) -> Dict[str, Any]:
        """
        更新目标信息
        
        Args:
            target_id: 目标ID
            update_data: 更新数据
        
        Returns:
            更新结果
        """
        logger.info(f"更新目标: ID={target_id}")
        
        # 验证更新数据
        validation_errors = self._validate_target_data(update_data)
        if validation_errors:
            logger.warning(f"目标更新数据验证失败: {validation_errors}")
            return {
                'status': 'error',
                'message': '数据验证失败',
                'errors': validation_errors
            }
        
        session = Session()
        try:
            target = session.query(Target).filter_by(id=target_id).first()
            if not target:
                logger.warning(f"目标不存在: ID={target_id}")
                return {
                    'status': 'error',
                    'message': '目标不存在'
                }
            
            # 处理更新数据
            processed_data = self._process_target_data(update_data)
            
            # 更新字段
            for field, value in processed_data.items():
                if hasattr(target, field):
                    setattr(target, field, value)
            
            session.commit()
            session.refresh(target)
            
            logger.info(f"目标更新成功: ID={target_id}")
            
            return {
                'status': 'success',
                'target': {
                    'id': target.id,
                    'name': target.name,
                    'url': target.url,
                    'ip_address': target.ip_address,
                    'type': target.target_type,
                    'tags': target.tags or [],
                    'project_id': target.project_id
                }
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"更新目标失败: {e}")
            return {
                'status': 'error',
                'message': f'更新失败: {str(e)}'
            }
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def delete_target(self, target_id: int) -> Dict[str, Any]:
        """
        删除目标
        
        Args:
            target_id: 目标ID
        
        Returns:
            删除结果
        """
        logger.warning(f"删除目标: ID={target_id}")
        
        session = Session()
        try:
            target = session.query(Target).filter_by(id=target_id).first()
            if not target:
                logger.warning(f"目标不存在: ID={target_id}")
                return {
                    'status': 'error',
                    'message': '目标不存在'
                }
            
            target_name = target.name
            session.delete(target)
            session.commit()
            
            logger.warning(f"目标已删除: {target_name}")
            
            return {
                'status': 'success',
                'message': f'目标 "{target_name}" 已删除'
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"删除目标失败: {e}")
            return {
                'status': 'error',
                'message': f'删除失败: {str(e)}'
            }
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def search_targets(self, query: str, project_id: Optional[int] = None) -> List[Dict]:
        """
        搜索目标
        
        Args:
            query: 搜索查询
            project_id: 项目ID限制
        
        Returns:
            匹配的目标列表
        """
        logger.debug(f"搜索目标: query='{query}', project_id={project_id}")
        
        if not query.strip():
            return self.get_targets(project_id)
        
        session = Session()
        try:
            query_filter = session.query(Target)
            
            if project_id:
                query_filter = query_filter.filter_by(project_id=project_id)
            
            # 搜索名称、URL、IP地址
            search_term = f"%{query.strip()}%"
            query_filter = query_filter.filter(
                Target.name.ilike(search_term) |
                Target.url.ilike(search_term) |
                Target.ip_address.ilike(search_term)
            )
            
            targets = query_filter.order_by(Target.created_at.desc()).all()
            
            result = []
            for target in targets:
                result.append({
                    'id': target.id,
                    'name': target.name,
                    'url': target.url,
                    'ip_address': target.ip_address,
                    'type': target.target_type,
                    'tags': target.tags or [],
                    'project_id': target.project_id,
                    'created_at': target.created_at.strftime('%Y-%m-%d %H:%M:%S')
                })
            
            logger.debug(f"搜索到 {len(result)} 个目标")
            return result
            
        except Exception as e:
            logger.error(f"搜索目标失败: {e}")
            return []
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def get_targets_by_tags(self, tags: List[str], project_id: Optional[int] = None) -> List[Dict]:
        """
        根据标签获取目标
        
        Args:
            tags: 标签列表
            project_id: 项目ID限制
        
        Returns:
            匹配的目标列表
        """
        logger.debug(f"根据标签获取目标: tags={tags}, project_id={project_id}")
        
        session = Session()
        try:
            query_filter = session.query(Target)
            
            if project_id:
                query_filter = query_filter.filter_by(project_id=project_id)
            
            # 过滤包含指定标签的目标
            matching_targets = []
            for target in query_filter.all():
                target_tags = target.tags or []
                if any(tag in target_tags for tag in tags):
                    matching_targets.append({
                        'id': target.id,
                        'name': target.name,
                        'url': target.url,
                        'ip_address': target.ip_address,
                        'type': target.target_type,
                        'tags': target_tags,
                        'project_id': target.project_id,
                        'created_at': target.created_at.strftime('%Y-%m-%d %H:%M:%S')
                    })
            
            logger.debug(f"找到 {len(matching_targets)} 个匹配标签的目标")
            return matching_targets
            
        except Exception as e:
            logger.error(f"根据标签获取目标失败: {e}")
            return []
        finally:
            session.close()
    
    @error_handler_decorator(error_handler)
    def get_target_statistics(self, project_id: Optional[int] = None) -> Dict[str, Any]:
        """
        获取目标统计信息
        
        Args:
            project_id: 项目ID限制
        
        Returns:
            统计信息字典
        """
        logger.debug(f"获取目标统计: project_id={project_id}")
        
        session = Session()
        try:
            query = session.query(Target)
            
            if project_id:
                query = query.filter_by(project_id=project_id)
            
            targets = query.all()
            
            # 统计各种类型的目标
            type_counts = {}
            tag_counts = {}
            
            for target in targets:
                # 统计类型
                target_type = target.target_type
                type_counts[target_type] = type_counts.get(target_type, 0) + 1
                
                # 统计标签
                for tag in (target.tags or []):
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
            
            statistics = {
                'total_targets': len(targets),
                'type_distribution': type_counts,
                'tag_distribution': tag_counts,
                'most_common_tags': sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            }
            
            logger.debug(f"目标统计: {statistics}")
            return statistics
            
        except Exception as e:
            logger.error(f"获取目标统计失败: {e}")
            return {
                'total_targets': 0,
                'type_distribution': {},
                'tag_distribution': {},
                'most_common_tags': []
            }
        finally:
            session.close()
