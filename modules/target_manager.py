import csv
import json
from typing import List, Dict
from models import Session, Project, Target, TargetType, ProjectStatus

class TargetManager:
    def __init__(self):
        # 确保有一个默认项目
        self._ensure_default_project()
        
    def _ensure_default_project(self):
        """确保存在默认项目"""
        session = Session()
        try:
            # 查找或创建默认项目
            default_project = session.query(Project).filter_by(name="默认项目").first()
            if not default_project:
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
        finally:
            session.close()
        
    def add_target(self, target_data: Dict) -> Dict:
        """添加单个目标"""
        if isinstance(target_data, str):
            try:
                target_data = json.loads(target_data)
            except json.JSONDecodeError:
                raise ValueError("无效的目标数据格式")
        
        # 基本验证
        if not isinstance(target_data, dict):
            raise ValueError("目标数据必须是字典")
            
        if not target_data.get('url') and not target_data.get('ip'):
            raise ValueError("目标必须包含URL或IP地址")
        
        session = Session()
        try:
            # 获取默认项目
            default_project = session.query(Project).filter_by(name="默认项目").first()
            if not default_project:
                self._ensure_default_project()
                default_project = session.query(Project).filter_by(name="默认项目").first()
            
            # 创建新目标
            target = Target(
                project_id=default_project.id,
                name=target_data.get('name', ''),
                url=target_data.get('url', ''),
                ip_address=target_data.get('ip', ''),
                target_type=self._map_target_type(target_data.get('type', 'website')),
                tags=target_data.get('tags', '').split(',') if target_data.get('tags') else []
            )
            
            session.add(target)
            session.commit()
            
            return {
                'id': target.id,
                'name': target.name,
                'url': target.url,
                'ip': target.ip_address,
                'type': target.target_type,
                'created_at': target.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        finally:
            session.close()
    
    def _map_target_type(self, type_str: str) -> str:
        """映射目标类型"""
        type_mapping = {
            'website': TargetType.DOMAIN.value,
            'api': TargetType.URL.value,
            'network': TargetType.NETWORK.value,
            'service': TargetType.IP.value
        }
        return type_mapping.get(type_str, TargetType.DOMAIN.value)
    
    def import_from_csv(self, file_path: str) -> None:
        """从CSV文件导入目标"""
        with open(file_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                self.add_target(row)
    
    def get_targets(self) -> List[Dict]:
        """获取所有目标"""
        session = Session()
        try:
            targets = session.query(Target).all()
            result = []
            for target in targets:
                result.append({
                    'id': target.id,
                    'name': target.name,
                    'url': target.url,
                    'ip': target.ip_address,
                    'type': target.target_type,
                    'tags': target.tags or [],
                    'created_at': target.created_at.strftime('%Y-%m-%d %H:%M:%S')
                })
            return result
        finally:
            session.close()
    
    def get_target_by_id(self, target_id: int) -> Dict:
        """根据ID获取目标"""
        session = Session()
        try:
            target = session.query(Target).filter_by(id=target_id).first()
            if target:
                return {
                    'id': target.id,
                    'name': target.name,
                    'url': target.url,
                    'ip': target.ip_address,
                    'type': target.target_type,
                    'tags': target.tags or [],
                    'created_at': target.created_at.strftime('%Y-%m-%d %H:%M:%S')
                }
            return None
        finally:
            session.close()
