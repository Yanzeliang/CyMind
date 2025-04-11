import csv
import json
from typing import List, Dict

class TargetManager:
    def __init__(self):
        self.targets = []  # 临时使用内存存储
        
    def add_target(self, target_data: Dict) -> None:
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
            
        if 'url' in target_data and not isinstance(target_data['url'], str):
            raise ValueError("URL必须是字符串")
            
        if 'ip' in target_data and not isinstance(target_data['ip'], str):
            raise ValueError("IP地址必须是字符串")
            
        self.targets.append({
            'id': len(self.targets) + 1,
            'name': target_data.get('name', ''),
            'url': target_data.get('url', ''),
            'ip': target_data.get('ip', ''),
            'type': target_data.get('type', 'website'),
            'created_at': target_data.get('created_at', '')
        })
    
    def import_from_csv(self, file_path: str) -> None:
        """从CSV文件导入目标"""
        with open(file_path, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                self.add_target(row)
    
    def get_targets(self) -> List[Dict]:
        """获取所有目标"""
        return self.targets
    
    def get_target_by_id(self, target_id: int) -> Dict:
        """根据ID获取目标"""
        for target in self.targets:
            if target['id'] == target_id:
                return target
        return None
