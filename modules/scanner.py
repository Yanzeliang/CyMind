import subprocess
import json
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor

class Scanner:
    def __init__(self):
        self.active_scans = {}
        self.executor = ThreadPoolExecutor(max_workers=5)
        
    def run_scan(self, target: Dict, scan_type: str) -> Dict:
        """运行扫描任务"""
        scan_id = f"{target['id']}_{scan_type}"
        
        if scan_id in self.active_scans:
            return {"status": "error", "message": "扫描已在进行中"}
            
        future = self.executor.submit(
            self._execute_scan, 
            target, 
            scan_type
        )
        
        self.active_scans[scan_id] = {
            "future": future,
            "status": "running",
            "target": target,
            "type": scan_type
        }
        
        return {"status": "started", "scan_id": scan_id}
    
    def _execute_scan(self, target: Dict, scan_type: str) -> Dict:
        """执行具体的扫描命令"""
        try:
            if scan_type == "port_scan":
                return self._port_scan(target)
            elif scan_type == "vulnerability_scan":
                return self._vulnerability_scan(target)
            else:
                return {"error": "未知的扫描类型"}
        except Exception as e:
            return {"error": str(e)}
        finally:
            scan_id = f"{target['id']}_{scan_type}"
            self.active_scans[scan_id]["status"] = "completed"
    
    def _port_scan(self, target: Dict) -> Dict:
        """端口扫描实现"""
        import nmap
        from ..models import Session, ScanResult
        import json
        
        scanner = nmap.PortScanner()
        
        try:
            # 执行快速端口扫描
            scanner.scan(hosts=target['url'], arguments='-T4 -F')
            
            # 解析扫描结果
            scan_results = []
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    ports = scanner[host][proto].keys()
                    for port in ports:
                        scan_results.append({
                            'port': port,
                            'protocol': proto,
                            'state': scanner[host][proto][port]['state'],
                            'service': scanner[host][proto][port]['name']
                        })
            
            # 保存到数据库
            session = Session()
            try:
                result = ScanResult(
                    target=target['url'],
                    scan_type='port_scan',
                    result=json.dumps(scan_results)
                )
                session.add(result)
                session.commit()
                session.refresh(result)
            except Exception as e:
                session.rollback()
                raise e
            finally:
                session.close()
            
            return {
                'status': 'completed',
                'target': target['url'],
                'ports': scan_results,
                'scan_id': result.id
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }
    
    def _vulnerability_scan(self, target: Dict) -> Dict:
        """漏洞扫描实现"""
        # 这里将实现nuclei/xray扫描逻辑
        return {"status": "vuln_scan_not_implemented"}
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """获取扫描状态"""
        scan = self.active_scans.get(scan_id)
        if not scan:
            return {"status": "not_found"}
        
        if scan["future"].done():
            try:
                result = scan["future"].result()
                return {"status": "completed", "result": result}
            except Exception as e:
                return {"status": "error", "message": str(e)}
        else:
            return {"status": "running"}
