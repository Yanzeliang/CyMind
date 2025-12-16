import subprocess
import json
import logging
from typing import Dict, List
from concurrent.futures import ThreadPoolExecutor

from models import Session, ScanResult, Scan, Target, ScanType, ScanStatus, ResultType, Severity

logger = logging.getLogger(__name__)


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
                return {"status": "error", "message": "未知的扫描类型"}
        except Exception as exc:  # pragma: no cover - 记录异常
            logger.exception("扫描执行失败")
            return {"status": "error", "message": str(exc)}
        finally:
            scan_id = f"{target['id']}_{scan_type}"
            if scan_id in self.active_scans:
                self.active_scans[scan_id]["status"] = "completed"
                # 清理已完成的扫描任务
                del self.active_scans[scan_id]

    def _port_scan(self, target: Dict) -> Dict:
        """端口扫描实现"""
        logger.info("开始端口扫描: %s", target.get('url') or target.get('ip'))

        # 提取扫描目标
        command_target = self._extract_scan_target(target)
        if not command_target:
            logger.error("未提供有效的扫描目标")
            return {"status": "error", "message": "未提供有效的扫描目标"}

        try:
            cmd = ["nmap", "-T4", "-F", "-oG", "-", command_target]
            logger.debug("执行命令: %s", " ".join(cmd))
            completed_process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
        except FileNotFoundError:
            logger.exception("nmap命令未找到")
            return {
                "status": "error",
                "message": "nmap命令未找到，请确认已安装nmap"
            }
        except Exception as exc:
            logger.exception("执行nmap命令时出错")
            return {"status": "error", "message": str(exc)}

        if completed_process.returncode != 0:
            error_message = completed_process.stderr.strip() or "nmap扫描失败"
            logger.error("扫描失败: %s", error_message)
            return {"status": "error", "message": error_message}

        scan_results = self._parse_nmap_output(completed_process.stdout)
        logger.debug("nmap输出解析结果: %s", scan_results)

        record_payload = {"ports": scan_results}
        if not scan_results:
            record_payload["message"] = "扫描完成，未发现开放端口"

        session = Session()
        try:
            # 查找目标
            target_obj = session.query(Target).filter_by(id=target['id']).first()
            if not target_obj:
                logger.error("目标不存在: %s", target['id'])
                return {"status": "error", "message": "目标不存在"}
            
            # 创建扫描记录
            scan = Scan(
                project_id=target_obj.project_id,
                target_id=target_obj.id,
                scan_type=ScanType.RECON.value,
                status=ScanStatus.COMPLETED.value
            )
            session.add(scan)
            session.commit()
            
            # 创建扫描结果记录
            scan_result = ScanResult(
                scan_id=scan.id,
                result_type=ResultType.SERVICE.value,
                data=record_payload,
                severity=Severity.INFO.value,
                confidence=0.9
            )
            session.add(scan_result)
            session.commit()
            session.refresh(scan_result)
            logger.info("扫描结果已保存，扫描ID: %s, 结果ID: %s", scan.id, scan_result.id)
            
        except Exception as exc:
            session.rollback()
            logger.error("数据库保存失败: %s", exc)
            return {
                "status": "error",
                "message": f"保存扫描结果失败: {exc}"
            }
        finally:
            session.close()

        response: Dict = {
            "status": "completed",
            "target": command_target,
            "ports": scan_results,
            "scan_id": scan.id
        }
        if not scan_results:
            response["message"] = record_payload["message"]

        return response

    def _parse_nmap_output(self, output: str) -> List[Dict[str, str]]:
        """解析 nmap -oG 输出，提取开放端口信息"""
        ports: List[Dict[str, str]] = []

        for line in output.splitlines():
            if "Ports:" not in line:
                continue

            _, ports_section = line.split("Ports:", 1)
            for raw_entry in ports_section.split(','):
                entry = raw_entry.strip()
                if not entry or '/' not in entry:
                    continue

                segments = entry.split('/')
                if len(segments) < 3:
                    continue

                port_str = segments[0]
                state = segments[1] or ""
                protocol = segments[2] or ""
                service = segments[4] if len(segments) > 4 and segments[4] else ""

                if state.lower() != "open":
                    continue

                try:
                    port_value = int(port_str)
                except ValueError:
                    port_value = port_str

                ports.append({
                    "port": port_value,
                    "state": state,
                    "protocol": protocol or "unknown",
                    "service": service or "unknown"
                })

        return ports

    def _extract_scan_target(self, target: Dict) -> str:
        """从目标信息中提取可扫描的主机名或IP"""
        # 优先使用IP地址
        if target.get('ip_address') and target['ip_address'].strip():
            return target['ip_address'].strip()
        
        # 如果有IP字段
        if target.get('ip') and target['ip'].strip():
            return target['ip'].strip()
        
        # 从URL中提取主机名
        url = target.get('url', '').strip()
        if url:
            # 移除协议前缀
            if url.startswith('https://'):
                url = url[8:]
            elif url.startswith('http://'):
                url = url[7:]
            
            # 移除路径部分
            if '/' in url:
                url = url.split('/')[0]
            
            # 移除端口号（如果有）
            if ':' in url and not url.count(':') > 1:  # 避免IPv6地址
                url = url.split(':')[0]
            
            return url
        
        # 使用name字段作为最后的选择
        name = target.get('name', '').strip()
        if name and '.' in name:  # 简单检查是否像域名
            return name
        
        return ""

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
                # 清理已完成的扫描任务
                del self.active_scans[scan_id]
                return {"status": "completed", "result": result}
            except Exception as exc:  # pragma: no cover - 捕获执行错误
                logger.exception("获取扫描结果失败")
                # 清理失败的扫描任务
                del self.active_scans[scan_id]
                return {"status": "error", "message": str(exc)}
        else:
            return {"status": "running"}
