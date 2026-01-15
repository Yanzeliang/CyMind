"""
漏洞扫描模块 - CyMind

提供以下功能：
- Web 应用漏洞扫描 (基础 XSS、SQL 注入检测)
- 服务漏洞扫描 (基于 nmap 脚本)
- 目录扫描 (使用常见路径字典)
"""

import subprocess
import socket
import ssl
import json
import logging
import re
import urllib.parse
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
import threading
import uuid

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Note: Models are not used directly in this module
# Database operations are handled by the API layer in app.py

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityResult:
    """漏洞结果数据结构"""
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    cve: Optional[str] = None
    cvss: Optional[float] = None
    affected_url: Optional[str] = None
    affected_parameter: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    confidence: float = 0.5  # 0.0 - 1.0


@dataclass
class DirectoryScanResult:
    """目录扫描结果"""
    url: str
    status_code: int
    content_length: int
    content_type: Optional[str] = None
    redirect_url: Optional[str] = None


class VulnScanner:
    """漏洞扫描器"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_scans: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        
        # 常见目录字典
        self.common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'wp-login.php',
            'dashboard', 'console', 'panel', 'manager', 'cpanel',
            'phpmyadmin', 'mysql', 'sql', 'database', 'db',
            'backup', 'backups', 'bak', 'old', 'temp', 'tmp',
            'config', 'configuration', 'conf', 'settings',
            'api', 'api/v1', 'api/v2', 'rest', 'graphql',
            'upload', 'uploads', 'files', 'images', 'img', 'assets',
            'static', 'css', 'js', 'scripts', 'styles',
            'test', 'testing', 'dev', 'development', 'staging',
            'docs', 'documentation', 'readme', 'README.md',
            '.git', '.svn', '.env', '.htaccess', 'robots.txt', 'sitemap.xml',
            'wp-content', 'wp-includes', 'xmlrpc.php',
            'server-status', 'server-info', 'info.php', 'phpinfo.php',
            'cgi-bin', 'bin', 'include', 'includes',
            'vendor', 'node_modules', 'bower_components',
            'private', 'secret', 'hidden', 'internal',
            'user', 'users', 'member', 'members', 'account',
            'register', 'signup', 'signin', 'logout', 'auth',
            'error', '404', '500', 'errors', 'logs', 'log'
        ]
        
        # XSS 测试向量
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
            '<svg onload=alert(1)>',
        ]
        
        # SQL 注入测试向量
        self.sqli_payloads = [
            "'",
            "''",
            "1' OR '1'='1",
            "1' OR '1'='1'--",
            "1' OR '1'='1'/*",
            "1; DROP TABLE users--",
            "1' UNION SELECT NULL--",
            "' OR 1=1--",
            "admin'--",
        ]
        
        # SQL 错误特征
        self.sql_error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'ORA-\d{5}',
            r'PostgreSQL.*ERROR',
            r'Driver.*SQL Server',
            r'SQLite.*error',
            r'Syntax error.*SQL',
            r'SQLSTATE\[',
            r'mysql_fetch',
            r'pg_query',
            r'sqlite_',
            r'Unclosed quotation mark',
        ]
    
    def start_web_vuln_scan(self, target_url: str, target_id: int = None) -> Dict:
        """启动 Web 漏洞扫描"""
        scan_id = str(uuid.uuid4())
        
        with self._lock:
            self.active_scans[scan_id] = {
                'status': 'running',
                'type': 'web_vuln',
                'target': target_url,
                'started_at': datetime.now().isoformat(),
                'results': [],
                'progress': 0
            }
        
        # 后台执行扫描
        self.executor.submit(self._execute_web_vuln_scan, scan_id, target_url, target_id)
        
        logger.info(f"Web 漏洞扫描启动: {target_url}, scan_id={scan_id}")
        return {
            'status': 'started',
            'scan_id': scan_id,
            'message': f'Web 漏洞扫描已启动'
        }
    
    def _execute_web_vuln_scan(self, scan_id: str, target_url: str, target_id: int = None):
        """执行 Web 漏洞扫描"""
        if not REQUESTS_AVAILABLE:
            self._update_scan_error(scan_id, "请安装 requests 库: pip install requests")
            return
        
        try:
            vulnerabilities = []
            
            # 1. 基础安全头检查 (20%)
            self._update_scan_progress(scan_id, 10, "检查安全响应头...")
            header_vulns = self._check_security_headers(target_url)
            vulnerabilities.extend(header_vulns)
            
            # 2. SSL/TLS 检查 (40%)
            self._update_scan_progress(scan_id, 30, "检查 SSL/TLS 配置...")
            ssl_vulns = self._check_ssl_config(target_url)
            vulnerabilities.extend(ssl_vulns)
            
            # 3. XSS 检测 (60%)
            self._update_scan_progress(scan_id, 50, "检测 XSS 漏洞...")
            xss_vulns = self._check_xss(target_url)
            vulnerabilities.extend(xss_vulns)
            
            # 4. SQL 注入检测 (80%)
            self._update_scan_progress(scan_id, 70, "检测 SQL 注入...")
            sqli_vulns = self._check_sql_injection(target_url)
            vulnerabilities.extend(sqli_vulns)
            
            # 5. 敏感文件检测 (100%)
            self._update_scan_progress(scan_id, 90, "检测敏感文件...")
            sensitive_vulns = self._check_sensitive_files(target_url)
            vulnerabilities.extend(sensitive_vulns)
            
            # 完成扫描
            with self._lock:
                self.active_scans[scan_id]['status'] = 'completed'
                self.active_scans[scan_id]['progress'] = 100
                self.active_scans[scan_id]['results'] = [asdict(v) for v in vulnerabilities]
                self.active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
            
            logger.info(f"Web 漏洞扫描完成: scan_id={scan_id}, 发现 {len(vulnerabilities)} 个问题")
            
        except Exception as e:
            self._update_scan_error(scan_id, str(e))
            logger.error(f"Web 漏洞扫描错误: {e}")
    
    def _check_security_headers(self, url: str) -> List[VulnerabilityResult]:
        """检查安全响应头"""
        vulnerabilities = []
        
        try:
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            # 检查必要的安全头
            security_headers = {
                'X-Frame-Options': ('防止点击劫持', 'high'),
                'X-Content-Type-Options': ('防止 MIME 类型嗅探', 'medium'),
                'X-XSS-Protection': ('浏览器 XSS 过滤', 'low'),
                'Strict-Transport-Security': ('强制 HTTPS', 'high'),
                'Content-Security-Policy': ('内容安全策略', 'medium'),
                'Referrer-Policy': ('引用策略', 'low'),
            }
            
            for header, (description, severity) in security_headers.items():
                if header not in headers:
                    vulnerabilities.append(VulnerabilityResult(
                        title=f"缺少安全头: {header}",
                        severity=severity,
                        description=f"响应中缺少 {header} 头。{description}。",
                        affected_url=url,
                        remediation=f"建议在服务器配置中添加 {header} 响应头。",
                        confidence=0.9
                    ))
            
            # 检查 Server 头信息泄露
            if 'Server' in headers:
                server_info = headers['Server']
                if any(v in server_info.lower() for v in ['apache', 'nginx', 'iis', 'tomcat']):
                    vulnerabilities.append(VulnerabilityResult(
                        title="服务器版本信息泄露",
                        severity='low',
                        description=f"Server 头泄露了服务器信息: {server_info}",
                        affected_url=url,
                        evidence=f"Server: {server_info}",
                        remediation="配置服务器隐藏版本信息。",
                        confidence=0.8
                    ))
                    
        except Exception as e:
            logger.warning(f"安全头检查失败: {e}")
        
        return vulnerabilities
    
    def _check_ssl_config(self, url: str) -> List[VulnerabilityResult]:
        """检查 SSL/TLS 配置"""
        vulnerabilities = []
        
        if not url.startswith('https://'):
            vulnerabilities.append(VulnerabilityResult(
                title="网站未使用 HTTPS",
                severity='high',
                description="网站未启用 HTTPS，数据传输可能被窃听或篡改。",
                affected_url=url,
                remediation="建议启用 HTTPS 并配置有效的 SSL 证书。",
                confidence=1.0
            ))
            return vulnerabilities
        
        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # 检查证书有效期
                    not_after = cert.get('notAfter')
                    if not_after:
                        # 简单检查，实际应该解析日期
                        pass
                    
        except ssl.SSLCertVerificationError as e:
            vulnerabilities.append(VulnerabilityResult(
                title="SSL 证书验证失败",
                severity='high',
                description=f"SSL 证书验证失败: {str(e)}",
                affected_url=url,
                remediation="配置有效的 SSL 证书。",
                confidence=0.95
            ))
        except Exception as e:
            logger.warning(f"SSL 检查失败: {e}")
        
        return vulnerabilities
    
    def _check_xss(self, url: str) -> List[VulnerabilityResult]:
        """检测反射型 XSS"""
        vulnerabilities = []
        
        # 只检查有参数的 URL
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            # 尝试常见参数
            test_params = ['q', 'search', 'id', 'name', 'query', 'keyword']
            for param in test_params[:3]:  # 限制测试数量
                for payload in self.xss_payloads[:3]:
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(payload)}"
                    try:
                        response = requests.get(test_url, timeout=10, verify=False)
                        if payload in response.text:
                            vulnerabilities.append(VulnerabilityResult(
                                title="潜在反射型 XSS",
                                severity='high',
                                description=f"在参数 {param} 中发现潜在的反射型 XSS 漏洞。",
                                affected_url=test_url,
                                affected_parameter=param,
                                evidence=f"Payload: {payload}",
                                remediation="对用户输入进行 HTML 编码，实施内容安全策略。",
                                confidence=0.7
                            ))
                            break
                    except:
                        pass
        
        return vulnerabilities
    
    def _check_sql_injection(self, url: str) -> List[VulnerabilityResult]:
        """检测 SQL 注入"""
        vulnerabilities = []
        
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        test_params = list(params.keys()) if params else ['id', 'user', 'page']
        
        for param in test_params[:3]:
            for payload in self.sqli_payloads[:3]:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(payload)}"
                try:
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # 检查 SQL 错误特征
                    for pattern in self.sql_error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            vulnerabilities.append(VulnerabilityResult(
                                title="潜在 SQL 注入漏洞",
                                severity='critical',
                                description=f"在参数 {param} 中发现潜在的 SQL 注入漏洞。",
                                affected_url=test_url,
                                affected_parameter=param,
                                evidence=f"发现 SQL 错误特征",
                                remediation="使用参数化查询，避免拼接 SQL 语句。",
                                confidence=0.8
                            ))
                            return vulnerabilities  # 发现一个就返回
                except:
                    pass
        
        return vulnerabilities
    
    def _check_sensitive_files(self, url: str) -> List[VulnerabilityResult]:
        """检测敏感文件"""
        vulnerabilities = []
        
        sensitive_files = [
            ('.git/config', 'Git 配置文件', 'high'),
            ('.env', '环境配置文件', 'critical'),
            ('wp-config.php.bak', 'WordPress 配置备份', 'critical'),
            ('config.php.bak', '配置文件备份', 'high'),
            ('database.sql', '数据库备份', 'critical'),
            ('.htaccess', 'Apache 配置', 'medium'),
            ('phpinfo.php', 'PHP 信息泄露', 'medium'),
            ('server-status', 'Apache 状态', 'medium'),
            ('robots.txt', 'Robots 文件', 'info'),
        ]
        
        base_url = url.rstrip('/')
        
        for file_path, description, severity in sensitive_files[:5]:
            test_url = f"{base_url}/{file_path}"
            try:
                response = requests.get(test_url, timeout=5, verify=False)
                if response.status_code == 200 and len(response.content) > 0:
                    if file_path == 'robots.txt':
                        # robots.txt 是正常的
                        continue
                    vulnerabilities.append(VulnerabilityResult(
                        title=f"敏感文件泄露: {file_path}",
                        severity=severity,
                        description=f"发现敏感文件 {file_path}。{description}。",
                        affected_url=test_url,
                        remediation="删除或限制访问敏感文件。",
                        confidence=0.9
                    ))
            except:
                pass
        
        return vulnerabilities
    
    def start_directory_scan(self, target_url: str, wordlist: List[str] = None, 
                            target_id: int = None) -> Dict:
        """启动目录扫描"""
        scan_id = str(uuid.uuid4())
        
        with self._lock:
            self.active_scans[scan_id] = {
                'status': 'running',
                'type': 'directory',
                'target': target_url,
                'started_at': datetime.now().isoformat(),
                'results': [],
                'progress': 0
            }
        
        dirs_to_scan = wordlist if wordlist else self.common_dirs
        self.executor.submit(self._execute_directory_scan, scan_id, target_url, dirs_to_scan, target_id)
        
        logger.info(f"目录扫描启动: {target_url}, scan_id={scan_id}")
        return {
            'status': 'started',
            'scan_id': scan_id,
            'message': f'目录扫描已启动，将检查 {len(dirs_to_scan)} 个路径'
        }
    
    def _execute_directory_scan(self, scan_id: str, target_url: str, 
                                dirs: List[str], target_id: int = None):
        """执行目录扫描"""
        if not REQUESTS_AVAILABLE:
            self._update_scan_error(scan_id, "请安装 requests 库: pip install requests")
            return
        
        try:
            base_url = target_url.rstrip('/')
            found_dirs = []
            total = len(dirs)
            
            for i, directory in enumerate(dirs):
                progress = int((i / total) * 100)
                self._update_scan_progress(scan_id, progress, f"扫描: /{directory}")
                
                test_url = f"{base_url}/{directory}"
                try:
                    response = requests.get(
                        test_url, 
                        timeout=5, 
                        verify=False,
                        allow_redirects=False
                    )
                    
                    # 只记录存在的路径 (200, 301, 302, 403)
                    if response.status_code in [200, 301, 302, 303, 307, 403]:
                        result = DirectoryScanResult(
                            url=test_url,
                            status_code=response.status_code,
                            content_length=len(response.content),
                            content_type=response.headers.get('Content-Type', ''),
                            redirect_url=response.headers.get('Location', '')
                        )
                        found_dirs.append(asdict(result))
                        
                except requests.RequestException:
                    pass
            
            # 完成扫描
            with self._lock:
                self.active_scans[scan_id]['status'] = 'completed'
                self.active_scans[scan_id]['progress'] = 100
                self.active_scans[scan_id]['results'] = found_dirs
                self.active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
            
            logger.info(f"目录扫描完成: scan_id={scan_id}, 发现 {len(found_dirs)} 个路径")
            
        except Exception as e:
            self._update_scan_error(scan_id, str(e))
            logger.error(f"目录扫描错误: {e}")
    
    def start_service_vuln_scan(self, target: str, target_id: int = None) -> Dict:
        """启动服务漏洞扫描（使用 nmap 脚本）"""
        scan_id = str(uuid.uuid4())
        
        with self._lock:
            self.active_scans[scan_id] = {
                'status': 'running',
                'type': 'service_vuln',
                'target': target,
                'started_at': datetime.now().isoformat(),
                'results': [],
                'progress': 0
            }
        
        self.executor.submit(self._execute_service_vuln_scan, scan_id, target, target_id)
        
        logger.info(f"服务漏洞扫描启动: {target}, scan_id={scan_id}")
        return {
            'status': 'started',
            'scan_id': scan_id,
            'message': '服务漏洞扫描已启动'
        }
    
    def _execute_service_vuln_scan(self, scan_id: str, target: str, target_id: int = None):
        """执行服务漏洞扫描"""
        try:
            vulnerabilities = []
            
            # 尝试使用 nmap 的漏洞扫描脚本
            self._update_scan_progress(scan_id, 20, "运行 nmap 漏洞脚本...")
            
            try:
                # 使用 nmap 的 vuln 脚本类别
                result = subprocess.run(
                    ['nmap', '-sV', '--script=vuln', '-T4', '--top-ports', '100', target],
                    capture_output=True,
                    text=True,
                    timeout=300  # 5分钟超时
                )
                
                self._update_scan_progress(scan_id, 80, "解析扫描结果...")
                
                # 解析 nmap 输出查找漏洞
                output = result.stdout
                vulns_found = self._parse_nmap_vuln_output(output, target)
                vulnerabilities.extend(vulns_found)
                
            except FileNotFoundError:
                # nmap 未安装，使用基础检测
                self._update_scan_progress(scan_id, 50, "nmap 未安装，使用基础检测...")
                basic_vulns = self._basic_service_check(target)
                vulnerabilities.extend(basic_vulns)
            except subprocess.TimeoutExpired:
                logger.warning("nmap 扫描超时")
            
            # 完成扫描
            with self._lock:
                self.active_scans[scan_id]['status'] = 'completed'
                self.active_scans[scan_id]['progress'] = 100
                self.active_scans[scan_id]['results'] = [asdict(v) for v in vulnerabilities]
                self.active_scans[scan_id]['completed_at'] = datetime.now().isoformat()
            
            logger.info(f"服务漏洞扫描完成: scan_id={scan_id}")
            
        except Exception as e:
            self._update_scan_error(scan_id, str(e))
            logger.error(f"服务漏洞扫描错误: {e}")
    
    def _parse_nmap_vuln_output(self, output: str, target: str) -> List[VulnerabilityResult]:
        """解析 nmap 漏洞扫描输出"""
        vulnerabilities = []
        
        # 查找 CVE 引用
        cve_pattern = r'(CVE-\d{4}-\d+)'
        cves = re.findall(cve_pattern, output)
        
        for cve in set(cves):
            vulnerabilities.append(VulnerabilityResult(
                title=f"发现已知漏洞: {cve}",
                severity='high',
                cve=cve,
                description=f"nmap 扫描发现目标存在 {cve} 漏洞。",
                affected_url=target,
                remediation="请参考 CVE 数据库获取修复建议。",
                confidence=0.8
            ))
        
        # 查找其他漏洞指示
        if 'VULNERABLE' in output.upper():
            # 尝试提取漏洞信息
            vuln_sections = re.findall(r'\|_?\s*(.+?VULNERABLE.+?)(?=\n\||\Z)', output, re.IGNORECASE | re.DOTALL)
            for section in vuln_sections[:5]:  # 限制数量
                vulnerabilities.append(VulnerabilityResult(
                    title="nmap 发现潜在漏洞",
                    severity='medium',
                    description=section[:200],
                    affected_url=target,
                    remediation="请进一步调查并应用安全补丁。",
                    confidence=0.7
                ))
        
        return vulnerabilities
    
    def _basic_service_check(self, target: str) -> List[VulnerabilityResult]:
        """基础服务检查（无需 nmap）"""
        vulnerabilities = []
        
        # 检查常见不安全服务
        insecure_ports = [
            (21, 'FTP', '明文传输'),
            (23, 'Telnet', '明文传输'),
            (110, 'POP3', '明文传输'),
            (143, 'IMAP', '明文传输'),
        ]
        
        for port, service, issue in insecure_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    vulnerabilities.append(VulnerabilityResult(
                        title=f"不安全的服务: {service}",
                        severity='medium',
                        description=f"端口 {port} 上运行着 {service} 服务，{issue}。",
                        affected_url=f"{target}:{port}",
                        remediation=f"建议使用加密版本的 {service} 或禁用该服务。",
                        confidence=0.9
                    ))
            except:
                pass
        
        return vulnerabilities
    
    def _update_scan_progress(self, scan_id: str, progress: int, status: str):
        """更新扫描进度"""
        with self._lock:
            if scan_id in self.active_scans:
                self.active_scans[scan_id]['progress'] = progress
                self.active_scans[scan_id]['current_status'] = status
    
    def _update_scan_error(self, scan_id: str, error: str):
        """更新扫描错误"""
        with self._lock:
            if scan_id in self.active_scans:
                self.active_scans[scan_id]['status'] = 'error'
                self.active_scans[scan_id]['error'] = error
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """获取扫描状态"""
        with self._lock:
            if scan_id not in self.active_scans:
                return {'status': 'not_found', 'message': '扫描不存在'}
            return self.active_scans[scan_id].copy()
    
    def cleanup_completed_scans(self, max_age_hours: int = 24):
        """清理已完成的扫描"""
        with self._lock:
            to_remove = []
            for scan_id, scan_data in self.active_scans.items():
                if scan_data['status'] in ['completed', 'error']:
                    # 可以添加时间检查
                    to_remove.append(scan_id)
            
            for scan_id in to_remove:
                del self.active_scans[scan_id]
