from typing import Dict, List, Any, Optional
import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

class Reporter:
    """报告生成器模块，支持 HTML、Markdown 和 PDF 格式"""
    
    def __init__(self):
        # 设置模板目录
        self.template_dir = os.path.join(
            os.path.dirname(__file__), 
            '../templates/reports'
        )
        
        # 如果模板目录不存在，创建它
        os.makedirs(self.template_dir, exist_ok=True)
        
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=True
        )
        
        # 报告存储目录
        self.reports_dir = os.path.join(
            os.path.dirname(__file__),
            '../reports'
        )
        os.makedirs(self.reports_dir, exist_ok=True)
        
    def generate_report(self, 
                      scan_results: Dict, 
                      report_type: str = 'html',
                      template_name: str = 'default') -> str:
        """生成扫描报告
        
        Args:
            scan_results: 扫描结果数据
            report_type: 报告类型 (html, markdown, pdf, json)
            template_name: 模板名称
            
        Returns:
            生成的报告内容
        """
        if report_type == 'html':
            return self._generate_html_report(scan_results, template_name)
        elif report_type == 'markdown':
            return self._generate_markdown_report(scan_results)
        elif report_type == 'pdf':
            return self._generate_pdf_report(scan_results, template_name)
        elif report_type == 'json':
            return self._generate_json_report(scan_results)
        else:
            raise ValueError(f"不支持的报告类型: {report_type}")
    
    def _generate_html_report(self, 
                            scan_results: Dict, 
                            template_name: str) -> str:
        """生成HTML报告"""
        try:
            template = self.env.get_template(f"{template_name}.html")
        except Exception:
            # 如果模板不存在，使用内置 HTML 生成
            return self._generate_fallback_html_report(scan_results)
            
        summary = self._generate_summary(scan_results)
        return template.render(
            title="渗透测试报告",
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            results=scan_results,
            summary=summary
        )
    
    def _generate_fallback_html_report(self, scan_results: Dict) -> str:
        """生成备用 HTML 报告（不依赖模板）"""
        summary = self._generate_summary(scan_results)
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyMind 渗透测试报告</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #00d4ff; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 30px; }}
        h3 {{ color: #0099cc; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card h3 {{ color: #00d4ff; margin: 0 0 10px 0; font-size: 14px; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; }}
        .critical {{ color: #ff4757; }}
        .high {{ color: #ff6b35; }}
        .medium {{ color: #ffa502; }}
        .low {{ color: #2ed573; }}
        .info {{ color: #00d4ff; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #1a1a2e; color: white; }}
        tr:hover {{ background: #f8f9fa; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #ff4757; color: white; }}
        .badge-high {{ background: #ff6b35; color: white; }}
        .badge-medium {{ background: #ffa502; color: black; }}
        .badge-low {{ background: #2ed573; color: white; }}
        .badge-info {{ background: #00d4ff; color: white; }}
        .meta {{ color: #666; font-size: 14px; margin-bottom: 30px; }}
        pre {{ background: #1a1a2e; color: #00d4ff; padding: 15px; border-radius: 8px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🧠 CyMind 渗透测试报告</h1>
        <div class="meta">
            <p><strong>生成时间:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>目标:</strong> {scan_results.get('target', 'N/A')}</p>
            <p><strong>扫描类型:</strong> {scan_results.get('scan_type', 'N/A')}</p>
        </div>
        
        <h2>📊 扫描摘要</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>总漏洞数</h3>
                <div class="value">{summary['total_vulnerabilities']}</div>
            </div>
            <div class="summary-card">
                <h3>严重</h3>
                <div class="value critical">{summary['critical']}</div>
            </div>
            <div class="summary-card">
                <h3>高危</h3>
                <div class="value high">{summary['high_risk']}</div>
            </div>
            <div class="summary-card">
                <h3>中危</h3>
                <div class="value medium">{summary['medium_risk']}</div>
            </div>
            <div class="summary-card">
                <h3>低危</h3>
                <div class="value low">{summary['low_risk']}</div>
            </div>
        </div>
        
        {self._render_html_results(scan_results)}
        
        <hr>
        <p style="text-align: center; color: #666;">
            报告由 CyMind 自动生成 | <a href="https://github.com/CyMind">GitHub</a>
        </p>
    </div>
</body>
</html>"""
        return html
    
    def _render_html_results(self, scan_results: Dict) -> str:
        """渲染 HTML 结果部分"""
        html_parts = []
        
        # 端口扫描结果
        if 'ports' in scan_results:
            html_parts.append('<h2>🔍 开放端口</h2>')
            ports = scan_results['ports']
            if ports:
                html_parts.append('<table><tr><th>端口</th><th>协议</th><th>服务</th><th>状态</th></tr>')
                for port in ports:
                    html_parts.append(f'''<tr>
                        <td><strong>{port.get('port', 'N/A')}</strong></td>
                        <td>{port.get('protocol', 'tcp').upper()}</td>
                        <td>{port.get('service', '未知')}</td>
                        <td><span class="badge badge-info">{port.get('state', 'open')}</span></td>
                    </tr>''')
                html_parts.append('</table>')
            else:
                html_parts.append('<p>未发现开放端口</p>')
        
        # 漏洞结果
        if 'vulnerabilities' in scan_results:
            html_parts.append('<h2>⚠️ 发现的漏洞</h2>')
            vulns = scan_results['vulnerabilities']
            if vulns:
                html_parts.append('<table><tr><th>漏洞名称</th><th>严重性</th><th>CVE</th><th>描述</th></tr>')
                for vuln in vulns:
                    severity = vuln.get('severity', 'info').lower()
                    html_parts.append(f'''<tr>
                        <td><strong>{vuln.get('title', 'N/A')}</strong></td>
                        <td><span class="badge badge-{severity}">{severity.upper()}</span></td>
                        <td>{vuln.get('cve', 'N/A')}</td>
                        <td>{vuln.get('description', '')[:100]}...</td>
                    </tr>''')
                html_parts.append('</table>')
            else:
                html_parts.append('<p>未发现漏洞</p>')
        
        # 子域名结果
        if 'subdomains' in scan_results:
            html_parts.append('<h2>🌐 发现的子域名</h2>')
            subdomains = scan_results['subdomains']
            if subdomains:
                html_parts.append('<ul>')
                for subdomain in subdomains[:20]:  # 限制显示数量
                    if isinstance(subdomain, dict):
                        html_parts.append(f'<li>{subdomain.get("subdomain", subdomain)}</li>')
                    else:
                        html_parts.append(f'<li>{subdomain}</li>')
                html_parts.append('</ul>')
                if len(subdomains) > 20:
                    html_parts.append(f'<p>... 还有 {len(subdomains) - 20} 个子域名</p>')
        
        # 原始结果
        if 'raw' in scan_results:
            html_parts.append('<h2>📄 原始数据</h2>')
            html_parts.append(f'<pre>{json.dumps(scan_results["raw"], indent=2, ensure_ascii=False)}</pre>')
        
        return '\n'.join(html_parts)
    
    def _generate_markdown_report(self, scan_results: Dict) -> str:
        """生成Markdown格式报告"""
        summary = self._generate_summary(scan_results)
        
        lines = [
            "# 🧠 CyMind 渗透测试报告",
            "",
            "## 📋 报告信息",
            "",
            f"- **生成时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- **目标:** {scan_results.get('target', 'N/A')}",
            f"- **扫描类型:** {scan_results.get('scan_type', 'N/A')}",
            "",
            "---",
            "",
            "## 📊 扫描摘要",
            "",
            "| 指标 | 数量 |",
            "|------|------|",
            f"| 总漏洞数 | {summary['total_vulnerabilities']} |",
            f"| 🔴 严重 | {summary['critical']} |",
            f"| 🟠 高危 | {summary['high_risk']} |",
            f"| 🟡 中危 | {summary['medium_risk']} |",
            f"| 🟢 低危 | {summary['low_risk']} |",
            f"| 🔵 信息 | {summary['info']} |",
            "",
            "---",
            ""
        ]
        
        # 开放端口
        if 'ports' in scan_results and scan_results['ports']:
            lines.extend([
                "## 🔍 开放端口",
                "",
                "| 端口 | 协议 | 服务 | 状态 |",
                "|------|------|------|------|"
            ])
            for port in scan_results['ports']:
                lines.append(
                    f"| {port.get('port', 'N/A')} | "
                    f"{port.get('protocol', 'tcp').upper()} | "
                    f"{port.get('service', '未知')} | "
                    f"{port.get('state', 'open')} |"
                )
            lines.extend(["", "---", ""])
        
        # 漏洞列表
        if 'vulnerabilities' in scan_results and scan_results['vulnerabilities']:
            lines.extend([
                "## ⚠️ 发现的漏洞",
                ""
            ])
            for i, vuln in enumerate(scan_results['vulnerabilities'], 1):
                severity = vuln.get('severity', 'info').upper()
                severity_icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': '🔵'}.get(severity, '⚪')
                lines.extend([
                    f"### {i}. {vuln.get('title', '未知漏洞')}",
                    "",
                    f"- **严重性:** {severity_icon} {severity}",
                    f"- **CVE:** {vuln.get('cve', 'N/A')}",
                    f"- **CVSS评分:** {vuln.get('cvss', 'N/A')}",
                    "",
                    f"**描述:** {vuln.get('description', '无描述')}",
                    "",
                    f"**修复建议:** {vuln.get('remediation', '请参考官方安全公告')}",
                    "",
                    "---",
                    ""
                ])
        
        # 子域名
        if 'subdomains' in scan_results and scan_results['subdomains']:
            lines.extend([
                "## 🌐 发现的子域名",
                "",
                f"共发现 **{len(scan_results['subdomains'])}** 个子域名：",
                ""
            ])
            for subdomain in scan_results['subdomains'][:30]:
                if isinstance(subdomain, dict):
                    sd = subdomain.get('subdomain', str(subdomain))
                    ip = subdomain.get('ip', '')
                    lines.append(f"- `{sd}` {f'({ip})' if ip else ''}")
                else:
                    lines.append(f"- `{subdomain}`")
            if len(scan_results['subdomains']) > 30:
                lines.append(f"- ... 还有 {len(scan_results['subdomains']) - 30} 个")
            lines.extend(["", "---", ""])
        
        # 服务信息
        if 'services' in scan_results and scan_results['services']:
            lines.extend([
                "## 🖥️ 服务信息",
                "",
                "| 服务 | 版本 | 端口 | 备注 |",
                "|------|------|------|------|"
            ])
            for service in scan_results['services']:
                lines.append(
                    f"| {service.get('service', 'N/A')} | "
                    f"{service.get('version', 'N/A')} | "
                    f"{service.get('port', 'N/A')} | "
                    f"{service.get('note', '')} |"
                )
            lines.extend(["", "---", ""])
        
        # DNS 信息
        if 'dns' in scan_results and scan_results['dns']:
            lines.extend([
                "## 📡 DNS 记录",
                ""
            ])
            for record_type, records in scan_results['dns'].items():
                lines.append(f"### {record_type.upper()} 记录")
                for record in records:
                    lines.append(f"- `{record}`")
                lines.append("")
            lines.extend(["---", ""])
        
        # 页脚
        lines.extend([
            "",
            "---",
            "",
            "> 📝 **报告由 CyMind 自动生成**",
            ">",
            "> ⚠️ **免责声明:** 本报告仅供授权渗透测试使用，"
            "请遵守相关法律法规。",
            ""
        ])
        
        return '\n'.join(lines)
    
    def _generate_pdf_report(self, scan_results: Dict, template_name: str = 'default') -> str:
        """生成PDF报告
        
        首先生成 HTML，然后提示用户使用浏览器打印为 PDF
        或者使用 weasyprint（如果可用）
        """
        try:
            from weasyprint import HTML
            html_content = self._generate_fallback_html_report(scan_results)
            
            # 生成 PDF 文件
            report_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_path = os.path.join(self.reports_dir, f"report_{report_id}.pdf")
            
            HTML(string=html_content).write_pdf(pdf_path)
            return f"PDF 报告已生成: {pdf_path}"
            
        except ImportError:
            # weasyprint 未安装，返回 HTML 并提示
            html_content = self._generate_fallback_html_report(scan_results)
            html_path = os.path.join(self.reports_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return f"PDF 功能需要安装 weasyprint。已生成 HTML 报告: {html_path}\n提示: pip install weasyprint"
    
    def _generate_json_report(self, scan_results: Dict) -> str:
        """生成 JSON 格式报告"""
        report_data = {
            "meta": {
                "title": "CyMind 渗透测试报告",
                "generated_at": datetime.now().isoformat(),
                "target": scan_results.get("target", "N/A"),
                "scan_type": scan_results.get("scan_type", "N/A")
            },
            "summary": self._generate_summary(scan_results),
            "results": scan_results
        }
        return json.dumps(report_data, indent=2, ensure_ascii=False)
    
    def _generate_summary(self, scan_results: Dict) -> Dict:
        """生成报告摘要，统计各级别漏洞数量"""
        summary = {
            'total_vulnerabilities': 0,
            'critical': 0,
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'info': 0,
            'total_ports': 0,
            'total_services': 0,
            'total_subdomains': 0
        }
        
        # 统计漏洞
        vulnerabilities = scan_results.get('vulnerabilities', [])
        summary['total_vulnerabilities'] = len(vulnerabilities)
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity == 'critical':
                summary['critical'] += 1
            elif severity == 'high':
                summary['high_risk'] += 1
            elif severity == 'medium':
                summary['medium_risk'] += 1
            elif severity == 'low':
                summary['low_risk'] += 1
            else:
                summary['info'] += 1
        
        # 也检查扫描结果中的 results 字段
        results = scan_results.get('results', [])
        for result in results:
            if isinstance(result, dict):
                severity = result.get('severity', 'info').lower()
                if severity == 'critical':
                    summary['critical'] += 1
                    summary['total_vulnerabilities'] += 1
                elif severity == 'high':
                    summary['high_risk'] += 1
                    summary['total_vulnerabilities'] += 1
                elif severity == 'medium':
                    summary['medium_risk'] += 1
                    summary['total_vulnerabilities'] += 1
                elif severity == 'low':
                    summary['low_risk'] += 1
                    summary['total_vulnerabilities'] += 1
        
        # 统计端口
        summary['total_ports'] = len(scan_results.get('ports', []))
        
        # 统计服务
        summary['total_services'] = len(scan_results.get('services', []))
        
        # 统计子域名
        summary['total_subdomains'] = len(scan_results.get('subdomains', []))
        
        return summary
    
    def save_report(self, report_content: str, file_path: str = None, 
                   report_format: str = 'html') -> str:
        """保存报告到文件
        
        Args:
            report_content: 报告内容
            file_path: 保存路径（可选，自动生成）
            report_format: 报告格式
            
        Returns:
            保存的文件路径
        """
        if file_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            ext = {'html': 'html', 'markdown': 'md', 'pdf': 'pdf', 'json': 'json'}.get(report_format, 'txt')
            file_path = os.path.join(self.reports_dir, f"report_{timestamp}.{ext}")
        
        # 确保目录存在
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return file_path
    
    def list_reports(self) -> List[Dict]:
        """列出所有已生成的报告"""
        reports = []
        if os.path.exists(self.reports_dir):
            for filename in os.listdir(self.reports_dir):
                filepath = os.path.join(self.reports_dir, filename)
                if os.path.isfile(filepath):
                    stat = os.stat(filepath)
                    reports.append({
                        'filename': filename,
                        'path': filepath,
                        'size': stat.st_size,
                        'created_at': datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                        'format': filename.split('.')[-1] if '.' in filename else 'unknown'
                    })
        return sorted(reports, key=lambda x: x['created_at'], reverse=True)
