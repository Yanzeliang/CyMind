"""
Comprehensive Reconnaissance Module for CyMind

This module provides advanced reconnaissance capabilities including:
- Subdomain enumeration using multiple tools
- Enhanced service fingerprinting
- DNS analysis and certificate transparency searches
- Technology stack identification
- Comprehensive target discovery
"""

import subprocess
import json
import logging
import asyncio
import aiohttp
import dns.resolver
import ssl
import socket
import re
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from dataclasses import dataclass, asdict
from enum import Enum

from models import Session, ScanResult, Scan, Target, ScanType, ScanStatus, ResultType, Severity

logger = logging.getLogger(__name__)


class ReconToolType(Enum):
    """Types of reconnaissance tools available"""
    SUBDOMAIN_ENUM = "subdomain_enumeration"
    SERVICE_FINGERPRINT = "service_fingerprinting"
    DNS_ANALYSIS = "dns_analysis"
    CERT_TRANSPARENCY = "certificate_transparency"
    TECH_STACK = "technology_stack"
    PORT_SCAN = "port_scan"


@dataclass
class SubdomainResult:
    """Result structure for subdomain enumeration"""
    subdomain: str
    source: str
    ip_addresses: List[str]
    status_code: Optional[int] = None
    title: Optional[str] = None
    technologies: List[str] = None
    
    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []


@dataclass
class ServiceResult:
    """Result structure for service fingerprinting"""
    host: str
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    ssl_info: Optional[Dict] = None
    confidence: float = 0.0


@dataclass
class DNSResult:
    """Result structure for DNS analysis"""
    domain: str
    record_type: str
    records: List[str]
    ttl: Optional[int] = None
    nameservers: List[str] = None
    
    def __post_init__(self):
        if self.nameservers is None:
            self.nameservers = []


@dataclass
class TechnologyResult:
    """Result structure for technology stack identification"""
    url: str
    technologies: List[Dict[str, Any]]
    server_headers: Dict[str, str]
    cms: Optional[str] = None
    framework: Optional[str] = None
    
    def __post_init__(self):
        if not hasattr(self, 'server_headers'):
            self.server_headers = {}


class ReconModule:
    """Comprehensive reconnaissance module"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.active_scans = {}
        self.session = None
        
        # Tool availability cache
        self._tool_cache = {}
        
        # Common subdomain wordlist
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns3', 'm', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns4', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile',
            'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo',
            'cp', 'calendar', 'wiki', 'web', 'media', 'email', 'images', 'img',
            'www1', 'intranet', 'portal', 'video', 'sip', 'dns2', 'api', 'cdn',
            'stats', 'dns1', 'ns5', 'upload', 'client', 'forum', 'bb', 'smtp2',
            'staging', 'server', 'ns6', 'mx1', 'mx2', 'ns7', 'ns8', 'search',
            'ftp2', 'archive', 'rss', 'vpn2', 'mssql', 'dns3', 'ns0', 'image'
        ]
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(limit=100)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def check_tool_availability(self, tool_name: str) -> bool:
        """Check if a reconnaissance tool is available"""
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]
        
        try:
            result = subprocess.run(
                [tool_name, '--help'],
                capture_output=True,
                timeout=5
            )
            available = result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            available = False
        
        self._tool_cache[tool_name] = available
        return available
    
    def run_comprehensive_recon(self, target: Dict, tools: List[str] = None) -> Dict:
        """Run comprehensive reconnaissance on a target"""
        scan_id = f"recon_{target['id']}_{int(time.time())}"
        
        if scan_id in self.active_scans:
            return {"status": "error", "message": "Reconnaissance already in progress"}
        
        # Default tools if none specified
        if tools is None:
            tools = ['subdomain_enum', 'service_fingerprint', 'dns_analysis', 'tech_stack']
        
        future = self.executor.submit(
            self._execute_comprehensive_recon,
            target,
            tools,
            scan_id
        )
        
        self.active_scans[scan_id] = {
            "future": future,
            "status": "running",
            "target": target,
            "tools": tools,
            "start_time": time.time()
        }
        
        return {"status": "started", "scan_id": scan_id}
    
    def _execute_comprehensive_recon(self, target: Dict, tools: List[str], scan_id: str) -> Dict:
        """Execute comprehensive reconnaissance"""
        results = {
            "scan_id": scan_id,
            "target": target,
            "tools_used": tools,
            "results": {},
            "summary": {},
            "start_time": time.time()
        }
        
        try:
            # Extract target information
            target_url = target.get('url', '')
            target_ip = target.get('ip', '')
            target_domain = self._extract_domain(target_url) if target_url else target_ip
            
            if not target_domain:
                return {"status": "error", "message": "Invalid target format"}
            
            logger.info(f"Starting comprehensive recon for: {target_domain}")
            
            # Run selected reconnaissance tools
            if 'subdomain_enum' in tools:
                logger.info("Running subdomain enumeration...")
                results["results"]["subdomains"] = self._run_subdomain_enumeration(target_domain)
            
            if 'service_fingerprint' in tools:
                logger.info("Running service fingerprinting...")
                results["results"]["services"] = self._run_service_fingerprinting(target_domain, target_ip)
            
            if 'dns_analysis' in tools:
                logger.info("Running DNS analysis...")
                results["results"]["dns"] = self._run_dns_analysis(target_domain)
            
            if 'tech_stack' in tools:
                logger.info("Running technology stack identification...")
                results["results"]["technologies"] = self._run_technology_identification(target_url or f"http://{target_domain}")
            
            # Generate summary
            results["summary"] = self._generate_recon_summary(results["results"])
            results["end_time"] = time.time()
            results["duration"] = results["end_time"] - results["start_time"]
            results["status"] = "completed"
            
            # Save results to database
            self._save_recon_results(target, results)
            
            logger.info(f"Comprehensive recon completed for {target_domain}")
            return results
            
        except Exception as e:
            logger.exception(f"Comprehensive recon failed for {target}: {e}")
            results["status"] = "error"
            results["error"] = str(e)
            results["end_time"] = time.time()
            return results
        
        finally:
            # Clean up active scan
            if scan_id in self.active_scans:
                self.active_scans[scan_id]["status"] = "completed"
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = f"http://{url}"
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return ""
    
    def _run_subdomain_enumeration(self, domain: str) -> List[Dict]:
        """Run subdomain enumeration using multiple methods"""
        subdomains = set()
        results = []
        
        # Method 1: Use subfinder if available
        if self.check_tool_availability('subfinder'):
            subfinder_results = self._run_subfinder(domain)
            subdomains.update(sub['subdomain'] for sub in subfinder_results)
            results.extend(subfinder_results)
        
        # Method 2: Use amass if available
        if self.check_tool_availability('amass'):
            amass_results = self._run_amass(domain)
            for result in amass_results:
                if result['subdomain'] not in subdomains:
                    subdomains.add(result['subdomain'])
                    results.append(result)
        
        # Method 3: DNS brute force with common subdomains
        brute_results = self._run_dns_bruteforce(domain)
        for result in brute_results:
            if result['subdomain'] not in subdomains:
                subdomains.add(result['subdomain'])
                results.append(result)
        
        # Method 4: Certificate transparency search
        ct_results = self._search_certificate_transparency(domain)
        for result in ct_results:
            if result['subdomain'] not in subdomains:
                subdomains.add(result['subdomain'])
                results.append(result)
        
        # Verify and enrich subdomain results
        enriched_results = []
        for result in results:
            enriched = self._enrich_subdomain_result(result)
            enriched_results.append(enriched)
        
        logger.info(f"Found {len(enriched_results)} subdomains for {domain}")
        return enriched_results
    
    def _run_subfinder(self, domain: str) -> List[Dict]:
        """Run subfinder for subdomain enumeration"""
        try:
            cmd = ['subfinder', '-d', domain, '-silent', '-o', '/dev/stdout']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                logger.warning(f"Subfinder failed: {result.stderr}")
                return []
            
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    subdomains.append({
                        'subdomain': line.strip(),
                        'source': 'subfinder',
                        'ip_addresses': []
                    })
            
            return subdomains
            
        except Exception as e:
            logger.warning(f"Subfinder execution failed: {e}")
            return []
    
    def _run_amass(self, domain: str) -> List[Dict]:
        """Run amass for subdomain enumeration"""
        try:
            cmd = ['amass', 'enum', '-d', domain, '-silent']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.warning(f"Amass failed: {result.stderr}")
                return []
            
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    subdomains.append({
                        'subdomain': line.strip(),
                        'source': 'amass',
                        'ip_addresses': []
                    })
            
            return subdomains
            
        except Exception as e:
            logger.warning(f"Amass execution failed: {e}")
            return []
    
    def _run_dns_bruteforce(self, domain: str) -> List[Dict]:
        """Run DNS brute force with common subdomains"""
        subdomains = []
        
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                answers = dns.resolver.resolve(full_domain, 'A')
                ip_addresses = [str(answer) for answer in answers]
                
                subdomains.append({
                    'subdomain': full_domain,
                    'source': 'dns_bruteforce',
                    'ip_addresses': ip_addresses
                })
                
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                continue
            except Exception as e:
                logger.debug(f"DNS resolution failed for {full_domain}: {e}")
                continue
        
        return subdomains
    
    def _search_certificate_transparency(self, domain: str) -> List[Dict]:
        """Search certificate transparency logs for subdomains"""
        subdomains = []
        
        try:
            # Use crt.sh API
            import requests
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                seen_domains = set()
                
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and subdomain.endswith(f'.{domain}') and subdomain not in seen_domains:
                            seen_domains.add(subdomain)
                            subdomains.append({
                                'subdomain': subdomain,
                                'source': 'certificate_transparency',
                                'ip_addresses': []
                            })
        
        except Exception as e:
            logger.warning(f"Certificate transparency search failed: {e}")
        
        return subdomains
    
    def _enrich_subdomain_result(self, result: Dict) -> Dict:
        """Enrich subdomain result with additional information"""
        subdomain = result['subdomain']
        
        # Resolve IP addresses if not already done
        if not result.get('ip_addresses'):
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                result['ip_addresses'] = [str(answer) for answer in answers]
            except Exception:
                result['ip_addresses'] = []
        
        # Try to get HTTP status and title
        for protocol in ['https', 'http']:
            try:
                import requests
                url = f"{protocol}://{subdomain}"
                response = requests.get(url, timeout=10, verify=False)
                result['status_code'] = response.status_code
                
                # Extract title
                if 'text/html' in response.headers.get('content-type', ''):
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        result['title'] = title_match.group(1).strip()
                
                break  # Success, no need to try other protocol
                
            except Exception:
                continue
        
        return result
    
    def _run_service_fingerprinting(self, domain: str, ip: str = None) -> List[Dict]:
        """Run comprehensive service fingerprinting"""
        services = []
        target = ip or domain
        
        if not target:
            return services
        
        # Method 1: Nmap service detection
        nmap_services = self._run_nmap_service_detection(target)
        services.extend(nmap_services)
        
        # Method 2: Banner grabbing for common ports
        banner_services = self._run_banner_grabbing(target)
        services.extend(banner_services)
        
        # Method 3: SSL/TLS analysis
        ssl_services = self._run_ssl_analysis(target)
        services.extend(ssl_services)
        
        return services
    
    def _run_nmap_service_detection(self, target: str) -> List[Dict]:
        """Run nmap service detection"""
        services = []
        
        try:
            cmd = ['nmap', '-sV', '-sC', '--top-ports', '1000', '-T4', target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.warning(f"Nmap service detection failed: {result.stderr}")
                return services
            
            # Parse nmap output
            services = self._parse_nmap_service_output(result.stdout, target)
            
        except Exception as e:
            logger.warning(f"Nmap service detection failed: {e}")
        
        return services
    
    def _parse_nmap_service_output(self, output: str, target: str) -> List[Dict]:
        """Parse nmap service detection output"""
        services = []
        current_port = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Match port lines
            port_match = re.match(r'(\d+)/(tcp|udp)\s+(\w+)\s+(.+)', line)
            if port_match:
                port, protocol, state, service_info = port_match.groups()
                
                if state == 'open':
                    service_parts = service_info.split()
                    service_name = service_parts[0] if service_parts else 'unknown'
                    version = ' '.join(service_parts[1:]) if len(service_parts) > 1 else None
                    
                    services.append({
                        'host': target,
                        'port': int(port),
                        'protocol': protocol,
                        'service': service_name,
                        'version': version,
                        'confidence': 0.8
                    })
        
        return services
    
    def _run_banner_grabbing(self, target: str) -> List[Dict]:
        """Run banner grabbing for common services"""
        services = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
        
        for port in common_ports:
            try:
                banner = self._grab_banner(target, port)
                if banner:
                    service_name = self._identify_service_from_banner(banner, port)
                    services.append({
                        'host': target,
                        'port': port,
                        'protocol': 'tcp',
                        'service': service_name,
                        'banner': banner,
                        'confidence': 0.6
                    })
            except Exception:
                continue
        
        return services
    
    def _grab_banner(self, host: str, port: int, timeout: int = 5) -> Optional[str]:
        """Grab banner from a service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None
    
    def _identify_service_from_banner(self, banner: str, port: int) -> str:
        """Identify service from banner"""
        banner_lower = banner.lower()
        
        # Common service patterns
        if 'ssh' in banner_lower:
            return 'ssh'
        elif 'ftp' in banner_lower:
            return 'ftp'
        elif 'smtp' in banner_lower:
            return 'smtp'
        elif 'http' in banner_lower or 'server:' in banner_lower:
            return 'http'
        elif 'mysql' in banner_lower:
            return 'mysql'
        elif 'postgresql' in banner_lower:
            return 'postgresql'
        elif port == 22:
            return 'ssh'
        elif port == 21:
            return 'ftp'
        elif port == 25:
            return 'smtp'
        elif port in [80, 8080]:
            return 'http'
        elif port in [443, 8443]:
            return 'https'
        else:
            return 'unknown'
    
    def _run_ssl_analysis(self, target: str) -> List[Dict]:
        """Run SSL/TLS analysis"""
        services = []
        ssl_ports = [443, 993, 995, 465, 587, 8443]
        
        for port in ssl_ports:
            try:
                ssl_info = self._analyze_ssl_certificate(target, port)
                if ssl_info:
                    services.append({
                        'host': target,
                        'port': port,
                        'protocol': 'tcp',
                        'service': 'ssl/tls',
                        'ssl_info': ssl_info,
                        'confidence': 0.9
                    })
            except Exception:
                continue
        
        return services
    
    def _analyze_ssl_certificate(self, host: str, port: int, timeout: int = 10) -> Optional[Dict]:
        """Analyze SSL certificate"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'signature_algorithm': cert.get('signatureAlgorithm'),
                        'san': cert.get('subjectAltName', [])
                    }
        except Exception:
            return None
    
    def _run_dns_analysis(self, domain: str) -> Dict:
        """Run comprehensive DNS analysis"""
        dns_results = {
            'domain': domain,
            'records': {},
            'nameservers': [],
            'mx_records': [],
            'txt_records': [],
            'soa_record': None
        }
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records = [str(answer) for answer in answers]
                dns_results['records'][record_type] = records
                
                if record_type == 'NS':
                    dns_results['nameservers'] = records
                elif record_type == 'MX':
                    dns_results['mx_records'] = records
                elif record_type == 'TXT':
                    dns_results['txt_records'] = records
                elif record_type == 'SOA':
                    dns_results['soa_record'] = records[0] if records else None
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                dns_results['records'][record_type] = []
            except Exception as e:
                logger.debug(f"DNS query failed for {domain} {record_type}: {e}")
                dns_results['records'][record_type] = []
        
        return dns_results
    
    def _run_technology_identification(self, url: str) -> Dict:
        """Run technology stack identification"""
        tech_results = {
            'url': url,
            'technologies': [],
            'server_headers': {},
            'cms': None,
            'framework': None
        }
        
        try:
            import requests
            response = requests.get(url, timeout=15, verify=False)
            
            # Analyze headers
            tech_results['server_headers'] = dict(response.headers)
            
            # Identify technologies from headers
            technologies = self._identify_technologies_from_headers(response.headers)
            tech_results['technologies'].extend(technologies)
            
            # Analyze HTML content
            if 'text/html' in response.headers.get('content-type', ''):
                html_technologies = self._identify_technologies_from_html(response.text)
                tech_results['technologies'].extend(html_technologies)
            
            # Identify CMS and framework
            tech_results['cms'] = self._identify_cms(response.headers, response.text)
            tech_results['framework'] = self._identify_framework(response.headers, response.text)
            
        except Exception as e:
            logger.warning(f"Technology identification failed for {url}: {e}")
        
        return tech_results
    
    def _identify_technologies_from_headers(self, headers: Dict) -> List[Dict]:
        """Identify technologies from HTTP headers"""
        technologies = []
        
        # Server header analysis
        server = headers.get('Server', '').lower()
        if 'apache' in server:
            technologies.append({'name': 'Apache', 'category': 'Web Server', 'confidence': 0.9})
        elif 'nginx' in server:
            technologies.append({'name': 'Nginx', 'category': 'Web Server', 'confidence': 0.9})
        elif 'iis' in server:
            technologies.append({'name': 'IIS', 'category': 'Web Server', 'confidence': 0.9})
        
        # X-Powered-By header
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            technologies.append({'name': 'PHP', 'category': 'Programming Language', 'confidence': 0.8})
        elif 'asp.net' in powered_by:
            technologies.append({'name': 'ASP.NET', 'category': 'Framework', 'confidence': 0.8})
        
        return technologies
    
    def _identify_technologies_from_html(self, html: str) -> List[Dict]:
        """Identify technologies from HTML content"""
        technologies = []
        html_lower = html.lower()
        
        # JavaScript frameworks
        if 'react' in html_lower or 'reactjs' in html_lower:
            technologies.append({'name': 'React', 'category': 'JavaScript Framework', 'confidence': 0.7})
        if 'angular' in html_lower or 'angularjs' in html_lower:
            technologies.append({'name': 'Angular', 'category': 'JavaScript Framework', 'confidence': 0.7})
        if 'vue' in html_lower or 'vuejs' in html_lower:
            technologies.append({'name': 'Vue.js', 'category': 'JavaScript Framework', 'confidence': 0.7})
        if 'jquery' in html_lower:
            technologies.append({'name': 'jQuery', 'category': 'JavaScript Library', 'confidence': 0.8})
        
        # CSS frameworks
        if 'bootstrap' in html_lower:
            technologies.append({'name': 'Bootstrap', 'category': 'CSS Framework', 'confidence': 0.8})
        
        return technologies
    
    def _identify_cms(self, headers: Dict, html: str) -> Optional[str]:
        """Identify Content Management System"""
        html_lower = html.lower()
        
        # WordPress
        if 'wp-content' in html_lower or 'wordpress' in html_lower:
            return 'WordPress'
        
        # Drupal
        if 'drupal' in html_lower or '/sites/default/' in html_lower:
            return 'Drupal'
        
        # Joomla
        if 'joomla' in html_lower or '/components/com_' in html_lower:
            return 'Joomla'
        
        return None
    
    def _identify_framework(self, headers: Dict, html: str) -> Optional[str]:
        """Identify web framework"""
        # Check headers first
        server = headers.get('Server', '').lower()
        powered_by = headers.get('X-Powered-By', '').lower()
        
        if 'django' in server or 'django' in powered_by:
            return 'Django'
        elif 'flask' in server or 'flask' in powered_by:
            return 'Flask'
        elif 'express' in server or 'express' in powered_by:
            return 'Express.js'
        
        return None
    
    def _generate_recon_summary(self, results: Dict) -> Dict:
        """Generate summary of reconnaissance results"""
        summary = {
            'total_subdomains': 0,
            'total_services': 0,
            'unique_technologies': 0,
            'dns_records_found': 0,
            'high_value_targets': [],
            'security_notes': []
        }
        
        # Subdomain summary
        if 'subdomains' in results:
            summary['total_subdomains'] = len(results['subdomains'])
            
            # Identify high-value targets
            for subdomain in results['subdomains']:
                name = subdomain['subdomain'].lower()
                if any(keyword in name for keyword in ['admin', 'api', 'dev', 'test', 'staging', 'vpn']):
                    summary['high_value_targets'].append(subdomain['subdomain'])
        
        # Service summary
        if 'services' in results:
            summary['total_services'] = len(results['services'])
            
            # Check for interesting services
            for service in results['services']:
                if service['port'] in [22, 21, 23, 3389]:  # SSH, FTP, Telnet, RDP
                    summary['security_notes'].append(f"Remote access service found: {service['service']} on port {service['port']}")
        
        # Technology summary
        if 'technologies' in results:
            tech_data = results['technologies']
            if 'technologies' in tech_data:
                summary['unique_technologies'] = len(tech_data['technologies'])
        
        # DNS summary
        if 'dns' in results:
            dns_data = results['dns']
            summary['dns_records_found'] = sum(len(records) for records in dns_data.get('records', {}).values())
        
        return summary
    
    def _save_recon_results(self, target: Dict, results: Dict):
        """Save reconnaissance results to database"""
        session = Session()
        
        try:
            # Find target
            target_obj = session.query(Target).filter_by(id=target['id']).first()
            if not target_obj:
                logger.error(f"Target not found: {target['id']}")
                return
            
            # Create scan record
            scan = Scan(
                project_id=target_obj.project_id,
                target_id=target_obj.id,
                scan_type=ScanType.RECON.value,
                status=ScanStatus.COMPLETED.value
            )
            session.add(scan)
            session.commit()
            
            # Save subdomain results
            if 'subdomains' in results['results']:
                for subdomain_data in results['results']['subdomains']:
                    scan_result = ScanResult(
                        scan_id=scan.id,
                        result_type=ResultType.SUBDOMAIN.value,
                        data=subdomain_data,
                        severity=Severity.INFO.value,
                        confidence=0.8
                    )
                    session.add(scan_result)
            
            # Save service results
            if 'services' in results['results']:
                for service_data in results['results']['services']:
                    scan_result = ScanResult(
                        scan_id=scan.id,
                        result_type=ResultType.SERVICE.value,
                        data=service_data,
                        severity=Severity.INFO.value,
                        confidence=service_data.get('confidence', 0.5)
                    )
                    session.add(scan_result)
            
            # Save DNS results
            if 'dns' in results['results']:
                scan_result = ScanResult(
                    scan_id=scan.id,
                    result_type=ResultType.DNS.value,
                    data=results['results']['dns'],
                    severity=Severity.INFO.value,
                    confidence=0.9
                )
                session.add(scan_result)
            
            # Save technology results
            if 'technologies' in results['results']:
                scan_result = ScanResult(
                    scan_id=scan.id,
                    result_type=ResultType.TECHNOLOGY.value,
                    data=results['results']['technologies'],
                    severity=Severity.INFO.value,
                    confidence=0.7
                )
                session.add(scan_result)
            
            # Save summary
            scan_result = ScanResult(
                scan_id=scan.id,
                result_type=ResultType.SUMMARY.value,
                data=results['summary'],
                severity=Severity.INFO.value,
                confidence=1.0
            )
            session.add(scan_result)
            
            session.commit()
            logger.info(f"Reconnaissance results saved for scan {scan.id}")
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to save reconnaissance results: {e}")
            raise
        finally:
            session.close()
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """Get reconnaissance scan status"""
        scan = self.active_scans.get(scan_id)
        if not scan:
            return {"status": "not_found"}
        
        if scan["future"].done():
            try:
                result = scan["future"].result()
                # Clean up completed scan
                del self.active_scans[scan_id]
                return {"status": "completed", "result": result}
            except Exception as e:
                logger.exception("Failed to get scan result")
                del self.active_scans[scan_id]
                return {"status": "error", "message": str(e)}
        else:
            # Calculate progress estimate
            elapsed = time.time() - scan["start_time"]
            progress = min(int((elapsed / 300) * 100), 95)  # Estimate 5 minutes max
            return {
                "status": "running", 
                "progress": progress,
                "elapsed_time": elapsed,
                "tools": scan["tools"]
            }
    
    def list_available_tools(self) -> Dict[str, bool]:
        """List available reconnaissance tools"""
        tools = {
            'subfinder': self.check_tool_availability('subfinder'),
            'amass': self.check_tool_availability('amass'),
            'nmap': self.check_tool_availability('nmap'),
            'dns_bruteforce': True,  # Built-in
            'certificate_transparency': True,  # Built-in
            'banner_grabbing': True,  # Built-in
            'ssl_analysis': True,  # Built-in
            'technology_identification': True  # Built-in
        }
        return tools
    
    def cleanup_completed_scans(self):
        """Clean up completed scans from memory"""
        completed_scans = []
        for scan_id, scan_data in self.active_scans.items():
            if scan_data["future"].done():
                completed_scans.append(scan_id)
        
        for scan_id in completed_scans:
            del self.active_scans[scan_id]
        
        logger.info(f"Cleaned up {len(completed_scans)} completed scans")