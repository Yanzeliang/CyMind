"""
Hypothesis 测试策略
定义用于属性测试的数据生成策略
"""

from hypothesis import strategies as st
from hypothesis.strategies import composite
from core.interfaces import ScanType, ScanStatus, ReportFormat, Severity
import string
import ipaddress


# 基础数据策略
@composite
def valid_urls(draw):
    """生成有效的URL"""
    protocols = ["http", "https"]
    protocol = draw(st.sampled_from(protocols))
    
    # 生成域名
    domain_parts = draw(st.lists(
        st.text(alphabet=string.ascii_lowercase + string.digits, min_size=1, max_size=10),
        min_size=1, max_size=3
    ))
    domain = ".".join(domain_parts) + draw(st.sampled_from([".com", ".org", ".net", ".edu"]))
    
    # 可选端口
    port = draw(st.one_of(st.none(), st.integers(min_value=1, max_value=65535)))
    port_str = f":{port}" if port else ""
    
    return f"{protocol}://{domain}{port_str}"


@composite
def valid_ips(draw):
    """生成有效的IP地址"""
    # IPv4 地址
    octets = draw(st.lists(st.integers(min_value=1, max_value=254), min_size=4, max_size=4))
    return ".".join(map(str, octets))


@composite
def target_data_strategy(draw):
    """生成目标数据"""
    name = draw(st.text(alphabet=string.ascii_letters + string.digits + " -_", min_size=1, max_size=50))
    
    # 至少有URL或IP其中之一
    has_url = draw(st.booleans())
    has_ip = draw(st.booleans())
    
    # 确保至少有一个
    if not has_url and not has_ip:
        has_url = True
    
    url = draw(valid_urls()) if has_url else None
    ip = draw(valid_ips()) if has_ip else None
    
    target_type = draw(st.sampled_from(["website", "api", "network", "service"]))
    tags = draw(st.lists(
        st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=10),
        min_size=0, max_size=5
    ))
    
    return {
        "name": name,
        "url": url,
        "ip": ip,
        "type": target_type,
        "tags": tags
    }


@composite
def scan_config_strategy(draw):
    """生成扫描配置"""
    return {
        "timeout": draw(st.integers(min_value=30, max_value=3600)),
        "threads": draw(st.integers(min_value=1, max_value=50)),
        "aggressive": draw(st.booleans()),
        "custom_ports": draw(st.lists(
            st.integers(min_value=1, max_value=65535),
            min_size=0, max_size=20
        ))
    }


@composite
def scan_result_strategy(draw):
    """生成扫描结果"""
    scan_type = draw(st.sampled_from(list(ScanType)))
    severity = draw(st.sampled_from(list(Severity)))
    
    # 根据扫描类型生成相应的结果数据
    if scan_type == ScanType.PORT_SCAN:
        result_data = {
            "ports": draw(st.lists(
                st.dictionaries(
                    keys=st.sampled_from(["port", "state", "service", "protocol"]),
                    values=st.one_of(
                        st.integers(min_value=1, max_value=65535),
                        st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=20)
                    )
                ),
                min_size=0, max_size=10
            ))
        }
    elif scan_type == ScanType.SUBDOMAIN_ENUM:
        result_data = {
            "subdomains": draw(st.lists(
                valid_urls(),
                min_size=0, max_size=20
            ))
        }
    else:
        result_data = {
            "findings": draw(st.lists(
                st.dictionaries(
                    keys=st.sampled_from(["title", "description", "severity"]),
                    values=st.text(min_size=1, max_size=100)
                ),
                min_size=0, max_size=5
            ))
        }
    
    return {
        "scan_type": scan_type,
        "severity": severity,
        "result_data": result_data
    }


# CSV 数据策略
@composite
def csv_row_strategy(draw):
    """生成CSV行数据"""
    return {
        "name": draw(st.text(alphabet=string.ascii_letters + " ", min_size=1, max_size=30)),
        "url": draw(st.one_of(st.none(), valid_urls())),
        "ip": draw(st.one_of(st.none(), valid_ips())),
        "type": draw(st.sampled_from(["website", "api", "network"]))
    }


# 漏洞数据策略
@composite
def vulnerability_strategy(draw):
    """生成漏洞数据"""
    cve_year = draw(st.integers(min_value=2000, max_value=2024))
    cve_number = draw(st.integers(min_value=1, max_value=99999))
    
    return {
        "cve_id": f"CVE-{cve_year}-{cve_number:05d}",
        "title": draw(st.text(min_size=10, max_size=100)),
        "description": draw(st.text(min_size=50, max_size=500)),
        "severity": draw(st.sampled_from(list(Severity))),
        "cvss_score": draw(st.floats(min_value=0.0, max_value=10.0)),
        "references": draw(st.lists(valid_urls(), min_size=0, max_size=5))
    }


# 用户数据策略
@composite
def user_data_strategy(draw):
    """生成用户数据"""
    username = draw(st.text(
        alphabet=string.ascii_lowercase + string.digits + "_",
        min_size=3, max_size=20
    ))
    email = f"{username}@{draw(st.sampled_from(['example.com', 'test.org', 'demo.net']))}"
    
    return {
        "username": username,
        "email": email,
        "role": draw(st.sampled_from(["admin", "user", "viewer"]))
    }