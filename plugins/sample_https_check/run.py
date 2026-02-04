import json
import sys
from urllib.parse import urlparse


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        print(json.dumps({"status": "error", "message": "Invalid JSON input"}))
        return

    params = payload.get("params", {})
    target = params.get("target_url") or params.get("target") or ""
    if not target:
        print(json.dumps({"status": "error", "message": "target_url is required"}))
        return

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    parsed = urlparse(target)
    if parsed.scheme != "https":
        result = {
            "status": "success",
            "result_type": "vulnerability",
            "severity": "high",
            "confidence": 0.7,
            "data": {
                "target_url": target
            },
            "vulnerabilities": [
                {
                    "title": "网站未使用 HTTPS（插件检测）",
                    "severity": "high",
                    "description": "目标未使用 HTTPS，传输可能被窃听或篡改。",
                    "affected_url": target,
                    "remediation": "启用 HTTPS 并配置有效的 TLS 证书。"
                }
            ]
        }
    else:
        result = {
            "status": "success",
            "result_type": "information",
            "severity": "info",
            "confidence": 0.9,
            "data": {
                "target_url": target,
                "message": "HTTPS 已启用"
            },
            "vulnerabilities": []
        }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
