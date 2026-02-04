"""
Plugin System for CyMind

Features:
- Dynamic plugin discovery and registration
- Standardized plugin I/O via JSON on stdin/stdout
- Sandboxed execution guardrails (path/timeout)
- Result normalization and integration into ScanResult/Vulnerability
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from core.config import get_config
from core.logging_config import get_logger
from core.exceptions import PluginError
from models import (
    Session, Plugin, PluginType, Scan, ScanResult, Target, Vulnerability,
    ScanType, ScanStatus, ResultType, Severity
)

logger = get_logger("cymind.plugin_system")


@dataclass
class PluginManifest:
    name: str
    version: str
    plugin_type: str
    entry: str
    description: str = ""
    author: str = ""
    capabilities: List[str] = None
    configuration: Dict[str, Any] = None
    requirements: Dict[str, Any] = None
    enabled: bool = True

    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []
        if self.configuration is None:
            self.configuration = {}
        if self.requirements is None:
            self.requirements = {}


class PluginSystem:
    """Plugin system manager"""

    def __init__(self):
        self.config = get_config()
        self.plugin_dir = self._resolve_plugin_dir(self.config.plugins.plugin_directory)
        self.sandbox_enabled = self.config.plugins.sandbox_enabled
        self.max_execution_time = self.config.plugins.max_execution_time
        self._cache: Dict[str, PluginManifest] = {}

        if self.config.plugins.auto_discovery:
            self.discover_plugins()

    def _resolve_plugin_dir(self, plugin_dir: str) -> str:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        resolved = os.path.abspath(os.path.join(base_dir, plugin_dir))
        os.makedirs(resolved, exist_ok=True)
        return resolved

    def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover plugins from plugin directory and register them"""
        manifests: List[PluginManifest] = []
        for root, dirs, files in os.walk(self.plugin_dir):
            if 'plugin.json' not in files:
                continue

            manifest_path = os.path.join(root, 'plugin.json')
            try:
                manifest = self._load_manifest(manifest_path)
                self._cache[manifest.name] = manifest
                manifests.append(manifest)
            except PluginError as exc:
                logger.warning(f"Skipping invalid plugin manifest {manifest_path}: {exc}")
                continue

        registered = []
        for manifest in manifests:
            result = self.register_plugin(manifest)
            registered.append(result)

        return registered

    def _load_manifest(self, manifest_path: str) -> PluginManifest:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        required = ['name', 'version', 'type', 'entry']
        for field in required:
            if field not in data or not str(data[field]).strip():
                raise PluginError(f"Missing required field '{field}'", data.get('name'))

        plugin_type = data['type'].lower()
        if plugin_type not in ('python', 'bash', 'external'):
            raise PluginError(f"Unsupported plugin type: {plugin_type}", data.get('name'))

        manifest = PluginManifest(
            name=data['name'],
            version=data['version'],
            plugin_type=plugin_type,
            entry=data['entry'],
            description=data.get('description', ''),
            author=data.get('author', ''),
            capabilities=data.get('capabilities', []),
            configuration=data.get('configuration', {}),
            requirements=data.get('requirements', {}),
            enabled=data.get('enabled', True)
        )

        # validate entry path
        entry_path = os.path.abspath(os.path.join(os.path.dirname(manifest_path), manifest.entry))
        if not os.path.exists(entry_path):
            raise PluginError(f"Entry file not found: {manifest.entry}", manifest.name)

        if self.sandbox_enabled:
            if not entry_path.startswith(self.plugin_dir):
                raise PluginError("Entry path escapes plugin directory", manifest.name)

        return manifest

    def register_plugin(self, plugin: PluginManifest) -> Dict[str, Any]:
        """Register plugin in database (create or update)"""
        session = Session()
        try:
            existing = session.query(Plugin).filter_by(name=plugin.name).first()
            plugin_type = PluginType.PYTHON.value if plugin.plugin_type == 'python' else (
                PluginType.BASH.value if plugin.plugin_type == 'bash' else PluginType.EXTERNAL.value
            )

            if existing:
                existing.version = plugin.version
                existing.plugin_type = plugin_type
                existing.configuration = plugin.configuration
                # Preserve explicit user disablement
                if existing.enabled is True:
                    existing.enabled = plugin.enabled
                existing.description = plugin.description
                existing.author = plugin.author
                existing.capabilities = plugin.capabilities
                existing.requirements = plugin.requirements
                existing.last_updated = datetime.now()
                session.commit()
                return {"status": "updated", "name": plugin.name}

            new_plugin = Plugin(
                name=plugin.name,
                version=plugin.version,
                plugin_type=plugin_type,
                configuration=plugin.configuration,
                enabled=plugin.enabled,
                description=plugin.description,
                author=plugin.author,
                capabilities=plugin.capabilities,
                requirements=plugin.requirements
            )
            session.add(new_plugin)
            session.commit()
            return {"status": "registered", "name": plugin.name}
        except Exception as exc:
            session.rollback()
            raise PluginError(f"Failed to register plugin: {exc}", plugin.name)
        finally:
            session.close()

    def get_plugins(self) -> List[Dict[str, Any]]:
        """Get plugin list from database"""
        session = Session()
        try:
            plugins = session.query(Plugin).order_by(Plugin.name.asc()).all()
            result = []
            for plugin in plugins:
                result.append({
                    "name": plugin.name,
                    "version": plugin.version,
                    "type": plugin.plugin_type,
                    "enabled": plugin.enabled,
                    "description": plugin.description,
                    "author": plugin.author,
                    "capabilities": plugin.capabilities or [],
                    "last_updated": plugin.last_updated.isoformat() if plugin.last_updated else None
                })
            return result
        finally:
            session.close()

    def _get_plugin_record(self, plugin_name: str) -> Optional[Plugin]:
        session = Session()
        try:
            return session.query(Plugin).filter_by(name=plugin_name).first()
        finally:
            session.close()

    def validate_plugin(self, plugin_path: str) -> Dict[str, Any]:
        """Validate a plugin manifest file path"""
        try:
            manifest = self._load_manifest(plugin_path)
            return {"status": "success", "plugin": manifest.name}
        except PluginError as exc:
            return {"status": "error", "message": str(exc)}

    def uninstall_plugin(self, plugin_name: str) -> bool:
        """Disable plugin in database (soft uninstall)"""
        session = Session()
        try:
            plugin = session.query(Plugin).filter_by(name=plugin_name).first()
            if not plugin:
                return False
            plugin.enabled = False
            plugin.last_updated = datetime.now()
            session.commit()
            return True
        except Exception as exc:
            session.rollback()
            raise PluginError(f"Failed to uninstall plugin: {exc}", plugin_name)
        finally:
            session.close()

    def execute_plugin(self, plugin_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute plugin by name with standardized input/output."""
        manifest = self._cache.get(plugin_name)
        if not manifest:
            # attempt discovery refresh
            self.discover_plugins()
            manifest = self._cache.get(plugin_name)

        if not manifest:
            return {"status": "error", "message": f"插件未找到: {plugin_name}"}
        plugin_record = self._get_plugin_record(plugin_name)
        if plugin_record and not plugin_record.enabled:
            return {"status": "error", "message": f"插件已禁用: {plugin_name}"}
        if plugin_record and plugin_record.configuration:
            manifest.configuration = plugin_record.configuration

        manifest_path = self._find_manifest_path(plugin_name)
        if not manifest_path:
            return {"status": "error", "message": "插件清单文件不存在"}

        entry_path = os.path.abspath(os.path.join(os.path.dirname(manifest_path), manifest.entry))
        if self.sandbox_enabled and not entry_path.startswith(self.plugin_dir):
            return {"status": "error", "message": "插件入口路径无效"}

        payload = {
            "params": params,
            "config": manifest.configuration,
            "plugin": {
                "name": manifest.name,
                "version": manifest.version,
                "type": manifest.plugin_type,
                "capabilities": manifest.capabilities
            }
        }

        try:
            output = self._run_plugin_process(manifest, entry_path, payload)
            normalized = self._normalize_plugin_output(plugin_name, output)
            persisted = self._persist_plugin_result(plugin_name, params, normalized)
            normalized["db_scan_id"] = persisted
            return normalized
        except PluginError as exc:
            logger.error(f"插件执行失败: {exc}")
            return {"status": "error", "message": str(exc)}

    def _run_plugin_process(self, manifest: PluginManifest, entry_path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if manifest.plugin_type == 'python':
            cmd = [sys.executable, entry_path]
        elif manifest.plugin_type == 'bash':
            cmd = ['/bin/bash', entry_path]
        else:
            cmd = [entry_path]

        try:
            result = subprocess.run(
                cmd,
                input=json.dumps(payload),
                text=True,
                capture_output=True,
                timeout=self.max_execution_time
            )
        except subprocess.TimeoutExpired:
            raise PluginError(f"Plugin timed out after {self.max_execution_time}s", manifest.name)
        except Exception as exc:
            raise PluginError(f"Plugin execution failed: {exc}", manifest.name)

        if result.returncode != 0:
            raise PluginError(result.stderr.strip() or "Plugin exited with error", manifest.name)

        try:
            return json.loads(result.stdout.strip() or "{}")
        except json.JSONDecodeError:
            raise PluginError("Plugin output is not valid JSON", manifest.name)

    def _normalize_plugin_output(self, plugin_name: str, output: Dict[str, Any]) -> Dict[str, Any]:
        status = output.get("status", "success")
        if status != "success":
            raise PluginError(output.get("message", "Plugin error"), plugin_name)

        result_type = output.get("result_type", ResultType.INFORMATION.value)
        severity = output.get("severity", Severity.INFO.value)
        confidence = float(output.get("confidence", 0.5))
        data = output.get("data", {})
        vulnerabilities = output.get("vulnerabilities", [])

        return {
            "status": "success",
            "plugin": plugin_name,
            "result_type": result_type,
            "severity": severity,
            "confidence": confidence,
            "data": data,
            "vulnerabilities": vulnerabilities
        }

    def _persist_plugin_result(self, plugin_name: str, params: Dict[str, Any], normalized: Dict[str, Any]) -> Optional[int]:
        target_id = params.get("target_id")
        if not target_id:
            return None

        session = Session()
        try:
            target = session.query(Target).filter_by(id=target_id).first()
            if not target:
                return None

            scan = Scan(
                project_id=target.project_id,
                target_id=target.id,
                scan_type=ScanType.CUSTOM.value,
                status=ScanStatus.COMPLETED.value,
                completed_at=datetime.now(),
                configuration={"plugin": plugin_name}
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)

            scan_result = ScanResult(
                scan_id=scan.id,
                result_type=normalized.get("result_type", ResultType.INFORMATION.value),
                data={
                    "plugin": plugin_name,
                    "data": normalized.get("data", {}),
                    "vulnerabilities": normalized.get("vulnerabilities", [])
                },
                severity=normalized.get("severity"),
                confidence=normalized.get("confidence", 0.5)
            )
            session.add(scan_result)
            session.commit()
            session.refresh(scan_result)

            # Persist vulnerabilities
            for vuln in normalized.get("vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                vuln_record = Vulnerability(
                    scan_result_id=scan_result.id,
                    cve_id=vuln.get("cve"),
                    title=vuln.get("title", "Plugin Finding"),
                    description=vuln.get("description", ""),
                    severity=vuln.get("severity", Severity.INFO.value),
                    cvss_score=vuln.get("cvss"),
                    affected_service=vuln.get("affected_service") or vuln.get("affected_url"),
                    remediation=vuln.get("remediation", "")
                )
                session.add(vuln_record)

            session.commit()
            return scan.id
        except Exception as exc:
            session.rollback()
            logger.error(f"Failed to persist plugin result: {exc}")
            return None
        finally:
            session.close()

    def _find_manifest_path(self, plugin_name: str) -> Optional[str]:
        for root, dirs, files in os.walk(self.plugin_dir):
            if 'plugin.json' not in files:
                continue
            manifest_path = os.path.join(root, 'plugin.json')
            try:
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if data.get('name') == plugin_name:
                    return manifest_path
            except Exception:
                continue
        return None
