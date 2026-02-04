"""
Lightweight CVE database loader and matcher.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional

from core.config import get_config
from core.logging_config import get_logger

logger = get_logger("cymind.vuln_database")


class VulnerabilityDatabase:
    """Simple JSON-backed CVE database."""

    def __init__(self, db_path: Optional[str] = None):
        self.config = get_config()
        self.db_path = db_path or self._default_db_path()
        self._data: List[Dict] = []
        self.load_cve_database()

    def _default_db_path(self) -> str:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        return os.path.join(base_dir, 'config', 'cve_database.json')

    def load_cve_database(self) -> bool:
        """Load CVE database from JSON file."""
        if not os.path.exists(self.db_path):
            logger.warning(f"CVE database not found at {self.db_path}")
            self._data = []
            return False

        try:
            with open(self.db_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, list):
                self._data = data
                logger.info(f"Loaded CVE database with {len(self._data)} entries")
                return True
            logger.warning("CVE database format invalid (expected list)")
        except Exception as exc:
            logger.error(f"Failed to load CVE database: {exc}")

        self._data = []
        return False

    def update_database(self) -> bool:
        """Update database (placeholder)."""
        logger.info("CVE database update not implemented")
        return False

    def match_vulnerabilities(self, service_info: Dict) -> List[Dict]:
        """Match vulnerabilities by service name and version regex."""
        service = (service_info.get('service') or '').lower()
        version = (service_info.get('version') or '')
        if not service or not version:
            return []

        matches: List[Dict] = []
        for entry in self._data:
            service_regex = entry.get('service_regex')
            version_regex = entry.get('version_regex')
            if not service_regex or not version_regex:
                continue

            try:
                if not re.search(service_regex, service, re.IGNORECASE):
                    continue
                if not re.search(version_regex, version, re.IGNORECASE):
                    continue
            except re.error:
                continue

            matches.append(entry)

        return matches

    def get_vulnerability_details(self, cve_id: str) -> Optional[Dict]:
        for entry in self._data:
            if entry.get('cve') == cve_id:
                return entry
        return None

    def search_vulnerabilities(self, query: str) -> List[Dict]:
        query = (query or '').lower()
        if not query:
            return []

        results = []
        for entry in self._data:
            if query in (entry.get('cve', '').lower()) or query in (entry.get('description', '').lower()):
                results.append(entry)
        return results
