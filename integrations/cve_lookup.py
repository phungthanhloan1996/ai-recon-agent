"""
integrations/cve_lookup.py - CVE Database Integration
Tra cứu CVE cho WordPress plugins, themes, và core.
"""

import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional

import requests

logger = logging.getLogger("recon.cve")


class CVELookup:
    """Tra cứu CVE cho WordPress components, có cache SQLite và fail-safe."""

    def __init__(self, api_token: Optional[str] = None):
        self.api_token = api_token or os.getenv("WPSCAN_API_TOKEN")
        self.nvd_api_key = os.getenv("NVD_API_KEY")
        self.cache_db = os.path.join(os.path.dirname(__file__), "../data/cve_cache.db")
        self._init_db()

    def _init_db(self):
        """Khởi tạo database cache."""
        os.makedirs(os.path.dirname(self.cache_db), exist_ok=True)
        conn = sqlite3.connect(self.cache_db)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS cve_cache (
                    component TEXT,
                    version TEXT,
                    cves TEXT,
                    last_updated TIMESTAMP,
                    PRIMARY KEY (component, version)
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def get_wp_plugin_cves(self, plugin_name: str, version: str) -> List[Dict]:
        """Lấy CVE cho WordPress plugin."""
        plugin_name = (plugin_name or "").strip().lower()
        version = (version or "").strip()
        if not plugin_name or not self._is_usable_version(version):
            return []

        cache_key = f"plugin:{plugin_name}"
        cached = self._check_cache(cache_key, version)
        if cached is not None:
            return cached

        cves = []
        if self.api_token:
            cves = self._fetch_from_wpscan("plugins", plugin_name, version)
        if not cves:
            cves = self._fetch_from_nvd(f"wordpress plugin {plugin_name}", version)

        if cves:
            self._save_cache(cache_key, version, cves)
        return cves

    def get_wp_theme_cves(self, theme_name: str, version: str) -> List[Dict]:
        """Lấy CVE cho WordPress theme."""
        theme_name = (theme_name or "").strip().lower()
        version = (version or "").strip()
        if not theme_name or not self._is_usable_version(version):
            return []

        cache_key = f"theme:{theme_name}"
        cached = self._check_cache(cache_key, version)
        if cached is not None:
            return cached

        cves = []
        if self.api_token:
            cves = self._fetch_from_wpscan("themes", theme_name, version)
        if not cves:
            cves = self._fetch_from_nvd(f"wordpress theme {theme_name}", version)

        if cves:
            self._save_cache(cache_key, version, cves)
        return cves

    def get_wp_core_cves(self, version: str) -> List[Dict]:
        """Lấy CVE cho WordPress core."""
        version = (version or "").strip()
        if not self._is_usable_version(version):
            return []

        cached = self._check_cache("wordpress", version)
        if cached is not None:
            return cached

        cves = []
        if self.api_token:
            cves = self._fetch_from_wpscan("wordpresses", "wordpress", version)
        if not cves:
            cves = self._fetch_from_nvd("wordpress core", version)

        if cves:
            self._save_cache("wordpress", version, cves)
        return cves

    def _fetch_from_wpscan(self, endpoint: str, name: str, version: str) -> List[Dict]:
        """Fetch từ WPScan API."""
        try:
            url = f"https://wpscan.com/api/v3/{endpoint}/{name}"
            headers = {"Authorization": f"Token token={self.api_token}"}
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code != 200:
                if response.status_code != 404:
                    logger.warning(f"[CVE] WPScan returned {response.status_code} for {name}")
                return []

            data = response.json()
            vulnerabilities = []
            for vuln in data.get("vulnerabilities", []):
                affected_versions = vuln.get("affected_versions", "")
                if self._version_affected(version, affected_versions):
                    vulnerabilities.append(
                        {
                            "cve": self._extract_cve_id(vuln),
                            "title": vuln.get("title", ""),
                            "description": vuln.get("description", ""),
                            "severity": (vuln.get("severity") or "MEDIUM").upper(),
                            "cvss_score": self._extract_wpscan_cvss(vuln),
                            "fixed_in": vuln.get("fixed_in", ""),
                            "references": self._normalize_references(vuln.get("references", {})),
                            "component": name,
                            "affected_versions": affected_versions,
                            "source": "wpscan",
                        }
                    )
            return vulnerabilities
        except Exception as e:
            logger.error(f"[CVE] WPScan fetch failed for {name}: {e}")
            return []

    def _fetch_from_nvd(self, keyword: str, version: str) -> List[Dict]:
        """Fetch từ NVD API."""
        try:
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"keywordSearch": f"{keyword} {version}", "resultsPerPage": 10}
            headers = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            response = requests.get(url, params=params, headers=headers, timeout=10)
            if response.status_code != 200:
                logger.warning(f"[CVE] NVD returned {response.status_code} for {keyword}")
                return []

            data = response.json()
            vulnerabilities = []
            for entry in data.get("vulnerabilities", []):
                cve = entry.get("cve", {})
                description = self._extract_nvd_description(cve)
                cvss_data = self._extract_nvd_cvss(cve)
                vulnerabilities.append(
                    {
                        "cve": cve.get("id", "Unknown"),
                        "title": description,
                        "description": description,
                        "severity": cvss_data.get("severity", "MEDIUM"),
                        "cvss_score": cvss_data.get("baseScore", 0),
                        "references": [ref.get("url") for ref in cve.get("references", []) if ref.get("url")],
                        "component": keyword,
                        "source": "nvd",
                    }
                )
            return vulnerabilities
        except Exception as e:
            logger.error(f"[CVE] NVD fetch failed for {keyword}: {e}")
            return []

    def _check_cache(self, component: str, version: str) -> Optional[List[Dict]]:
        """Kiểm tra cache trong 24h."""
        conn = sqlite3.connect(self.cache_db)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT cves, last_updated FROM cve_cache WHERE component = ? AND version = ?",
                (component, version),
            )
            row = cursor.fetchone()
        finally:
            conn.close()

        if not row:
            return None

        try:
            cves = json.loads(row[0])
            last_updated = datetime.fromisoformat(row[1])
        except Exception:
            return None

        if datetime.now() - last_updated < timedelta(hours=24):
            logger.debug(f"[CVE] Cache hit for {component} v{version}")
            return cves
        return None

    def _save_cache(self, component: str, version: str, cves: List[Dict]):
        """Lưu cache."""
        conn = sqlite3.connect(self.cache_db)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "REPLACE INTO cve_cache (component, version, cves, last_updated) VALUES (?, ?, ?, ?)",
                (component, version, json.dumps(cves), datetime.now().isoformat()),
            )
            conn.commit()
        finally:
            conn.close()

    def _version_affected(self, current: str, affected_range) -> bool:
        """Kiểm tra version có thể nằm trong range bị ảnh hưởng không."""
        if not affected_range:
            return True

        current_ver = self._parse_version(current)
        if not current_ver:
            return True

        if isinstance(affected_range, dict):
            constraints = []
            for key, meta in affected_range.items():
                if meta.get("status") in {"affected", "unfixed"}:
                    constraints.append(key)
            return any(self._version_affected(current, item) for item in constraints) if constraints else True

        if isinstance(affected_range, list):
            return any(self._version_affected(current, item) for item in affected_range)

        text = str(affected_range).strip()
        if not text:
            return True

        if "<=" in text:
            max_ver = self._parse_version(text.split("<=")[-1].strip())
            return bool(max_ver and current_ver <= max_ver)
        if ">=" in text:
            min_ver = self._parse_version(text.split(">=")[-1].strip())
            return bool(min_ver and current_ver >= min_ver)
        if "<" in text:
            max_ver = self._parse_version(text.split("<")[-1].strip())
            return bool(max_ver and current_ver < max_ver)
        if ">" in text:
            min_ver = self._parse_version(text.split(">")[-1].strip())
            return bool(min_ver and current_ver > min_ver)
        if "-" in text:
            parts = text.split("-", 1)
            min_ver = self._parse_version(parts[0].strip())
            max_ver = self._parse_version(parts[1].strip())
            return bool(min_ver and max_ver and min_ver <= current_ver <= max_ver)

        exact_ver = self._parse_version(text)
        return bool(exact_ver and current_ver == exact_ver)

    def _parse_version(self, version: str) -> tuple:
        parts = re.findall(r"\d+", str(version))
        return tuple(int(p) for p in parts[:4]) if parts else ()

    def _is_usable_version(self, version: str) -> bool:
        if not version:
            return False
        return version.lower() not in {"unknown", "latest", "n/a", "none"}

    def _extract_cve_id(self, vuln: Dict) -> str:
        cve = vuln.get("cve")
        if isinstance(cve, dict):
            return cve.get("id", "Unknown")
        if isinstance(cve, str):
            return cve
        references = vuln.get("references", {}) or {}
        for candidate in references.get("cve", []):
            if candidate:
                return candidate
        return "Unknown"

    def _extract_wpscan_cvss(self, vuln: Dict) -> float:
        cvss = vuln.get("cvss")
        if isinstance(cvss, dict):
            return cvss.get("score", 0) or 0
        if isinstance(cvss, (int, float)):
            return cvss
        return 0

    def _normalize_references(self, references) -> List[str]:
        if isinstance(references, dict):
            urls = references.get("url", [])
            return [url for url in urls if url]
        if isinstance(references, list):
            return [url for url in references if isinstance(url, str) and url]
        return []

    def _extract_nvd_description(self, cve: Dict) -> str:
        descriptions = cve.get("descriptions", []) or []
        for item in descriptions:
            if item.get("lang") == "en" and item.get("value"):
                return item["value"]
        return descriptions[0].get("value", "") if descriptions else ""

    def _extract_nvd_cvss(self, cve: Dict) -> Dict:
        metrics = cve.get("metrics", {}) or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key) or []
            if values:
                cvss_data = values[0].get("cvssData", {}) or {}
                severity = cvss_data.get("baseSeverity") or values[0].get("baseSeverity") or "MEDIUM"
                return {
                    "severity": str(severity).upper(),
                    "baseScore": cvss_data.get("baseScore", 0),
                }
        return {"severity": "MEDIUM", "baseScore": 0}
