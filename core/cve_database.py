"""
core/cve_database.py - CVE lookup via NVD API v2 + local SQLite cache

Third CVE layer (after wpscan-local + searchsploit). Covers Apache, Nginx,
PHP, WordPress core, MySQL, and other web-stack software that searchsploit
often misses because there's no public Exploit-DB PoC.

No API key required — public NVD access (5 req/30s without key).
All results are cached in SQLite to avoid repeated network calls.
Cache TTL: 7 days per (product, version) pair.

Integration: imported by whatweb_runner and wp_scanner as fallback after
searchsploit returns no results. Never raises — always returns [] on error.
"""

import json
import logging
import re
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.cve_matcher import match_single_range, normalize_version

logger = logging.getLogger("recon.cve_db")

_DB_PATH = Path.home() / ".local" / "share" / "ai-recon" / "cve_cache.db"
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_TTL = 7 * 86400        # 7 days
_REQ_TIMEOUT = 12              # seconds per HTTP request
_RATE_LIMIT_DELAY = 6.5        # NVD public: 5 req/30s → 1 req/6s is safe

# Product name → CPE vendor:product pairs for NVD CPE matching
_PRODUCT_CPE_MAP = {
    "apache":       [("apache", "http_server")],
    "apache http server": [("apache", "http_server")],
    "nginx":        [("nginx", "nginx")],
    "php":          [("php", "php")],
    "wordpress":    [("wordpress", "wordpress")],
    "mysql":        [("oracle", "mysql"), ("mysql", "mysql")],
    "mariadb":      [("mariadb", "mariadb")],
    "openssh":      [("openbsd", "openssh")],
    "openssl":      [("openssl", "openssl")],
    "drupal":       [("drupal", "drupal")],
    "joomla":       [("joomla", "joomla")],
    "tomcat":       [("apache", "tomcat")],
    "spring":       [("vmware", "spring_framework"), ("pivotal_software", "spring_framework")],
    "jquery":       [("jquery", "jquery")],
    "laravel":      [("laravel", "laravel")],
    "django":       [("djangoproject", "django")],
    "flask":        [("palletsprojects", "flask")],
    "express":      [("expressjs", "express")],
    "node.js":      [("nodejs", "node.js")],
    "nodejs":       [("nodejs", "node.js")],
    "ruby on rails":  [("rubyonrails", "ruby_on_rails")],
    "rails":        [("rubyonrails", "ruby_on_rails")],
}

_SEVERITY_MAP = {
    "CRITICAL": ["rce", "remote code execution", "unauthenticated rce", "os command injection"],
    "HIGH": [
        "sql injection", "sqli", "file upload", "lfi", "rfi",
        "privilege escalation", "auth bypass", "authentication bypass",
        "arbitrary file", "arbitrary code",
    ],
    "MEDIUM": [
        "xss", "cross-site scripting", "csrf", "ssrf",
        "directory traversal", "path traversal", "open redirect",
        "information disclosure", "xxe",
    ],
    "LOW": ["dos", "denial of service", "brute force"],
}

_TYPE_MAP = [
    ("rce",                  ["rce", "remote code execution", "os command injection", "arbitrary code"]),
    ("sqli",                 ["sql injection", "sqli"]),
    ("file_upload",          ["file upload", "arbitrary file upload"]),
    ("lfi",                  ["lfi", "local file inclusion", "local file read"]),
    ("rfi",                  ["rfi", "remote file inclusion"]),
    ("xss",                  ["xss", "cross-site scripting"]),
    ("ssrf",                 ["ssrf", "server-side request forgery"]),
    ("xxe",                  ["xxe", "xml external entity"]),
    ("path_traversal",       ["directory traversal", "path traversal"]),
    ("auth_bypass",          ["auth bypass", "authentication bypass"]),
    ("privilege_escalation", ["privilege escalation"]),
    ("info_disclosure",      ["information disclosure", "sensitive data"]),
]


class CVEDatabase:
    """
    SQLite-backed CVE cache with NVD API v2 as the data source.

    Thread-safe. Uses a single global rate-limit lock so parallel callers
    don't blast the NVD endpoint.
    """

    _rate_lock = threading.Lock()
    _last_request_ts: float = 0.0

    def __init__(self):
        _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._db_path = str(_DB_PATH)
        self._init_db()

    # ── Public API ────────────────────────────────────────────────────────────

    def query(self, product: str, version: str = "") -> List[Dict]:
        """
        Return CVE dicts for the given product+version.

        Checks SQLite cache first (TTL=7d). On miss, queries NVD and
        populates cache. Version-range filters noise.
        Never raises; returns [] on any error.
        """
        if not product:
            return []
        product_norm = product.strip().lower()
        try:
            cached = self._cache_get(product_norm, version)
            if cached is not None:
                return self._filter_by_version(cached, version)

            cves = self._nvd_fetch(product_norm, version)
            self._cache_set(product_norm, version, cves)
            return self._filter_by_version(cves, version)
        except Exception as e:
            logger.debug("[CVE_DB] query(%s, %s) error: %s", product, version, e)
            return []

    def query_many(self, tech_versions: List[Dict]) -> List[Dict]:
        """Batch query. tech_versions: [{'name': 'Apache', 'version': '2.4.49'}, ...]"""
        all_results: List[Dict] = []
        seen_cves: set = set()
        for item in tech_versions:
            name = item.get("name") or item.get("tech", "")
            ver  = item.get("version") or item.get("ver", "")
            for r in self.query(name, ver):
                key = r["cve_id"] or r["title"]
                if key not in seen_cves:
                    seen_cves.add(key)
                    all_results.append(r)
        return sorted(all_results, key=lambda x: _sev_order(x["severity"]))

    # ── SQLite cache ──────────────────────────────────────────────────────────

    def _init_db(self):
        with sqlite3.connect(self._db_path) as con:
            con.execute(
                """CREATE TABLE IF NOT EXISTS cve_cache (
                    product     TEXT NOT NULL,
                    version_key TEXT NOT NULL,
                    fetched_at  REAL NOT NULL,
                    data        TEXT NOT NULL,
                    PRIMARY KEY (product, version_key)
                )"""
            )
            con.execute("CREATE INDEX IF NOT EXISTS idx_product ON cve_cache(product)")
            con.commit()

    def _cache_get(self, product: str, version: str) -> Optional[List[Dict]]:
        """Return cached list or None if missing/stale."""
        key = _version_cache_key(version)
        with sqlite3.connect(self._db_path) as con:
            row = con.execute(
                "SELECT fetched_at, data FROM cve_cache WHERE product=? AND version_key=?",
                (product, key),
            ).fetchone()
        if row is None:
            return None
        fetched_at, data_json = row
        if (time.time() - fetched_at) > _CACHE_TTL:
            return None  # stale
        try:
            return json.loads(data_json)
        except Exception:
            return None

    def _cache_set(self, product: str, version: str, cves: List[Dict]):
        key = _version_cache_key(version)
        with sqlite3.connect(self._db_path) as con:
            con.execute(
                """INSERT OR REPLACE INTO cve_cache(product, version_key, fetched_at, data)
                   VALUES (?, ?, ?, ?)""",
                (product, key, time.time(), json.dumps(cves)),
            )
            con.commit()

    # ── NVD API v2 ────────────────────────────────────────────────────────────

    def _nvd_fetch(self, product_norm: str, version: str) -> List[Dict]:
        """Query NVD API v2. Returns raw normalized list (pre-version-filter)."""
        cpes = _PRODUCT_CPE_MAP.get(product_norm)
        results: List[Dict] = []
        if cpes:
            for vendor, prod in cpes:
                results.extend(self._nvd_by_cpe(vendor, prod, version))
                if results:
                    break
        if not results:
            # Fallback: keyword search
            results = self._nvd_by_keyword(product_norm, version)
        return results

    def _nvd_by_cpe(self, vendor: str, product: str, version: str) -> List[Dict]:
        """Query NVD by CPE name for precise product matching."""
        # Use cpeName with version for direct lookup
        cpe_name = f"cpe:2.3:a:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": 50,
        }
        return self._nvd_request(params, f"{vendor}/{product}")

    def _nvd_by_keyword(self, keyword: str, version: str) -> List[Dict]:
        """Fallback: keyword search (broader, may need filtering)."""
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 30,
        }
        return self._nvd_request(params, keyword)

    def _nvd_request(self, params: Dict, label: str) -> List[Dict]:
        """Execute one NVD API request with rate limiting."""
        self._rate_limit()
        url = f"{_NVD_BASE}?{urllib.parse.urlencode(params)}"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "ai-recon-agent/1.0 (security research)",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=_REQ_TIMEOUT) as resp:
                raw = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.debug("[CVE_DB] NVD rate limited for %s — skipping", label)
            else:
                logger.debug("[CVE_DB] NVD HTTP %d for %s", e.code, label)
            return []
        except Exception as e:
            logger.debug("[CVE_DB] NVD request failed for %s: %s", label, e)
            return []

        results = []
        for item in raw.get("vulnerabilities", []):
            normed = self._normalize_nvd(item)
            if normed:
                results.append(normed)
        logger.debug("[CVE_DB] NVD returned %d results for %s", len(results), label)
        return results

    def _rate_limit(self):
        """Enforce NVD public rate limit: 1 request per _RATE_LIMIT_DELAY seconds."""
        with CVEDatabase._rate_lock:
            now = time.time()
            wait = _RATE_LIMIT_DELAY - (now - CVEDatabase._last_request_ts)
            if wait > 0:
                time.sleep(wait)
            CVEDatabase._last_request_ts = time.time()

    # ── Normalization ─────────────────────────────────────────────────────────

    def _normalize_nvd(self, item: Dict) -> Optional[Dict]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description
        descriptions = cve.get("descriptions", [])
        title = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            cve_id,
        )

        # CVSS severity
        metrics = cve.get("metrics", {})
        severity = self._extract_severity(metrics, title)

        # Affected version range from configurations
        version_range = self._extract_version_range(cve)

        return {
            "cve_id":            cve_id,
            "all_cves":          [cve_id],
            "title":             title[:300],
            "edb_id":            "",
            "severity":          severity,
            "type":              self._infer_type(title),
            "version_range":     version_range,
            "exploit_available": bool(cve.get("cisaExploitAdd") or cve.get("cisaKev")),
            "platform":          "",
            "date":              cve.get("published", "")[:10],
            "source":            "nvd",
            "technology":        "",
        }

    def _extract_severity(self, metrics: Dict, title: str) -> str:
        # Try CVSS v3.1 first, then v3.0, then v2
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                base = entries[0].get("cvssData", {})
                sev = (base.get("baseSeverity") or "").upper()
                if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    return sev
        return self._infer_severity_from_title(title)

    def _extract_version_range(self, cve: Dict) -> str:
        """
        Extract a single version range string from NVD configurations.
        Returns "" if not parseable.
        """
        try:
            configs = cve.get("configurations", [])
            for config in configs:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if not match.get("vulnerable"):
                            continue
                        lo = match.get("versionStartIncluding") or match.get("versionStartExcluding")
                        hi = match.get("versionEndIncluding") or match.get("versionEndExcluding")
                        lo_op = ">=" if match.get("versionStartIncluding") else ">"
                        hi_op = "<=" if match.get("versionEndIncluding") else "<"

                        if lo and hi:
                            return f"{lo_op}{lo},{hi_op}{hi}"
                        if hi:
                            return f"{hi_op}{hi}"
                        if lo:
                            return f"{lo_op}{lo}"
                        # exact version in CPE
                        cpe = match.get("criteria", "")
                        parts = cpe.split(":")
                        if len(parts) >= 6:
                            ver = parts[5]
                            if ver not in ("*", "-", ""):
                                return ver
        except Exception:
            pass
        return ""

    def _infer_severity_from_title(self, title: str) -> str:
        t = title.lower()
        for sev, kws in _SEVERITY_MAP.items():
            if any(k in t for k in kws):
                return sev
        return "MEDIUM"

    def _infer_type(self, title: str) -> str:
        t = title.lower()
        for vtype, kws in _TYPE_MAP:
            if any(k in t for k in kws):
                return vtype
        return "vulnerability"

    # ── Version filtering ─────────────────────────────────────────────────────

    def _filter_by_version(self, cves: List[Dict], version: str) -> List[Dict]:
        """Remove CVEs whose version range excludes the given version."""
        if not version or normalize_version(version) is None:
            return cves
        out = []
        for c in cves:
            vr = c.get("version_range", "")
            if not vr:
                out.append(c)
                continue
            # Compound range: ">=lo,<=hi" or ">=lo,<hi"
            if "," in vr:
                parts = vr.split(",", 1)
                match_lo = match_single_range(version, parts[0].strip())
                match_hi = match_single_range(version, parts[1].strip())
                if match_lo is None or match_hi is None:
                    out.append(c)  # unparseable → keep
                elif match_lo and match_hi:
                    out.append(c)
            else:
                result = match_single_range(version, vr)
                if result is None or result:
                    out.append(c)
        return out


def _version_cache_key(version: str) -> str:
    """Normalise version for use as a cache key (strip whitespace, lowercase)."""
    return (version or "").strip().lower() or "__any__"


def _sev_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)


# ── Module-level singleton ────────────────────────────────────────────────────

_db: Optional[CVEDatabase] = None
_db_lock = threading.Lock()


def get_db() -> CVEDatabase:
    global _db
    if _db is None:
        with _db_lock:
            if _db is None:
                _db = CVEDatabase()
    return _db


def query_cves(product: str, version: str = "") -> List[Dict]:
    """Convenience wrapper — module-level entry point."""
    try:
        return get_db().query(product, version)
    except Exception as e:
        logger.debug("[CVE_DB] query_cves error: %s", e)
        return []


def warm_cache_async(tech_versions: List[Dict]) -> None:
    """
    Pre-fetch CVEs for a list of technologies in a background thread.
    Call after live_hosts phase so results are cached before scanning.
    """
    def _worker():
        db = get_db()
        for item in tech_versions:
            name = item.get("name") or item.get("tech", "")
            ver  = item.get("version") or item.get("ver", "")
            if name:
                db.query(name, ver)

    t = threading.Thread(target=_worker, daemon=True, name="cve-db-warmup")
    t.start()
