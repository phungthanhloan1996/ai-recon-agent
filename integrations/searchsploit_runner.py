"""
integrations/searchsploit_runner.py - Local CVE lookup via searchsploit (Exploit-DB)

No external API. Runs searchsploit --json locally.
Includes version range filtering to eliminate false positives.
Update with: searchsploit --update
"""

import json
import logging
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("recon.searchsploit")

_STALE_MARKER = Path.home() / ".local" / "share" / "ai-recon" / ".searchsploit_updated"

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

# Regex to extract version range from searchsploit title.
# Handles patterns like:
#   "Apache 2.4.49 - Path Traversal"             → exact 2.4.49
#   "Apache < 2.4.51 - RCE"                      → < 2.4.51
#   "Contact Form 7 <= 5.3.1 - SQLi"             → <= 5.3.1
#   "Plugin 1.0.2 - 1.5.0 - XSS"                → range 1.0.2–1.5.0
#   "WordPress 4.0-4.9.18 - Authenticated RCE"   → range 4.0–4.9.18
_VER_PART = r"\d+(?:\.\d+){0,3}"
_RANGE_RE = re.compile(
    r"(?:"
    r"(?P<op><=|>=|<|>)\s*(?P<ver>" + _VER_PART + r")"   # operator + version
    r"|(?P<lo>" + _VER_PART + r")\s*[-–]\s*(?P<hi>" + _VER_PART + r")"  # lo-hi range
    r"|(?P<exact>" + _VER_PART + r")(?=\s*[-–\s])"                        # exact before separator
    r")"
)


class SearchsploitRunner:
    """Local CVE/exploit lookup via searchsploit with version-range filtering."""

    def __init__(self):
        self._bin = shutil.which("searchsploit")

    def available(self) -> bool:
        return bool(self._bin)

    # ── Public query ──────────────────────────────────────────────────────────

    def query(self, tech: str, version: str = "") -> List[Dict]:
        """
        Query searchsploit for a technology + optional version.
        When version is given, filters out entries whose title specifies a
        version range that does NOT include the given version.
        Returns list of unified CVE dicts.
        """
        if not self._bin:
            return []
        term = f"{tech} {version}".strip()
        try:
            proc = subprocess.run(
                [self._bin, "--json", term],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode not in (0, 1):
                return []
            data = json.loads(proc.stdout or "{}")
            results = []
            for entry in data.get("RESULTS_EXPLOIT", []):
                normed = self._normalize(entry, tech)
                if not normed:
                    continue
                if version and not self._version_matches(normed, version):
                    logger.debug(
                        "[SEARCHSPLOIT] Filtered out '%s' — version %s not in range '%s'",
                        normed["title"][:60], version, normed.get("version_range", "?"),
                    )
                    continue
                results.append(normed)
            return results
        except Exception as e:
            logger.debug("[SEARCHSPLOIT] query(%s %s) error: %s", tech, version, e)
            return []

    def query_many(self, tech_versions: List[Dict]) -> List[Dict]:
        """Query multiple technologies. tech_versions: [{"name": "Apache", "version": "2.4.49"}, ...]"""
        all_results = []
        seen_edb: set = set()
        for item in tech_versions:
            name = item.get("name") or item.get("tech", "")
            version = item.get("version") or item.get("ver", "")
            for r in self.query(name, version):
                if r["edb_id"] not in seen_edb:
                    seen_edb.add(r["edb_id"])
                    all_results.append(r)
        return sorted(all_results, key=lambda x: _sev_order(x["severity"]))

    # ── DB management ─────────────────────────────────────────────────────────

    def is_db_stale(self, max_age_days: int = 7) -> bool:
        if not _STALE_MARKER.exists():
            return True
        return (time.time() - _STALE_MARKER.stat().st_mtime) > max_age_days * 86400

    def update_db(self) -> bool:
        if not self._bin:
            return False
        try:
            logger.info("[SEARCHSPLOIT] Updating Exploit-DB local database...")
            proc = subprocess.run(
                [self._bin, "--update"], capture_output=True, text=True, timeout=180,
            )
            _STALE_MARKER.parent.mkdir(parents=True, exist_ok=True)
            _STALE_MARKER.touch()
            logger.info("[SEARCHSPLOIT] DB updated (rc=%d)", proc.returncode)
            return proc.returncode == 0
        except Exception as e:
            logger.warning("[SEARCHSPLOIT] Update failed: %s", e)
            return False

    # ── Version range filtering ───────────────────────────────────────────────

    def _extract_version_range(self, title: str) -> Optional[str]:
        """
        Parse a version range / exact version from a searchsploit title string.
        Returns a rule string compatible with cve_matcher.match_single_range,
        or None if no parseable version info is found.

        Examples:
          "Apache < 2.4.51 - RCE"           → "< 2.4.51"
          "Plugin 5.3.1 - SQL Injection"     → "5.3.1"   (exact)
          "WordPress 4.0-4.9.18 - RCE"      → "4.0-4.9.18"
        """
        # Strip the description part (everything after " - ") to reduce noise,
        # but only if there's a clear separator far enough into the string.
        # Titles look like: "Product name {version_info} - Description"
        # We want to work on the product+version part only.
        sep_match = re.search(r"\s+-\s+[A-Z]", title)
        version_section = title[:sep_match.start()] if sep_match else title

        for m in _RANGE_RE.finditer(version_section):
            if m.group("op") and m.group("ver"):
                return f"{m.group('op')}{m.group('ver')}"
            if m.group("lo") and m.group("hi"):
                return f"{m.group('lo')}-{m.group('hi')}"
            if m.group("exact"):
                return m.group("exact")
        return None

    def _version_matches(self, entry: Dict, input_version: str) -> bool:
        """
        Return True if the input_version is within the entry's version range,
        OR if the entry has no parseable version range (can't filter → keep).
        """
        from core.cve_matcher import match_single_range, normalize_version

        version_range = entry.get("version_range")
        if not version_range:
            return True  # no range info → can't filter, keep it

        if normalize_version(input_version) is None:
            return True  # unparseable input version → keep it

        result = match_single_range(input_version, version_range)
        if result is None:
            return True  # range unparseable → keep it
        return result

    # ── Normalization ─────────────────────────────────────────────────────────

    def _normalize(self, entry: Dict, tech_hint: str = "") -> Optional[Dict]:
        title = entry.get("Title", "").strip()
        if not title:
            return None

        codes_raw = entry.get("Codes", "") or ""
        cve_ids = [
            c.strip().upper() for c in codes_raw.split(";")
            if re.match(r"CVE-\d{4}-\d+", c.strip(), re.IGNORECASE)
        ]
        primary_cve = cve_ids[0] if cve_ids else ""

        version_range = self._extract_version_range(title)

        return {
            "cve_id":            primary_cve,
            "all_cves":          cve_ids,
            "title":             title,
            "edb_id":            str(entry.get("EDB-ID", "")),
            "severity":          self._infer_severity(title),
            "type":              self._infer_type(title),
            "version_range":     version_range or "",
            "exploit_available": True,
            "platform":          entry.get("Platform", ""),
            "date":              entry.get("Date_Published") or entry.get("Date_Added", ""),
            "source":            "searchsploit",
            "technology":        tech_hint,
        }

    def _infer_severity(self, title: str) -> str:
        t = title.lower()
        for sev, keywords in _SEVERITY_MAP.items():
            if any(kw in t for kw in keywords):
                return sev
        return "MEDIUM"

    def _infer_type(self, title: str) -> str:
        t = title.lower()
        for vtype, keywords in _TYPE_MAP:
            if any(kw in t for kw in keywords):
                return vtype
        return "vulnerability"


def _sev_order(sev: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev, 4)


_runner: Optional[SearchsploitRunner] = None


def get_runner() -> SearchsploitRunner:
    global _runner
    if _runner is None:
        _runner = SearchsploitRunner()
    return _runner


def ensure_db_fresh(max_age_days: int = 7) -> None:
    import threading
    runner = get_runner()
    if not runner.available():
        return
    if runner.is_db_stale(max_age_days):
        t = threading.Thread(target=runner.update_db, daemon=True, name="searchsploit-update")
        t.start()
