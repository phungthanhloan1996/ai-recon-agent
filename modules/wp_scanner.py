"""
modules/wp_scanner.py - WordPress Scanner Engine
Scans WordPress installations using rules and HTTP probing
"""

import json
import os
import re
import time
import logging
import urllib.request
import urllib.parse
import urllib.error
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from core.state_manager import StateManager
from core.http_engine import HTTPClient
from core.executor import tool_available, run_command
from core.cve_matcher import match_any_range

logger = logging.getLogger("recon.wordpress")

# WordPress constants
WP_VULNERABILITIES = {
    "xmlrpc_enabled": {"severity": "MEDIUM", "description": "XML-RPC enabled"},
    "user_enumeration": {"severity": "LOW", "description": "User enumeration possible"},
    "config_backup": {"severity": "HIGH", "description": "Config backup exposed"},
    "readme_exposed": {"severity": "LOW", "description": "Readme file exposed"},
    "git_exposed": {"severity": "MEDIUM", "description": "Git repository exposed"},
    "debug_log_exposed": {"severity": "MEDIUM", "description": "Debug log exposed"}
}

WP_PLUGINS = [
    "hello-dolly", "akismet", "woocommerce", "contact-form-7",
    "wordpress-seo", "wp-super-cache", "jetpack", "google-analytics-for-wordpress"
]

WP_THEMES = [
    "twentytwentyone", "twentytwenty", "twentynineteen", "astra",
    "generatepress", "oceanwp", "divi", "avada"
]

WP_CORE_FILES = [
    "wp-config.php", "wp-login.php", "wp-admin/", "wp-content/",
    "wp-includes/", "xmlrpc.php", "readme.html"
]

WP_CONFIG_FILES = [
    "wp-config.php", "wp-config.php.bak", ".htaccess", "php.ini"
]

WP_ADMIN_PATHS = [
    "/wp-admin/", "/wp-admin/admin.php", "/wp-admin/users.php",
    "/wp-admin/plugins.php", "/wp-admin/themes.php"
]

WP_UPLOAD_PATHS = [
    "/wp-content/uploads/", "/wp-content/uploads/2023/",
    "/wp-content/uploads/2022/", "/wp-content/uploads/2021/"
]

WP_INCLUDES_PATHS = [
    "/wp-includes/", "/wp-includes/js/", "/wp-includes/css/",
    "/wp-includes/images/"
]

WP_CONTENT_PATHS = [
    "/wp-content/", "/wp-content/themes/", "/wp-content/plugins/",
    "/wp-content/uploads/"
]

WP_PLUGIN_PATHS = [
    "/wp-content/plugins/", "/wp-content/mu-plugins/"
]

WP_THEME_PATHS = [
    "/wp-content/themes/"
]

WP_CORE_PATHS = [
    "/", "/wp-admin/", "/wp-content/", "/wp-includes/"
]

WP_VERSION_PATTERNS = [
    r'WordPress (\d+\.\d+(?:\.\d+)?)',
    r'content="WordPress (\d+\.\d+(?:\.\d+)?)"',
    r'version (\d+\.\d+(?:\.\d+)?)'
]

WP_PLUGIN_PATTERNS = [
    r'wp-content/plugins/([^/]+)/',
    r'plugins/([^/]+)/'
]

WP_THEME_PATTERNS = [
    r'wp-content/themes/([^/]+)/',
    r'themes/([^/]+)/'
]

WP_CONFIG_PATTERNS = [
    r'DB_NAME[^\'"]*[\'"]([^\'"]+)[\'"]',
    r'DB_USER[^\'"]*[\'"]([^\'"]+)[\'"]',
    r'DB_PASSWORD[^\'"]*[\'"]([^\'"]+)[\'"]'
]

WP_ADMIN_PATTERNS = [
    r'/wp-admin/',
    r'admin_url'
]

WP_UPLOAD_PATTERNS = [
    r'/wp-content/uploads/',
    r'upload_dir'
]

WP_INCLUDES_PATTERNS = [
    r'/wp-includes/',
    r'include_path'
]

WP_CONTENT_PATTERNS = [
    r'/wp-content/',
    r'content_url'
]

WP_PLUGIN_PATTERNS = WP_PLUGIN_PATTERNS  # Reuse
WP_THEME_PATTERNS = WP_THEME_PATTERNS    # Reuse
WP_CORE_PATTERNS = [
    r'wp-blog-header\.php',
    r'wp-load\.php'
]


class WordPressScannerEngine:
    """
    Engine for scanning WordPress installations.
    Uses HTTP probing and rules instead of external tools.
    """

    def __init__(self, state: StateManager, output_dir: str, wps_token: str = ""):
        self.state = state
        self.output_dir = output_dir
        self.wps_token = wps_token
        self.http_client = HTTPClient()
        self.results_file = os.path.join(output_dir, "wordpress_scan.json")
        self.wpscan_cache_dir = os.path.join(output_dir, "_cache", "wpscan")
        self.wp_rules = self._load_wp_rules()

        # WordPress detection patterns
        self.wp_indicators = [
            "/wp-login.php",
            "/wp-admin/",
            "/wp-content/",
            "/wp-includes/",
            "/xmlrpc.php",
            "/readme.html",
            "/wp-config.php"
        ]

        # Vulnerability checks
        self.vuln_checks = [
            {
                "path": "/xmlrpc.php",
                "method": "POST",
                "data": "<?xml version='1.0'?><methodCall><methodName>system.listMethods</methodName></methodCall>",
                "vulnerable_if": "system.",
                "type": "xmlrpc_enabled"
            },
            {
                "path": "/wp-json/wp/v2/users",
                "method": "GET",
                "vulnerable_if": '"id":',
                "type": "user_enumeration"
            },
            {
                "path": "/wp-config.php.bak",
                "method": "GET",
                "vulnerable_if": "DB_NAME",
                "type": "config_backup"
            },
            {
                "path": "/readme.html",
                "method": "GET",
                "vulnerable_if": "WordPress",
                "type": "readme_exposed"
            },
            {
                "path": "/.git/HEAD",
                "method": "GET",
                "vulnerable_if": "ref:",
                "type": "git_exposed"
            },
            {
                "path": "/wp-content/debug.log",
                "method": "GET",
                "vulnerable_if": "PHP",
                "type": "debug_log_exposed"
            }
        ]

    def _load_wp_rules(self) -> Dict[str, Any]:
        rules_file = os.path.join(os.path.dirname(__file__), "../rules/wordpress_rules.json")
        if not os.path.exists(rules_file):
            return {}
        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("wordpress", data)
        except Exception as e:
            logger.debug(f"[WP] Failed to load wordpress rules: {e}")
            return {}

    def scan_wordpress_sites(self, targets: List[str]) -> Dict[str, Any]:
        """Scan WordPress installations"""
        canonical_targets = self._canonicalize_targets(targets)
        logger.info(f"[WP] Scanning {len(canonical_targets)} canonical targets for WordPress...")

        results = {}

        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_and_scan_site, target): target for target in canonical_targets}

            with tqdm(total=len(canonical_targets), desc="WordPress Scan", unit="site") as pbar:
                for future in as_completed(futures):
                    target = futures[future]
                    try:
                        result = future.result()
                        if result:
                            results[target] = result
                            logger.info(f"[WP] WordPress detected at {target}")
                        else:
                            logger.debug(f"[WP] Not WordPress: {target}")
                    except Exception as e:
                        logger.debug(f"[WP] Error scanning {target}: {e}")
                    pbar.update(1)

        # Save results
        self._save_results(results)

        # Update state
        self._update_state(results)

        logger.info(f"[WP] Scanned {len(results)} WordPress sites")
        return results

    def _canonicalize_targets(self, targets: List[str]) -> List[str]:
        """
        Reduce noisy URL-level targets to canonical site roots:
        - keep scheme + host only
        - prefer https when both schemes exist
        """
        host_schemes: Dict[str, set] = {}
        for raw in targets:
            u = (raw or "").strip()
            if not u:
                continue
            if not u.startswith(("http://", "https://")):
                u = "https://" + u
            try:
                p = urlparse(u)
            except Exception:
                continue
            host = (p.netloc or "").strip().lower()
            scheme = (p.scheme or "https").lower()
            if not host:
                continue
            host_schemes.setdefault(host, set()).add(scheme)

        out = []
        for host, schemes in sorted(host_schemes.items()):
            scheme = "https" if "https" in schemes else sorted(schemes)[0]
            out.append(f"{scheme}://{host}")
        return out

    def _check_and_scan_site(self, target: str) -> Optional[Dict[str, Any]]:
        """Check if site is WordPress and scan it"""
        if self._is_wordpress_site(target):
            return self._scan_wordpress_site(target)
        return None

    def _is_wordpress_site(self, url: str) -> bool:
        """Check if URL is a WordPress site"""
        try:
            # Check multiple indicators
            for indicator in self.wp_indicators[:3]:  # Check first 3 indicators
                test_url = url.rstrip("/") + indicator
                response = self.http_client.get(test_url, timeout=10)

                if response.status_code == 200:
                    content = response.text.lower()
                    if "wordpress" in content or "wp-" in content:
                        return True

            # Check homepage for WordPress meta
            response = self.http_client.get(url, timeout=10)
            content = response.text.lower()

            wp_signatures = [
                "wp-content",
                "wp-includes",
                "wordpress",
                "generator\" content=\"wordpress",
                "/wp-json/"
            ]

            if any(sig in content for sig in wp_signatures):
                return True

        except Exception as e:
            logger.debug(f"[WP] Error checking {url}: {e}")

        return False

    def _scan_wordpress_site_basic(self, url: str) -> Dict[str, Any]:
        """Legacy/basic WordPress site scan."""
        logger.info(f"[WP] Scanning WordPress site: {url}")

        result = {
            "url": url,
            "version": self._detect_version(url),
            "plugins": self._enumerate_plugins(url),
            "themes": self._enumerate_themes(url),
            "users": self._enumerate_users(url),
            "vulnerabilities": [],
            "interesting_findings": []
        }

        # Run vulnerability checks
        for check in self.vuln_checks:
            vuln_result = self._run_vuln_check(url, check)
            if vuln_result:
                result["vulnerabilities"].append(vuln_result)

        # Check for common vulnerable plugins/themes
        result["vulnerabilities"].extend(self._check_known_vulnerabilities(url, result))

        logger.info(f"[WP] Found {len(result['vulnerabilities'])} potential issues at {url}")
        return result

    def _detect_version(self, url: str) -> str:
        """Detect WordPress version"""
        version_checks = [
            "/readme.html",
            "/wp-includes/version.php",
            "/wp-admin/install.php"
        ]

        for path in version_checks:
            try:
                response = self.http_client.get(url.rstrip("/") + path, timeout=10)
                if response.status_code == 200:
                    content = response.text

                    # Look for version patterns
                    version_match = re.search(r'WordPress (\d+\.\d+(?:\.\d+)?)', content)
                    if version_match:
                        return version_match.group(1)

                    # Check meta generator
                    meta_match = re.search(r'content="WordPress (\d+\.\d+(?:\.\d+)?)"', content)
                    if meta_match:
                        return meta_match.group(1)

            except Exception:
                continue

        # Fallback: homepage generator tag
        try:
            response = self.http_client.get(url, timeout=10)
            meta_match = re.search(r'content="WordPress (\d+\.\d+(?:\.\d+)?)"', response.text, re.IGNORECASE)
            if meta_match:
                return meta_match.group(1)
        except Exception:
            pass

        return "unknown"

    def _enumerate_plugins(self, url: str) -> List[Dict[str, Any]]:
        """Enumerate WordPress plugins"""
        plugins = []

        # Common plugin paths to check
        plugin_paths = [
            "/wp-content/plugins/",
            "/wp-content/plugins/hello-dolly/",
            "/wp-content/plugins/akismet/",
            "/wp-content/plugins/woocommerce/"
        ]

        for path in plugin_paths:
            try:
                response = self.http_client.get(url.rstrip("/") + path, timeout=10)
                if response.status_code == 200:
                    # Parse directory listing or check for plugin files
                    if "index of" in response.text.lower():
                        # Directory listing enabled
                        plugins.extend(self._parse_plugin_directory(response.text))
                    else:
                        # Check for specific plugin indicators
                        plugin_name = path.split("/")[-2]
                        if plugin_name and plugin_name != "plugins":
                            plugins.append({
                                "name": plugin_name,
                                "version": "unknown",
                                "path": path
                            })

            except Exception:
                continue

        # Fingerprint common plugins and infer versions from readme/stable tag.
        for plugin in WP_PLUGINS:
            plugin_url = f"{url.rstrip('/')}/wp-content/plugins/{plugin}/"
            try:
                r = self.http_client.get(plugin_url, timeout=8)
                if r.status_code != 200:
                    continue
                version = "unknown"
                readme = self.http_client.get(f"{plugin_url}readme.txt", timeout=8)
                if readme.status_code == 200:
                    version = self._extract_version_from_text(readme.text)
                plugins.append(
                    {
                        "name": plugin,
                        "version": version,
                        "path": f"/wp-content/plugins/{plugin}/",
                    }
                )
            except Exception:
                continue

        return plugins

    def _enumerate_themes(self, url: str) -> List[Dict[str, Any]]:
        """Enumerate WordPress themes"""
        themes = []

        try:
            response = self.http_client.get(url.rstrip("/") + "/wp-content/themes/", timeout=10)
            if response.status_code == 200 and "index of" in response.text.lower():
                themes.extend(self._parse_theme_directory(response.text))
        except Exception:
            pass

        # Fingerprint common themes and infer versions from style.css header.
        for theme in WP_THEMES:
            theme_base = f"{url.rstrip('/')}/wp-content/themes/{theme}/"
            try:
                r = self.http_client.get(theme_base, timeout=8)
                if r.status_code != 200:
                    continue
                version = "unknown"
                style = self.http_client.get(f"{theme_base}style.css", timeout=8)
                if style.status_code == 200:
                    version = self._extract_version_from_text(style.text)
                themes.append(
                    {
                        "name": theme,
                        "version": version,
                        "path": f"/wp-content/themes/{theme}/",
                    }
                )
            except Exception:
                continue

        return themes

    def _enumerate_users(self, url: str) -> List[str]:
        """Enumerate WordPress users"""
        users = []

        # Try user enumeration via REST API
        try:
            response = self.http_client.get(url.rstrip("/") + "/wp-json/wp/v2/users", timeout=10)
            if response.status_code == 200:
                user_data = response.json()
                for user in user_data:
                    username = user.get("slug") or user.get("name")
                    if username:
                        users.append(username)
        except Exception:
            pass

        # Try author enumeration
        for i in range(1, 11):  # Check first 10 authors
            try:
                response = self.http_client.get(f"{url.rstrip('/')}/?author={i}", timeout=10)
                if response.status_code == 200 and "author" in response.url:
                    # Extract username from redirect or content
                    username_match = re.search(r'/author/([^/]+)/', response.url)
                    if username_match:
                        users.append(username_match.group(1))
            except Exception:
                continue

        return list(set(users))  # Remove duplicates

    def _run_wpscan(self, url: str) -> Dict[str, Any]:
        """Run WPScan on the target URL"""
        if not tool_available("wpscan"):
            logger.debug("WPScan not available")
            return {}

        os.makedirs(self.wpscan_cache_dir, exist_ok=True)
        cmd = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--cache-dir", self.wpscan_cache_dir
        ]

        if self.wps_token:
            cmd.extend(["--api-token", self.wps_token])

        try:
            cmd_env = os.environ.copy()
            cmd_env["WPSCAN_CACHE_DIR"] = self.wpscan_cache_dir
            ret, out, err = run_command(cmd, timeout=300, env=cmd_env)
            if ret == 0 and out:
                try:
                    data = json.loads(out)
                    return data
                except json.JSONDecodeError:
                    logger.error("Failed to parse WPScan JSON output")
                    return {}
            else:
                logger.error(f"WPScan failed: {err}")
                return {}
        except Exception as e:
            logger.error(f"WPScan execution error: {e}")
            return {}

    def _scan_wordpress_site(self, url: str) -> Dict[str, Any]:
        """Scan a WordPress site using WPScan and HTTP checks"""
        site_info = {
            "url": url,
            "version": self._detect_version(url),
            "plugins": self._enumerate_plugins(url),
            "themes": self._enumerate_themes(url),
            "users": self._enumerate_users(url),
            "vulnerabilities": []
        }

        # Run WPScan if available
        wpscan_data = self._run_wpscan(url)
        if wpscan_data:
            # Merge WPScan results
            if "version" in wpscan_data:
                site_info["version"] = wpscan_data["version"].get("number", site_info["version"])
            if "plugins" in wpscan_data:
                # Merge plugins
                wpscan_plugins = []
                for plugin_data in wpscan_data["plugins"]:
                    wpscan_plugins.append({
                        "name": plugin_data.get("name", ""),
                        "version": plugin_data.get("version", "unknown"),
                        "vulnerabilities": plugin_data.get("vulnerabilities", [])
                    })
                site_info["plugins"].extend(wpscan_plugins)
            if "themes" in wpscan_data:
                wpscan_themes = []
                for theme_data in wpscan_data["themes"]:
                    wpscan_themes.append({
                        "name": theme_data.get("name", ""),
                        "version": theme_data.get("version", "unknown"),
                        "vulnerabilities": theme_data.get("vulnerabilities", [])
                    })
                site_info["themes"].extend(wpscan_themes)
            if "vulnerabilities" in wpscan_data:
                site_info["vulnerabilities"].extend(wpscan_data["vulnerabilities"])

        # Run HTTP-based vulnerability checks
        for check in self.vuln_checks:
            vuln = self._run_vuln_check(url, check)
            if vuln:
                site_info["vulnerabilities"].append(vuln)

        # Check for known vulnerabilities in plugins/themes
        known_vulns = self._check_known_vulnerabilities(url, site_info)
        site_info["vulnerabilities"].extend(known_vulns)
        site_info["conditioned_findings"] = self._build_conditioned_findings(site_info)

        return site_info

    def _normalize_component_name(self, name: str) -> str:
        return (name or "").strip().lower().replace("_", "-")

    def _infer_auth_requirement(self, vuln_type: str) -> str:
        t = (vuln_type or "").lower()
        if "auth_bypass" in t:
            return "unauthenticated"
        if "xss" in t:
            return "authenticated_or_public_context"
        if "file_disclosure" in t:
            return "unauthenticated_or_low_priv"
        if "rce" in t:
            return "unknown_often_authenticated"
        return "unknown"

    def _score_condition(self, version_match: Optional[bool], component_present: bool, auth_requirement: str) -> int:
        score = 0
        if component_present:
            score += 30
        if version_match is True:
            score += 45
        elif version_match is None:
            score += 15
        if auth_requirement == "unauthenticated":
            score += 15
        elif auth_requirement == "unknown_often_authenticated":
            score += 5
        return min(score, 95)

    def _build_conditioned_findings(self, site_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build exploit-condition-aware findings:
        - version range applicability
        - component presence
        - auth requirement hint
        """
        findings: List[Dict[str, Any]] = []
        plugin_rules = self.wp_rules.get("plugin_vulnerabilities", {}) or {}
        theme_rules = self.wp_rules.get("theme_vulnerabilities", {}) or {}
        site_url = site_info.get("url", "")

        for plugin in site_info.get("plugins", []):
            p_name = plugin.get("name", "")
            p_ver = plugin.get("version", "unknown")
            norm = self._normalize_component_name(p_name)
            rule = None
            for k, v in plugin_rules.items():
                if self._normalize_component_name(k) == norm:
                    rule = v
                    break
            if not rule:
                continue
            vmatch = match_any_range(p_ver, rule.get("versions", []))
            auth_req = self._infer_auth_requirement(rule.get("type", ""))
            confidence = self._score_condition(vmatch, True, auth_req)
            findings.append(
                {
                    "component_type": "plugin",
                    "name": p_name,
                    "version": p_ver,
                    "cve": rule.get("cve", []),
                    "vuln_type": rule.get("type", "unknown"),
                    "severity": rule.get("severity", "HIGH"),
                    "conditions": {
                        "version_match": vmatch,
                        "component_present": True,
                        "auth_requirement": auth_req,
                        "candidate_endpoint": f"{site_url.rstrip('/')}/wp-content/plugins/{p_name}/",
                    },
                    "confidence": confidence,
                    "status": "candidate" if confidence >= 70 else "likely" if confidence >= 45 else "weak",
                    "chain_candidate": confidence >= 70,
                }
            )

        for theme in site_info.get("themes", []):
            t_name = theme.get("name", "")
            t_ver = theme.get("version", "unknown")
            norm = self._normalize_component_name(t_name)
            rule = None
            for k, v in theme_rules.items():
                if self._normalize_component_name(k) == norm:
                    rule = v
                    break
            if not rule:
                continue
            vmatch = match_any_range(t_ver, rule.get("versions", []))
            auth_req = self._infer_auth_requirement(rule.get("type", ""))
            confidence = self._score_condition(vmatch, True, auth_req)
            findings.append(
                {
                    "component_type": "theme",
                    "name": t_name,
                    "version": t_ver,
                    "cve": rule.get("cve", []),
                    "vuln_type": rule.get("type", "unknown"),
                    "severity": rule.get("severity", "MEDIUM"),
                    "conditions": {
                        "version_match": vmatch,
                        "component_present": True,
                        "auth_requirement": auth_req,
                        "candidate_endpoint": f"{site_url.rstrip('/')}/wp-content/themes/{t_name}/",
                    },
                    "confidence": confidence,
                    "status": "candidate" if confidence >= 70 else "likely" if confidence >= 45 else "weak",
                    "chain_candidate": confidence >= 70,
                }
            )

        return findings

    def _run_vuln_check(self, url: str, check: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run a single vulnerability check"""
        try:
            check_url = url.rstrip("/") + check["path"]
            method = check.get("method", "GET")

            if method == "GET":
                response = self.http_client.get(check_url, timeout=10)
            elif method == "POST":
                data = check.get("data", "")
                response = self.http_client.post(check_url, data=data, timeout=10)
            else:
                return None

            if response.status_code == 200:
                content = response.text
                vulnerable_pattern = check.get("vulnerable_if", "")

                if vulnerable_pattern in content:
                    return {
                        "type": check["type"],
                        "url": check_url,
                        "severity": "MEDIUM",
                        "description": f"Potential {check['type']} vulnerability",
                        "evidence": content[:200]
                    }

        except Exception as e:
            logger.debug(f"[WP] Check failed {check['path']}: {e}")

        return None

    def _check_known_vulnerabilities(self, url: str, site_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for known vulnerabilities in detected plugins/themes"""
        vulnerabilities = []

        # Load WordPress rules
        rules_file = os.path.join(os.path.dirname(__file__), "../rules/wordpress_rules.json")
        if os.path.exists(rules_file):
            try:
                with open(rules_file, 'r') as f:
                    wp_rules = json.load(f)

                # Check plugins
                for plugin in site_info.get("plugins", []):
                    plugin_name = plugin.get("name", "")
                    if plugin_name in wp_rules.get("vulnerable_plugins", {}):
                        vuln_info = wp_rules["vulnerable_plugins"][plugin_name]
                        vulnerabilities.append({
                            "type": "plugin_vulnerability",
                            "name": plugin_name,
                            "severity": vuln_info.get("severity", "HIGH"),
                            "cve": vuln_info.get("cve", []),
                            "description": vuln_info.get("description", "")
                        })

                # Check themes
                for theme in site_info.get("themes", []):
                    theme_name = theme.get("name", "")
                    if theme_name in wp_rules.get("vulnerable_themes", {}):
                        vuln_info = wp_rules["vulnerable_themes"][theme_name]
                        vulnerabilities.append({
                            "type": "theme_vulnerability",
                            "name": theme_name,
                            "severity": vuln_info.get("severity", "HIGH"),
                            "cve": vuln_info.get("cve", []),
                            "description": vuln_info.get("description", "")
                        })

            except Exception as e:
                logger.debug(f"[WP] Error loading rules: {e}")

        return vulnerabilities

    def _extract_version_from_text(self, text: str) -> str:
        """Extract plugin/theme version from common headers."""
        patterns = [
            r"Stable tag:\s*([0-9][0-9a-zA-Z\.\-_]+)",
            r"Version:\s*([0-9][0-9a-zA-Z\.\-_]+)",
            r"WordPress\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return "unknown"

    def _parse_plugin_directory(self, html: str) -> List[Dict[str, Any]]:
        """Parse plugin directory listing"""
        plugins = []
        # Simple regex to extract plugin names from directory listing
        plugin_matches = re.findall(r'<a href="([^"]+)/">[^<]*</a>', html)
        for match in plugin_matches:
            if not match.startswith('.') and match not in ['..', 'index.php']:
                plugins.append({
                    "name": match,
                    "version": "unknown",
                    "path": f"/wp-content/plugins/{match}/"
                })
        return plugins

    def _parse_theme_directory(self, html: str) -> List[Dict[str, Any]]:
        """Parse theme directory listing"""
        themes = []
        theme_matches = re.findall(r'<a href="([^"]+)/">[^<]*</a>', html)
        for match in theme_matches:
            if not match.startswith('.') and match not in ['..', 'index.php']:
                themes.append({
                    "name": match,
                    "version": "unknown",
                    "path": f"/wp-content/themes/{match}/"
                })
        return themes

    def _save_results(self, results: Dict[str, Any]):
        """Save scan results"""
        with open(self.results_file, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"[WP] Saved WordPress scan results → {self.results_file}")

    def _update_state(self, results: Dict[str, Any]):
        """Update state with WordPress findings"""
        all_plugins = []
        all_themes = []
        all_users = []
        all_vulns = []
        all_conditioned = []

        for site_result in results.values():
            all_plugins.extend(site_result.get("plugins", []))
            all_themes.extend(site_result.get("themes", []))
            all_users.extend(site_result.get("users", []))
            all_vulns.extend(site_result.get("vulnerabilities", []))
            all_conditioned.extend(site_result.get("conditioned_findings", []))

        self.state.update(
            wordpress_detected=True,
            wp_sites=list(results.keys()),
            wp_plugins=all_plugins,
            wp_themes=all_themes,
            wp_users=list(set(all_users)),
            wp_vulnerabilities=all_vulns,
            wp_conditioned_findings=all_conditioned
        )

        critical_vulns = [v for v in all_vulns if v.get("severity") == "CRITICAL"]
        if critical_vulns:
            logger.warning(f"[WP] Found {len(critical_vulns)} CRITICAL WordPress vulnerabilities!")
