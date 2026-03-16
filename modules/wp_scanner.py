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
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from core.state_manager import StateManager
from core.http_engine import HTTPClient
from core.executor import tool_available, run_command

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

    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.http_client = HTTPClient()
        self.results_file = os.path.join(output_dir, "wordpress_scan.json")

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

    def scan_wordpress_sites(self, targets: List[str]) -> Dict[str, Any]:
        """Scan WordPress installations"""
        logger.info(f"[WP] Scanning {len(targets)} targets for WordPress...")

        results = {}

        # Use thread pool for parallel scanning
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._check_and_scan_site, target): target for target in targets}

            with tqdm(total=len(targets), desc="WordPress Scan", unit="site") as pbar:
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

    def _scan_wordpress_site(self, url: str) -> Dict[str, Any]:
        """Scan a WordPress site for vulnerabilities and information"""
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

        for site_result in results.values():
            all_plugins.extend(site_result.get("plugins", []))
            all_themes.extend(site_result.get("themes", []))
            all_users.extend(site_result.get("users", []))
            all_vulns.extend(site_result.get("vulnerabilities", []))

        self.state.update(
            wordpress_detected=True,
            wp_sites=list(results.keys()),
            wp_plugins=all_plugins,
            wp_themes=all_themes,
            wp_users=list(set(all_users)),
            wp_vulnerabilities=all_vulns
        )

        critical_vulns = [v for v in all_vulns if v.get("severity") == "CRITICAL"]
        if critical_vulns:
            logger.warning(f"[WP] Found {len(critical_vulns)} CRITICAL WordPress vulnerabilities!")
