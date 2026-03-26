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
from integrations.cve_lookup import CVELookup

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

        # BUG 7 FIX: Reduce max_workers from 10 to 3 to avoid overwhelming server
        with ThreadPoolExecutor(max_workers=3) as executor:
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
                # BUG 7 FIX: Wrap each HTTP call in try/except
                try:
                    response = self.http_client.get(test_url, timeout=10)
                    if response.status_code == 200:
                        content = response.text.lower()
                        if "wordpress" in content or "wp-" in content:
                            return True
                except Exception:
                    logger.debug(f"[WP] Probe failed for {test_url}")
                    continue

            # Check homepage for WordPress meta
            try:
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
            except Exception:
                logger.debug(f"[WP] Homepage probe failed for {url}")

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
        """Enumerate WordPress users and print results immediately"""
        users = []
        rest_api_users = []

        # Try user enumeration via REST API
        try:
            response = self.http_client.get(url.rstrip("/") + "/wp-json/wp/v2/users", timeout=10)
            if response.status_code == 200:
                user_data = response.json()
                for user in user_data:
                    username = user.get("slug") or user.get("name")
                    if username:
                        users.append(username)
                        rest_api_users.append(username)
                
                # Print results immediately
                if rest_api_users:
                    print(f"\n[✓] WordPress Users Enumerated via REST API ({url}/wp-json/wp/v2/users):")
                    for user in rest_api_users:
                        print(f"    • {user}")
                    logger.info(f"[REST-API] Found {len(rest_api_users)} users via /wp-json/wp/v2/users")
        except Exception as e:
            logger.debug(f"[REST-API] User enumeration via REST API failed: {str(e)[:50]}")

        # Try author enumeration
        author_users = []
        for i in range(1, 11):  # Check first 10 authors
            try:
                response = self.http_client.get(f"{url.rstrip('/')}/?author={i}", timeout=10)
                if response.status_code == 200 and "author" in response.url:
                    # Extract username from redirect or content
                    username_match = re.search(r'/author/([^/]+)/', response.url)
                    if username_match:
                        username = username_match.group(1)
                        if username not in users:
                            users.append(username)
                            author_users.append(username)
            except Exception:
                continue

        # Print author enumeration results
        if author_users:
            print(f"\n[✓] WordPress Users Enumerated via Author Probe ({url}):")
            for user in author_users:
                print(f"    • {user}")
            logger.info(f"[AUTHOR-PROBE] Found {len(author_users)} users via author parameter")

        return list(set(users))  # Remove duplicates

    def _run_wpscan(self, url: str) -> Dict[str, Any]:
        """Run WPScan as ENRICHMENT ONLY - fail fast if not available or slow"""
        if not tool_available("wpscan"):
            logger.debug("[WP] WPScan not available - using advanced scan data only")
            return {}

        os.makedirs(self.wpscan_cache_dir, exist_ok=True)
        
        # Build command with proper parameters for WPScan 3.x
        cmd = [
            "wpscan",
            "--url", url,
            "--format", "json",
            "--cache-dir", self.wpscan_cache_dir,
            "--disable-tls-checks",  # Skip SSL verification
            "-e", "vp,u,m"  # Enumerate vulnerable plugins, users, media
        ]

        # Only add API token if provided - skip if invalid
        if self.wps_token and len(self.wps_token) > 10:
            cmd.extend(["--api-token", self.wps_token])
        else:
            # Exit code 5 often means missing/invalid API token - use cache only mode
            logger.debug("[WP] No valid WPScan API token - using cache only")
            cmd.append("--no-update")  # Skip update check when no token
            cmd.append("--stealthy")  # More conservative scanning

        # FAIL FAST: Only try once, no endless retries
        max_retries = 2
        for attempt in range(max_retries):
            try:
                cmd_env = os.environ.copy()
                cmd_env["WPSCAN_CACHE_DIR"] = self.wpscan_cache_dir
                
                ret, out, err = run_command(cmd, timeout=config.WPSCAN_TIMEOUT, env=cmd_env)
                
                # Handle specific exit codes
                if ret == 5:
                    logger.warning(f"[WP] WPScan exit code 5 - API token or parameter issue")
                    # Try without API token on retry
                    if self.wps_token and attempt == 0:
                        logger.debug("[WP] Retrying WPScan without API token...")
                        self.wps_token = ""
                        cmd = [c for c in cmd if c != "--api-token" and not (cmd[cmd.index(c)-1:cmd.index(c)+2] if cmd.index(c) > 0 else False)]
                        continue
                    else:
                        logger.debug(f"[WP] WPScan failed with code 5 - skipping (likely API token invalid)")
                        return {}
                
                if ret != 0:
                    logger.debug(f"[WP] WPScan failed with code {ret} - skipping (not critical)")
                    return {}
                
                # Parse output
                if out:
                    try:
                        data = json.loads(out)
                        logger.info(f"[WP] WPScan enrichment successful")
                        return data
                    except json.JSONDecodeError:
                        logger.debug("[WP] Failed to parse WPScan output - skipping")
                        return {}
                
                # Success - exit retry loop
                break
                        
            except Exception as e:
                logger.debug(f"[WP] WPScan execution failed: {str(e)[:50]} - skipping")
                return {}
        
        return {}

    def _scan_wordpress_site(self, url: str) -> Dict[str, Any]:
        """Scan a WordPress site using wp_advanced_scan as PRIMARY, WPScan as enrichment only"""
        site_info = {
            "url": url,
            "version": None,
            "plugins": [],
            "themes": [],
            "users": [],
            "vulnerabilities": [],
            "core_vulnerabilities": [],
            "source": "wp_advanced_scan"  # Track source
        }

        # ✅ STEP 1: PRIMARY - Run wp_advanced_scan
        logger.info(f"[WP] Running wp_advanced_scan on {url}...")
        try:
            from integrations.wp_advanced_scan import WordPressAdvancedScan
            advanced_scan = WordPressAdvancedScan(url)
            advanced_data = advanced_scan.run_data_collection()
            
            # Merge advanced scan results
            if advanced_data:
                if advanced_data.get("version_detection"):
                    site_info["version"] = advanced_data["version_detection"].get("wp_version")
                if advanced_data.get("plugin_versions"):
                    for plugin_name, plugin_info in advanced_data["plugin_versions"].items():
                        site_info["plugins"].append({
                            "name": plugin_name,
                            "version": plugin_info.get("version", "unknown"),
                            "vulnerabilities": plugin_info.get("vulnerabilities", [])
                        })
                if advanced_data.get("vulnerabilities"):
                    site_info["vulnerabilities"].extend(advanced_data["vulnerabilities"])
                
                logger.info(f"[WP] wp_advanced_scan: {len(site_info['plugins'])} plugins, {len(site_info['vulnerabilities'])} vulns")
        except Exception as e:
            logger.warning(f"[WP] wp_advanced_scan failed: {str(e)[:100]}")
        
        # ✅ STEP 2: ENRICHMENT - Run basic HTTP detection if no data yet
        if not site_info["plugins"]:
            logger.info(f"[WP] Running basic HTTP enumeration on {url}...")
            site_info["version"] = self._detect_version(url)
            site_info["plugins"] = self._enumerate_plugins(url)
            site_info["themes"] = self._enumerate_themes(url)
            site_info["users"] = self._enumerate_users(url)
        
        # ✅ STEP 3: OPTIONAL - Run WPScan if available (enrichment ONLY)
        # Do NOT fail if WPScan fails - we already have data from advanced_scan
        wpscan_data = self._run_wpscan(url)
        if wpscan_data:
            logger.info(f"[WP] WPScan enrichment succeeded")
            # Merge only NEW data from WPScan
            if "version" in wpscan_data and not site_info["version"]:
                site_info["version"] = wpscan_data["version"].get("number")
            if "plugins" in wpscan_data:
                plugin_names = {p["name"].lower() for p in site_info["plugins"]}
                for plugin_data in wpscan_data["plugins"]:
                    if plugin_data.get("name", "").lower() not in plugin_names:
                        site_info["plugins"].append({
                            "name": plugin_data.get("name", ""),
                            "version": plugin_data.get("version", "unknown"),
                            "vulnerabilities": plugin_data.get("vulnerabilities", [])
                        })
            if "vulnerabilities" in wpscan_data:
                site_info["vulnerabilities"].extend(wpscan_data["vulnerabilities"])
        else:
            logger.debug(f"[WP] WPScan unavailable or failed - continuing with basic scan data")
        
        # ✅ STEP 4: HTTP-based vulnerability checks
        for check in self.vuln_checks:
            vuln = self._run_vuln_check(url, check)
            if vuln:
                site_info["vulnerabilities"].append(vuln)

        # ✅ STEP 5: Check for known vulnerabilities
        known_vulns = self._check_known_vulnerabilities(url, site_info)
        site_info["vulnerabilities"].extend(known_vulns)

        # ✅ STEP 6: Enrich detected components with CVEs without changing scan flow
        self._enrich_site_info_with_cves(site_info)
        site_info["conditioned_findings"] = self._build_conditioned_findings(site_info)

        return site_info

    def _enrich_site_info_with_cves(self, site_info: Dict[str, Any]):
        """Attach CVEs to detected WordPress components using fail-safe lookups."""
        try:
            cve_lookup = CVELookup()
        except Exception as e:
            logger.warning(f"[WP] CVE lookup initialization failed: {e}")
            return

        for plugin in site_info.get("plugins", []):
            if not isinstance(plugin, dict):
                continue
            plugin.setdefault("vulnerabilities", [])
            if plugin["vulnerabilities"]:
                continue
            name = plugin.get("name")
            version = plugin.get("version")
            if not name or not version or str(version).lower() == "unknown":
                continue
            try:
                cves = cve_lookup.get_wp_plugin_cves(name, version)
                if cves:
                    plugin["vulnerabilities"] = cves
                    logger.warning(f"[WP] {name} v{version} has {len(cves)} CVEs")
            except Exception as e:
                logger.warning(f"[WP] Plugin CVE lookup failed for {name}: {e}")

        for theme in site_info.get("themes", []):
            if not isinstance(theme, dict):
                continue
            theme.setdefault("vulnerabilities", [])
            if theme["vulnerabilities"]:
                continue
            name = theme.get("name")
            version = theme.get("version")
            if not name or not version or str(version).lower() == "unknown":
                continue
            try:
                cves = cve_lookup.get_wp_theme_cves(name, version)
                if cves:
                    theme["vulnerabilities"] = cves
                    logger.warning(f"[WP] Theme {name} v{version} has {len(cves)} CVEs")
            except Exception as e:
                logger.warning(f"[WP] Theme CVE lookup failed for {name}: {e}")

        if site_info.get("version") and not site_info.get("core_vulnerabilities"):
            try:
                cves = cve_lookup.get_wp_core_cves(site_info["version"])
                if cves:
                    site_info["core_vulnerabilities"] = cves
                    logger.warning(f"[WP] WordPress {site_info['version']} has {len(cves)} CVEs")
            except Exception as e:
                logger.warning(f"[WP] Core CVE lookup failed for {site_info.get('version')}: {e}")

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
                            "url": url,
                            "name": plugin_name,
                            "severity": vuln_info.get("severity", "HIGH"),
                            "cve": vuln_info.get("cve", []),
                            "description": vuln_info.get("description", ""),
                            "confidence": 0.8,
                            "source": "wordpress_rules",
                            "evidence": f"Plugin {plugin_name} detected"
                        })

                # Check themes
                for theme in site_info.get("themes", []):
                    theme_name = theme.get("name", "")
                    if theme_name in wp_rules.get("vulnerable_themes", {}):
                        vuln_info = wp_rules["vulnerable_themes"][theme_name]
                        vulnerabilities.append({
                            "type": "theme_vulnerability",
                            "url": url,
                            "name": theme_name,
                            "severity": vuln_info.get("severity", "HIGH"),
                            "cve": vuln_info.get("cve", []),
                            "description": vuln_info.get("description", ""),
                            "confidence": 0.8,
                            "source": "wordpress_rules",
                            "evidence": f"Theme {theme_name} detected"
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

    def detect_wordpress_from_state_data(self) -> bool:
        """
        Detect WordPress by analyzing existing scan data in state (urls, endpoints arrays).
        Returns True if WordPress detected with confidence > 70%.
        This runs AFTER crawling to extract WordPress patterns from discovered data.
        """
        logger.info("[WP] Analyzing existing scan data for WordPress patterns...")
        
        # Collect all URLs from state
        all_urls = self._collect_all_urls_from_state()
        if not all_urls:
            logger.warning("[WP] No URLs found in state to analyze")
            return False
        
        logger.debug(f"[WP] Analyzing {len(all_urls)} URLs for WordPress indicators")
        
        # Analyze URLs for WordPress patterns
        wp_findings = self._analyze_urls_for_wordpress(all_urls)
        confidence = wp_findings['confidence']
        
        logger.info(f"[WP] WordPress confidence: {confidence:.1f}% (matches: {wp_findings['pattern_matches']}/{wp_findings['total_patterns']})")
        
        # If confidence > 70%, WordPress is detected
        is_wordpress = confidence > 70.0
        
        if is_wordpress:
            logger.info("[WP] WordPress detected from scan data patterns")
            # Extract version, plugins, themes from URLs
            version = self._extract_version_from_urls(all_urls)
            plugins = self._extract_plugins_from_urls(all_urls)
            themes = self._extract_themes_from_urls(all_urls)
            
            logger.info(f"[WP] Extracted: version={version}, {len(plugins)} plugins, {len(themes)} themes")
            
            # Update state with findings
            self.state.update(
                wordpress_detected=True,
                wp_version=version,
                wp_plugins=plugins,
                wp_themes=themes,
                wp_scan_confidence=confidence,
                wp_pattern_matches=wp_findings['matches']
            )
            return True
        else:
            logger.debug(f"[WP] Insufficient WordPress patterns found (confidence {confidence:.1f}% < 70%)")
            return False

    def _collect_all_urls_from_state(self) -> List[str]:
        """Collect all discovered URLs from state (urls and endpoints arrays)"""
        urls = set()
        
        # Get URLs from state.urls
        state_urls = self.state.get("urls", [])
        if isinstance(state_urls, list):
            urls.update(str(u) for u in state_urls if u)
        
        # Get URLs from state.endpoints
        endpoints = self.state.get("endpoints", [])
        if isinstance(endpoints, list):
            # Endpoints might be dicts with 'url' key or just strings
            for ep in endpoints:
                if isinstance(ep, dict) and 'url' in ep:
                    urls.add(str(ep['url']))
                elif isinstance(ep, str):
                    urls.add(ep)
        
        # Get URLs from crawled data if available
        crawled = self.state.get("crawled_urls", [])
        if isinstance(crawled, list):
            urls.update(str(u) for u in crawled if u)
        
        logger.debug(f"[WP] Collected {len(urls)} unique URLs from state")
        return list(urls)

    def _analyze_urls_for_wordpress(self, urls: List[str]) -> Dict[str, Any]:
        """
        Analyze URLs for WordPress patterns.
        Returns dict with:
        - confidence: percentage score 0-100
        - pattern_matches: list of matched patterns
        - total_patterns: count of max possible patterns
        - matches: dict mapping patterns to found URLs
        """
        # WordPress patterns to look for
        patterns = {
            'wp-login': r'wp-login\.php',
            'xmlrpc': r'xmlrpc\.php',
            'wp-admin': r'/wp-admin',
            'wp-content': r'/wp-content',
            'wp-includes': r'/wp-includes',
            'wp-json': r'/wp-json',
            'wp-config': r'wp-config',
            'readme': r'readme\.html'
        }
        
        matched_patterns = {}
        total_unique_patterns = len(patterns)
        
        # Check each URL against patterns
        for pattern_name, pattern_regex in patterns.items():
            for url in urls:
                if re.search(pattern_regex, url, re.IGNORECASE):
                    if pattern_name not in matched_patterns:
                        matched_patterns[pattern_name] = []
                    matched_patterns[pattern_name].append(url)
                    break  # One match per pattern is enough
        
        # Calculate confidence score
        matches_count = len(matched_patterns)
        confidence = (matches_count / total_unique_patterns) * 100 if total_unique_patterns > 0 else 0
        
        return {
            'confidence': confidence,
            'pattern_matches': matches_count,
            'total_patterns': total_unique_patterns,
            'matches': matched_patterns
        }

    def _extract_version_from_urls(self, urls: List[str]) -> str:
        """Extract WordPress version from URL parameters (e.g., ?ver=5.8.1)"""
        versions = []
        version_pattern = r'[?&]ver=([0-9.]+)'
        
        for url in urls:
            match = re.search(version_pattern, url, re.IGNORECASE)
            if match:
                version = match.group(1)
                versions.append(version)
        
        if versions:
            # Return the most common version found
            from collections import Counter
            version_counts = Counter(versions)
            most_common_version = version_counts.most_common(1)[0][0]
            logger.debug(f"[WP] Extracted version from URLs: {most_common_version} (found {len(versions)} references)")
            return most_common_version
        
        return "unknown"

    def _extract_plugins_from_urls(self, urls: List[str]) -> List[Dict[str, str]]:
        """Extract WordPress plugins from URL paths (/wp-content/plugins/[name]/)"""
        plugins = {}
        plugin_pattern = r'/wp-content/plugins/([^/]+)/'
        
        for url in urls:
            matches = re.findall(plugin_pattern, url, re.IGNORECASE)
            for plugin_name in matches:
                if plugin_name and plugin_name not in ['plugins']:
                    if plugin_name not in plugins:
                        plugins[plugin_name] = {
                            'name': plugin_name,
                            'version': 'unknown',
                            'path': f'/wp-content/plugins/{plugin_name}/'
                        }
        
        result = list(plugins.values())
        logger.debug(f"[WP] Extracted {len(result)} plugins from URLs")
        return result

    def _extract_themes_from_urls(self, urls: List[str]) -> List[Dict[str, str]]:
        """Extract WordPress themes from URL paths (/wp-content/themes/[name]/)"""
        themes = {}
        theme_pattern = r'/wp-content/themes/([^/]+)/'
        
        for url in urls:
            matches = re.findall(theme_pattern, url, re.IGNORECASE)
            for theme_name in matches:
                if theme_name and theme_name not in ['themes']:
                    if theme_name not in themes:
                        themes[theme_name] = {
                            'name': theme_name,
                            'version': 'unknown',
                            'path': f'/wp-content/themes/{theme_name}/'
                        }
        
        result = list(themes.values())
        logger.debug(f"[WP] Extracted {len(result)} themes from URLs")
        return result

    def _update_state(self, results: Dict[str, Any]):
        """Update state with WordPress findings"""
        all_plugins = []
        all_themes = []
        all_users = []
        all_vulns = []
        all_conditioned = []
        all_core_vulns = []
        wp_core = {}

        for site_result in results.values():
            all_plugins.extend(site_result.get("plugins", []))
            all_themes.extend(site_result.get("themes", []))
            all_users.extend(site_result.get("users", []))
            all_vulns.extend(site_result.get("vulnerabilities", []))
            all_conditioned.extend(site_result.get("conditioned_findings", []))
            all_core_vulns.extend(site_result.get("core_vulnerabilities", []))
            if not wp_core and (site_result.get("version") or site_result.get("core_vulnerabilities")):
                wp_core = {
                    "version": site_result.get("version"),
                    "vulnerabilities": site_result.get("core_vulnerabilities", []),
                    "url": site_result.get("url"),
                }

        self.state.update(
            wordpress_detected=True,
            wp_sites=list(results.keys()),
            wp_plugins=all_plugins,
            wp_themes=all_themes,
            wp_users=list(set(all_users)),
            wp_vulnerabilities=all_vulns,
            wp_core=wp_core,
            core_vulnerabilities=all_core_vulns,
            wp_version=(wp_core.get("version") or self.state.get("wp_version", "unknown")),
            wp_conditioned_findings=all_conditioned
        )

        # Merge vào confirmed_vulnerabilities
        existing = self.state.get("confirmed_vulnerabilities", []) or []
        for v in all_vulns:
            if not any(e.get("type") == v.get("type") and e.get("url") == v.get("url") for e in existing):
                existing.append(v)
        self.state.update(confirmed_vulnerabilities=existing)

        critical_vulns = [v for v in all_vulns if v.get("severity") == "CRITICAL"]
        if critical_vulns:
            logger.warning(f"[WP] Found {len(critical_vulns)} CRITICAL WordPress vulnerabilities!")
