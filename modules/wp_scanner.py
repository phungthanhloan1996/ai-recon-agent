"""
modules/wp_scanner.py - WordPress Scanner Engine
Scans WordPress installations using rules and HTTP probing
"""

import json
import os
import re
import time
import logging
import subprocess
import urllib.request
import urllib.parse
import urllib.error
import config
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

from core.state_manager import StateManager
from core.http_engine import HTTPClient
from core.executor import tool_available, run_command
from core.cve_matcher import match_any_range
from core.scan_optimizer import get_optimizer

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

    OPTIMIZATION: Added multi-level caching to avoid redundant scans:
    - Cache key: domain + WordPress version + plugin versions hash
    - Cache TTL: 24 hours (configurable)
    - Cache location: {output_dir}/_cache/wp_scan_results.json
    """

    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.http_client = HTTPClient()
        self.results_file = os.path.join(output_dir, "wordpress_scan.json")
        self.wpscan_cache_dir = os.path.join(output_dir, "_cache", "wpscan")
        # OPTIMIZATION: New cache for scan results
        self.scan_cache_file = os.path.join(output_dir, "_cache", "wp_scan_results.json")
        self.scan_cache_ttl = 86400  # 24 hours
        self.wp_rules = self._load_wp_rules()
        
        # WAF blocking detection
        self.waf_block_count = 0
        self.waf_block_threshold = 3  # Skip heavy scans after 3 WAF blocks

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

    def _generate_cache_key(self, url: str, version: str, plugins: List[Dict]) -> str:
        """
        OPTIMIZATION: Generate cache key based on domain + WP version + plugin versions.
        Cache hit = same domain, same WP version, same plugin versions → skip rescan.
        """
        import hashlib
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # Build plugin version signature
        plugin_sig = sorted([
            f"{p.get('name', '')}:{p.get('version', 'unknown')}"
            for p in plugins if isinstance(p, dict)
        ])
        sig_str = f"{domain}|{version}|{'|'.join(plugin_sig)}"
        
        return hashlib.md5(sig_str.encode()).hexdigest()

    def _load_scan_cache(self) -> Dict[str, Any]:
        """OPTIMIZATION: Load cached scan results from file."""
        if not os.path.exists(self.scan_cache_file):
            return {}
        try:
            with open(self.scan_cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Filter expired entries
            now = time.time()
            valid_data = {}
            for key, entry in data.items():
                if now - entry.get("timestamp", 0) < self.scan_cache_ttl:
                    valid_data[key] = entry
            # Save cleaned cache
            if len(valid_data) != len(data):
                with open(self.scan_cache_file, "w", encoding="utf-8") as f:
                    json.dump(valid_data, f, indent=2)
            return valid_data
        except Exception as e:
            logger.debug(f"[WP] Cache read error: {e}")
            return {}

    def _save_scan_cache(self, cache: Dict[str, Any]):
        """OPTIMIZATION: Save scan results to cache."""
        try:
            os.makedirs(os.path.dirname(self.scan_cache_file), exist_ok=True)
            with open(self.scan_cache_file, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            logger.debug(f"[WP] Cache write error: {e}")

    def _get_cached_result(self, url: str, version: str, plugins: List[Dict]) -> Optional[Dict[str, Any]]:
        """OPTIMIZATION: Check cache for existing scan result."""
        cache = self._load_scan_cache()
        cache_key = self._generate_cache_key(url, version, plugins)
        entry = cache.get(cache_key)
        if entry:
            age_hours = (time.time() - entry["timestamp"]) / 3600
            logger.info(f"[WP] Cache HIT for {url} (age={age_hours:.1f}h)")
            return entry.get("result")
        return None

    def _cache_result(self, url: str, version: str, plugins: List[Dict], result: Dict[str, Any]):
        """OPTIMIZATION: Cache scan result for future use."""
        cache = self._load_scan_cache()
        cache_key = self._generate_cache_key(url, version, plugins)
        cache[cache_key] = {
            "timestamp": time.time(),
            "url": url,
            "version": version,
            "plugin_count": len(plugins),
            "result": result
        }
        self._save_scan_cache(cache)
        logger.debug(f"[WP] Cached scan result for {url}")

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
                p = urllib.parse.urlparse(u)
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
        """Enumerate WordPress plugins with WAF-aware detection.
        
        FIX: Added WAF blocking detection and adaptive strategies:
        1. Detect 403/406/429 responses and switch to passive detection
        2. Use REST API as fallback when direct plugin paths are blocked
        3. Extract plugins from discovered URLs in state (passive detection)
        4. Limit requests to avoid rate limiting
        """
        plugins = []
        waf_blocked = False
        block_count = 0
        max_blocks_before_fallback = 5
        
        # Phase 1: Try direct plugin path probing (active detection)
        plugin_paths = [
            "/wp-content/plugins/",
            "/wp-content/plugins/hello-dolly/",
            "/wp-content/plugins/akismet/",
            "/wp-content/plugins/woocommerce/"
        ]

        for path in plugin_paths:
            if waf_blocked:
                logger.debug(f"[WP] WAF blocking detected, skipping direct plugin probe for {path}")
                break
                
            try:
                response = self.http_client.get(url.rstrip("/") + path, timeout=10)
                
                # Check for WAF blocking
                if response.status_code in [403, 406, 429]:
                    block_count += 1
                    logger.warning(f"[WP] WAF blocking detected on {path} (status: {response.status_code})")
                    if block_count >= max_blocks_before_fallback:
                        waf_blocked = True
                        logger.info(f"[WP] Switching to passive detection mode after {block_count} blocks")
                    continue
                    
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
                                "path": path,
                                "detection_method": "direct_probe"
                            })

            except Exception as e:
                logger.debug(f"[WP] Plugin probe failed for {path}: {e}")
                continue

        # Phase 2: If WAF blocked direct probing, use REST API fallback
        if waf_blocked:
            logger.info(f"[WP] Using REST API fallback for plugin detection on {url}")
            rest_api_plugins = self._detect_plugins_via_rest_api(url)
            
            # Only add plugins not already found
            existing_names = {p['name'] for p in plugins}
            for plugin in rest_api_plugins:
                if plugin['name'] not in existing_names:
                    plugins.append(plugin)
                    existing_names.add(plugin['name'])

        # Phase 3: Passive detection from state URLs (no network requests)
        state_plugins = self._detect_plugins_from_state_urls()
        existing_names = {p['name'] for p in plugins}
        for plugin in state_plugins:
            if plugin['name'] not in existing_names:
                plugins.append(plugin)
                existing_names.add(plugin['name'])

        # Phase 4: Fingerprint common plugins (only if not WAF blocked)
        if not waf_blocked:
            for plugin in WP_PLUGINS[:5]:  # Limit to first 5 to reduce requests
                plugin_url = f"{url.rstrip('/')}/wp-content/plugins/{plugin}/"
                try:
                    r = self.http_client.get(plugin_url, timeout=8)
                    
                    # Check for WAF blocking
                    if r.status_code in [403, 406, 429]:
                        logger.debug(f"[WP] WAF blocking on {plugin_url}, skipping remaining plugins")
                        break
                    
                    if r.status_code != 200:
                        continue
                        
                    version = "unknown"
                    readme = self.http_client.get(f"{plugin_url}readme.txt", timeout=8)
                    if readme.status_code == 200:
                        version = self._extract_version_from_text(readme.text)
                    
                    # Only add if not already found
                    if not any(p['name'] == plugin for p in plugins):
                        plugins.append({
                            "name": plugin,
                            "version": version,
                            "path": f"/wp-content/plugins/{plugin}/",
                            "detection_method": "fingerprint"
                        })
                except Exception:
                    continue

        # Add detection metadata
        for plugin in plugins:
            if 'detection_method' not in plugin:
                plugin['detection_method'] = 'passive'
        
        return plugins

    def _detect_plugins_via_rest_api(self, url: str) -> List[Dict[str, Any]]:
        """Detect plugins via WordPress REST API (WAF-friendly fallback).
        
        Uses the WordPress REST API to enumerate plugins without triggering WAF.
        This is less intrusive than direct file probing.
        """
        plugins = []
        
        # Try WordPress REST API plugin enumeration endpoints
        api_endpoints = [
            "/wp-json/wp/v2/plugins",  # Requires authentication (WordPress 5.0+)
            "/wp-json/wp/v2/plugins?per_page=100",
            "/wp-json/?rest_route=/wp/v2/plugins",
        ]
        
        for endpoint in api_endpoints:
            try:
                full_url = url.rstrip("/") + endpoint
                response = self.http_client.get(full_url, timeout=10)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            for plugin_data in data:
                                if isinstance(plugin_data, dict):
                                    plugins.append({
                                        "name": plugin_data.get("plugin", plugin_data.get("slug", "unknown")),
                                        "version": plugin_data.get("version", "unknown"),
                                        "path": plugin_data.get("plugin_file", ""),
                                        "detection_method": "rest_api"
                                    })
                            break  # Success, no need to try other endpoints
                    except (json.JSONDecodeError, ValueError):
                        continue
            except Exception as e:
                logger.debug(f"[WP] REST API plugin detection failed for {endpoint}: {e}")
                continue
        
        return plugins

    def _detect_plugins_from_state_urls(self) -> List[Dict[str, Any]]:
        """Detect plugins passively from URLs already discovered in state.
        
        This method extracts plugin names from URL patterns like:
        /wp-content/plugins/{plugin_name}/...
        
        No additional network requests are made.
        """
        plugins = []
        seen_plugins = set()
        
        # Get all URLs from state
        all_urls = set()
        
        urls_from_state = self.state.get("urls", [])
        if isinstance(urls_from_state, list):
            all_urls.update(str(u) for u in urls_from_state if u)
        
        endpoints = self.state.get("endpoints", [])
        if isinstance(endpoints, list):
            for ep in endpoints:
                if isinstance(ep, dict) and 'url' in ep:
                    all_urls.add(str(ep['url']))
                elif isinstance(ep, str):
                    all_urls.add(ep)
        
        crawled = self.state.get("crawled_urls", [])
        if isinstance(crawled, list):
            all_urls.update(str(u) for u in crawled if u)
        
        # Extract plugin names from URLs
        plugin_pattern = r'/wp-content/plugins/([^/]+)/'
        for url in all_urls:
            matches = re.findall(plugin_pattern, url, re.IGNORECASE)
            for match in matches:
                if match and match not in seen_plugins and match not in ['plugins', 'index.php']:
                    seen_plugins.add(match)
                    plugins.append({
                        "name": match,
                        "version": "unknown",
                        "path": f"/wp-content/plugins/{match}/",
                        "detection_method": "passive_url_analysis"
                    })
        
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
        """Run wpscan WITHOUT --api-token (local DB only, never rate-limited).

        Requires wpscan local DB to be populated:
          wpscan --update   (no API token needed, downloads plugins.json etc.)

        Returns parsed wpscan JSON or {} on failure.
        """
        if not tool_available("wpscan"):
            return {}
        try:
            cmd = [
                "wpscan",
                "--url", url,
                "--format", "json",
                "--no-update",           # use local DB only
                "--disable-tls-checks",
                "--random-user-agent",
                "--enumerate", "vp,vt,u1-3",  # vulnerable plugins, themes, users
                "--plugins-detection", "passive",
            ]
            # Never pass --api-token — avoids all rate-limiting
            rc, stdout, stderr = run_command(cmd, timeout=120)
            if rc != 0 or not stdout.strip():
                logger.debug("[WP] wpscan returned rc=%d for %s", rc, url)
                return {}
            data = json.loads(stdout)
            return self._parse_wpscan_json(data)
        except Exception as e:
            logger.debug("[WP] wpscan error for %s: %s", url, e)
            return {}

    def _parse_wpscan_json(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize wpscan JSON output into our internal format."""
        result: Dict[str, Any] = {"version": None, "plugins": [], "vulnerabilities": []}

        # Version
        version_info = data.get("version") or {}
        if isinstance(version_info, dict):
            result["version"] = version_info.get("number")

        # Plugins with vulnerabilities
        plugins_raw = data.get("plugins") or {}
        if isinstance(plugins_raw, dict):
            for slug, pdata in plugins_raw.items():
                if not isinstance(pdata, dict):
                    continue
                vulns = []
                for v in (pdata.get("vulnerabilities") or []):
                    vuln_entry = {
                        "cve_id": "",
                        "title": v.get("title", ""),
                        "severity": "HIGH",
                        "type": v.get("vuln_type", "vulnerability").lower(),
                        "exploit_available": bool(v.get("references", {}).get("exploitdb")),
                        "source": "wpscan_local",
                    }
                    # Extract CVE from references
                    refs = v.get("references") or {}
                    cves = refs.get("cve") or []
                    if cves:
                        vuln_entry["cve_id"] = f"CVE-{cves[0]}" if not str(cves[0]).startswith("CVE") else cves[0]
                    vuln_entry["all_cves"] = [
                        f"CVE-{c}" if not str(c).startswith("CVE") else c for c in cves
                    ]
                    vulns.append(vuln_entry)

                result["plugins"].append({
                    "name": slug,
                    "version": (pdata.get("version") or {}).get("number", "unknown"),
                    "vulnerabilities": vulns,
                })

        # Interesting findings as vulnerabilities
        for finding in (data.get("interesting_findings") or []):
            if isinstance(finding, dict):
                result["vulnerabilities"].append({
                    "type": finding.get("type", "interesting_finding"),
                    "url": finding.get("url", ""),
                    "severity": "LOW",
                    "cve_id": "",
                    "source": "wpscan_local",
                    "evidence": [finding.get("to_s", "")],
                })

        return result

    def _scan_wordpress_site(self, url: str) -> Dict[str, Any]:
        """Scan a WordPress site using wp_advanced_scan as PRIMARY, WPScan as enrichment only.
        
        OPTIMIZATION: Cache scan results by domain + WP version + plugin versions.
        If cache hit, return cached result immediately (skip all scanning).
        """
        site_info = {
            "url": url,
            "version": None,
            "plugins": [],
            "themes": [],
            "users": [],
            "vulnerabilities": [],
            "core_vulnerabilities": [],
            "source": "wp_advanced_scan"
        }

        # ✅ STEP 0: CHECK CACHE (OPTIMIZATION)
        # First, do a quick version + plugin detection to build cache key
        quick_version = self._detect_version(url)
        quick_plugins = self._enumerate_plugins(url)
        cached = self._get_cached_result(url, quick_version, quick_plugins)
        if cached:
            logger.info(f"[WP] Using cached scan result for {url}")
            return cached

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
        wpscan_data = self._run_wpscan(url)
        if wpscan_data:
            logger.info(f"[WP] WPScan enrichment succeeded")
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

        # ✅ STEP 6: Enrich detected components with CVEs
        self._enrich_site_info_with_cves(site_info)
        site_info["conditioned_findings"] = self._build_conditioned_findings(site_info)

        # ✅ STEP 7: CACHE RESULT (OPTIMIZATION)
        self._cache_result(url, site_info["version"] or "unknown", site_info["plugins"], site_info)

        return site_info

    def _enrich_site_info_with_cves(self, site_info: Dict[str, Any]):
        """Enrich plugins/themes with CVEs from searchsploit local DB.

        Only queries plugins that have NO CVEs from wpscan yet (avoids duplicates).
        searchsploit is purely local — no API, no rate limiting.
        """
        try:
            from integrations.searchsploit_runner import get_runner
        except ImportError:
            return
        runner = get_runner()
        if not runner.available():
            return

        for plugin in (site_info.get("plugins") or []):
            if not isinstance(plugin, dict):
                continue
            # Skip if wpscan already found CVEs for this plugin
            if plugin.get("vulnerabilities"):
                continue
            name = plugin.get("name", "")
            version = plugin.get("version", "")
            if not name:
                continue
            results = runner.query(f"wordpress {name}", version)
            if results:
                plugin["vulnerabilities"] = results
                logger.info(
                    "[WP] searchsploit enriched plugin '%s' with %d CVE entries",
                    name, len(results),
                )

        for theme in (site_info.get("themes") or []):
            if not isinstance(theme, dict) or theme.get("vulnerabilities"):
                continue
            name = theme.get("name", "")
            version = theme.get("version", "")
            if not name:
                continue
            results = runner.query(f"wordpress theme {name}", version)
            if results:
                theme["vulnerabilities"] = results

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
