"""
WordPress Advanced Scan Integration
- Pure HTTP-based WordPress detection and enumeration
- No external dependencies beyond stdlib + requests
- Extracts ONLY data collection, NO reporting
- Returns structured findings for pipeline merge
"""

import sys
import os
import json
import time
import re
import logging
from urllib.parse import urljoin, quote
import requests
from typing import Dict, List, Optional, Any

logger = logging.getLogger("recon.wp_scan")


class WordPressAdvancedScan:
    """
    Data-only scanner for WordPress installations.
    Uses pure HTTP requests to detect version, plugins, themes, and enumerate users.
    Zero external tool dependencies - just requests library.
    """
    
    def __init__(self, target_url: str, timeout_per_check: int = 10):
        """
        Initialize advanced scan for a WordPress target
        
        Args:
            target_url: Target domain/URL
            timeout_per_check: Timeout for individual HTTP requests
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout_per_check
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.data = {
            "target": target_url,
            "timestamp": time.time(),
            "version_detection": {},
            "php_analysis": {},
            "wordpress_api": {},
            "plugin_versions": {},
            "server_behaviors": {},
            "vulnerabilities": [],
            "observations": {
                "posture_indicators": [],
                "behavioral_patterns": [],
                "reality_context": []
            }
        }
    
    def run_data_collection(self) -> dict:
        """
        Run all data collection using pure HTTP requests.
        NO external tools, NO external libraries beyond requests.
        Returns structured findings for integration into main pipeline
        """
        logger.debug(f"[WP_SCAN] Starting HTTP-based WordPress detection for {self.target_url}")
        
        try:
            # Detect WordPress version
            self._detect_wordpress_version()
            
            # Detect PHP version
            self._detect_php_version()
            
            # Enumerate plugins and themes
            self._enumerate_plugins()
            self._enumerate_themes()
            
            # Check REST API
            self._check_rest_api()
            
            # Check for common vulnerabilities
            self._check_vulnerabilities()
            
            logger.debug(f"[WP_SCAN] Detection complete. Found {len(self.data.get('vulnerabilities', []))} issues")
            
        except Exception as e:
            logger.debug(f"[WP_SCAN] Error during collection: {e}")
        
        return self.data
    
    def _detect_wordpress_version(self):
        """Detect WordPress version from meta tags, readme.html, etc."""
        version = None
        methods = []
        
        try:
            # Method 1: Check meta generator tag
            response = self._make_request(self.target_url)
            if response:
                content = response.text
                
                # Pattern: <meta name="generator" content="WordPress X.X.X" />
                match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)', content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    methods.append("meta_generator")
                
                # Pattern: ?ver=X.X.X in script/link src attributes
                if not version:
                    ver_match = re.search(r'\?ver=([\d.]+)["\']', content)
                    if ver_match:
                        version = ver_match.group(1)
                        methods.append("url_param")
        except:
            pass
        
        # Method 2: Check readme.html
        try:
            response = self._make_request(f"{self.target_url}/readme.html")
            if response and response.status_code == 200:
                match = re.search(r'WordPress\s+([\d.]+)', response.text)
                if match:
                    version = match.group(1)
                    methods.append("readme_html")
        except:
            pass
        
        if version:
            self.data["version_detection"] = {
                "wp_version": version,
                "confidence": "high" if len(methods) > 1 else "medium",
                "methods": methods,
                "eol": self._check_eol_version(version)
            }
            logger.info(f"[WP_SCAN] Detected WordPress {version}")
    
    def _detect_php_version(self):
        """Detect PHP version from response headers and errors"""
        php_version = None
        try:
            response = self._make_request(self.target_url)
            if response:
                # Check X-Powered-By header
                powered_by = response.headers.get('X-Powered-By', '')
                match = re.search(r'PHP/([\d.]+)', powered_by)
                if match:
                    php_version = match.group(1)
                
                # Check Server header
                if not php_version:
                    server = response.headers.get('Server', '')
                    match = re.search(r'PHP/([\d.]+)', server)
                    if match:
                        php_version = match.group(1)
        except:
            pass
        
        if php_version:
            self.data["php_analysis"] = {
                "php_version": php_version,
                "php_versions_found": [php_version],
                "consistent_across_endpoints": True,
                "outdated": self._check_outdated_php(php_version)
            }
    
    def _enumerate_plugins(self):
        """Enumerate plugins from HTML sources and common paths"""
        plugins_found = {}
        
        try:
            # Check wp-content/plugins directory listing
            response = self._make_request(f"{self.target_url}/wp-content/plugins/")
            if response and response.status_code == 200:
                # Look for plugin folders in HTML
                matches = re.findall(r'href=["\']([a-z0-9\-]+)/?["\']', response.text, re.IGNORECASE)
                for plugin_name in matches:
                    if plugin_name not in ('..', '.', 'index.php'):
                        plugins_found[plugin_name] = {"version": "unknown", "detected": True}
        except:
            pass
        
        # Common plugins to check
        common_plugins = [
            'akismet', 'hello-dolly', 'woocommerce', 'contact-form-7',
            'wordpress-seo', 'wp-super-cache', 'jetpack', 'elementor',
            'yoast-seo', 'all-in-one-seo-pack', 'wordfence', 'gravityforms'
        ]
        
        for plugin in common_plugins:
            try:
                # Try to fetch plugin readme.txt for version
                response = self._make_request(f"{self.target_url}/wp-content/plugins/{plugin}/readme.txt")
                if response and response.status_code == 200:
                    match = re.search(r'Stable tag:\s*([\d.]+)', response.text)
                    version = match.group(1) if match else "unknown"
                    plugins_found[plugin] = {"version": version, "detected": True}
            except:
                pass
        
        if plugins_found:
            self.data["plugin_versions"] = plugins_found
    
    def _enumerate_themes(self):
        """Enumerate themes from HTML and common paths"""
        themes_found = {}
        
        try:
            response = self._make_request(self.target_url)
            if response:
                # Look for theme stylesheet references
                matches = re.findall(r'/wp-content/themes/([a-z0-9\-]+)/', response.text, re.IGNORECASE)
                for theme_name in set(matches):
                    themes_found[theme_name] = {"version": "unknown", "detected": True}
        except:
            pass
        
        # Common themes to check
        common_themes = [
            'twentytwentyone', 'twentytwenty', 'twentynineteen',
            'astra', 'generatepress', 'oceanwp', 'divi', 'avada'
        ]
        
        for theme in common_themes:
            try:
                response = self._make_request(f"{self.target_url}/wp-content/themes/{theme}/style.css")
                if response and response.status_code == 200:
                    match = re.search(r'Version:\s*([\d.]+)', response.text)
                    version = match.group(1) if match else "unknown"
                    themes_found[theme] = {"version": version, "detected": True}
            except:
                pass
        
        if themes_found:
            self.data["theme_versions"] = themes_found
    
    def _check_rest_api(self):
        """Check if WordPress REST API is accessible and enumerate users"""
        urls_to_try = [
            f"{self.target_url}/wp-json/wp/v2/users",
            f"{self.target_url}/index.php?rest_route=/wp/v2/users"
        ]
        for api_url in urls_to_try:
            try:
                response = self._make_request(api_url)
                if response and response.status_code == 200:
                    try:
                        users_data = response.json()
                        if isinstance(users_data, list) and users_data:
                            users = [u.get('slug') or u.get('name', 'unknown') for u in users_data if isinstance(u, dict)]
                            self.data["wordpress_api"] = {
                                "rest_api_enabled": True,
                                "user_enumeration_possible": True,
                                "users_found": users[:10]
                            }
                            logger.info(f"[WP_SCAN] Found {len(users)} users via REST API")
                            break
                    except:
                        pass
            except:
                pass
    
    def _check_vulnerabilities(self):
        """Check for common WordPress vulnerabilities"""
        vulns = []
        
        # Check xmlrpc.php - allows user enumeration & potential RCE
        try:
            response = self._make_request(f"{self.target_url}/xmlrpc.php")
            if response and response.status_code == 200:
                vulns.append({
                    "type": "XMLRPC_ENABLED",
                    "severity": "MEDIUM",
                    "description": "XML-RPC is enabled - can be used for user enumeration and pingback attacks",
                    "evidence": "/xmlrpc.php is accessible"
                })
        except:
            pass
        
        # Check wp-config.php backup
        try:
            response = self._make_request(f"{self.target_url}/wp-config.php.bak")
            if response and response.status_code == 200:
                vulns.append({
                    "type": "CONFIG_BACKUP_EXPOSED",
                    "severity": "CRITICAL",
                    "description": "WordPress config backup file is exposed",
                    "evidence": "/wp-config.php.bak is accessible"
                })
        except:
            pass
        
        # Check debug.log
        try:
            response = self._make_request(f"{self.target_url}/wp-content/debug.log")
            if response and response.status_code == 200:
                vulns.append({
                    "type": "DEBUG_LOG_EXPOSED",
                    "severity": "HIGH",
                    "description": "Debug log file is publicly accessible",
                    "evidence": "/wp-content/debug.log is readable"
                })
        except:
            pass
        
        if vulns:
            self.data["vulnerabilities"] = vulns
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make HTTP request with timeout and error handling"""
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except:
            return None
    
    def _check_eol_version(self, version: str) -> bool:
        """Check if WordPress version is EOL"""
        try:
            parts = version.split('.')
            major = int(parts[0]) if parts else 0
            # WordPress < 6.0 is EOL
            return major < 6
        except:
            return False
    
    def _check_outdated_php(self, version: str) -> bool:
        """Check if PHP version is outdated"""
        outdated_versions = ['5.', '7.0', '7.1', '7.2', '7.3', '7.4']
        return any(version.startswith(v) for v in outdated_versions)
    
    @staticmethod
    def merge_into_state(state, advanced_scan_data: dict):
        """
        Merge advanced scan findings into agent state
        
        Args:
            state: Current agent state (dict or StateManager)
            advanced_scan_data: Data from advanced scan
            
        Returns:
            Updated state (returns the input state object)
        """
        from core.state_manager import StateManager
        import json
        from dataclasses import asdict
        
        # Handle StateManager objects
        is_state_manager = isinstance(state, StateManager)
        if is_state_manager:
            # Convert StateManager to dict for processing
            state_dict = asdict(state.state) if hasattr(state, 'state') else {}
        else:
            state_dict = state if isinstance(state, dict) else {}
        
        # Ensure required keys exist
        if "technical_details" not in state_dict:
            state_dict["technical_details"] = {}
        
        # Add advanced WordPress scan results
        state_dict["technical_details"]["wordpress_advanced_scan"] = advanced_scan_data
        
        # Update/enrich WordPress findings
        if advanced_scan_data.get("version_detection"):
            state_dict["cms_version"] = f"WordPress {advanced_scan_data['version_detection'].get('wp_version')}"
            state_dict["wordpress_eol"] = advanced_scan_data["version_detection"].get("eol", False)
        
        if advanced_scan_data.get("php_analysis"):
            state_dict["server_php_version"] = advanced_scan_data["php_analysis"].get("php_version")
            state_dict["php_outdated"] = advanced_scan_data["php_analysis"].get("outdated", False)
        
        if advanced_scan_data.get("wordpress_api"):
            state_dict["wordpress_rest_api_enabled"] = advanced_scan_data["wordpress_api"].get("rest_api_enabled", False)
            state_dict["user_enumeration_via_api"] = advanced_scan_data["wordpress_api"].get("user_enumeration_possible", False)
            if advanced_scan_data["wordpress_api"].get("users_found"):
                state_dict["wp_users"] = advanced_scan_data["wordpress_api"]["users_found"]

        if advanced_scan_data.get("plugin_versions"):
            if "plugins" not in state_dict:
                state_dict["plugins"] = []
            # Merge plugins, avoiding duplicates - DEFENSIVE check for dict types
            existing_plugins = {}
            for p in state_dict.get("plugins", []):
                if isinstance(p, dict):
                    name = p.get("name")
                    if name:
                        existing_plugins[name] = p
            
            for plugin in advanced_scan_data["plugin_versions"].get("detected_plugins", []):
                if isinstance(plugin, dict):
                    name = plugin.get("name")
                    if name and name not in existing_plugins:
                        state_dict["plugins"].append(plugin)
        
        # Add vulnerabilities from advanced scan
        if advanced_scan_data.get("vulnerabilities"):
            if "confirmed_vulnerabilities" not in state_dict:
                state_dict["confirmed_vulnerabilities"] = []
            
            for vuln in advanced_scan_data["vulnerabilities"]:
                # Check if already exists
                exists = any(
                    v.get("type") == vuln.get("type")
                    for v in state_dict.get("confirmed_vulnerabilities", [])
                )
                if not exists:
                    state_dict["confirmed_vulnerabilities"].append(vuln)
        
        # Add observations for context
        if advanced_scan_data.get("observations"):
            state_dict["scan_observations"] = advanced_scan_data["observations"]
        
        # If it was a StateManager, update it via the update() method
        if is_state_manager:
            state.update(**state_dict)
        else:
            # Return the dict
            return state_dict
        
        return state


def scan_all_wordpress_targets(targets: list, max_workers: int = 1) -> dict:
    """
    Scan multiple WordPress targets for advanced findings
    
    Args:
        targets: List of target URLs
        max_workers: Parallel workers (recommended: 1 to avoid rate limiting)
        
    Returns:
        Dictionary with results keyed by target
    """
    results = {}
    
    for target in targets:
        try:
            scanner = WordPressAdvancedScan(target)
            data = scanner.run_data_collection()
            results[target] = data
            time.sleep(2)  # Rate limiting between targets
        except Exception as e:
            print(f"[ERROR] Scan failed for {target}: {str(e)[:80]}")
            results[target] = {"error": str(e)[:100]}
    
    return results
