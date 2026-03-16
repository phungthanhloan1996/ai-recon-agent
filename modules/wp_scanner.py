"""
modules/wp_scanner.py - WordPress Scanner Engine
Scans WordPress installations using rules and HTTP probing
"""

import json
import os
import re
import time
import logging
from typing import Dict, List, Any, Optional

from core.state_manager import StateManager
from core.http_engine import HTTPClient

logger = logging.getLogger("recon.wordpress")


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

        for target in targets:
            if self._is_wordpress_site(target):
                logger.info(f"[WP] WordPress detected at {target}")
                scan_result = self._scan_wordpress_site(target)
                results[target] = scan_result
            else:
                logger.debug(f"[WP] Not WordPress: {target}")

        # Save results
        self._save_results(results)

        # Update state
        self._update_state(results)

        logger.info(f"[WP] Scanned {len(results)} WordPress sites")
        return results

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
    def __init__(self, state: StateManager, output_dir: str,
                 wpscan_token: str = "", nvd_key: str = ""):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.wpscan_token = wpscan_token or os.environ.get("WPSCAN_API_TOKEN", "")
        self.nvd_key = nvd_key or os.environ.get("NVD_API_KEY", "")
        self._nvd_cache: Dict[str, Dict] = {}
        self._nvd_last_call = 0.0

        if self.wpscan_token:
            logger.info("[WP] WPScan API token loaded ✓")
        else:
            logger.warning("[WP] No WPScan API token — vuln detection limited")

        if self.nvd_key:
            logger.info("[WP] NVD API key loaded ✓")
        else:
            logger.warning("[WP] No NVD API key — rate limited to 10 req/min")

    def run(self) -> Optional[Dict]:
        logger.info(f"\n{'='*60}")
        logger.info(f"  PHASE 6: WORDPRESS DEEP SCAN")
        logger.info(f"{'='*60}")

        self.state.set_phase("wp_scan")
        wp_detected = self.state.get("wordpress_detected", False)

        if not wp_detected:
            wp_detected = self._manual_wp_detect()
            if not wp_detected:
                logger.info("[WP] WordPress not detected - skipping WP scan")
                return None

        logger.info("[WP] WordPress confirmed - running deep scan")

        wp_hosts = self._find_wp_hosts()
        if not wp_hosts:
            logger.warning("[WP] No WP hosts found")
            return None

        all_results = {}
        for host_url in wp_hosts:
            result = self._scan_host(host_url)
            if result:
                result = self._enrich_with_nvd(result)
                all_results[host_url] = result

        self._aggregate_results(all_results)
        return all_results

    # ─── WPScan ──────────────────────────────────────────────────────────────

    def _scan_host(self, url: str) -> Optional[Dict]:
        logger.info(f"[WP] Scanning: {url}")
        output_file = os.path.join(
            self.output_dir,
            f"wpscan_{url.replace('://', '_').replace('/', '_')}.json"
        )

        if not tool_available("wpscan"):
            logger.warning("[WP] wpscan not installed - running manual checks")
            return self._manual_wp_checks(url)

        cmd = [
            "wpscan",
            "--url", url,
            "--enumerate", "p,t,u,tt,cb,dbe",
            "--plugins-detection", "aggressive",
            "--format", "json",
            "--output", output_file,
            "--disable-tls-checks",
            "--random-user-agent",
            "--no-banner",
        ]

        if self.wpscan_token:
            cmd += ["--api-token", self.wpscan_token]
            logger.info("[WP] Running with API token — full vuln DB enabled")

        _, stdout, stderr = run_command(cmd, timeout=600)

        if not os.path.exists(output_file):
            logger.warning("[WP] wpscan output file not found, parsing stdout")
            return self._parse_wpscan_text(stdout)

        try:
            with open(output_file) as f:
                data = json.load(f)
            return self._parse_wpscan_json(data, url)
        except Exception as e:
            logger.error(f"[WP] Failed to parse wpscan JSON: {e}")
            return self._parse_wpscan_text(stdout)

    def _parse_wpscan_json(self, data: Dict, url: str) -> Dict:
        result = {
            "url": url,
            "version": data.get("version", {}).get("number", "unknown"),
            "version_status": data.get("version", {}).get("status", ""),
            "plugins": [],
            "themes": [],
            "users": [],
            "vulnerabilities": [],
            "interesting_findings": [],
            "nvd_enriched": [],
        }

        # Plugins
        for plugin_name, plugin_data in data.get("plugins", {}).items():
            plugin = {
                "name": plugin_name,
                "version": plugin_data.get("version", {}).get("number", "unknown"),
                "vulnerabilities": [],
            }
            for vuln in plugin_data.get("vulnerabilities", []):
                cves = vuln.get("references", {}).get("cve", [])
                plugin["vulnerabilities"].append({
                    "title": vuln.get("title", ""),
                    "type": vuln.get("vuln_type", ""),
                    "cve": cves,
                    "fixed_in": vuln.get("fixed_in", ""),
                    "cvss": None,
                    "nvd_description": "",
                })
                result["vulnerabilities"].append({
                    "tool": "wpscan",
                    "name": vuln.get("title", ""),
                    "type": vuln.get("vuln_type", ""),
                    "severity": "HIGH",
                    "url": url,
                    "plugin": plugin_name,
                    "cve": cves,
                    "fixed_in": vuln.get("fixed_in", ""),
                })
                if cves:
                    logger.warning(
                        f"[WP] Plugin vuln: {plugin_name} — "
                        f"{vuln.get('title','')[:60]} [{', '.join(cves)}]"
                    )
            result["plugins"].append(plugin)
            logger.info(f"[WP] Plugin: {plugin_name} v{plugin['version']} (vulns: {len(plugin['vulnerabilities'])})")

        # Themes
        for theme_name, theme_data in data.get("themes", {}).items():
            theme_vulns = theme_data.get("vulnerabilities", [])
            result["themes"].append({
                "name": theme_name,
                "version": theme_data.get("version", {}).get("number", "unknown"),
                "vulnerabilities": len(theme_vulns),
            })
            for vuln in theme_vulns:
                cves = vuln.get("references", {}).get("cve", [])
                result["vulnerabilities"].append({
                    "tool": "wpscan",
                    "name": vuln.get("title", ""),
                    "type": vuln.get("vuln_type", ""),
                    "severity": "MEDIUM",
                    "url": url,
                    "theme": theme_name,
                    "cve": cves,
                })

        # Users
        for user_login in data.get("users", {}):
            result["users"].append(user_login)
            logger.warning(f"[WP] User found: {user_login}")

        # Interesting findings
        for finding in data.get("interesting_findings", []):
            result["interesting_findings"].append({
                "url": finding.get("url", ""),
                "type": finding.get("type", ""),
                "info": finding.get("to_s", ""),
            })

        return result

    def _parse_wpscan_text(self, text: str) -> Dict:
        result = {
            "plugins": [], "themes": [], "users": [],
            "vulnerabilities": [], "interesting_findings": [], "nvd_enriched": [],
        }
        for line in text.splitlines():
            if "| Found By:" in line or "Author:" in line:
                m = re.search(r"\| (\w+) \|", line)
                if m:
                    result["users"].append(m.group(1))
            if "[+] Name:" in line or "Plugin:" in line:
                m = re.search(r"Name: (\S+)", line)
                if m:
                    result["plugins"].append({"name": m.group(1), "version": "?", "vulnerabilities": []})
            if "vulnerability" in line.lower() or "CVE" in line:
                cves = re.findall(r"CVE-\d{4}-\d+", line)
                result["vulnerabilities"].append({
                    "tool": "wpscan",
                    "name": line.strip()[:100],
                    "severity": "MEDIUM",
                    "url": "",
                    "cve": cves,
                })
        return result

    # ─── NVD Enrichment ──────────────────────────────────────────────────────

    def _enrich_with_nvd(self, result: Dict) -> Dict:
        all_cves = set()
        for vuln in result.get("vulnerabilities", []):
            for cve in vuln.get("cve", []):
                if cve:
                    all_cves.add(cve.upper())

        if not all_cves:
            return result

        logger.info(f"[NVD] Enriching {len(all_cves)} CVEs...")
        nvd_data = {}

        for cve_id in sorted(all_cves):
            data = self._nvd_lookup(cve_id)
            if data:
                nvd_data[cve_id] = data
                logger.info(
                    f"[NVD] {cve_id} → CVSS:{data.get('cvss','N/A')} "
                    f"[{data.get('severity','?')}] {data.get('description','')[:60]}"
                )

        # Merge vào vulnerabilities
        for vuln in result["vulnerabilities"]:
            for cve in vuln.get("cve", []):
                if cve.upper() in nvd_data:
                    nd = nvd_data[cve.upper()]
                    vuln["cvss"] = nd.get("cvss")
                    vuln["nvd_severity"] = nd.get("severity")
                    vuln["nvd_description"] = nd.get("description", "")
                    vuln["nvd_published"] = nd.get("published", "")
                    if nd.get("severity") == "CRITICAL":
                        vuln["severity"] = "CRITICAL"

        # Merge vào plugin entries
        for plugin in result.get("plugins", []):
            for pv in plugin.get("vulnerabilities", []):
                for cve in pv.get("cve", []):
                    if cve.upper() in nvd_data:
                        nd = nvd_data[cve.upper()]
                        pv["cvss"] = nd.get("cvss")
                        pv["nvd_description"] = nd.get("description", "")

        result["nvd_enriched"] = list(nvd_data.values())
        logger.info(f"[NVD] Done: {len(nvd_data)}/{len(all_cves)} CVEs resolved")
        return result

    def _nvd_lookup(self, cve_id: str) -> Optional[Dict]:
        if cve_id in self._nvd_cache:
            return self._nvd_cache[cve_id]

        delay = NVD_RATE_LIMIT_DELAY if self.nvd_key else NVD_RATE_LIMIT_NO_KEY
        elapsed = time.time() - self._nvd_last_call
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._nvd_last_call = time.time()

        try:
            params = urllib.parse.urlencode({"cveId": cve_id})
            url = f"{NVD_API_BASE}?{params}"
            headers = {"Accept": "application/json"}
            if self.nvd_key:
                headers["apiKey"] = self.nvd_key

            req = urllib.request.Request(url, headers=headers)
            resp = urllib.request.urlopen(req, timeout=15)
            raw = json.loads(resp.read().decode())

            vulns = raw.get("vulnerabilities", [])
            if not vulns:
                return None

            cve_data = vulns[0].get("cve", {})

            # Description tiếng Anh
            descriptions = cve_data.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )

            # CVSS: thử v3.1 → v3.0 → v2.0
            metrics = cve_data.get("metrics", {})
            cvss_score = None
            severity = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = metrics.get(key, [])
                if entries:
                    cvss_data = entries[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity") or entries[0].get("baseSeverity")
                    break

            result = {
                "cve_id": cve_id,
                "cvss": cvss_score,
                "severity": severity,
                "description": description,
                "published": cve_data.get("published", ""),
                "lastModified": cve_data.get("lastModified", ""),
                "references": [r.get("url", "") for r in cve_data.get("references", [])[:5]],
            }
            self._nvd_cache[cve_id] = result
            return result

        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("[NVD] 429 Rate limited — sleeping 30s")
                time.sleep(30)
            elif e.code == 403:
                logger.warning("[NVD] 403 Forbidden — check NVD API key")
            else:
                logger.debug(f"[NVD] HTTP {e.code} for {cve_id}")
            return None
        except Exception as e:
            logger.debug(f"[NVD] Lookup failed {cve_id}: {e}")
            return None

    # ─── Manual / Fallback ───────────────────────────────────────────────────

    def _manual_wp_detect(self) -> bool:
        live_hosts = self.state.get("live_hosts", [])
        for host in live_hosts[:5]:
            url = host.get("url", "")
            if not url:
                continue
            try:
                req = urllib.request.Request(
                    url.rstrip("/") + "/wp-login.php",
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                resp = urllib.request.urlopen(req, timeout=8)
                content = resp.read(3000).decode("utf-8", errors="ignore")
                if "wordpress" in content.lower() or "wp-login" in content.lower():
                    logger.info(f"[WP] WordPress detected at {url}")
                    self.state.update(wordpress_detected=True)
                    return True
            except Exception:
                pass
        return False

    def _find_wp_hosts(self) -> List[str]:
        live_hosts = self.state.get("live_hosts", [])
        wp_hosts = []
        for host in live_hosts:
            tech_str = " ".join(host.get("tech", [])).lower()
            if "wordpress" in tech_str or "woocommerce" in tech_str:
                wp_hosts.append(host.get("url", ""))
        if not wp_hosts and live_hosts:
            wp_hosts = [h["url"] for h in live_hosts[:3]]
        return [u for u in wp_hosts if u]

    def _manual_wp_checks(self, url: str) -> Dict:
        result = {
            "url": url,
            "plugins": [], "themes": [], "users": [],
            "vulnerabilities": [], "interesting_findings": [], "nvd_enriched": [],
        }
        checks = [
            ("/xmlrpc.php", "xmlrpc_exposed"),
            ("/wp-json/wp/v2/users", "user_enumeration"),
            ("/wp-config.php.bak", "config_backup"),
            ("/.htaccess", "htaccess_exposed"),
            ("/readme.html", "readme_exposed"),
            ("/license.txt", "license_exposed"),
            ("/wp-cron.php", "wpcron_exposed"),
            ("/wp-content/debug.log", "debug_log_exposed"),
            ("/.git/HEAD", "git_exposed"),
        ]
        for path, check_type in checks:
            try:
                req = urllib.request.Request(
                    url.rstrip("/") + path,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                resp = urllib.request.urlopen(req, timeout=8)
                status = resp.getcode()
                content = resp.read(5000).decode("utf-8", errors="ignore")
                if status == 200:
                    logger.warning(f"[WP] {check_type}: {url.rstrip('/')}{path}")
                    result["interesting_findings"].append({
                        "url": url.rstrip("/") + path,
                        "type": check_type,
                        "info": f"HTTP {status}",
                    })
                    if "users" in path:
                        try:
                            for user in json.loads(content):
                                u = user.get("slug") or user.get("name", "")
                                if u:
                                    result["users"].append(u)
                                    logger.warning(f"[WP] User: {u}")
                        except Exception:
                            pass
            except Exception:
                pass
        return result

    # ─── Aggregate ───────────────────────────────────────────────────────────

    def _aggregate_results(self, all_results: Dict):
        all_plugins, all_themes, all_users, all_vulns = [], [], [], []
        for result in all_results.values():
            all_plugins.extend(result.get("plugins", []))
            all_themes.extend(result.get("themes", []))
            all_users.extend(result.get("users", []))
            all_vulns.extend(result.get("vulnerabilities", []))

        all_users = list(set(all_users))
        self.state.update(
            wp_plugins=all_plugins,
            wp_themes=all_themes,
            wp_users=all_users,
            wp_vulns=all_vulns,
        )

        critical = [v for v in all_vulns if v.get("severity") == "CRITICAL"]
        if critical:
            logger.warning(f"[WP] {len(critical)} CRITICAL vulns found!")

        logger.info(
            f"[WP] Summary: {len(all_plugins)} plugins, {len(all_themes)} themes, "
            f"{len(all_users)} users, {len(all_vulns)} vulns ({len(critical)} CRITICAL)"
        )
        for vuln in all_vulns:
            self.state.add_vulnerability(vuln)