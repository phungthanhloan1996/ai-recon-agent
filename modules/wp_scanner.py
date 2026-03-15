"""
modules/wp_scanner.py - Phase 6: WordPress Deep Scan
Tool: wpscan + WPScan API token + NVD API enrichment
"""

import json
import os
import re
import time
import logging
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional

from core.executor import run_command, tool_available
from core.state_manager import StateManager

logger = logging.getLogger("recon.phase6")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT_DELAY = 0.6   # 5 req/s với key
NVD_RATE_LIMIT_NO_KEY = 6.0  # 10 req/min không key


class WPScannerModule:
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