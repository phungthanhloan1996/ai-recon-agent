"""
modules/live_hosts.py - Live Host Detection Engine
Detects live hosts using HTTP probing with technology detection
Includes intelligent host filtering (dedup, sub-path, dev/test detection)
"""

import json
import os
import logging
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.state_manager import StateManager
from core.http_engine import HTTPClient
from core.host_filter import HostFilter

logger = logging.getLogger("recon.live_hosts")


class LiveHostEngine:
    """
    Engine for detecting live hosts and their technologies.
    Uses HTTP probing instead of external tools.
    """

    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.http_client = HTTPClient()
        self.live_file = os.path.join(output_dir, "live_hosts.txt")
        self.results_file = os.path.join(output_dir, "live_hosts.json")
        self.budget = (self.state.get("scan_metadata", {}) or {}).get("budget", {})

        # Common ports to probe
        self.ports = [80, 443, 8080, 8443, 8888, 3000, 5000, 4443, 9000]

        # Technology detection patterns
        self.tech_patterns = {
            "wordpress": ["wp-content", "wp-includes", "wordpress"],
            "apache": ["apache"],
            "nginx": ["nginx"],
            "iis": ["microsoft-iis"],
            "php": ["php"],
            "nodejs": ["node", "express"],
            "django": ["django"],
            "laravel": ["laravel"],
            "react": ["react"],
            "vue": ["vue"],
            "angular": ["angular"],
            "jquery": ["jquery"],
            "bootstrap": ["bootstrap"]
        }

    def detect_live_hosts(self, targets: List[str], skip_dev_test: bool = True) -> List[Dict[str, Any]]:
        """
        Detect live hosts from target list with intelligent filtering.
        
        Args:
            targets: List of target URLs/domains
            skip_dev_test: If True, filter out dev/test environments
        
        Returns:
            Filtered list of live hosts (production only if skip_dev_test=True)
        """
        logger.info(f"[LIVE] Probing {len(targets)} targets...")
        
        live_hosts = []
        primary_limit = int(self.budget.get("live_primary_targets", 220))
        secondary_limit = int(self.budget.get("live_secondary_targets", 90))
        secondary_ports = self.ports[2: 2 + int(self.budget.get("live_ports_secondary", 4))]
        timeout = int(self.budget.get("live_timeout", 6))
        
        primary_targets = targets[:primary_limit]
        if not primary_targets:
            self._save_results([])
            return []
        
        # 🔥 FIX: Chuẩn hóa URL trước khi probe
        normalized_targets = []
        for target in primary_targets:
            if target.startswith(('http://', 'https://')):
                # Đã có scheme
                normalized_targets.append(target)
            else:
                # Thêm cả http và https
                normalized_targets.append(f"http://{target}")
                normalized_targets.append(f"https://{target}")
        
        # Queue 1: fast primary probing
        primary_candidates = []
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = []
            for target in normalized_targets:
                futures.append(executor.submit(self.probe_host, target, timeout))
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        live_hosts.append(result)
                        host = result["url"].split("://", 1)[-1].split(":", 1)[0].split("/", 1)[0]
                        primary_candidates.append(host)
                except Exception as e:
                    logger.debug(f"[LIVE] Probe error: {e}")
    


        # Queue 2: deeper port probing only on hosts that were alive in queue 1.
        secondary_hosts = list(dict.fromkeys(primary_candidates))[:secondary_limit]
        if secondary_hosts and secondary_ports:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = []
                for host in secondary_hosts:
                    for port in secondary_ports:
                        futures.append(executor.submit(self.probe_host, f"http://{host}:{port}", timeout))
                        futures.append(executor.submit(self.probe_host, f"https://{host}:{port}", timeout))
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            live_hosts.append(result)
                    except Exception as e:
                        logger.debug(f"[LIVE] Secondary probe error: {e}")

        # Remove duplicates and sort
        unique_hosts = self._deduplicate_hosts(live_hosts)
        
        # 🔥 NEW: Apply intelligent host filtering (dedup, sub-paths, dev/test)
        if skip_dev_test:
            host_filter = HostFilter(skip_dev_test=True)
            filtered_hosts = host_filter.filter_hosts(unique_hosts)
            
            stats = host_filter.get_stats()
            logger.info(f"[LIVE] Host filter applied: {stats['total']} → {stats['passed']} "
                       f"(duplicates: {stats['duplicates']}, sub_paths: {stats['sub_paths']}, "
                       f"dev/test: {stats['dev_test']})")
            
            unique_hosts = filtered_hosts

        # Save results
        self._save_results(unique_hosts)

        logger.info(f"[LIVE] Found {len(unique_hosts)} live hosts")
        return unique_hosts

    def probe_host(self, url: str, timeout: int = 10) -> Dict[str, Any]:
        """Probe a single host URL"""
        try:
            response = self.http_client.get(url, timeout=timeout, allow_redirects=True)

            if response.status_code < 400:  # Consider 2xx, 3xx as live
                host_info = {
                    "url": url,
                    "status": response.status_code,
                    "status_code": response.status_code,
                    "title": self._extract_title(response.text),
                    "tech": self._detect_technologies(response),
                    "content_length": len(response.text),
                    "headers": dict(response.headers),
                    "server": response.headers.get("server", ""),
                    "ip": "",  # Would need DNS resolution
                }

                logger.debug(f"[LIVE] ✓ {url} [{response.status_code}] '{host_info['title'][:30]}'")
                return host_info

        except Exception as e:
            logger.debug(f"[LIVE] ✗ {url} - {str(e)[:50]}")

        return None

    def _extract_title(self, html: str) -> str:
        """Extract page title from HTML"""
        try:
            import re
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                return title_match.group(1).strip()
        except Exception:
            pass
        return ""

    def _detect_technologies(self, response) -> List[str]:
        """Detect technologies from response"""
        detected = []

        # Check headers
        server = response.headers.get("server", "").lower()
        for tech, patterns in self.tech_patterns.items():
            if any(pattern in server for pattern in patterns):
                if tech not in detected:
                    detected.append(tech)

        # Check response content
        content_lower = response.text.lower()
        for tech, patterns in self.tech_patterns.items():
            if any(pattern in content_lower for pattern in patterns):
                if tech not in detected:
                    detected.append(tech)

        # Check for common CMS/framework indicators
        if "wp-content" in content_lower or "wp-includes" in content_lower:
            if "wordpress" not in detected:
                detected.append("wordpress")

        if "drupal" in content_lower:
            if "drupal" not in detected:
                detected.append("drupal")

        if "joomla" in content_lower:
            if "joomla" not in detected:
                detected.append("joomla")

        return detected

    def _deduplicate_hosts(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate hosts, preferring HTTPS over HTTP"""
        seen = {}
        https_hosts = {}

        for host in hosts:
            url = host["url"]
            domain_port = url.split("//")[-1].split("/")[0]  # domain:port

            # Prefer HTTPS
            if "https://" in url:
                https_hosts[domain_port] = host
            elif domain_port not in https_hosts:
                seen[domain_port] = host

        # Combine, preferring HTTPS
        unique = list(https_hosts.values()) + [h for h in seen.values() if h["url"].split("//")[-1].split("/")[0] not in https_hosts]

        return unique

    def _save_results(self, hosts: List[Dict[str, Any]]):
        """Save live hosts to files"""
        # Save JSON
        with open(self.results_file, "w") as f:
            json.dump(hosts, f, indent=2)

        # Save text file
        with open(self.live_file, "w") as f:
            for host in hosts:
                status = host.get("status_code", host.get("status", ""))
                line = f"{host['url']} [{status}] {host['title']}"
                f.write(line + "\n")

        logger.info(f"[LIVE] Saved {len(hosts)} live hosts → {self.live_file}")

        # Update state
        for host in hosts:
            self.state.add_live_host(host)

            # Update technologies in state
            if host.get("tech"):
                domain = host["url"].split("//")[-1].split("/")[0]
                existing = self.state.get("technologies", {})
                existing[domain] = host["tech"]
                self.state.update(technologies=existing)

        # Detect WordPress
        self._detect_wordpress(hosts)

    def _detect_wordpress(self, hosts: List[Dict[str, Any]]):
        """Check if any host is WordPress"""
        for host in hosts:
            tech = host.get("tech", [])
            title = host.get("title", "").lower()

            if "wordpress" in tech or any("wp-" in t.lower() for t in tech) or "wordpress" in title:
                logger.info(f"[LIVE] 🎯 WordPress detected on {host['url']}")
                self.state.update(wordpress_detected=True)
                break
