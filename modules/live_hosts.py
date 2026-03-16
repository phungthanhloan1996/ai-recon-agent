"""
modules/live_hosts.py - Live Host Detection Engine
Detects live hosts using HTTP probing with technology detection
"""

import json
import os
import logging
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.state_manager import StateManager
from core.http_engine import HTTPClient

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

    def detect_live_hosts(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Detect live hosts from target list"""
        logger.info(f"[LIVE] Probing {len(targets)} targets...")

        live_hosts = []

        # Use thread pool for concurrent probing
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []

            for target in targets:
                # Probe both HTTP and HTTPS for each target
                for port in [80, 443]:
                    protocol = "https" if port == 443 else "http"
                    url = f"{protocol}://{target}"

                    futures.append(executor.submit(self.probe_host, url))

                # Also probe alternative ports
                for port in self.ports[2:]:  # Skip 80, 443 already done
                    for protocol in ["http", "https"]:
                        url = f"{protocol}://{target}:{port}"
                        futures.append(executor.submit(self.probe_host, url))

            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        live_hosts.append(result)
                except Exception as e:
                    logger.debug(f"[LIVE] Probe error: {e}")

        # Remove duplicates and sort
        unique_hosts = self._deduplicate_hosts(live_hosts)

        # Save results
        self._save_results(unique_hosts)

        logger.info(f"[LIVE] Found {len(unique_hosts)} live hosts")
        return unique_hosts

    def probe_host(self, url: str) -> Dict[str, Any]:
        """Probe a single host URL"""
        try:
            response = self.http_client.get(url, timeout=10, allow_redirects=True)

            if response.status_code < 400:  # Consider 2xx, 3xx as live
                host_info = {
                    "url": url,
                    "status": response.status_code,
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
        except:
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
                line = f"{host['url']} [{host['status']}] {host['title']}"
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
    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.live_file = os.path.join(output_dir, "live_hosts.txt")

    def run(self) -> List[Dict]:
        logger.info(f"\n{'='*60}")
        logger.info(f"  PHASE 2: LIVE HOST DETECTION")
        logger.info(f"{'='*60}")

        self.state.set_phase("live_hosts")
        subdomains = self.state.get("subdomains", [])

        if not subdomains:
            logger.warning("[LIVE] No subdomains to probe, using target directly")
            subdomains = [self.target]

        logger.info(f"[LIVE] Probing {len(subdomains)} hosts...")

        if not tool_available("httpx"):
            logger.error("[LIVE] httpx not found! Cannot detect live hosts.")
            # Fallback: just mark target as alive
            fallback = [{"url": f"https://{self.target}", "status": 200, "title": "", "tech": []}]
            self.state.update(live_hosts=fallback)
            return fallback

        live_hosts = self._run_httpx(subdomains)
        self._save_live_hosts(live_hosts)

        # Update state
        for host in live_hosts:
            self.state.add_live_host(host)
            if host.get("tech"):
                domain = host["url"].split("//")[-1].split("/")[0]
                existing = self.state.get("technologies", {})
                existing[domain] = host["tech"]
                self.state.update(technologies=existing)

        # Detect WordPress
        self._detect_wordpress(live_hosts)

        logger.info(f"[LIVE] Found {len(live_hosts)} live hosts")
        return live_hosts

    def _run_httpx(self, subdomains: List[str]) -> List[Dict]:
        """
        Run httpx via stdin pipe — tránh lỗi -l không được support
        trên một số version của ProjectDiscovery httpx.
        stdin_data = newline-joined domain list
        """
        stdin_data = "\n".join(subdomains)

        # Lưu input ra file để debug
        input_file = os.path.join(self.output_dir, "hosts_input.txt")
        with open(input_file, "w") as f:
            f.write(stdin_data)

        cmd = [
            "httpx",
            "-ports", PORTS,
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-json",
            "-silent",
            "-timeout", "10",
            "-threads", "50",
            "-follow-redirects",
        ]

        _, stdout, stderr = run_command(
            cmd,
            timeout=300,
            stdin_data=stdin_data,
        )

        # Nếu stderr có lỗi option không nhận → thử fallback flags
        if stderr and ("no such option" in stderr.lower() or "unknown flag" in stderr.lower()):
            logger.warning(f"[LIVE] httpx flag error: {stderr[:100]} — thử fallback flags")
            stdout = self._run_httpx_fallback(stdin_data)

        return self._parse_httpx_output(stdout)

    def _run_httpx_fallback(self, stdin_data: str) -> str:
        """
        Fallback cho httpx version cũ — chỉ dùng các flag cơ bản nhất,
        bỏ -tech-detect nếu không support.
        """
        cmd = [
            "httpx",
            "-status-code",
            "-title",
            "-json",
            "-silent",
            "-timeout", "10",
            "-threads", "50",
        ]
        _, stdout, stderr = run_command(cmd, timeout=300, stdin_data=stdin_data)

        if stderr and ("no such option" in stderr.lower() or "unknown flag" in stderr.lower()):
            # Fallback tối giản nhất
            logger.warning("[LIVE] httpx fallback minimal — chỉ dùng -json -silent")
            cmd_min = ["httpx", "-json", "-silent"]
            _, stdout, _ = run_command(cmd_min, timeout=300, stdin_data=stdin_data)

        return stdout

    def _parse_httpx_output(self, stdout: str) -> List[Dict]:
        """
        Parse JSON output của httpx.
        Handle cả field name cũ lẫn mới (ProjectDiscovery thay đổi
        field names giữa các version).
        """
        live_hosts = []

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)

                # ── URL ──────────────────────────────────────────────────
                url = (data.get("url")
                       or data.get("input")
                       or "")

                # ── Status code ──────────────────────────────────────────
                # version cũ: "status-code", version mới: "status_code"
                status = (data.get("status-code")
                          or data.get("status_code")
                          or data.get("status")
                          or 0)

                # ── Title ────────────────────────────────────────────────
                title = data.get("title") or ""

                # ── Technologies ─────────────────────────────────────────
                # version cũ: "tech" (list), version mới: "technologies" (list)
                tech = (data.get("tech")
                        or data.get("technologies")
                        or [])
                # Đôi khi tech là list of dict {"name": "..."}
                if tech and isinstance(tech[0], dict):
                    tech = [t.get("name", "") for t in tech]

                # ── Content length ───────────────────────────────────────
                cl = (data.get("content-length")
                      or data.get("content_length")
                      or 0)

                # ── Webserver ─────────────────────────────────────────────
                webserver = (data.get("webserver")
                             or data.get("web-server")
                             or "")

                # ── IP ───────────────────────────────────────────────────
                ip = (data.get("host")
                      or data.get("ip")
                      or data.get("a", [""])[0] if isinstance(data.get("a"), list) else ""
                      or "")

                if not url:
                    continue

                host_info = {
                    "url": url,
                    "status": int(status) if status else 0,
                    "title": title,
                    "tech": tech,
                    "content_length": cl,
                    "webserver": webserver,
                    "ip": ip,
                }
                live_hosts.append(host_info)
                logger.info(
                    f"[LIVE] ✓ {host_info['url']} "
                    f"[{host_info['status']}] "
                    f"title='{str(host_info['title'])[:40]}' "
                    f"tech={host_info['tech'][:3]}"
                )

            except json.JSONDecodeError:
                # httpx đôi khi in plain URL khi không có -json
                if line.startswith("http"):
                    live_hosts.append({
                        "url": line, "status": 200,
                        "title": "", "tech": [],
                        "content_length": 0, "webserver": "", "ip": "",
                    })
                    logger.info(f"[LIVE] ✓ {line} [plain]")

        return live_hosts

    def _detect_wordpress(self, live_hosts: List[Dict]):
        """Check if any host is WordPress"""
        wp_indicators = ["wordpress", "wp-content", "wp-includes", "woocommerce"]
        for host in live_hosts:
            tech_str = " ".join(host.get("tech", [])).lower()
            title_str = host.get("title", "").lower()
            if any(ind in tech_str or ind in title_str for ind in wp_indicators):
                logger.info(f"[LIVE] 🎯 WordPress detected on {host['url']}")
                self.state.update(wordpress_detected=True)
                break

    def _save_live_hosts(self, live_hosts: List[Dict]):
        with open(self.live_file, "w") as f:
            for host in live_hosts:
                line = f"{host['url']} [{host['status']}] {host['title']}"
                f.write(line + "\n")
        logger.info(f"[LIVE] Saved {len(live_hosts)} live hosts → {self.live_file}")