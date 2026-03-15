"""
modules/live_hosts.py - Phase 2: Live Host Detection
Tool: httpx
Detect: live domains, title, status code, technologies
"""

import json
import os
import logging
from typing import Dict, List

from core.executor import run_command, tool_available
from core.state_manager import StateManager

logger = logging.getLogger("recon.phase2")

# Common ports to probe
PORTS = "80,443,8080,8443,8888,3000,5000,4443,9000"


class LiveHostsModule:
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