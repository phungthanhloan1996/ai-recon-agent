"""
modules/toolkit_scanner.py - External Kali toolkit orchestration.
Runs high-value scanners on selected live hosts.
"""

import json
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Callable, Optional

from core.executor import run_command, tool_available
from core.state_manager import StateManager

logger = logging.getLogger("recon.toolkit")


class ToolkitScanner:
    def __init__(self, state: StateManager, output_dir: str, aggressive: bool = False):
        self.state = state
        self.output_dir = output_dir
        self.aggressive = aggressive
        self.budget = (self.state.get("scan_metadata", {}) or {}).get("budget", {})
        self.results_file = os.path.join(output_dir, "toolkit_findings.json")

    def run(
        self,
        live_hosts: List[Dict[str, Any]],
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> List[Dict[str, Any]]:
        if not live_hosts:
            return []
        host_urls = self._select_high_value_hosts(live_hosts)
        host_limit = int(self.budget.get("toolkit_hosts", 8))
        host_urls = host_urls[:host_limit]
        findings: List[Dict[str, Any]] = []

        for url in host_urls:
            findings.extend(self._run_host_tools(url, progress_cb=progress_cb))

        with open(self.results_file, "w") as f:
            json.dump(findings, f, indent=2)
        self.state.update(external_findings=findings)
        logger.info(f"[TOOLKIT] Recorded {len(findings)} findings")
        return findings

    def _select_high_value_hosts(self, live_hosts: List[Dict[str, Any]]) -> List[str]:
        scored: List[tuple[int, str]] = []
        for h in live_hosts:
            u = h.get("url", "")
            if not u:
                continue
            s = 0
            st = int(h.get("status_code", 0) or 0)
            if st == 200:
                s += 35
            elif 300 <= st < 400:
                s += 20
            elif 400 <= st < 500:
                s += 15
            low = u.lower()
            if any(k in low for k in ("admin", "login", "wp-admin", "api", "graphql")):
                s += 25
            if any(k in low for k in ("staging", "dev", "test", "beta")):
                s += 12
            scored.append((s, u))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [u for _, u in scored]

    def _run_host_tools(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        host = url.split("://", 1)[-1].split("/", 1)[0]
        jobs: List[tuple[str, List[str], int, str]] = []

        if tool_available("whatweb"):
            jobs.append(("whatweb", ["whatweb", "--no-errors", url], 60, "INFO"))
        if tool_available("wafw00f"):
            jobs.append(("wafw00f", ["wafw00f", "-a", url], 90, "INFO"))
        if tool_available("nikto"):
            jobs.append(("nikto", ["nikto", "-host", url, "-maxtime", "2m"], 180, "MEDIUM"))
        if tool_available("nmap"):
            jobs.append(("nmap", ["nmap", "-sV", "-Pn", "--top-ports", "100", "--open", host], 180, "INFO"))
        if self.aggressive and tool_available("ffuf"):
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if os.path.exists(wordlist):
                jobs.append((
                    "ffuf",
                    ["ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist, "-mc", "200,204,301,302,307,401,403", "-t", "30", "-ac"],
                    180,
                    "LOW",
                ))

        workers = int(self.budget.get("toolkit_parallel_tools", 3))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            fut_map = {}
            for tool_name, cmd, timeout, severity in jobs:
                if progress_cb:
                    progress_cb("toolkit", tool_name, "running")
                fut = executor.submit(run_command, cmd, timeout)
                fut_map[fut] = (tool_name, severity)

            for fut in as_completed(fut_map):
                tool_name, sev = fut_map[fut]
                try:
                    ret, stdout, _ = fut.result()
                except Exception:
                    ret, stdout = -3, ""
                if progress_cb:
                    progress_cb("toolkit", tool_name, "done" if ret == 0 else "failed")
                if ret == 0 and stdout:
                    if tool_name == "wafw00f":
                        sev = "LOW" if "No WAF detected" in stdout else "INFO"
                    out.append({"tool": tool_name, "url": url, "severity": sev, "output": stdout[:4000]})

        return out
