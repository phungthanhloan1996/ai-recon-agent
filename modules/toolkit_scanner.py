"""
modules/toolkit_scanner.py - External Kali toolkit orchestration.
Runs high-value scanners on selected live hosts.
"""

import json
import logging
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Callable, Optional
from urllib.parse import urlparse

from core.executor import run_command, tool_available
from core.state_manager import StateManager
from core.http_engine import HTTPClient
from integrations.whatweb_runner import WhatwebRunner
from integrations.naabu_runner import NaabuRunner
from integrations.dirbusting_runner import DirBustingRunner
from integrations.wappalyzer_runner import WappalyzerRunner
from modules.api_scanner import APIScannerRunner

logger = logging.getLogger("recon.toolkit")


class ToolkitScanner:
    def __init__(self, state: StateManager, output_dir: str, aggressive: bool = False):
        self.state = state
        self.output_dir = output_dir
        self.aggressive = aggressive
        self.budget = (self.state.get("scan_metadata", {}) or {}).get("budget", {})
        self.results_file = os.path.join(output_dir, "toolkit_findings.json")
        
        # Initialize advanced scanners
        self.whatweb_runner = WhatwebRunner(output_dir, verbose=False)
        self.naabu_runner = NaabuRunner(output_dir, fast=True)
        self.dirbusting_runner = DirBustingRunner(output_dir)
        self.wappalyzer_runner = WappalyzerRunner(output_dir)
        self.api_scanner = APIScannerRunner(output_dir)
        self.http_client = HTTPClient()
        self.toolkit_metrics = {"tech": 0, "ports": 0, "dirs": 0, "api": 0, "vulns": 0}

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
        self.state.update_scan_metadata(toolkit_metrics=self.toolkit_metrics.copy())
        logger.info(f"[TOOLKIT] Recorded {len(findings)} findings")
        return findings

    def _notify_progress(
        self,
        progress_cb: Optional[Callable[[str, str, str], None]],
        tool: str,
        status: str,
        detail: str = ""
    ):
        if progress_cb:
            try:
                progress_cb("toolkit", tool, status, detail)
            except TypeError:
                progress_cb("toolkit", tool, status)

    def _merge_toolkit_data_into_state(self, finding: Dict[str, Any]):
        tool = finding.get("tool", "")
        data = finding.get("data", {}) or {}
        persisted = (self.state.get("scan_metadata", {}) or {}).get("toolkit_metrics", {}) or {}
        metrics = {
            "tech": max(int(self.toolkit_metrics.get("tech", 0)), int(persisted.get("tech", 0) or 0)),
            "ports": max(int(self.toolkit_metrics.get("ports", 0)), int(persisted.get("ports", 0) or 0)),
            "dirs": max(int(self.toolkit_metrics.get("dirs", 0)), int(persisted.get("dirs", 0) or 0)),
            "api": max(int(self.toolkit_metrics.get("api", 0)), int(persisted.get("api", 0) or 0)),
            "vulns": max(int(self.toolkit_metrics.get("vulns", 0)), int(persisted.get("vulns", 0) or 0)),
        }

        if tool == "whatweb":
            for tech in data.get("technologies", []):
                tech_name = tech.get("name")
                if not tech_name:
                    continue
                self.state.update_technologies(tech_name, tech)
            metrics["tech"] = len(self.state.get("technologies", {}) or {})
            metrics["vulns"] += len(data.get("vulnerabilities", []) or [])

        elif tool == "wappalyzer":
            version_info = data.get("version_info", {}) or {}
            for tech_name in data.get("technologies", []):
                if not tech_name:
                    continue
                payload = {"name": tech_name}
                if tech_name in version_info:
                    payload["version"] = version_info[tech_name]
                self.state.update_technologies(tech_name, payload)
            metrics["tech"] = len(self.state.get("technologies", {}) or {})

        elif tool in {"nmap", "naabu"}:
            ports = data.get("ports", []) or []
            if ports:
                host = finding.get("host", "")
                self.state.update_technologies(host, {"open_ports": ports})
                metrics["ports"] = max(metrics["ports"], len(ports))

        elif tool == "api_scanner":
            api_endpoints = []
            for endpoint in data.get("rest_endpoints", []) or []:
                api_endpoints.append(endpoint)
            for endpoint in data.get("graphql_endpoints", []) or []:
                api_endpoints.append(endpoint)
            for doc in data.get("api_docs", []) or []:
                if isinstance(doc, dict):
                    api_endpoints.append(doc.get("url") or doc.get("endpoint"))
            base_url = finding.get("url", "").rstrip("/")
            normalized = []
            for endpoint in api_endpoints:
                if not endpoint:
                    continue
                if endpoint.startswith(("http://", "https://")):
                    normalized.append(endpoint)
                elif endpoint.startswith("/") and base_url:
                    normalized.append(f"{base_url}{endpoint}")
            for endpoint_url in dict.fromkeys(normalized):
                self.state.upsert_endpoint({
                    "url": endpoint_url,
                    "source": "api_scanner",
                    "categories": ["api"],
                    "method": "GET",
                })
            metrics["api"] = max(metrics["api"], len(dict.fromkeys(normalized)))
            metrics["vulns"] += len(data.get("vulnerabilities", []) or [])

        elif tool == "dirbusting":
            dirs = data.get("directories", []) or []
            files = data.get("files", []) or []
            metrics["dirs"] = max(metrics["dirs"], len(dirs) + len(files))

        self.toolkit_metrics = metrics
        self.state.update_scan_metadata(toolkit_metrics=self.toolkit_metrics.copy())

    def _select_high_value_hosts(self, live_hosts: List[Dict[str, Any]]) -> List[str]:
        scored: List[tuple[int, str]] = []
        for h in live_hosts:
            u = h.get("url", "")
            if not u:
                continue
            # Skip URLs với file extension
            from urllib.parse import urlparse as _up
            _path = _up(u).path
            if any(k in u for k in ('wp-json', 'oembed', 'embed', 'feed', 'xmlrpc')):
                continue
            if len(_path.split('/')) > 4:
                continue
            if '.' in _path.split('/')[-1]:
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
        """Run comprehensive toolkit scans on URL"""
        out: List[Dict[str, Any]] = []
        host, explicit_port = self._extract_host_and_port(url)
        
        # Tier 1: High-priority scanners (parallel)
        logger.info(f"[TOOLKIT] Starting comprehensive scan on {url}")
        
        tier1_results = self._run_tier1_scanners(url, host, explicit_port, progress_cb)
        out.extend(tier1_results)
        
        # Tier 2: Advanced scanners (only on aggressive mode)
        if self.aggressive:
            tier2_results = self._run_tier2_scanners(url, host, progress_cb)
            out.extend(tier2_results)
        
        # Tier 3: API scanning
        tier3_results = self._run_api_scanners(url, progress_cb)
        out.extend(tier3_results)
        
        return out

    def _run_tier1_scanners(
        self,
        url: str,
        host: str,
        explicit_port: Optional[int],
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """Priority 1: Technology detection and vulnerability scanning"""
        out: List[Dict[str, Any]] = []
        jobs: List[tuple[str, Callable]] = []
        
        # Whatweb - advanced technology detection with CVE matching (increased timeout)
        jobs.append(("whatweb", lambda: self._scan_whatweb(url, progress_cb, timeout=120)))
        
        # Wappalyzer - comprehensive tech fingerprinting
        jobs.append(("wappalyzer", lambda: self._scan_wappalyzer(url, progress_cb)))
        
        # WAF detection
        if tool_available("wafw00f"):
            jobs.append(("wafw00f", lambda: self._scan_wafw00f(url, progress_cb, timeout=120)))
        
        # Nikto - web server vulnerability scanner
        if tool_available("nikto"):
            jobs.append(("nikto", lambda: self._scan_nikto(url, progress_cb, timeout=180)))
        
        # Naabu - fast port scanning (if naabu is available)
        if explicit_port is not None and tool_available("nmap"):
            jobs.append(("nmap", lambda: self._scan_nmap(host, explicit_port, progress_cb, timeout=180)))
        elif tool_available("naabu"):
            jobs.append(("naabu", lambda: self._scan_naabu(host, progress_cb, timeout=180)))
        elif tool_available("nmap"):
            # Fallback to nmap with increased timeout
            jobs.append(("nmap", lambda: self._scan_nmap(host, None, progress_cb, timeout=180)))
        
        workers = int(self.budget.get("toolkit_parallel_tools", 4))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            fut_map = {executor.submit(scan_func): (tool_name,) for tool_name, scan_func in jobs}
            
            for fut in as_completed(fut_map):
                try:
                    result = fut.result()
                    if result:
                        out.append(result)
                except Exception as e:
                    logger.error(f"Error in tier1 scanner: {e}")
        
        return out

    def _extract_host_and_port(self, url: str) -> tuple[str, Optional[int]]:
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc or url
        try:
            port = parsed.port
        except ValueError:
            port = None
        return host, port

    def _run_tier2_scanners(
        self,
        url: str,
        host: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """Priority 2: Directory brute-forcing and deep scanning"""
        out: List[Dict[str, Any]] = []
        
        # Directory and file brute-forcing
        logger.info(f"[TOOLKIT] Starting directory brute-forcing on {url}")
        dirbusting_result = self._scan_dirbusting(url, progress_cb)
        if dirbusting_result:
            out.append(dirbusting_result)
        
        # FFUF - web fuzzing (if available)
        if tool_available("ffuf"):
            ffuf_result = self._scan_ffuf(url, progress_cb)
            if ffuf_result:
                out.append(ffuf_result)
        
        return out

    def _run_api_scanners(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """API endpoint detection and testing"""
        out: List[Dict[str, Any]] = []
        
        logger.info(f"[TOOLKIT] Scanning for API endpoints on {url}")
        api_result = self._scan_api(url, progress_cb)
        if api_result and api_result.get("apis_found"):
            out.append(api_result)
        
        return out

    def _scan_whatweb(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 60
    ) -> Optional[Dict[str, Any]]:
        """Run whatweb scanner"""
        self._notify_progress(progress_cb, "whatweb", "running", "whatweb: detecting technologies...")
        
        try:
            result = self.whatweb_runner.run(url, timeout=timeout)
            self._notify_progress(
                progress_cb,
                "whatweb",
                "done" if result.get("success") else "failed",
                f"whatweb: detected {len(result.get('technologies', []))} technologies"
                if result.get("success")
                else "whatweb: no data"
            )
            
            if result.get("success"):
                # Log detected technologies
                for tech in result.get("technologies", []):
                    logger.info(f"[WHATWEB] Detected: {tech.get('name')} {tech.get('version', '')}")
                
                # Log vulnerabilities
                for vuln in result.get("vulnerabilities", []):
                    logger.warning(f"[WHATWEB-CVE] {vuln.get('cve')} in {vuln.get('technology')} {vuln.get('version')}")
                
                self._merge_toolkit_data_into_state({
                    "tool": "whatweb",
                    "data": result,
                    "url": url,
                })
                return {
                    "tool": "whatweb",
                    "url": url,
                    "severity": "INFO",
                    "success": True,
                    "data": result
                }
            else:
                # Return partial success with error info
                logger.warning(f"[WHATWEB] No data for {url}: {result.get('error')}")
                return {
                    "tool": "whatweb",
                    "url": url,
                    "severity": "INFO",
                    "success": False,
                    "data": result
                }
        except Exception as e:
            logger.error(f"Whatweb error: {e}")
            return {
                "tool": "whatweb",
                "url": url,
                "severity": "LOW",
                "success": False,
                "error": str(e)
            }
        
        return None

    def _scan_wappalyzer(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run wappalyzer scanner"""
        self._notify_progress(progress_cb, "wappalyzer", "running", "wappalyzer: fingerprinting stack...")
        
        try:
            result = self.wappalyzer_runner.run(url, timeout=60)
            self._notify_progress(progress_cb, "wappalyzer", "done", f"wappalyzer: found {len(result.get('technologies', []))} technologies")
            
            if result.get("technologies"):
                # Log detected technologies
                for tech in result.get("technologies", []):
                    logger.info(f"[WAPPALYZER] {tech}")
                
                self._merge_toolkit_data_into_state({
                    "tool": "wappalyzer",
                    "data": result,
                    "url": url,
                })
                return {
                    "tool": "wappalyzer",
                    "url": url,
                    "severity": "INFO",
                    "data": result
                }
        except Exception as e:
            logger.error(f"Wappalyzer error: {e}")
        
        return None

    def _scan_wafw00f(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 90
    ) -> Optional[Dict[str, Any]]:
        """Run WAF detection"""
        self._notify_progress(progress_cb, "wafw00f", "running", "wafw00f: detecting web application firewall...")
        
        try:
            ret, stdout, _ = run_command(["wafw00f", "-a", url], timeout=timeout)
            self._notify_progress(progress_cb, "wafw00f", "done" if ret == 0 else "failed", "wafw00f: detection complete")
            
            if ret == 0 and stdout:
                severity = "LOW" if "No WAF detected" in stdout else "INFO"
                logger.info(f"[WAFW00F] WAF Detection: {'Found' if severity == 'INFO' else 'Not Found'}")
                return {
                    "tool": "wafw00f",
                    "url": url,
                    "severity": severity,
                    "output": stdout[:2000],
                    "success": True
                }
            else:
                logger.warning(f"[WAFW00F] Scan incomplete for {url} (return code: {ret})")
                return {
                    "tool": "wafw00f",
                    "url": url,
                    "severity": "LOW",
                    "output": stdout[:1000] if stdout else _[:1000] if _ else "",
                    "success": False
                }
        except Exception as e:
            logger.error(f"WAF detection error: {e}")
            return {
                "tool": "wafw00f",
                "url": url,
                "severity": "LOW",
                "success": False,
                "error": str(e)
            }
        
        return None

    def _scan_nikto(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 180
    ) -> Optional[Dict[str, Any]]:
        """Run nikto vulnerability scanner"""
        self._notify_progress(progress_cb, "nikto", "running", "nikto: probing web server misconfigurations...")
        
        try:
            # Prepare output file path
            output_file = os.path.join(self.output_dir, f"nikto_{url.replace(':', '_').replace('/', '_')}.json")
            
            ret, stdout, _ = run_command(
                ["nikto", "-host", url, "-maxtime", "2m", "-Format", "json", "-o", output_file],
                timeout=180
            )
            self._notify_progress(progress_cb, "nikto", "done" if ret == 0 else "failed", "nikto: scan finished")
            
            if ret == 0 and os.path.exists(output_file):
                logger.info(f"[NIKTO] Scan completed on {url}, saved to {output_file}")
                return {
                    "tool": "nikto",
                    "url": url,
                    "severity": "MEDIUM",
                    "output_file": output_file
                }
        except Exception as e:
            logger.error(f"Nikto error: {e}")
        
        return None

    def _scan_naabu(
        self,
        host: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 120
    ) -> Optional[Dict[str, Any]]:
        """Run naabu for fast port scanning"""
        self._notify_progress(progress_cb, "naabu", "running", f"naabu: scanning common ports on {host}...")
        
        try:
            result = self.naabu_runner.run(host, timeout=timeout)
            self._notify_progress(progress_cb, "naabu", "done" if result.get("success") else "failed", f"naabu: found {len(result.get('ports', []))} open ports")
            
            if result.get("success") and result.get("ports"):
                logger.info(f"[NAABU] Found {len(result.get('ports', []))} open ports on {host}")
                for port, service_info in result.get("services", {}).items():
                    service = service_info.get("service", "Unknown")
                    logger.debug(f"[NAABU] Port {port}: {service}")
                
                self._merge_toolkit_data_into_state({
                    "tool": "naabu",
                    "data": result,
                    "host": host,
                })
                return {
                    "tool": "naabu",
                    "host": host,
                    "severity": "INFO",
                    "data": result,
                    "success": True
                }
            else:
                logger.warning(f"[NAABU] No ports found or failed for {host}: {result.get('error')}")
                return {
                    "tool": "naabu",
                    "host": host,
                    "severity": "INFO",
                    "data": result,
                    "success": False
                }
        except Exception as e:
            logger.error(f"Naabu error: {e}")
            return {
                "tool": "naabu",
                "host": host,
                "severity": "LOW",
                "success": False,
                "error": str(e)
            }
        
        return None

    def _scan_nmap(
        self,
        host: str,
        explicit_port: Optional[int] = None,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 120
    ) -> Optional[Dict[str, Any]]:
        """Run nmap for port scanning (fallback) - optimized"""
        port_hint = str(explicit_port) if explicit_port is not None else "top-50"
        self._notify_progress(progress_cb, "nmap", "running", f"nmap: scanning ports {port_hint} on {host}...")
        
        try:
            # Optimized: fewer ports, faster timing
            cmd = ["nmap", "-Pn", "--open"]
            if explicit_port is not None:
                cmd.extend(["-p", str(explicit_port), host])
            else:
                cmd.extend(["--top-ports", "50", host])
            
            # Add timing - local hosts get faster settings
            if host in ["localhost", "127.0.0.1", "::1"]:
                cmd.extend(["-sV", "-T5"])
            else:
                cmd.append("-T4")
            
            ret, stdout, stderr = run_command(cmd, timeout=timeout)
            parsed_ports = self._parse_nmap_ports(stdout or "")
            self._notify_progress(progress_cb, "nmap", "done" if ret == 0 else "failed", f"nmap: found {len(parsed_ports)} open ports")
            if ret == 0 and stdout:
                open_ports = len(parsed_ports)
                logger.info(f"[NMAP] Port scan completed on {host}: {open_ports} ports open")
                if parsed_ports:
                    self.state.update_technologies(host, {"open_ports": [p["port"] for p in parsed_ports]})
                self._merge_toolkit_data_into_state({
                    "tool": "nmap",
                    "data": {
                        "ports": [p["port"] for p in parsed_ports],
                        "services": {p["port"]: {"service": p["service"], "state": p["state"]} for p in parsed_ports},
                    },
                    "host": host,
                })
                return {
                    "tool": "nmap",
                    "host": host,
                    "severity": "INFO",
                    "output": stdout[:2000],
                    "success": True,
                    "ports_found": open_ports,
                    "data": {
                        "ports": [p["port"] for p in parsed_ports],
                        "services": {p["port"]: {"service": p["service"], "state": p["state"]} for p in parsed_ports}
                    }
                }
            elif stdout:
                # Partial results
                open_ports = len(parsed_ports)
                logger.warning(f"[NMAP] Partial {host}: {open_ports} ports")
                if parsed_ports:
                    self.state.update_technologies(host, {"open_ports": [p["port"] for p in parsed_ports]})
                self._merge_toolkit_data_into_state({
                    "tool": "nmap",
                    "data": {
                        "ports": [p["port"] for p in parsed_ports],
                        "services": {p["port"]: {"service": p["service"], "state": p["state"]} for p in parsed_ports},
                    },
                    "host": host,
                })
                return {
                    "tool": "nmap",
                    "host": host,
                    "severity": "INFO",
                    "output": stdout[:1000],
                    "success": True if open_ports > 0 else False,
                    "ports_found": open_ports,
                    "data": {
                        "ports": [p["port"] for p in parsed_ports],
                        "services": {p["port"]: {"service": p["service"], "state": p["state"]} for p in parsed_ports}
                    }
                }
            else:
                logger.warning(f"[NMAP] Failed for {host}")
                return {
                    "tool": "nmap",
                    "host": host,
                    "severity": "INFO",
                    "output": stderr[:500] if stderr else "[NO OUTPUT]",
                    "success": False
                }
        except subprocess.TimeoutExpired:
            logger.warning(f"[NMAP] Timeout on {host}")
            return {
                "tool": "nmap",
                "host": host,
                "severity": "INFO",
                "output": "[TIMEOUT]",
                "success": False
            }
        except Exception as e:
            logger.error(f"Nmap error: {e}")
            return {
                "tool": "nmap",
                "host": host,
                "severity": "LOW",
                "success": False,
                "error": str(e)
            }
        
        return None

    def _parse_nmap_ports(self, output: str) -> List[Dict[str, Any]]:
        ports: List[Dict[str, Any]] = []
        for line in output.splitlines():
            match = re.match(r"^\s*(\d+)/(tcp|udp)\s+(\S+)\s+(.+?)\s*$", line)
            if not match:
                continue
            state = match.group(3).strip().lower()
            if state != "open":
                continue
            service = match.group(4).strip().split()[0]
            ports.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": state,
                "service": service,
            })
        return ports

    def _scan_dirbusting(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run directory brute-forcing"""
        self._notify_progress(progress_cb, "dirbusting", "running", "dirbusting: testing common paths...")
        
        try:
            result = self.dirbusting_runner.run(url, timeout=180)
            tested_paths = len(result.get("directories", []) or []) + len(result.get("files", []) or [])
            self._notify_progress(progress_cb, "dirbusting", "done" if result.get("success") else "failed", f"dirbusting: tested {tested_paths} discovered paths")
            
            if result.get("success"):
                found_count = len(result.get("directories", [])) + len(result.get("files", []))
                if found_count > 0:
                    logger.info(f"[DIRBUSTING] Found {found_count} items on {url}")
                    
                    # Log suspicious findings
                    for path in result.get("suspicious", []):
                        logger.warning(f"[DIRBUSTING-SUSPICIOUS] {path}")
                    
                    self._merge_toolkit_data_into_state({
                        "tool": "dirbusting",
                        "data": result,
                        "url": url,
                    })
                    return {
                        "tool": "dirbusting",
                        "url": url,
                        "severity": "LOW",
                        "data": result
                    }
        except Exception as e:
            logger.error(f"Dirbusting error: {e}")
        
        return None

    def _scan_ffuf(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run ffuf web fuzzer"""
        self._notify_progress(progress_cb, "ffuf", "running", "ffuf: fuzzing content paths...")
        
        try:
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if not os.path.exists(wordlist):
                return None
            
            ret, stdout, _ = run_command(
                [
                    "ffuf",
                    "-u", f"{url.rstrip('/')}/FUZZ",
                    "-w", wordlist,
                    "-mc", "200,204,301,302,307,401,403",
                    "-t", "50",
                    "-ac",
                    "-o", "/tmp/ffuf_output.json",
                    "-of", "json"
                ],
                timeout=180
            )
            self._notify_progress(progress_cb, "ffuf", "done" if ret == 0 else "failed", "ffuf: fuzzing finished")
            
            if ret == 0:
                logger.info(f"[FFUF] Web fuzzing completed on {url}")
                return {
                    "tool": "ffuf",
                    "url": url,
                    "severity": "INFO",
                    "output": stdout[:2000]
                }
        except Exception as e:
            logger.error(f"FFUF error: {e}")
        
        return None

    def _scan_api(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run API scanner"""
        self._notify_progress(progress_cb, "api_scanner", "running", "api_scanner: discovering REST/GraphQL/docs...")
        
        try:
            result = self.api_scanner.scan(url)
            apis_found = (
                list(result.get("rest_endpoints", []))
                + list(result.get("graphql_endpoints", []))
                + [doc.get("url") or doc.get("endpoint") for doc in result.get("api_docs", []) if isinstance(doc, dict)]
            )
            apis_found = [api for api in apis_found if api]
            result["apis_found"] = list(dict.fromkeys(apis_found))
            self._notify_progress(progress_cb, "api_scanner", "done", f"api_scanner: found {len(result['apis_found'])} API endpoints")

            if result.get("apis_found"):
                logger.info(f"[API] Found {len(result.get('apis_found', []))} API endpoints")
                
                # Log vulnerabilities
                for vuln in result.get("vulnerabilities", []):
                    logger.warning(f"[API-VULN] {vuln.get('type')} ({vuln.get('severity')})")
                
                self._merge_toolkit_data_into_state({
                    "tool": "api_scanner",
                    "data": result,
                    "url": url,
                })
                return {
                    "tool": "api_scanner",
                    "url": url,
                    "severity": "MEDIUM" if result.get("vulnerabilities") else "INFO",
                    "data": result
                }
        except Exception as e:
            logger.error(f"API scanner error: {e}")
        
        return None

    def _check_security_headers(self, response) -> List[Dict[str, Any]]:
        """Check for missing security headers (OWASP A02:2021)."""
        findings = []
        required_headers = {
            "X-Frame-Options": {"severity": "MEDIUM", "title": "Missing X-Frame-Options Header", "description": "Prevents clickjacking attacks.", "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN"},
            "X-XSS-Protection": {"severity": "LOW", "title": "Missing X-XSS-Protection Header", "description": "Enables XSS filtering in browsers.", "recommendation": "Set X-XSS-Protection to '1; mode=block'"},
            "X-Content-Type-Options": {"severity": "MEDIUM", "title": "Missing X-Content-Type-Options Header", "description": "Prevents MIME-type sniffing.", "recommendation": "Set X-Content-Type-Options to 'nosniff'"},
            "Strict-Transport-Security": {"severity": "HIGH", "title": "Missing HSTS Header", "description": "Forces browsers to use HTTPS.", "recommendation": "Set with max-age of at least 31536000"},
            "Content-Security-Policy": {"severity": "MEDIUM", "title": "Missing CSP Header", "description": "Prevents XSS and data injection attacks.", "recommendation": "Implement appropriate CSP"},
            "Referrer-Policy": {"severity": "LOW", "title": "Missing Referrer-Policy Header", "description": "Controls referrer information.", "recommendation": "Set to 'strict-origin-when-cross-origin'"},
            "Permissions-Policy": {"severity": "LOW", "title": "Missing Permissions-Policy Header", "description": "Controls browser features.", "recommendation": "Restrict unnecessary browser features"},
        }
        if not hasattr(response, 'headers') or not response.headers:
            return findings
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        for header_name, info in required_headers.items():
            if header_name.lower() not in headers_lower:
                findings.append({"type": "missing_security_header", "severity": info["severity"], "title": info["title"], "description": info["description"], "recommendation": info["recommendation"], "missing_header": header_name})
        return findings

    def _check_debug_mode(self, response) -> List[Dict[str, Any]]:
        """Check for debug mode exposure (OWASP A02:2021)."""
        findings = []
        if not hasattr(response, 'text') and not hasattr(response, 'content'):
            return findings
        response_text = getattr(response, 'text', '') or getattr(response, 'content', b'').decode('utf-8', errors='ignore')
        if not response_text:
            return findings
        debug_patterns = [
            (r'(?i)traceback \(most recent call last\)', "Python traceback exposed"),
            (r'(?i)stack trace', "Stack trace exposed"),
            (r'(?i)debug\s*=\s*(true|yes|1|on)', "Debug mode enabled"),
            (r'(?i)laravel_debug\s*=\s*(true|yes|1)', "Laravel debug mode enabled"),
            (r'(?i)APP_DEBUG\s*=\s*(true|yes|1)', "Laravel APP_DEBUG enabled"),
            (r'(?i)Compilation debug="true"', "ASP.NET compilation debug enabled"),
            (r'(?i)in .+\.php on line \d+', "PHP error with line number"),
            (r'(?i)Warning\s*:', "PHP warning exposed"),
            (r'(?i)Fatal error\s*:', "PHP fatal error exposed"),
            (r'(?i)Undefined variable\s*:', "PHP undefined variable exposed"),
            (r'(?i)sql query\s*:', "SQL query exposed"),
        ]
        for pattern, description in debug_patterns:
            if re.search(pattern, response_text):
                severity = "HIGH" if any(kw in description.lower() for kw in ["debug", "traceback", "stack trace", "sql"]) else "MEDIUM"
                findings.append({"type": "debug_mode_exposed", "severity": severity, "title": "Debug Information Exposed", "description": description, "recommendation": "Disable debug mode in production."})
                break
        return findings

    def _check_directory_listing(self, url: str) -> List[Dict[str, Any]]:
        """Check for directory listing (OWASP A02:2021)."""
        findings = []
        paths = ["/", "/images/", "/assets/", "/uploads/", "/files/", "/backup/"]
        patterns = [r'Index of /', r'\[DIR\]', r'<title>Index of', r'Parent Directory']
        for path in paths:
            try:
                test_url = url.rstrip('/') + path
                response = self.http_client.get(test_url, timeout=10)
                if response.status_code == 200:
                    text = getattr(response, 'text', '')
                    for p in patterns:
                        if re.search(p, text, re.IGNORECASE):
                            findings.append({"type": "directory_listing", "severity": "MEDIUM", "url": test_url, "title": "Directory Listing Enabled", "description": f"Directory listing at {test_url}", "recommendation": "Disable directory listing in web server config"})
                            break
            except Exception:
                continue
        return findings

    def _check_exposed_files(self, base_url: str) -> List[Dict[str, Any]]:
        """Check for exposed sensitive files (OWASP A02:2021)."""
        findings = []
        exposed = {
            "/.git/HEAD": {"severity": "HIGH", "title": "Git Repository Exposed", "description": ".git directory accessible.", "check": r'ref:'},
            "/.env": {"severity": "CRITICAL", "title": "Environment File Exposed", "description": ".env file accessible with potential secrets.", "check": r'(?:DB_|APP_|API_|SECRET_)'},
            "/phpinfo.php": {"severity": "MEDIUM", "title": "PHP Info Exposed", "description": "phpinfo() page accessible.", "check": r'PHP Version|phpinfo'},
            "/swagger.json": {"severity": "LOW", "title": "Swagger Docs Exposed", "description": "API documentation publicly accessible.", "check": r'swagger|openapi'},
            "/actuator/info": {"severity": "MEDIUM", "title": "Spring Boot Actuator Exposed", "description": "Actuator info endpoint accessible.", "check": None},
            "/.htaccess": {"severity": "MEDIUM", "title": ".htaccess Exposed", "description": "Server configuration exposed.", "check": r'RewriteRule|Redirect'},
            "/robots.txt": {"severity": "INFO", "title": "Robots.txt Found", "description": "May reveal hidden paths.", "check": r'Disallow|Allow'},
            "/wp-config.php": {"severity": "CRITICAL", "title": "WordPress Config Exposed", "description": "Database credentials may be exposed.", "check": r'DB_NAME|DB_USER'},
        }
        for path, info in exposed.items():
            try:
                test_url = base_url.rstrip('/') + path
                response = self.http_client.get(test_url, timeout=10)
                if response.status_code == 200:
                    text = getattr(response, 'text', '')
                    if info["check"]:
                        if re.search(info["check"], text, re.IGNORECASE):
                            findings.append({"type": "exposed_sensitive_file", "severity": info["severity"], "url": test_url, "title": info["title"], "description": info["description"], "recommendation": f"Remove or restrict access to {path}"})
                    elif len(text) > 10:
                        findings.append({"type": "exposed_sensitive_file", "severity": info["severity"], "url": test_url, "title": info["title"], "description": info["description"], "recommendation": f"Remove or restrict access to {path}"})
            except Exception:
                continue
        return findings

    def _run_security_misconfig_checks(self, url: str, progress_cb: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Run all security misconfiguration checks (OWASP A02:2021)."""
        findings = []
        self._notify_progress(progress_cb, "security-misconfig", "running", "Checking security headers, debug mode, directory listing, exposed files...")
        try:
            response = self.http_client.get(url, timeout=15)
            findings.extend(self._check_security_headers(response))
            findings.extend(self._check_debug_mode(response))
        except Exception:
            pass
        findings.extend(self._check_directory_listing(url))
        findings.extend(self._check_exposed_files(url))
        self._notify_progress(progress_cb, "security-misconfig", "done", f"Found {len(findings)} security misconfigurations")
        return findings
