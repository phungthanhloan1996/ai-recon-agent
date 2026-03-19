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
        """Run comprehensive toolkit scans on URL"""
        out: List[Dict[str, Any]] = []
        host = url.split("://", 1)[-1].split("/", 1)[0]
        
        # Tier 1: High-priority scanners (parallel)
        logger.info(f"[TOOLKIT] Starting comprehensive scan on {url}")
        
        tier1_results = self._run_tier1_scanners(url, host, progress_cb)
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
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> List[Dict[str, Any]]:
        """Priority 1: Technology detection and vulnerability scanning"""
        out: List[Dict[str, Any]] = []
        jobs: List[tuple[str, Callable]] = []
        
        # Whatweb - advanced technology detection with CVE matching
        jobs.append(("whatweb", lambda: self._scan_whatweb(url, progress_cb)))
        
        # Wappalyzer - comprehensive tech fingerprinting
        jobs.append(("wappalyzer", lambda: self._scan_wappalyzer(url, progress_cb)))
        
        # WAF detection
        if tool_available("wafw00f"):
            jobs.append(("wafw00f", lambda: self._scan_wafw00f(url, progress_cb)))
        
        # Nikto - web server vulnerability scanner
        if tool_available("nikto"):
            jobs.append(("nikto", lambda: self._scan_nikto(url, progress_cb)))
        
        # Naabu - fast port scanning (if naabu is available)
        if tool_available("naabu"):
            jobs.append(("naabu", lambda: self._scan_naabu(host, progress_cb)))
        elif tool_available("nmap"):
            # Fallback to nmap
            jobs.append(("nmap", lambda: self._scan_nmap(host, progress_cb)))
        
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
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run whatweb scanner"""
        if progress_cb:
            progress_cb("toolkit", "whatweb", "running")
        
        try:
            result = self.whatweb_runner.run(url, timeout=60)
            if progress_cb:
                progress_cb("toolkit", "whatweb", "done" if result.get("success") else "failed")
            
            if result.get("success"):
                # Log detected technologies
                for tech in result.get("technologies", []):
                    logger.info(f"[WHATWEB] Detected: {tech.get('name')} {tech.get('version', '')}")
                
                # Log vulnerabilities
                for vuln in result.get("vulnerabilities", []):
                    logger.warning(f"[WHATWEB-CVE] {vuln.get('cve')} in {vuln.get('technology')} {vuln.get('version')}")
                
                return {
                    "tool": "whatweb",
                    "url": url,
                    "severity": "INFO",
                    "success": True,
                    "data": result
                }
        except Exception as e:
            logger.error(f"Whatweb error: {e}")
        
        return None

    def _scan_wappalyzer(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run wappalyzer scanner"""
        if progress_cb:
            progress_cb("toolkit", "wappalyzer", "running")
        
        try:
            result = self.wappalyzer_runner.run(url, timeout=60)
            if progress_cb:
                progress_cb("toolkit", "wappalyzer", "done")
            
            if result.get("technologies"):
                # Log detected technologies
                for tech in result.get("technologies", []):
                    logger.info(f"[WAPPALYZER] {tech}")
                
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
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run WAF detection"""
        if progress_cb:
            progress_cb("toolkit", "wafw00f", "running")
        
        try:
            ret, stdout, _ = run_command(["wafw00f", "-a", url], timeout=90)
            if progress_cb:
                progress_cb("toolkit", "wafw00f", "done" if ret == 0 else "failed")
            
            if ret == 0 and stdout:
                severity = "LOW" if "No WAF detected" in stdout else "INFO"
                logger.info(f"[WAFW00F] WAF Detection: {'Found' if severity == 'INFO' else 'Not Found'}")
                return {
                    "tool": "wafw00f",
                    "url": url,
                    "severity": severity,
                    "output": stdout[:2000]
                }
        except Exception as e:
            logger.error(f"WAF detection error: {e}")
        
        return None

    def _scan_nikto(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run nikto vulnerability scanner"""
        if progress_cb:
            progress_cb("toolkit", "nikto", "running")
        
        try:
            ret, stdout, _ = run_command(
                ["nikto", "-host", url, "-maxtime", "2m", "-Format", "json"],
                timeout=180
            )
            if progress_cb:
                progress_cb("toolkit", "nikto", "done" if ret == 0 else "failed")
            
            if ret == 0 and stdout:
                logger.info(f"[NIKTO] Scan completed on {url}")
                return {
                    "tool": "nikto",
                    "url": url,
                    "severity": "MEDIUM",
                    "output": stdout[:3000]
                }
        except Exception as e:
            logger.error(f"Nikto error: {e}")
        
        return None

    def _scan_naabu(
        self,
        host: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run naabu for fast port scanning"""
        if progress_cb:
            progress_cb("toolkit", "naabu", "running")
        
        try:
            result = self.naabu_runner.run(host, timeout=120)
            if progress_cb:
                progress_cb("toolkit", "naabu", "done" if result.get("success") else "failed")
            
            if result.get("success") and result.get("ports"):
                logger.info(f"[NAABU] Found {len(result.get('ports', []))} open ports on {host}")
                for port, service_info in result.get("services", {}).items():
                    service = service_info.get("service", "Unknown")
                    logger.debug(f"[NAABU] Port {port}: {service}")
                
                return {
                    "tool": "naabu",
                    "host": host,
                    "severity": "INFO",
                    "data": result
                }
        except Exception as e:
            logger.error(f"Naabu error: {e}")
        
        return None

    def _scan_nmap(
        self,
        host: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run nmap for port scanning (fallback)"""
        if progress_cb:
            progress_cb("toolkit", "nmap", "running")
        
        try:
            ret, stdout, _ = run_command(
                ["nmap", "-sV", "-Pn", "--top-ports", "100", "--open", host],
                timeout=180
            )
            if progress_cb:
                progress_cb("toolkit", "nmap", "done" if ret == 0 else "failed")
            
            if ret == 0 and stdout:
                logger.info(f"[NMAP] Port scan completed on {host}")
                return {
                    "tool": "nmap",
                    "host": host,
                    "severity": "INFO",
                    "output": stdout[:2000]
                }
        except Exception as e:
            logger.error(f"Nmap error: {e}")
        
        return None

    def _scan_dirbusting(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run directory brute-forcing"""
        if progress_cb:
            progress_cb("toolkit", "dirbusting", "running")
        
        try:
            result = self.dirbusting_runner.run(url, timeout=180)
            if progress_cb:
                progress_cb("toolkit", "dirbusting", "done" if result.get("success") else "failed")
            
            if result.get("success"):
                found_count = len(result.get("directories", [])) + len(result.get("files", []))
                if found_count > 0:
                    logger.info(f"[DIRBUSTING] Found {found_count} items on {url}")
                    
                    # Log suspicious findings
                    for path in result.get("suspicious", []):
                        logger.warning(f"[DIRBUSTING-SUSPICIOUS] {path}")
                    
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
        if progress_cb:
            progress_cb("toolkit", "ffuf", "running")
        
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
            if progress_cb:
                progress_cb("toolkit", "ffuf", "done" if ret == 0 else "failed")
            
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
        if progress_cb:
            progress_cb("toolkit", "api_scanner", "running")
        
        try:
            result = self.api_scanner.scan(url)
            if progress_cb:
                progress_cb("toolkit", "api_scanner", "done")
            
            if result.get("apis_found"):
                logger.info(f"[API] Found {len(result.get('apis_found', []))} API endpoints")
                
                # Log vulnerabilities
                for vuln in result.get("vulnerabilities", []):
                    logger.warning(f"[API-VULN] {vuln.get('type')} ({vuln.get('severity')})")
                
                return {
                    "tool": "api_scanner",
                    "url": url,
                    "severity": "MEDIUM" if result.get("vulnerabilities") else "INFO",
                    "data": result
                }
        except Exception as e:
            logger.error(f"API scanner error: {e}")
        
        return None

