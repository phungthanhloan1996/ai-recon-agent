import urllib.parse
"""
modules/toolkit_scanner.py - External Kali toolkit orchestration.
Runs high-value scanners on selected live hosts.
"""

import json
import logging
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Callable, Optional
from urllib.parse import urlparse

from core.executor import run_command, tool_available
from core.state_manager import StateManager
from core.http_engine import HTTPClient
from core.scan_deduplicator import ScanDeduplicator
from core.scan_optimizer import get_optimizer
from core.resource_manager import get_result_cache, get_concurrency_manager, get_nuclei_pool
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
        
        # Initialize deduplicator to prevent redundant scanning
        self.deduplicator = ScanDeduplicator(output_dir, ttl_hours=24)
        
        # FIX #4 & #5: Initialize result cache for nmap and wappalyzer (TTL=1 hour)
        self.result_cache = get_result_cache(default_ttl=3600)
        
        # Resource Management: Initialize global concurrency manager
        # Controls max concurrent heavy operations across all tools
        toolkit_workers = int(self.budget.get("toolkit_parallel_tools", 4))
        self.concurrency = get_concurrency_manager(max_concurrent=20)
        
        # Resource Management: Initialize Nuclei worker pool for vulnerability scanning
        # Uses adaptive timeouts and worker limits to prevent resource exhaustion
        nuclei_workers = int(self.budget.get("nuclei_workers", 3))
        self.nuclei_pool = get_nuclei_pool(max_workers=nuclei_workers, default_timeout=300)
        
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
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        per_host_timeout: int = 180,
    ) -> List[Dict[str, Any]]:
        if not live_hosts:
            return []
        host_urls = self._select_high_value_hosts(live_hosts)
        host_limit = int(self.budget.get("toolkit_hosts", 8))
        host_urls = host_urls[:host_limit]
        findings: List[Dict[str, Any]] = []

        total_hosts = len(host_urls)
        for host_idx, url in enumerate(host_urls, 1):
            logger.info(
                "[TOOLKIT] [%d/%d] Scanning host: %s", host_idx, total_hosts, url
            )
            _t0 = time.time()
            # Per-host timeout: prevent one slow host from blocking the rest.
            # IMPORTANT: do NOT use `with ThreadPoolExecutor(...) as pool:` here —
            # the context manager calls shutdown(wait=True) on exit, which blocks
            # until the thread finishes even after result(timeout=...) raises.
            # Instead, call shutdown(wait=False) on timeout so we move to the next host.
            _host_pool = ThreadPoolExecutor(max_workers=1)
            _host_fut = _host_pool.submit(self._run_host_tools, url, progress_cb)
            try:
                host_findings = _host_fut.result(timeout=per_host_timeout)
                _host_pool.shutdown(wait=False)
            except Exception as _exc:
                _kind = "timeout" if "TimeoutError" in type(_exc).__name__ or isinstance(_exc, TimeoutError) else "error"
                logger.warning(
                    "[TOOLKIT] [%d/%d] %s on %s after %.0fs — skipping",
                    host_idx, total_hosts, _kind, url, time.time() - _t0,
                )
                _host_pool.shutdown(wait=False)   # abandon thread, do NOT wait
                host_findings = []
            _elapsed = time.time() - _t0
            logger.info(
                "[TOOLKIT] [%d/%d] Done in %.0fs — %d findings: %s",
                host_idx,
                total_hosts,
                _elapsed,
                len(host_findings),
                url,
            )
            findings.extend(host_findings)
            # Save partial results to state after each host so timeouts don't lose data
            self.state.update(external_findings=findings)
            with open(self.results_file, "w") as f:
                json.dump(findings, f, indent=2)

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

    def _normalize_url_to_root(self, url: str) -> str:
        """
        Normalize URL to root domain path for dirbusting.
        
        FIX: This prevents dirbusting on WordPress archive paths like
        /2021/03/ or /2022/10/ which are static and not useful targets.
        
        Args:
            url: Original URL
            
        Returns:
            URL normalized to root path
        """
        parsed = urllib.parse.urlparse(url)
        
        # WordPress year/month archive pattern: /YYYY/MM/ or /YYYY/MM/DD/
        wp_archive_pattern = re.compile(r'^/\d{4}/\d{2}(/d{2})?/?$')
        
        # If path matches WordPress archive pattern, normalize to root
        if parsed.path and wp_archive_pattern.match(parsed.path):
            logger.debug(f"[TOOLKIT] Normalizing WordPress archive path: {url} -> root")
            return f"{parsed.scheme}://{parsed.netloc}/"
        
        # WordPress category/tag paths: /category/xxx, /tag/xxx
        wp_taxonomy_paths = ['/category/', '/tag/', '/author/']
        path_lower = parsed.path.lower()
        
        for wp_path in wp_taxonomy_paths:
            if wp_path in path_lower:
                # Check if it's a deeply nested taxonomy path
                path_parts = parsed.path.strip('/').split('/')
                if len(path_parts) > 2:
                    logger.debug(f"[TOOLKIT] Normalizing WordPress taxonomy path: {url} -> root")
                    return f"{parsed.scheme}://{parsed.netloc}/"
                break
        
        # If path is deeply nested (>3 levels), normalize to root
        if parsed.path:
            path_depth = len([p for p in parsed.path.split('/') if p])
            if path_depth > 3:
                logger.debug(f"[TOOLKIT] Normalizing deeply nested path (depth={path_depth}): {url} -> root")
                return f"{parsed.scheme}://{parsed.netloc}/"
        
        return url
    
    def _select_high_value_hosts(self, live_hosts: List[Dict[str, Any]]) -> List[str]:
        """Select high-value hosts for scanning, with deduplication, static file filtering, and optimizer blacklist check.
        
        FIX: Added URL normalization to prevent dirbusting on WordPress archive paths.
        """
        scored: List[tuple[int, str]] = []
        optimizer = get_optimizer()
        
        # Static file extensions to skip
        static_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.svg', '.map'}
        
        # WordPress static paths to skip (but allow PHP files)
        wp_static_paths = ['/wp-content/uploads/', '/wp-includes/', '/wp-content/cache/']
        
        # WordPress archive patterns to normalize to root
        wp_archive_patterns = [
            re.compile(r'^/\d{4}/\d{2}(/d{2})?/?$'),  # /YYYY/MM/ or /YYYY/MM/DD/
        ]
        
        # WordPress taxonomy paths that should be normalized
        wp_taxonomy_prefixes = ['/category/', '/tag/', '/author/']
        
        for h in live_hosts:
            u = h.get("url", "")
            if not u:
                continue
            
            parsed = urllib.parse.urlparse(u)
            original_path = parsed.path
            path = original_path.lower()
            url_lower = u.lower()
            
            # FIX: Normalize URL to root if it matches problematic patterns
            should_normalize = False
            
            # Check WordPress archive patterns
            for pattern in wp_archive_patterns:
                if pattern.match(original_path):
                    should_normalize = True
                    logger.debug(f"[TOOLKIT] Detected WordPress archive path: {u}")
                    break
            
            # Check WordPress taxonomy paths (deeply nested)
            if not should_normalize:
                for prefix in wp_taxonomy_prefixes:
                    if prefix in path:
                        path_parts = original_path.strip('/').split('/')
                        if len(path_parts) > 2:
                            should_normalize = True
                            logger.debug(f"[TOOLKIT] Detected WordPress taxonomy path: {u}")
                            break
            
            # Check deeply nested paths
            if not should_normalize and original_path:
                path_depth = len([p for p in original_path.split('/') if p])
                if path_depth > 3:
                    should_normalize = True
                    logger.debug(f"[TOOLKIT] Detected deeply nested path (depth={path_depth}): {u}")
            
            # Normalize to root if needed
            if should_normalize:
                u = f"{parsed.scheme}://{parsed.netloc}/"
                parsed = urllib.parse.urlparse(u)
                path = "/"
                url_lower = u.lower()
            
            # Skip already scanned hosts (deduplication)
            hostname = parsed.hostname or parsed.netloc
            
            # Check optimizer blacklist first
            if optimizer.is_host_blacklisted(hostname):
                logger.debug(f"[TOOLKIT] Skipping blacklisted host: {hostname}")
                continue
            
            if self.deduplicator.is_host_scanned(hostname):
                logger.debug(f"[TOOLKIT] Skipping already scanned host: {hostname}")
                continue
            
            # Skip static file extensions
            if any(path.endswith(ext) for ext in static_extensions):
                logger.debug(f"[TOOLKIT] Skipping static file: {u}")
                continue
            
            # Skip WordPress static paths (but allow PHP files in uploads)
            skip_wp_static = False
            for wp_path in wp_static_paths:
                if wp_path in url_lower:
                    # Allow PHP files in uploads (potential shells)
                    if '/wp-content/uploads/' in url_lower and path.endswith('.php'):
                        continue
                    skip_wp_static = True
                    break
            if skip_wp_static:
                logger.debug(f"[TOOLKIT] Skipping WordPress static path: {u}")
                continue
            
            # Skip API-only endpoints that are better handled by API scanner
            if any(k in url_lower for k in ('wp-json', 'oembed', 'embed', 'feed', 'xmlrpc')):
                # But don't skip if it has other high-value indicators
                if not any(k in url_lower for k in ("admin", "login", "upload")):
                    continue
            
            # Calculate score
            s = 0
            st = int(h.get("status_code", 0) or 0)
            if st == 200:
                s += 35
            elif 300 <= st < 400:
                s += 20
            elif 400 <= st < 500:
                s += 15
            
            if any(k in url_lower for k in ("admin", "login", "wp-admin", "api", "graphql")):
                s += 25
            if any(k in url_lower for k in ("staging", "dev", "test", "beta")):
                s += 12
            
            # Bonus for having parameters
            if parsed.query:
                s += 10
            
            # Bonus for executable file types
            if any(path.endswith(ext) for ext in ('.php', '.asp', '.aspx', '.jsp', '.cgi')):
                s += 8
            
            scored.append((s, u))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        selected = list(dict.fromkeys([u for _, u in scored]))  # Remove duplicates while preserving order
        
        logger.info(f"[TOOLKIT] Selected {len(selected)}/{len(live_hosts)} high-value hosts for scanning")
        return selected

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
        
        # Whatweb - advanced technology detection with CVE matching (optimized timeout)
        jobs.append(("whatweb", lambda: self._scan_whatweb(url, progress_cb, timeout=90)))
        
        # Wappalyzer - comprehensive tech fingerprinting
        jobs.append(("wappalyzer", lambda: self._scan_wappalyzer(url, progress_cb)))
        
        # WAF detection (optimized timeout)
        if tool_available("wafw00f"):
            jobs.append(("wafw00f", lambda: self._scan_wafw00f(url, progress_cb, timeout=60)))
        
        # Nikto - web server vulnerability scanner (optimized timeout)
        if tool_available("nikto"):
            jobs.append(("nikto", lambda: self._scan_nikto(url, progress_cb, timeout=120)))
        
        # Naabu - fast port scanning (if naabu is available, optimized timeout)
        if explicit_port is not None and tool_available("nmap"):
            jobs.append(("nmap", lambda: self._scan_nmap(host, explicit_port, progress_cb, timeout=90)))
        elif tool_available("naabu"):
            jobs.append(("naabu", lambda: self._scan_naabu(host, progress_cb, timeout=90)))
        elif tool_available("nmap"):
            # Fallback to nmap with optimized timeout
            jobs.append(("nmap", lambda: self._scan_nmap(host, None, progress_cb, timeout=90)))
        
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
        parsed = urllib.parse.urlparse(url)
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
        """Run whatweb scanner with concurrency control"""
        self._notify_progress(progress_cb, "whatweb", "running", "whatweb: detecting technologies...")
        
        # Resource Management: Acquire concurrency slot for heavy operation
        operation_id = f"whatweb_{hash(url)}"
        if not self.concurrency.acquire(operation_id, timeout=300):
            logger.warning(f"[TOOLKIT] Could not acquire concurrency slot for whatweb on {url}")
            return {"tool": "whatweb", "url": url, "severity": "INFO", "success": False, "error": "Concurrency limit reached"}
        
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
                # Build human-readable output for the report generator
                tech_lines = []
                for tech in result.get("technologies", []):
                    name = tech.get("name", "")
                    version = tech.get("version", "")
                    category = tech.get("category", "")
                    tech_lines.append(f"  [{category}] {name}" + (f" v{version}" if version else ""))
                for vuln in result.get("vulnerabilities", []):
                    tech_lines.append(f"  [CVE] {vuln.get('cve')} in {vuln.get('technology')} {vuln.get('version')} ({vuln.get('severity')})")
                output_text = "\n".join(tech_lines) if tech_lines else "(no technologies detected)"
                return {
                    "tool": "whatweb",
                    "url": url,
                    "severity": "INFO",
                    "success": True,
                    "output": output_text,
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
        finally:
            # Resource Management: Always release concurrency slot
            self.concurrency.release(operation_id)
        
        return None

    def _scan_wappalyzer(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Optional[Dict[str, Any]]:
        """Run wappalyzer scanner with caching and concurrency control"""
        
        # FIX #5: Check cache first
        cache_key = f"wappalyzer:{url}"
        cached_result = self.result_cache.get(cache_key)
        if cached_result is not None:
            logger.info(f"[WAPPALYZER] Using cached result for {url}")
            self._notify_progress(progress_cb, "wappalyzer", "cached", f"wappalyzer: using cached result")
            return cached_result
        
        self._notify_progress(progress_cb, "wappalyzer", "running", "wappalyzer: fingerprinting stack...")
        
        # Resource Management: Acquire concurrency slot for heavy operation
        operation_id = f"wappalyzer_{hash(url)}"
        if not self.concurrency.acquire(operation_id, timeout=300):
            logger.warning(f"[TOOLKIT] Could not acquire concurrency slot for wappalyzer on {url}")
            return {"tool": "wappalyzer", "url": url, "severity": "INFO", "success": False, "error": "Concurrency limit reached"}
        
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

                # Build human-readable output for the report generator
                tech_list = result.get("technologies", [])
                version_info = result.get("version_info", {})
                tech_lines = []
                for tech in tech_list:
                    ver = version_info.get(tech, "")
                    tech_lines.append(f"  {tech}" + (f" v{ver}" if ver else ""))
                output_text = "\n".join(tech_lines) if tech_lines else "(no technologies detected)"

                response = {
                    "tool": "wappalyzer",
                    "url": url,
                    "severity": "INFO",
                    "output": output_text,
                    "data": result
                }
                
                # FIX #5: Cache successful results
                self.result_cache.set(cache_key, response, ttl=3600)
                logger.debug(f"[CACHE] Cached wappalyzer result for {url}")
                
                return response
        except Exception as e:
            logger.error(f"Wappalyzer error: {e}")
        finally:
            # Resource Management: Always release concurrency slot
            self.concurrency.release(operation_id)
        
        return None

    def _scan_wafw00f(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 60
    ) -> Optional[Dict[str, Any]]:
        """Run WAF detection - FIXED: removed --nocolor flag (not supported in newer versions)"""
        self._notify_progress(progress_cb, "wafw00f", "running", "wafw00f: detecting web application firewall...")
        
        try:
            # FIXED: Removed --nocolor flag - not supported in newer wafw00f versions
            # FIXED: Reduced timeout to 60s (was 90s)
            ret, stdout, stderr = run_command(
                ["wafw00f", "-a", url], 
                timeout=timeout
            )
            
            # FIXED: Handle various exit codes gracefully
            if ret == 0 and stdout:
                severity = "LOW" if "No WAF detected" in stdout else "INFO"
                logger.info(f"[WAFW00F] WAF Detection: {'Found' if severity == 'INFO' else 'Not Found'} for {url}")
                self._notify_progress(progress_cb, "wafw00f", "done", f"wafw00f: {'WAF detected' if severity == 'INFO' else 'no WAF'}")
                return {
                    "tool": "wafw00f",
                    "url": url,
                    "severity": severity,
                    "output": stdout[:2000],
                    "success": True
                }
            elif ret == -2 or (stderr and "Traceback" in stderr):
                # FIXED: Handle Python crashes gracefully
                logger.warning(f"[WAFW00F] Tool crashed for {url} (exit code: {ret})")
                self._notify_progress(progress_cb, "wafw00f", "crashed", "wafw00f: tool crashed")
                return {
                    "tool": "wafw00f",
                    "url": url,
                    "severity": "LOW",
                    "output": f"[TOOL CRASH] wafw00f exited with code {ret}. stderr: {stderr[:500] if stderr else 'N/A'}",
                    "success": False,
                    "error": f"wafw00f crashed (exit code: {ret})"
                }
            else:
                logger.warning(f"[WAFW00F] Scan incomplete for {url} (return code: {ret})")
                self._notify_progress(progress_cb, "wafw00f", "failed", f"wafw00f: exit code {ret}")
                return {
                    "tool": "wafw00f",
                    "url": url,
                    "severity": "LOW",
                    "output": (stdout or "")[:1000] + (stderr or "")[:500],
                    "success": False
                }
        except subprocess.TimeoutExpired:
            logger.warning(f"[WAFW00F] Timeout for {url}")
            self._notify_progress(progress_cb, "wafw00f", "timeout", "wafw00f: timed out")
            return {
                "tool": "wafw00f",
                "url": url,
                "severity": "LOW",
                "output": "[TIMEOUT] wafw00f exceeded time limit",
                "success": False,
                "error": "Timeout"
            }
        except Exception as e:
            logger.error(f"[WAFW00F] Error for {url}: {e}")
            self._notify_progress(progress_cb, "wafw00f", "error", f"wafw00f: {str(e)[:50]}")
            return {
                "tool": "wafw00f",
                "url": url,
                "severity": "LOW",
                "success": False,
                "error": str(e)
            }

    def _scan_nikto(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 600
    ) -> Optional[Dict[str, Any]]:
        """Run nikto vulnerability scanner - FIXED with better error handling and increased timeout"""
        self._notify_progress(progress_cb, "nikto", "running", "nikto: probing web server misconfigurations...")
        
        try:
            # FIXED: Prepare output file path with sanitized name
            safe_url = url.replace(':', '_').replace('/', '_').replace('.', '_')[:50]
            output_file = os.path.join(self.output_dir, f"nikto_{safe_url}.json")
            
            # Derive -maxtime from subprocess timeout (leave 10s headroom for init/teardown)
            nikto_maxtime = max(30, timeout - 10)
            nikto_maxtime_str = f"{nikto_maxtime}s"
            ret, stdout, stderr = run_command(
                ["nikto", "-host", url, "-maxtime", nikto_maxtime_str, "-timeout", "20", "-Format", "json", "-o", output_file],
                timeout=timeout
            )
            
            # FIXED: Handle various exit codes gracefully
            if ret == 0 and os.path.exists(output_file):
                logger.info(f"[NIKTO] Scan completed on {url}, saved to {output_file}")
                self._notify_progress(progress_cb, "nikto", "done", f"nikto: scan finished, saved to {output_file}")
                return {
                    "tool": "nikto",
                    "url": url,
                    "severity": "MEDIUM",
                    "output_file": output_file,
                    "success": True
                }
            elif ret == 1 or (stderr and "error" in stderr.lower()):
                # FIXED: Handle nikto errors gracefully (exit code 1)
                logger.warning(f"[NIKTO] Scan failed for {url} (exit code: {ret})")
                self._notify_progress(progress_cb, "nikto", "failed", f"nikto: exit code {ret}")
                return {
                    "tool": "nikto",
                    "url": url,
                    "severity": "LOW",
                    "output": f"[ERROR] nikto exited with code {ret}. stderr: {stderr[:500] if stderr else 'N/A'}",
                    "success": False,
                    "error": f"nikto failed (exit code: {ret})"
                }
            else:
                # Check if we got partial results
                has_output = bool(stdout) or os.path.exists(output_file)
                if has_output:
                    logger.warning(f"[NIKTO] Scan incomplete but got partial results for {url} (return code: {ret})")
                    self._notify_progress(progress_cb, "nikto", "partial", f"nikto: partial results")
                    return {
                        "tool": "nikto",
                        "url": url,
                        "severity": "LOW",
                        "output": (stdout or "")[:1000] + (stderr or "")[:500],
                        "success": True,  # Partial success
                        "partial": True
                    }
                else:
                    logger.warning(f"[NIKTO] Scan incomplete for {url} (return code: {ret})")
                    self._notify_progress(progress_cb, "nikto", "failed", f"nikto: exit code {ret}")
                    return {
                        "tool": "nikto",
                        "url": url,
                        "severity": "LOW",
                        "output": (stdout or "")[:1000] + (stderr or "")[:500],
                        "success": False
                    }
        except subprocess.TimeoutExpired:
            logger.warning(f"[NIKTO] Timeout for {url}")
            self._notify_progress(progress_cb, "nikto", "timeout", "nikto: timed out")
            return {
                "tool": "nikto",
                "url": url,
                "severity": "LOW",
                "output": "[TIMEOUT] nikto exceeded time limit",
                "success": False,
                "error": "Timeout"
            }
        except Exception as e:
            logger.error(f"[NIKTO] Error for {url}: {e}")
            self._notify_progress(progress_cb, "nikto", "error", f"nikto: {str(e)[:50]}")
            return {
                "tool": "nikto",
                "url": url,
                "severity": "LOW",
                "success": False,
                "error": str(e)
            }

    def _scan_naabu(
        self,
        host: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 120
    ) -> Optional[Dict[str, Any]]:
        """Run naabu for fast port scanning with concurrency control"""
        self._notify_progress(progress_cb, "naabu", "running", f"naabu: scanning common ports on {host}...")
        
        # Resource Management: Acquire concurrency slot for heavy operation
        operation_id = f"naabu_{hash(host)}"
        if not self.concurrency.acquire(operation_id, timeout=300):
            logger.warning(f"[TOOLKIT] Could not acquire concurrency slot for naabu on {host}")
            return {"tool": "naabu", "host": host, "severity": "INFO", "success": False, "error": "Concurrency limit reached"}
        
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
        finally:
            # Resource Management: Always release concurrency slot
            self.concurrency.release(operation_id)
        
        return None

    def _scan_nmap(
        self,
        host: str,
        explicit_port: Optional[int] = None,
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        timeout: int = 120
    ) -> Optional[Dict[str, Any]]:
        """Run nmap for port scanning (fallback) - optimized with caching (FIX #4)"""
        port_hint = str(explicit_port) if explicit_port is not None else "top-50"
        
        # FIX #4: Check cache first
        cache_key = f"nmap:{host}:{explicit_port}"
        cached_result = self.result_cache.get(cache_key)
        if cached_result is not None:
            logger.info(f"[NMAP] Using cached result for {host} (ports: {cached_result.get('ports_found', 0)} found)")
            self._notify_progress(progress_cb, "nmap", "cached", f"nmap: using cached result for {host}")
            return cached_result
        
        self._notify_progress(progress_cb, "nmap", "running", f"nmap: scanning ports {port_hint} on {host}...")
        
        # Resource Management: Acquire concurrency slot for heavy operation
        operation_id = f"nmap_{hash(host)}_{explicit_port}"
        if not self.concurrency.acquire(operation_id, timeout=300):
            logger.warning(f"[TOOLKIT] Could not acquire concurrency slot for nmap on {host}")
            return {"tool": "nmap", "host": host, "severity": "INFO", "output": "[CONCURRENCY LIMIT]", "success": False, "error": "Concurrency limit reached"}
        
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
            
            result = None
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
                result = {
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
                result = {
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
                result = {
                    "tool": "nmap",
                    "host": host,
                    "severity": "INFO",
                    "output": stderr[:500] if stderr else "[NO OUTPUT]",
                    "success": False
                }
            
            # FIX #4: Cache successful results
            if result and result.get("success"):
                self.result_cache.set(cache_key, result, ttl=3600)
                logger.debug(f"[CACHE] Cached nmap result for {host}")
            
            return result
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
        finally:
            # Resource Management: Always release concurrency slot
            self.concurrency.release(operation_id)
        
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
        """Run directory brute-forcing with concurrency control"""
        self._notify_progress(progress_cb, "dirbusting", "running", "dirbusting: testing common paths...")
        
        # Resource Management: Acquire concurrency slot for heavy operation
        operation_id = f"dirbusting_{hash(url)}"
        if not self.concurrency.acquire(operation_id, timeout=300):
            logger.warning(f"[TOOLKIT] Could not acquire concurrency slot for dirbusting on {url}")
            return {"tool": "dirbusting", "url": url, "severity": "LOW", "success": False, "error": "Concurrency limit reached"}
        
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
        finally:
            # Resource Management: Always release concurrency slot
            self.concurrency.release(operation_id)
        
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
