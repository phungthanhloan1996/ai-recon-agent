"""
integrations/httpx_runner.py - Fast HTTP Probing with httpx (ProjectDiscovery)
Efficient live host detection using httpx (Go-based, much faster than Python HTTP clients)
"""

import subprocess
import json
import logging
import os
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger("recon.httpx")


def _decode_output(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


class HttpxRunner:
    """Run httpx for fast HTTP probing - optimized for live host detection"""

    def __init__(self, output_dir: str = None):
        self.output_dir = output_dir
        # Find httpx binary - prefer Go-installed version
        self.httpx_path = self._find_httpx()

    def _find_httpx(self) -> str:
        """Find httpx binary in common locations"""
        candidates = [
            os.path.expanduser("~/go/bin/httpx"),  # Go-installed
            "/usr/local/bin/httpx",
            "/usr/bin/httpx",
            os.path.expanduser("~/.local/bin/httpx"),
        ]
        for path in candidates:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                # Verify it's ProjectDiscovery httpx (not Python httpx)
                try:
                    result = subprocess.run(
                        [path, "-version"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    # ProjectDiscovery httpx outputs version to stderr
                    output = (result.stdout + result.stderr).lower()
                    if "projectdiscovery" in output or ("httpx" in output and "version" in output):
                        logger.debug(f"[HTTPX] Found ProjectDiscovery httpx at {path}")
                        return path
                except Exception:
                    continue
        # Fallback to PATH lookup
        return "httpx"

    def is_available(self) -> bool:
        """Check if httpx is available"""
        try:
            result = subprocess.run(
                [self.httpx_path, "-version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def probe_hosts(self, targets: List[str], 
                    timeout: int = 10,
                    threads: int = 50,
                    rate_limit: int = 150,
                    follow_redirects: bool = True,
                    max_redirects: int = 3,
                    ports: List[int] = None,
                    tech_detect: bool = False,
                    extract_title: bool = True,
                    status_code: bool = True,
                    content_type: bool = True,
                    content_length: bool = False,
                    response_time: bool = True,
                    web_server: bool = True,
                    ip_resolve: bool = True,
                    filter_codes: List[int] = None,
                    match_codes: List[int] = None,
                    ) -> List[Dict[str, Any]]:
        """
        Probe multiple hosts for HTTP connectivity.
        
        Args:
            targets: List of target URLs/domains to probe
            timeout: Timeout in seconds per probe
            threads: Number of concurrent threads
            rate_limit: Max requests per second
            follow_redirects: Whether to follow redirects
            max_redirects: Max redirects to follow
            ports: Optional list of ports to probe
            tech_detect: Enable technology detection
            extract_title: Extract page title
            status_code: Include status code in output
            content_type: Include content-type in output
            content_length: Include content-length in output
            response_time: Include response time in output
            web_server: Extract web server header
            ip_resolve: Resolve IP addresses
            filter_codes: Filter out these status codes
            match_codes: Only keep these status codes
            
        Returns:
            List of dicts containing probe results for live hosts
        """
        if not targets or not self.is_available():
            logger.warning("[HTTPX] httpx not available or no targets provided")
            return []

        results = []
        
        # Build command
        cmd = [
            self.httpx_path,
            "-silent",  # Suppress banner
            "-json",    # JSON output for easy parsing
            "-timeout", str(timeout),
            "-threads", str(min(threads, len(targets))),
            "-rate-limit", str(rate_limit),
        ]

        # Optional probes
        if status_code:
            cmd.append("-sc")
        if content_type:
            cmd.append("-ct")
        if content_length:
            cmd.append("-cl")
        if response_time:
            cmd.append("-rt")
        if extract_title:
            cmd.append("-title")
        if web_server:
            cmd.append("-server")
        if ip_resolve:
            cmd.append("-ip")
        if tech_detect:
            cmd.append("-td")

        # Redirect handling
        if follow_redirects:
            cmd.append("-fr")
            cmd.extend(["-maxr", str(max_redirects)])

        # Port filtering
        if ports:
            port_str = ",".join(str(p) for p in ports)
            cmd.extend(["-p", port_str])

        # Status code filtering
        if filter_codes:
            cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])
        if match_codes:
            cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])

        # Add targets via stdin for efficiency
        try:
            input_data = "\n".join(targets)
            result = subprocess.run(
                cmd,
                input=input_data.encode("utf-8"),
                capture_output=True,
                text=False,
                timeout=max(timeout * len(targets) // threads + 30, 300)  # Adaptive timeout
            )

            if result.returncode == 0:
                results = self._parse_json_output(_decode_output(result.stdout))
                logger.info(f"[HTTPX] Probed {len(targets)} targets, found {len(results)} live hosts")
            else:
                logger.warning(f"[HTTPX] httpx returned non-zero: {_decode_output(result.stderr)[:200]}")

        except subprocess.TimeoutExpired:
            logger.warning("[HTTPX] httpx timed out, returning partial results")
        except Exception as e:
            logger.error(f"[HTTPX] Error running httpx: {e}")

        return results

    def probe_hosts_from_file(self, input_file: str,
                              output_file: str = None,
                              timeout: int = 10,
                              threads: int = 50,
                              **kwargs) -> List[Dict[str, Any]]:
        """
        Probe hosts from a file.
        
        Args:
            input_file: Path to file containing targets (one per line)
            output_file: Optional path to save JSON output
            timeout: Timeout in seconds
            threads: Number of threads
            **kwargs: Additional arguments passed to probe_hosts
            
        Returns:
            List of probe results
        """
        if not os.path.isfile(input_file):
            logger.error(f"[HTTPX] Input file not found: {input_file}")
            return []

        with open(input_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]

        return self.probe_hosts(targets, timeout=timeout, threads=threads, **kwargs)

    def _parse_json_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse httpx JSONL output"""
        results = []
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                # Normalize the output format
                result = {
                    "url": entry.get("url", ""),
                    "host": entry.get("host", ""),
                    "status_code": entry.get("status_code", 0),
                    "title": entry.get("title", ""),
                    "content_type": entry.get("content_type", ""),
                    "content_length": entry.get("content_length", 0),
                    "response_time": entry.get("response_time_seconds", 0) or entry.get("response_time", 0),
                    "web_server": entry.get("webserver", "") or entry.get("server", ""),
                    "ip": entry.get("host_ip", "") or entry.get("ip", ""),
                    "tech": entry.get("tech", []),
                    "final_url": entry.get("final_url", ""),
                    "chain": entry.get("chain", []),
                    "scheme": entry.get("scheme", ""),
                    "port": entry.get("port", 0),
                    "path": entry.get("path", ""),
                    "raw_headers": entry.get("header", {}),
                }
                results.append(result)
            except json.JSONDecodeError:
                logger.debug(f"[HTTPX] Failed to parse line: {line[:100]}")
            except Exception as e:
                logger.debug(f"[HTTPX] Error processing entry: {e}")

        return results

    def quick_probe(self, targets: List[str], timeout: int = 5) -> List[Dict[str, Any]]:
        """
        Quick probe for live host detection - optimized for speed.
        Uses aggressive settings for fast results.
        """
        return self.probe_hosts(
            targets,
            timeout=timeout,
            threads=100,
            rate_limit=300,
            follow_redirects=True,
            max_redirects=2,
            tech_detect=False,  # Skip tech detect for speed
            extract_title=True,
            status_code=True,
            content_type=False,
            content_length=False,
            response_time=True,
            web_server=True,
            ip_resolve=True,
            # Only consider 2xx and 3xx as live
            match_codes=[200, 201, 202, 203, 204, 206, 301, 302, 303, 307, 308],
        )

    def validate_live_hosts(self, urls: List[str], timeout: int = 8) -> List[Dict[str, Any]]:
        """
        Validate which hosts are live - primary method for recon pipeline.
        Optimized for accuracy while maintaining speed.
        """
        if not urls:
            return []

        logger.info(f"[HTTPX] Validating {len(urls)} hosts with httpx...")
        
        # Use quick probe for initial validation
        results = self.quick_probe(urls, timeout=timeout)
        
        # Log summary
        status_codes = {}
        for r in results:
            code = r.get("status_code", 0)
            status_codes[code] = status_codes.get(code, 0) + 1
        
        logger.info(f"[HTTPX] Live hosts by status: {status_codes}")
        
        # Save results to file if output_dir is set
        if self.output_dir and results:
            self._save_results(urls, results)
            return self._load_saved_results()
        
        return results

    def _save_results(self, urls: List[str], results: List[Dict[str, Any]]):
        """Save probe results to file in output directory"""
        if not self.output_dir:
            return
        
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            
            # Save as JSON for structured data
            json_file = os.path.join(self.output_dir, "httpx_results.json")
            data = {
                "timestamp": __import__('time').time(),
                "total_urls_checked": len(urls),
                "live_hosts_count": len(results),
                "results": results
            }
            with open(json_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"[HTTPX] Saved {len(results)} results to {json_file}")
            
            # Also save live URLs as text file (one per line)
            text_file = os.path.join(self.output_dir, "live_hosts.txt")
            live_urls = [r.get("url", "") for r in results if r.get("url")]
            with open(text_file, 'w') as f:
                f.write('\n'.join(live_urls))
            logger.debug(f"[HTTPX] Saved {len(live_urls)} live URLs to {text_file}")
            
        except Exception as e:
            logger.error(f"[HTTPX] Failed to save results: {e}")

    def _load_saved_results(self) -> List[Dict[str, Any]]:
        """Read saved JSON results back from disk and return the parsed result list."""
        if not self.output_dir:
            return []

        json_file = os.path.join(self.output_dir, "httpx_results.json")
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data.get("results", [])
        except Exception as e:
            logger.error(f"[HTTPX] Failed to read saved JSON results: {e}")
        return []

    def dns_verify(self, targets: List[str], timeout: int = 5,
                   threads: int = 100, rate_limit: int = 300) -> Dict[str, Dict[str, Any]]:
        """
        DNS verification using httpx - optimized for speed and accuracy.
        Uses httpx's DNS resolution capabilities to verify host existence.
        
        Args:
            targets: List of target domains/URLs to verify
            timeout: DNS timeout in seconds
            threads: Number of concurrent DNS threads
            rate_limit: Max DNS requests per second
            
        Returns:
            Dictionary mapping hostnames to DNS verification results:
            {
                "example.com": {
                    "resolved": True,
                    "ip": "93.184.216.34",
                    "response_time": 0.123,
                    "status": "live",
                    "error": None
                },
                ...
            }
        """
        if not targets or not self.is_available():
            logger.warning("[HTTPX] httpx not available for DNS verification")
            return {}

        results = {}
        
        # Build httpx command for DNS-only verification
        cmd = [
            self.httpx_path,
            "-silent",
            "-json",
            "-timeout", str(timeout),
            "-threads", str(min(threads, len(targets))),
            "-rate-limit", str(rate_limit),
            "-sc",          # Status code
            "-ip",          # Resolve IP
            "-title",       # Extract title
            "-server",      # Web server header
            "-rt",          # Response time
            "-no-body",     # Skip body for speed (DNS-focused)
        ]
        
        try:
            input_data = "\n".join(targets)
            result = subprocess.run(
                cmd,
                input=input_data.encode("utf-8"),
                capture_output=True,
                text=False,
                timeout=max(timeout * len(targets) // threads + 30, 180)
            )
            
            if result.returncode == 0:
                for line in _decode_output(result.stdout).strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        host = entry.get("host", "") or entry.get("url", "")
                        ip = entry.get("host_ip", "") or entry.get("ip", "")
                        
                        results[host] = {
                            "resolved": bool(ip),
                            "ip": ip,
                            "status_code": entry.get("status_code", 0),
                            "title": entry.get("title", ""),
                            "web_server": entry.get("webserver", "") or entry.get("server", ""),
                            "response_time": entry.get("response_time_seconds", 0) or entry.get("response_time", 0),
                            "status": "live" if entry.get("status_code", 0) >= 200 else "unreachable",
                            "error": None,
                        }
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.debug(f"[HTTPX] DNS verify parse error: {e}")
            else:
                logger.warning(f"[HTTPX] DNS verify failed: {_decode_output(result.stderr)[:200]}")
                
        except subprocess.TimeoutExpired:
            logger.warning("[HTTPX] DNS verify timed out")
        except Exception as e:
            logger.error(f"[HTTPX] DNS verify error: {e}")
        
        # Mark unresolved hosts
        for target in targets:
            host = target.split("/")[2] if "/" in target else target
            if host not in results:
                results[host] = {
                    "resolved": False,
                    "ip": "",
                    "status_code": 0,
                    "title": "",
                    "web_server": "",
                    "response_time": 0,
                    "status": "dead",
                    "error": "DNS resolution failed or host unreachable"
                }
        
        # Log summary
        resolved = sum(1 for r in results.values() if r["resolved"])
        live = sum(1 for r in results.values() if r["status"] == "live")
        logger.info(f"[HTTPX] DNS verify: {len(targets)} targets, {resolved} resolved, {live} live")
        
        return results

    def dns_verify_fast(self, targets: List[str]) -> Dict[str, bool]:
        """
        Ultra-fast DNS verification - returns only resolved/unresolved status.
        Uses aggressive settings for maximum speed.
        
        Args:
            targets: List of target domains/URLs
            
        Returns:
            Dictionary mapping hostnames to boolean (True = resolved/live)
        """
        if not targets or not self.is_available():
            return {}
        
        # Use minimal httpx settings for speed
        cmd = [
            self.httpx_path,
            "-silent",
            "-json",
            "-timeout", "3",
            "-threads", "200",
            "-rate-limit", "500",
            "-sc",
            "-ip",
            "-no-body",
            "-fr",  # Follow redirects
            "-maxr", "1",  # Max 1 redirect
        ]
        
        results = {}
        
        try:
            input_data = "\n".join(targets)
            result = subprocess.run(
                cmd,
                input=input_data.encode("utf-8"),
                capture_output=True,
                text=False,
                timeout=120
            )
            
            if result.returncode == 0:
                for line in _decode_output(result.stdout).strip().split("\n"):
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        host = entry.get("host", "") or entry.get("url", "")
                        ip = entry.get("host_ip", "") or entry.get("ip", "")
                        status_code = entry.get("status_code", 0)
                        
                        # Consider resolved if we got an IP and valid status code
                        results[host] = bool(ip) and (200 <= status_code < 500)
                    except (json.JSONDecodeError, Exception):
                        continue
        
        except (subprocess.TimeoutExpired, Exception) as e:
            logger.warning(f"[HTTPX] Fast DNS verify error: {e}")
        
        # Mark unresolved
        for target in targets:
            host = target.split("/")[2] if "/" in target else target
            if host not in results:
                results[host] = False
        
        return results

    def verify_dns_with_fallback(self, targets: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        DNS verification with fallback mechanisms.
        First tries httpx, then falls back to system DNS if needed.
        
        Args:
            targets: List of target domains/URLs
            
        Returns:
            Comprehensive DNS verification results
        """
        if not targets:
            return {}
        
        results = {}
        
        # Phase 1: Try httpx for all targets
        logger.info(f"[HTTPX] Phase 1: httpx DNS verification for {len(targets)} targets")
        httpx_results = self.dns_verify(targets, timeout=5, threads=100)
        
        for host, result in httpx_results.items():
            results[host] = result
        
        # Phase 2: For unresolved hosts, try with longer timeout
        unresolved = [h for h, r in results.items() if not r.get("resolved", False)]
        if unresolved:
            logger.info(f"[HTTPX] Phase 2: Retry {len(unresolved)} unresolved hosts with longer timeout")
            retry_results = self.dns_verify(unresolved, timeout=10, threads=50)
            for host, result in retry_results.items():
                if result.get("resolved", False):
                    results[host] = result
        
        # Log final summary
        resolved_count = sum(1 for r in results.values() if r.get("resolved", False))
        live_count = sum(1 for r in results.values() if r.get("status") == "live")
        logger.info(f"[HTTPX] DNS verify complete: {resolved_count} resolved, {live_count} live out of {len(targets)}")
        
        return results

    def get_live_hosts_only(self, urls: List[str]) -> List[str]:
        """
        Quick filter to return only live hosts from a list.
        Optimized for use in pipelines where only live hosts are needed.
        
        Args:
            urls: List of URLs to filter
            
        Returns:
            List of URLs that are confirmed live
        """
        if not urls:
            return []
        
        results = self.quick_probe(urls, timeout=5)
        live_urls = [r.get("url", "") for r in results if r.get("status_code", 0) >= 200 and r.get("status_code", 0) < 500]
        
        logger.info(f"[HTTPX] Filtered {len(urls)} URLs -> {len(live_urls)} live hosts")
        return live_urls
