"""
modules/recon.py - Recon Engine
External integrations for comprehensive surface discovery
"""

import json
import os
import logging
import ssl
import socket
import time
import posixpath
import ipaddress
from urllib.parse import urlparse
from urllib.parse import urljoin, quote
import urllib.request
from typing import List, Set, Dict, Callable, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
# Thêm dòng này nếu chưa có
import config
from core.state_manager import StateManager
from core.executor import check_tools, run_command, tool_available
from core.host_filter import HostFilter
from integrations.subfinder_runner import SubfinderRunner
from integrations.gau_runner import GAURunner
from integrations.wayback_runner import WaybackRunner
from integrations.httpx_runner import HttpxRunner

logger = logging.getLogger("recon.engine")
# Constants
RECON_TOOLS = ["subfinder", "assetfinder", "crtsh", "gau", "waybackurls"]
STATIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".mp3", ".mp4", ".avi",
    ".mov", ".woff", ".woff2", ".ttf", ".eot", ".css", ".map", ".js"
}

# Free hosting domains to skip early (unlikely to be targets, cause connection failures)
FREE_HOSTING_DOMAINS = {
    "wordpress.com", "blogspot.com", "blogspot.co.uk", "blogspot.fr", "blogspot.de",
    "blogspot.es", "blogspot.it", "blogspot.jp", "blogspot.com.br", "blogspot.in",
    "wixsite.com", "weebly.com", "tumblr.com", "medium.com", "ghost.io",
    "github.io", "gitlab.io", "pages.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "firebaseapp.com", "azurewebsites.net",
    "000webhostapp.com", "infinityfreeapp.com", "rf.gd", "epizy.com",
}

class ReconEngine:
    """
    Comprehensive reconnaissance engine using multiple sources:
    - Subdomain enumeration (passive)
    - Archived URL discovery
    - Live host validation
    """

    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.manifest_file = os.path.join(output_dir, "recon_manifest.json")

        # FIX: ensure target exists
        self.target = state.get("target")

        if not self.target:
            raise ValueError("Target domain not found in state")

        self.raw_target = self.target
        parsed_target = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        self.target_host = parsed_target.hostname or self.target.replace("https://", "").replace("http://", "").strip()
        self.target_port = parsed_target.port
        self.target_scheme = parsed_target.scheme or "https"
        self.target_netloc = parsed_target.netloc or self.target_host
        self.target = self.target_host
        self.is_public_hostname = self._is_public_hostname(self.target_host)
        if config.LOCAL_HTTP_ONLY and not self.is_public_hostname and "://" not in self.raw_target:
            self.target_scheme = "http"

        # Initialize integrations
        self.subfinder = SubfinderRunner(output_dir)
        self.gau = GAURunner(output_dir)
        self.wayback = WaybackRunner(output_dir)
        self.httpx = HttpxRunner(output_dir)
        
        # Get allowed_domains from state (all targets from targets.txt)
        allowed_domains = self.state.get("allowed_domains", [])
        self.host_filter = HostFilter(skip_dev_test=True, allowed_domains=allowed_domains)
        
        self.budget = (self.state.get("scan_metadata", {}) or {}).get("budget", {})
        self.cache_file = os.path.join(os.path.dirname(__file__), "../data/recon_cache.json")

    def run(self, progress_cb: Optional[Callable[[str, str, str], None]] = None):
        """Execute full reconnaissance pipeline"""
        logger.info(f"[RECON] Starting reconnaissance for {self.target}")
        if progress_cb:
            progress_cb("recon", "subfinder+assetfinder+amass+crtsh", "running")
        cache = self._load_recon_cache()
        if cache:
            subdomains = cache.get("subdomains", [])
            archived_urls = cache.get("archived_urls", [])
            self.state.update(subdomains=subdomains, archived_urls=archived_urls)
            if progress_cb:
                progress_cb("recon", "cache", "hit")
        else:
            # Multi-source subdomain discovery
            subdomains = self.discover_subdomains()
            self.state.update(subdomains=subdomains)
            if progress_cb:
                progress_cb("recon", "subfinder+assetfinder+amass+crtsh", "done")
                progress_cb("recon", "wayback+gau+waybackurls", "running")

            # Archived URL discovery
            archived_urls = self.discover_archived_urls()
            self.state.update(archived_urls=archived_urls)
            self._save_recon_cache(subdomains, archived_urls)
            if progress_cb:
                progress_cb("recon", "wayback+gau+waybackurls", "done")

        # Merge and deduplicate
        if progress_cb:
            progress_cb("recon", "url-normalize", "running")
        all_urls = self.merge_url_sources(subdomains, archived_urls)
        self.state.update(urls=all_urls)
        if progress_cb:
            progress_cb("recon", "url-normalize", "done")

        # Validate live hosts
        if progress_cb:
            progress_cb("recon", "http-validate", "running")
        live_hosts = self.validate_live_hosts(all_urls)

        min_live_threshold = getattr(config, 'MIN_LIVE_HOSTS_FOR_FALLBACK', 1)
        if len(live_hosts) < min_live_threshold and len(all_urls) > 100:
            logger.warning(f"[RECON] Only {len(live_hosts)} live hosts, attempting fallback validation")
            live_hosts = self.validate_live_hosts(all_urls[:500], timeout=10)

        self.state.update(live_hosts=live_hosts)
        if progress_cb:
            progress_cb("recon", "http-validate", "done")

        # CRITICAL: Check if we have minimum data to continue
        min_subdomains = 1  # At least the main domain
        min_urls = 1        # At least one URL to work with

        if len(subdomains) < min_subdomains or len(all_urls) < min_urls:
            logger.warning(f"[RECON] ⚠️  LOW DISCOVERY: Only {len(subdomains)} subdomains, {len(all_urls)} URLs")
            logger.info("[RECON] 🔄 Activating fallback discovery methods...")

            # Fallback 1: Direct domain probing
            try:
                fallback_urls = self.fallback_direct_probing()
                if fallback_urls:
                    all_urls.extend(fallback_urls)
                    self.state.update(urls=all_urls)
                    logger.info(f"[RECON] ✅ Fallback added {len(fallback_urls)} direct URLs")
            except Exception as e:
                logger.warning(f"[RECON] Fallback direct probing failed: {e}")

            # Fallback 2: Certificate transparency lookup
            try:
                cert_subdomains = self.fallback_cert_transparency()
                if cert_subdomains:
                    subdomains.extend(cert_subdomains)
                    self.state.update(subdomains=subdomains)
                    logger.info(f"[RECON] ✅ Fallback added {len(cert_subdomains)} CT subdomains")
            except Exception as e:
                logger.warning(f"[RECON] Fallback CT failed: {e}")

            # Fallback 3: DNS enumeration
            try:
                dns_subdomains = self.fallback_dns_enumeration()
                if dns_subdomains:
                    subdomains.extend(dns_subdomains)
                    self.state.update(subdomains=subdomains)
                    logger.info(f"[RECON] ✅ Fallback added {len(dns_subdomains)} DNS subdomains")
            except Exception as e:
                logger.warning(f"[RECON] Fallback DNS failed: {e}")

        # Final validation
        if not all_urls:
            logger.error("[RECON] ❌ CRITICAL: No URLs found even with fallbacks!")
            logger.error("[RECON] 💡 Suggestions:")
            logger.error("   - Check if domain is valid and online")
            logger.error("   - Try manual URL input: --urls-file urls.txt")
            logger.error("   - Domain might be too new or heavily protected")
            # Don't crash - let agent continue with minimal data
            all_urls = self._build_direct_probe_candidates()
            self.state.update(urls=all_urls)

        logger.info(f"[RECON] Completed: {len(subdomains)} subdomains, {len(archived_urls)} archived URLs, {len(live_hosts)} live hosts")
        self._write_manifest(subdomains, archived_urls, live_hosts)

    def _write_manifest(self, subdomains: List[str], archived_urls: List[str], live_hosts: List[Dict[str, Any]]):
        """Write a lightweight manifest of recon artifacts for later phases and resume/debug."""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            safe_target = self.target.replace(".", "_").replace("/", "_")
            manifest = {
                "phase": "recon",
                "target": self.target,
                "artifacts": {
                    "subdomains_txt": os.path.join(self.output_dir, "subdomains.txt"),
                    "subdomains_scored_json": os.path.join(self.output_dir, "subdomains_scored.json"),
                    "archived_urls_txt": os.path.join(self.output_dir, "archived_urls.txt"),
                    "httpx_results_json": os.path.join(self.output_dir, "httpx_results.json"),
                    "httpx_live_hosts_txt": os.path.join(self.output_dir, "live_hosts.txt"),
                    "subfinder_output_txt": os.path.join(self.output_dir, f"subfinder_{safe_target}.txt"),
                    "wayback_output_txt": os.path.join(self.output_dir, f"wayback_{safe_target}.txt"),
                    "wayback_output_json": os.path.join(self.output_dir, f"wayback_{safe_target}.json"),
                    "gau_output_txt": os.path.join(self.output_dir, f"gau_{safe_target}.txt"),
                },
                "counts": {
                    "subdomains": len(subdomains or []),
                    "archived_urls": len(archived_urls or []),
                    "live_hosts": len(live_hosts or []),
                }
            }
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        except Exception as e:
            logger.warning(f"[RECON] Failed to write manifest: {e}")

    def _fallback_to_archived_data(self, urls: List[str]) -> List[str]:
        """Khi crawler timeout, sử dụng dữ liệu đã crawl từ Wayback/GAU"""
        logger.info("[RECON] Using archived data as fallback")
        archived = self.state.get("archived_urls", [])
        if archived:
            logger.info(f"[RECON] Fallback: using {len(archived)} archived URLs")
            return archived
        return urls

    def _build_direct_probe_candidates(self) -> List[str]:
        """Build direct probe URLs while preserving explicit scheme/port when provided."""
        candidates: List[str] = []
        preferred_schemes = ["https", "http"] if self.is_public_hostname else ["http", "https"]

        if self.raw_target.startswith(("http://", "https://")):
            candidates.append(self.raw_target.rstrip("/"))

        if self.target_port:
            for scheme in [self.target_scheme] + preferred_schemes:
                url = f"{scheme}://{self.target_host}:{self.target_port}"
                if url not in candidates:
                    candidates.append(url)
        else:
            preferred = f"{self.target_scheme}://{self.target_host}"
            candidates.append(preferred)
            for scheme in preferred_schemes:
                url = f"{scheme}://{self.target_host}"
                if url not in candidates:
                    candidates.append(url)

        if self.is_public_hostname and not self.target_host.startswith("www."):
            www_host = f"www.{self.target_host}"
            if self.target_port:
                url = f"{self.target_scheme}://{www_host}:{self.target_port}"
            else:
                url = f"{self.target_scheme}://{www_host}"
            if url not in candidates:
                candidates.append(url)

        return candidates

    def fallback_direct_probing(self) -> List[str]:
        """Fallback: return canonical direct target URLs for validation/crawling."""
        logger.info("[RECON] Direct probing fallback for canonical target URLs")
        return self._build_direct_probe_candidates()

    def fallback_cert_transparency(self) -> List[str]:
        """Fallback: query crt.sh for additional subdomains on public hosts."""
        if not self.is_public_hostname:
            logger.info(f"[RECON] Skipping CT fallback for local/non-public target: {self.target_host}")
            return []

        timeout = int(getattr(config, "CT_API_TIMEOUT", 8))
        url = f"https://crt.sh/?q=%25.{quote(self.target_host)}&output=json"
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "ai-recon-agent/1.0"},
            method="GET",
        )

        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                payload = resp.read().decode("utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"[RECON] CT lookup failed for {self.target_host}: {e}")
            return []

        try:
            entries = json.loads(payload)
        except Exception as e:
            logger.warning(f"[RECON] CT response parse failed for {self.target_host}: {e}")
            return []

        found: Set[str] = set()
        for entry in entries if isinstance(entries, list) else []:
            names = str(entry.get("name_value", "")).splitlines()
            for raw_name in names:
                sub = raw_name.strip().lower().lstrip("*.").rstrip(".")
                if sub and sub.endswith(self.target_host):
                    found.add(sub)

        results = sorted(found)[:500]
        logger.info(f"[RECON] CT fallback discovered {len(results)} candidate subdomains")
        return results

    def _load_recon_cache(self) -> Optional[Dict[str, List[str]]]:
        ttl_hours = int(self.budget.get("recon_cache_ttl_hours", 24))
        if ttl_hours <= 0 or not os.path.exists(self.cache_file):
            return None
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            entry = data.get(self.target)
            if not entry:
                return None
            ts = float(entry.get("timestamp", 0))
            if ts <= 0:
                return None
            age_hours = (time.time() - ts) / 3600.0
            if age_hours > ttl_hours:
                return None
            subdomains = entry.get("subdomains", []) or []
            archived_urls = entry.get("archived_urls", []) or []
            if not subdomains and not archived_urls:
                return None
            logger.info(f"[RECON] Cache hit: subs={len(subdomains)} urls={len(archived_urls)} age={age_hours:.1f}h")
            return {"subdomains": subdomains, "archived_urls": archived_urls}
        except Exception as e:
            logger.debug(f"[RECON] Cache read error: {e}")
            return None

    def _save_recon_cache(self, subdomains: List[str], archived_urls: List[str]):
        try:
            os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
            data = {}
            if os.path.exists(self.cache_file):
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
            data[self.target] = {
                "timestamp": time.time(),
                "subdomains": list(dict.fromkeys(subdomains))[:5000],
                "archived_urls": list(dict.fromkeys(archived_urls))[:8000],
            }
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"[RECON] Cache write error: {e}")

    def discover_subdomains(self) -> List[str]:
        """Discover subdomains using passive techniques
        
        OPTIMIZATION: Only use subfinder + assetfinder (removed amass and CT logs for speed)
        - amass: too slow (often times out), high resource usage
        - CT logs (crt.sh): unreliable, often returns empty/slow responses
        """
        logger.info("[RECON] Discovering subdomains (optimized: subfinder + assetfinder only)")

        if not self.is_public_hostname:
            logger.info(f"[RECON] Skipping passive subdomain enumeration for local/non-public target: {self.target_host}")
            return []

        subdomains: Set[str] = set()
        source_map: Dict[str, Set[str]] = {}

        # Subfinder (passive sources) - PRIMARY tool
        subfinder_subs = self.subfinder.discover_subdomains(self.target)
        subdomains.update(subfinder_subs)
        for sub in subfinder_subs:
            source_map.setdefault(sub.lower(), set()).add("subfinder")

        # Assetfinder - SECONDARY tool (fast, lightweight)
        if tool_available("assetfinder"):
            rc, stdout, _ = run_command(["assetfinder", "--subs-only", self.target], timeout=60)
            if rc == 0 and stdout:
                assetfinder_subs = {
                    s.strip().lower()
                    for s in stdout.splitlines()
                    if s.strip() and s.strip().lower().endswith(self.target)
                }
                subdomains.update(assetfinder_subs)
                for sub in assetfinder_subs:
                    source_map.setdefault(sub, set()).add("assetfinder")

        # REMOVED: Amass passive (too slow, times out frequently)
        # REMOVED: CRT.sh (unreliable, slow, often empty responses)
        # These are kept as fallback methods only (see fallback_cert_transparency)

        # DNS verification to improve accuracy while preserving breadth
        verified = self._verify_subdomains_dns(list(subdomains), source_map)
        subdomains = set(verified)

        # Save to file
        subdomains_file = os.path.join(self.output_dir, "subdomains.txt")
        with open(subdomains_file, 'w') as f:
            f.write('\n'.join(sorted(subdomains)))
        score_file = os.path.join(self.output_dir, "subdomains_scored.json")
        scored = []
        for sub in sorted(subdomains):
            sources = sorted(source_map.get(sub, set()))
            scored.append({"subdomain": sub, "sources": sources, "source_count": len(sources)})
        with open(score_file, "w") as f:
            json.dump(scored, f, indent=2)

        logger.info(f"[RECON] Found {len(subdomains)} unique subdomains (optimized pipeline)")
        return list(subdomains)

    def discover_archived_urls(self) -> List[str]:
        """Discover URLs from archive sources"""
        logger.info("[RECON] Discovering archived URLs")

        if not self.is_public_hostname:
            logger.info(f"[RECON] Skipping archive lookups for local/non-public target: {self.target_host}")
            return []

        urls = set()

        # Wayback Machine
        wayback_urls = self.wayback.fetch_urls(self.target, max_urls=2000)
        urls.update(wayback_urls)

        # GetAllURLs (GAU)
        gau_timeout = int(self.budget.get("recon_gau_timeout", 60))  # FIXED: Reduced from 120s to 60s
        gau_urls = self.gau.fetch_urls(self.target, max_urls=2000, timeout=gau_timeout)
        urls.update(gau_urls)

        # Note: waybackurls CLI tool is redundant with self.wayback.fetch_urls()
        # The WaybackRunner integration already fetches from Wayback Machine API
        # No need to call the external waybackurls tool

        urls = set(self._filter_useful_urls(urls))

        # Save to file
        archived_file = os.path.join(self.output_dir, "archived_urls.txt")
        with open(archived_file, 'w') as f:
            f.write('\n'.join(sorted(urls)))

        logger.info(f"[RECON] Found {len(urls)} archived URLs")
        return list(urls)

    def _verify_subdomains_dns(self, subs: List[str], source_map: Dict[str, Set[str]]) -> List[str]:
        """
        Keep broad coverage but improve accuracy:
        - include DNS-resolved subdomains
        - include unresolved only when seen by >=2 independent sources
        """
        if not subs:
            return []
        limit = int(self.budget.get("recon_dns_verify_limit", 500))
        sample = list(dict.fromkeys([s.lower() for s in subs]))[:limit]
        resolved: Set[str] = set()

        def resolve(sub: str) -> Optional[str]:
            try:
                socket.gethostbyname(sub)
                return sub
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=25) as executor:
            futures = [executor.submit(resolve, sub) for sub in sample]
            for future in as_completed(futures):
                r = future.result()
                if r:
                    resolved.add(r)

        high_conf_unresolved = {
            sub for sub in sample
            if sub not in resolved and len(source_map.get(sub, set())) >= 2
        }
        merged = sorted(resolved | high_conf_unresolved)
        logger.info(
            f"[RECON] DNS verify: resolved={len(resolved)} kept_unresolved={len(high_conf_unresolved)} total={len(merged)}"
        )
        return merged

    def merge_url_sources(self, subdomains: List[str], archived_urls: List[str]) -> List[str]:
        """Merge and deduplicate URLs from all sources, preserving target scheme"""
        all_urls = set()
        
        # Determine target scheme (http or https)
        target_scheme = "https"  # default
        raw_target = self.state.get("target", "")
        if raw_target:
            if raw_target.startswith("http://"):
                target_scheme = "http"
            elif raw_target.startswith("https://"):
                target_scheme = "https"

        for url in self._build_direct_probe_candidates():
            all_urls.add(url)

        # Add subdomains as URLs - only use target scheme, not both
        for sub in subdomains:
            if self.target_port and sub == self.target_host:
                all_urls.add(f"{target_scheme}://{sub}:{self.target_port}")
            else:
                all_urls.add(f"{target_scheme}://{sub}")
        
        # Add archived URLs (already include scheme from sources)
        all_urls.update(self._filter_useful_urls(archived_urls))

        # Normalize URLs
        from core.url_normalizer import URLNormalizer
        normalizer = URLNormalizer()
        normalized = normalizer.normalize_urls(list(all_urls))
        normalized = self._filter_useful_urls(normalized)

        logger.info(f"[RECON] Merged to {len(normalized)} unique URLs (using {target_scheme}:// scheme)")
        return normalized

    def validate_live_hosts(self, urls: List[str], timeout: Optional[int] = None) -> List[Dict]:
        """
        Validate which hosts are live using httpx (ProjectDiscovery) for fast HTTP probing.
        
        This method uses httpx instead of Python's HTTPClient for several reasons:
        1. httpx is Go-based and much faster (100+ concurrent threads)
        2. Better timeout handling and connection pooling
        3. Built-in technology detection and title extraction
        4. More efficient DNS resolution and connection handling
        
        Falls back to Python HTTPClient if httpx is not available.
        """
        logger.info("[RECON] Validating live hosts")

        max_urls = int(self.budget.get("recon_validate_urls", 200))
        timeout_val = int(timeout if timeout is not None else self.budget.get("live_timeout", 8))
        sample_urls = self._select_validation_candidates(urls, max_urls)

        if not sample_urls:
            logger.warning("[RECON] No URLs to validate")
            return []

        # PRIMARY: Use httpx for fast HTTP probing
        if self.httpx.is_available():
            logger.info(f"[RECON] Using httpx for live host validation ({len(sample_urls)} URLs, timeout={timeout_val}s)")
            try:
                httpx_results = self.httpx.validate_live_hosts(sample_urls, timeout=timeout_val)
                
                # Convert httpx results to standard format
                live_hosts = []
                for r in httpx_results:
                    live_hosts.append({
                        "url": r.get("url", ""),
                        "status": "live",
                        "status_code": r.get("status_code", 0),
                        "response_time": r.get("response_time", 0),
                        "title": r.get("title", ""),
                        "web_server": r.get("web_server", ""),
                        "ip": r.get("ip", ""),
                        "tech": r.get("tech", []),
                        "content_type": r.get("content_type", ""),
                    })
                
                logger.info(f"[RECON] httpx validated {len(live_hosts)} live hosts out of {len(sample_urls)} checked")
                return live_hosts
                
            except Exception as e:
                logger.warning(f"[RECON] httpx validation failed: {e}, falling back to Python HTTPClient")

        # FALLBACK: Use Python HTTPClient if httpx is not available
        logger.info(f"[RECON] Falling back to Python HTTPClient for validation ({len(sample_urls)} URLs)")
        live_hosts = []

        from core.http_engine import HTTPClient
        from core.session_manager import SessionManager
        
        session = SessionManager(self.output_dir)
        http_client = HTTPClient(session)
        http_client.min_delay = 0.0

        # Check URLs in parallel
        def check_url(url):
            try:
                response = http_client.get(url, timeout=timeout_val)
                if response.status_code < 500:  # Consider 4xx as live too
                    return {
                        "url": url,
                        "status": "live",
                        "status_code": response.status_code,
                        "response_time": getattr(response, 'elapsed', 0)
                    }
            except Exception:
                pass
            return None

        workers = int(self.budget.get("recon_validate_workers", 16))

        # Use ThreadPoolExecutor for parallel checking with graceful shutdown handling
        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                try:
                    futures = [executor.submit(check_url, url) for url in sample_urls]
                except RuntimeError as e:
                    if "interpreter shutdown" in str(e):
                        logger.warning("[RECON] Cannot schedule futures - interpreter shutting down, returning partial results")
                        return live_hosts
                    raise
                
                try:
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result:
                                live_hosts.append(result)
                        except RuntimeError as e:
                            if "interpreter shutdown" in str(e):
                                logger.warning("[RECON] Interpreter shutting down during result collection, returning partial results")
                                break
                            raise
                except RuntimeError as e:
                    if "interpreter shutdown" in str(e):
                        logger.warning("[RECON] Interpreter shutting down, returning partial results")
        except RuntimeError as e:
            if "interpreter shutdown" in str(e):
                logger.error("[RECON] Fatal: Interpreter shutdown during validation")
            else:
                logger.error(f"[RECON] Validation error: {e}")
        except Exception as e:
            logger.error(f"[RECON] Unexpected validation error: {e}")

        logger.info(f"[RECON] Validated {len(live_hosts)} live hosts out of {len(sample_urls)} checked")
        return live_hosts

    def _is_public_hostname(self, host: str) -> bool:
        host = (host or "").strip().lower()
        if not host:
            return False
        if host in {"localhost", "localhost.localdomain"}:
            return False
        try:
            ip = ipaddress.ip_address(host)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast)
        except ValueError:
            pass
        if "." not in host:
            return False
        local_suffixes = (".local", ".localhost", ".internal", ".lan", ".home", ".test", ".example", ".invalid")
        return not host.endswith(local_suffixes)

    def _filter_useful_urls(self, urls) -> List[str]:
        """
        Filter URLs to keep only useful ones for scanning.
        Integrates with HostFilter for comprehensive filtering:
        - Multi-domain filter: Only allow URLs from allowed_domains (targets.txt)
        - Third-party domains filter
        - Free hosting filter
        - Suspicious subdomains filter
        - Static files filter
        - Deduplication
        """
        filtered: List[str] = []
        seen = set()
        # Track canonical paths for deduplication
        canonical_paths: Dict[str, str] = {}
        
        for raw_url in urls:
            url = (raw_url or "").strip()
            if not url or url in seen:
                continue
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue
            
            hostname = parsed.hostname or ""

            # Preserve the user's explicit scheme/port choice for the primary target.
            # If the target was provided as http://host:port, avoid keeping synthetic
            # https://host:port variants for that same endpoint unless the user asked for it.
            if (
                self.target_port
                and hostname == self.target_host
                and parsed.port == self.target_port
                and parsed.scheme != self.target_scheme
            ):
                continue
            
            # MULTI-DOMAIN FILTER: Only allow URLs from allowed_domains (targets.txt)
            # This is the primary filter to ensure we only scan target domains
            if self.host_filter.allowed_domains and not self.host_filter._is_in_allowed_domains(url):
                logger.debug(f"[RECON] Filtering URL not in allowed_domains: {url[:100]}")
                continue
            
            # Skip third-party domains (vimeo, instagram, facebook, google, etc.)
            is_third_party = False
            third_party_bases = ['vimeo.com', 'instagram.com', 'facebook.com', 'google.com',
                                 'googletagmanager.com', 'youtu.be', 'youtube.com', 'twitter.com',
                                 'linkedin.com', 'github.com', 'gravatar.com', 'cloudflare.com',
                                 'jsdelivr.net', 'bootstrapcdn.com', 'fontawesome.com',
                                 'googleapis.com', 'gstatic.com', 'doubleclick.net',
                                 'google-analytics.com']
            for domain in third_party_bases:
                if hostname == domain or hostname.endswith("." + domain):
                    is_third_party = True
                    logger.debug(f"[RECON] Filtering third-party URL: {url[:100]}")
                    break
            if is_third_party:
                continue
            
            # FIXED: Skip free hosting subdomains (user sites), but NOT the platform's main domain
            # Filter user sites like example.wordpress.com, but allow wordpress.com itself
            is_free_hosting = False
            for free_domain in FREE_HOSTING_DOMAINS:
                if hostname.endswith("." + free_domain):
                    # Get the subdomain part (everything before the free domain)
                    subdomain = hostname[:-(len(free_domain) + 1)]
                    # Only filter if it's a non-empty subdomain that's NOT just 'www'
                    # This allows wordpress.com and www.wordpress.com to pass through
                    if subdomain and subdomain != 'www':
                        is_free_hosting = True
                        logger.debug(f"[RECON] Filtering free hosting user site: {url[:100]}")
                        break
            if is_free_hosting:
                continue
            
            # Skip suspicious/auto-generated subdomains (very long random strings)
            if len(hostname) > 253:
                logger.debug(f"[RECON] Filtering oversized hostname: {url[:100]}")
                continue
            labels = hostname.split('.')
            skip_suspicious = False
            for label in labels:
                if len(label) > 50:
                    skip_suspicious = True
                    break
                # Check for random-looking patterns (32+ char alphanumeric)
                if len(label) >= 32 and re.match(r'^[a-z0-9]{32,}$', label):
                    skip_suspicious = True
                    break
            if skip_suspicious:
                logger.debug(f"[RECON] Filtering suspicious subdomain: {url[:100]}")
                continue
            
            path = parsed.path or "/"
            ext = os.path.splitext(path.lower())[1]
            if ext in STATIC_EXTENSIONS:
                continue
            if len(url) > 2048:
                continue
            if parsed.query.count("*") > 2:
                continue
            if any(seg in {"wp-content", "uploads"} for seg in path.lower().split("/")) and ext:
                continue
            normalized_path = posixpath.normpath(path)
            if normalized_path.startswith("/../"):
                continue
            
            # ─── PRIORITY 4: ENHANCED URL DEDUPLICATION ──────────────────────────
            # Create canonical form for deduplication (path + sorted params)
            canonical = self._canonicalize_url_for_dedup(url)
            if canonical in canonical_paths:
                # Keep the first URL seen for each canonical form
                continue
            canonical_paths[canonical] = url
            
            seen.add(url)
            filtered.append(url)
        return filtered

    def _canonicalize_url_for_dedup(self, url: str) -> str:
        """
        Create a canonical form of URL for deduplication.
        Normalizes query parameters and removes noise.
        """
        parsed = urlparse(url)
        path = parsed.path or "/"
        
        # Normalize path
        path = posixpath.normpath(path)
        
        # Parse and sort query parameters
        params = []
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    key, _ = param.split('=', 1)
                    params.append(key.lower())
                else:
                    params.append(param.lower())
        
        # Create canonical form: scheme://host/path?sorted_params
        canonical = f"{parsed.scheme}://{parsed.netloc}{path}"
        if params:
            canonical += "?" + "&".join(sorted(set(params)))
        
        return canonical

    def _filter_low_value_paths(self, urls: List[str]) -> List[str]:
        """
        Filter out low-value paths that are not worth scanning.
        This is called AFTER initial filtering to further reduce noise.
        """
        # Paths to deprioritize or remove
        low_value_patterns = [
            # WordPress oEmbed - low exploitation value
            '/oembed/',
            '/wp-json/oembed/',
            '/wp-oembed',
            # WordPress uploads - usually not exploitable
            '/wp-content/uploads/',
            '/wp-includes/',
            # Generic static-like paths
            '/feed/',
            '/sitemap',
            '/robots.txt',
            # WordPress REST API endpoints without sensitive data
            '/wp-json/wp/v2/types',
            '/wp-json/wp/v2/taxonomies',
            '/wp-json/wp/v2/search',
        ]
        
        # Injection-prone parameters that indicate valuable URLs
        valuable_params = {
            'id', 'page', 'itemid', 'post_id', 'p', 'cat', 'tag',
            'search', 'query', 'url', 'redirect', 'next', 'callback',
            'file', 'path', 'include', 'template', 'rest_route',
            'action', 'method', 'cmd', 'exec', 'download',
        }
        
        filtered = []
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Check if URL matches low-value patterns
            is_low_value = any(pattern in path for pattern in low_value_patterns)
            
            # Check if URL has valuable parameters
            has_valuable_params = False
            if parsed.query:
                url_params = set()
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key = param.split('=', 1)[0].lower()
                        url_params.add(key)
                has_valuable_params = bool(url_params & valuable_params)
            
            # Keep URL if it has valuable parameters, even if path is low-value
            if is_low_value and not has_valuable_params:
                logger.debug(f"[RECON] Filtering low-value URL: {url[:100]}")
                continue
            
            filtered.append(url)
        
        return filtered

    def _group_urls_by_path(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        Group URLs by their base path (without query string).
        Useful for identifying endpoint clusters.
        """
        groups: Dict[str, List[str]] = {}
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path or "/"
            if path not in groups:
                groups[path] = []
            groups[path].append(url)
        return groups

    def _select_representative_urls(self, urls: List[str], max_per_path: int = 5) -> List[str]:
        """
        Select representative URLs from each path group.
        Prioritizes URLs with injection-prone parameters.
        """
        groups = self._group_urls_by_path(urls)
        selected = []
        
        injection_params = {
            'id', 'page', 'itemid', 'post_id', 'p', 'cat', 'tag',
            'search', 'query', 'url', 'redirect', 'next', 'callback',
            'file', 'path', 'include', 'template', 'rest_route',
            'action', 'method', 'cmd', 'exec', 'download',
        }
        
        for path, url_list in groups.items():
            if len(url_list) <= max_per_path:
                selected.extend(url_list)
            else:
                # Sort by parameter value (prefer URLs with injection-prone params)
                def score_url(url):
                    parsed = urlparse(url)
                    if not parsed.query:
                        return 0
                    url_params = set()
                    for param in parsed.query.split('&'):
                        if '=' in param:
                            key = param.split('=', 1)[0].lower()
                            url_params.add(key)
                    return len(url_params & injection_params)
                
                # Sort by score descending, take top N
                url_list.sort(key=score_url, reverse=True)
                selected.extend(url_list[:max_per_path])
        
        return selected

    def _select_validation_candidates(self, urls: List[str], max_urls: int) -> List[str]:
        candidates = []
        seen_hosts = set()

        def score(url: str):
            parsed = urlparse(url)
            path = parsed.path or "/"
            ext = os.path.splitext(path.lower())[1]
            path_depth = len([part for part in path.split("/") if part])
            query_penalty = 1 if parsed.query else 0
            static_penalty = 3 if ext in STATIC_EXTENSIONS else 0
            scheme_penalty = 0
            if (
                self.target_port
                and (parsed.hostname or "") == self.target_host
                and parsed.port == self.target_port
                and parsed.scheme != self.target_scheme
            ):
                scheme_penalty = 5
            return (scheme_penalty, static_penalty, query_penalty, path_depth, len(path), len(url))

        for url in sorted(self._filter_useful_urls(urls), key=score):
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host:
                continue
            host_key = (host, parsed.port, parsed.scheme)
            host_base_key = (host, parsed.port)
            if host_base_key in seen_hosts and len(candidates) >= max_urls // 2:
                continue
            seen_hosts.add(host_key)
            seen_hosts.add(host_base_key)
            candidates.append(url)
            if len(candidates) >= max_urls:
                break
        return candidates

    def fallback_dns_enumeration(self) -> List[str]:
        """Bruteforce common subdomains with DNS resolution"""
        logger.info(f"[RECON] DNS bruteforce enumeration for {self.target}")
        common_subs = [
            'www', 'mail', 'ftp', 'webmail', 'admin', 'test', 'staging', 'dev',
            'beta', 'demo', 'api', 'app', 'mobile', 'portal', 'secure', 'ns1', 'ns2',
            'mx1', 'backup', 'db', 'db1', 'db2', 'cdn', 'files', 'images', 'blog',
            'forum', 'shop', 'store', 'docs', 'wiki', 'cpanel', 'whm', 'panel'
        ]
        subdomains = []
        for sub in common_subs:
            subdomain = f"{sub}.{self.target}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.append(subdomain)
            except socket.gaierror:
                pass
        logger.info(f"[RECON] DNS resolved {len(subdomains)} common subdomains")
        return subdomains
