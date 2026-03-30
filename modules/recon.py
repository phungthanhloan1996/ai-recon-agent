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
from typing import List, Set, Dict, Callable, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from core.state_manager import StateManager
from core.executor import check_tools, run_command, tool_available
from integrations.subfinder_runner import SubfinderRunner
from integrations.gau_runner import GAURunner
from integrations.wayback_runner import WaybackRunner

logger = logging.getLogger("recon.engine")
# Constants
RECON_TOOLS = ["subfinder", "assetfinder", "crtsh", "gau", "waybackurls"]
STATIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".mp3", ".mp4", ".avi",
    ".mov", ".woff", ".woff2", ".ttf", ".eot", ".css", ".map", ".js"
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

        # FIX: ensure target exists
        self.target = state.get("target")

        if not self.target:
            raise ValueError("Target domain not found in state")

        parsed_target = urlparse(self.target if "://" in self.target else f"https://{self.target}")
        self.target_host = parsed_target.hostname or self.target.replace("https://", "").replace("http://", "").strip()
        self.target_port = parsed_target.port
        self.target = self.target_host
        self.is_public_hostname = self._is_public_hostname(self.target_host)

        # Initialize integrations
        self.subfinder = SubfinderRunner(output_dir)
        self.gau = GAURunner(output_dir)
        self.wayback = WaybackRunner()
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

        if len(live_hosts) < config.MIN_LIVE_HOSTS_FOR_FALLBACK and len(all_urls) > 100:
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
            all_urls = [f"https://{self.target}", f"http://{self.target}"]
            self.state.update(urls=all_urls)

        logger.info(f"[RECON] Completed: {len(subdomains)} subdomains, {len(archived_urls)} archived URLs, {len(live_hosts)} live hosts")

    def _fallback_to_archived_data(self, urls: List[str]) -> List[str]:
        """Khi crawler timeout, sử dụng dữ liệu đã crawl từ Wayback/GAU"""
        logger.info("[RECON] Using archived data as fallback")
        archived = self.state.get("archived_urls", [])
        if archived:
            logger.info(f"[RECON] Fallback: using {len(archived)} archived URLs")
            return archived
        return urls

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
        """Discover subdomains using passive techniques"""
        logger.info("[RECON] Discovering subdomains")

        if not self.is_public_hostname:
            logger.info(f"[RECON] Skipping passive subdomain enumeration for local/non-public target: {self.target_host}")
            return []

        subdomains: Set[str] = set()
        source_map: Dict[str, Set[str]] = {}

        # Subfinder (passive sources)
        subfinder_subs = self.subfinder.discover_subdomains(self.target)
        subdomains.update(subfinder_subs)
        for sub in subfinder_subs:
            source_map.setdefault(sub.lower(), set()).add("subfinder")

        # Assetfinder
        if tool_available("assetfinder"):
            rc, stdout, _ = run_command(["assetfinder", "--subs-only", self.target], timeout=120)
            if rc == 0 and stdout:
                assetfinder_subs = {
                    s.strip().lower()
                    for s in stdout.splitlines()
                    if s.strip() and s.strip().lower().endswith(self.target)
                }
                subdomains.update(assetfinder_subs)
                for sub in assetfinder_subs:
                    source_map.setdefault(sub, set()).add("assetfinder")

        # Amass passive - uses configurable timeout (default 120s, was 45s)
        if tool_available("amass"):
            amass_timeout = config.AMASS_TIMEOUT
            rc, stdout, _ = run_command(
                ["amass", "enum", "-passive", "-norecursive", "-noalts", "-d", self.target, "-silent"],
                timeout=amass_timeout,
            )
            if rc == 0 and stdout:
                amass_subs = {
                    s.strip().lower()
                    for s in stdout.splitlines()
                    if s.strip() and s.strip().lower().endswith(self.target)
                }
                subdomains.update(amass_subs)
                for sub in amass_subs:
                    source_map.setdefault(sub, set()).add("amass")
            elif rc == -2:
                logger.warning(f"[RECON] Amass timed out after {amass_timeout}s; continuing with other sources (increase AMASS_TIMEOUT env if needed)")

        # CRT.sh (small passive boost)
        crt_subs = set(self.fallback_cert_transparency())
        subdomains.update(crt_subs)
        for sub in crt_subs:
            source_map.setdefault(sub.lower(), set()).add("crtsh")

        # DNS verification to improve accuracy while preserving breadth
        verified = self._verify_subdomains_dns(list(subdomains), source_map)
        subdomains = set(verified)

        # Could add more sources here (crt.sh, etc.)

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

        logger.info(f"[RECON] Found {len(subdomains)} unique subdomains")
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
        gau_timeout = int(self.budget.get("recon_gau_timeout", 120))
        gau_urls = self.gau.fetch_urls(self.target, max_urls=2000, timeout=gau_timeout)
        urls.update(gau_urls)

        # waybackurls
        if tool_available("waybackurls"):
            rc, stdout, _ = run_command(["waybackurls"], timeout=120, stdin_data=f"{self.target}\n")
            if rc == 0 and stdout:
                wb_urls = {
                    u.strip()
                    for u in stdout.splitlines()
                    if u.strip().startswith(("http://", "https://"))
                }
                urls.update(wb_urls)

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
        
        # Add subdomains as URLs - only use target scheme, not both
        for sub in subdomains:
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
        """Validate which hosts are live"""
        logger.info("[RECON] Validating live hosts")

        live_hosts = []

        # Import HTTP client for validation
        from core.http_engine import HTTPClient
        from core.session_manager import SessionManager
        
        session = SessionManager(self.output_dir)
        http_client = HTTPClient(session)
        http_client.min_delay = 0.0

        # Check URLs in parallel
        def check_url(url):
            try:
                response = http_client.get(url, timeout=timeout)
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

        max_urls = int(self.budget.get("recon_validate_urls", 120))
        timeout = int(timeout if timeout is not None else self.budget.get("live_timeout", 6))
        workers = int(self.budget.get("recon_validate_workers", 16))

        # Use ThreadPoolExecutor for parallel checking
        with ThreadPoolExecutor(max_workers=workers) as executor:
            sample_urls = self._select_validation_candidates(urls, max_urls)
            futures = [executor.submit(check_url, url) for url in sample_urls]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)

        logger.info(f"[RECON] Validated {len(live_hosts)} live hosts out of {len(sample_urls)} checked")
        return live_hosts

    def fallback_direct_probing(self) -> List[str]:
        """Generate common paths for direct probing fallback"""
        logger.info(f"[RECON] Generating direct probe URLs for {self.target}")
        urls = []
        common_paths = [
            '', '/', '/admin', '/login', '/wp-admin', '/administrator', '/dashboard',
            '/panel', '/cpanel', '/admin.php', '/login.php', '/index.php', '/sitemap.xml',
            '/robots.txt', '/.env', '/config', '/api', '/graphql', '/wp-login.php'
        ]
        for path in common_paths:
            urls.append(urljoin(f"https://{self.target}", path))
            urls.append(urljoin(f"http://{self.target}", path))
        
        # Normalize
        from core.url_normalizer import URLNormalizer
        normalizer = URLNormalizer()
        normalized = normalizer.normalize_urls(urls)
        logger.info(f"[RECON] Generated {len(normalized)} direct probe URLs")
        return list(normalized)

    def fallback_cert_transparency(self) -> List[str]:
        """Fetch subdomains from crt.sh Certificate Transparency logs with improved error handling.
        
        FIX #6: Handle empty/invalid CT responses better
        """
        logger.info(f"[RECON] Querying Certificate Transparency logs for {self.target}")

        if not self.is_public_hostname:
            logger.info(f"[RECON] Skipping CT lookup for local/non-public target: {self.target_host}")
            return []
        
        ct_timeout = config.CT_API_TIMEOUT if hasattr(config, 'CT_API_TIMEOUT') else 20
        
        # Retry with XML/JSON fallback
        for attempt in range(2):
            try:
                query = f"%25.{self.target}"
                url = f"https://crt.sh/?q={quote(query)}&output=json"
                
                with urllib.request.urlopen(url, timeout=ct_timeout) as resp:
                    raw = resp.read().decode('utf-8', errors='replace').strip()
                    
                    # FIX #6: Better handling of empty and invalid responses
                    if not raw or raw == "null" or raw == "" or raw == "[]":
                        logger.debug(f"[RECON] CT returned empty response")
                        return []
                    
                    if not raw.startswith("["):
                        logger.debug(f"[RECON] CT response not JSON array: {raw[:80]}")
                        # Try to fallback to XML
                        if attempt == 0:
                            try:
                                url_xml = f"https://crt.sh/?q={quote(query)}&output=xml"
                                with urllib.request.urlopen(url_xml, timeout=ct_timeout) as resp_xml:
                                    xml_data = resp_xml.read().decode('utf-8', errors='replace')
                                    # Just log and skip XML parsing for now
                                    logger.debug(f"[RECON] CT XML response available but skipping")
                            except Exception as xml_e:
                                logger.debug(f"[RECON] CT XML fallback failed: {xml_e}")
                        time.sleep(1)
                        continue
                    
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError as je:
                        logger.debug(f"[RECON] CT JSON parse failed: {je}")
                        if attempt == 0:
                            time.sleep(1)
                            continue
                        return []
                
                # Extract subdomains
                subdomains = set()
                for entry in data[:100]:  # Increased limit from 50 to 100
                    if isinstance(entry, dict) and 'name_value' in entry:
                        subs = str(entry['name_value']).strip().split('\n')
                        for sub in subs:
                            sub = sub.lower().strip()
                            if sub and self.target in sub:
                                subdomains.add(sub)
                
                logger.info(f"[RECON] Found {len(subdomains)} CT subdomains")
                return list(subdomains)
                
            except socket.timeout as e:
                logger.warning(f"[RECON] CT lookup timeout after {ct_timeout}s (attempt {attempt + 1}/2): {e}")
                if attempt == 0:
                    time.sleep(2)
                    continue
                return []
            except Exception as e:
                logger.warning(f"[RECON] CT lookup failed (attempt {attempt + 1}/2): {e}")
                if attempt == 0:
                    time.sleep(2)
                    continue
                return []
        return []

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
        filtered: List[str] = []
        seen = set()
        for raw_url in urls:
            url = (raw_url or "").strip()
            if not url or url in seen:
                continue
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
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
            seen.add(url)
            filtered.append(url)
        return filtered

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
            return (static_penalty, query_penalty, path_depth, len(path), len(url))

        for url in sorted(self._filter_useful_urls(urls), key=score):
            host = urlparse(url).hostname or ""
            if not host:
                continue
            if host in seen_hosts and len(candidates) >= max_urls // 2:
                continue
            seen_hosts.add(host)
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
