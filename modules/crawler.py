import urllib.parse
"""
modules/crawler.py - Discovery Engine
Endpoint extraction from HTML, JavaScript, forms, and hidden parameters

OPTIMIZATION: Refactored into phased pipeline with endpoint scoring.
- Phase 1: Passive Recon (already done in recon.py)
- Phase 2: Live Hosts + Deduplication (already done in recon.py)
- Phase 3: Smart Crawl (hakrawler lightweight as PRIMARY, browser_crawler as fallback)
- Phase 4: Heavy Scanning (only on high-value endpoints, score >= 7)
"""

import os
import re
import logging
import json
import tempfile
from typing import Dict, List, Set, Tuple, Callable, Optional
from urllib.parse import urlparse, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import time
import config
from core.executor import check_tools, run_command
from core.state_manager import StateManager
from core.http_engine import HTTPClient
from core.phase_admission import PhaseAdmission
from integrations.browser_crawler import BrowserCrawler
from modules.api_scanner import APIScannerRunner

logger = logging.getLogger("recon.discovery")

# Constants
CRAWL_TOOLS = ["katana", "gau", "waybackurls", "hakrawler"]
CRAWL_MAX_PARALLEL_HOSTS = 6
CRAWL_DEPTH = 4
PARAM_TOOLS = ["arjun", "paramspider"]
JS_TOOLS = ["linkfinder", "jsfinder2"]
EXCLUDE_EXTENSIONS = [
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".svg",
    ".map", ".min.js", ".min.css"
]
ENDPOINT_PATTERNS = {
    "admin": r"/admin|/administrator|/wp-admin|/manager|/console|/dashboard|/panel",
    "upload": r"/upload|/file|/attachment|/media",
    "api": r"/api/|/v\d+/|/graphql|/rest/",
    "auth": r"/login|/signin|/auth|/register|/password",
    "backup": r"\.bak$|\.sql$|\.tar$|\.zip$|backup",
    "config": r"\.env$|config\.|settings\.|\.ini$|\.cfg$",
    "wordpress": r"wp-content|wp-includes|xmlrpc\.php|wp-json",
    "git": r"\.git/|\.svn/|\.htaccess",
    "params": r"\?.*="
}


class DiscoveryEngine:
    """
    Comprehensive endpoint discovery engine.
    Extracts endpoints from multiple sources: HTML, JavaScript, forms, APIs.
    """

    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.http_client = HTTPClient()
        self.browser_crawler = BrowserCrawler()
        self.phase_admission = PhaseAdmission(state)
        self.budget = (self.state.get("scan_metadata", {}) or {}).get("budget", {})

        # Patterns for endpoint discovery
        self.endpoint_patterns = {
            "admin": re.compile(r"/admin|/administrator|/wp-admin|/manager|/console|/dashboard|/panel"),
            "upload": re.compile(r"/upload|/file|/attachment|/media"),
            "api": re.compile(r"/api/|/v\d+/|/graphql|/rest/"),
            "auth": re.compile(r"/login|/signin|/auth|/register|/password"),
            "backup": re.compile(r"\.bak$|\.sql$|\.tar$|\.zip$|backup"),
            "config": re.compile(r"\.env$|config\.|settings\.|\.ini$|\.cfg$"),
            "wordpress": re.compile(r"wp-content|wp-includes|xmlrpc\.php|wp-json"),
            "git": re.compile(r"\.git/|\.svn/|\.htaccess"),
            "params": re.compile(r"\?.*=")
        }

        self.exclude_extensions = {
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
            ".ico", ".woff", ".woff2", ".ttf", ".eot", ".svg",
            ".map", ".min.js", ".min.css"
        }

    def score_endpoint(self, url: str) -> int:
        """
        OPTIMIZATION: Score endpoint for exploitation value (0-15 scale).
        Only endpoints with score >= 7 will undergo heavy scanning (Nikto, Nuclei, Arjun, mutation).
        
        Scoring criteria:
        - Has parameters (?x=): +2
        - API patterns (/api/, /v1/, /graphql, /rest/, /wp-json): +3
        - Admin paths (/admin, /wp-admin, /dashboard, /panel): +3
        - Auth paths (/login, /auth, /signin, /register): +2
        - Upload paths (/upload, /file, /media, /attachment): +2
        - Config/backup files (.env, .bak, .git, wp-config): +3
        - WordPress indicators: +1
        """
        score = 0
        url_lower = url.lower()
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        query = parsed.query
        
        # Has parameters (injection potential)
        if query and '=' in query:
            score += 2
        
        # API patterns (high value for automation/testing)
        api_patterns = ['/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/wp-json/', '/soap', '/rpc']
        if any(p in url_lower for p in api_patterns):
            score += 3
        
        # Admin/management paths (high privilege operations)
        admin_patterns = ['/admin', '/wp-admin', '/administrator', '/dashboard', '/panel', '/manager', '/console', '/cpanel']
        if any(p in path for p in admin_patterns):
            score += 3
        
        # Auth paths (authentication bypass, credential testing)
        auth_patterns = ['/login', '/auth', '/signin', '/register', '/password', '/wp-login', '/oauth', '/saml']
        if any(p in path for p in auth_patterns):
            score += 2
        
        # Upload paths (file upload vulnerabilities)
        upload_patterns = ['/upload', '/file', '/media', '/attachment', '/wp-content/uploads']
        if any(p in path for p in upload_patterns):
            score += 2
        
        # Config/backup files (information disclosure)
        config_patterns = ['.env', '.bak', '.git', '.svn', 'wp-config', '.sql', '.tar', '.zip', 'phpinfo']
        if any(p in url_lower for p in config_patterns):
            score += 3
        
        # WordPress indicators (large attack surface)
        wp_patterns = ['wp-content', 'wp-includes', 'xmlrpc', 'wp-json']
        if any(p in url_lower for p in wp_patterns):
            score += 1
        
        return min(score, 15)

    def run(self, progress_cb: Optional[Callable[[str, str, str], None]] = None):
        """Execute endpoint discovery pipeline"""
        logger.info("[DISCOVERY] Starting endpoint discovery")

        urls = self._prepare_seed_urls(self.state.get("urls", []))
        discovered_endpoints = []
        seed_limit = int(self.budget.get("crawl_seed_urls", 260))
        browser_limit = int(self.budget.get("crawl_browser_urls", 40))
        browser_links = int(self.budget.get("crawl_browser_links_per_url", 120))
        http_workers = int(self.budget.get("crawl_workers_http", 20))
        browser_workers = int(self.budget.get("crawl_workers_browser", 4))

        seed_urls = urls[:seed_limit]
        browser_urls = urls[:browser_limit]

        # Queue 1: HTTP parser crawl
        if progress_cb:
            progress_cb("crawl", "http-parser", "running")
        with ThreadPoolExecutor(max_workers=http_workers) as executor:
            futures = [executor.submit(self.discover_from_url, url) for url in seed_urls]
            for future in as_completed(futures):
                try:
                    discovered_endpoints.extend(future.result())
                except Exception as e:
                    logger.debug(f"[DISCOVERY] HTTP crawl task failed: {e}")
        if progress_cb:
            progress_cb("crawl", "http-parser", "done")

        # Queue 2: Browser runtime crawl
        if progress_cb:
            progress_cb("crawl", "playwright", "running")
        with ThreadPoolExecutor(max_workers=browser_workers) as executor:
            futures = [executor.submit(self.browser_crawler.crawl, url, browser_links) for url in browser_urls]
            for future in as_completed(futures):
                try:
                    discovered_endpoints.extend(future.result())
                except Exception as e:
                    logger.debug(f"[DISCOVERY] Browser crawl task failed: {e}")
        if progress_cb:
            progress_cb("crawl", "playwright", "done")

        # Queue 3: Katana CLI deep crawl
        try:
            if progress_cb:
                progress_cb("crawl", "katana", "running")
            discovered_endpoints.extend(self._discover_with_katana(seed_urls))
        except Exception as e:
            logger.debug(f"[DISCOVERY] Katana crawl failed: {e}")
        finally:
            if progress_cb:
                progress_cb("crawl", "katana", "done")

        # Queue 4: Hakrawler for additional runtime-discovered links/forms
        try:
            if progress_cb:
                progress_cb("crawl", "hakrawler", "running")
            discovered_endpoints.extend(self._discover_with_hakrawler(seed_urls))
        except Exception as e:
            logger.debug(f"[DISCOVERY] Hakrawler crawl failed: {e}")
        finally:
            if progress_cb:
                progress_cb("crawl", "hakrawler", "done")

        # Queue 5: Parameter discovery (Arjun + ParamSpider)
        try:
            if progress_cb:
                progress_cb("crawl", "arjun+paramspider", "running")
            discovered_endpoints.extend(self._discover_with_param_tools(seed_urls))
        except Exception as e:
            logger.debug(f"[DISCOVERY] Param tools failed: {e}")
        finally:
            if progress_cb:
                progress_cb("crawl", "arjun+paramspider", "done")

        # Queue 6: JS URL extraction via JSFinder2 / LinkFinder
        try:
            if progress_cb:
                progress_cb("crawl", "jsfinder2+linkfinder", "running")
            discovered_endpoints.extend(self._discover_with_js_tools(seed_urls))
        except Exception as e:
            logger.debug(f"[DISCOVERY] JS tools failed: {e}")
        finally:
            if progress_cb:
                progress_cb("crawl", "jsfinder2+linkfinder", "done")

        # Remove duplicates and filter
        unique_endpoints = self.deduplicate_endpoints(discovered_endpoints)

        # Classify endpoints
        classified = self.classify_endpoints(unique_endpoints)

        # NEW: Run API scanner on discovered endpoints to detect API surfaces
        api_endpoints = self._scan_for_apis(classified)
        if api_endpoints:
            logger.info(f"[DISCOVERY] API scanner found {len(api_endpoints)} API endpoints")
            # Merge API findings into endpoints
            existing_urls = {ep.get('url') for ep in classified}
            for api_ep in api_endpoints:
                if api_ep.get('url') not in existing_urls:
                    classified.append(api_ep)

        if not classified and seed_urls:
            classified = self._build_seed_fallback_endpoints(seed_urls)
            if classified:
                logger.warning(
                    "[DISCOVERY] Discovery returned empty; injected %s canonical seed endpoint(s)",
                    len(classified),
                )

        self.state.update(endpoints=classified)

        # Save to file
        endpoints_file = os.path.join(self.output_dir, "endpoints.txt")
        with open(endpoints_file, 'w') as f:
            for ep in classified:
                f.write(f"{ep.get('url', '')}\n")

        logger.info(f"[DISCOVERY] Discovered {len(classified)} unique endpoints")

    def _prepare_seed_urls(self, urls: List[str]) -> List[str]:
        """Prioritize crawl seeds that are already known-live and preserve explicit ports."""
        live_urls = [
            host.get("url", "")
            for host in (self.state.get("live_hosts", []) or [])
            if isinstance(host, dict) and host.get("url", "").startswith(("http://", "https://"))
        ]
        merged = list(dict.fromkeys(live_urls + (urls or [])))
        if not merged:
            fallback_urls = [ep.get("url") for ep in self._build_seed_fallback_endpoints([self.target]) if ep.get("url")]
            if fallback_urls:
                logger.warning(
                    "[DISCOVERY] Upstream provided no seed URLs; preserved %s canonical target seed(s)",
                    len(fallback_urls),
                )
                return fallback_urls
            return []

        target_parsed = urllib.parse.urlparse(self.target or "")
        target_host = target_parsed.hostname or ""
        target_port = target_parsed.port

        prepared: List[str] = []
        seen = set()
        pruned_invalid = 0
        pruned_blacklisted = 0
        for url in merged:
            if not url.startswith(("http://", "https://")):
                continue
            record = self.phase_admission.register(url)
            if not record or not self.phase_admission.is_valid_endpoint(record):
                pruned_invalid += 1
                continue

            host = record.get("host") or ""
            if host and self.phase_admission.optimizer.is_host_blacklisted(host):
                pruned_blacklisted += 1
                continue

            normalized_url = record.get("url") or url
            parsed = urllib.parse.urlparse(normalized_url)
            key = (parsed.scheme, parsed.netloc, parsed.path, parsed.query)
            if key in seen:
                continue

            # When the original target includes an explicit port, deprioritize
            # synthetic default-port URLs for that same host to avoid wasting crawl budget.
            if target_host and target_port and parsed.hostname == target_host and parsed.port in (None, 80, 443):
                if parsed.port != target_port and parsed.netloc != f"{target_host}:{target_port}":
                    continue

            seen.add(key)
            prepared.append(normalized_url)

        if pruned_invalid or pruned_blacklisted:
            logger.info(
                "[DISCOVERY] Seed filtering reduced %s -> %s (invalid=%s blacklisted=%s)",
                len(merged),
                len(prepared),
                pruned_invalid,
                pruned_blacklisted,
            )

        if not prepared and merged:
            fallback_urls = [ep.get("url") for ep in self._build_seed_fallback_endpoints(merged) if ep.get("url")]
            if fallback_urls:
                logger.warning(
                    "[DISCOVERY] Seed filtering would empty the queue; preserved %s canonical seed URL(s)",
                    len(fallback_urls),
                )
                return fallback_urls

        return prepared

    def _build_seed_fallback_endpoints(self, seed_urls: List[str]) -> List[Dict]:
        fallback: List[Dict] = []
        seen = set()
        for raw_seed in list(seed_urls or []) + [self.target]:
            record = self.phase_admission.register(raw_seed)
            if not record:
                continue
            parsed = urllib.parse.urlparse(record.get("url") or "")
            path = (parsed.path or "/").rstrip("/") or "/"
            path_variants = list(dict.fromkeys([path, "/" if path != "/" else "/", f"{path}/" if path != "/" else "/"]))
            scheme_variants = list(dict.fromkeys([parsed.scheme, "http", "https"]))
            for scheme in scheme_variants:
                for path_variant in path_variants:
                    variant = urlunparse((scheme, parsed.netloc, path_variant, "", parsed.query, ""))
                    candidate = self.phase_admission.register(variant)
                    if not candidate or not self.phase_admission.is_valid_endpoint(candidate):
                        continue
                    fingerprint = candidate.get("exact_fingerprint") or candidate.get("url")
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                    fallback.append({
                        "url": candidate["url"],
                        "type": "seed",
                        "source": "seed_fallback",
                        "method": "GET",
                    })
        return self.classify_endpoints(fallback)

    def _discover_with_katana(self, seed_urls: List[str]) -> List[Dict]:
        """Use katana CLI for deeper JS-aware crawling with retry mechanism."""
        if not check_tools(["katana"]).get("katana"):
            return []
        seeds = [u for u in seed_urls[:30] if u.startswith(("http://", "https://"))]
        if not seeds:
            return []
        
        max_retries = max(1, config.CRAWLER_TOOL_MAX_RETRIES)
        per_url_timeout = min(int(config.KATANA_TIMEOUT), 45)
        run_timeout = min(int(config.KATANA_RUN_TIMEOUT), max(45, 6 * len(seeds)))
        for attempt in range(max_retries):
            rc, stdout, stderr = run_command(
                [
                    "katana", "-silent", "-d", "3", "-list", "-",
                    "-c", str(config.KATANA_CONCURRENCY),
                    "-rl", str(config.KATANA_RATE_LIMIT),
                    "-timeout", str(per_url_timeout),
                    "-retry", "1",
                    "-mrs", "2000000"
                ],
                timeout=run_timeout,
                stdin_data="\n".join(seeds) + "\n"
            )
            if rc == 0 and stdout:
                found = []
                for line in stdout.splitlines():
                    u = line.strip()
                    if not u:
                        continue
                    found.append({"url": u, "type": "katana", "source": "katana", "method": "GET"})
                logger.info(f"[DISCOVERY] Katana discovered {len(found)} endpoints")
                return found
            if rc == -2:
                logger.warning("[DISCOVERY] Katana timed out; skipping immediate retry")
                if not config.CRAWLER_RETRY_ON_TIMEOUT:
                    break
            if attempt < max_retries - 1:
                logger.debug(f"[DISCOVERY] Katana attempt {attempt + 1} failed (rc={rc}): {stderr[:120]}")
                time.sleep(1 + attempt)
            else:
                logger.warning(f"[DISCOVERY] Katana exhausted {max_retries} attempts")
        return []

    def _discover_with_hakrawler(self, seed_urls: List[str]) -> List[Dict]:
        """Use hakrawler for alternate crawl strategy with retry mechanism."""
        if not check_tools(["hakrawler"]).get("hakrawler"):
            return []
        seeds = [u for u in seed_urls[:30] if u.startswith(("http://", "https://"))]
        if not seeds:
            return []
        
        max_retries = max(1, config.CRAWLER_TOOL_MAX_RETRIES)
        for attempt in range(max_retries):
            rc, stdout, stderr = run_command(
                ["hakrawler", "-subs", "-d", "3", "-t", str(config.HAKRAWLER_THREADS), "-u"],
                timeout=config.HAKRAWLER_RUN_TIMEOUT,
                stdin_data="\n".join(seeds) + "\n"
            )
            if rc == 0 and stdout:
                found = self._parse_plain_url_output(stdout, source="hakrawler")
                logger.info(f"[DISCOVERY] Hakrawler discovered {len(found)} endpoints")
                return found
            if rc == -2:
                logger.warning("[DISCOVERY] Hakrawler timed out; skipping immediate retry")
                if not config.CRAWLER_RETRY_ON_TIMEOUT:
                    break
            if attempt < max_retries - 1:
                logger.debug(f"[DISCOVERY] Hakrawler attempt {attempt + 1} failed (rc={rc}): {stderr[:120]}")
                time.sleep(1 + attempt)
            else:
                logger.warning(f"[DISCOVERY] Hakrawler exhausted {max_retries} attempts")
        return []

    def _discover_with_param_tools(self, seed_urls: List[str]) -> List[Dict]:
        """Discover hidden parameters and convert to testable endpoints."""
        out: List[Dict] = []
        seeds = [u for u in seed_urls[:20] if u.startswith(("http://", "https://"))]
        if not seeds:
            return out

        if check_tools(["arjun"]).get("arjun"):
            for url in seeds[:8]:
                # FIX: Skip arjun on static URLs without query strings or API patterns
                api_patterns = ["/api/", "/graphql", "/rest/", "/wp-json"]
                has_query = "?" in url
                has_api = any(p in url for p in api_patterns)
                if not has_query and not has_api:
                    logger.debug(f"[DISCOVERY] Skipping arjun on static URL: {url}")
                    continue
                with tempfile.NamedTemporaryFile(prefix="arjun_", suffix=".txt", delete=False) as tf:
                    out_file = tf.name
                try:
                    rc, stdout, stderr = run_command(
                        ["arjun", "-u", url, "-oT", out_file, "-q", "-t", "8"],
                        timeout=120
                    )
                    if rc == -4 or (stderr and "Traceback" in stderr):
                        logger.warning("[DISCOVERY] Arjun failed at runtime; skipping remaining Arjun jobs")
                        break
                    if rc == 0 and os.path.exists(out_file):
                        with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                param = line.strip()
                                if not param or "=" in param:
                                    continue
                                sep = "&" if "?" in url else "?"
                                out.append(
                                    {
                                        "url": f"{url}{sep}{param}=FUZZ",
                                        "type": "param",
                                        "source": "arjun",
                                        "method": "GET",
                                    }
                                )
                except Exception as e:
                    logger.debug(f"[DISCOVERY] Arjun failed for {url}: {e}")
                finally:
                    if os.path.exists(out_file):
                        os.unlink(out_file)

        if check_tools(["paramspider"]).get("paramspider"):
            domains = sorted({urllib.parse.urlparse(u).netloc for u in seeds if urllib.parse.urlparse(u).netloc})
            # FIX: Only run paramspider on domains with API patterns or historical query strings
            api_patterns = ["/api/", "/graphql", "/rest/", "/wp-json"]
            domains_with_potential = []
            for domain in domains:
                domain_seeds = [u for u in seeds if urllib.parse.urlparse(u).netloc == domain]
                has_api = any(any(p in u for p in api_patterns) for u in domain_seeds)
                has_params = any("?" in u for u in domain_seeds)
                if has_api or has_params:
                    domains_with_potential.append(domain)
            if not domains_with_potential:
                logger.debug("[DISCOVERY] Skipping paramspider - no API patterns or query strings found")
            else:
                for domain in domains_with_potential[:4]:
                    rc, stdout, stderr = run_command(["paramspider", "-d", domain, "-s"], timeout=180)
                    if rc == -4 or (stderr and "Traceback" in stderr):
                        logger.warning("[DISCOVERY] ParamSpider failed at runtime; skipping remaining ParamSpider jobs")
                        break
                    if rc != 0 or not stdout:
                        continue
                    out.extend(self._parse_plain_url_output(stdout, source="paramspider"))

        if out:
            logger.info(f"[DISCOVERY] Param tools discovered {len(out)} endpoints")
        return out

    def _discover_with_js_tools(self, seed_urls: List[str]) -> List[Dict]:
        """Extract endpoints from JavaScript assets using external analyzers."""
        out: List[Dict] = []
        js_assets = self._collect_js_assets(seed_urls[:20])[:30]
        if not js_assets:
            return out

        if check_tools(["jsfinder2"]).get("jsfinder2"):
            for js_url in js_assets[:20]:
                with tempfile.NamedTemporaryFile(prefix="jsfinder2_", suffix=".txt", delete=False) as tf:
                    url_file = tf.name
                try:
                    rc, stdout, _ = run_command(
                        ["jsfinder2", "-u", js_url, "-ou", url_file],
                        timeout=90
                    )
                    if os.path.exists(url_file):
                        with open(url_file, "r", encoding="utf-8", errors="ignore") as f:
                            out.extend(self._parse_plain_url_output(f.read(), source="jsfinder2"))
                    elif rc == 0 and stdout:
                        out.extend(self._parse_plain_url_output(stdout, source="jsfinder2"))
                except Exception as e:
                    logger.debug(f"[DISCOVERY] JSFinder2 failed for {js_url}: {e}")
                finally:
                    if os.path.exists(url_file):
                        os.unlink(url_file)

        # LinkFinder fallback when installed as Python module only.
        for js_url in js_assets[:10]:
            rc, stdout, _ = run_command(
                ["python", "-m", "linkfinder", "-i", js_url, "-o", "cli"],
                timeout=90
            )
            if rc == 0 and stdout:
                out.extend(self._parse_plain_url_output(stdout, source="linkfinder"))

        if out:
            logger.info(f"[DISCOVERY] JS tools discovered {len(out)} endpoints")
        return out

    def _collect_js_assets(self, seed_urls: List[str]) -> List[str]:
        assets: List[str] = []
        for url in seed_urls:
            try:
                response = self.http_client.get(url, timeout=8)
                if response.status_code >= 400:
                    continue
                soup = BeautifulSoup(response.text, "html.parser")
                for tag in soup.find_all("script", src=True):
                    script_src = tag.get("src", "").strip()
                    normalized = self.normalize_endpoint(script_src, url)
                    if normalized and normalized.endswith(".js"):
                        assets.append(normalized)
            except Exception:
                continue
        return list(dict.fromkeys(assets))

    def _parse_plain_url_output(self, text: str, source: str) -> List[Dict]:
        found: List[Dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("[") or "usage:" in line.lower():
                continue
            match = re.search(r"https?://[^\s'\"<>]+", line)
            if not match:
                continue
            found.append(
                {
                    "url": match.group(0),
                    "type": source,
                    "source": source,
                    "method": "GET",
                }
            )
        return found

    def discover_from_url(self, url: str) -> List[Dict]:
        """Discover endpoints from a single URL"""
        endpoints = []
        record = self.phase_admission.register(url)
        if not record or not self.phase_admission.is_valid_endpoint(record):
            return endpoints

        host = record.get("host") or ""
        if host and self.phase_admission.optimizer.is_host_blacklisted(host):
            return endpoints

        url = record.get("url") or url
        
        # Skip binary files to avoid parsing errors
        binary_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.zip', '.tar', '.gz', 
                            '.mp4', '.avi', '.mov', '.pdf', '.exe', '.dll', '.so',
                            '.bin', '.iso', '.deb', '.rpm', '.woff', '.woff2', '.ttf'}
        url_lower = url.lower()
        if any(url_lower.endswith(ext) for ext in binary_extensions):
            logger.debug(f"[DISCOVERY] Skipping binary asset: {url}")
            return endpoints

        try:
            response = self.http_client.get(url, timeout=10)

            if response.status_code != 200:
                return endpoints

            content = response.text
            soup = BeautifulSoup(content, 'html.parser')

            # Extract from HTML links
            endpoints.extend(self.extract_from_links(soup, url))

            # Extract from forms
            endpoints.extend(self.extract_from_forms(soup, url))

            # Extract from JavaScript
            endpoints.extend(self.extract_from_javascript(content, url))

            # Extract from comments
            endpoints.extend(self.extract_from_comments(soup, url))

        except Exception as e:
            if "Skipping blacklisted host" in str(e):
                return endpoints
            logger.debug(f"[DISCOVERY] Error discovering from {url}: {e}")

        return endpoints

    def extract_from_links(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract endpoints from HTML links"""
        endpoints = []

        for link in soup.find_all('a', href=True):
            href = link['href']
            endpoint = self.normalize_endpoint(href, base_url)
            if endpoint:
                endpoints.append({
                    "url": endpoint,
                    "type": "link",
                    "source": base_url,
                    "method": "GET"
                })

        return endpoints

    def extract_from_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract endpoints from HTML forms"""
        endpoints = []

        for form in soup.find_all('form'):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()

            endpoint = self.normalize_endpoint(action, base_url)
            if endpoint:
                # Extract form parameters
                params = []
                for input_field in form.find_all('input'):
                    name = input_field.get('name', '')
                    if name:
                        params.append(name)

                endpoints.append({
                    "url": endpoint,
                    "type": "form",
                    "source": base_url,
                    "method": method,
                    "parameters": params
                })

        return endpoints

    def extract_from_javascript(self, content: str, base_url: str) -> List[Dict]:
        """Extract endpoints from JavaScript code"""
        endpoints = []

        # Common patterns for URLs in JavaScript
        patterns = [
            r'["\']([^"\']*\.(?:php|asp|jsp|do|action))["\']',
            r'["\'](/[^"\']*(?:api|rest|json)[^"\']*)["\']',
            r'(?:url|href|src):\s*["\']([^"\']+)["\']',
            r'\$\.(?:get|post|ajax)\(["\']([^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'XMLHttpRequest.*open\([^,]+,\s*["\']([^"\']+)["\']'
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                endpoint = self.normalize_endpoint(match, base_url)
                if endpoint:
                    endpoints.append({
                        "url": endpoint,
                        "type": "javascript",
                        "source": base_url,
                        "method": "GET"  # Default, could be refined
                    })

        return endpoints

    def extract_from_comments(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract endpoints from HTML comments"""
        endpoints = []

        for comment in soup.find_all(text=lambda text: isinstance(text, str) and '<!--' in text):
            # Look for URLs in comments
            urls = re.findall(r'https?://[^\s<>"\']+', str(comment))
            for url in urls:
                endpoint = self.normalize_endpoint(url, base_url)
                if endpoint:
                    endpoints.append({
                        "url": endpoint,
                        "type": "comment",
                        "source": base_url,
                        "method": "GET"
                    })

        return endpoints

    def normalize_endpoint(self, endpoint: str, base_url: str) -> str:
        """Normalize an endpoint URL"""
        if not endpoint:
            return None
        record = self.phase_admission.register(endpoint, base_url=base_url)
        if not record or not self.phase_admission.is_valid_endpoint(record):
            return None

        parsed = urllib.parse.urlparse(record["url"])
        if any(parsed.path.endswith(ext) for ext in self.exclude_extensions):
            return None

        return record["url"]

    def deduplicate_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Remove duplicate endpoints with intelligent URL normalization.
        
        FIX #7: Normalize URLs, strip noise params (fbclid, utm_*, etc.), handle query variations
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        seen = {}  # Map normalized URL -> original endpoint
        unique = []
        noise_params = {'fbclid', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'gclid', 'msclkid'}

        for ep in endpoints:
            url = ep.get('url', '')
            if not url:
                continue
            
            # Normalize URL: parse, filter params, reconstruct
            try:
                parsed = urllib.parse.urlparse(url)
                
                # Filter out noise tracking parameters
                if parsed.query:
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    clean_params = {k: v for k, v in params.items() if k.lower() not in noise_params}
                    clean_query = urlencode(clean_params, doseq=True) if clean_params else ""
                else:
                    clean_query = ""
                
                # Reconstruct normalized URL (without fragment)
                normalized_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc.lower(),  # Domain lowercase
                    parsed.path,
                    parsed.params,
                    clean_query,
                    ""  # Remove fragment
                ))
                
                # Also check if we've seen this without params
                path_only_key = urlunparse((parsed.scheme, parsed.netloc.lower(), parsed.path, parsed.params, "", ""))
                
                # Avoid duplicates by normalized URL
                if normalized_url not in seen and path_only_key not in seen:
                    seen[normalized_url] = True
                    unique.append(ep)
                    
            except Exception as e:
                # Fallback to simple dedup if parsing fails
                if url not in seen:
                    seen[url] = True
                    unique.append(ep)
                logger.debug(f"[CRAWLER] Failed to normalize {url}: {e}")

        logger.debug(f"[CRAWLER] Deduplicated {len(endpoints)} → {len(unique)} endpoints")
        return unique

    def _scan_for_apis(self, endpoints: List[Dict]) -> List[Dict]:
        """Run API scanner on endpoints to detect REST/GraphQL APIs.
        
        NEW: Integrates API scanner into the discovery phase to identify
        API endpoints early and add them to the endpoint pool for testing.
        """
        api_scanner = APIScannerRunner(self.output_dir)
        api_findings = []
        
        # Get base URLs from endpoints
        base_urls = set()
        for ep in endpoints:
            url = ep.get('url', '')
            if url:
                record = self.phase_admission.register(url)
                if not record or not self.phase_admission.is_valid_endpoint(record):
                    continue
                if record.get("host") and self.phase_admission.optimizer.is_host_blacklisted(record["host"]):
                    continue
                parsed = urllib.parse.urlparse(record.get("url") or url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                base_urls.add(base_url)
        
        # Scan each base URL for APIs
        for base_url in list(base_urls)[:5]:  # Limit to 5 base URLs
            try:
                # Get content for scanning
                content = ""
                try:
                    response = self.http_client.get(base_url, timeout=10)
                    if response.status_code == 200:
                        content = response.text
                except:
                    pass
                
                # Run API scanner
                result = api_scanner.scan(base_url, content=content)
                
                # Convert API findings to endpoint format
                for rest_ep in result.get('rest_endpoints', []):
                    if isinstance(rest_ep, str):
                        full_url = rest_ep if rest_ep.startswith('http') else f"{base_url}{rest_ep}"
                        api_findings.append({
                            'url': full_url,
                            'type': 'api_rest',
                            'source': 'api_scanner',
                            'method': 'GET',
                            'categories': ['api', 'rest'],
                            'parameters': []
                        })
                
                for graphql_ep in result.get('graphql_endpoints', []):
                    if isinstance(graphql_ep, str):
                        full_url = graphql_ep if graphql_ep.startswith('http') else f"{base_url}{graphql_ep}"
                        api_findings.append({
                            'url': full_url,
                            'type': 'api_graphql',
                            'source': 'api_scanner',
                            'method': 'POST',
                            'categories': ['api', 'graphql'],
                            'parameters': []
                        })
                
                # Store API vulnerabilities in state for later exploitation
                api_vulns = result.get('vulnerabilities', [])
                if api_vulns:
                    existing_api_vulns = self.state.get('api_vulnerabilities', []) or []
                    existing_api_vulns.extend(api_vulns)
                    self.state.update(api_vulnerabilities=existing_api_vulns)
                    logger.warning(f"[DISCOVERY] API scanner found {len(api_vulns)} API vulnerabilities on {base_url}")
                
            except Exception as e:
                logger.debug(f"[DISCOVERY] API scanner failed for {base_url}: {e}")
        
        return api_findings

    def classify_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Add classification metadata to endpoints"""
        classified = []
        
        # 🔥 FIX: Mở rộng patterns
        endpoint_patterns = {
            "admin": re.compile(r"/admin|/administrator|/wp-admin|/manager|/console|/dashboard|/panel", re.IGNORECASE),
            "upload": re.compile(r"/upload|/file|/attachment|/media|/wp-content/uploads", re.IGNORECASE),
            "api": re.compile(r"/api/|/v\d+/|/graphql|/rest/|/wp-json", re.IGNORECASE),
            "auth": re.compile(r"/login|/signin|/auth|/register|/password|/wp-login", re.IGNORECASE),
            "backup": re.compile(r"\.bak$|\.sql$|\.tar$|\.zip$|backup", re.IGNORECASE),
            "config": re.compile(r"\.env$|config\.|settings\.|\.ini$|\.cfg$|wp-config", re.IGNORECASE),
            "wordpress": re.compile(r"wp-content|wp-includes|xmlrpc\.php|wp-json|wp-login", re.IGNORECASE),
            "git": re.compile(r"\.git/|\.svn/|\.htaccess", re.IGNORECASE),
            "rpc": re.compile(r"xmlrpc|soap|rpc", re.IGNORECASE),  # 🔥 THÊM
            "params": re.compile(r"\?.*=", re.IGNORECASE)
        }
        
        for ep in endpoints:
            url = ep.get('url', '')
            categories = []
            
            # 🔥 FIX: Check từng pattern
            for category, pattern in endpoint_patterns.items():
                if pattern.search(url):
                    categories.append(category)
            
            # 🔥 FIX: Nếu không có category nào, gán mặc định
            if not categories:
                url_lower = url.lower()
                if 'wp' in url_lower or 'wordpress' in url_lower:
                    categories.append('wordpress')
                elif 'api' in url_lower:
                    categories.append('api')
                else:
                    categories.append('general')
            
            # Extract parameters
            parsed = urllib.parse.urlparse(url)
            params = list(parse_qs(parsed.query).keys()) if parsed.query else []
            
            # 🔥 FIX: Nếu không có params nhưng URL có dấu ?, thêm parameter mặc định
            if not params and '?' in url:
                params = ['q']
            
            ep.update({
                "categories": categories,
                "parameters": params,
                "path": parsed.path,
                "query": parsed.query
            })
            
            classified.append(ep)
        
        return classified
