"""
modules/crawler.py - Discovery Engine
Endpoint extraction from HTML, JavaScript, forms, and hidden parameters
"""

import os
import re
import logging
from typing import Dict, List, Set
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup

from core.state_manager import StateManager
from core.http_engine import HTTPClient

logger = logging.getLogger("recon.discovery")


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

    def run(self):
        """Execute endpoint discovery pipeline"""
        logger.info("[DISCOVERY] Starting endpoint discovery")

        urls = self.state.get("urls", [])
        discovered_endpoints = []

        for url in urls[:50]:  # Limit for performance
            try:
                endpoints = self.discover_from_url(url)
                discovered_endpoints.extend(endpoints)
            except Exception as e:
                logger.debug(f"[DISCOVERY] Failed to discover from {url}: {e}")

        # Remove duplicates and filter
        unique_endpoints = self.deduplicate_endpoints(discovered_endpoints)

        # Classify endpoints
        classified = self.classify_endpoints(unique_endpoints)

        self.state.update(endpoints=classified)

        # Save to file
        endpoints_file = os.path.join(self.output_dir, "endpoints.txt")
        with open(endpoints_file, 'w') as f:
            for ep in classified:
                f.write(f"{ep.get('url', '')}\n")

        logger.info(f"[DISCOVERY] Discovered {len(classified)} unique endpoints")

    def discover_from_url(self, url: str) -> List[Dict]:
        """Discover endpoints from a single URL"""
        endpoints = []

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

        # Skip external domains
        if endpoint.startswith(('http://', 'https://')):
            parsed = urlparse(endpoint)
            base_parsed = urlparse(base_url)
            if parsed.netloc and parsed.netloc != base_parsed.netloc:
                return None

        # Convert relative to absolute
        if not endpoint.startswith(('http://', 'https://')):
            base_parsed = urlparse(base_url)
            if endpoint.startswith('/'):
                endpoint = f"{base_parsed.scheme}://{base_parsed.netloc}{endpoint}"
            else:
                # Relative path
                base_path = base_parsed.path.rsplit('/', 1)[0] + '/'
                endpoint = f"{base_parsed.scheme}://{base_parsed.netloc}{base_path}{endpoint}"

        # Remove fragments
        endpoint = endpoint.split('#')[0]

        # Skip excluded extensions
        parsed = urlparse(endpoint)
        if any(parsed.path.endswith(ext) for ext in self.exclude_extensions):
            return None

        return endpoint

    def deduplicate_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Remove duplicate endpoints"""
        seen = set()
        unique = []

        for ep in endpoints:
            url = ep.get('url', '')
            if url and url not in seen:
                seen.add(url)
                unique.append(ep)

        return unique

    def classify_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Add classification metadata to endpoints"""
        classified = []

        for ep in endpoints:
            url = ep.get('url', '')
            categories = []

            # Classify based on patterns
            for category, pattern in self.endpoint_patterns.items():
                if pattern.search(url):
                    categories.append(category)

            # Extract parameters
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys()) if parsed.query else []

            ep.update({
                "categories": categories,
                "parameters": params,
                "path": parsed.path,
                "query": parsed.query
            })

            classified.append(ep)

        return classified
    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.urls_file = os.path.join(output_dir, "urls.txt")
        self.endpoints_file = os.path.join(output_dir, "endpoints.txt")

    def run(self) -> Dict:
        logger.info(f"\n{'='*60}")
        logger.info(f"  PHASE 3: CRAWLING & URL DISCOVERY")
        logger.info(f"{'='*60}")

        self.state.set_phase("crawling")
        live_hosts = self.state.get("live_hosts", [])
        tool_status = check_tools(CRAWL_TOOLS)
        all_urls: Set[str] = set()

        if not live_hosts:
            logger.warning("[CRAWL] No live hosts found, crawling base target")
            live_hosts = [{"url": f"https://{self.target}"}]

        hosts_to_crawl = live_hosts[:20]
        logger.info(f"[CRAWL] Crawling {len(hosts_to_crawl)} hosts (parallel max {CRAWL_MAX_PARALLEL_HOSTS}), depth={CRAWL_DEPTH}")

        def _crawl_one_host(host: dict) -> Tuple[str, Set[str]]:
            base_url = host.get("url", "")
            if not base_url:
                return base_url or "?", set()
            urls: Set[str] = set()
            if tool_status.get("katana"):
                urls.update(self._run_katana(base_url))
            if tool_status.get("gau"):
                urls.update(self._run_gau(urlparse(base_url).netloc))
            if tool_status.get("waybackurls"):
                urls.update(self._run_waybackurls(urlparse(base_url).netloc))
            if tool_status.get("hakrawler"):
                urls.update(self._run_hakrawler(base_url))
            return base_url, urls

        with ThreadPoolExecutor(max_workers=min(CRAWL_MAX_PARALLEL_HOSTS, len(hosts_to_crawl))) as executor:
            futures = {executor.submit(_crawl_one_host, h): h for h in hosts_to_crawl}
            for future in as_completed(futures):
                try:
                    base_url, urls = future.result()
                    all_urls.update(urls)
                    logger.info(f"[CRAWL] {base_url} → {len(urls)} URLs")
                except Exception as e:
                    logger.warning(f"[CRAWL] Host failed: {e}")

        if not any(tool_status.values()):
            logger.warning("[CRAWL] No crawl tools available! Using basic URL generation")
            all_urls.update(self._generate_basic_urls())

        # Filter and categorize
        filtered_urls = self._filter_urls(all_urls)
        endpoints = self._categorize_endpoints(filtered_urls)

        # Save files
        self._save_urls(filtered_urls)
        self._save_endpoints(endpoints)

        # Update state
        self.state.update(urls=list(filtered_urls))
        for ep in endpoints:
            self.state.add_endpoint(ep)

        # Parameter Discovery
        param_tool_status = check_tools(PARAM_TOOLS)
        if any(param_tool_status.values()):
            logger.info("[CRAWL] Running parameter discovery...")
            params_found = self._run_param_discovery(filtered_urls, param_tool_status)
            self.state.update(params=params_found)
            logger.info(f"[CRAWL] Found {len(params_found)} parameter sets")

        # JavaScript Endpoint Extraction
        js_tool_status = check_tools(JS_TOOLS)
        if any(js_tool_status.values()):
            logger.info("[CRAWL] Extracting endpoints from JavaScript...")
            js_endpoints = self._run_js_extraction(filtered_urls, js_tool_status)
            for ep in js_endpoints:
                self.state.add_endpoint(ep)
            logger.info(f"[CRAWL] Extracted {len(js_endpoints)} JS endpoints")

        logger.info(f"[CRAWL] Total: {len(filtered_urls)} URLs, {len(endpoints)} categorized endpoints")
        return {"urls": list(filtered_urls), "endpoints": endpoints}

    def _run_katana(self, url: str) -> Set[str]:
        cmd = [
            "katana",
            "-u", url,
            "-d", str(CRAWL_DEPTH),
            "-jc",
            "-silent",
            "-timeout", "10",
            "-c", "20",
        ]
        _, stdout, _ = run_command(cmd, timeout=180)
        return self._parse_urls(stdout)

    def _run_gau(self, domain: str) -> Set[str]:
        # gau nhận domain qua stdin hoặc argument tùy version
        cmd = ["gau", "--threads", "5", "--timeout", "30", domain]
        _, stdout, stderr = run_command(cmd, timeout=120)
        if not stdout and stderr:
            # fallback: pipe qua stdin
            cmd2 = ["gau", "--threads", "5"]
            _, stdout, _ = run_command(cmd2, timeout=120, stdin_data=domain)
        return self._parse_urls(stdout)

    def _run_waybackurls(self, domain: str) -> Set[str]:
        # waybackurls nhận domain từ stdin
        cmd = ["waybackurls"]
        _, stdout, _ = run_command(cmd, timeout=120, stdin_data=domain)
        return self._parse_urls(stdout)

    def _run_hakrawler(self, url: str) -> Set[str]:
        # hakrawler đọc URLs từ stdin
        cmd = ["hakrawler", "-depth", "2", "-plain", "-insecure"]
        _, stdout, _ = run_command(cmd, timeout=120, stdin_data=url)
        return self._parse_urls(stdout)

    def _parse_urls(self, output: str) -> Set[str]:
        urls = set()
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("http"):
                urls.add(line)
        return urls

    def _filter_urls(self, urls: Set[str]) -> Set[str]:
        """Filter out static assets and irrelevant URLs"""
        filtered = set()
        for url in urls:
            parsed = urlparse(url)
            path = parsed.path.lower()
            
            # Skip static assets
            skip = False
            for ext in EXCLUDE_EXTENSIONS:
                if path.endswith(ext):
                    skip = True
                    break
            
            if not skip:
                filtered.add(url)
        
        return filtered

    def _categorize_endpoints(self, urls: Set[str]) -> List[Dict]:
        """Categorize URLs into endpoint types"""
        endpoints = []
        seen_paths = set()

        for url in urls:
            parsed = urlparse(url)
            path = parsed.path

            if path in seen_paths:
                continue
            seen_paths.add(path)

            categories = []
            for cat, pattern in ENDPOINT_PATTERNS.items():
                if re.search(pattern, url, re.IGNORECASE):
                    categories.append(cat)

            endpoint = {
                "url": url,
                "path": path,
                "host": parsed.netloc,
                "has_params": bool(parsed.query),
                "categories": categories,
                "params": parsed.query.split("&") if parsed.query else [],
            }

            if categories or parsed.query:  # Only keep interesting endpoints
                endpoints.append(endpoint)
                logger.debug(f"[CRAWL] Endpoint: {path} [{', '.join(categories)}]")

        return endpoints

    def _generate_basic_urls(self) -> Set[str]:
        """Generate common URLs when no crawl tools are available"""
        common_paths = [
            "/", "/admin", "/login", "/wp-admin", "/api",
            "/upload", "/backup", "/.env", "/.git/HEAD",
            "/robots.txt", "/sitemap.xml", "/phpinfo.php",
            "/wp-login.php", "/xmlrpc.php", "/wp-json/wp/v2/users",
        ]
        urls = set()
        for host in self.state.get("live_hosts", [{"url": f"https://{self.target}"}]):
            base = host.get("url", "").rstrip("/")
            for path in common_paths:
                urls.add(base + path)
        return urls

    def _save_urls(self, urls: Set[str]):
        with open(self.urls_file, "w") as f:
            f.write("\n".join(sorted(urls)) + "\n")
        logger.info(f"[CRAWL] Saved {len(urls)} URLs → {self.urls_file}")

    def _save_endpoints(self, endpoints: List[Dict]):
        with open(self.endpoints_file, "w") as f:
            for ep in endpoints:
                cats = ",".join(ep["categories"]) if ep["categories"] else "misc"
                f.write(f"[{cats}] {ep['url']}\n")
        logger.info(f"[CRAWL] Saved {len(endpoints)} endpoints → {self.endpoints_file}")

    def _run_param_discovery(self, urls: Set[str], tool_status: Dict[str, bool]) -> List[Dict]:
        """Run parameter discovery on endpoints without params"""
        params_found = []
        endpoints_no_params = [u for u in urls if "?" not in u and not any(ext in u for ext in EXCLUDE_EXTENSIONS)]

        if tool_status.get("arjun"):
            for url in endpoints_no_params[:50]:  # Limit to avoid too many
                cmd = ["arjun", "-u", url, "--passive", "--timeout", "10"]
                _, stdout, _ = run_command(cmd, timeout=60)
                if stdout:
                    params = self._parse_arjun_output(stdout)
                    if params:
                        params_found.append({"url": url, "params": params})

        if tool_status.get("paramspider"):
            for url in endpoints_no_params[:50]:
                cmd = ["paramspider", "-d", urlparse(url).netloc, "--level", "low"]
                _, stdout, _ = run_command(cmd, timeout=60)
                if stdout:
                    params = self._parse_paramspider_output(stdout)
                    if params:
                        params_found.append({"url": url, "params": params})

        return params_found

    def _run_js_extraction(self, urls: Set[str], tool_status: Dict[str, bool]) -> List[Dict]:
        """Extract endpoints from JavaScript files"""
        js_endpoints = []
        js_files = [u for u in urls if u.endswith(".js") and not any(ext in u for ext in [".min.js"])]

        for js_url in js_files[:20]:  # Limit
            if tool_status.get("linkfinder"):
                cmd = ["linkfinder", "-i", js_url, "-o", "cli"]
                _, stdout, _ = run_command(cmd, timeout=60)
                if stdout:
                    endpoints = self._parse_linkfinder_output(stdout)
                    js_endpoints.extend(endpoints)

            if tool_status.get("jsfinder"):
                cmd = ["jsfinder", "-u", js_url]
                _, stdout, _ = run_command(cmd, timeout=60)
                if stdout:
                    endpoints = self._parse_jsfinder_output(stdout)
                    js_endpoints.extend(endpoints)

        return js_endpoints

    def _parse_arjun_output(self, output: str) -> List[str]:
        """Parse arjun output for params"""
        params = []
        for line in output.splitlines():
            if "parameter" in line.lower():
                # Assume format like "Found 5 parameters: id, name, ..."
                parts = line.split(":")
                if len(parts) > 1:
                    params.extend([p.strip() for p in parts[1].split(",")])
        return params

    def _parse_paramspider_output(self, output: str) -> List[str]:
        """Parse paramspider output"""
        params = []
        for line in output.splitlines():
            if "?" in line:
                parsed = urlparse(line)
                if parsed.query:
                    params.extend(parsed.query.split("&"))
        return list(set(params))

    def _parse_linkfinder_output(self, output: str) -> List[Dict]:
        """Parse linkfinder output for endpoints"""
        endpoints = []
        for line in output.splitlines():
            if line.startswith("http"):
                endpoints.append({"url": line.strip(), "source": "js", "categories": ["api"]})
        return endpoints

    def _parse_jsfinder_output(self, output: str) -> List[Dict]:
        """Parse jsfinder output"""
        endpoints = []
        for line in output.splitlines():
            if "endpoint" in line.lower() or "/" in line:
                endpoints.append({"url": line.strip(), "source": "js", "categories": ["internal"]})
        return endpoints