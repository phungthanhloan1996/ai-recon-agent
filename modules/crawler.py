"""
modules/crawler.py - Phase 3: URL + Endpoint Discovery
Tools: katana, gau, waybackurls, hakrawler
Discover: parameters, API endpoints, uploads, admin panels
"""

import os
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse

from core.executor import run_command, check_tools
from core.state_manager import StateManager

logger = logging.getLogger("recon.phase3")

CRAWL_TOOLS = ["katana", "gau", "waybackurls", "hakrawler"]
# Số host crawl đồng thời; depth katana (env CRAWL_DEPTH=5 nếu muốn sâu hơn)
CRAWL_MAX_PARALLEL_HOSTS = int(os.environ.get("CRAWL_PARALLEL_HOSTS", "6"))
CRAWL_DEPTH = int(os.environ.get("CRAWL_DEPTH", "4"))

# Patterns to identify interesting endpoints
ENDPOINT_PATTERNS = {
    "admin": r"/admin|/administrator|/wp-admin|/manager|/console|/dashboard|/panel",
    "upload": r"/upload|/file|/attachment|/media",
    "api": r"/api/|/v\d+/|/graphql|/rest/",
    "auth": r"/login|/signin|/auth|/register|/password",
    "backup": r"\.bak$|\.sql$|\.tar$|\.zip$|backup",
    "config": r"\.env$|config\.|settings\.|\.ini$|\.cfg$",
    "wp": r"wp-content|wp-includes|xmlrpc\.php|wp-json",
    "git": r"\.git/|\.svn/|\.htaccess",
    "param": r"\?.*=",
}

EXCLUDE_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".svg",
    ".map", ".min.js", ".min.css"
}


class CrawlerModule:
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