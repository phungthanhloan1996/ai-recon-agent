"""
modules/crawler.py - Discovery Engine
Endpoint extraction from HTML, JavaScript, forms, and hidden parameters
"""

import os
import re
import logging
from typing import Dict, List, Set, Tuple
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from core.executor import check_tools, run_command
from core.state_manager import StateManager
from core.http_engine import HTTPClient

logger = logging.getLogger("recon.discovery")

# Constants
CRAWL_TOOLS = ["katana", "gau", "waybackurls", "hakrawler"]
CRAWL_MAX_PARALLEL_HOSTS = 6
CRAWL_DEPTH = 4
PARAM_TOOLS = ["arjun", "paramspider"]
JS_TOOLS = ["linkfinder", "jsfinder"]
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

        for url in urls[:200]:  # Increased limit for better coverage
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