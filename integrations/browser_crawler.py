import urllib.parse
"""
integrations/browser_crawler.py - Lightweight HTTP-based crawler (FALLBACK ONLY).

OPTIMIZATION: This is now a FALLBACK crawler. Primary crawling is done by hakrawler.
Only use this when hakrawler fails or for specific JS-heavy pages that need BeautifulSoup parsing.

FIX #2: Added blacklist checking before crawling to avoid crawling blacklisted hosts.
FIX #3: Integrated with GlobalConcurrencyManager for resource control.
"""
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

from core.scan_optimizer import get_optimizer
from core.resource_manager import get_concurrency_manager

logger = logging.getLogger("recon.browser_crawler")

class BrowserCrawler:
    """
    OPTIMIZATION: Lightweight HTTP crawler as FALLBACK only.
    - Primary crawler: hakrawler (fast, Go-based, no JS overhead)
    - This crawler: Only used when hakrawler fails or for specific needs
    - Reduced timeout, limited depth, no JS execution
    
    FIX #2: Now checks host blacklist before crawling to avoid wasting resources
    on hosts that have been identified as problematic.
    """
    def __init__(self, timeout_ms: int = 8000, target_scheme: Optional[str] = None):
        # OPTIMIZATION: Reduced timeout from 15s to 8s
        self.timeout = timeout_ms / 1000
        self.target_scheme = target_scheme or "https"
        self.max_depth = 2  # OPTIMIZATION: Limited depth (was unlimited)
        self.rate_limit_delay = 0.1  # OPTIMIZATION: Small delay between requests
        self._logged_blacklisted_hosts = set()
        self._logged_blacklisted_urls = set()

    def _is_host_blacklisted(self, url: str) -> bool:
        """
        FIX #2: Check if the host is blacklisted before crawling.
        
        Args:
            url: URL to check
            
        Returns:
            True if host is blacklisted, False otherwise
        """
        try:
            optimizer = get_optimizer()
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or parsed.netloc
            
            if optimizer and optimizer.is_host_blacklisted(hostname):
                reason = optimizer.get_skip_reason(hostname) if hasattr(optimizer, 'get_skip_reason') else "blacklisted"
                if hostname not in self._logged_blacklisted_hosts:
                    logger.debug(f"[BROWSER] Skipping blacklisted host: {hostname} ({reason})")
                    self._logged_blacklisted_hosts.add(hostname)
                return True
        except Exception as e:
            # If optimizer fails, don't block crawling
            logger.debug(f"[BROWSER] Failed to check blacklist for {url}: {e}")
        
        return False

    def crawl(self, url: str, max_links: int = 100) -> List[Dict[str, Any]]:
        """
        OPTIMIZATION: Reduced max_links from 200 to 100.
        This is a FALLBACK crawler - use hakrawler for primary crawling.
        
        FIX #2: Now checks blacklist before crawling to avoid wasted effort.
        
        Args:
            url: URL to crawl
            max_links: Maximum number of links to extract
            
        Returns:
            List of discovered endpoints
        """
        # FIX #2: Check blacklist before crawling
        if self._is_host_blacklisted(url):
            if url not in self._logged_blacklisted_urls:
                logger.debug(f"[BROWSER] Skipping crawl for blacklisted URL: {url}")
                self._logged_blacklisted_urls.add(url)
            return []
        
        findings: List[Dict[str, Any]] = []
        parsed_base = urllib.parse.urlparse(url)
        try:
            # OPTIMIZATION: Use shorter timeout and simpler headers
            resp = requests.get(url, timeout=self.timeout, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; ReconAgent/1.0)"},
                                allow_redirects=False)  # OPTIMIZATION: Don't follow redirects
            soup = BeautifulSoup(resp.text, "html.parser")
            raw_links = []
            # OPTIMIZATION: Only extract <a> tags (skip script, link, form for speed)
            for tag in soup.find_all("a", href=True):
                raw_links.append(tag['href'])
        except Exception as e:
            logger.debug(f"[BROWSER] Crawl failed for {url}: {e}")
            return []

        seen = set()
        # OPTIMIZATION: Process fewer links
        for raw in raw_links[:max_links]:
            abs_url = urljoin(url, raw)
            parsed = urllib.parse.urlparse(abs_url)
            
            # FIX #2: Also check blacklist for discovered URLs
            if self._is_host_blacklisted(abs_url):
                continue
            
            if parsed.scheme not in ("http", "https"):
                continue
            if self.target_scheme.lower() == "http" and parsed.scheme == "https":
                continue
            if parsed.netloc != parsed_base.netloc:
                continue
            # OPTIMIZATION: Skip static assets
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.svg']):
                continue
            clean = abs_url.split("#")[0]
            if clean in seen:
                continue
            seen.add(clean)
            findings.append({"url": clean, "type": "browser_fallback",
                             "source": url, "method": "GET"})
            if len(findings) >= max_links:
                break

        logger.debug(f"[BROWSER] {url} -> {len(findings)} endpoints (fallback mode)")
        return findings

    def crawl_batch(self, urls: List[str], max_links_per_url: int = 100) -> List[Dict[str, Any]]:
        """
        Crawl multiple URLs with blacklist checking.
        
        Args:
            urls: List of URLs to crawl
            max_links_per_url: Maximum links to extract per URL
            
        Returns:
            List of all discovered endpoints
        """
        all_findings = []
        
        for url in urls:
            # FIX #2: Check blacklist before each crawl
            if self._is_host_blacklisted(url):
                logger.debug(f"[BROWSER] Skipping blacklisted URL in batch: {url}")
                continue
            
            findings = self.crawl(url, max_links_per_url)
            all_findings.extend(findings)
        
        return all_findings
