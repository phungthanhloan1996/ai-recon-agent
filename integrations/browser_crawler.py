"""
integrations/browser_crawler.py - HTTP-based crawler (replaces Playwright).
"""
import logging
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("recon.browser_crawler")

class BrowserCrawler:
    def __init__(self, timeout_ms: int = 15000, target_scheme: Optional[str] = None):
        self.timeout = timeout_ms / 1000
        self.target_scheme = target_scheme or "https"

    def crawl(self, url: str, max_links: int = 200) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        parsed_base = urlparse(url)
        try:
            resp = requests.get(url, timeout=self.timeout, verify=False,
                                headers={"User-Agent": "Mozilla/5.0"})
            soup = BeautifulSoup(resp.text, "html.parser")
            raw_links = []
            for tag in soup.find_all(["a", "script", "link", "form"]):
                val = tag.get("href") or tag.get("src") or tag.get("action")
                if val:
                    raw_links.append(val)
        except Exception as e:
            logger.debug(f"[BROWSER] Crawl failed for {url}: {e}")
            return []

        seen = set()
        for raw in raw_links[:max_links * 2]:
            abs_url = urljoin(url, raw)
            parsed = urlparse(abs_url)
            if parsed.scheme not in ("http", "https"):
                continue
            if self.target_scheme.lower() == "http" and parsed.scheme == "https":
                continue
            if parsed.netloc != parsed_base.netloc:
                continue
            clean = abs_url.split("#")[0]
            if clean in seen:
                continue
            seen.add(clean)
            findings.append({"url": clean, "type": "browser_js",
                             "source": url, "method": "GET"})
            if len(findings) >= max_links:
                break

        logger.info(f"[BROWSER] {url} -> {len(findings)} endpoints")
        return findings