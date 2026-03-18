"""
integrations/browser_crawler.py - Browser-based JavaScript crawler.
Requires playwright to be installed in the environment.
"""

import logging
from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("recon.browser_crawler")


class BrowserCrawler:
    def __init__(self, timeout_ms: int = 15000):
        self.timeout_ms = timeout_ms

    def crawl(self, url: str, max_links: int = 200) -> List[Dict[str, Any]]:
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            logger.warning("[BROWSER] playwright is not available, skipping JS crawl")
            return []

        findings: List[Dict[str, Any]] = []
        parsed_base = urlparse(url)

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(ignore_https_errors=True)
                page.goto(url, wait_until="networkidle", timeout=self.timeout_ms)

                # Collect href/src/action and fetch/XHR URLs.
                links = page.eval_on_selector_all(
                    "a[href],script[src],link[href],form[action]",
                    """els => els.map(e => e.getAttribute('href') || e.getAttribute('src') || e.getAttribute('action')).filter(Boolean)"""
                )
                xhr_urls = page.evaluate(
                    """() => {
                        const out = [];
                        const resources = performance.getEntriesByType("resource");
                        for (const r of resources) { out.push(r.name); }
                        return out;
                    }"""
                )
                browser.close()
        except Exception as e:
            logger.debug(f"[BROWSER] Crawl failed for {url}: {e}")
            return []

        merged = (links or []) + (xhr_urls or [])
        seen = set()
        for raw in merged[: max_links * 2]:
            abs_url = urljoin(url, raw)
            parsed = urlparse(abs_url)
            if parsed.scheme not in ("http", "https"):
                continue
            if parsed.netloc != parsed_base.netloc:
                continue
            clean = abs_url.split("#")[0]
            if clean in seen:
                continue
            seen.add(clean)
            findings.append(
                {
                    "url": clean,
                    "type": "browser_js",
                    "source": url,
                    "method": "GET",
                }
            )
            if len(findings) >= max_links:
                break

        logger.info(f"[BROWSER] {url} -> {len(findings)} JS-discovered endpoints")
        return findings
