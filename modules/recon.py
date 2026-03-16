"""
modules/recon.py - Recon Engine
External integrations for comprehensive surface discovery
"""

import json
import os
import logging
import ssl
import urllib.request
from typing import List, Set, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.state_manager import StateManager
from core.executor import check_tools, run_command
from integrations.subfinder_runner import SubfinderRunner
from integrations.gau_runner import GAURunner
from integrations.wayback_runner import WaybackRunner

logger = logging.getLogger("recon.engine")
# Constants
RECON_TOOLS = ["subfinder", "assetfinder", "crtsh", "gau", "waybackurls"]

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

        # Remove protocol if present
        self.target = self.target.replace("https://", "").replace("http://", "").strip()

        # Initialize integrations
        self.subfinder = SubfinderRunner(output_dir)
        self.gau = GAURunner(output_dir)
        self.wayback = WaybackRunner()

    def run(self):
        """Execute full reconnaissance pipeline"""
        print("DEBUG TARGET:", self.target)
        logger.info(f"[RECON] Starting reconnaissance for {self.target}")

        # Subdomain discovery
        subdomains = self.discover_subdomains()
        self.state.update(subdomains=subdomains)

        # Archived URL discovery
        archived_urls = self.discover_archived_urls()
        self.state.update(archived_urls=archived_urls)

        # Merge and deduplicate
        all_urls = self.merge_url_sources(subdomains, archived_urls)
        self.state.update(urls=all_urls)

        # Validate live hosts
        live_hosts = self.validate_live_hosts(all_urls)
        self.state.update(live_hosts=live_hosts)

        logger.info(f"[RECON] Completed: {len(subdomains)} subdomains, {len(archived_urls)} archived URLs, {len(live_hosts)} live hosts")

    def discover_subdomains(self) -> List[str]:
        """Discover subdomains using passive techniques"""
        logger.info("[RECON] Discovering subdomains")

        subdomains = set()

        # Subfinder (passive sources)
        subfinder_subs = self.subfinder.discover_subdomains(self.target)
        subdomains.update(subfinder_subs)

        # Could add more sources here (crt.sh, etc.)

        # Save to file
        subdomains_file = os.path.join(self.output_dir, "subdomains.txt")
        with open(subdomains_file, 'w') as f:
            f.write('\n'.join(sorted(subdomains)))

        logger.info(f"[RECON] Found {len(subdomains)} unique subdomains")
        return list(subdomains)

    def discover_archived_urls(self) -> List[str]:
        """Discover URLs from archive sources"""
        logger.info("[RECON] Discovering archived URLs")

        urls = set()

        # Wayback Machine
        wayback_urls = self.wayback.fetch_urls(self.target, max_urls=2000)
        urls.update(wayback_urls)

        # GetAllURLs (GAU)
        gau_urls = self.gau.fetch_urls(self.target, max_urls=2000)
        urls.update(gau_urls)

        # Save to file
        archived_file = os.path.join(self.output_dir, "archived_urls.txt")
        with open(archived_file, 'w') as f:
            f.write('\n'.join(sorted(urls)))

        logger.info(f"[RECON] Found {len(urls)} archived URLs")
        return list(urls)

    def merge_url_sources(self, subdomains: List[str], archived_urls: List[str]) -> List[str]:
        """Merge and deduplicate URLs from all sources"""
        all_urls = set()

        # Add subdomains as URLs
        for sub in subdomains:
            all_urls.add(f"https://{sub}")
            all_urls.add(f"http://{sub}")

        # Add archived URLs
        all_urls.update(archived_urls)

        # Normalize URLs
        from core.url_normalizer import URLNormalizer
        normalizer = URLNormalizer()
        normalized = normalizer.normalize_urls(list(all_urls))

        logger.info(f"[RECON] Merged to {len(normalized)} unique URLs")
        return normalized

    def validate_live_hosts(self, urls: List[str]) -> List[Dict]:
        """Validate which hosts are live"""
        logger.info("[RECON] Validating live hosts")

        live_hosts = []

        # Import HTTP client for validation
        from core.http_engine import HTTPClient
        from core.session_manager import SessionManager
        
        session = SessionManager(self.output_dir)
        http_client = HTTPClient(session)

        # Check URLs in parallel
        def check_url(url):
            try:
                response = http_client.get(url, timeout=10)
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

        # Use ThreadPoolExecutor for parallel checking
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_url, url) for url in urls[:200]]  # Limit to 200 URLs
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)

        logger.info(f"[RECON] Validated {len(live_hosts)} live hosts out of {len(urls[:200])} checked")
        return live_hosts
