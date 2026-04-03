"""
integrations/wayback_runner.py - Wayback Machine Integration
Fetches URLs from Internet Archive Wayback Machine
"""

import requests
import logging
import os
import sys
import json
from typing import List, Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

logger = logging.getLogger("recon.wayback_runner")


class WaybackRunner:
    """
    Integration with Internet Archive Wayback Machine.
    Fetches historical URLs for comprehensive endpoint discovery.
    """

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize WaybackRunner.
        
        Args:
            output_dir: Directory to save results. If None, results are only returned in memory.
        """
        self.output_dir = output_dir
        self.base_url = "https://web.archive.org/cdx/search/cdx"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; WaybackURLFetcher/1.0)'
        })

    def fetch_urls(self, domain: str, max_urls: int = 5000) -> List[str]:
        """
        Fetch URLs from Wayback Machine with pagination support

        Args:
            domain: Target domain
            max_urls: Maximum URLs to fetch (can exceed 2000 with pagination)

        Returns:
            List of discovered URLs
        """
        urls = set()
        
        try:
            # Use configured pagination size (default 5000) instead of hard 2000 limit
            page_size = config.WAYBACK_PAGINATION_SIZE if hasattr(config, 'WAYBACK_PAGINATION_SIZE') else 5000
            pagination_step = config.WAYBACK_PAGINATION_OFFSET if hasattr(config, 'WAYBACK_PAGINATION_OFFSET') else 5000
            
            offset = 0
            fetched_count = 0
            
            while fetched_count < max_urls:
                logger.info(f"[WAYBACK] Fetching {domain} (offset: {offset}, total: {fetched_count})")
                
                # Wayback CDX API parameters with pagination
                params = {
                    'url': f"*.{domain}/*",  # Include subdomains
                    'output': 'json',
                    'fl': 'original',  # Only return original URLs
                    'collapse': 'urlkey',  # Collapse duplicates
                    'limit': min(page_size, max_urls - fetched_count),  # Limit per page
                    'offset': offset  # Pagination offset
                }

                response = self.session.get(self.base_url, params=params, timeout=30)

                if response.status_code == 200:
                    data = response.json()
                    page_urls = []
                    
                    # Skip header row if present and collect URLs
                    for row in data[1:] if len(data) > 0 else []:  # Skip first row (headers)
                        if isinstance(row, list) and len(row) > 0:
                            url = row[0]
                            if url.startswith(('http://', 'https://')) and url not in urls:
                                urls.add(url)
                                page_urls.append(url)
                                fetched_count += 1
                                if fetched_count >= max_urls:
                                    break
                    
                    # If we got fewer URLs than requested, we've hit the end
                    if len(page_urls) < min(page_size, max_urls - fetched_count + len(page_urls)):
                        logger.info(f"[WAYBACK] Reached end of results after {fetched_count} URLs")
                        break
                    
                    # Move to next page
                    offset += pagination_step
                else:
                    logger.error(f"[WAYBACK] API error: {response.status_code}")
                    break

            logger.info(f"[WAYBACK] Discovered {len(urls)} unique URLs from Wayback Machine")
            
            # Save results to file if output_dir is set
            if self.output_dir:
                self._save_results(domain, list(urls))
                return self._load_saved_urls(domain)[:max_urls]
            
            return list(urls)

        except requests.exceptions.RequestException as e:
            logger.error(f"[WAYBACK] Request error: {e}")
            if self.output_dir and urls:
                self._save_results(domain, list(urls))
                return self._load_saved_urls(domain)[:max_urls]
            return list(urls)
        except Exception as e:
            logger.error(f"[WAYBACK] Error: {e}")
            # Still try to save partial results
            if self.output_dir and urls:
                self._save_results(domain, list(urls))
                return self._load_saved_urls(domain)[:max_urls]
            return list(urls)

    def _save_results(self, domain: str, urls: List[str]):
        """Save fetched URLs to file in output directory"""
        if not self.output_dir:
            return
        
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            
            # Save as text file (one URL per line)
            safe_domain = domain.replace('.', '_').replace('/', '_')
            text_file = os.path.join(self.output_dir, f"wayback_{safe_domain}.txt")
            with open(text_file, 'w') as f:
                f.write('\n'.join(sorted(urls)))
            logger.debug(f"[WAYBACK] Saved {len(urls)} URLs to {text_file}")
            
            # Also save as JSON for structured data
            json_file = os.path.join(self.output_dir, f"wayback_{safe_domain}.json")
            data = {
                "domain": domain,
                "timestamp": __import__('time').time(),
                "url_count": len(urls),
                "urls": sorted(urls)
            }
            with open(json_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"[WAYBACK] Saved JSON to {json_file}")
            
        except Exception as e:
            logger.error(f"[WAYBACK] Failed to save results: {e}")

    def _load_saved_urls(self, domain: str) -> List[str]:
        """Read saved Wayback URL text output from disk."""
        if not self.output_dir:
            return []

        safe_domain = domain.replace('.', '_').replace('/', '_')
        text_file = os.path.join(self.output_dir, f"wayback_{safe_domain}.txt")
        try:
            with open(text_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"[WAYBACK] Failed to read saved URL file: {e}")
            return []

    def fetch_by_year(self, domain: str, year: int) -> List[str]:
        """Fetch URLs from a specific year"""
        urls = set()

        try:
            params = {
                'url': f"*.{domain}/*",
                'output': 'json',
                'fl': 'original',
                'collapse': 'urlkey',
                'from': year,
                'to': year
            }

            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for row in data:
                    if isinstance(row, list) and len(row) > 0:
                        url = row[0]
                        if url.startswith(('http://', 'https://')):
                            urls.add(url)

            return list(urls)

        except Exception as e:
            logger.error(f"[WAYBACK] Error fetching year {year}: {e}")
            return []

    def get_snapshots_info(self, url: str) -> List[Dict]:
        """
        Get snapshot information for a specific URL

        Args:
            url: Target URL

        Returns:
            List of snapshot metadata
        """
        try:
            params = {
                'url': url,
                'output': 'json',
                'fl': 'timestamp,original,statuscode,digest,length'
            }

            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                snapshots = []

                for row in data:
                    if isinstance(row, list) and len(row) >= 5:
                        snapshots.append({
                            'timestamp': row[0],
                            'url': row[1],
                            'status_code': row[2],
                            'digest': row[3],
                            'length': row[4]
                        })

                return snapshots

            return []

        except Exception as e:
            logger.error(f"[WAYBACK] Error getting snapshots for {url}: {e}")
            return []
