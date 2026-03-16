"""
integrations/wayback_runner.py - Wayback Machine Integration
Fetches URLs from Internet Archive Wayback Machine
"""

import requests
import logging
from typing import List, Dict

logger = logging.getLogger("recon.wayback_runner")


class WaybackRunner:
    """
    Integration with Internet Archive Wayback Machine.
    Fetches historical URLs for comprehensive endpoint discovery.
    """

    def __init__(self):
        self.base_url = "https://web.archive.org/cdx/search/cdx"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; WaybackURLFetcher/1.0)'
        })

    def fetch_urls(self, domain: str, max_urls: int = 5000) -> List[str]:
        """
        Fetch URLs from Wayback Machine

        Args:
            domain: Target domain
            max_urls: Maximum URLs to fetch

        Returns:
            List of discovered URLs
        """
        urls = set()

        try:
            # Wayback CDX API parameters
            params = {
                'url': f"*.{domain}/*",  # Include subdomains
                'output': 'json',
                'fl': 'original',  # Only return original URLs
                'collapse': 'urlkey',  # Collapse duplicates
                'limit': max_urls
            }

            logger.info(f"[WAYBACK] Fetching URLs for {domain}")

            response = self.session.get(self.base_url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()

                # Skip header row if present
                for row in data:
                    if isinstance(row, list) and len(row) > 0:
                        url = row[0]
                        if url.startswith(('http://', 'https://')):
                            urls.add(url)

                logger.info(f"[WAYBACK] Discovered {len(urls)} URLs from Wayback Machine")
                return list(urls)

            else:
                logger.error(f"[WAYBACK] API error: {response.status_code}")
                return []

        except requests.exceptions.RequestException as e:
            logger.error(f"[WAYBACK] Request error: {e}")
            return []
        except Exception as e:
            logger.error(f"[WAYBACK] Error: {e}")
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