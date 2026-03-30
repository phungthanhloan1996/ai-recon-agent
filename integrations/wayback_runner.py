"""
integrations/wayback_runner.py - Wayback Machine Integration
Fetches URLs from Internet Archive Wayback Machine
"""

import requests
import logging
import os
import sys
from typing import List, Dict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

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
            return list(urls)

        except requests.exceptions.RequestException as e:
            logger.error(f"[WAYBACK] Request error: {e}")
            return list(urls)
        except Exception as e:
            logger.error(f"[WAYBACK] Error: {e}")
            return list(urls)

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