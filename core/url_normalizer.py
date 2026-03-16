"""
core/url_normalizer.py - URL Normalization Engine
Prevent redundant scanning by normalizing URLs
"""

import re
import logging
from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger("recon.url_normalizer")


class URLNormalizer:
    """
    Normalizes URLs to prevent redundant scanning.
    - Sorts parameters
    - Removes duplicates
    - Replaces numeric parameters with wildcards
    """

    def __init__(self):
        self.numeric_pattern = re.compile(r'\b\d+\b')
        self.seen_urls = set()

    def normalize_urls(self, urls: List[str]) -> List[str]:
        """Normalize a list of URLs"""
        normalized = []
        for url in urls:
            norm_url = self.normalize_url(url)
            if norm_url and norm_url not in self.seen_urls:
                normalized.append(norm_url)
                self.seen_urls.add(norm_url)
        return normalized

    def normalize_url(self, url: str) -> str:
        """Normalize a single URL"""
        try:
            parsed = urlparse(url)
            
            # Sort query parameters
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                # Sort parameters alphabetically
                sorted_params = sorted(params.items())
                # Replace numeric values with wildcard
                wildcard_params = []
                for key, values in sorted_params:
                    wildcard_values = []
                    for value in values:
                        if self._is_numeric_param(value):
                            wildcard_values.append('*')
                        else:
                            wildcard_values.append(value)
                    wildcard_params.append((key, wildcard_values))
                query = urlencode(wildcard_params, doseq=True)
            else:
                query = parsed.query

            # Reconstruct URL
            normalized = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query,
                parsed.fragment
            ))

            return normalized

        except Exception as e:
            logger.warning(f"Failed to normalize URL {url}: {e}")
            return url

    def _is_numeric_param(self, value: str) -> bool:
        """Check if a parameter value is purely numeric"""
        return bool(re.match(r'^\d+$', value.strip()))

    def deduplicate_urls(self, urls: List[str]) -> List[str]:
        """Remove duplicate URLs"""
        return list(set(urls))