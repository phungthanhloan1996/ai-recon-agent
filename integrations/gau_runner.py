"""
integrations/gau_runner.py - GetAllURLs (GAU) Integration
Fetches archived URLs from various sources
"""

import subprocess
import logging
from typing import List
import os

logger = logging.getLogger("recon.gau_runner")


class GAURunner:
    """
    Integration with GetAllURLs tool for fetching archived URLs.
    GAU aggregates URLs from multiple sources: Common Crawl, AlienVault, etc.
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.gau_path = self._find_gau_binary()

    def _find_gau_binary(self) -> str:
        """Find GAU binary in system PATH"""
        common_paths = [
            "/usr/local/bin/gau",
            "/usr/bin/gau",
            "/opt/gau/gau",
            "gau",  # Assume in PATH
            os.path.expanduser("~/go/bin/gau"),  # Go install path
            "/usr/local/go/bin/gau",
        ]

        for path in common_paths:
            if os.path.exists(path) or self._is_in_path(path):
                return path

        logger.warning("GAU binary not found, URLs from archives will be skipped")
        return None

    def _is_in_path(self, command: str) -> bool:
        """Check if command is available in PATH"""
        try:
            subprocess.run([command, "--help"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def fetch_urls(self, domain: str, max_urls: int = 10000) -> List[str]:
        """
        Fetch archived URLs for a domain using GAU

        Args:
            domain: Target domain
            max_urls: Maximum number of URLs to fetch

        Returns:
            List of discovered URLs
        """
        if not self.gau_path:
            logger.warning("GAU not available, skipping archived URL discovery")
            return []

        urls = set()
        output_file = os.path.join(self.output_dir, f"gau_{domain.replace('.', '_')}.txt")

        try:
            # Run GAU command
            cmd = [
                self.gau_path,
                "--threads", "10",
                "--verbose",
                "--subs",  # Include subdomains
                domain
            ]

            logger.info(f"[GAU] Fetching archived URLs for {domain}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                # Parse output
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    line = line.strip()
                    if line and line.startswith(('http://', 'https://')):
                        urls.add(line)

                # Save to file
                with open(output_file, 'w') as f:
                    f.write('\n'.join(sorted(urls)))

                logger.info(f"[GAU] Discovered {len(urls)} archived URLs for {domain}")
                return list(urls)[:max_urls]  # Limit results

            else:
                logger.error(f"[GAU] Failed: {result.stderr}")
                return []

        except subprocess.TimeoutExpired:
            logger.warning("[GAU] Timeout expired")
            return []
        except Exception as e:
            logger.error(f"[GAU] Error: {e}")
            return []

    def fetch_with_filters(self, domain: str, include_patterns: List[str] = None,
                          exclude_patterns: List[str] = None) -> List[str]:
        """
        Fetch URLs with filtering

        Args:
            domain: Target domain
            include_patterns: Only include URLs matching these patterns
            exclude_patterns: Exclude URLs matching these patterns

        Returns:
            Filtered list of URLs
        """
        urls = self.fetch_urls(domain)

        if not urls:
            return urls

        filtered = []

        for url in urls:
            # Apply include filters
            if include_patterns:
                if not any(pattern in url for pattern in include_patterns):
                    continue

            # Apply exclude filters
            if exclude_patterns:
                if any(pattern in url for pattern in exclude_patterns):
                    continue

            filtered.append(url)

        logger.info(f"[GAU] Filtered to {len(filtered)} URLs")
        return filtered