"""
integrations/subfinder_runner.py - Subfinder Integration
Discovers subdomains using passive reconnaissance
"""

import subprocess
import logging
from typing import List, Dict
import os
import json

logger = logging.getLogger("recon.subfinder_runner")


class SubfinderRunner:
    """
    Integration with Subfinder for passive subdomain enumeration.
    Uses multiple sources: certificate transparency, DNS dumps, etc.
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.subfinder_path = self._find_subfinder_binary()

    def _find_subfinder_binary(self) -> str:
        """Find Subfinder binary"""
        common_paths = [
            "/usr/local/bin/subfinder",
            "/usr/bin/subfinder",
            "/opt/subfinder/subfinder",
            "subfinder",  # Assume in PATH
            os.path.expanduser("~/go/bin/subfinder"),  # Go install path
            "/usr/local/go/bin/subfinder",
        ]

        for path in common_paths:
            if os.path.exists(path) or self._is_in_path(path):
                return path

        logger.warning("Subfinder binary not found, passive subdomain discovery will be skipped")
        return None

    def _is_in_path(self, command: str) -> bool:
        """Check if command is in PATH"""
        try:
            subprocess.run([command, "-version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def discover_subdomains(self, domain: str) -> List[str]:
        """
        Discover subdomains for a given domain

        Args:
            domain: Target domain

        Returns:
            List of discovered subdomains
        """
        if not self.subfinder_path:
            logger.warning("Subfinder not available, skipping passive subdomain discovery")
            return []

        subdomains = set()
        output_file = os.path.join(self.output_dir, f"subfinder_{domain.replace('.', '_')}.txt")

        try:
            # Run subfinder command
            cmd = [
                self.subfinder_path,
                "-d", domain,
                "-o", output_file,  # Output to file
                "-t", "50",  # Threads
            ]

            logger.info(f"[SUBFINDER] Discovering subdomains for {domain}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
                # Removed timeout to let subfinder run until completion
            )

            if result.returncode == 0 or os.path.exists(output_file):
                # Read results from file even if returncode != 0
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and '.' in line:
                                subdomains.add(line.lower())

                logger.info(f"[SUBFINDER] Discovered {len(subdomains)} subdomains for {domain}")
                return list(subdomains)

            else:
                logger.error(f"[SUBFINDER] Failed with returncode {result.returncode}: {result.stderr}")
                if os.path.exists(output_file):
                    logger.info(f"[SUBFINDER] Output file exists, reading anyway")
                    with open(output_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and '.' in line:
                                subdomains.add(line.lower())
                    return list(subdomains)
                return []
                return []

        except subprocess.TimeoutExpired:
            logger.warning("[SUBFINDER] Timeout expired")
            return []
        except Exception as e:
            logger.error(f"[SUBFINDER] Error: {e}")
            return []

    def discover_with_sources(self, domain: str, sources: List[str] = None) -> Dict[str, List[str]]:
        """
        Discover subdomains with source attribution

        Args:
            domain: Target domain
            sources: List of sources to use (optional)

        Returns:
            Dict mapping sources to discovered subdomains
        """
        if not self.subfinder_path:
            return {}

        try:
            # Run with JSON output for source attribution
            cmd = [
                self.subfinder_path,
                "-d", domain,
                "-json",  # JSON output
                "-silent",
                "-t", "30",
                "-timeout", "20"
            ]

            if sources:
                cmd.extend(["-sources", ",".join(sources)])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode == 0:
                source_results = {}

                # Parse JSON lines
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            source = data.get('source', 'unknown')
                            subdomain = data.get('host', '')

                            if subdomain:
                                if source not in source_results:
                                    source_results[source] = []
                                source_results[source].append(subdomain.lower())

                        except json.JSONDecodeError:
                            continue

                return source_results

            else:
                logger.error(f"[SUBFINDER] JSON mode failed: {result.stderr}")
                # Fallback to regular discovery
                subdomains = self.discover_subdomains(domain)
                return {"all": subdomains}

        except Exception as e:
            logger.error(f"[SUBFINDER] Error in source discovery: {e}")
            return {}