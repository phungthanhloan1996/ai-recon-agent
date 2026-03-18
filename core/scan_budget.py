"""
core/scan_budget.py - Adaptive scan budget engine.
Keeps full-scan intent while preventing hard bottlenecks.
"""

from dataclasses import dataclass, asdict


@dataclass
class ScanBudget:
    # Recon/live
    recon_validate_urls: int = 120
    recon_gau_timeout: int = 120
    recon_dns_verify_limit: int = 500
    recon_validate_workers: int = 16
    recon_cache_ttl_hours: int = 24
    live_primary_targets: int = 220
    live_secondary_targets: int = 90
    live_ports_secondary: int = 4
    live_timeout: int = 6

    # Discovery/crawl
    crawl_seed_urls: int = 260
    crawl_browser_urls: int = 40
    crawl_browser_links_per_url: int = 120
    crawl_timeout: int = 10
    crawl_workers_http: int = 20
    crawl_workers_browser: int = 4

    # Scan/toolkit
    scan_prioritized_endpoints: int = 140
    toolkit_hosts: int = 8
    toolkit_parallel_tools: int = 3

    @staticmethod
    def build(target: str, aggressive: bool = False) -> "ScanBudget":
        """
        Build a budget profile.
        Aggressive mode increases limits, still bounded to avoid runaway scans.
        """
        if aggressive:
            return ScanBudget(
                recon_validate_urls=220,
                recon_gau_timeout=150,
                recon_dns_verify_limit=1000,
                recon_validate_workers=24,
                recon_cache_ttl_hours=36,
                live_primary_targets=350,
                live_secondary_targets=140,
                live_ports_secondary=6,
                live_timeout=7,
                crawl_seed_urls=450,
                crawl_browser_urls=70,
                crawl_browser_links_per_url=180,
                crawl_timeout=12,
                crawl_workers_http=30,
                crawl_workers_browser=6,
                scan_prioritized_endpoints=220,
                toolkit_hosts=14,
                toolkit_parallel_tools=5,
            )
        return ScanBudget()

    def to_dict(self):
        return asdict(self)
