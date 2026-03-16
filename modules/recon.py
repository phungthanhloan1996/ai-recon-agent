"""
modules/recon.py - Recon Engine
External integrations for comprehensive surface discovery
"""

import json
import os
import logging
from typing import List, Set

from core.state_manager import StateManager
from integrations.subfinder_runner import SubfinderRunner
from integrations.gau_runner import GAURunner
from integrations.wayback_runner import WaybackRunner

logger = logging.getLogger("recon.engine")


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
        self.target = state.get("target")

        # Initialize integrations
        self.subfinder = SubfinderRunner(output_dir)
        self.gau = GAURunner(output_dir)
        self.wayback = WaybackRunner()

    def run(self):
        """Execute full reconnaissance pipeline"""
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

        # Use existing live_hosts module for validation
        from modules.live_hosts import LiveHostsModule
        live_module = LiveHostsModule(self.state, self.output_dir)
        # This would need to be adapted to work with URL list instead of state

        # For now, return basic validation
        for url in urls[:100]:  # Limit for performance
            try:
                # Simple validation - could be enhanced
                live_hosts.append({
                    "url": url,
                    "status": "unknown",  # Would need actual checking
                    "response_time": 0
                })
            except:
                continue

        logger.info(f"[RECON] Validated {len(live_hosts)} potential live hosts")
        return live_hosts
    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.subdomains_file = os.path.join(output_dir, "subdomains.txt")

    def run(self) -> List[str]:
        logger.info(f"\n{'='*60}")
        logger.info(f"  PHASE 1: SUBDOMAIN ENUMERATION → {self.target}")
        logger.info(f"{'='*60}")

        self.state.set_phase("recon")
        tool_status = check_tools(RECON_TOOLS)
        all_subdomains: Set[str] = set()

        # crt.sh (cert transparency) - luôn chạy, không cần binary
        try:
            crt_subs = self._run_crtsh()
            all_subdomains.update(crt_subs)
            logger.info(f"[RECON] crt.sh: {len(crt_subs)} subdomains")
        except Exception as e:
            logger.warning(f"[RECON] crt.sh failed: {e}")

        # Chạy song song các tool có sẵn
        tasks = []
        if tool_status.get("subfinder"):
            tasks.append(("subfinder", self._run_subfinder))
        if tool_status.get("assetfinder"):
            tasks.append(("assetfinder", self._run_assetfinder))
        if tool_status.get("amass"):
            tasks.append(("amass", self._run_amass))

        if tasks:
            with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
                future_to_name = {executor.submit(fn): name for name, fn in tasks}
                for future in as_completed(future_to_name):
                    name = future_to_name[future]
                    try:
                        subs = future.result()
                        all_subdomains.update(subs)
                        logger.info(f"[RECON] {name}: {len(subs)} subdomains")
                    except Exception as e:
                        logger.warning(f"[RECON] {name} failed: {e}")
        else:
            logger.warning("[RECON] No recon tools available")

        # Always include the base domain
        all_subdomains.add(self.target)

        # Clean and filter
        cleaned = self._clean_subdomains(all_subdomains)

        # Save to file
        self._save(cleaned)

        # Update state
        self.state.update(subdomains=list(cleaned))

        logger.info(f"[RECON] Total unique subdomains: {len(cleaned)}")
        return list(cleaned)

    def _run_crtsh(self) -> Set[str]:
        """Certificate Transparency via crt.sh - không cần cài thêm tool"""
        url = f"https://crt.sh/?q=%.{self.target}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "AI-Recon-Agent/1.0"})
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
            data = json.loads(resp.read().decode())
        subs = set()
        for item in data:
            name = (item.get("name_value") or "").strip().lower()
            for part in name.split():
                if part and ("*" not in part):
                    subs.add(part)
            cn = (item.get("common_name") or "").strip().lower()
            if cn and "*" not in cn:
                subs.add(cn)
        return self._clean_subdomains(subs)

    def _run_subfinder(self) -> Set[str]:
        cmd = ["subfinder", "-d", self.target, "-silent", "-all"]
        _, stdout, _ = run_command(cmd, timeout=180)
        return self._parse_lines(stdout)

    def _run_assetfinder(self) -> Set[str]:
        cmd = ["assetfinder", "--subs-only", self.target]
        _, stdout, _ = run_command(cmd, timeout=120)
        return self._parse_lines(stdout)

    def _run_amass(self) -> Set[str]:
        out_file = os.path.join(self.output_dir, "amass_out.txt")
        cmd = [
            "amass", "enum",
            "-passive",
            "-d", self.target,
            "-o", out_file,
            "-timeout", "5"
        ]
        run_command(cmd, timeout=360)

        subdomains = set()
        if os.path.exists(out_file):
            with open(out_file) as f:
                for line in f:
                    sub = line.strip()
                    if sub:
                        subdomains.add(sub)
        return subdomains

    def _parse_lines(self, output: str) -> Set[str]:
        return {
            line.strip().lower()
            for line in output.splitlines()
            if line.strip()
        }

    def _clean_subdomains(self, subdomains: Set[str]) -> Set[str]:
        """Filter valid subdomains for target"""
        cleaned = set()
        for sub in subdomains:
            sub = sub.strip().lower()
            # Must end with target domain
            if sub.endswith(f".{self.target}") or sub == self.target:
                # Remove wildcards
                if "*" not in sub:
                    cleaned.add(sub)
        return cleaned

    def _save(self, subdomains: Set[str]):
        sorted_subs = sorted(subdomains)
        with open(self.subdomains_file, "w") as f:
            f.write("\n".join(sorted_subs) + "\n")
        logger.info(f"[RECON] Saved {len(sorted_subs)} subdomains → {self.subdomains_file}")