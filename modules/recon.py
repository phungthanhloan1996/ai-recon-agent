"""
modules/recon.py - Phase 1: Subdomain Enumeration
Tools: subfinder, assetfinder, amass + crt.sh (API, không cần binary)
"""

import json
import os
import logging
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set

from core.executor import run_command, check_tools
from core.state_manager import StateManager

logger = logging.getLogger("recon.phase1")

RECON_TOOLS = ["subfinder", "assetfinder", "amass"]


class ReconModule:
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