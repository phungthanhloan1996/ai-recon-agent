"""
modules/recon.py - Phase 1: Subdomain Enumeration
Tools: subfinder, assetfinder, amass
"""

import os
import logging
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

        # --- subfinder ---
        if tool_status.get("subfinder"):
            subs = self._run_subfinder()
            all_subdomains.update(subs)
            logger.info(f"[RECON] subfinder: {len(subs)} subdomains")
        else:
            logger.warning("[RECON] subfinder not found - skipping")

        # --- assetfinder ---
        if tool_status.get("assetfinder"):
            subs = self._run_assetfinder()
            all_subdomains.update(subs)
            logger.info(f"[RECON] assetfinder: {len(subs)} subdomains")
        else:
            logger.warning("[RECON] assetfinder not found - skipping")

        # --- amass ---
        if tool_status.get("amass"):
            subs = self._run_amass()
            all_subdomains.update(subs)
            logger.info(f"[RECON] amass: {len(subs)} subdomains")
        else:
            logger.warning("[RECON] amass not found - skipping")

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