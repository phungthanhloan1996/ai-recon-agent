"""
modules/scanner.py - Phase 5: Vulnerability Scanning
Tools: nuclei, nikto
Detect: XSS, SQLi, misconfigurations, exposed files
"""

import json
import os
import logging
from typing import Dict, List

from core.executor import run_command, check_tools
from core.state_manager import StateManager

logger = logging.getLogger("recon.phase5")

SCAN_TOOLS = ["nuclei", "nikto"]

NUCLEI_TAGS = [
    "cve", "sqli", "xss", "lfi", "rce", "ssrf",
    "exposure", "misconfig", "default-login",
    "wp-plugin", "file-upload", "auth-bypass",
]


class ScannerModule:
    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.vulns_file = os.path.join(output_dir, "vulnerabilities.json")

    def run(self) -> List[Dict]:
        logger.info(f"\n{'='*60}")
        logger.info(f"  PHASE 5: VULNERABILITY SCANNING")
        logger.info(f"{'='*60}")

        self.state.set_phase("scanning")
        tool_status = check_tools(SCAN_TOOLS)
        live_hosts = self.state.get("live_hosts", [])
        all_vulns: List[Dict] = []

        if not live_hosts:
            live_hosts = [{"url": f"https://{self.target}"}]

        # Run nuclei
        if tool_status.get("nuclei"):
            nuclei_vulns = self._run_nuclei(live_hosts)
            all_vulns.extend(nuclei_vulns)
            logger.info(f"[SCAN] nuclei found {len(nuclei_vulns)} issues")
        else:
            logger.warning("[SCAN] nuclei not found - skipping")

        # Run nikto
        if tool_status.get("nikto"):
            for host in live_hosts[:5]:  # Nikto is slow, limit
                nikto_vulns = self._run_nikto(host["url"])
                all_vulns.extend(nikto_vulns)
            logger.info(f"[SCAN] nikto added {len(all_vulns)} total issues")
        else:
            logger.warning("[SCAN] nikto not found - skipping")

        # Save results
        self._save_vulns(all_vulns)

        # Update state
        for vuln in all_vulns:
            self.state.add_vulnerability(vuln)

        # Summary
        self._print_summary(all_vulns)
        return all_vulns

    def _run_nuclei(self, live_hosts: List[Dict]) -> List[Dict]:
        """Run nuclei against all live hosts"""
        targets_file = os.path.join(self.output_dir, "nuclei_targets.txt")
        output_file = os.path.join(self.output_dir, "nuclei_out.json")

        # Write targets
        with open(targets_file, "w") as f:
            for host in live_hosts:
                f.write(host["url"] + "\n")

        cmd = [
            "nuclei",
            "-l", targets_file,
            "-tags", ",".join(NUCLEI_TAGS),
            "-severity", "info,low,medium,high,critical",
            "-json",
            "-o", output_file,
            "-silent",
            "-c", "20",
            "-timeout", "15",
            "-no-color",
        ]

        _, _, _ = run_command(cmd, timeout=600)

        vulns = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        vuln = {
                            "tool": "nuclei",
                            "template": data.get("template-id", ""),
                            "name": data.get("info", {}).get("name", ""),
                            "severity": data.get("info", {}).get("severity", "info").upper(),
                            "url": data.get("matched-at", ""),
                            "description": data.get("info", {}).get("description", ""),
                            "tags": data.get("info", {}).get("tags", []),
                            "cvss_score": data.get("info", {}).get("classification", {}).get("cvss-score", None),
                            "cve": data.get("info", {}).get("classification", {}).get("cve-id", []),
                            "evidence": data.get("extracted-results", []),
                        }
                        vulns.append(vuln)
                        sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(vuln["severity"], "⚪")
                        logger.warning(
                            f"[NUCLEI] {sev_icon} [{vuln['severity']}] "
                            f"{vuln['name']} @ {vuln['url']}"
                        )
                    except json.JSONDecodeError:
                        pass

        return vulns

    def _run_nikto(self, url: str) -> List[Dict]:
        """Run nikto against a single URL"""
        output_file = os.path.join(self.output_dir, "nikto_out.txt")

        cmd = [
            "nikto",
            "-h", url,
            "-output", output_file,
            "-Format", "txt",
            "-Tuning", "1234567890abc",
            "-nointeractive",
        ]

        _, stdout, _ = run_command(cmd, timeout=300)

        vulns = []
        # Parse nikto text output
        for line in stdout.splitlines():
            line = line.strip()
            if line.startswith("+ ") and ("OSVDB" in line or "vulnerability" in line.lower() or
                    "exposed" in line.lower() or "found" in line.lower()):
                vuln = {
                    "tool": "nikto",
                    "name": line[:100],
                    "severity": "MEDIUM",
                    "url": url,
                    "description": line,
                    "template": "nikto",
                    "tags": ["nikto"],
                }
                vulns.append(vuln)
                logger.warning(f"[NIKTO] {line[:80]}")

        return vulns

    def _save_vulns(self, vulns: List[Dict]):
        with open(self.vulns_file, "w") as f:
            json.dump(vulns, f, indent=2, default=str)
        logger.info(f"[SCAN] Saved {len(vulns)} vulnerabilities → {self.vulns_file}")

    def _print_summary(self, vulns: List[Dict]):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            sev = v.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        print(f"\n{'='*50}")
        print("  VULNERABILITY SCAN SUMMARY")
        print(f"{'='*50}")
        for sev, count in counts.items():
            if count > 0:
                print(f"  {sev:10s} : {count}")
        print(f"  TOTAL      : {len(vulns)}")
        print(f"{'='*50}\n")