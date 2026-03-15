"""
modules/scanner.py - Phase 5: Vulnerability Scanning
Tools: nuclei, nikto (nuclei tags theo target; nikto chạy song song)
"""

import json
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from core.executor import run_command, check_tools
from core.state_manager import StateManager
from core.session_manager import SessionManager

logger = logging.getLogger("recon.phase5")

SCAN_TOOLS = ["nuclei", "nikto"]

NUCLEI_TAGS_BASE = [
    "cve", "sqli", "xss", "lfi", "rce", "ssrf",
    "exposure", "misconfig", "default-login",
    "wp-plugin", "file-upload", "auth-bypass",
]
NIKTO_MAX_PARALLEL = int(os.environ.get("NIKTO_PARALLEL", "4"))
NIKTO_MAX_HOSTS = int(os.environ.get("NIKTO_MAX_HOSTS", "10"))


class ScannerModule:
    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.vulns_file = os.path.join(output_dir, "vulnerabilities.json")
        self.session_mgr = SessionManager(output_dir)
        self.session_mgr.load_session()  # Load if exists

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

        # Run nuclei (tags động theo endpoint: wp, api)
        if tool_status.get("nuclei"):
            nuclei_vulns = self._run_nuclei(live_hosts)
            all_vulns.extend(nuclei_vulns)
            logger.info(f"[SCAN] nuclei found {len(nuclei_vulns)} issues")
        else:
            logger.warning("[SCAN] nuclei not found - skipping")

        # Run nikto song song nhiều host
        if tool_status.get("nikto"):
            nikto_hosts = live_hosts[:NIKTO_MAX_HOSTS]
            with ThreadPoolExecutor(max_workers=min(NIKTO_MAX_PARALLEL, len(nikto_hosts))) as executor:
                futures = {executor.submit(self._run_nikto, h["url"], i): i for i, h in enumerate(nikto_hosts)}
                for future in as_completed(futures):
                    try:
                        nikto_vulns = future.result()
                        all_vulns.extend(nikto_vulns)
                    except Exception as e:
                        logger.warning(f"[SCAN] nikto host failed: {e}")
            logger.info(f"[SCAN] nikto scanned {len(nikto_hosts)} hosts")
        else:
            logger.warning("[SCAN] nikto not found - skipping")

        # Deduplicate results
        all_vulns = self._deduplicate_vulns(all_vulns)

        # Save results
        self._save_vulns(all_vulns)

        # Update state
        for vuln in all_vulns:
            self.state.add_vulnerability(vuln)

        # Summary
        self._print_summary(all_vulns)
        return all_vulns

    def _nuclei_tags(self) -> List[str]:
        """Tags động: thêm wordpress, api nếu endpoint có dấu hiệu"""
        tags = list(NUCLEI_TAGS_BASE)
        endpoints = self.state.get("endpoints", [])
        urls_str = " ".join(e.get("url", "") + " " + " ".join(e.get("categories", [])) for e in endpoints)
        if "wp" in urls_str or "wordpress" in urls_str.lower() or "wp-admin" in urls_str or "wp-json" in urls_str:
            tags.extend(["wordpress"])
        if "/api/" in urls_str or "api" in urls_str or "graphql" in urls_str.lower():
            tags.extend(["api", "swagger"])
        return list(dict.fromkeys(tags))  # unique, giữ thứ tự

    def _run_nuclei(self, live_hosts: List[Dict]) -> List[Dict]:
        """Run nuclei against all live hosts"""
        targets_file = os.path.join(self.output_dir, "nuclei_targets.txt")
        output_file = os.path.join(self.output_dir, "nuclei_out.json")
        tags = self._nuclei_tags()
        logger.info(f"[SCAN] nuclei tags: {tags}")

        # Write targets
        with open(targets_file, "w") as f:
            for host in live_hosts:
                f.write(host["url"] + "\n")

        cmd = [
            "nuclei",
            "-l", targets_file,
            "-tags", ",".join(tags),
            "-severity", "info,low,medium,high,critical",
            "-json",
            "-o", output_file,
            "-silent",
            "-c", "20",
            "-timeout", "15",
            "-no-color",
        ]

        # Add session if available
        session_data = self.session_mgr.get_session_data()
        if session_data["cookies"]:
            cookie_str = "; ".join([f"{k}={v}" for k, v in session_data["cookies"].items()])
            cmd.extend(["-H", f"Cookie: {cookie_str}"])
        if session_data["headers"]:
            for k, v in session_data["headers"].items():
                cmd.extend(["-H", f"{k}: {v}"])

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

    def _run_nikto(self, url: str, index: int = 0) -> List[Dict]:
        """Run nikto against a single URL (index để ghi file riêng khi chạy song song)"""
        safe = str(index).replace("/", "_")
        output_file = os.path.join(self.output_dir, f"nikto_out{safe}.txt")

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

    def _deduplicate_vulns(self, vulns: List[Dict]) -> List[Dict]:
        """Remove duplicate vulnerabilities based on URL + name + severity"""
        seen = set()
        deduped = []
        for vuln in vulns:
            key = (vuln.get("url", ""), vuln.get("name", ""), vuln.get("severity", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(vuln)
        logger.info(f"[SCAN] Deduplicated {len(vulns)} → {len(deduped)} vulnerabilities")
        return deduped

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