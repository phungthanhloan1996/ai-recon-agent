"""
integrations/dalfox_runner.py - Dalfox XSS Scanner Integration
"""

import subprocess
import logging
import os
import re
import json
from typing import List, Dict, Any

logger = logging.getLogger("recon.dalfox")

class DalfoxRunner:
    """Run dalfox for XSS detection"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.results_dir = os.path.join(output_dir, "dalfox_results") if output_dir else None
        self.seen_urls = set()  # For deduplication

    def _get_output_path(self, url: str) -> str:
        safe_name = re.sub(r'[^\w\-]', '_', url)[:100]
        base_dir = self.results_dir or self.output_dir or "."
        os.makedirs(base_dir, exist_ok=True)
        return os.path.join(base_dir, f"dalfox_{safe_name}.json")

    def _read_output_file(self, output_path: str) -> str:
        if not os.path.exists(output_path):
            return ""
        try:
            with open(output_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            logger.error(f"[DALFOX] Failed to read output file {output_path}: {e}")
            return ""

    def _parse_findings(self, content: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        if not content:
            return findings

        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                return [item for item in parsed if isinstance(item, dict)]
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            if "vulnerab" in line.lower() or "xss" in line.lower() or "payload" in line.lower():
                findings.append({
                    "type": "xss",
                    "evidence": line[:500],
                    "severity": "HIGH",
                })
        return findings

    def run(self, url: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Run dalfox on URL with configurable timeout.
        
        Args:
            url: Target URL to scan
            timeout: Timeout in seconds (default: 30s per endpoint)
        """
        from core.executor import tool_available
        if not tool_available("dalfox"):
            logger.warning("[DALFOX] dalfox not installed, skipping")
            return {"success": False, "error": "dalfox not found in PATH"}
        
        # BUG 8 FIX: Strip fragment from URL
        url = url.split('#')[0]
        
        # BUG 8 FIX: Dedup - skip if already scanned this URL
        if url in self.seen_urls:
            logger.debug(f"[DALFOX] Skipping duplicate URL: {url}")
            return {"success": False, "error": "duplicate"}
        self.seen_urls.add(url)
        
        # BUG 8 FIX: Safe filename - replace unsafe characters
        output_path = self._get_output_path(url)
        
        try:
            # BUG 8 FIX: Use configurable timeout (default 30s)
            cmd = ["dalfox", "url", url, "--output", output_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            file_output = self._read_output_file(output_path)
            findings = self._parse_findings(file_output or result.stdout)
            if result.returncode == 0 or file_output:
                return {
                    "success": True,
                    "output": file_output or result.stdout,
                    "url": url,
                    "artifact_path": output_path,
                    "findings": findings,
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr,
                    "url": url,
                    "artifact_path": output_path,
                    "findings": findings,
                    "output": file_output or result.stdout,
                }
        except subprocess.TimeoutExpired:
            logger.warning(f"[DALFOX] Timeout after {timeout}s on {url}")
            return {
                "success": False,
                "error": "timeout",
                "url": url,
                "artifact_path": output_path,
                "findings": self._parse_findings(self._read_output_file(output_path)),
            }
        except Exception as e:
            logger.error(f"[DALFOX] Failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "url": url,
                "artifact_path": output_path,
                "findings": self._parse_findings(self._read_output_file(output_path)),
            }
