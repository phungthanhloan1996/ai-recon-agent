"""
integrations/dalfox_runner.py - Dalfox XSS Scanner Integration
"""

import subprocess
import logging
import os
import re
from typing import List, Dict, Any

logger = logging.getLogger("recon.dalfox")

class DalfoxRunner:
    """Run dalfox for XSS detection"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.seen_urls = set()  # For deduplication

    def run(self, url: str) -> Dict[str, Any]:
        """Run dalfox on URL"""
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
        safe_name = re.sub(r'[^\w\-]', '_', url)[:100]
        output_path = os.path.join(self.output_dir, f"dalfox_{safe_name}.json")
        
        try:
            # BUG 8 FIX: Reduce timeout from 120s to 60s
            cmd = ["dalfox", "url", url, "--output", output_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                return {"success": True, "output": result.stdout, "url": url}
            else:
                return {"success": False, "error": result.stderr}
        except subprocess.TimeoutExpired:
            logger.warning(f"[DALFOX] Timeout after 60s on {url}")
            return {"success": False, "error": "timeout"}
        except Exception as e:
            logger.error(f"[DALFOX] Failed: {e}")
            return {"success": False, "error": str(e)}