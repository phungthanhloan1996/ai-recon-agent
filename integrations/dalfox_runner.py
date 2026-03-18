"""
integrations/dalfox_runner.py - Dalfox XSS Scanner Integration
"""

import subprocess
import logging
from typing import List, Dict, Any

logger = logging.getLogger("recon.dalfox")

class DalfoxRunner:
    """Run dalfox for XSS detection"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def run(self, url: str) -> Dict[str, Any]:
        """Run dalfox on URL"""
        try:
            cmd = ["dalfox", "url", url, "--output", f"{self.output_dir}/dalfox_{url.replace('/', '_')}.json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                return {"success": True, "output": result.stdout, "url": url}
            else:
                return {"success": False, "error": result.stderr}
        except Exception as e:
            logger.error(f"Dalfox failed: {e}")
            return {"success": False, "error": str(e)}