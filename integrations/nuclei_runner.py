"""
integrations/nuclei_runner.py - Nuclei Scanner Integration
"""

import subprocess
import logging
from typing import List, Dict, Any

logger = logging.getLogger("recon.nuclei")

class NucleiRunner:
    """Run nuclei for general vulnerability scanning"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def run(self, url: str) -> Dict[str, Any]:
        """Run nuclei on URL"""
        try:
            cmd = ["nuclei", "-u", url, "-o", f"{self.output_dir}/nuclei_{url.replace('/', '_')}.json", "-json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                return {"success": True, "output": result.stdout, "url": url}
            else:
                return {"success": False, "error": result.stderr}
        except Exception as e:
            logger.error(f"Nuclei failed: {e}")
            return {"success": False, "error": str(e)}