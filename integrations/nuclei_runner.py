"""
integrations/nuclei_runner.py - Nuclei Scanner Integration
"""

import subprocess
import logging
import time
from typing import List, Dict, Any
import config

logger = logging.getLogger("recon.nuclei")

class NucleiRunner:
    """Run nuclei for general vulnerability scanning with improved concurrency"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.max_retries = max(1, config.NUCLEI_MAX_RETRIES)

    def run(self, url: str) -> Dict[str, Any]:
        """Run nuclei on URL with retry mechanism and optimized concurrency"""
        for attempt in range(self.max_retries):
            try:
                # Optimized nuclei command:
                # -c: limit concurrent requests to avoid overwhelming target/rate limits
                # -timeout: individual template timeout
                # -retries: retry failed requests
                cmd = [
                    "nuclei",
                    "-u", url,
                    "-o", f"{self.output_dir}/nuclei_{url.replace('/', '_').replace(':', '')}.json",
                    "-json",
                    "-c", str(config.NUCLEI_CONCURRENCY),
                    "-timeout", str(config.NUCLEI_TEMPLATE_TIMEOUT),
                    "-retries", "1",  # Retry once on failure
                    "-rl", str(config.NUCLEI_RATE_LIMIT),
                    "-exclude-severity", "info,unknown",  # Skip low-value findings
                    "-stats",  # Show progress stats
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=config.NUCLEI_RUN_TIMEOUT
                )
                
                if result.returncode == 0:
                    logger.debug(f"[NUCLEI] Scan completed successfully for {url}")
                    return {"success": True, "output": result.stdout, "url": url}
                elif result.returncode == 124:  # Timeout signal
                    if attempt < self.max_retries - 1 and config.CRAWLER_RETRY_ON_TIMEOUT:
                        logger.warning(f"[NUCLEI] Timeout on attempt {attempt + 1}, retrying...")
                        time.sleep(1 + attempt)
                        continue
                    else:
                        logger.warning(f"[NUCLEI] Timeout after {self.max_retries} attempts")
                        return {"success": False, "error": "Nuclei timeout after retries"}
                else:
                    logger.debug(f"[NUCLEI] Nuclei returned code {result.returncode} for {url}")
                    return {"success": False, "error": result.stderr}
                    
            except subprocess.TimeoutExpired:
                if attempt < self.max_retries - 1 and config.CRAWLER_RETRY_ON_TIMEOUT:
                    logger.warning(f"[NUCLEI] Process timeout on attempt {attempt + 1}, retrying...")
                    time.sleep(1 + attempt)
                    continue
                else:
                    logger.error(f"[NUCLEI] Process exceeded {config.NUCLEI_RUN_TIMEOUT}s timeout after {self.max_retries} attempts")
                    return {"success": False, "error": "Nuclei process timeout"}
            except Exception as e:
                logger.error(f"[NUCLEI] Scan failed on attempt {attempt + 1}: {e}")
                if attempt == self.max_retries - 1:
                    return {"success": False, "error": str(e)}
        
        return {"success": False, "error": "Nuclei scan exhausted all retries"}
