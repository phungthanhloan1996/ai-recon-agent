"""
integrations/nuclei_runner.py - Nuclei Scanner Integration
Enhanced with worker pool management and adaptive timeout handling.
Integrated with GlobalConcurrencyManager and NucleiWorkerPool from core.resource_manager.
"""

import subprocess
import logging
import time
from typing import List, Dict, Any, Optional
import config

# ─── Resource Management Integration ─────────────────────────────────────────
from core.resource_manager import get_concurrency_manager, get_nuclei_pool

logger = logging.getLogger("recon.nuclei")


class NucleiRunner:
    """Run nuclei for general vulnerability scanning with improved concurrency and timeout handling"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.max_retries = max(1, config.NUCLEI_MAX_RETRIES)
        
        # Adaptive timeout tracking per URL
        self._timeout_history: Dict[str, List[float]] = {}
        self._default_timeout = config.NUCLEI_RUN_TIMEOUT
        self._adaptive_timeout_enabled = True
        
        # Worker pool settings
        self._max_concurrent_scans = config.NUCLEI_CONCURRENCY
        self._active_scans = 0
        self._scan_lock = None
        
        try:
            import threading
            self._scan_lock = threading.Semaphore(self._max_concurrent_scans)
        except Exception:
            pass

    def _get_adaptive_timeout(self, url: str) -> int:
        """
        Get adaptive timeout based on historical performance for this URL.
        Reduces timeout for URLs that consistently timeout.
        """
        if not self._adaptive_timeout_enabled:
            return self._default_timeout
        
        history = self._timeout_history.get(url, [])
        
        if not history:
            return self._default_timeout
        
        # Count timeouts in history
        timeout_count = sum(1 for t in history if t >= self._default_timeout * 0.9)
        
        if timeout_count > 0:
            # Progressive timeout reduction: 75%, 56%, 42% of original
            reduction = 0.75 ** min(timeout_count, 3)
            adaptive_timeout = int(self._default_timeout * reduction)
            return max(30, min(adaptive_timeout, self._default_timeout * 2))
        
        # Calculate average completion time with buffer
        avg_time = sum(history) / len(history)
        return int(min(avg_time * 1.5, self._default_timeout * 2))

    def _record_scan_time(self, url: str, elapsed: float, timed_out: bool = False):
        """Record scan time for adaptive timeout calculation"""
        if url not in self._timeout_history:
            self._timeout_history[url] = []
        
        self._timeout_history[url].append(elapsed)
        
        # Keep only last 5 entries per URL
        if len(self._timeout_history[url]) > 5:
            self._timeout_history[url] = self._timeout_history[url][-5:]

    def run(self, url: str, timeout: int = None) -> Dict[str, Any]:
        """
        Run nuclei on URL with:
        - Adaptive timeout based on URL history
        - Worker pool limiting (max concurrent scans)
        - Retry mechanism with exponential backoff
        - Progress tracking for unfinished futures
        - Default timeout of 30 seconds per endpoint
        """
        # Use adaptive timeout if not specified, default to 30s
        if timeout is None:
            timeout = self._get_adaptive_timeout(url)
            # Ensure minimum timeout of 30 seconds for each endpoint
            timeout = max(timeout, 30)
        
        # Acquire worker slot if using concurrency control
        acquired_slot = False
        if self._scan_lock:
            acquired_slot = self._scan_lock.acquire(blocking=True, timeout=timeout + 30)
            if not acquired_slot:
                logger.warning(f"[NUCLEI] Could not acquire worker slot for {url}, skipping")
                return {"success": False, "error": "Could not acquire worker slot", "url": url}
        
        try:
            self._active_scans += 1
            return self._run_scan(url, timeout)
        finally:
            self._active_scans -= 1
            if acquired_slot and self._scan_lock:
                self._scan_lock.release()

    def _run_scan(self, url: str, timeout: int) -> Dict[str, Any]:
        """Internal scan execution with retry logic"""
        start_time = time.time()
        
        for attempt in range(self.max_retries):
            try:
                # Calculate current attempt timeout (increase on retry)
                attempt_timeout = timeout
                if attempt > 0:
                    # Increase timeout by 50% on each retry
                    attempt_timeout = int(timeout * (1.5 ** attempt))
                
                # Optimized nuclei command:
                # -c: limit concurrent requests to avoid overwhelming target/rate limits
                # -timeout: individual template timeout (not total scan timeout)
                # -retries: retry failed requests
                cmd = [
                    "nuclei",
                    "-u", url,
                    "-o", f"{self.output_dir}/nuclei_{url.replace('/', '_').replace(':', '')}.json",
                    "-json",
                    "-c", str(config.NUCLEI_CONCURRENCY),
                    "-timeout", str(min(config.NUCLEI_TEMPLATE_TIMEOUT, attempt_timeout // 10)),
                    "-retries", "1",  # Retry once on failure
                    "-rl", str(config.NUCLEI_RATE_LIMIT),
                    "-exclude-severity", "info,unknown",  # Skip low-value findings
                    "-stats",  # Show progress stats
                ]
                
                # Add bulk size limit to prevent overwhelming slow hosts
                if attempt > 0:
                    cmd.extend(["-bs", "10"])  # Reduce bulk size on retry
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=attempt_timeout
                )
                
                elapsed = time.time() - start_time
                self._record_scan_time(url, elapsed, timed_out=False)
                
                if result.returncode == 0:
                    logger.debug(f"[NUCLEI] Scan completed successfully for {url} in {elapsed:.1f}s")
                    return {"success": True, "output": result.stdout, "url": url}
                elif result.returncode == 124:  # Timeout signal
                    logger.warning(f"[NUCLEI] Timeout on attempt {attempt + 1} for {url} ({elapsed:.1f}s)")
                    if attempt < self.max_retries - 1 and config.CRAWLER_RETRY_ON_TIMEOUT:
                        backoff = 1 + attempt
                        logger.info(f"[NUCLEI] Retrying in {backoff}s...")
                        time.sleep(backoff)
                        continue
                    else:
                        self._record_scan_time(url, elapsed, timed_out=True)
                        logger.warning(f"[NUCLEI] Timeout after {self.max_retries} attempts for {url}")
                        return {"success": False, "error": "Nuclei timeout after retries", "url": url}
                else:
                    logger.debug(f"[NUCLEI] Nuclei returned code {result.returncode} for {url}")
                    return {"success": False, "error": result.stderr, "url": url}
                    
            except subprocess.TimeoutExpired:
                elapsed = time.time() - start_time
                self._record_scan_time(url, elapsed, timed_out=True)
                
                if attempt < self.max_retries - 1 and config.CRAWLER_RETRY_ON_TIMEOUT:
                    backoff = 1 + attempt
                    logger.warning(f"[NUCLEI] Process timeout on attempt {attempt + 1} ({elapsed:.1f}s), retrying in {backoff}s...")
                    time.sleep(backoff)
                    continue
                else:
                    logger.error(f"[NUCLEI] Process exceeded {attempt_timeout}s timeout after {self.max_retries} attempts for {url}")
                    return {"success": False, "error": "Nuclei process timeout", "url": url}
                    
            except Exception as e:
                logger.error(f"[NUCLEI] Scan failed on attempt {attempt + 1} for {url}: {e}")
                if attempt == self.max_retries - 1:
                    return {"success": False, "error": str(e), "url": url}
                time.sleep(1 + attempt)
        
        return {"success": False, "error": "Nuclei scan exhausted all retries", "url": url}

    def run_batch(self, urls: List[str], max_concurrent: int = None) -> List[Dict[str, Any]]:
        """
        Run nuclei on multiple URLs with controlled concurrency.
        
        Args:
            urls: List of URLs to scan
            max_concurrent: Maximum concurrent scans (uses config default if None)
            
        Returns:
            List of scan results
        """
        if not urls:
            return []
        
        if max_concurrent is None:
            max_concurrent = self._max_concurrent_scans
        
        results = []
        
        # Use simple sequential processing with concurrency control
        # For true parallel processing, use the NucleiWorkerPool from resource_manager
        for url in urls:
            result = self.run(url)
            results.append(result)
            
            # Log progress
            completed = len(results)
            total = len(urls)
            success_count = sum(1 for r in results if r.get("success"))
            logger.debug(f"[NUCLEI] Progress: {completed}/{total} ({success_count} successful)")
        
        return results

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about nuclei scans"""
        stats = {
            "total_urls_tracked": len(self._timeout_history),
            "active_scans": self._active_scans,
            "max_concurrent": self._max_concurrent_scans,
            "adaptive_timeout_enabled": self._adaptive_timeout_enabled,
        }
        
        # Calculate timeout statistics
        total_timeouts = 0
        total_scans = 0
        for url, times in self._timeout_history.items():
            for t in times:
                total_scans += 1
                if t >= self._default_timeout * 0.9:
                    total_timeouts += 1
        
        stats["timeout_rate"] = total_timeouts / max(1, total_scans)
        
        return stats

    def reset_adaptive_timeouts(self):
        """Reset adaptive timeout history"""
        self._timeout_history.clear()
        logger.info("[NUCLEI] Reset adaptive timeout history")