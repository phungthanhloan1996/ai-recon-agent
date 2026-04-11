import urllib.parse
import json
import logging
import os
import subprocess
import time
import tempfile
import random
from typing import Dict, List, Any, Optional
import atexit

logger = logging.getLogger("recon.load_testing")

class LoadTester:
    """
    Load Testing Module (formerly DDoSAttacker)
    
    This module performs RESILIENCE CHECKS and LOAD TESTING on target endpoints.
    It is OPTIONAL and DISABLED by default - only runs when explicitly requested.
    
    Purpose: Test target's resilience under load, identify rate limiting,
    and discover potential DoS vulnerabilities for defensive purposes.
    
    Usage: Only enable when explicitly requested by user for authorized testing.
    """
    
    # Default: DISABLED - only run when explicitly enabled
    ENABLED_BY_DEFAULT = False
    
    def __init__(self, state, output_dir: str, http_client=None, enabled: bool = None):
        self.state = state
        self.output_dir = output_dir
        self.http_client = http_client
        self.locust_process = None
        self.temp_dir = tempfile.mkdtemp()
        
        # Explicitly check if load testing is enabled
        # Can be set via: 1) parameter, 2) config, 3) default (disabled)
        if enabled is not None:
            self.enabled = enabled
        else:
            self.enabled = self.ENABLED_BY_DEFAULT
        
        atexit.register(self.cleanup)
        
        if not self.enabled:
            logger.info("[LOAD_TEST] Load testing module is DISABLED. "
                       "Set enabled=True to activate.")
    
    def is_enabled(self) -> bool:
        """Check if load testing is enabled"""
        return self.enabled
    
    def enable(self):
        """Enable load testing"""
        self.enabled = True
        logger.warning("[LOAD_TEST] Load testing ENABLED - will run resilience checks")
    
    def disable(self):
        """Disable load testing"""
        self.enabled = False
        logger.info("[LOAD_TEST] Load testing DISABLED")
    
    def cleanup(self):
        if self.locust_process:
            try:
                self.locust_process.terminate()
                time.sleep(2)
                if self.locust_process.poll() is None:
                    self.locust_process.kill()
            except:
                pass
    
    def run_load_test(self, endpoints: List[Dict], users: int = 100, 
                      spawn_rate: int = 10, runtime: int = 30,
                      method: str = "MIX") -> Dict:
        """
        Run load/resilience test using Locust.
        
        This is a RESILIENCE CHECK - tests target's ability to handle load.
        Only runs when explicitly enabled.
        
        Args:
            endpoints: List of target endpoints
            users: Number of concurrent users (default: 100, reduced from 1000)
            spawn_rate: Users spawned per second (default: 10, reduced from 100)
            runtime: Test duration in seconds (default: 30, reduced from 60)
            method: HTTP method mix (GET/POST/HEAD)
        
        Returns:
            Dict with test results
        """
        if not self.enabled:
            logger.info("[LOAD_TEST] Load testing is DISABLED. Skipping.")
            return {"status": "disabled", "reason": "load testing not enabled"}
        
        return self._run_load_test_internal(endpoints, users, spawn_rate, runtime, method)
    
    def _run_load_test_internal(self, endpoints: List[Dict], users: int, 
                                spawn_rate: int, runtime: int,
                                method: str) -> Dict:
        """Internal implementation of load test"""
        if not endpoints:
            logger.warning("[LOAD_TEST] No endpoints provided for testing")
            return {"status": "failed", "reason": "no endpoints"}
        
        # Prepare target URLs
        targets = []
        for ep in endpoints:
            if isinstance(ep, dict):
                url = ep.get("url") or ep.get("endpoint")
            else:
                url = str(ep) if ep else None
            
            # Validate URL format
            if url and isinstance(url, str):
                url = url.strip()
                # Check if it's a valid URL
                if url.startswith(('http://', 'https://', 'ftp://')):
                    if url not in targets:
                        targets.append(url)
                else:
                    logger.debug(f"[DDoS] Skipping invalid URL format: {url}")
        
        if not targets:
            logger.warning(f"[LOAD_TEST] No valid targets found from {len(endpoints)} endpoints")
            return {"status": "failed", "reason": "no valid targets"}
        
        logger.info(f"[LOAD_TEST] Preparing resilience check on {len(targets)} targets (from {len(endpoints)} endpoints)")
        
        # Create Locustfile
        try:
            locustfile = self._create_locustfile(targets, method)
            if not os.path.exists(locustfile):
                logger.error(f"[LOAD_TEST] Failed to create locustfile: {locustfile}")
                return {"status": "failed", "reason": "locustfile creation failed"}
        except Exception as e:
            logger.error(f"[LOAD_TEST] Error creating locustfile: {e}")
            return {"status": "failed", "reason": f"locustfile error: {e}"}
        
        # Run Locust in headless mode
        try:
            # Get base host (first target's domain)
            from urllib.parse import urlparse
            parsed = urllib.parse.urlparse(targets[0])
            host = f"{parsed.scheme}://{parsed.netloc}"
            
            cmd = [
                "python3",
                "-m", "locust",
                "-f", locustfile,
                "--headless",
                "-u", str(users),
                "-r", str(spawn_rate),
                "--run-time", f"{runtime}s",
                "--host", host,
                "--csv", os.path.join(self.output_dir, "ddos_results"),
                "--html", os.path.join(self.output_dir, "ddos_report.html")
            ]
            
            logger.info(f"[LOAD_TEST] 🧪 Starting resilience check: {users} users, {runtime}s, {len(targets)} targets")
            logger.info(f"[LOAD_TEST] Command: {' '.join(cmd[:3])} ...")
            
            # Run locust
            self.locust_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait for completion
            try:
                stdout, stderr = self.locust_process.communicate(timeout=runtime + 30)
                
                # Log output for debugging
                if stdout:
                    logger.debug(f"[LOAD_TEST] Locust stdout:\n{stdout[:500]}")
                if stderr and "error" in stderr.lower():
                    logger.warning(f"[LOAD_TEST] Locust stderr:\n{stderr[:500]}")
                    
            except subprocess.TimeoutExpired:
                logger.error(f"[LOAD_TEST] Test timeout after {runtime + 30}s")
                if self.locust_process:
                    self.locust_process.terminate()
                return {"status": "timeout", "reason": f"timeout after {runtime}s", "users": users, "runtime": runtime}
            
            # Parse results
            results_file = os.path.join(self.output_dir, "ddos_results_stats.csv")
            results = self._parse_results(results_file)
            results["status"] = "completed"
            results["users"] = users
            results["runtime"] = runtime
            results["targets"] = targets
            results["total_targets"] = len(targets)
            
            logger.info(f"[LOAD_TEST] Resilience check completed: {results.get('total_requests', 0)} requests, {results.get('current_rps', 0)} rps")
            
            return results
            
        except FileNotFoundError as e:
            logger.error(f"[LOAD_TEST] Locust command not found: {e}")
            logger.error("[LOAD_TEST] Install with: pip install locust --break-system-packages")
            return {"status": "failed", "reason": "locust not installed"}
        except Exception as e:
            logger.error(f"[LOAD_TEST] Test failed with exception: {type(e).__name__}: {e}", exc_info=True)
            return {"status": "error", "reason": str(e)}
    
    def _create_locustfile(self, targets: List[str], method: str) -> str:
        """Create Locustfile for load/resilience testing"""
        targets_json = json.dumps(targets)
        
        # Build locustfile content (avoiding f-string issues with nested braces)
        locust_content = f'''import json
import random
import time
from locust import HttpUser, task, between, events

TARGETS = {targets_json}

class DDoSUser(HttpUser):
    wait_time = between(0.01, 0.05)
    
    def on_start(self):
        self.targets = TARGETS
        self.attack_count = 0
    
    @task(10)
    def flood_endpoint(self):
        target = random.choice(self.targets)
        
        if '?' in target:
            target += f'&_r=' + str(random.randint(1, 999999))
        else:
            target += f'?_r=' + str(random.randint(1, 999999))
        
        headers = dict()
        headers['User-Agent'] = random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36'
        ])
        headers['Accept'] = '*/*'
        headers['Accept-Language'] = 'en-US,en;q=0.9'
        headers['Accept-Encoding'] = 'gzip, deflate, br'
        headers['Connection'] = 'keep-alive'
        headers['Cache-Control'] = 'no-cache'
        headers['Pragma'] = 'no-cache'
        headers['X-Forwarded-For'] = '.'.join([str(random.randint(1,255)) for _ in range(4)])
        
        methods = ['GET', 'POST', 'HEAD']
        method_weights = [7, 3, 1]
        selected_method = random.choices(methods, weights=method_weights)[0]
        
        try:
            if selected_method == 'GET':
                with self.client.get(target, headers=headers, timeout=2, name=target, catch_response=True) as response:
                    self.attack_count += 1
                    if response.status_code < 500:
                        response.success()
                    else:
                        response.failure(f"Status {{response.status_code}}")
            elif selected_method == 'POST':
                payload = {{"data": "x" * random.randint(100, 500)}}
                with self.client.post(target, json=payload, headers=headers, timeout=2, name=target, catch_response=True) as response:
                    self.attack_count += 1
                    if response.status_code < 500:
                        response.success()
                    else:
                        response.failure(f"Status {{response.status_code}}")
            else:  # HEAD
                with self.client.head(target, headers=headers, timeout=2, name=target, catch_response=True) as response:
                    self.attack_count += 1
                    if response.status_code < 500:
                        response.success()
                    else:
                        response.failure(f"Status {{response.status_code}}")
        except Exception as e:
            pass
    
    @task(1)
    def aggressive_burst(self):
        for _ in range(3):
            self.flood_endpoint()
            time.sleep(0.01)

@events.quitting.add_listener
def on_quit(environment, **kwargs):
    stats = environment.runner.stats
    total_requests = sum(stats.num_requests.values())
    print(f"DDoS completed: {{total_requests}} total requests")
'''
        
        locust_file = os.path.join(self.temp_dir, "ddos_locustfile.py")
        try:
            with open(locust_file, "w") as f:
                f.write(locust_content)
            logger.debug(f"[LOAD_TEST] Locustfile created at: {locust_file}")
        except Exception as e:
            logger.error(f"[LOAD_TEST] Failed to write locustfile: {e}")
            raise
        
        return locust_file
    
    def _parse_results(self, stats_file: str) -> Dict:
        """Parse Locust stats CSV"""
        results = {
            "total_requests": 0,
            "current_rps": 0,
            "avg_response_time": 0,
            "failures": 0
        }
        
        if not os.path.exists(stats_file):
            logger.warning(f"[LOAD_TEST] Stats file not found: {stats_file}")
            return results
        
        try:
            import csv
            with open(stats_file, 'r') as f:
                reader = csv.DictReader(f)
                row_count = 0
                for row in reader:
                    row_count += 1
                    if row and row.get('Name') == 'Aggregated':
                        try:
                            results['total_requests'] = int(row.get('Request Count', 0))
                            results['current_rps'] = float(row.get('Requests/s', 0))
                            results['avg_response_time'] = float(row.get('Average Response Time', 0))
                            results['failures'] = int(row.get('Failure Count', 0))
                            logger.debug(f"[LOAD_TEST] Parsed aggregated stats: {results['total_requests']} requests, {results['current_rps']} rps")
                        except ValueError as ve:
                            logger.warning(f"[DDoS] Error converting stat values: {ve}")
                        break
                
                if row_count == 0:
                    logger.warning(f"[LOAD_TEST] Stats file is empty: {stats_file}")
                    
        except Exception as e:
            logger.warning(f"[LOAD_TEST] Error parsing stats file: {type(e).__name__}: {e}")
        
        return results
