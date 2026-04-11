import urllib.parse
"""
Scan Optimizer - Centralized optimization for scanning operations
Addresses performance issues with dead hosts, port scanning, retries, and caching
"""

import time
import hashlib
import json
import threading
from collections import defaultdict
from typing import Dict, Set, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class HostStatus:
    """Tracks the status and health of a host - OPTIMIZED mode with stricter thresholds"""
    hostname: str
    is_alive: bool = True
    failure_count: int = 0
    consecutive_failures: int = 0  # Track consecutive failures for skip logic
    last_checked: float = 0
    last_failure_time: float = 0
    failure_reasons: List[str] = field(default_factory=list)
    dns_error: bool = False
    connection_timeout: bool = False
    blacklist_threshold: int = 2  # REDUCED: blacklist after 2 failures (was 3)
    dns_blacklist_threshold: int = 2  # REDUCED: DNS errors need 2 failures (was 3)
    is_blacklisted: bool = False
    should_skip: bool = False  # NEW: skip target entirely
    skip_reason: str = ""
    priority: int = 1  # 1=high, 2=medium, 3=low
    total_requests: int = 0
    total_failures: int = 0
    timeout_count: int = 0  # Track timeout-specific failures for adaptive timeout
    adaptive_timeout_enabled: bool = False  # Enable adaptive timeout after multiple timeouts
    _logged_blacklist: bool = False  # Track if blacklist log was emitted
    
    def should_blacklist(self) -> bool:
        """Check if host should be blacklisted based on failures - BALANCED mode"""
        # FIXED: DNS errors need 3 failures before blacklisting (was 1 - too aggressive)
        if self.dns_error and self.failure_count >= self.dns_blacklist_threshold:
            return True
        # FIXED: Connection timeouts need 3 failures before blacklisting (was 1 - too aggressive)
        if self.connection_timeout and self.failure_count >= self.blacklist_threshold:
            return True
        # Standard threshold for other failures
        return self.failure_count >= self.blacklist_threshold
    
    def should_skip_target(self) -> bool:
        """NEW: Check if target should be skipped entirely after N consecutive failures"""
        # Skip after 3 consecutive failures
        if self.consecutive_failures >= 3:
            return True
        # Skip if blacklisted
        if self.is_blacklisted:
            return True
        # Skip if success rate is below 30%
        if self.total_requests >= 5 and (self.total_failures / self.total_requests) > 0.7:
            return True
        return False
    
    def record_failure(self, reason: str = "unknown"):
        """Record a failure and update status - AGGRESSIVE mode"""
        self.failure_count += 1
        self.consecutive_failures += 1
        self.total_failures += 1
        self.total_requests += 1
        self.last_failure_time = time.time()
        self.failure_reasons.append(reason)
        
        reason_lower = reason.lower()
        if "dns" in reason_lower or "name resolution" in reason_lower:
            self.dns_error = True
        if "timeout" in reason_lower or "timed out" in reason_lower or "timed" in reason_lower:
            self.connection_timeout = True
            self.timeout_count += 1  # Track timeout count for adaptive timeout
            # Enable adaptive timeout after 2 timeouts
            if self.timeout_count >= 2:
                self.adaptive_timeout_enabled = True
        
        # Debug logging
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"HostStatus.record_failure: {self.hostname}, count={self.failure_count}, "
                    f"consecutive={self.consecutive_failures}, "
                    f"dns_error={self.dns_error}, timeout={self.connection_timeout}, "
                    f"timeout_count={self.timeout_count}, adaptive_timeout={self.adaptive_timeout_enabled}, "
                    f"should_blacklist={self.should_blacklist()}, "
                    f"should_skip={self.should_skip_target()}")
            
        if self.should_blacklist():
            self.is_blacklisted = True
            self.is_alive = False
            self.should_skip = True
            self.skip_reason = f"blacklisted after {self.failure_count} failures"
            logger.warning(f"Host {self.hostname} blacklisted and skipped after {self.failure_count} failures "
                          f"(DNS: {self.dns_error}, Timeout: {self.connection_timeout})")
        elif self.should_skip_target():
            self.should_skip = True
            self.skip_reason = f"consecutive failures: {self.consecutive_failures}"
            logger.warning(f"Host {self.hostname} marked for skip: {self.skip_reason}")
    
    def record_success(self):
        """Record a success and reset consecutive failure counter"""
        self.consecutive_failures = 0
        self.total_requests += 1
        self.is_alive = True
        self.failure_count = max(0, self.failure_count - 1)  # Gradual recovery
        if self.failure_count < self.blacklist_threshold:
            self.is_blacklisted = False
            self.should_skip = False


@dataclass
class PortScanResult:
    """Cached result of a port scan"""
    host: str
    open_ports: Set[int] = field(default_factory=set)
    closed_ports: Set[int] = field(default_factory=set)
    scan_time: float = 0
    service_hints: Dict[int, str] = field(default_factory=dict)
    is_valid: bool = True


class ScanOptimizer:
    """
    Centralized optimizer for scanning operations
    Implements intelligent host filtering, port caching, and retry optimization
    """
    
    # Common ports by service type (prioritized)
    WEB_PORTS = [80, 443, 8080, 8443]
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 
                   3306, 3389, 5432, 5900, 8080, 8443, 9000]
    
    # Reduced timeout values (in seconds)
    CONNECTION_TIMEOUT = 3  # Reduced from 5s - fail fast on dead hosts
    READ_TIMEOUT = 8        # Reduced from 10s
    DNS_TIMEOUT = 2         # Fast DNS timeout
    DIRBUST_TIMEOUT = 30    # Reduced from 60s+
    
    # Rate limiting
    MAX_CONCURRENT_HOSTS = 5
    HOST_SCAN_DELAY = 0.5   # Delay between host scans
    
    def __init__(self):
        self.host_statuses: Dict[str, HostStatus] = {}
        self.port_cache: Dict[str, PortScanResult] = {}
        self.wpscan_failures: Dict[str, int] = defaultdict(int)
        self.dirbust_failures: Dict[str, int] = defaultdict(int)
        self._lock = threading.RLock()
        
        # Statistics
        self.stats = {
            'hosts_skipped': 0,
            'ports_cached': 0,
            'retries_avoided': 0,
            'time_saved_seconds': 0,
            'queue_cleared': 0,  # Track queue clear events
            'iteration_skipped': 0  # Track skipped iterations
        }
        
        # OPTIMIZATION: Track blacklisted hosts for queue clearing
        self._blacklisted_hosts: Set[str] = set()
        
        # OPTIMIZATION: Track scan data for iteration decisions
        self._previous_scan_data: Dict[str, Any] = {}
    
    def get_host_status(self, hostname: str) -> Optional[HostStatus]:
        """Get or create host status"""
        with self._lock:
            if hostname not in self.host_statuses:
                self.host_statuses[hostname] = HostStatus(hostname=hostname)
            return self.host_statuses[hostname]
    
    def is_host_blacklisted(self, hostname: str) -> bool:
        """Check if host should be skipped (blacklisted or marked for skip)"""
        status = self.get_host_status(hostname)
        if status.is_blacklisted or status.should_skip:
            self.stats['hosts_skipped'] += 1
            logger.debug(f"Skipping host: {hostname} "
                        f"(blacklisted={status.is_blacklisted}, "
                        f"should_skip={status.should_skip}, "
                        f"failures: {status.failure_count}, "
                        f"consecutive: {status.consecutive_failures}, "
                        f"reason: {status.skip_reason})")
            return True
        return False

    def should_skip_target(self, hostname: str) -> bool:
        """NEW: Check if target should be completely skipped"""
        status = self.get_host_status(hostname)
        return status.should_skip_target()

    def get_skip_reason(self, hostname: str) -> str:
        """NEW: Get the reason why a target should be skipped"""
        status = self.get_host_status(hostname)
        if status.should_skip:
            return status.skip_reason
        if status.is_blacklisted:
            return f"blacklisted after {status.failure_count} failures"
        if status.consecutive_failures >= 3:
            return f"consecutive failures: {status.consecutive_failures}"
        return ""
    
    def record_host_failure(self, hostname: str, reason: str = "unknown"):
        """Record a host failure and check for blacklisting.
        
        OPTIMIZATION: Immediately registers blacklisted hosts for queue clearing
        to prevent sending more requests to dead hosts.
        """
        status = self.get_host_status(hostname)
        status.record_failure(reason)
        
        if status.is_blacklisted:
            # OPTIMIZATION: Register for queue clearing immediately
            self.register_blacklisted_host(hostname)
            logger.warning(f"Blacklisting host {hostname} after "
                          f"{status.failure_count} failures "
                          f"(DNS error: {status.dns_error}, "
                          f"timeouts: {status.connection_timeout})")
    
    def record_host_success(self, hostname: str):
        """Record a successful host connection"""
        status = self.get_host_status(hostname)
        status.is_alive = True
        status.failure_count = max(0, status.failure_count - 1)  # Gradual recovery
        status.is_blacklisted = False
    
    def cache_port_scan(self, host: str, open_ports: Set[int], 
                       closed_ports: Set[int] = None, 
                       service_hints: Dict[int, str] = None) -> None:
        """Cache port scan results"""
        with self._lock:
            self.port_cache[host] = PortScanResult(
                host=host,
                open_ports=open_ports,
                closed_ports=closed_ports or set(),
                scan_time=time.time(),
                service_hints=service_hints or {}
            )
    
    def get_cached_ports(self, host: str, max_age: int = 3600) -> Optional[PortScanResult]:
        """Get cached port scan results if valid"""
        with self._lock:
            if host in self.port_cache:
                result = self.port_cache[host]
                age = time.time() - result.scan_time
                if age < max_age and result.is_valid:
                    self.stats['ports_cached'] += 1
                    logger.debug(f"Using cached port scan for {host} "
                                f"(open: {result.open_ports}, age: {age:.0f}s)")
                    return result
            return None
    
    def should_skip_port(self, host: str, port: int) -> bool:
        """Check if port was already confirmed closed for this host"""
        cached = self.get_cached_ports(host)
        if cached and port in cached.closed_ports:
            return True
        return False
    
    def get_smart_ports(self, host: str, service_type: str = "web") -> List[int]:
        """
        Get prioritized ports based on service type and previous results
        Reduces unnecessary port scanning
        """
        if service_type == "web":
            return self.WEB_PORTS
        elif service_type == "common":
            return self.COMMON_PORTS
        else:
            # If we have cached results, prioritize open ports
            cached = self.get_cached_ports(host)
            if cached and cached.open_ports:
                return list(cached.open_ports)
            return self.WEB_PORTS
    
    def should_retry_wpscan(self, plugin_name: str, attempt: int) -> bool:
        """
        Intelligent WPScan retry logic
        Reduces wasted time on rate-limited plugins
        
        Args:
            plugin_name: Name of the plugin being scanned
            attempt: Attempt number (0 = first, 1 = first retry, 2 = second retry)
        
        Returns:
            True if retry should be attempted, False if should skip
        """
        with self._lock:
            key = f"{plugin_name}"
            failures = self.wpscan_failures[key]
            
            # First attempt (attempt 0) always allowed
            if attempt == 0:
                return True
            
            # First retry (attempt 1) - allow if less than 2 failures
            if attempt == 1:
                if failures < 2:
                    return True
                else:
                    self.stats['retries_avoided'] += 1
                    logger.debug(f"Skipping WPScan retry for {plugin_name} "
                               f"(already failed {failures} times)")
                    return False
            
            # Second retry (attempt 2) - deny if any failures
            if attempt >= 2:
                self.stats['retries_avoided'] += 1
                logger.debug(f"Skipping WPScan retry for {plugin_name} "
                           f"(max retries reached, failures: {failures})")
                return False
            
            return False
    
    def record_wpscan_failure(self, plugin_name: str, is_rate_limit: bool = False):
        """Record WPScan failure"""
        with self._lock:
            key = f"{plugin_name}"
            self.wpscan_failures[key] += 1
            if is_rate_limit:
                logger.warning(f"WPScan rate limited for {plugin_name}, "
                             f"will skip future retries")
    
    def should_retry_dirbust(self, path: str, attempt: int) -> bool:
        """
        Directory brute-force retry logic
        No retries on timeout - immediate skip
        """
        with self._lock:
            key = f"dirbust:{path}"
            failures = self.dirbust_failures[key]
            
            # No retries on timeout
            if failures >= 1:
                self.stats['retries_avoided'] += 1
                logger.debug(f"Skipping dirbust retry for {path} "
                           f"(previous timeout/failure)")
                return False
            
            return attempt == 0
    
    def record_dirbust_timeout(self, path: str):
        """Record directory brute-force timeout"""
        with self._lock:
            key = f"dirbust:{path}"
            self.dirbust_failures[key] += 1
            logger.warning(f"Dirbust timeout for {path}, skipping future attempts")
    
    def assign_host_priority(self, hostname: str, 
                           has_web_content: bool = False,
                           is_subdomain: bool = False) -> int:
        """
        Assign scanning priority to hosts
        1 = High (live web content)
        2 = Medium (responsive but no content)
        3 = Low (dead/unresponsive)
        """
        status = self.get_host_status(hostname)
        
        if status.is_blacklisted:
            return 3  # Lowest priority
        
        if has_web_content and status.failure_count == 0:
            return 1  # Highest priority
        
        if status.failure_count <= 1:
            return 2  # Medium priority
        
        return 3  # Low priority
    
    def get_optimized_timeout(self, hostname: str, 
                            operation: str = "connection") -> int:
        """
        Get optimized timeout based on host history - ADAPTIVE TIMEOUT
        
        OPTIMIZATION: Implements adaptive timeout for hosts with multiple timeouts:
        - After 2 timeouts: reduce timeout by 50%
        - After 3 timeouts: reduce timeout by 75%
        - After 4+ timeouts: use minimal timeout (2s)
        
        This prevents wasting time on hosts that consistently timeout.
        """
        status = self.get_host_status(hostname)
        
        # Fast timeout for hosts with DNS errors
        if status.dns_error:
            return 2
        
        # ADAPTIVE TIMEOUT: Reduce timeout for hosts with multiple timeouts
        if status.adaptive_timeout_enabled and operation == "connection":
            timeout_count = status.timeout_count
            if timeout_count >= 4:
                # Minimal timeout after 4+ timeouts
                return 2
            elif timeout_count >= 3:
                # 25% of normal timeout after 3 timeouts
                return max(2, int(self.CONNECTION_TIMEOUT * 0.25))
            elif timeout_count >= 2:
                # 50% of normal timeout after 2 timeouts
                return max(2, int(self.CONNECTION_TIMEOUT * 0.5))
        
        # Standard timeout for new hosts
        if operation == "connection":
            return self.CONNECTION_TIMEOUT
        elif operation == "dns":
            return self.DNS_TIMEOUT
        else:
            return self.READ_TIMEOUT

    # ─── FIX #8: ENDPOINT PRE-FILTERING ────────────────────────────────────────
    
    def should_scan_endpoint(self, url: str) -> bool:
        """
        FIX #8: Pre-filter endpoints before adding to scan queue.
        
        Checks if endpoint has parameters that can be tested for vulnerabilities.
        Endpoints without parameters are skipped to avoid wasting scan budget.
        
        Args:
            url: URL to check
            
        Returns:
            True if endpoint should be scanned, False if it should be skipped
        """
        from urllib.parse import urlparse, parse_qs
        
        parsed = urllib.parse.urlparse(url)
        
        # Check if URL has query parameters
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                return True  # Has parameters, should scan
        
        # Check if URL path has potential path parameters (e.g., /users/123)
        path = parsed.path
        path_segments = [s for s in path.split('/') if s]
        
        # Look for numeric segments that might be IDs
        for segment in path_segments:
            if segment.isdigit() or (len(segment) > 0 and segment.replace('-', '').replace('_', '').isdigit()):
                return True  # Has potential path parameter
        
        # Check for common parameter patterns in path
        param_patterns = [
            '/id/', '/user/', '/item/', '/product/', '/post/', '/page/',
            '/category/', '/tag/', '/search/', '/filter/', '/sort/',
            '/api/v', '/rest/', '/graphql', '/action/', '/cmd/',
        ]
        
        path_lower = path.lower()
        for pattern in param_patterns:
            if pattern in path_lower:
                return True  # Has potential parameter pattern
        
        # Endpoint has no apparent parameters - skip scanning
        return False
    
    def get_endpoint_scan_priority(self, url: str) -> int:
        """
        FIX #8: Get scan priority for endpoint based on parameter richness.
        
        Returns:
            1 = High priority (multiple parameters, injection-prone names)
            2 = Medium priority (single parameter)
            3 = Low priority (no parameters, path-based only)
        """
        from urllib.parse import urlparse, parse_qs
        
        parsed = urllib.parse.urlparse(url)
        
        # Count query parameters
        param_count = 0
        injection_prone = False
        
        if parsed.query:
            params = parse_qs(parsed.query)
            param_count = len(params)
            
            # Check for injection-prone parameter names
            injection_names = {
                'id', 'page', 'itemid', 'post_id', 'p', 'cat', 'tag',
                'search', 'query', 'url', 'redirect', 'next', 'callback',
                'file', 'path', 'include', 'template', 'rest_route',
                'action', 'method', 'cmd', 'exec', 'download', 'data',
                'input', 'output', 'content', 'body', 'payload'
            }
            
            for param_name in params.keys():
                if param_name.lower() in injection_names:
                    injection_prone = True
                    break
        
        # High priority: multiple parameters or injection-prone names
        if param_count >= 2 or injection_prone:
            return 1
        
        # Medium priority: single parameter
        if param_count == 1:
            return 2
        
        # Low priority: no parameters (path-based only)
        return 3
    
    def filter_endpoints_for_scanning(self, urls: List[str]) -> List[Dict[str, Any]]:
        """
        FIX #8: Filter and prioritize endpoints for scanning.
        
        Args:
            urls: List of URLs to filter
            
        Returns:
            List of dicts with 'url', 'should_scan', and 'priority' keys
        """
        results = []
        
        for url in urls:
            should_scan = self.should_scan_endpoint(url)
            priority = self.get_endpoint_scan_priority(url) if should_scan else 3
            
            results.append({
                'url': url,
                'should_scan': should_scan,
                'priority': priority
            })
        
        # Sort by priority (lower = higher priority)
        results.sort(key=lambda x: x['priority'])
        
        return results

    # ═══════════════════════════════════════════════════════════════════════════
    # QUEUE MANAGEMENT - Clear queue when hosts are blacklisted
    # ═══════════════════════════════════════════════════════════════════════════
    
    def register_blacklisted_host(self, hostname: str) -> None:
        """
        Register a newly blacklisted host for queue clearing.
        Call this immediately after a host is blacklisted to trigger queue cleanup.
        """
        with self._lock:
            if hostname not in self._blacklisted_hosts:
                self._blacklisted_hosts.add(hostname)
                logger.info(f"[OPTIMIZER] Registered blacklisted host for queue clearing: {hostname}")
    
    def get_blacklisted_hosts(self) -> Set[str]:
        """Get set of all blacklisted hosts for queue filtering."""
        with self._lock:
            return self._blacklisted_hosts.copy()
    
    def is_host_in_blacklist(self, hostname: str) -> bool:
        """Check if a host is in the blacklist (for queue filtering)."""
        with self._lock:
            return hostname in self._blacklisted_hosts
    
    def clear_queue_for_blacklisted_hosts(self, queue: List[Any], 
                                          url_extractor=None) -> List[Any]:
        """
        Remove items from queue that target blacklisted hosts.
        
        Args:
            queue: List of queue items (URLs, endpoints, etc.)
            url_extractor: Function to extract URL from queue item.
                          If None, items are assumed to be URL strings.
        
        Returns:
            Filtered queue with blacklisted hosts removed.
        """
        if not self._blacklisted_hosts:
            return queue
        
        filtered = []
        removed = 0
        
        for item in queue:
            url = url_extractor(item) if url_extractor else str(item)
            try:
                from urllib.parse import urlparse
                parsed = urllib.parse.urlparse(url)
                hostname = parsed.hostname or parsed.netloc or ""
                
                if hostname in self._blacklisted_hosts:
                    removed += 1
                    logger.debug(f"[OPTIMIZER] Removed blacklisted host from queue: {hostname}")
                else:
                    filtered.append(item)
            except Exception:
                # Keep items that can't be parsed
                filtered.append(item)
        
        if removed > 0:
            self.stats['queue_cleared'] += removed
            logger.warning(f"[OPTIMIZER] Cleared {removed} items from queue for blacklisted hosts")
        
        return filtered

    # ═══════════════════════════════════════════════════════════════════════════
    # ITERATION OPTIMIZATION - Skip unnecessary iterations
    # ═══════════════════════════════════════════════════════════════════════════
    
    def store_scan_data(self, data: Dict[str, Any]) -> None:
        """
        Store current scan data for comparison in next iteration.
        Used to detect if there's new data worth re-scanning.
        """
        with self._lock:
            self._previous_scan_data = {
                'endpoint_count': data.get('endpoint_count', 0),
                'vulnerability_count': data.get('vulnerability_count', 0),
                'new_endpoints': set(data.get('new_endpoints', [])),
                'new_vulns': set(data.get('new_vulns', [])),
                'timestamp': time.time()
            }
    
    def should_skip_iteration(self, current_data: Dict[str, Any]) -> bool:
        """
        Determine if next iteration should be skipped due to no new data.
        
        OPTIMIZATION: Skip iteration 2+ if:
        - No new endpoints discovered
        - No new vulnerabilities found
        - Same scan data as previous iteration
        
        Returns:
            True if iteration should be skipped, False otherwise.
        """
        if not self._previous_scan_data:
            # No previous data to compare - don't skip
            return False
        
        with self._lock:
            prev = self._previous_scan_data
            
            # Check for new endpoints
            current_endpoints = set(current_data.get('new_endpoints', []))
            prev_endpoints = prev.get('new_endpoints', set())
            new_endpoints = current_endpoints - prev_endpoints
            
            # Check for new vulnerabilities
            current_vulns = set(current_data.get('new_vulns', []))
            prev_vulns = prev.get('new_vulns', set())
            new_vulns = current_vulns - prev_vulns
            
            # Skip if no new data
            if not new_endpoints and not new_vulns:
                self.stats['iteration_skipped'] += 1
                logger.info(f"[OPTIMIZER] Skipping iteration - no new data detected "
                           f"(endpoints: {len(current_endpoints)}, vulns: {len(current_vulns)})")
                return True
            
            logger.info(f"[OPTIMIZER] Continuing iteration - new data found: "
                       f"{len(new_endpoints)} endpoints, {len(new_vulns)} vulns")
            return False
    
    def reset_iteration_data(self) -> None:
        """Reset iteration tracking data (call at end of scan cycle)."""
        with self._lock:
            self._previous_scan_data.clear()
            logger.debug("[OPTIMIZER] Reset iteration tracking data")
    
    def calculate_time_saved(self) -> Dict[str, Any]:
        """Calculate time saved through optimizations - ENHANCED with all optimizations"""
        # Estimate time saved from each optimization
        skipped_hosts_time = self.stats['hosts_skipped'] * 120  # ~2min per dead host
        cached_ports_time = self.stats['ports_cached'] * 10     # ~10s per port
        avoided_retries_time = self.stats['retries_avoided'] * 60  # ~1min per retry
        queue_cleared_time = self.stats['queue_cleared'] * 30  # ~30s per queue item cleared
        iteration_skipped_time = self.stats['iteration_skipped'] * 300  # ~5min per skipped iteration
        
        total_saved = (skipped_hosts_time + cached_ports_time + avoided_retries_time + 
                      queue_cleared_time + iteration_skipped_time)
        
        return {
            'hosts_skipped': self.stats['hosts_skipped'],
            'ports_cached': self.stats['ports_cached'],
            'retries_avoided': self.stats['retries_avoided'],
            'queue_items_cleared': self.stats['queue_cleared'],
            'iterations_skipped': self.stats['iteration_skipped'],
            'estimated_time_saved_seconds': total_saved,
            'estimated_time_saved_minutes': total_saved / 60,
            'estimated_time_saved_hours': total_saved / 3600,
            'breakdown': {
                'skipped_hosts_minutes': skipped_hosts_time / 60,
                'cached_ports_minutes': cached_ports_time / 60,
                'avoided_retries_minutes': avoided_retries_time / 60,
                'queue_cleared_minutes': queue_cleared_time / 60,
                'iterations_skipped_minutes': iteration_skipped_time / 60
            }
        }
    
    def generate_report(self) -> str:
        """Generate optimization report"""
        stats = self.calculate_time_saved()
        
        report = [
            "\n" + "="*60,
            "SCAN OPTIMIZATION REPORT",
            "="*60,
            f"Hosts skipped (blacklisted): {stats['hosts_skipped']}",
            f"Port scans cached: {stats['ports_cached']}",
            f"Retries avoided: {stats['retries_avoided']}",
            f"Estimated time saved: {stats['estimated_time_saved_minutes']:.1f} minutes",
            f"  ({stats['estimated_time_saved_hours']:.2f} hours)",
            "="*60
        ]
        
        return "\n".join(report)


# Global optimizer instance
optimizer = ScanOptimizer()


def get_optimizer() -> ScanOptimizer:
    """Get the global optimizer instance"""
    return optimizer