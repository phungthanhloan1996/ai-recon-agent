"""
core/resource_manager.py - Global Resource Management and Concurrency Control
Provides centralized management for:
- Global concurrency limits
- Worker pools for heavy operations
- Timeout tracking and adaptive adjustments
- Result caching for expensive operations
"""

import threading
import time
import logging
from collections import defaultdict
from typing import Dict, Set, List, Optional, Any, Callable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
import hashlib

logger = logging.getLogger("recon.resource_manager")


@dataclass
class CacheEntry:
    """A cached result with TTL support"""
    data: Any
    timestamp: float
    ttl: int  # Time-to-live in seconds
    hits: int = 0
    
    def is_valid(self) -> bool:
        """Check if cache entry is still valid"""
        return (time.time() - self.timestamp) < self.ttl
    
    def access(self) -> Any:
        """Access the cached data and increment hit counter"""
        self.hits += 1
        return self.data


class GlobalConcurrencyManager:
    """
    Global concurrency manager that limits the total number of
    concurrent operations across all tools and phases.
    
    This prevents resource exhaustion when running multiple heavy
    tools (subfinder, assetfinder, nuclei, etc.) simultaneously.
    """
    
    def __init__(self, max_concurrent: int = 10):
        """
        Initialize the concurrency manager.
        
        Args:
            max_concurrent: Maximum number of concurrent operations
        """
        self.max_concurrent = max_concurrent
        self._semaphore = threading.Semaphore(max_concurrent)
        self._active_operations: Dict[str, float] = {}  # operation_id -> start_time
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(max_workers=max_concurrent)
        
        # Statistics
        self.stats = {
            'total_operations': 0,
            'completed_operations': 0,
            'failed_operations': 0,
            'max_concurrent_reached': 0,
            'total_wait_time': 0.0,
        }
    
    def acquire(self, operation_id: str, timeout: float = None) -> bool:
        """
        Acquire a slot for an operation.
        
        Args:
            operation_id: Unique identifier for the operation
            timeout: Maximum time to wait for a slot (None = wait forever)
            
        Returns:
            True if slot acquired, False if timeout
        """
        start_time = time.time()
        acquired = self._semaphore.acquire(blocking=True, timeout=timeout)
        
        if acquired:
            with self._lock:
                self._active_operations[operation_id] = time.time()
                self.stats['total_operations'] += 1
                current_active = len(self._active_operations)
                if current_active > self.stats['max_concurrent_reached']:
                    self.stats['max_concurrent_reached'] = current_active
                
                wait_time = time.time() - start_time
                self.stats['total_wait_time'] += wait_time
                
                if wait_time > 0.1:  # Only log if waited significantly
                    logger.debug(f"[CONCURRENCY] {operation_id} waited {wait_time:.2f}s for slot")
        
        return acquired
    
    def release(self, operation_id: str) -> None:
        """
        Release a slot after operation completes.
        
        Args:
            operation_id: Unique identifier for the operation
        """
        with self._lock:
            if operation_id in self._active_operations:
                del self._active_operations[operation_id]
                self.stats['completed_operations'] += 1
        self._semaphore.release()
    
    def record_failure(self, operation_id: str) -> None:
        """Record an operation failure"""
        with self._lock:
            if operation_id in self._active_operations:
                del self._active_operations[operation_id]
            self.stats['failed_operations'] += 1
        self._semaphore.release()
    
    def get_active_count(self) -> int:
        """Get current number of active operations"""
        with self._lock:
            return len(self._active_operations)
    
    def submit_with_limit(self, fn: Callable, *args, 
                          operation_id: str = None, 
                          timeout: float = None,
                          **kwargs) -> Optional[Any]:
        """
        Submit a function for execution with concurrency limiting.
        
        Args:
            fn: Function to execute
            *args: Arguments to pass to function
            operation_id: Unique identifier (auto-generated if None)
            timeout: Timeout for acquiring a slot
            **kwargs: Keyword arguments to pass to function
            
        Returns:
            Result of the function, or None if couldn't acquire slot
        """
        if operation_id is None:
            operation_id = f"op_{hash(str(fn) + str(args))}"
        
        if not self.acquire(operation_id, timeout):
            logger.warning(f"[CONCURRENCY] Could not acquire slot for {operation_id}")
            return None
        
        try:
            result = fn(*args, **kwargs)
            return result
        except Exception as e:
            logger.error(f"[CONCURRENCY] Operation {operation_id} failed: {e}")
            self.record_failure(operation_id)
            raise
        finally:
            self.release(operation_id)
    
    def map_with_limit(self, fn: Callable, items: List[Any], 
                       max_workers: int = None,
                       operation_prefix: str = "op") -> List[Any]:
        """
        Map a function over items with concurrency limiting.
        
        Args:
            fn: Function to apply to each item
            items: List of items to process
            max_workers: Override max concurrent workers for this batch
            operation_prefix: Prefix for operation IDs
            
        Returns:
            List of results
        """
        if max_workers:
            old_max = self.max_concurrent
            self.max_concurrent = max_workers
        
        results = []
        futures = {}
        
        for i, item in enumerate(items):
            operation_id = f"{operation_prefix}_{i}_{hash(str(item))}"
            
            def wrapped_fn(it=item, op_id=operation_id):
                if not self.acquire(op_id, timeout=300):
                    raise TimeoutError(f"Could not acquire slot for {op_id}")
                try:
                    return fn(it)
                finally:
                    self.release(op_id)
            
            future = self._executor.submit(wrapped_fn)
            futures[future] = i
        
        # Collect results in order
        results = [None] * len(items)
        for future in as_completed(futures):
            idx = futures[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                logger.error(f"[CONCURRENCY] Item {idx} failed: {e}")
                results[idx] = None
        
        if max_workers:
            self.max_concurrent = old_max
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get concurrency statistics"""
        with self._lock:
            stats = self.stats.copy()
            stats['current_active'] = len(self._active_operations)
            stats['max_concurrent'] = self.max_concurrent
            if stats['total_operations'] > 0:
                stats['avg_wait_time'] = stats['total_wait_time'] / stats['total_operations']
            else:
                stats['avg_wait_time'] = 0
            return stats
    
    def shutdown(self, wait: bool = True):
        """Shutdown the executor"""
        self._executor.shutdown(wait=wait)


class ResultCache:
    """
    Generic result cache with TTL support for expensive operations.
    Used for caching nmap scans, wappalyzer results, etc.
    """
    
    def __init__(self, default_ttl: int = 3600):
        """
        Initialize the cache.
        
        Args:
            default_ttl: Default time-to-live in seconds (1 hour)
        """
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self.default_ttl = default_ttl
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
        }
    
    def _generate_key(self, *args, **kwargs) -> str:
        """Generate a cache key from arguments"""
        key_data = str(args) + str(sorted(kwargs.items()))
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get a cached result by key.
        
        Args:
            key: Cache key
            
        Returns:
            Cached data if valid, None otherwise
        """
        with self._lock:
            if key in self._cache:
                entry = self._cache[key]
                if entry.is_valid():
                    self.stats['hits'] += 1
                    logger.debug(f"[CACHE] Hit for key: {key[:16]}...")
                    return entry.access()
                else:
                    # Expired, remove it
                    del self._cache[key]
                    self.stats['evictions'] += 1
            
            self.stats['misses'] += 1
            return None
    
    def set(self, key: str, data: Any, ttl: int = None) -> None:
        """
        Store a result in the cache.
        
        Args:
            key: Cache key
            data: Data to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        with self._lock:
            self._cache[key] = CacheEntry(
                data=data,
                timestamp=time.time(),
                ttl=ttl if ttl is not None else self.default_ttl
            )
            logger.debug(f"[CACHE] Stored key: {key[:16]}... (ttl={ttl or self.default_ttl}s)")
    
    def get_or_compute(self, key: str, compute_fn: Callable, 
                       ttl: int = None, *args, **kwargs) -> Any:
        """
        Get from cache or compute and cache the result.
        
        Args:
            key: Cache key
            compute_fn: Function to call if not cached
            ttl: Time-to-live for cached result
            *args, **kwargs: Arguments to pass to compute_fn
            
        Returns:
            Cached or computed result
        """
        cached = self.get(key)
        if cached is not None:
            return cached
        
        # Compute and cache
        result = compute_fn(*args, **kwargs)
        self.set(key, result, ttl)
        return result
    
    def invalidate(self, key: str) -> bool:
        """
        Invalidate a cache entry.
        
        Args:
            key: Cache key to invalidate
            
        Returns:
            True if entry was found and removed
        """
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self.stats['evictions'] += 1
                return True
            return False
    
    def invalidate_pattern(self, prefix: str) -> int:
        """
        Invalidate all cache entries matching a prefix.
        
        Args:
            prefix: Key prefix to match
            
        Returns:
            Number of entries invalidated
        """
        with self._lock:
            keys_to_remove = [k for k in self._cache if k.startswith(prefix)]
            for key in keys_to_remove:
                del self._cache[key]
                self.stats['evictions'] += 1
            return len(keys_to_remove)
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            logger.debug("[CACHE] Cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            stats = self.stats.copy()
            stats['size'] = len(self._cache)
            stats['valid_entries'] = sum(1 for e in self._cache.values() if e.is_valid())
            if stats['hits'] + stats['misses'] > 0:
                stats['hit_rate'] = stats['hits'] / (stats['hits'] + stats['misses'])
            else:
                stats['hit_rate'] = 0
            return stats


class NucleiWorkerPool:
    """
    Specialized worker pool for Nuclei scanning with:
    - Timeout tracking per endpoint
    - Adaptive timeout based on history
    - Worker limits to prevent resource exhaustion
    - Progress tracking
    """
    
    def __init__(self, max_workers: int = 3, default_timeout: int = 300):
        """
        Initialize the Nuclei worker pool.
        
        Args:
            max_workers: Maximum concurrent Nuclei processes
            default_timeout: Default timeout per scan in seconds
        """
        self.max_workers = max_workers
        self.default_timeout = default_timeout
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._active_scans: Dict[str, Dict] = {}
        self._timeout_history: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.RLock()
        
        # Adaptive timeout settings
        self.adaptive_timeout_enabled = True
        self.max_timeout = 600  # Maximum timeout (10 minutes)
        self.timeout_reduction_factor = 0.75  # Reduce timeout by 25% after timeout
        
        # Statistics
        self.stats = {
            'scans_completed': 0,
            'scans_timed_out': 0,
            'scans_failed': 0,
            'total_scan_time': 0.0,
        }
    
    def _get_adaptive_timeout(self, url: str) -> int:
        """
        Get adaptive timeout based on historical performance.
        
        Args:
            url: Target URL
            
        Returns:
            Timeout in seconds
        """
        if not self.adaptive_timeout_enabled:
            return self.default_timeout
        
        history = self._timeout_history.get(url, [])
        
        if not history:
            return self.default_timeout
        
        # Calculate average completion time
        avg_time = sum(history) / len(history)
        
        # If we have timeouts in history, reduce timeout
        timeout_count = sum(1 for t in history if t >= self.default_timeout)
        if timeout_count > 0:
            # Reduce timeout progressively
            reduction = self.timeout_reduction_factor ** min(timeout_count, 3)
            adaptive_timeout = int(self.default_timeout * reduction)
            return max(30, min(adaptive_timeout, self.max_timeout))
        
        # Add buffer to average time
        return int(min(avg_time * 1.5, self.max_timeout))
    
    def submit_scan(self, url: str, scan_fn: Callable, 
                    timeout: int = None) -> Dict[str, Any]:
        """
        Submit a Nuclei scan with timeout tracking.
        
        Args:
            url: Target URL
            scan_fn: Function that performs the scan
            timeout: Override timeout (None = use adaptive)
            
        Returns:
            Scan result dictionary
        """
        if timeout is None:
            timeout = self._get_adaptive_timeout(url)
        
        scan_id = f"nuclei_{hash(url)}_{time.time()}"
        
        with self._lock:
            self._active_scans[scan_id] = {
                'url': url,
                'start_time': time.time(),
                'timeout': timeout,
            }
        
        def wrapped_scan():
            start = time.time()
            try:
                result = scan_fn(url, timeout=timeout)
                elapsed = time.time() - start
                
                with self._lock:
                    self._timeout_history[url].append(elapsed)
                    # Keep only last 5 entries
                    if len(self._timeout_history[url]) > 5:
                        self._timeout_history[url] = self._timeout_history[url][-5:]
                    self.stats['scans_completed'] += 1
                    self.stats['total_scan_time'] += elapsed
                
                return result
            except TimeoutError:
                elapsed = time.time() - start
                with self._lock:
                    self._timeout_history[url].append(elapsed)
                    if len(self._timeout_history[url]) > 5:
                        self._timeout_history[url] = self._timeout_history[url][-5:]
                    self.stats['scans_timed_out'] += 1
                raise
            except Exception as e:
                with self._lock:
                    self.stats['scans_failed'] += 1
                raise
            finally:
                with self._lock:
                    if scan_id in self._active_scans:
                        del self._active_scans[scan_id]
        
        future = self._executor.submit(wrapped_scan)
        return {'future': future, 'scan_id': scan_id, 'url': url}
    
    def wait_for_scans(self, scans: List[Dict], 
                       return_when: str = FIRST_COMPLETED) -> List[Dict]:
        """
        Wait for a batch of scans with timeout tracking.
        
        Args:
            scans: List of scan dictionaries from submit_scan
            return_when: When to return (FIRST_COMPLETED, ALL_COMPLETED)
            
        Returns:
            List of completed scan results
        """
        futures = {s['future']: s for s in scans}
        done, _ = wait(futures.keys(), return_when=return_when, timeout=300)
        
        results = []
        for future in done:
            scan_info = futures[future]
            try:
                result = future.result(timeout=0)
                results.append({
                    'url': scan_info['url'],
                    'scan_id': scan_info['scan_id'],
                    'result': result,
                    'status': 'completed'
                })
            except Exception as e:
                results.append({
                    'url': scan_info['url'],
                    'scan_id': scan_info['scan_id'],
                    'result': None,
                    'status': 'failed',
                    'error': str(e)
                })
        
        return results
    
    def get_adaptive_timeout_for_url(self, url: str) -> int:
        """Get the adaptive timeout for a URL without submitting a scan"""
        return self._get_adaptive_timeout(url)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        with self._lock:
            stats = self.stats.copy()
            stats['active_scans'] = len(self._active_scans)
            stats['max_workers'] = self.max_workers
            
            # Timeout history summary
            if self._timeout_history:
                all_times = [t for times in self._timeout_history.values() for t in times]
                if all_times:
                    stats['avg_scan_time'] = sum(all_times) / len(all_times)
                    stats['timeout_rate'] = stats['scans_timed_out'] / max(1, stats['scans_completed'] + stats['scans_timed_out'])
            
            return stats
    
    def shutdown(self, wait: bool = True):
        """Shutdown the worker pool"""
        self._executor.shutdown(wait=wait)


# Global instances
_global_concurrency = None
_global_cache = None
_nuclei_pool = None


def get_concurrency_manager(max_concurrent: int = 10) -> GlobalConcurrencyManager:
    """Get or create the global concurrency manager"""
    global _global_concurrency
    if _global_concurrency is None:
        _global_concurrency = GlobalConcurrencyManager(max_concurrent)
    return _global_concurrency


def get_result_cache(default_ttl: int = 3600) -> ResultCache:
    """Get or create the global result cache"""
    global _global_cache
    if _global_cache is None:
        _global_cache = ResultCache(default_ttl)
    return _global_cache


def get_nuclei_pool(max_workers: int = 3, default_timeout: int = 300) -> NucleiWorkerPool:
    """Get or create the Nuclei worker pool"""
    global _nuclei_pool
    if _nuclei_pool is None:
        _nuclei_pool = NucleiWorkerPool(max_workers, default_timeout)
    return _nuclei_pool


def shutdown_all():
    """Shutdown all global resource managers"""
    global _global_concurrency, _global_cache, _nuclei_pool
    if _global_concurrency:
        _global_concurrency.shutdown(wait=True)
    if _nuclei_pool:
        _nuclei_pool.shutdown(wait=True)
    _global_concurrency = None
    _global_cache = None
    _nuclei_pool = None