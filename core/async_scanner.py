"""
core/async_scanner.py - Parallel scanning with asyncio support

Provides async-based parallel scanning capabilities for improved performance
and resource utilization across multiple targets and endpoints.
"""

import asyncio
import aiohttp
import time
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import logging
import hashlib
from enum import Enum

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Status of async scan tasks"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class ScanTask:
    """Represents a single async scan task"""
    task_id: str
    url: str
    method: str = "GET"
    payload: Optional[Dict] = None
    headers: Optional[Dict] = None
    status: ScanStatus = ScanStatus.PENDING
    result: Optional[Any] = None
    error: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class ScanBatch:
    """Represents a batch of scan tasks"""
    batch_id: str
    tasks: List[ScanTask] = field(default_factory=list)
    status: ScanStatus = ScanStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    results_summary: Dict = field(default_factory=dict)


class AsyncScanner:
    """
    Async-based parallel scanner with smart rate limiting and resource management.
    
    Features:
    - Parallel HTTP scanning with asyncio/aiohttp
    - Smart rate limiting with token bucket algorithm
    - Automatic retry with exponential backoff
    - Result deduplication and caching
    - Priority queue for task scheduling
    - Circuit breaker pattern for failing endpoints
    """
    
    def __init__(
        self,
        max_concurrent: int = 50,
        rate_limit: float = 100.0,  # requests per second
        timeout: int = 30,
        max_retries: int = 3,
        cache_ttl: int = 3600,
        enable_circuit_breaker: bool = True,
        circuit_breaker_threshold: int = 5,
    ):
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache_ttl = cache_ttl
        self.enable_circuit_breaker = enable_circuit_breaker
        self.circuit_breaker_threshold = circuit_breaker_threshold
        
        # Rate limiting
        self._tokens = rate_limit
        self._last_token_update = time.time()
        self._token_lock = asyncio.Lock()
        
        # Circuit breaker state
        self._circuit_failures: Dict[str, int] = defaultdict(int)
        self._circuit_open: Set[str] = set()
        self._circuit_reset_time: Dict[str, float] = {}
        
        # Cache for results
        self._cache: Dict[str, Tuple[Any, float]] = {}
        
        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None
        
        # Callbacks
        self._on_task_start: Optional[Callable] = None
        self._on_task_complete: Optional[Callable] = None
        self._on_task_error: Optional[Callable] = None
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'cached_responses': 0,
            'retries': 0,
            'circuit_breaks': 0,
        }
    
    def _generate_cache_key(self, url: str, method: str, payload: Optional[Dict]) -> str:
        """Generate cache key for request"""
        key_data = f"{method}:{url}:{payload}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _get_cached(self, key: str) -> Optional[Any]:
        """Get cached result if available and not expired"""
        if key in self._cache:
            result, timestamp = self._cache[key]
            if time.time() - timestamp < self.cache_ttl:
                self.stats['cached_responses'] += 1
                return result
            else:
                del self._cache[key]
        return None
    
    def _cache_result(self, key: str, result: Any):
        """Cache a result"""
        self._cache[key] = (result, time.time())
    
    async def _acquire_token(self):
        """Acquire a rate limit token"""
        async with self._token_lock:
            now = time.time()
            elapsed = now - self._last_token_update
            self._tokens = min(
                self.rate_limit,
                self._tokens + elapsed * self.rate_limit
            )
            self._last_token_update = now
            
            if self._tokens >= 1:
                self._tokens -= 1
                return True
            
            # Wait for token to become available
            wait_time = (1 - self._tokens) / self.rate_limit
            await asyncio.sleep(wait_time)
            self._tokens = 0
            return True
    
    def _is_circuit_open(self, host: str) -> bool:
        """Check if circuit breaker is open for host"""
        if not self.enable_circuit_breaker:
            return False
        
        if host in self._circuit_open:
            reset_time = self._circuit_reset_time.get(host, 0)
            if time.time() < reset_time:
                return True
            else:
                # Try half-open
                self._circuit_open.discard(host)
                return False
        return False
    
    def _record_failure(self, host: str):
        """Record a failure for circuit breaker"""
        if not self.enable_circuit_breaker:
            return
        
        self._circuit_failures[host] += 1
        if self._circuit_failures[host] >= self.circuit_breaker_threshold:
            self._circuit_open.add(host)
            self._circuit_reset_time[host] = time.time() + 60  # 1 minute cooldown
            self.stats['circuit_breaks'] += 1
            logger.warning(f"Circuit breaker opened for {host}")
    
    def _record_success(self, host: str):
        """Record a success and reset circuit breaker"""
        self._circuit_failures[host] = 0
        self._circuit_open.discard(host)
    
    async def _make_request(
        self,
        session: aiohttp.ClientSession,
        task: ScanTask
    ) -> Optional[Dict]:
        """Make a single HTTP request with retry logic"""
        
        # Check cache first
        cache_key = self._generate_cache_key(task.url, task.method, task.payload)
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached
        
        # Check circuit breaker
        from urllib.parse import urlparse
        host = urlparse(task.url).netloc
        if self._is_circuit_open(host):
            task.status = ScanStatus.FAILED
            task.error = "Circuit breaker open"
            return None
        
        task.status = ScanStatus.RUNNING
        task.start_time = time.time()
        
        if self._on_task_start:
            self._on_task_start(task)
        
        last_error = None
        for attempt in range(self.max_retries):
            try:
                await self._acquire_token()
                
                async with self._semaphore:
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    
                    kwargs = {
                        'method': task.method,
                        'url': task.url,
                        'timeout': timeout,
                        'headers': task.headers,
                    }
                    
                    if task.payload and task.method != "GET":
                        kwargs['json'] = task.payload
                    
                    async with session.request(**kwargs) as response:
                        result = {
                            'status_code': response.status,
                            'headers': dict(response.headers),
                            'body': await response.text(),
                            'url': task.url,
                            'method': task.method,
                            'timestamp': time.time(),
                        }
                        
                        # Cache successful responses
                        if response.status < 400:
                            self._cache_result(cache_key, result)
                        
                        task.status = ScanStatus.COMPLETED
                        task.result = result
                        task.end_time = time.time()
                        
                        self._record_success(host)
                        self.stats['successful_requests'] += 1
                        
                        if self._on_task_complete:
                            self._on_task_complete(task)
                        
                        return result
                        
            except asyncio.TimeoutError:
                last_error = "Timeout"
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt * 0.5)  # Exponential backoff
                    self.stats['retries'] += 1
                    
            except aiohttp.ClientError as e:
                last_error = f"Client error: {str(e)}"
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt * 0.5)
                    self.stats['retries'] += 1
                    
            except Exception as e:
                last_error = f"Unexpected error: {str(e)}"
                logger.error(f"Unexpected error in async scan: {e}")
                break
        
        task.status = ScanStatus.FAILED
        task.error = last_error
        task.end_time = time.time()
        self.stats['failed_requests'] += 1
        self._record_failure(host)
        
        if self._on_task_error:
            self._on_task_error(task)
        
        return None
    
    async def scan_urls(
        self,
        urls: List[str],
        method: str = "GET",
        payload: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[Dict]:
        """
        Scan multiple URLs in parallel with rate limiting and retry logic.
        
        Args:
            urls: List of URLs to scan
            method: HTTP method to use
            payload: Optional payload for POST requests
            headers: Optional headers
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of response dictionaries
        """
        self.stats['total_requests'] += len(urls)
        
        # Create semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        
        # Create aiohttp session
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=self.max_concurrent,
            enable_cleanup_closed=True,
        )
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create tasks
            tasks = []
            for url in urls:
                scan_task = ScanTask(
                    task_id=hashlib.md5(url.encode()).hexdigest()[:12],
                    url=url,
                    method=method,
                    payload=payload,
                    headers=headers,
                )
                tasks.append(self._make_request(session, scan_task))
            
            # Execute with progress tracking
            results = []
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result is not None:
                    results.append(result)
                
                if progress_callback:
                    completed = len(results)
                    total = len(urls)
                    progress_callback(completed, total, results)
        
        return results
    
    async def scan_with_callbacks(
        self,
        urls: List[str],
        on_start: Optional[Callable[[ScanTask], None]] = None,
        on_complete: Optional[Callable[[ScanTask], None]] = None,
        on_error: Optional[Callable[[ScanTask], None]] = None,
    ) -> List[Dict]:
        """
        Scan URLs with custom callbacks for each task lifecycle event.
        
        Args:
            urls: List of URLs to scan
            on_start: Callback when task starts
            on_complete: Callback when task completes successfully
            on_error: Callback when task fails
            
        Returns:
            List of response dictionaries
        """
        self._on_task_start = on_start
        self._on_task_complete = on_complete
        self._on_task_error = on_error
        
        return await self.scan_urls(urls)
    
    def scan_sync(
        self,
        urls: List[str],
        method: str = "GET",
        payload: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        progress_callback: Optional[Callable] = None,
    ) -> List[Dict]:
        """Synchronous wrapper for scan_urls"""
        return asyncio.run(self.scan_urls(
            urls, method, payload, headers, progress_callback
        ))
    
    def get_stats(self) -> Dict:
        """Get current scanning statistics"""
        return {
            **self.stats,
            'cache_size': len(self._cache),
            'circuit_breaker_open_hosts': len(self._circuit_open),
        }
    
    def clear_cache(self):
        """Clear the result cache"""
        self._cache.clear()
    
    def reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'cached_responses': 0,
            'retries': 0,
            'circuit_breaks': 0,
        }


class PriorityAsyncScanner(AsyncScanner):
    """
    Extended AsyncScanner with priority queue support.
    
    Allows prioritizing certain URLs over others based on score or criteria.
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._priority_queue: asyncio.PriorityQueue = None
    
    async def scan_with_priority(
        self,
        url_priorities: List[Tuple[str, float]],
        method: str = "GET",
        payload: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> List[Dict]:
        """
        Scan URLs in priority order (higher priority first).
        
        Args:
            url_priorities: List of (url, priority) tuples
            
        Returns:
            List of response dictionaries
        """
        # Sort by priority (descending)
        sorted_urls = sorted(url_priorities, key=lambda x: x[1], reverse=True)
        urls = [url for url, _ in sorted_urls]
        
        return await self.scan_urls(urls, method, payload, headers)


async def parallel_scan(
    urls: List[str],
    max_workers: int = 50,
    rate_limit: float = 100.0,
    timeout: int = 30,
    **kwargs
) -> List[Dict]:
    """
    Convenience function for parallel scanning.
    
    Args:
        urls: List of URLs to scan
        max_workers: Maximum concurrent requests
        rate_limit: Requests per second limit
        timeout: Request timeout in seconds
        **kwargs: Additional arguments passed to AsyncScanner
        
    Returns:
        List of response dictionaries
    """
    scanner = AsyncScanner(
        max_concurrent=max_workers,
        rate_limit=rate_limit,
        timeout=timeout,
        **kwargs
    )
    return await scanner.scan_urls(urls)


def sync_parallel_scan(
    urls: List[str],
    max_workers: int = 50,
    rate_limit: float = 100.0,
    timeout: int = 30,
    **kwargs
) -> List[Dict]:
    """Synchronous wrapper for parallel_scan"""
    return asyncio.run(parallel_scan(
        urls, max_workers, rate_limit, timeout, **kwargs
    ))