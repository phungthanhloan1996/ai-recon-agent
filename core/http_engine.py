"""
core/http_engine.py - HTTP Engine
Core network layer with connection pooling, retries, and rate limiting
"""

import requests
import logging
import time
import threading
from requests.exceptions import ConnectTimeout, ConnectionError as RequestsConnectionError, ReadTimeout
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import HeaderParsingError, NameResolutionError
import random
import config
import urllib3
from urllib.parse import urlparse
import ipaddress
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.scan_optimizer import get_optimizer

logger = logging.getLogger("recon.http_engine")


class HTTPClient:
    """
    HTTP client with advanced features:
    - Connection pooling
    - Retry strategy
    - Header rotation
    - Rate limiting
    - Proxy support
    """

    def __init__(self, session_manager=None, timeout: int = None, max_retries: int = 1):
        self.session = requests.Session()
        self.base_timeout = timeout or config.HTTP_TIMEOUT

        # AGGRESSIVE timeout profiles - ULTRA fast fail-fast
        # FIXED: Ensure all timeout values are proper int/float types
        self.timeouts = {
            "fast": float(max(2, int(self.base_timeout) - 3)),   # 5s (ultra-aggressive)
            "normal": float(max(3, int(int(self.base_timeout) * 0.8))),  # 8s (aggressive)
            "slow": float(max(5, int(int(self.base_timeout) * 1.5))),  # 15s (was 30s)
            "exploit": float(max(8, int(int(self.base_timeout) * 2))),  # 20s (was 50s)
            "connect": float(3)  # Connection timeout (ultra-aggressive)
        }
        self.max_retries = max_retries  # AGGRESSIVE: only 1 retry
        self.session_manager = session_manager
        self.last_request_time = 0
        self.min_delay = config.HTTP_MIN_DELAY
        self.max_delay = config.HTTP_MAX_DELAY
        self.scheme_cache = {}
        self.unreachable_ports = set()
        self.error_count = 0  # Track consecutive errors
        self.current_concurrency = config.HTTP_POOL_SIZE
        self._rate_lock = threading.Lock()
        self._dead_hosts = set()
        self._dead_host_errors = {}

        # ENHANCED: Connection pool of 50, with exponential backoff
        retry_strategy = Retry(
            total=max_retries,
            connect=0,
            read=0,
            redirect=0,
            other=0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            backoff_factor=config.HTTP_BACKOFF_FACTOR,
            respect_retry_after_header=True,
            raise_on_status=False
        )

        # Mount adapters with larger pool
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=config.HTTP_POOL_SIZE,
            pool_maxsize=config.HTTP_POOL_SIZE
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False

        # Default headers
        self.session.headers.update({
            'User-Agent': self._get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

    def get(self, url: str, **kwargs) -> requests.Response:
        """Make GET request with rate limiting and header rotation"""
        self._rate_limit()
        self._rotate_headers()
        
        # Normalize URL for localhost - skip HTTPS
        url = self._normalize_url(url)
        is_valid, msg = self._validate_url(url)
        if not is_valid:
            logger.warning(f"[HTTP] Skipping invalid URL: {msg}")
            raise ValueError(f"Invalid URL: {msg}")
        
        # Check if host is blacklisted by optimizer - fail fast
        parsed = urlparse(url)
        host = parsed.hostname or parsed.netloc or ""
        
        optimizer = get_optimizer()
        if optimizer.is_host_blacklisted(host):
            error = ConnectionError(f"Skipping blacklisted host: {host}")
            logger.debug(f"[HTTP] {error}")
            raise error
        
        # Check cache for unreachable ports - fail fast
        if host in self._dead_hosts:
            error = ConnectionError(f"Skipping dead host: {host}")
            logger.debug(f"[HTTP] {error}")
            raise error
        host_port = (parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
        if host_port in self.unreachable_ports:
            error = ConnectionError(f"Port {host_port[1]} on {host_port[0]} is unreachable (cached)")
            logger.debug(f"[HTTP] Skipping unreachable {url}: {error}")
            raise error
        
        # Get optimized timeout from optimizer based on host history
        optimizer = get_optimizer()
        host = parsed.hostname or ""
        optimized_timeout = optimizer.get_optimized_timeout(host, "connection")
        
        # Use the smaller of optimized timeout and mode-based timeout
        timeout_mode = kwargs.pop("timeout_mode", "normal")
        mode_timeout = self.timeouts.get(timeout_mode, self.base_timeout)
        timeout_value = min(optimized_timeout, mode_timeout)

        kwargs.setdefault('timeout', timeout_value)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('verify', config.SSL_VERIFY)
        
        try:
            response = self.session.get(url, **kwargs)
            self._clear_dead_host_error(host)
            self._handle_rate_limit_response(response, url)
            self._update_session(response)
            return response
        except (ConnectionError, RequestsConnectionError) as e:
            if self._is_name_resolution_error(e):
                self._record_dead_host_error(host, hard=True)
                logger.debug(f"[HTTP] Connection failed for {url}: {e}")
                raise
            # Cache connection refused errors
            if 'Connection refused' in str(e):
                self.unreachable_ports.add(host_port)
                logger.debug(f"[HTTP] Cached unreachable: {host_port}")
            
            # FALLBACK HTTPS -> HTTP for SSL errors
            if 'SSL' in str(e) and url.startswith('https://'):
                http_url = url.replace('https://', 'http://', 1)
                logger.debug(f"[HTTP] SSL failed, retrying with HTTP: {http_url}")
                try:
                    response = self.session.get(http_url, **kwargs)
                    self._update_session(response)
                    return response
                except Exception as e2:
                    logger.debug(f"[HTTP] Connection failed for {http_url}: {e2}")
                    raise e2
            
            logger.debug(f"[HTTP] Connection failed for {url}: {e}")
            raise
        except (ReadTimeout, ConnectTimeout) as e:
            logger.debug(f"[HTTP] Request timed out for {url}: {e}")
            raise
        except HeaderParsingError as e:
            logger.debug(f"[HTTP] Failed to parse headers (url={url}): {e}")
            try:
                response = self.session.get(url, **kwargs)
                self._clear_dead_host_error(host)
                self._update_session(response)
                return response
            except Exception as e2:
                logger.debug(f"[HTTP] Request failed for {url}: {e2}")
                raise e2
        except Exception as e:
            if self._is_name_resolution_error(e):
                self._record_dead_host_error(host, hard=True)
            logger.debug(f"[HTTP] Request failed for {url}: {e}")
            raise

    def post(self, url: str, data=None, json=None, **kwargs) -> requests.Response:
        """Make POST request"""
        self._rate_limit()
        self._rotate_headers()
        
        # Normalize URL for localhost - skip HTTPS
        url = self._normalize_url(url)
        is_valid, msg = self._validate_url(url)
        if not is_valid:
            logger.warning(f"[HTTP] Skipping invalid URL: {msg}")
            raise ValueError(f"Invalid URL: {msg}")
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or ""
        if host in self._dead_hosts:
            raise ConnectionError(f"Skipping dead host: {host}")
        
        timeout_mode = kwargs.pop("timeout_mode", "normal")
        timeout_value = self.timeouts.get(timeout_mode, self.base_timeout)

        kwargs.setdefault('timeout', timeout_value)
        kwargs.setdefault('verify', config.SSL_VERIFY)
        
        try:
            response = self.session.post(url, data=data, json=json, **kwargs)
            self._clear_dead_host_error(host)
            self._handle_rate_limit_response(response, url)
            self._update_session(response)
            return response
        except (ReadTimeout, ConnectTimeout) as e:
            logger.debug(f"[HTTP] POST request timed out for {url}: {e}")
            raise
        except Exception as e:
            if self._is_name_resolution_error(e):
                self._record_dead_host_error(host, hard=True)
            logger.debug(f"[HTTP] POST request failed for {url}: {e}")
            raise

    def _record_dead_host_error(self, host: str, hard: bool = False):
        """Track consecutive failures and blacklist host after threshold.
        
        OPTIMIZATION: Uses ScanOptimizer for intelligent blacklisting:
        - DNS errors: blacklist after 1 failure
        - Timeouts: blacklist after 2 failures  
        - Other failures: blacklist after 3 failures
        """
        if not host:
            return
        
        optimizer = get_optimizer()
        
        # Use optimizer for intelligent failure tracking
        if hard:
            optimizer.record_host_failure(host, "DNS resolution failed")
        else:
            optimizer.record_host_failure(host, "connection error")
        
        # Sync with local blacklist if optimizer blacklisted
        if optimizer.is_host_blacklisted(host) and host not in self._dead_hosts:
            self._dead_hosts.add(host)
            status = optimizer.get_host_status(host)
            logger.warning(f"[HTTP] Blacklisting host {host} after {status.failure_count} failures "
                          f"(DNS: {status.dns_error}, Timeouts: {status.connection_timeout})")

    def _clear_dead_host_error(self, host: str):
        if not host:
            return
        self._dead_host_errors.pop(host, None)
        self._dead_hosts.discard(host)

    def _is_name_resolution_error(self, error: Exception) -> bool:
        current = error
        visited = set()
        while current and id(current) not in visited:
            visited.add(id(current))
            if isinstance(current, NameResolutionError):
                return True
            if "name resolution" in str(current).lower() or "failed to resolve" in str(current).lower():
                return True
            current = getattr(current, "__cause__", None) or getattr(current, "__context__", None)
        return False

    def _rate_limit(self):
        """Implement rate limiting"""
        with self._rate_lock:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_delay:
                time.sleep(self.min_delay - elapsed)
            self.last_request_time = time.time()

    def _handle_rate_limit_response(self, response: requests.Response, url: str):
        if response.status_code == 429:
            self.error_count += 1
            retry_after = response.headers.get("Retry-After")
            # Exponential backoff with factor 2.0
            sleep_for = min(self.max_delay, self.min_delay * (2.0 ** self.error_count))
            if retry_after:
                try:
                    sleep_for = max(sleep_for, float(retry_after))
                except ValueError:
                    pass
            self.min_delay = min(self.max_delay, max(self.min_delay, sleep_for))
            logger.warning(f"[HTTP] 429 received for {url}; increasing min_delay to {self.min_delay:.2f}s (attempt {self.error_count})")
            time.sleep(sleep_for)
        elif self.error_count:
            self.error_count = 0
            self.min_delay = max(config.HTTP_MIN_DELAY, self.min_delay * 0.9)

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL for specific hosts.
        Skip HTTPS for local/private hosts entirely to avoid slow TLS failures.
        """
        if not url:
            return url
        
        # Extract host from URL
        parsed = urlparse(url)
        host = parsed.hostname or ''
        
        if config.LOCAL_HTTP_ONLY and self._is_local_or_private_host(host) and url.startswith('https://'):
            url = url.replace('https://', 'http://', 1)
            return url
        
        # Check cache for non-localhost hosts
        if host in self.scheme_cache:
            preferred_scheme = self.scheme_cache[host]
            if parsed.scheme != preferred_scheme:
                url = url.replace(f'{parsed.scheme}://', f'{preferred_scheme}://', 1)
        
        return url

    def _is_local_or_private_host(self, host: str) -> bool:
        host = (host or "").strip().lower()
        if not host:
            return False

        if host in {'localhost', '127.0.0.1', '::1', '0.0.0.0', 'localhost.localdomain'}:
            return True

        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            pass

        if "." not in host:
            return True

        local_suffixes = (".local", ".localhost", ".internal", ".lan", ".home", ".test", ".example", ".invalid")
        return host.endswith(local_suffixes)

    def _validate_url(self, url: str) -> tuple[bool, str]:
        """Validate URL before sending request"""
        if not url:
            return False, "Empty URL"
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False, f"Missing scheme or netloc: {url[:100]}"

            invalid_patterns = ['<', '>', '"', "'", '&lt;', '&gt;', 'script', 'alert']
            netloc_lower = parsed.netloc.lower()
            for pattern in invalid_patterns:
                if pattern in netloc_lower:
                    return False, f"Hostname contains invalid characters: {parsed.netloc}"

            try:
                parsed.port
            except ValueError as e:
                return False, f"Invalid port: {e}"

            if len(url) > config.MAX_URL_LENGTH:
                return False, f"URL too long: {len(url)} chars"

            return True, "OK"
        except Exception as e:
            return False, f"Parse error: {e}"

    def _rotate_headers(self):
        """Rotate user agent and other headers"""
        self.session.headers['User-Agent'] = self._get_random_user_agent()

    def _get_random_user_agent(self) -> str:
        """Get a random user agent string"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15'
        ]
        return random.choice(user_agents)

    def _update_session(self, response: requests.Response):
        """Update session with response data (cookies, etc.)"""
        if self.session_manager:
            self.session_manager.update_from_response(response)

    def set_proxy(self, proxy_url: str):
        """Set proxy for requests"""
        self.session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        logger.info(f"[HTTP] Proxy set to: {proxy_url}")

    def enable_tor(self):
        """Enable Tor proxy for requests."""
        if config.TOR_ENABLED:
            self.set_proxy(config.TOR_PROXY_URL)
            logger.info("[HTTP] Tor proxy enabled")
        else:
            logger.warning("[HTTP] Tor is not enabled in config")

    def disable_tor(self):
        """Disable Tor proxy and use direct connection."""
        self.session.proxies = {}
        logger.info("[HTTP] Tor proxy disabled, using direct connection")

    def close(self):
        """Close the session"""
        self.session.close()
