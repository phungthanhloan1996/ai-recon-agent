"""
core/http_engine.py - HTTP Engine
Core network layer with connection pooling, retries, and rate limiting
"""

import requests
import logging
import time
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import HeaderParsingError, NameResolutionError
import random
import config
import urllib3
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

    def __init__(self, session_manager=None, timeout: int = None, max_retries: int = 3):
        self.session = requests.Session()
        self.timeout = timeout or config.HTTP_TIMEOUT
        self.max_retries = max_retries
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
            total=max_retries,  # Retry up to 3 times
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
        
        # Check cache for unreachable ports - fail fast
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or ""
        if host in self._dead_hosts:
            error = ConnectionError(f"Skipping dead host: {host}")
            logger.debug(f"[HTTP] {error}")
            raise error
        host_port = (parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
        if host_port in self.unreachable_ports:
            error = ConnectionError(f"Port {host_port[1]} on {host_port[0]} is unreachable (cached)")
            logger.debug(f"[HTTP] Skipping unreachable {url}: {error}")
            raise error
        
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('verify', config.SSL_VERIFY)
        
        try:
            response = self.session.get(url, **kwargs)
            self._clear_dead_host_error(host)
            self._handle_rate_limit_response(response, url)
            self._update_session(response)
            return response
        except ConnectionError as e:
            if self._is_name_resolution_error(e):
                self._record_dead_host_error(host)
                logger.error(f"GET request failed for {url}: {e}")
                raise
            # Cache connection refused errors
            if 'Connection refused' in str(e):
                self.unreachable_ports.add(host_port)
                logger.debug(f"[HTTP] Cached unreachable: {host_port}")
            
            # FALLBACK HTTPS -> HTTP for SSL errors
            if 'SSL' in str(e) and url.startswith('https://'):
                http_url = url.replace('https://', 'http://', 1)
                logger.warning(f"[HTTP] SSL failed, retrying with HTTP: {http_url}")
                try:
                    response = self.session.get(http_url, **kwargs)
                    self._update_session(response)
                    return response
                except Exception as e2:
                    logger.error(f"GET request failed for {http_url}: {e2}")
                    raise e2
            
            logger.error(f"GET request failed for {url}: {e}")
            raise
        except HeaderParsingError as e:
            logger.warning(f"Failed to parse headers (url={url}): {e}")
            try:
                response = self.session.get(url, **kwargs)
                self._clear_dead_host_error(host)
                self._update_session(response)
                return response
            except Exception as e2:
                logger.error(f"GET request failed for {url}: {e2}")
                raise e2
        except Exception as e:
            if self._is_name_resolution_error(e):
                self._record_dead_host_error(host)
            logger.error(f"GET request failed for {url}: {e}")
            raise

    def post(self, url: str, data=None, json=None, **kwargs) -> requests.Response:
        """Make POST request"""
        self._rate_limit()
        self._rotate_headers()
        
        # Normalize URL for localhost - skip HTTPS
        url = self._normalize_url(url)
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or ""
        if host in self._dead_hosts:
            raise ConnectionError(f"Skipping dead host: {host}")
        
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', config.SSL_VERIFY)
        
        try:
            response = self.session.post(url, data=data, json=json, **kwargs)
            self._clear_dead_host_error(host)
            self._handle_rate_limit_response(response, url)
            self._update_session(response)
            return response
        except Exception as e:
            if self._is_name_resolution_error(e):
                self._record_dead_host_error(host)
            logger.error(f"POST request failed for {url}: {e}")
            raise

    def _record_dead_host_error(self, host: str):
        if not host:
            return
        self._dead_host_errors[host] = self._dead_host_errors.get(host, 0) + 1
        if self._dead_host_errors[host] >= 3 and host not in self._dead_hosts:
            self._dead_hosts.add(host)
            logger.warning(f"[HTTP] Marking {host} as dead after 3 failures")

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
            sleep_for = min(self.max_delay, self.min_delay * (1 + self.error_count))
            if retry_after:
                try:
                    sleep_for = max(sleep_for, float(retry_after))
                except ValueError:
                    pass
            self.min_delay = min(self.max_delay, max(self.min_delay, sleep_for))
            logger.warning(f"[HTTP] 429 received for {url}; increasing min_delay to {self.min_delay:.2f}s")
            time.sleep(sleep_for)
        elif self.error_count:
            self.error_count = 0
            self.min_delay = max(config.HTTP_MIN_DELAY, self.min_delay * 0.9)

    def _normalize_url(self, url: str) -> str:
        """
        Normalize URL for specific hosts.
        Skip HTTPS for localhost entirely to avoid SSL errors.
        """
        if not url:
            return url
        
        # Extract host from URL
        parsed = urlparse(url)
        host = parsed.hostname or ''
        
        # Skip HTTPS for localhost - use HTTP only
        if host in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
            if url.startswith('https://'):
                # Replace https:// with http://
                url = url.replace('https://', 'http://', 1)
                return url
        
        # Check cache for non-localhost hosts
        if host in self.scheme_cache:
            preferred_scheme = self.scheme_cache[host]
            if parsed.scheme != preferred_scheme:
                url = url.replace(f'{parsed.scheme}://', f'{preferred_scheme}://', 1)
        
        return url

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

    def close(self):
        """Close the session"""
        self.session.close()
