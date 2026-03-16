"""
core/http_engine.py - HTTP Engine
Core network layer with connection pooling, retries, and rate limiting
"""

import requests
import logging
import time
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import HeaderParsingError
import random
from config import SSL_VERIFY
import urllib3
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

    def __init__(self, session_manager=None, timeout: int = 30, max_retries: int = 3):
        self.session = requests.Session()
        self.timeout = timeout
        self.max_retries = max_retries
        self.session_manager = session_manager
        self.last_request_time = 0
        self.min_delay = 1  # Minimum delay between requests

        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            backoff_factor=1
        )

        # Mount adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
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
        
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('verify', SSL_VERIFY)
        
        try:
            response = self.session.get(url, **kwargs)
            self._update_session(response)
            return response
        except HeaderParsingError as e:
            logger.warning(f"Failed to parse headers (url={url}): {e}")
            # Try to get response anyway by making a raw request
            try:
                response = self.session.get(url, **kwargs)
                self._update_session(response)
                return response
            except Exception as e2:
                logger.error(f"GET request failed for {url}: {e2}")
                raise e2
        except Exception as e:
            logger.error(f"GET request failed for {url}: {e}")
            raise

    def post(self, url: str, data=None, json=None, **kwargs) -> requests.Response:
        """Make POST request"""
        self._rate_limit()
        self._rotate_headers()
        
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', SSL_VERIFY)
        
        try:
            response = self.session.post(url, data=data, json=json, **kwargs)
            self._update_session(response)
            return response
        except Exception as e:
            logger.error(f"POST request failed for {url}: {e}")
            raise

    def _rate_limit(self):
        """Implement rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_delay:
            time.sleep(self.min_delay - elapsed)
        self.last_request_time = time.time()

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