"""
core/tor_engine.py - Tor HTTP Engine
Provides Tor proxy integration for anonymous scanning.
"""

import requests
import logging
import config
from typing import Optional

logger = logging.getLogger("recon.tor_engine")


class TorHTTPEngine:
    """
    HTTP client that routes traffic through Tor network.
    Provides anonymity for scanning operations.
    """
    
    def __init__(self, proxy_url: str = None):
        """
        Initialize Tor HTTP Engine.
        
        Args:
            proxy_url: SOCKS proxy URL (default: from config.TOR_PROXY_URL)
        """
        self.proxy_url = proxy_url or config.TOR_PROXY_URL
        self.session = requests.Session()
        self._setup_proxy()
        self._setup_headers()
        
    def _setup_proxy(self):
        """Configure session to use Tor proxy."""
        self.session.proxies = {
            'http': self.proxy_url,
            'https': self.proxy_url
        }
        logger.debug(f"[TOR] Proxy configured: {self.proxy_url}")
    
    def _setup_headers(self):
        """Set default headers."""
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
    
    def get(self, url: str, timeout: int = 30, **kwargs) -> requests.Response:
        """Make GET request through Tor."""
        kwargs.setdefault('timeout', timeout)
        kwargs.setdefault('allow_redirects', True)
        kwargs.setdefault('verify', config.SSL_VERIFY)
        
        try:
            response = self.session.get(url, **kwargs)
            return response
        except Exception as e:
            logger.error(f"[TOR] GET request failed for {url}: {e}")
            raise
    
    def post(self, url: str, data=None, json=None, timeout: int = 30, **kwargs) -> requests.Response:
        """Make POST request through Tor."""
        kwargs.setdefault('timeout', timeout)
        kwargs.setdefault('verify', config.SSL_VERIFY)
        
        try:
            response = self.session.post(url, data=data, json=json, **kwargs)
            return response
        except Exception as e:
            logger.error(f"[TOR] POST request failed for {url}: {e}")
            raise
    
    def new_identity(self) -> bool:
        """
        Request a new Tor identity (circuit).
        Requires Tor control port authentication.
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            import stem
            from stem.control import Controller
            
            controller = Controller.from_port(port=config.TOR_CONTROL_PORT)
            controller.authenticate()
            controller.signal(stem.Signal.NEWNYM)
            controller.close()
            
            logger.info("[TOR] New identity requested")
            return True
        except ImportError:
            logger.warning("[TOR] stem library not installed, cannot rotate identity")
            return False
        except Exception as e:
            logger.error(f"[TOR] Failed to get new identity: {e}")
            return False
    
    def check_tor_status(self) -> dict:
        """
        Check if Tor is working and get current IP.
        
        Returns:
            dict with tor_status and ip_address
        """
        try:
            # Check Tor status by requesting check.torproject.org
            response = self.session.get('https://check.torproject.org/api/ip', timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'tor_status': 'connected' if data.get('IsTor', False) else 'not_tor',
                    'ip_address': data.get('IP', 'unknown')
                }
            return {'tor_status': 'error', 'ip_address': 'unknown'}
        except Exception as e:
            logger.error(f"[TOR] Failed to check Tor status: {e}")
            return {'tor_status': 'error', 'ip_address': 'unknown'}
    
    def close(self):
        """Close the session."""
        self.session.close()


def get_http_client(use_tor: bool = False):
    """
    Factory function to get appropriate HTTP client.
    
    Args:
        use_tor: If True, return TorHTTPEngine; otherwise return standard HTTPClient
        
    Returns:
        HTTPClient or TorHTTPEngine instance
    """
    if use_tor or config.TOR_ENABLED:
        logger.info("[TOR] Using Tor HTTP Engine")
        return TorHTTPEngine()
    else:
        from core.http_engine import HTTPClient
        return HTTPClient()