"""
core/url_normalizer_enhanced.py - Enhanced URL Normalization
Comprehensive URL validation, scheme handling, and redirect following
"""

import re
import logging
from typing import Tuple, Optional
from urllib.parse import urlparse, urljoin
import requests

logger = logging.getLogger("recon.url_normalizer")


class URLNormalizer:
    """
    Advanced URL normalization with:
    - Scheme validation and auto-prepending
    - Redirect following (301/302/307)
    - Domain/subdomain validation
    - Path normalization
    """

    # Common TLDs for basic validation
    COMMON_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'uk',
        'us', 'de', 'fr', 'it', 'es', 'br', 'cn', 'in', 'jp', 'au', 've',
        'vn', 'ru', 'ae', 'za', 'mx', 'pk', 'sg', 'hk', 'tw', 'kr', 'th',
        'id', 'ph', 'my', 'nz', 'nl', 'be', 'ch', 'at', 'se', 'no', 'dk',
        'fi', 'pl', 'cz', 'gr', 'pt', 'ie', 'info', 'biz', 'name', 'mobi'
    }

    @staticmethod
    def normalize(url: str, follow_redirects: bool = True, timeout: int = 5) -> Tuple[str, bool, str]:
        """
        Normalize URL to valid scheme://domain format
        
        Returns:
            (normalized_url, is_valid, error_message)
        """
        if not url or not isinstance(url, str):
            return "", False, "Invalid URL: empty or not string"

        url = url.strip().lower()

        # Step 1: Detect and fix missing scheme
        if not url.startswith(('http://', 'https://')):
            # Check if it looks like a domain
            if URLNormalizer._looks_like_domain(url):
                url = f"https://{url}"
            else:
                return "", False, "No scheme supplied and not recognizable as domain"

        # Step 2: Parse and validate
        try:
            parsed = urlparse(url)
        except Exception as e:
            return "", False, f"Failed to parse URL: {str(e)[:30]}"

        # Step 3: Validate scheme
        if parsed.scheme not in ('http', 'https'):
            return "", False, f"Invalid scheme: {parsed.scheme}"

        # Step 4: Validate netloc (domain)
        if not parsed.netloc:
            return "", False, "Missing domain/netloc"

        # Step 5: Normalize to base URL (domain + scheme only)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Step 6: Follow redirects if requested
        if follow_redirects:
            final_url, redirect_chain = URLNormalizer._follow_redirects(base_url, timeout)
            if final_url:
                base_url = final_url
                if len(redirect_chain) > 1:
                    logger.info(f"Followed {len(redirect_chain)-1} redirect(s): {' -> '.join(redirect_chain[:3])}")

        # Step 7: Validate final URL works
        is_alive = URLNormalizer._check_url_alive(base_url, timeout)
        if not is_alive:
            return "", False, f"URL does not respond: {base_url}"

        return base_url, True, ""

    @staticmethod
    def normalize_endpoint(base_url: str, path: str) -> str:
        """
        Normalize endpoint URL (base + path)
        """
        if not base_url:
            return ""
        
        # Ensure base_url has scheme
        if not base_url.startswith(('http://', 'https://')):
            base_url = f"https://{base_url}"
        
        # Clean path
        if path:
            path = path.lstrip('/')
            return f"{base_url}/{path}"
        return base_url

    @staticmethod
    def _looks_like_domain(text: str) -> bool:
        """Check if text looks like a valid domain"""
        # Remove common schemes if present
        text = text.replace('http://', '').replace('https://', '').strip()
        
        # Basic domain pattern: name.tld or subdomain.name.tld
        domain_pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$'
        
        if not re.match(domain_pattern, text):
            return False
        
        # Check if TLD is recognized
        parts = text.split('.')
        if parts and parts[-1] in URLNormalizer.COMMON_TLDS:
            return True
        
        # Also accept any 2-letter country code-like TLDs
        if len(parts[-1]) == 2 and parts[-1].isalpha():
            return True
        
        return False

    @staticmethod
    def _follow_redirects(url: str, timeout: int = 5, max_redirects: int = 5) -> Tuple[str, list]:
        """
        Follow 301/302/307 redirects
        Returns: (final_url, redirect_chain)
        """
        redirect_chain = [url]
        current = url
        
        for i in range(max_redirects):
            try:
                resp = requests.head(current, timeout=timeout, allow_redirects=False, verify=False)
                
                if resp.status_code in (301, 302, 307, 308):
                    location = resp.headers.get('Location')
                    if location:
                        # Handle relative redirects
                        if location.startswith('/'):
                            parsed = urlparse(current)
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"
                        
                        redirect_chain.append(location)
                        current = location
                    else:
                        break
                else:
                    break
            except Exception:
                break
        
        return current, redirect_chain

    @staticmethod
    def _check_url_alive(url: str, timeout: int = 5) -> bool:
        """
        Check if URL is reachable
        """
        try:
            resp = requests.head(url, timeout=timeout, allow_redirects=True, verify=False)
            return resp.status_code < 500
        except Exception:
            # Try GET if HEAD fails
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, stream=True)
                return resp.status_code < 500
            except Exception:
                return False

    @staticmethod
    def prepend_scheme(url: str) -> str:
        """Simple scheme prepending"""
        if not url.startswith(('http://', 'https://')):
            return f"https://{url}"
        return url
