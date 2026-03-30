"""
modules/api_vuln_scanner.py - API Vulnerability Detection
Broken authentication, rate limiting, input validation, etc.
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urljoin, parse_qs, urlparse

from core.http_engine import HTTPClient

logger = logging.getLogger("recon.api_vuln")


class APIVulnScanner:
    """Scan APIs for common vulnerabilities"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/api_vuln_findings.json"
    
    def scan(
        self,
        url: str,
        endpoints: Optional[List[str]] = None,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """Scan API endpoints for vulnerabilities"""
        result = {
            'url': url,
            'tool': 'api_vuln_scanner',
            'type': 'api_vulnerabilities',
            'endpoints_tested': 0,
            'vulnerabilities': [],
            'rate_limiting': None,
            'auth_bypass': [],
            'sensitive_data': []
        }
        
        if progress_cb:
            progress_cb('api_vuln_scanner', 'api_scanner', 'Scanning API vulnerabilities...')
        
        logger.info(f"[API_VULN] Scanning {url}")
        
        if not endpoints:
            endpoints = self._discover_api_endpoints(url)
        
        result['endpoints_tested'] = len(endpoints)
        
        for endpoint in endpoints:
            try:
                if progress_cb:
                    progress_cb('api_vuln_scanner', 'api_scanner', f'Testing {endpoint}...')
                
                # Test for authentication bypass
                auth_bypass = self._test_auth_bypass(url, endpoint)
                if auth_bypass:
                    result['auth_bypass'].append(auth_bypass)
                
                # Test for rate limiting
                rate_limit = self._test_rate_limiting(url, endpoint)
                if rate_limit and not result['rate_limiting']:
                    result['rate_limiting'] = rate_limit
                
                # Test for sensitive data exposure
                sensitive = self._test_sensitive_data(url, endpoint)
                if sensitive:
                    result['sensitive_data'].extend(sensitive)
                
                # Test for input validation
                input_vuln = self._test_input_validation(url, endpoint)
                if input_vuln:
                    result['vulnerabilities'].extend(input_vuln)
            
            except Exception as e:
                logger.debug(f"[API_VULN] Error testing {endpoint}: {e}")
        
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[API_VULN] Error saving: {e}")
        
        if progress_cb:
            vuln_count = len(result['vulnerabilities'])
            progress_cb('api_vuln_scanner', 'api_scanner', f'Found {vuln_count} API issues')
        
        return result
    
    def _discover_api_endpoints(self, url: str) -> List[str]:
        """Discover API endpoints"""
        endpoints = []
        
        common_paths = [
            '/api',
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/rest',
            '/rest/api',
            '/graphql',
            '/swagger',
            '/swagger.json',
            '/openapi.json',
            '/docs',
            '/api-docs',
        ]
        
        for path in common_paths:
            try:
                test_url = urljoin(url, path)
                resp = self.http_client.get(test_url, timeout=self.timeout)
                
                if resp.status_code in [200, 401]:
                    endpoints.append(path)
                    logger.info(f"[API_VULN] Discovered: {path}")
            except:
                pass
        
        return endpoints
    
    def _test_auth_bypass(self, url: str, endpoint: str) -> Optional[Dict]:
        """Test for authentication bypass"""
        try:
            api_url = urljoin(url, endpoint)
            
            # Test without headers
            resp1 = self.http_client.get(api_url, timeout=self.timeout)
            
            # Test with empty auth
            resp2 = self.http_client.get(
                api_url,
                headers={'Authorization': ''},
                timeout=self.timeout
            )
            
            # Test with fake token
            resp3 = self.http_client.get(
                api_url,
                headers={'Authorization': 'Bearer fake_token'},
                timeout=self.timeout
            )
            
            # If we get data without auth, it's vulnerable
            if resp1.status_code == 200 and len(resp1.text) > 50:
                if any(k in resp1.text.lower() for k in ['id', 'name', 'email', 'user']):
                    return {
                        'endpoint': endpoint,
                        'type': 'authentication_bypass',
                        'severity': 'critical',
                        'description': 'API returns data without authentication'
                    }
        
        except Exception as e:
            logger.debug(f"[API_VULN] Auth bypass test failed: {e}")
        
        return None
    
    def _test_rate_limiting(self, url: str, endpoint: str) -> Optional[Dict]:
        """Test for rate limiting"""
        try:
            api_url = urljoin(url, endpoint)
            
            # Send multiple requests quickly
            status_codes = []
            for i in range(10):
                resp = self.http_client.get(api_url, timeout=self.timeout)
                status_codes.append(resp.status_code)
            
            # Check if we got rate limited
            if 429 in status_codes or 503 in status_codes:
                return {
                    'endpoint': endpoint,
                    'type': 'rate_limiting',
                    'severity': 'info',
                    'description': 'Rate limiting is enabled (429/503 returned)'
                }
            
            # No rate limiting detected
            if status_codes.count(200) == 10:
                return {
                    'endpoint': endpoint,
                    'type': 'no_rate_limiting',
                    'severity': 'medium',
                    'description': 'No rate limiting detected - vulnerable to brute force'
                }
        
        except Exception as e:
            logger.debug(f"[API_VULN] Rate limiting test failed: {e}")
        
        return None
    
    def _test_sensitive_data(self, url: str, endpoint: str) -> List[Dict]:
        """Test for sensitive data exposure"""
        sensitive_data = []
        
        try:
            api_url = urljoin(url, endpoint)
            resp = self.http_client.get(api_url, timeout=self.timeout)
            
            # Check for sensitive patterns
            sensitive_patterns = {
                'password': r'(?i)(password|pwd|pass)[\s]*[=:]\s*["\']?[^"\'\s]+',
                'api_key': r'(?i)(api[_-]?key|apikey|api_token|token)[\s]*[=:]\s*["\']?[a-zA-Z0-9]+',
                'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
                'private_key': r'-----BEGIN (.+?) PRIVATE KEY-----',
                'database_uri': r'(mongodb|mysql|postgres|redis)://[^\s]+'
            }
            
            import re
            for data_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, resp.text)
                if matches:
                    sensitive_data.append({
                        'endpoint': endpoint,
                        'type': f'sensitive_data_exposure_{data_type}',
                        'severity': 'high',
                        'description': f'Found exposed {data_type} in response',
                        'count': len(matches)
                    })
        
        except Exception as e:
            logger.debug(f"[API_VULN] Sensitive data test failed: {e}")
        
        return sensitive_data
    
    def _test_input_validation(self, url: str, endpoint: str) -> List[Dict]:
        """Test for input validation issues"""
        vulns = []
        
        try:
            api_url = urljoin(url, endpoint)
            
            # Test for SQLi
            sqli_payload = "' OR '1'='1"
            resp = self.http_client.get(
                api_url,
                params={'q': sqli_payload},
                timeout=self.timeout
            )
            
            if 'error' in resp.text.lower() and 'sql' in resp.text.lower():
                vulns.append({
                    'endpoint': endpoint,
                    'type': 'sql_injection',
                    'severity': 'critical',
                    'description': 'API error messages reveal SQL injection possibility'
                })
            
            # Test for XSS
            xss_payload = '<img src=x onerror=alert(1)>'
            resp = self.http_client.get(
                api_url,
                params={'q': xss_payload},
                timeout=self.timeout
            )
            
            if xss_payload in resp.text:
                vulns.append({
                    'endpoint': endpoint,
                    'type': 'xss',
                    'severity': 'high',
                    'description': 'API reflects user input without encoding'
                })
            
            # Test for XXE
            xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            resp = self.http_client.post(
                api_url,
                data=xxe_payload,
                timeout=self.timeout
            )
            
            if 'root:' in resp.text:
                vulns.append({
                    'endpoint': endpoint,
                    'type': 'xxe',
                    'severity': 'critical',
                    'description': 'API is vulnerable to XML External Entity attacks'
                })
        
        except Exception as e:
            logger.debug(f"[API_VULN] Input validation test failed: {e}")
        
        return vulns
