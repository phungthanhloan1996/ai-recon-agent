"""
modules/idor_detector.py - Insecure Direct Object Reference
Horizontal privilege escalation detection
"""

import json
import logging
from typing import Dict, List, Any, Optional, Callable
import re

from core.http_engine import HTTPClient

logger = logging.getLogger("recon.idor")


class IDORDetector:
    """IDOR detection - user enumeration + access bypass"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/idor_findings.json"
    
    def detect(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """Detect IDOR vulnerabilities"""
        result = {
            'url': url,
            'tool': 'idor_detector',
            'type': 'idor_vulns',
            'user_enumerations': [],
            'access_bypasses': [],
            'endpoints_tested': 0
        }
        
        if progress_cb:
            progress_cb('idor', 'idor_detector', 'Testing IDOR...')
        
        logger.info(f"[IDOR] Scanning {url}")
        
        # Test user enumeration
        users = self._test_user_enumeration(url)
        result['user_enumerations'] = users
        
        if progress_cb:
            progress_cb('idor', 'idor_detector', f'Found {len(users)} users')
        
        # Test parameter-based IDOR
        idors = self._test_parameter_idor(url)
        result['access_bypasses'] = idors
        result['endpoints_tested'] = len(idors)
        
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[IDOR] Error saving: {e}")
        
        if progress_cb:
            total = len(users) + len(idors)
            progress_cb('idor', 'idor_detector', f'Found {total} IDOR issues')
        
        return result
    
    def _test_user_enumeration(self, url: str) -> List[Dict]:
        """Detect user enumeration vectors"""
        users = []
        
        # Common endpoints for user enumeration
        endpoints = [
            '/wp-json/wp/v2/users',  # WordPress REST API
            '/api/users',
            '/admin/users',
            '/user/list',
            '/users',
            '/author',
            '/profile',
        ]
        
        for endpoint in endpoints:
            try:
                test_url = url.rstrip('/') + endpoint
                resp = self.http_client.get(test_url, timeout=self.timeout)
                
                if resp.status_code in [200, 201]:
                    # Extract user info
                    user_info = self._extract_users_from_response(resp.text)
                    if user_info:
                        users.append({
                            'endpoint': endpoint,
                            'method': 'GET',
                            'user_count': len(user_info),
                            'users': user_info[:10]  # First 10
                        })
                        logger.info(f"[IDOR] User enumeration at {endpoint}: {len(user_info)} users")
            
            except Exception as e:
                logger.debug(f"[IDOR] User enum test failed: {e}")
        
        return users
    
    def _test_parameter_idor(self, url: str) -> List[Dict]:
        """Test for parameter-based IDOR (ID tampering)"""
        idors = []
        
        try:
            # Get baseline response with ID=1
            test_url = f"{url}?id=1"
            resp1 = self.http_client.get(test_url, timeout=self.timeout)
            
            # Try other IDs
            for test_id in [2, 10, 99, 100, 999]:
                try:
                    test_url_alt = f"{url}?id={test_id}"
                    resp_alt = self.http_client.get(test_url_alt, timeout=self.timeout)
                    
                    # If we get different successful responses, likely IDOR
                    if resp_alt.status_code == 200 and resp1.text != resp_alt.text:
                        idors.append({
                            'parameter': 'id',
                            'type': 'direct_object_reference',
                            'tested_ids': [1, test_id],
                            'response_different': True,
                            'confidence': 'high'
                        })
                        logger.info(f"[IDOR] Direct object reference found via ID parameter")
                        break
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"[IDOR] Parameter test failed: {e}")
        
        # Test other numeric parameters
        numeric_params = ['uid', 'user_id', 'user', 'profile_id', 'post_id', 'article_id']
        for param in numeric_params:
            try:
                test_url1 = f"{url}?{param}=1"
                test_url2 = f"{url}?{param}=2"
                
                resp1 = self.http_client.get(test_url1, timeout=self.timeout)
                resp2 = self.http_client.get(test_url2, timeout=self.timeout)
                
                if resp1.status_code == 200 and resp2.status_code == 200 and resp1.text != resp2.text:
                    idors.append({
                        'parameter': param,
                        'type': 'direct_object_reference',
                        'confidence': 'high'
                    })
                    logger.info(f"[IDOR] Found on parameter: {param}")
            
            except:
                pass
        
        return idors
    
    def _extract_users_from_response(self, response_text: str) -> List[str]:
        """Extract user info from API response"""
        users = []
        
        # JSON-based usernames
        username_patterns = [
            r'"username"\s*:\s*"([^"]+)"',
            r'"user"\s*:\s*"([^"]+)"',
            r'"name"\s*:\s*"([^"]+)"',
            r'"login"\s*:\s*"([^"]+)"',
            r'"email"\s*:\s*"([^"]+)"',
        ]
        
        for pattern in username_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            users.extend(matches)
        
        # Remove duplicates
        return list(set(users))
