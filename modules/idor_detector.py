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
        progress_cb: Optional[Callable[[str, str, str], None]] = None,
        sessions: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Detect IDOR vulnerabilities.

        Args:
            url: Target URL
            progress_cb: Optional progress callback
            sessions: List of authenticated session dicts from state.authenticated_sessions.
                      Each dict has keys: role, cookies (dict), headers (dict), success (bool).
                      When provided, IDOR tests are repeated for each session so cross-role
                      access violations (BOLA) can be detected.
        """
        result = {
            'url': url,
            'tool': 'idor_detector',
            'type': 'idor_vulns',
            'user_enumerations': [],
            'access_bypasses': [],
            'endpoints_tested': 0,
            'authenticated_roles_tested': [],
        }

        # Build list of (role_label, cookies, headers) contexts to test
        auth_contexts: List[Dict[str, Any]] = [
            {"role": "anonymous", "cookies": {}, "headers": {}}
        ]
        for sess in (sessions or []):
            if sess.get("success"):
                auth_contexts.append({
                    "role": sess.get("role", "unknown"),
                    "cookies": sess.get("cookies") or {},
                    "headers": sess.get("headers") or {},
                })
        result['authenticated_roles_tested'] = [c["role"] for c in auth_contexts]

        if progress_cb:
            progress_cb('idor', 'idor_detector', f'Testing IDOR ({len(auth_contexts)} roles)...')

        logger.info(f"[IDOR] Scanning {url} with {len(auth_contexts)} auth contexts")

        # Test user enumeration (anonymous first, then each authed role)
        for ctx in auth_contexts:
            users = self._test_user_enumeration(url, cookies=ctx["cookies"], headers=ctx["headers"])
            for u in users:
                u["auth_role"] = ctx["role"]
            result['user_enumerations'].extend(users)

        if progress_cb:
            progress_cb('idor', 'idor_detector', f'Found {len(result["user_enumerations"])} user enum hits')

        # Test parameter-based IDOR for each auth context
        for ctx in auth_contexts:
            idors = self._test_parameter_idor(url, cookies=ctx["cookies"], headers=ctx["headers"])
            for item in idors:
                item["auth_role"] = ctx["role"]
            result['access_bypasses'].extend(idors)
        result['endpoints_tested'] = len(result['access_bypasses'])
        
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[IDOR] Error saving: {e}")
        
        if progress_cb:
            total = len(users) + len(idors)
            progress_cb('idor', 'idor_detector', f'Found {total} IDOR issues')
        
        return result
    
    def _test_user_enumeration(
        self,
        url: str,
        cookies: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> List[Dict]:
        """Detect user enumeration vectors"""
        users = []
        cookies = cookies or {}
        headers = headers or {}

        enum_endpoints = [
            '/wp-json/wp/v2/users',
            '/api/users',
            '/api/v1/users',
            '/api/v2/users',
            '/admin/users',
            '/user/list',
            '/users',
            '/author',
            '/profile',
        ]

        for endpoint in enum_endpoints:
            try:
                test_url = url.rstrip('/') + endpoint
                resp = self.http_client.get(
                    test_url, timeout=self.timeout,
                    cookies=cookies, headers=headers,
                )
                if resp.status_code in [200, 201]:
                    user_info = self._extract_users_from_response(resp.text)
                    if user_info:
                        users.append({
                            'endpoint': endpoint,
                            'method': 'GET',
                            'user_count': len(user_info),
                            'users': user_info[:10],
                        })
                        logger.info(f"[IDOR] User enumeration at {endpoint}: {len(user_info)} users")
            except Exception as e:
                logger.debug(f"[IDOR] User enum test failed for {endpoint}: {e}")

        return users

    def _test_parameter_idor(
        self,
        url: str,
        cookies: Optional[Dict] = None,
        headers: Optional[Dict] = None,
    ) -> List[Dict]:
        """Test for parameter-based IDOR (ID tampering) + BOLA with auth context."""
        idors = []
        cookies = cookies or {}
        headers = headers or {}

        try:
            resp1 = self.http_client.get(
                f"{url}?id=1", timeout=self.timeout, cookies=cookies, headers=headers
            )
            for test_id in [2, 10, 99, 100, 999]:
                try:
                    resp_alt = self.http_client.get(
                        f"{url}?id={test_id}", timeout=self.timeout,
                        cookies=cookies, headers=headers,
                    )
                    if resp_alt.status_code == 200 and resp1.text != resp_alt.text:
                        idors.append({
                            'parameter': 'id',
                            'type': 'direct_object_reference',
                            'tested_ids': [1, test_id],
                            'response_different': True,
                            'confidence': 0.75,
                        })
                        logger.info("[IDOR] Direct object reference found via id parameter")
                        break
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"[IDOR] id parameter test failed: {e}")

        numeric_params = ['uid', 'user_id', 'user', 'profile_id', 'post_id', 'article_id', 'account_id', 'order_id']
        for param in numeric_params:
            try:
                resp_a = self.http_client.get(
                    f"{url}?{param}=1", timeout=self.timeout, cookies=cookies, headers=headers
                )
                resp_b = self.http_client.get(
                    f"{url}?{param}=2", timeout=self.timeout, cookies=cookies, headers=headers
                )
                if resp_a.status_code == 200 and resp_b.status_code == 200 and resp_a.text != resp_b.text:
                    idors.append({
                        'parameter': param,
                        'type': 'direct_object_reference',
                        'confidence': 0.7,
                    })
                    logger.info(f"[IDOR] Found on parameter: {param}")
            except Exception:
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
