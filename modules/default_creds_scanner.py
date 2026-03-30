"""
modules/default_creds_scanner.py - Default Credentials Scanning
Admin panels, CMS, databases
"""

import json
import logging
from typing import Dict, List, Any, Optional, Callable
import time

from core.http_engine import HTTPClient

logger = logging.getLogger("recon.default_creds")


class DefaultCredsScanner:
    """Scan for default credentials on admin panels"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/default_creds_findings.json"
        
        # Common default credentials
        self.creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', 'admin123'),
            ('admin', '123456'),
            ('admin', '12345678'),
            ('admin', 'qwerty'),
            ('admin', 'root'),
            ('admin', ''),
            ('root', 'root'),
            ('root', 'password'),
            ('test', 'test'),
            ('test', 'test123'),
            ('guest', 'guest'),
            ('anonymous', ''),
            ('wordpress', 'wordpress'),
        ]
    
    def scan(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """Scan for default credentials"""
        result = {
            'url': url,
            'tool': 'default_creds',
            'type': 'default_credentials',
            'credentials_found': [],
            'tested_endpoints': 0,
            'successful_logins': []
        }
        
        if progress_cb:
            progress_cb('default_creds', 'creds_scanner', 'Scanning default creds...')
        
        logger.info(f"[CREDS] Scanning {url}")
        
        # Common admin endpoints
        admin_endpoints = [
            '/wp-login.php',
            '/admin',
            '/admin/login',
            '/administration',
            '/admin.php',
            '/login.php',
            '/login',
            '/user/login',
            '/index.php?login',
            '/administrator',
        ]
        
        for endpoint in admin_endpoints:
            try:
                admin_url = url.rstrip('/') + endpoint
                
                # Test if endpoint exists
                try:
                    resp = self.http_client.get(admin_url, timeout=self.timeout)
                    if resp.status_code in [200, 403, 404]:
                        result['tested_endpoints'] += 1
                        
                        if progress_cb:
                            progress_cb('default_creds', 'creds_scanner', f'Testing {endpoint}...')
                        
                        # Try credentials
                        for username, password in self.creds:
                            login_result = self._try_login(admin_url, username, password)
                            if login_result:
                                result['successful_logins'].append(login_result)
                                result['credentials_found'].append({
                                    'endpoint': endpoint,
                                    'username': username,
                                    'password': password,
                                    'url': admin_url
                                })
                                logger.info(f"[CREDS] FOUND: {username}:{password} at {endpoint}")
                                break  # Move to next endpoint
                
                except Exception as e:
                    logger.debug(f"[CREDS] Endpoint test failed: {e}")
            
            except Exception as e:
                logger.debug(f"[CREDS] Error: {e}")
        
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[CREDS] Error saving: {e}")
        
        if progress_cb:
            found_count = len(result['credentials_found'])
            progress_cb('default_creds', 'creds_scanner', f'Found {found_count} working creds')
        
        return result
    
    def _try_login(self, url: str, username: str, password: str) -> Optional[Dict]:
        """Try to login with credentials"""
        try:
            # WordPress-style login
            if 'wp-login.php' in url:
                data = {
                    'log': username,
                    'pwd': password,
                    'wp-submit': 'Log In',
                    'redirect_to': '/wp-admin/',
                    'testcookie': '1'
                }
                
                resp = self.http_client.post(url, data=data, timeout=self.timeout)
                
                # Check for success indicators
                if 'wp-admin' in resp.text or 'dashboard' in resp.text.lower():
                    return {
                        'username': username,
                        'password': password,
                        'type': 'wordpress',
                        'success': True
                    }
            
            # Basic form login
            else:
                data = {
                    'username': username,
                    'password': password,
                    'login': 'Login',
                    'submit': 'Login'
                }
                
                resp = self.http_client.post(url, data=data, timeout=self.timeout)
                
                # Success indicators
                success_keywords = ['dashboard', 'panel', 'welcome', 'logout', 'administrator', 'admin']
                if any(k in resp.text.lower() for k in success_keywords):
                    return {
                        'username': username,
                        'password': password,
                        'type': 'form',
                        'success': True
                    }
        
        except Exception as e:
            logger.debug(f"[CREDS] Login attempt failed: {e}")
        
        return None
