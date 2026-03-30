"""
modules/waf_bypass_engine.py - WAF Detection and Bypass
Cloudflare, ModSecurity, Imperva, AWS WAF bypass techniques
"""

import json
import logging
import time
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urljoin, quote

from core.http_engine import HTTPClient

logger = logging.getLogger("recon.waf_bypass")


class WAFBypassEngine:
    """Advanced WAF detection and bypass"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/waf_bypass_findings.json"
    
    def detect_and_bypass(
        self,
        url: str,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """Detect WAF type and attempt bypass"""
        result = {
            'url': url,
            'tool': 'waf_bypass',
            'type': 'waf_detection',
            'waf_detected': [],
            'bypass_techniques': [],
            'successful_bypasses': [],
            'payloads_tested': 0
        }
        
        if progress_cb:
            progress_cb('waf_bypass', 'waf_detector', 'Detecting WAF...')
        
        logger.info(f"[WAF] Detecting WAF on {url}")
        
        # Detect WAF type
        waf_fp = self._detect_waf(url)
        result['waf_detected'] = waf_fp
        
        if not waf_fp:
            logger.info(f"[WAF] No WAF detected on {url}")
            if progress_cb:
                progress_cb('waf_bypass', 'waf_detector', 'No WAF detected')
            return result
        
        logger.info(f"[WAF] Detected: {[w['name'] for w in waf_fp]}")
        
        # Get bypass techniques for detected WAF
        for waf in waf_fp:
            waf_name = waf.get('name', '').lower()
            techniques = self._get_bypass_techniques(waf_name)
            result['bypass_techniques'].extend(techniques)
            
            if progress_cb:
                progress_cb('waf_bypass', 'waf_detector', f'Testing {waf_name}...')
            
            # Test bypass techniques
            for technique in techniques[:5]:  # Test top 5
                result['payloads_tested'] += 1
                bypass_result = self._test_bypass(url, technique)
                if bypass_result:
                    result['successful_bypasses'].append(bypass_result)
                    logger.info(f"[WAF] {waf_name} bypass successful: {technique['name']}")
        
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[WAF] Error saving findings: {e}")
        
        if progress_cb:
            success_count = len(result['successful_bypasses'])
            progress_cb('waf_bypass', 'waf_detector', f'Completed: {success_count} bypasses found')
        
        return result
    
    def _detect_waf(self, url: str) -> List[Dict]:
        """Fingerprint WAF type"""
        wafs = []
        
        try:
            resp = self.http_client.get(url)
            headers = resp.headers
            text = resp.text.lower()
            
            # Cloudflare
            if any(k in headers for k in ['cf-ray', 'cf-cache-status']) or \
               any(k in headers for k in ['server']) and 'cloudflare' in headers.get('server', '').lower():
                wafs.append({
                    'name': 'Cloudflare',
                    'confidence': 'high',
                    'indicators': ['cf-ray', 'cf-cache-status']
                })
                logger.debug(f"[WAF] Fingerprint: Cloudflare detected")
            
            # ModSecurity/OWASP
            if 'modsecurity' in headers.get('server', '').lower():
                wafs.append({
                    'name': 'ModSecurity',
                    'confidence': 'high',
                    'indicators': ['modsecurity in Server header']
                })
            
            # AWS WAF
            if '403' in str(resp.status_code) and any(k in text for k in ['amazon', 'aws']):
                wafs.append({
                    'name': 'AWS WAF',
                    'confidence': 'medium',
                    'indicators': ['AWS error page patterns']
                })
            
            # Imperva
            if any(k in headers.get('server', '').lower() for k in ['imperva', 'incapsula']):
                wafs.append({
                    'name': 'Imperva',
                    'confidence': 'high',
                    'indicators': ['imperva header']
                })
            
            # Akamai
            if any(k in headers for k in ['akamai-origin-hop']) or \
               'akamai' in headers.get('server', '').lower():
                wafs.append({
                    'name': 'Akamai',
                    'confidence': 'medium',
                    'indicators': ['akamai headers']
                })
            
            # F5 BIG-IP
            if 'bigip' in headers.get('server', '').lower():
                wafs.append({
                    'name': 'F5 BIG-IP',
                    'confidence': 'high',
                    'indicators': ['f5 header']
                })
        
        except Exception as e:
            logger.error(f"[WAF] Detection error: {e}")
        
        return wafs
    
    def _get_bypass_techniques(self, waf_name: str) -> List[Dict]:
        """Get bypass techniques for specific WAF"""
        techniques = {
            'cloudflare': [
                {
                    'name': 'IP Rotation',
                    'payload': 'standard_request',
                    'method': 'Use rotate IPs via proxy'
                },
                {
                    'name': 'Case Mixing',
                    'payload': '/AdMiN/SqLi.PhP',
                    'method': 'Mixed case in URI path'
                },
                {
                    'name': 'URL Encoding',
                    'payload': '/admin/%73qli.php',
                    'method': 'Double URL encode path'
                },
                {
                    'name': 'Unicode Normalization',
                    'payload': '/admin/%E0%BD%80dmin.php',
                    'method': 'Unicode bypass paths'
                },
                {
                    'name': 'HTTP/2 Push',
                    'payload': 'http2_push_exploit',
                    'method': 'Abuse HTTP/2 server push'
                }
            ],
            'modsecurity': [
                {
                    'name': 'Space Replacement',
                    'payload': 'select/**/count(*)',
                    'method': 'Replace space with /**/'
                },
                {
                    'name': 'Comment Insertion',
                    'payload': 'union/**/select',
                    'method': 'Insert comments between keywords'
                },
                {
                    'name': 'Null Byte',
                    'payload': 'admin.php%00.jpg',
                    'method': 'Null byte injection'
                },
                {
                    'name': 'Hex Encoding',
                    'payload': '0x3c7363726970743e',
                    'method': 'Hex encode payloads'
                },
                {
                    'name': 'Parameter Pollution',
                    'payload': '?id=1&id=union&id=select',
                    'method': 'Multiple parameter values'
                }
            ],
            'aws waf': [
                {
                    'name': 'Header Obfuscation',
                    'payload': 'X-Forwarded-For spoofing',
                    'method': 'Spoof source IP header'
                },
                {
                    'name': 'Case Variation',
                    'payload': '/AdMiN.PhP',
                    'method': 'Mixed case bypass'
                }
            ],
            'imperva': [
                {
                    'name': 'Concatenation',
                    'payload': 'con' + 'cat(' + 'string)',
                    'method': 'String concatenation'
                },
                {
                    'name': 'Tab Character',
                    'payload': 'select\t*',
                    'method': 'Tab as whitespace'
                }
            ]
        }
        
        return techniques.get(waf_name.lower(), techniques.get('modsecurity', []))
    
    def _test_bypass(self, url: str, technique: Dict) -> Optional[Dict]:
        """Test specific bypass technique"""
        try:
            payload = technique.get('payload', '')
            method = technique.get('method', '')
            
            # Inject payload
            test_url = f"{url}?test={quote(payload)}"
            
            try:
                resp = self.http_client.get(test_url, timeout=self.timeout)
                
                # Check if bypass worked
                if resp.status_code not in [403, 406, 429, 444]:
                    return {
                        'technique': technique['name'],
                        'method': method,
                        'status_code': resp.status_code,
                        'success': True,
                        'response_size': len(resp.text)
                    }
            except Exception as e:
                logger.debug(f"[WAF] Bypass test failed: {e}")
        
        except Exception as e:
            logger.error(f"[WAF] Bypass error: {e}")
        
        return None
