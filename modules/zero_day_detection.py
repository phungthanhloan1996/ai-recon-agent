"""
modules/zero_day_detection.py - Zero-Day & Unknown Vulnerability Detection
Fuzzing, behavior analysis, anomaly detection, unknown CVE prediction
"""

import logging
import random
import string
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger("recon.zeroday")


class ZeroDayDetection:
    """Zero-day and unknown vulnerability detection"""
    
    def __init__(self, http_client=None):
        self.http_client = http_client
        self.fuzzing_results = []
        self.potential_zero_days = []
        self.anomaly_detections = []
    
    def fuzzing_payloads(self) -> List[str]:
        """Generate fuzzing payloads to trigger unknown vulnerabilities"""
        payloads = []
        
        # Boundary values
        payloads.extend([
            '0', '-1', '9999999999', '-9999999999',
            '2147483647', '-2147483648',  # 32-bit boundaries
            '9223372036854775807', '-9223372036854775808',  # 64-bit boundaries
        ])
        
        # Type confusion
        payloads.extend([
            '[1,2,3]', '{"a":1}', 'null', 'undefined',
            'true', 'false', 'NaN', 'Infinity', '-Infinity'
        ])
        
        # Encoding fuzzing
        payloads.extend([
            '%00', '%0d%0a', '\x00', '\n', '\r\n',
            '\x1a', '\xff\xfe',  # BOM markers
        ])
        
        # Recursive/nested structures
        payloads.extend([
            '[[[[[[[[[[]]]]]]]]]]',  # Deep nesting
            '{"a":{"b":{"c":{"d":{"e":1}}}}}',
        ])
        
        # Character set fuzzing
        for _ in range(10):
            payloads.append(''.join(random.choices(string.printable, k=random.randint(1, 100))))
        
        # Unicode/special chars
        payloads.extend([
            '\u0000', '\uffff', '\U0001F600',  # Emoji
            '㇀' * 100,  # CJK characters
        ])
        
        return payloads
    
    def fuzz_endpoint(self, url: str, endpoint: Dict, payloads: List[str]) -> List[Dict]:
        """Fuzz endpoint with payloads to find anomalies"""
        anomalies = []
        
        if not self.http_client:
            return anomalies
        
        for payload in payloads[:50]:  # Limit to 50 payloads per endpoint
            try:
                # Try different injection points
                params = endpoint.get('parameters', {})
                
                # Parameter value fuzzing
                for param, value in params.items():
                    test_payload = {'method': endpoint.get('method', 'GET'), param: payload}
                    
                    resp = self.http_client.request(
                        method=test_payload.get('method'),
                        url=url + endpoint.get('path', ''),
                        params=test_payload,
                        timeout=5
                    )
                    
                    # Detect anomalies
                    if self._is_anomalous_response(resp):
                        anomalies.append({
                            'type': 'fuzzing_anomaly',
                            'endpoint': endpoint.get('path'),
                            'parameter': param,
                            'payload': payload[:50],
                            'response_status': resp.status_code,
                            'response_time': resp.elapsed.total_seconds(),
                            'response_size': len(resp.text),
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Potential zero-day indicator
                        if self._is_possible_zeroday(resp, endpoint):
                            self.potential_zero_days.append({
                                'type': 'potential_zero_day',
                                'endpoint': endpoint.get('path'),
                                'fuzzing_payload': payload[:50],
                                'anomaly_type': self._classify_anomaly(resp),
                                'severity': 'unknown',
                                'confidence': 0.45,
                                'timestamp': datetime.now().isoformat()
                            })
            
            except Exception as e:
                logger.debug(f"Fuzzing error on {url}: {e}")
        
        self.anomaly_detections.extend(anomalies)
        return anomalies
    
    def _is_anomalous_response(self, response: Any) -> bool:
        """Detect anomalous response"""
        # Unusual status codes
        if response.status_code not in [200, 301, 302, 304, 400, 401, 403, 404, 405, 429, 500, 502, 503]:
            return True
        
        # Unusual response times (possible delay-based issues)
        if hasattr(response, 'elapsed'):
            elapsed = response.elapsed.total_seconds()
            if elapsed > 30:  # Very long response
                return True
        
        # Unusual response sizes
        if len(response.text) > 1000000:  # Huge response
            return True
        
        # Error messages revealing internals
        if any(x in response.text.lower() for x in ['traceback', 'stack trace', 'debug', 'internal error', 'exception']):
            return True
        
        return False
    
    def _is_possible_zeroday(self, response: Any, endpoint: Dict) -> bool:
        """Check if response indicates possible zero-day"""
        # Crash/exception messages
        crash_indicators = ['segmentation fault', 'access violation', 'buffer overflow',
                           'memory corruption', 'null pointer', 'panic', 'fatal error']
        
        for indicator in crash_indicators:
            if indicator in response.text.lower():
                return True
        
        # Unusual state changes
        if hasattr(response, 'status_code'):
            if response.status_code >= 500:  # Server errors often indicate crashes
                return True
        
        return False
    
    def _classify_anomaly(self, response: Any) -> str:
        """Classify the type of anomaly"""
        if response.status_code >= 500:
            return 'server_crash'
        elif len(response.text) > 1000000:
            return 'memory_exhaustion'
        elif response.elapsed.total_seconds() > 30:
            return 'infinite_loop_or_hang'
        else:
            return 'unknown_behavior'
    
    def behavioral_analysis(self, endpoint_data: List[Dict]) -> List[Dict]:
        """Analyze endpoint behavior patterns for anomalies"""
        anomalies = []
        
        if len(endpoint_data) < 2:
            return anomalies
        
        # Baseline from first 10 samples
        baseline = {
            'avg_response_time': sum(e.get('response_time', 0) for e in endpoint_data[:10]) / min(10, len(endpoint_data)),
            'avg_response_size': sum(len(e.get('response_text', '')) for e in endpoint_data[:10]) / min(10, len(endpoint_data)),
            'common_status': max(set(e.get('status_code') for e in endpoint_data[:10]), key=list(e.get('status_code') for e in endpoint_data[:10]).count)
        }
        
        # Check for deviations
        for sample in endpoint_data[10:]:
            resp_time = sample.get('response_time', 0)
            resp_size = len(sample.get('response_text', ''))
            status = sample.get('status_code')
            
            # 2x deviation = anomaly
            if resp_time > baseline['avg_response_time'] * 2:
                anomalies.append({
                    'type': 'response_time_spike',
                    'expected': baseline['avg_response_time'],
                    'actual': resp_time,
                    'deviation_factor': resp_time / baseline['avg_response_time']
                })
            
            if resp_size > baseline['avg_response_size'] * 2:
                anomalies.append({
                    'type': 'response_size_spike',
                    'expected': baseline['avg_response_size'],
                    'actual': resp_size,
                    'deviation_factor': resp_size / baseline['avg_response_size']
                })
            
            if status != baseline['common_status'] and status >= 500:
                anomalies.append({
                    'type': 'error_status_spike',
                    'expected': baseline['common_status'],
                    'actual': status
                })
        
        return anomalies
    
    @staticmethod
    def get_potential_zero_day_classes() -> List[Dict]:
        """Get potential zero-day vulnerability classes"""
        classes = [
            {
                'name': 'use_after_free',
                'indicators': ['segmentation fault', 'access violation', 'heap corruption'],
                'detectability': 'medium'
            },
            {
                'name': 'buffer_overflow',
                'indicators': ['stack smashing', 'overflow', 'buffer corruption'],
                'detectability': 'medium'
            },
            {
                'name': 'integer_overflow',
                'indicators': ['unexpected calculation', 'wrapping', 'negative values'],
                'detectability': 'low'
            },
            {
                'name': 'type_confusion',
                'indicators': ['type mismatch', 'unexpected cast', 'wrong type handling'],
                'detectability': 'low'
            },
            {
                'name': 'race_condition',
                'indicators': ['timing sensitive', 'concurrent access', 'non-deterministic'],
                'detectability': 'low'
            },
            {
                'name': 'logic_bomb',
                'indicators': ['time-based trigger', 'condition met', 'payload activation'],
                'detectability': 'very_low'
            },
            {
                'name': 'compiler_optimization_bug',
                'indicators': ['optimization artifact', 'code generation error'],
                'detectability': 'very_low'
            }
        ]
        
        return classes


class AnomalyDetector:
    """Detect behavioral/traffic anomalies suggesting vulnerabilities"""
    
    @staticmethod
    def detect_information_disclosure_patterns() -> List[Dict]:
        """Detect patterns of information disclosure"""
        patterns = [
            {
                'name': 'error_message_leakage',
                'indicators': ['exception details', 'file paths', 'database errors'],
                'severity': 'medium'
            },
            {
                'name': 'header_leakage',
                'indicators': ['X-Powered-By', 'Server', 'X-Version'],
                'severity': 'low'
            },
            {
                'name': 'source_code_disclosure',
                'indicators': ['.git', '.env', 'backup files'],
                'severity': 'critical'
            },
            {
                'name': 'timing_side_channel',
                'indicators': ['response time variance', 'processing time'],
                'severity': 'high'
            }
        ]
        
        return patterns
    
    @staticmethod
    def detect_authentication_weaknesses() -> List[Dict]:
        """Detect weak authentication patterns"""
        patterns = [
            {
                'name': 'username_enumeration',
                'indicators': ['different_responses', 'timing_differences'],
                'severity': 'medium'
            },
            {
                'name': 'weak_password_policy',
                'indicators': ['no_complexity_req', 'short_passwords'],
                'severity': 'high'
            },
            {
                'name': 'session_fixation',
                'indicators': ['session_not_changed_on_login'],
                'severity': 'high'
            },
            {
                'name': 'broken_cryptography',
                'indicators': ['old_tls', 'weak_cipher', 'no_encryption'],
                'severity': 'critical'
            }
        ]
        
        return patterns
