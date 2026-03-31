"""
core/response_analyzer.py - HTTP Response Analyzer
Phân tích response để xác định exploit success
"""

import re
import logging
from typing import Any, Dict, List, Optional, Tuple

from modules.crypto_scanner import CryptographicScanner

logger = logging.getLogger("recon.response_analyzer")


# ═══════════════════════════════════════════════════════════════════════════════
# PHP VERSION DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

# Regex patterns for PHP version detection
PHP_VERSION_PATTERNS = [
    # X-Powered-By header: PHP/7.4.33, PHP/8.1, PHP/7.4
    re.compile(r"PHP/?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
    # PHP Version in body: "PHP Version 7.4.33", "PHP/7.4.33"
    re.compile(r"PHP\s*[Vv]ersion\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
    # Server header: PHP/7.4.33
    re.compile(r"Server:\s*PHP/?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
    # phpinfo() output patterns
    re.compile(r'<td\s+class="e"\s*>PHP\s+Version\s*</td>\s*<td\s+class="v"\s*>([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.IGNORECASE),
    # expose_php = on header format
    re.compile(r"X-Powered-By:\s*PHP/?([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE),
]

# Patterns that indicate PHP but without version
PHP_PRESENCE_PATTERNS = [
    re.compile(r"PHP/?([0-9]+)", re.IGNORECASE),
    re.compile(r'<\?php', re.IGNORECASE),
    re.compile(r'PHP\/([0-9])', re.IGNORECASE),
]


def detect_php_version(headers: Optional[Dict[str, str]] = None, body: str = "") -> Optional[str]:
    """
    Detect PHP version from HTTP response headers and body.
    
    Args:
        headers: Response headers as dict (case-insensitive keys)
        body: Response body as string
        
    Returns:
        PHP version string (e.g., "7.4.33", "8.1") or None if not detected
    """
    # Check headers first (most reliable)
    if headers:
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            # Check X-Powered-By header
            if header_lower in ("x-powered-by", "x-poweredby", "x_powered_by"):
                for pattern in PHP_VERSION_PATTERNS:
                    match = pattern.search(header_value)
                    if match:
                        version = match.group(1)
                        logger.info(f"[PHP] Detected PHP version {version} from {header_name} header")
                        return version
            
            # Check Server header
            if header_lower in ("server", "x-server"):
                for pattern in PHP_VERSION_PATTERNS:
                    match = pattern.search(header_value)
                    if match:
                        version = match.group(1)
                        logger.info(f"[PHP] Detected PHP version {version} from {header_name} header")
                        return version
    
    # Check body content
    if body:
        for pattern in PHP_VERSION_PATTERNS:
            match = pattern.search(body)
            if match:
                version = match.group(1)
                logger.info(f"[PHP] Detected PHP version {version} from response body")
                return version
    
    return None


def detect_php_presence(headers: Optional[Dict[str, str]] = None, body: str = "") -> bool:
    """
    Check if PHP is present (even without version info).
    
    Args:
        headers: Response headers as dict
        body: Response body as string
        
    Returns:
        True if PHP is detected, False otherwise
    """
    if headers:
        for header_name, header_value in headers.items():
            if header_name.lower() in ("x-powered-by", "server"):
                if re.search(r"php", header_value, re.IGNORECASE):
                    return True
    
    if body:
        for pattern in PHP_PRESENCE_PATTERNS:
            if pattern.search(body):
                return True
    
    return False


class VulnerabilityScorer:
    """
    Scientific scoring for vulnerabilities.
    
    Base score (0-1):
    - +0.4 = payload reflected in response (direct code execution)
    - +0.3 = response anomaly (DB error / status change / timing)
    - +0.3 = confirmed by second payload
    
    Rules:
    - score < 0.5  → DISCARD (likely false positive)
    - 0.5 - 0.7   → LOW
    - 0.7 - 0.9   → MEDIUM
    - > 0.9       → HIGH
    
    CRITICAL RULE: Evidence required for each point
    """
    
    def __init__(self):
        self.min_viable_score = 0.5  # Below this = DISCARD
    
    def score_vulnerability(
        self,
        exploit_type: str,
        response_text: str,
        baseline_response: Optional[str],
        payload: Optional[str],
        payload_count: int = 1,
        status_code: int = 200,
        baseline_status: int = 200
    ) -> Dict:
        """
        Calculate vulnerability confidence score.
        
        Returns: {
            'score': 0.0-1.0,
            'severity': 'INFO|LOW|MEDIUM|HIGH',
            'evidence': ['evidence_1', ...],
            'evidence_count': int,
            'validation_status': 'unconfirmed|confirmed' 
        }
        """
        score = 0.0
        evidence = []
        
        # EVIDENCE 1: Payload Reflection - STRONGEST (+0.4)
        if payload and self._is_payload_reflected(response_text, payload):
            score += 0.4
            evidence.append(f"Payload reflected in response ({payload[:30]}...)")
        
        # EVIDENCE 2: Response Anomaly
        anomaly_score = self._check_response_anomaly(
            response_text, baseline_response, status_code, baseline_status, exploit_type
        )
        if anomaly_score > 0:
            score += anomaly_score  # Up to +0.3
            if status_code != baseline_status:
                evidence.append(f"Status changed: {baseline_status}→{status_code}")
            if baseline_response and len(response_text) != len(baseline_response):
                diff = len(response_text) - len(baseline_response)
                evidence.append(f"Response length changed: {diff:+d} bytes")
        
        # EVIDENCE 3: Validation (second payload) - REWARDING CONSISTENCY (+0.3)
        if payload_count >= 2:
            score += 0.3
            evidence.append("Confirmed by multiple payloads")
        
        # Apply floor: remove low-confidence findings (lowered from 0.5 to 0.35 for blind injection)
        if score < 0.35:
            return {
                'score': 0.0,
                'severity': 'DISCARDED',
                'evidence': evidence,
                'evidence_count': len(evidence),
                'validation_status': 'invalid',
                'reason': 'Score below minimum viable threshold (0.35)'
            }
        
        # Normalize to [0.5, 1.0] for viable findings
        if score > 1.0:
            score = 1.0
        
        # Determine severity
        if score > 0.9:
            severity = 'HIGH'
        elif score > 0.7:
            severity = 'MEDIUM'
        elif score > 0.5:
            severity = 'LOW'
        else:
            severity = 'INFO'
        
        # Validation status
        validation = 'confirmed' if payload_count >= 2 else 'unconfirmed'
        
        return {
            'score': round(score, 2),
            'severity': severity,
            'evidence': evidence,
            'evidence_count': len(evidence),
            'validation_status': validation,
            'reason': f"Evidence verified: {len(evidence)} out of 3 points"
        }
    
    def _is_payload_reflected(self, response_text: str, payload: str) -> bool:
        """
        Check if payload is reflected in the response.
        IMPORTANT: Must be actual code behavior, not just in error message.
        """
        if not response_text or not payload:
            return False
        
        # Make the check more specific
        response_lower = response_text.lower()
        payload_lower = payload.lower()
        
        # Short payloads might occur by chance, need longer match
        if len(payload) < 5:
            return False
        
        # Find if payload appears
        if payload_lower in response_lower:
            # Verify it's not just in an error message about the input
            # Context check: avoid "invalid input: <payload>"
            idx = response_lower.find(payload_lower)
            context_before = response_lower[max(0, idx-50):idx]
            
            invalid_contexts = ['invalid', 'error', 'rejected', 'not allowed', 'syntax error in']
            if any(ic in context_before for ic in invalid_contexts):
                return False  # It's in an error message
            
            return True
        
        return False
    
    def _check_response_anomaly(
        self,
        response_text: str,
        baseline_response: Optional[str],
        status_code: int,
        baseline_status: int,
        exploit_type: str
    ) -> float:
        """
        Check for response anomalies that indicate vulnerability.
        Max +0.3, requires actual evidence.
        """
        score = 0.0
        
        # Status code change (allows for some flexibility)
        if status_code != baseline_status:
            # Some changes indicate success, others are normal
            if status_code == 500 and exploit_type in ['sql_injection', 'command_injection']:
                score += 0.15  # Server error on injection attempt
            elif status_code == 403 and exploit_type == 'auth_bypass':
                score += 0.15  # Access control
            elif status_code in [400, 422] and status_code != baseline_status:
                # Input rejection (less reliable)
                score += 0.05
        
        # Response content change (only if we have baseline)
        if baseline_response:
            # Look for error patterns that ONLY appear with injection
            response_keywords = self._extract_error_keywords(response_text)
            baseline_keywords = self._extract_error_keywords(baseline_response)
            
            # New error keywords appearing → +0.15
            new_errors = response_keywords - baseline_keywords
            if new_errors and exploit_type in ['sql_injection', 'command_injection']:
                score += 0.15
        
        return min(score, 0.3)
    
    def _extract_error_keywords(self, response_text: str) -> set:
        """Extract DB/injection error keywords"""
        error_patterns = {
            'sql': [
                'sql', 'syntax', 'query', 'database', 'table', 'column',
                'syntax error', 'near', 'unexpected', 'mysql', 'postgresql',
                'sqlite', 'oracle', 'mssql'
            ],
            'rce': ['uid=', 'root@', '/bin/', 'command not found', 'permission denied'],
            'xss': ['<script>', '</script>', 'onclick=', 'onerror=', 'alert()']
        }
        
        found = set()
        response_lower = response_text.lower()
        
        for category, patterns in error_patterns.items():
            for pattern in patterns:
                if pattern in response_lower:
                    found.add(pattern)
        
        return found



# Signatures for detecting successful exploits
SIGNATURES = {
    "sql_injection": {
        "success": [
            r"you have an error in your sql syntax",
            r"warning.*mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"syntax error.*near",
            r"pg_query\(\): query failed",
            r"supplied argument is not a valid postgresql",
            r"ora-\d{5}",  # Oracle errors
            r"microsoft.*odbc.*driver",
            r"mysql_fetch_array\(\)",
            r"sqlite_step\(\)",
            r"division by zero",
            r"sql syntax.*near",
        ],
        "data_leak": [
            r"root:.*:/bin/",
            r"\d+:\d+:\d+:\d+",  # potential data rows
        ]
    },
    "xss": {
        "success": [
            r"<script>alert\(",
            r"<svg.*onload=",
            r"javascript:alert",
            r"onerror=alert",
        ]
    },
    "lfi": {
        "success": [
            r"root:x:0:0",
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"for 16-bit app support",
            r"daemon:x:",
            r"/bin/bash",
            r"etc/passwd",
        ]
    },
    "rce": {
        "success": [
            r"uid=\d+\(\w+\) gid=\d+",
            r"total \d+\ndrwx",
            r"linux \d+\.\d+",
            r"Microsoft Windows \[Version",
            r"command not found",
        ]
    },
    "upload": {
        "success": [
            r"file uploaded successfully",
            r"upload successful",
            r"file has been uploaded",
            r"successfully uploaded",
        ],
        "webshell": [
            r"uid=",
            r"whoami",
            r"system\(",
            r"shell_exec\(",
        ]
    },
    "auth_bypass": {
        "success": [
            r"welcome.*admin",
            r"logged in as",
            r"dashboard",
            r"logout",
        ]
    },
    "xmlrpc": {
        "success": [
            r"<methodResponse>",
            r"<value>",
            r"faultCode",
        ],
        "bruteforce_success": [
            r"isAdmin.*1",
            r"<string>.*</string>",
        ]
    },
    "info_disclosure": {
        "sensitive": [
            r"api[_\s-]?key\s*[=:]\s*['\"]?[\w\-]{16,}",
            r"secret[_\s-]?key\s*[=:]\s*['\"]?[\w\-]{16,}",
            r"password\s*[=:]\s*['\"]?[\w\-@#$%]{6,}",
            r"db_pass(word)?\s*[=:]\s*",
            r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            r"AWS_SECRET_ACCESS_KEY",
            r"authorization:\s*bearer\s+[\w\-\.]+",
        ]
    }
}

HTTP_STATUS_RISK = {
    200: "OK - Potential success",
    201: "Created - Possible successful upload/creation",
    301: "Redirect - Note destination",
    302: "Redirect - Note destination",
    401: "Unauthorized - Auth required (try bypass)",
    403: "Forbidden - Access control (try bypass)",
    500: "Server Error - Possible injection point",
    502: "Bad Gateway - Backend error",
    503: "Service Unavailable",
}


class ResponseAnalyzer:
    def __init__(self, output_dir: str = None):
        self.findings = []
        self.scorer = VulnerabilityScorer()
        self.crypto_scanner = CryptographicScanner(output_dir=output_dir)
        self.crypto_findings = []

    def analyze(
        self,
        response_text: str,
        status_code: int,
        url: str,
        exploit_type: str,
        payload: Optional[str] = None,
        baseline_response: Optional[Dict] = None
    ) -> Dict:
        """
        Analyze HTTP response for exploit success indicators using scientific scoring.
        
        Args:
            response_text: Response body
            status_code: HTTP status code
            url: Target URL
            exploit_type: Type of exploit (xss, sql_injection, etc.)
            payload: Payload used
            baseline_response: Baseline response for comparison
        
        Returns:
            {
                'url': str,
                'exploit_type': str,
                'payload': str,
                'status_code': int,
                'success': bool,
                'confidence': 0.0-1.0,
                'severity': str,
                'evidence': [str],
                'validation_status': str
            }
        """
        baseline_text = baseline_response.get('content', '') if baseline_response else None
        baseline_status = baseline_response.get('status_code', 200) if baseline_response else 200
        
        # Use scientific scorer
        score_result = self.scorer.score_vulnerability(
            exploit_type=exploit_type,
            response_text=response_text,
            baseline_response=baseline_text,
            payload=payload,
            payload_count=1,
            status_code=status_code,
            baseline_status=baseline_status
        )
        
        result = {
            "url": url,
            "exploit_type": exploit_type,
            "payload": payload,
            "status_code": status_code,
            "success": score_result['score'] >= self.scorer.min_viable_score,
            "confidence": score_result['score'],
            "indicators": score_result.get('evidence', []),
            "severity": score_result['severity'],
            "validation_status": score_result.get('validation_status', 'unconfirmed'),
            "evidence_count": score_result.get('evidence_count', 0),
            "reason": score_result.get('reason', '')
        }
        
        # Only track findings that pass the threshold
        if result['success']:
            logger.info(
                f"[SCORING] ✓ VULNERABILITY [{exploit_type}] "
                f"score={result['confidence']} severity={result['severity']} url={url}"
            )
            self.findings.append(result)
        else:
            logger.debug(
                f"[SCORING] ✗ REJECTED [{exploit_type}] "
                f"score={result['confidence']} (below 0.5 threshold) url={url}"
            )
        
        return result

    def analyze_shell_response(self, response_text: str) -> Tuple[bool, str]:
        """Check if webshell executed successfully"""
        patterns = SIGNATURES["rce"]["success"]
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                # Extract command output
                lines = response_text.strip().splitlines()
                output = "\n".join(lines[:10])
                return True, output
        return False, ""

    def check_sql_data_exfil(self, response_text: str) -> Optional[str]:
        """Check if SQLi leaked actual data"""
        # Look for tabular data patterns
        patterns = [
            r"(\w+@[\w.]+)",  # emails
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # phone numbers
            r"admin|administrator|root|superuser",  # admin users
        ]
        found = []
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            found.extend(matches[:3])
        
        if found:
            return ", ".join(set(found))
        return None

    def get_findings(self) -> List[Dict]:
        return self.findings

    def severity_summary(self) -> Dict:
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            sev = finding.get("severity", "INFO")
            summary[sev] = summary.get(sev, 0) + 1
        # Include crypto findings in summary
        for finding in self.crypto_findings:
            sev = finding.get("severity", "INFO")
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def _check_crypto_failures(self, response) -> List[Dict[str, Any]]:
        """
        Check for cryptographic failures in response (OWASP A04:2021).
        
        Args:
            response: HTTP response object with text, headers attributes
            
        Returns:
            List of cryptographic security findings
        """
        findings = []
        
        try:
            response_text = ""
            headers = {}
            
            # Extract response data
            if hasattr(response, 'text'):
                response_text = response.text
            elif hasattr(response, 'content'):
                response_text = response.content.decode('utf-8', errors='ignore')
            
            if hasattr(response, 'headers'):
                headers = dict(response.headers) if response.headers else {}
            
            # Check for sensitive data exposure
            if response_text:
                sensitive_findings = self.crypto_scanner.check_sensitive_data(response_text)
                findings.extend(sensitive_findings)
            
            # Check for HSTS header
            if headers:
                hsts_findings = self.crypto_scanner.check_hsts(headers)
                findings.extend(hsts_findings)
            
            # Store findings
            self.crypto_findings.extend(findings)
            
            if findings:
                logger.warning(f"[RESPONSE_ANALYZER] Found {len(findings)} cryptographic security issues")
                
        except Exception as e:
            logger.debug(f"[RESPONSE_ANALYZER] Crypto check failed: {e}")
        
        return findings

    def check_response_crypto(self, response, url: str = "") -> List[Dict[str, Any]]:
        """
        Public method to check cryptographic issues in a response.
        
        Args:
            response: HTTP response object
            url: Optional URL for context
            
        Returns:
            List of cryptographic findings
        """
        return self._check_crypto_failures(response)

    def get_crypto_findings(self) -> List[Dict[str, Any]]:
        """Get all cryptographic security findings"""
        return self.crypto_findings

    def save_crypto_findings(self, filepath: str = None):
        """Save crypto findings to file"""
        if not self.crypto_findings:
            return
        
        if not filepath:
            filepath = os.path.join(self.crypto_scanner.output_dir or ".", "crypto_findings.json")
        
        try:
            import json
            with open(filepath, 'w') as f:
                json.dump(self.crypto_findings, f, indent=2, default=str)
            logger.info(f"[RESPONSE_ANALYZER] Crypto findings saved to {filepath}")
        except Exception as e:
            logger.error(f"[RESPONSE_ANALYZER] Failed to save crypto findings: {e}")
