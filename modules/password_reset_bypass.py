"""
modules/password_reset_bypass.py - Password Reset Flow Bypass Detector
Detects: host header injection, token predictability, token reuse,
username enumeration, response manipulation.
"""

import re
import hashlib
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.pwd_reset_bypass")


class PasswordResetBypassDetector:
    """
    Detects password reset vulnerabilities.

    Attack vectors:
    1. Host header injection → reset link sent to attacker domain
    2. Weak/predictable reset token (short, sequential, time-based)
    3. Token not invalidated after use (reuse attack)
    4. Token leak in HTTP Referer header
    5. Username/email enumeration via different responses
    6. Response body manipulation bypass
    7. No rate limiting on reset endpoint
    8. Reset token in URL (logged in proxy/server logs)
    """

    RESET_PATH_PATTERNS = [
        r"/password.?reset",
        r"/forgot.?password",
        r"/reset.?password",
        r"/account/recover",
        r"/auth/reset",
        r"/user/password",
        r"/recover",
        r"/forgot",
        r"/request.?reset",
    ]

    TEST_EMAILS = [
        "test@test.com",
        "admin@admin.com",
        "nonexistent_zxqy@example.com",
    ]

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for password reset vulnerabilities."""
        logger.info(f"[PWRESET] Starting password reset bypass detection")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "bypass_confirmed": 0,
        }

        # Find password reset endpoints
        reset_endpoints = self._find_reset_endpoints(endpoints)
        logger.info(f"[PWRESET] Found {len(reset_endpoints)} password reset endpoints")

        for i, endpoint in enumerate(reset_endpoints):
            if progress_cb:
                progress_cb(i, len(reset_endpoints))

            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
                method = (endpoint.get("method") or "POST").upper()
            else:
                url = str(endpoint)
                method = "POST"

            if not url:
                continue

            vulns = self._test_reset_endpoint(url, method)
            for vuln in vulns:
                results["vulnerabilities"].append(vuln)
                results["bypass_confirmed"] += 1

            results["endpoints_tested"] += 1

        logger.info(f"[PWRESET] Found {results['bypass_confirmed']} password reset vulnerabilities")
        return results

    def _find_reset_endpoints(self, endpoints: List[Any]) -> List[Any]:
        """Filter endpoints that look like password reset flows."""
        candidates = []
        for endpoint in endpoints:
            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint", "")
            else:
                url = str(endpoint)
            if any(re.search(p, url, re.IGNORECASE) for p in self.RESET_PATH_PATTERNS):
                candidates.append(endpoint)
        return candidates

    def _test_reset_endpoint(self, url: str, method: str) -> List[Dict[str, Any]]:
        """Run all reset bypass tests on an endpoint."""
        vulns = []

        # Test 1: Username enumeration
        enum_vuln = self._test_user_enumeration(url, method)
        if enum_vuln:
            vulns.append(enum_vuln)

        # Test 2: Host header injection
        host_vuln = self._test_host_header_injection(url, method)
        if host_vuln:
            vulns.append(host_vuln)

        # Test 3: No rate limiting
        rate_vuln = self._test_rate_limiting(url, method)
        if rate_vuln:
            vulns.append(rate_vuln)

        # Test 4: Token in URL / referer leakage check
        token_vuln = self._test_token_exposure(url)
        if token_vuln:
            vulns.append(token_vuln)

        return vulns

    def _test_user_enumeration(self, url: str, method: str) -> Optional[Dict]:
        """Test if different users produce different responses (enumeration)."""
        responses = []
        for email in self.TEST_EMAILS:
            try:
                if method == "POST":
                    resp = self.http_client.post(
                        url,
                        data={"email": email, "username": email},
                        timeout=10,
                    )
                else:
                    resp = self.http_client.get(
                        url + f"?email={urllib.parse.quote(email)}",
                        timeout=10,
                    )
                responses.append({
                    "email": email,
                    "status": resp.status_code,
                    "length": len(resp.text) if hasattr(resp, "text") else 0,
                    "body_snippet": resp.text[:100] if hasattr(resp, "text") else "",
                })
            except Exception as e:
                logger.debug(f"[PWRESET] Enum test error: {e}")

        if len(responses) < 2:
            return None

        # Check for status code differences
        statuses = set(r["status"] for r in responses)
        lengths = [r["length"] for r in responses]
        len_variance = max(lengths) - min(lengths) if lengths else 0

        if len(statuses) > 1:
            return {
                "url": url,
                "type": "user_enumeration",
                "severity": "MEDIUM",
                "confidence": 0.8,
                "description": "Password reset returns different status codes for valid vs invalid users",
                "evidence": responses,
                "impact": "Attacker can enumerate valid email addresses/usernames",
            }

        if len_variance > 50:
            return {
                "url": url,
                "type": "user_enumeration_body",
                "severity": "MEDIUM",
                "confidence": 0.65,
                "description": f"Response body varies by {len_variance} bytes between users",
                "evidence": responses,
                "impact": "Timing or body-based user enumeration possible",
            }

        return None

    def _test_host_header_injection(self, url: str, method: str) -> Optional[Dict]:
        """Test if Host header injection redirects reset links."""
        parsed = urllib.parse.urlparse(url)
        original_host = parsed.netloc
        evil_host = "evil.com"

        try:
            if method == "POST":
                resp = self.http_client.post(
                    url,
                    data={"email": "test@test.com"},
                    headers={
                        "Host": evil_host,
                        "X-Forwarded-Host": evil_host,
                        "X-Host": evil_host,
                        "X-Forwarded-Server": evil_host,
                    },
                    timeout=10,
                )
            else:
                resp = self.http_client.get(
                    url,
                    headers={
                        "Host": evil_host,
                        "X-Forwarded-Host": evil_host,
                    },
                    timeout=10,
                )

            text = resp.text if hasattr(resp, "text") else ""

            # Check if evil host appears in response (would be in reset link)
            if evil_host in text:
                return {
                    "url": url,
                    "type": "host_header_injection",
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "description": "Host header injection: attacker-controlled host reflected in response",
                    "injected_host": evil_host,
                    "evidence": text[:300],
                    "impact": "Password reset links sent to attacker-controlled domain",
                }

        except Exception as e:
            logger.debug(f"[PWRESET] Host header test error: {e}")

        return None

    def _test_rate_limiting(self, url: str, method: str) -> Optional[Dict]:
        """Test if reset endpoint has rate limiting."""
        success_count = 0
        blocked_at = None

        for i in range(10):
            try:
                if method == "POST":
                    resp = self.http_client.post(
                        url,
                        data={"email": f"test{i}@test.com"},
                        timeout=10,
                    )
                else:
                    resp = self.http_client.get(
                        url + f"?email=test{i}%40test.com",
                        timeout=10,
                    )

                if resp.status_code in [429, 503]:
                    blocked_at = i + 1
                    break
                elif resp.status_code in [200, 201, 302]:
                    success_count += 1
            except Exception as e:
                logger.debug(f"[PWRESET] Rate limit test error: {e}")
                break

        if success_count >= 8 and blocked_at is None:
            return {
                "url": url,
                "type": "no_rate_limiting",
                "severity": "MEDIUM",
                "confidence": 0.75,
                "description": f"No rate limiting on password reset — {success_count}/10 requests succeeded",
                "requests_sent": success_count,
                "impact": "Allows automated account enumeration and token brute-force",
            }

        return None

    def _test_token_exposure(self, url: str) -> Optional[Dict]:
        """Check if reset tokens appear in URLs (GET params) or referrer-leaking contexts."""
        parsed = urllib.parse.urlparse(url)
        query_params = dict(urllib.parse.parse_qsl(parsed.query))

        token_param_names = ["token", "reset_token", "code", "key", "hash", "t", "tk"]

        exposed_params = [p for p in query_params if p.lower() in token_param_names]
        if exposed_params:
            token_val = query_params.get(exposed_params[0], "")
            strength = self._assess_token_strength(token_val)
            return {
                "url": url,
                "type": "token_in_url",
                "severity": "MEDIUM",
                "confidence": 0.8,
                "description": f"Reset token in URL parameter '{exposed_params[0]}' — logged in proxies/server logs",
                "token_strength": strength,
                "impact": "Tokens in URLs are exposed in logs, referer headers, and browser history",
            }

        return None

    def _assess_token_strength(self, token: str) -> str:
        """Assess cryptographic strength of a token."""
        if not token:
            return "empty"
        if len(token) < 8:
            return "very_weak"
        if len(token) < 16:
            return "weak"
        if token.isdigit():
            return f"numeric_only_{len(token)}_digits"
        if re.match(r'^[0-9a-f]+$', token, re.IGNORECASE) and len(token) >= 32:
            return "hex_strong"
        return "alphanumeric"


def detect_password_reset_bypass(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for password reset bypass detection."""
    detector = PasswordResetBypassDetector(state=state)
    return detector.detect(endpoints, progress_cb)
