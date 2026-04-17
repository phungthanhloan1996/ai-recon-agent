"""
modules/cors_scanner.py - CORS Misconfiguration Scanner
Detects: wildcard origins, null origin, trusted subdomain bypass,
arbitrary origin reflection, credentials with wildcard.
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.cors_scanner")


class CORSScanner:
    """
    Detects CORS misconfigurations.

    Attack vectors:
    1. Arbitrary origin reflected with ACAO: <attacker>
    2. null origin accepted: ACAO: null
    3. Subdomain wildcard: *.target.com → evil.target.com bypass
    4. Prefix/suffix bypass: target.com.evil.com
    5. ACAO: * with ACAC: true (invalid but some servers allow)
    6. Pre-flight bypass for non-simple methods
    """

    TEST_ORIGINS = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        "https://localhost",
        "http://127.0.0.1",
    ]

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for CORS misconfigurations."""
        logger.info(f"[CORS] Starting CORS scan on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "cors_confirmed": 0,
        }

        # Deduplicate by origin host to avoid hammering same server
        seen_hosts = set()
        for i, endpoint in enumerate(endpoints):
            if progress_cb:
                progress_cb(i, len(endpoints))

            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
            else:
                url = str(endpoint)

            if not url:
                continue

            parsed = urllib.parse.urlparse(url)
            host_key = f"{parsed.scheme}://{parsed.netloc}"
            if host_key in seen_hosts:
                results["endpoints_tested"] += 1
                continue
            seen_hosts.add(host_key)

            cors_result = self._test_cors(url)
            if cors_result.get("vulnerable"):
                results["vulnerabilities"].append(cors_result)
                results["cors_confirmed"] += 1

            results["endpoints_tested"] += 1

        logger.info(f"[CORS] Found {results['cors_confirmed']} CORS misconfigurations")
        return results

    def _test_cors(self, url: str) -> Dict[str, Any]:
        """Test a URL for CORS misconfigurations."""
        result = {
            "url": url,
            "vulnerable": False,
            "confidence": 0.0,
            "issues": [],
            "evidence": [],
        }

        parsed = urllib.parse.urlparse(url)
        target_host = parsed.netloc

        # Build test origins including subdomain bypass attempts
        test_origins = list(self.TEST_ORIGINS)
        test_origins += [
            f"https://evil.{target_host}",
            f"https://{target_host}.evil.com",
            f"https://not{target_host}",
        ]

        for origin in test_origins:
            try:
                response = self.http_client.get(
                    url,
                    headers={"Origin": origin},
                    timeout=10,
                )

                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")
                acam = response.headers.get("Access-Control-Allow-Methods", "")

                issue = self._evaluate_cors_headers(origin, acao, acac, acam, target_host)
                if issue:
                    result["vulnerable"] = True
                    result["issues"].append(issue)
                    result["evidence"].append({
                        "origin_sent": origin,
                        "ACAO": acao,
                        "ACAC": acac,
                    })
                    result["confidence"] = max(result["confidence"], issue.get("confidence", 0.7))

            except Exception as e:
                logger.debug(f"[CORS] Error testing {url} with origin {origin}: {e}")
                continue

        # Test preflight
        preflight_issue = self._test_preflight(url)
        if preflight_issue:
            result["vulnerable"] = True
            result["issues"].append(preflight_issue)
            result["confidence"] = max(result["confidence"], 0.6)

        return result

    def _evaluate_cors_headers(
        self, origin: str, acao: str, acac: str, acam: str, target_host: str
    ) -> Optional[Dict]:
        """Evaluate CORS response headers for misconfigurations."""
        if not acao:
            return None

        credentials_enabled = acac.lower() == "true"

        # Critical: ACAO reflects arbitrary origin + credentials
        if acao == origin and origin not in ["https://evil.com"] and credentials_enabled:
            return {
                "type": "arbitrary_origin_with_credentials",
                "description": f"Origin '{origin}' reflected in ACAO with credentials enabled",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "impact": "Full CORS bypass — attacker can make credentialed cross-origin requests",
            }

        # Critical: ACAO reflects evil.com or attacker.com
        if acao in ["https://evil.com", "https://attacker.com"]:
            severity = "CRITICAL" if credentials_enabled else "HIGH"
            return {
                "type": "arbitrary_origin_reflected",
                "description": f"Arbitrary origin '{acao}' accepted",
                "severity": severity,
                "confidence": 0.9,
                "impact": "CORS policy accepts arbitrary origins",
            }

        # High: null origin accepted
        if origin == "null" and acao == "null":
            severity = "HIGH" if credentials_enabled else "MEDIUM"
            return {
                "type": "null_origin_accepted",
                "description": "null origin accepted in ACAO",
                "severity": severity,
                "confidence": 0.85,
                "impact": "Sandboxed iframe or file:// origin can make credentialed requests",
            }

        # High: wildcard + credentials (technically invalid but some implementations allow)
        if acao == "*" and credentials_enabled:
            return {
                "type": "wildcard_with_credentials",
                "description": "ACAO: * combined with ACAC: true",
                "severity": "HIGH",
                "confidence": 0.8,
                "impact": "Wildcard with credentials is misconfigured",
            }

        # Medium: subdomain bypass
        if acao == origin and f".{target_host}" in origin:
            return {
                "type": "subdomain_bypass",
                "description": f"Subdomain '{origin}' accepted — XSS on any subdomain gives full access",
                "severity": "MEDIUM",
                "confidence": 0.75,
                "impact": "Subdomain takeover or XSS on subdomain enables CORS bypass",
            }

        # Medium: prefix/suffix bypass
        if acao == origin and target_host in origin and origin != f"https://{target_host}":
            return {
                "type": "origin_prefix_bypass",
                "description": f"Origin '{origin}' accepted (contains target host but is not the target)",
                "severity": "MEDIUM",
                "confidence": 0.7,
                "impact": "Prefix/suffix bypass in origin validation",
            }

        return None

    def _test_preflight(self, url: str) -> Optional[Dict]:
        """Test preflight OPTIONS request for permissive configuration."""
        try:
            response = self.http_client.request(
                "OPTIONS",
                url,
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Header, Authorization",
                },
                timeout=10,
            )

            acam = response.headers.get("Access-Control-Allow-Methods", "")
            acah = response.headers.get("Access-Control-Allow-Headers", "")
            acao = response.headers.get("Access-Control-Allow-Origin", "")

            if acao == "https://evil.com" and "PUT" in acam:
                return {
                    "type": "permissive_preflight",
                    "description": "Preflight allows arbitrary origin and dangerous methods",
                    "severity": "HIGH",
                    "confidence": 0.75,
                    "allowed_methods": acam,
                    "allowed_headers": acah,
                }
        except Exception as e:
            logger.debug(f"[CORS] Preflight test failed for {url}: {e}")
        return None


def detect_cors(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for CORS misconfiguration detection."""
    detector = CORSScanner(state=state)
    return detector.detect(endpoints, progress_cb)
