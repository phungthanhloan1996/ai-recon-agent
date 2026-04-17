"""
modules/crlf_injection.py - CRLF Injection Detector
Detects HTTP header injection via %0d%0a, %0a, and other CRLF payloads.
Covers: header injection, response splitting, cookie injection, log injection.
"""

import logging
import urllib.parse
from typing import Dict, List, Any, Optional

logger = logging.getLogger("recon.crlf_injection")

# ── Payloads ──────────────────────────────────────────────────────────────────
_CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:crlf=injected",
    "%0aSet-Cookie:crlf=injected",
    "%0d%0aLocation:https://evil.com",
    "%0d%0aX-CRLF-Injected:true",
    "\r\nSet-Cookie:crlf=injected",
    "\nSet-Cookie:crlf=injected",
    "%E5%98%8D%E5%98%8ASet-Cookie:crlf=injected",   # Unicode overlong
    "%u000dSet-Cookie:crlf=injected",
    "%%0d%%0aSet-Cookie:crlf=injected",             # Double encoding
    "%0d%0a%20Set-Cookie:crlf=injected",            # Folded header
]

# Response headers to check for injected values
_INJECTION_INDICATORS = [
    "crlf=injected",
    "x-crlf-injected",
    "set-cookie: crlf",
    "location: https://evil",
]

# Parameters commonly used in redirects / header manipulation
_REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "return", "return_url",
    "next", "next_url", "goto", "redir", "location", "dest",
    "destination", "target", "path", "ref", "referrer",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_response_for_injection(response, payload: str) -> bool:
    """Return True if the response headers reflect the injected CRLF payload."""
    if response is None:
        return False
    # Check response headers
    headers_str = "\n".join(
        f"{k.lower()}: {v.lower()}" for k, v in response.headers.items()
    )
    body_lower = (response.text or "")[:2000].lower()
    for indicator in _INJECTION_INDICATORS:
        if indicator in headers_str or indicator in body_lower:
            return True
    return False


def _inject_into_url(base_url: str, param: str, payload: str) -> str:
    """Build a test URL with the CRLF payload injected into `param`."""
    parsed = urllib.parse.urlparse(base_url)
    params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    params[param] = payload
    new_query = urllib.parse.urlencode(params)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


# ── Main detector ─────────────────────────────────────────────────────────────

def detect_crlf_injection(
    state: Any,
    endpoints: List[Any],
    http_client: Any = None,
) -> Dict[str, Any]:
    """
    Tier-3 entry point for CRLF injection detection.

    Strategy:
    1. For endpoints that already have redirect-related parameters, inject CRLF
       payloads and observe response headers.
    2. For endpoints without such params, append common redirect params with
       CRLF payloads and check responses.
    """
    if http_client is None:
        try:
            from core.http_engine import HTTPClient
            http_client = HTTPClient(timeout=10)
        except Exception:
            logger.warning("[CRLF] HTTPClient unavailable")
            return {"vulnerabilities": [], "endpoints_tested": 0}

    vulnerabilities: List[Dict[str, Any]] = []
    tested = 0
    # Deduplicate by (netloc, param): same underlying server misconfiguration
    # affects every URL on the domain — report once per domain+param combo.
    seen_vulns: set = set()

    # Path keywords that suggest redirect/header-manipulation behaviour
    _REDIRECT_PATH_HINTS = {
        "redirect", "auth", "login", "oauth", "callback", "return",
        "goto", "next", "sso", "saml", "logout", "forward",
    }

    for ep in (endpoints or [])[:40]:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url or not url.startswith(("http://", "https://")):
            continue

        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc
        existing_params = list(urllib.parse.parse_qs(parsed.query).keys())

        # Which params to test: existing redirect params come first
        params_to_test = [p for p in existing_params if p.lower() in _REDIRECT_PARAMS]
        if not params_to_test:
            # Only inject generic params when the path itself hints at redirect behaviour
            path_lower = parsed.path.lower()
            if any(kw in path_lower for kw in _REDIRECT_PATH_HINTS):
                params_to_test = _REDIRECT_PARAMS[:3]
            else:
                continue  # no redirect params and no redirect path — skip

        for param in params_to_test:
            # Skip if we already confirmed CRLF for this domain+param
            if (netloc, param) in seen_vulns:
                continue
            for payload in _CRLF_PAYLOADS[:5]:  # limit probes per endpoint
                test_url = _inject_into_url(url, param, payload)
                try:
                    resp = http_client.get(test_url, timeout=8, allow_redirects=False)
                    tested += 1

                    if _check_response_for_injection(resp, payload):
                        seen_vulns.add((netloc, param))
                        vuln = {
                            "type": "crlf_injection",
                            "url": url,
                            "parameter": param,
                            "payload": payload,
                            "severity": "HIGH",
                            "confidence": 0.85,
                            "evidence": f"CRLF payload reflected in response headers (param={param})",
                            "source": "crlf_injection_detector",
                            "remediation": "Sanitize all user-supplied values before including in HTTP response headers. Strip or encode CR (\\r) and LF (\\n) characters.",
                        }
                        vulnerabilities.append(vuln)
                        logger.warning(
                            f"[CRLF] Injection confirmed: {netloc} param={param} payload={payload!r}"
                        )
                        break  # one confirmed payload per param is enough
                except Exception as e:
                    logger.debug(f"[CRLF] Probe failed {test_url}: {e}")

    logger.info(f"[CRLF] Tested {tested} probes, found {len(vulnerabilities)} injections")
    return {
        "vulnerabilities": vulnerabilities,
        "endpoints_tested": tested,
        "crlf_confirmed": len(vulnerabilities),
    }
