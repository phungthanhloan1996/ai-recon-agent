"""
modules/open_redirect.py - Open Redirect Detector
Detects open redirect vulnerabilities in URL/redirect parameters.
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.open_redirect")


class OpenRedirectDetector:
    """
    Detects open redirect vulnerabilities.

    Attack vectors:
    1. Direct URL parameter injection: ?redirect=https://evil.com
    2. Protocol-relative redirect: ?next=//evil.com
    3. Backslash bypass: ?url=https:\\\\evil.com
    4. URL encoding bypass: ?url=%68%74%74%70%73%3A%2F%2Fevil.com
    5. Double encoding: ?url=%252F%252Fevil.com
    6. JavaScript protocol: ?redirect=javascript:alert(1)
    7. Data URI: ?url=data:text/html,<script>...
    """

    REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "//evil.com/",
        "https://evil.com/",
        "https:evil.com",
        "https:\\\\evil.com",
        "/\\evil.com",
        "/%09/evil.com",
        "/%2F/evil.com",
        "/%5C/evil.com",
        "https://evil%E3%80%82com",
        "%68%74%74%70%73%3A%2F%2Fevil.com",
        "javascript:alert(document.domain)",
        "data:text/html,<script>alert(1)</script>",
    ]

    REDIRECT_PARAM_NAMES = {
        "redirect", "redirect_to", "redirect_url", "redirectUrl", "redirectUri",
        "redirect_uri", "return", "return_to", "returnUrl", "return_url",
        "next", "goto", "url", "target", "dest", "destination",
        "continue", "forward", "location", "link", "callback",
        "out", "view", "logoutRedirect", "successRedirect", "failureRedirect",
        "from", "back", "ref", "referer", "referrer", "origin",
        "path", "to", "navigate", "go",
    }

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for open redirect vulnerabilities."""
        logger.info(f"[REDIRECT] Starting open redirect detection on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "redirect_confirmed": 0,
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
            else:
                url = str(endpoint)
                params = []

            if not url:
                continue

            parsed = urllib.parse.urlparse(url)
            url_params = list(urllib.parse.parse_qs(parsed.query).keys())
            all_params = list(set(params + url_params))

            # Find redirect-susceptible params
            redirect_params = [p for p in all_params if p.lower() in self.REDIRECT_PARAM_NAMES]

            # Also check if URL has redirect-related path segments
            if not redirect_params:
                if any(kw in url.lower() for kw in ["redirect", "return", "next", "goto", "callback"]):
                    redirect_params = all_params[:3] if all_params else []

            for param in redirect_params:
                vuln = self._test_redirect(url, param)
                if vuln.get("vulnerable"):
                    results["vulnerabilities"].append(vuln)
                    results["redirect_confirmed"] += 1
                    break  # One finding per endpoint

            results["endpoints_tested"] += 1

        logger.info(f"[REDIRECT] Found {results['redirect_confirmed']} open redirect vulnerabilities")
        return results

    def _test_redirect(self, url: str, param: str) -> Dict[str, Any]:
        """Test a parameter for open redirect."""
        result = {
            "url": url,
            "parameter": param,
            "vulnerable": False,
            "confidence": 0.0,
            "evidence": [],
        }

        for payload in self.REDIRECT_PAYLOADS:
            try:
                test_url = self._inject_param(url, param, payload)
                resp = self.http_client.get(test_url, timeout=10)

                check = self._check_redirect(resp, payload)
                if check["score"] > 0.5:
                    result["vulnerable"] = True
                    result["confidence"] = max(result["confidence"], check["score"])
                    result["evidence"].append({
                        "payload": payload,
                        "indicator": check["reason"],
                        "status": resp.status_code,
                        "location": resp.headers.get("Location", ""),
                    })
                    if result["confidence"] >= 0.8:
                        return result

            except Exception as e:
                logger.debug(f"[REDIRECT] Error testing {param} on {url}: {e}")
                continue

        return result

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject redirect payload into parameter."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _location_host(location: str) -> str:
        """Extract the netloc (host) of a Location header value."""
        try:
            parsed = urllib.parse.urlparse(location)
            # Handle protocol-relative: //evil.com/path
            if not parsed.scheme and location.startswith("//"):
                parsed = urllib.parse.urlparse("https:" + location)
            return (parsed.netloc or "").lower()
        except Exception:
            return ""

    def _check_redirect(self, response, payload: str) -> Dict[str, Any]:
        """Check if response indicates open redirect."""
        score = 0.0
        reason = ""

        location = response.headers.get("Location", "")
        location_host = self._location_host(location)

        # A genuine open redirect means the HOST of the Location header is evil.com,
        # not merely that the query string of a same-origin redirect contains "evil.com"
        # (e.g., WordPress HTTP→HTTPS redirects preserving query params like ?url=https://evil.com).
        if response.status_code in [301, 302, 303, 307, 308]:
            if location_host == "evil.com":
                score = 0.95
                reason = f"Direct redirect to evil.com: {location}"
            elif "evil.com" in location_host:
                score = 0.9
                reason = f"Subdomain redirect to evil.com: {location}"
            elif "//" in location and "evil" in location_host:
                score = 0.9
                reason = f"Protocol-relative redirect: {location}"
            elif location and self._is_external_redirect(location):
                # Only flag if we injected an external payload and the Location is truly external
                if "evil.com" in payload.lower():
                    score = 0.7
                    reason = f"External redirect: {location}"
            elif location:
                # Same-origin redirect — not a vulnerability
                score = 0.0

        # Meta refresh or JS redirect in body — only valid if body contains
        # a redirect to evil.com's actual domain, not just in a parameter value.
        body = response.text if hasattr(response, "text") else ""
        evil_in_redirect_target = any(
            f'evil.com{sep}' in body.lower() or body.lower().endswith('evil.com')
            for sep in ['/', '"', "'", ' ']
        )
        if evil_in_redirect_target and any(x in body.lower() for x in
                                           ["window.location", "document.location",
                                            "meta http-equiv=\"refresh\""]):
            score = max(score, 0.75)
            reason = reason or "JavaScript/meta redirect to evil.com in response body"

        # JavaScript protocol
        if "javascript:" in payload.lower() and response.status_code in [301, 302, 303, 307, 308]:
            if "javascript:" in location.lower():
                score = max(score, 0.85)
                reason = reason or "JavaScript protocol redirect"

        return {"score": score, "reason": reason}

    def _is_external_redirect(self, location: str) -> bool:
        """Check if redirect location is external."""
        try:
            parsed = urllib.parse.urlparse(location)
            return bool(parsed.netloc) and parsed.netloc not in ["", "localhost", "127.0.0.1"]
        except Exception:
            return False


def detect_open_redirect(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for open redirect detection."""
    detector = OpenRedirectDetector(state=state)
    return detector.detect(endpoints, progress_cb)
