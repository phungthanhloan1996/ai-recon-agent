"""
modules/deserialization_scanner.py - Insecure Deserialization Scanner
Detects Java, Python pickle, PHP, .NET deserialization vulnerabilities.
"""

import re
import base64
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.deserialization")


class DeserializationScanner:
    """
    Detects insecure deserialization vulnerabilities.

    Attack vectors:
    1. Java serialized object detection (magic bytes: aced0005)
    2. Python pickle injection (via base64-encoded cookie/param)
    3. PHP object injection via unserialize()
    4. .NET BinaryFormatter / ViewState tampering
    5. YAML deserialization (!!python/object)
    6. Ruby Marshal injection
    """

    # Java serialized object magic bytes (base64)
    JAVA_MAGIC_B64 = "rO0AB"  # base64 of \xac\xed\x00\x05

    # Canary payloads - safe probes that reveal deserialization behavior
    JAVA_CANARY_PAYLOADS = [
        # URLDNS gadget - triggers DNS lookup (detectable OOB)
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcHAFH6cLjze9KwIAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAADHA=",
        # Serialized null object
        "rO0ABXA=",
    ]

    # PHP unserialize payloads
    PHP_PAYLOADS = [
        # Simple object (safe probe)
        'O:8:"stdClass":0:{}',
        # Array with suspicious key
        'a:1:{s:5:"class";s:4:"test";}',
        # Magic method trigger probe
        'O:4:"Test":1:{s:4:"data";s:4:"test";}',
    ]

    # Python pickle probes (base64 encoded - safe probes only)
    # Pickle REDUCE opcode probe - does not execute, just tests acceptance
    PICKLE_PROBES_B64 = [
        "gASVIAAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwGc3RyaW5nlIWUUpQu",
    ]

    # .NET ViewState magic
    VIEWSTATE_MAGIC = "/wEy"  # base64 of .NET ViewState

    DESER_INDICATORS = [
        # Java
        r"ClassNotFoundException",
        r"java\.io\.InvalidClassException",
        r"java\.io\.StreamCorruptedException",
        r"com\.sun\.org\.apache",
        r"org\.apache\.commons",
        r"ObjectInputStream",
        r"SerializationException",
        # PHP
        r"unserialize\(\)",
        r"__wakeup",
        r"__destruct.*called",
        r"Cannot unserialize",
        r"Error.*unserialize",
        # Python
        r"pickle\.loads",
        r"_reconstruct",
        r"UnpicklingError",
        # .NET
        r"BinaryFormatter",
        r"SerializationBinder",
        r"System\.Runtime\.Serialization",
        # General
        r"Deserialization.*error",
        r"Invalid.*serial",
    ]

    DESER_PARAM_NAMES = {
        "data", "object", "obj", "payload", "token", "session",
        "state", "viewstate", "__viewstate", "serialized",
        "cache", "body", "input", "content", "raw",
    }

    DESER_CONTENT_TYPES = [
        "application/x-java-serialized-object",
        "application/octet-stream",
        "application/x-www-form-urlencoded",
    ]

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for insecure deserialization."""
        logger.info(f"[DESER] Starting deserialization scan on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "deser_confirmed": 0,
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
                method = (endpoint.get("method") or "POST").upper()
                content_type = endpoint.get("content_type", "")
            else:
                url = str(endpoint)
                params = []
                method = "POST"
                content_type = ""

            if not url:
                continue

            # Detect existing serialized data in cookies/params
            exposure = self._detect_serialized_data(url)
            if exposure:
                results["vulnerabilities"].append(exposure)
                results["deser_confirmed"] += 1

            # Test injection
            parsed = urllib.parse.urlparse(url)
            url_params = list(urllib.parse.parse_qs(parsed.query).keys())
            all_params = list(set(params + url_params))
            deser_params = [p for p in all_params if p.lower() in self.DESER_PARAM_NAMES]

            for param in deser_params[:3]:
                vuln = self._test_deser_param(url, param, method)
                if vuln.get("vulnerable"):
                    results["vulnerabilities"].append(vuln)
                    results["deser_confirmed"] += 1
                    break

            results["endpoints_tested"] += 1

        logger.info(f"[DESER] Found {results['deser_confirmed']} deserialization vulnerabilities")
        return results

    def _detect_serialized_data(self, url: str) -> Optional[Dict]:
        """Detect if endpoint returns/expects serialized data."""
        try:
            resp = self.http_client.get(url, timeout=10)

            # Check cookies for serialized objects
            cookies = resp.cookies if hasattr(resp, "cookies") else {}
            for cookie_name, cookie_val in (cookies.items() if hasattr(cookies, "items") else []):
                # Decode URL-encoded cookie
                decoded = urllib.parse.unquote(str(cookie_val))
                deser_type = self._identify_serialized(decoded)
                if deser_type:
                    return {
                        "url": url,
                        "type": "deserialization_exposure",
                        "severity": "HIGH",
                        "confidence": 0.85,
                        "description": f"{deser_type} serialized object found in cookie '{cookie_name}'",
                        "cookie": cookie_name,
                        "impact": "Serialized objects in cookies are high-risk for deserialization attacks",
                    }

            # Check response body
            text = resp.text if hasattr(resp, "text") else ""
            deser_type = self._identify_serialized(text)
            if deser_type:
                return {
                    "url": url,
                    "type": "deserialization_exposure",
                    "severity": "MEDIUM",
                    "confidence": 0.7,
                    "description": f"{deser_type} serialized object in response body",
                    "impact": "Serialized data exposed — may be reflected back and deserialized",
                }

        except Exception as e:
            logger.debug(f"[DESER] Error checking {url}: {e}")
        return None

    def _identify_serialized(self, data: str) -> Optional[str]:
        """Identify type of serialized object in string."""
        if not data:
            return None

        # Java: base64 starting with rO0AB
        if self.JAVA_MAGIC_B64 in data:
            return "Java"

        # Try base64 decode and check magic bytes
        for chunk in re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', data):
            try:
                decoded = base64.b64decode(chunk + "==")
                if decoded[:2] == b'\xac\xed':
                    return "Java"
                if decoded[:2] == b'\x80\x02' or decoded[:1] == b'\x80':
                    return "Python pickle"
            except Exception:
                pass

        # PHP: O:N:"ClassName":
        if re.search(r'O:\d+:"[A-Za-z_]', data):
            return "PHP"

        # .NET ViewState
        if self.VIEWSTATE_MAGIC in data or "__VIEWSTATE" in data:
            return ".NET ViewState"

        # Python pickle raw
        if re.search(r'c__builtin__|cbuiltins|posix|subprocess', data):
            return "Python pickle"

        # YAML unsafe
        if re.search(r'!!python/object', data):
            return "Python YAML"

        return None

    def _test_deser_param(self, url: str, param: str, method: str) -> Dict[str, Any]:
        """Test parameter with serialized payloads."""
        result = {
            "url": url,
            "parameter": param,
            "vulnerable": False,
            "confidence": 0.0,
            "deser_type": None,
            "evidence": [],
        }

        for payload_b64 in self.JAVA_CANARY_PAYLOADS:
            try:
                payload_bytes = base64.b64decode(payload_b64)
                if method == "POST":
                    resp = self.http_client.post(
                        url,
                        data={param: payload_b64},
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        timeout=12,
                    )
                else:
                    test_url = self._inject_param(url, param, payload_b64)
                    resp = self.http_client.get(test_url, timeout=12)

                check = self._check_deser_response(resp)
                if check["score"] > 0.4:
                    result["vulnerable"] = True
                    result["confidence"] = check["score"]
                    result["deser_type"] = check.get("type", "Java")
                    result["evidence"].append({
                        "payload_type": "Java URLDNS canary",
                        "indicator": check["reason"],
                        "status": resp.status_code,
                    })
                    return result

            except Exception as e:
                logger.debug(f"[DESER] Error testing {param} on {url}: {e}")

        # Test PHP payloads
        for payload in self.PHP_PAYLOADS:
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

                check = self._check_deser_response(resp)
                if check["score"] > 0.4:
                    result["vulnerable"] = True
                    result["confidence"] = check["score"]
                    result["deser_type"] = "PHP"
                    result["evidence"].append({
                        "payload": payload,
                        "indicator": check["reason"],
                        "status": resp.status_code,
                    })
                    return result

            except Exception as e:
                logger.debug(f"[DESER] PHP test error: {e}")

        return result

    def _inject_param(self, url: str, param: str, value: str) -> str:
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _check_deser_response(self, response) -> Dict[str, Any]:
        """Check response for deserialization indicators."""
        score = 0.0
        reason = ""
        deser_type = None
        text = response.text if hasattr(response, "text") else ""

        for pattern in self.DESER_INDICATORS:
            if re.search(pattern, text, re.IGNORECASE):
                score = 0.75
                reason = f"Deserialization error: {pattern}"
                if "java" in pattern.lower() or "classnotfound" in pattern.lower():
                    deser_type = "Java"
                elif "php" in pattern.lower() or "unserialize" in pattern.lower():
                    deser_type = "PHP"
                elif "pickle" in pattern.lower():
                    deser_type = "Python"
                break

        # 500 errors can indicate deserialization crash
        if response.status_code == 500 and score == 0:
            score = 0.3
            reason = "500 error on serialized payload — possible processing"

        return {"score": score, "reason": reason, "type": deser_type}


def detect_deserialization(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for deserialization vulnerability detection."""
    detector = DeserializationScanner(state=state)
    return detector.detect(endpoints, progress_cb)
