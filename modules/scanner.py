"""
modules/scanner.py - Scanning Engine
AI-driven vulnerability scanning with payload generation and mutation
"""

import json
import os
import logging
from typing import Dict, List, Any
import time
import base64
import concurrent.futures
import urllib.parse

from core.state_manager import StateManager
from core.http_engine import HTTPClient
from ai.payload_gen import PayloadGenerator
from ai.payload_mutation import PayloadMutator
from learning.learning_engine import LearningEngine
from integrations.dalfox_runner import DalfoxRunner
from integrations.nuclei_runner import NucleiRunner
from core.executor import run_command, tool_available

logger = logging.getLogger("recon.scanning")


class ScanningEngine:
    """
    Intelligent vulnerability scanning engine.
    Uses AI-generated payloads, applies mutations, and tests endpoints.
    """

    def __init__(self, state: StateManager, output_dir: str,
                 payload_gen: PayloadGenerator, payload_mutator: PayloadMutator,
                 learning_engine: LearningEngine):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.http_client = HTTPClient()
        self.payload_gen = payload_gen
        self.payload_mutator = payload_mutator
        self.learning_engine = learning_engine
        self.dalfox_runner = DalfoxRunner(output_dir)
        self.nuclei_runner = NucleiRunner(output_dir)

        self.scan_results_file = os.path.join(output_dir, "scan_results.json")

    def run(self):
        """Execute vulnerability scanning pipeline"""
        logger.info("[SCANNING] Starting AI-driven vulnerability scanning")

        prioritized_endpoints = self.state.get("prioritized_endpoints", [])
        budget = (self.state.get("scan_metadata", {}) or {}).get("budget", {})
        self.max_endpoints = int(self.state.get("max_endpoints", budget.get("scan_prioritized_endpoints", 140)))

        # Use parallel execution for scanning endpoints
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.scan_endpoint, endpoint) for endpoint in prioritized_endpoints[:self.max_endpoints]]
            for future in concurrent.futures.as_completed(futures, timeout=300):  # 5 min timeout per endpoint
                try:
                    self.process_endpoint_results(future.result())
                except concurrent.futures.TimeoutError:
                    logger.error("[SCANNING] Endpoint scan timed out")
                except Exception as e:
                    logger.error(f"[SCANNING] Failed to scan endpoint: {e}")

        logger.info("[SCANNING] Completed scanning - results streamed to file")

    def process_endpoint_results(self, responses: List[Dict[str, Any]]):
        """Process and stream endpoint results to file"""
        with open(self.scan_results_file, 'a') as f:
            for response in responses:
                json.dump(response, f)
                f.write('\n')  # JSONL format

    def scan_endpoint(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan a single endpoint with AI-generated payloads"""
        url = endpoint.get("url", "")
        categories = endpoint.get("categories", [])
        parameters = endpoint.get("parameters", [])

        logger.debug(f"[SCANNING] Scanning {url} (categories: {categories})")

        responses = []
        auth_contexts = self._get_auth_contexts()

        # Get baseline response (normal request without payload)
        baseline_response = self.get_baseline_response(url)
        if not baseline_response:
            logger.debug(f"[SCANNING] Failed to get baseline for {url}")
            return responses

        # Decision logic: auto-detect and call external tools
        if parameters:
            if self._detect_sqli_potential(endpoint):
                self._run_sqlmap(url, parameters)
            if self._detect_xss_potential(endpoint):
                dalfox_result = self.dalfox_runner.run(url)
                if dalfox_result.get("success"):
                    vuln = {"type": "xss", "url": url, "tool": "dalfox", "output": dalfox_result["output"]}
                    current_vulns = self.state.get("vulnerabilities", [])
                    current_vulns.append(vuln)
                    self.state.update(vulnerabilities=current_vulns)

        # Run nuclei for general scan
        if parameters or any(kw in url for kw in ["admin", "login", "api"]):
            nuclei_result = self.nuclei_runner.run(url)
            if nuclei_result.get("success"):
                vuln = {"type": "general", "url": url, "tool": "nuclei", "output": nuclei_result["output"]}
                current_vulns = self.state.get("vulnerabilities", [])
                current_vulns.append(vuln)
                self.state.update(vulnerabilities=current_vulns)

        # Generate payloads based on endpoint type
        for category in categories:
            if category == "xss":
                context = self._detect_xss_context(baseline_response.get("content", ""))
                payloads = self.payload_gen.generate_xss(context, self.get_max_payloads_for_category(category))
            else:
                payloads = self.payload_gen.generate_for_category(category, parameters)

            # Apply mutations
            mutated_payloads = self.payload_mutator.mutate_payloads(payloads)

            # Determine payload count based on category risk
            max_payloads = self.get_max_payloads_for_category(category)

            # Test payloads
            for payload_item in mutated_payloads[:max_payloads]:
                payload = {}
                try:
                    # Normalize payload to dictionary format
                    if isinstance(payload_item, str):
                        payload = {"value": payload_item, "method": "GET", "params": {}}
                    elif isinstance(payload_item, dict):
                        payload = payload_item
                    else:
                        logger.warning(f"Skipping unknown payload type: {type(payload_item)}")
                        continue

                    for auth_ctx in auth_contexts:
                        response = self.test_payload(url, payload, category, baseline_response, auth_ctx)
                        response["auth_role"] = auth_ctx.get("role")
                        responses.append(response)

                        if response.get("vulnerable"):
                            self.learning_engine.add_successful_payload(payload, category)
                        else:
                            # Mutate and retry on failure - using the original string value
                            payload_value = payload.get("value", "")
                            if not isinstance(payload_value, str):
                                continue  # Cannot mutate non-string value

                            mutated = self.payload_mutator.mutate_payloads([payload_value])
                            for p_str in mutated[:2]:
                                # Normalize again for testing
                                p = {"value": p_str, "method": "GET", "params": {}}
                                resp = self.test_payload(url, p, category, baseline_response, auth_ctx)
                                resp["auth_role"] = auth_ctx.get("role")
                                responses.append(resp)
                                if resp.get("vulnerable"):
                                    self.learning_engine.add_successful_payload(p, category)
                                    break

                    # Small delay to avoid overwhelming
                    time.sleep(0.1)

                except Exception as e:
                    logger.error(f"[PAYLOAD] Failed to test payload on {url}: {e} (payload: {payload})")

        return responses

    def get_baseline_response(self, url: str) -> Dict[str, Any]:
        """Get baseline response for comparison and tech fingerprinting"""
        try:
            response = self.http_client.get(url, timeout=10)
            
            # Detect tech stack
            tech_detected = self._detect_tech_stack(response)
            if tech_detected:
                current_tech = set(self.state.get("tech_stack", []))
                current_tech.update(tech_detected)
                self.state.update(tech_stack=list(current_tech))
            
            return {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "response_time": response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                "content": response.text,
                "headers": dict(response.headers),
                "tech": tech_detected
            }
        except Exception as e:
            logger.debug(f"[SCANNING] Baseline request failed for {url}: {e}")
            return None

    def _detect_tech_stack(self, response) -> set:
        """Detect technology stack from response"""
        tech = set()
        headers = response.headers
        body = response.text.lower()
        
        # Server headers
        server = headers.get('server', '').lower()
        if 'apache' in server:
            tech.add('apache')
        if 'nginx' in server:
            tech.add('nginx')
        if 'iis' in server:
            tech.add('iis')
        
        # Powered by
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            tech.add('php')
        if 'asp.net' in powered_by:
            tech.add('asp.net')
        if 'nodejs' in powered_by or 'node' in powered_by:
            tech.add('nodejs')
        
        # Body patterns
        if 'wp-content' in body or 'wordpress' in body:
            tech.add('wordpress')
        if 'laravel' in body or 'csrf-token' in body:
            tech.add('laravel')
        if 'jquery' in body:
            tech.add('jquery')
        if 'bootstrap' in body:
            tech.add('bootstrap')
        if 'react' in body:
            tech.add('react')
        if 'vue' in body:
            tech.add('vue')
        if 'angular' in body:
            tech.add('angular')
        
        # API patterns
        if '/api/' in body or 'swagger' in body:
            tech.add('api')
        if 'graphql' in body:
            tech.add('graphql')
        
        return tech

    def get_max_payloads_for_category(self, category: str) -> int:
        """Determine maximum payloads to test based on category risk"""
        high_risk = ['sql_injection', 'command_injection', 'xss', 'file_inclusion']
        if category in high_risk:
            return 20  # More payloads for high-risk categories
        return 10  # Default

    def test_payload(
        self,
        url: str,
        payload: Dict[str, Any],
        category: str,
        baseline: Dict[str, Any],
        auth_ctx: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Test a single payload against an endpoint with baseline comparison and WAF bypass"""
        payload_value = payload.get("value", "")
        method = payload.get("method", "GET")
        params = payload.get("params", {})
        auth_ctx = auth_ctx or {}
        req_headers = auth_ctx.get("headers", {}) or {}
        req_cookies = auth_ctx.get("cookies", {}) or {}

        max_retries = 3
        mutations = self.payload_mutator._apply_waf_bypass(payload_value)
        import random
        random.shuffle(mutations)  # Randomize order
        
        for mutation in [payload_value] + mutations:  # Try original first, then mutations
            waf_bypass_attempted = mutation != payload_value
            
            for attempt in range(max_retries):
                try:
                    # Prepare request
                    if method == "GET":
                        parsed = urllib.parse.urlparse(url)
                        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                        if query_pairs:
                            first_key = query_pairs[0][0]
                            query_pairs[0] = (first_key, mutation)
                        else:
                            inject_key = next(iter(params.keys()), "q") if isinstance(params, dict) else "q"
                            query_pairs.append((inject_key, mutation))
                        new_query = urllib.parse.urlencode(query_pairs, doseq=True)
                        test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                        response = self.http_client.get(test_url, timeout=10, headers=req_headers, cookies=req_cookies)
                    elif method == "POST":
                        post_data = dict(params) if isinstance(params, dict) else {}
                        if post_data:
                            first_key = next(iter(post_data.keys()))
                            post_data[first_key] = mutation
                        else:
                            post_data = {"q": mutation}
                        response = self.http_client.post(url, data=post_data, timeout=10, headers=req_headers, cookies=req_cookies)
                    else:
                        # Default to GET
                        response = self.http_client.get(url, timeout=10, headers=req_headers, cookies=req_cookies)

                    # Check for WAF blocking
                    if self._is_waf_blocked(response):
                        if not waf_bypass_attempted:
                            break  # Try next mutation
                        else:
                            logger.debug(f"[WAF] Bypass failed for {url}")
                            continue  # Try next attempt
                    
                    # If we reach here, WAF bypassed or no WAF
                    if waf_bypass_attempted:
                        logger.info(f"[WAF] Bypass successful with mutation for {url}")

                    # Analyze response with baseline comparison
                    analysis = self.analyze_response(response, baseline, {"value": mutation}, category)

                    if analysis.get("vulnerable"):
                        logger.info(f"[VULN] Potential {category} vulnerability detected on {url} (confidence: {analysis.get('confidence', 0)})")

                    return {
                        "endpoint": url,
                        "payload": mutation,
                        "method": method,
                        "status_code": response.status_code,
                        "content_length": len(response.text),
                        "response_time": response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                        "baseline_status": baseline["status_code"],
                        "baseline_length": baseline["content_length"],
                        "baseline_time": baseline["response_time"],
                        "category": category,
                        "vulnerable": analysis.get("vulnerable", False),
                        "confidence": analysis.get("confidence", 0),
                        "reason": analysis.get("reason", ""),
                        "timestamp": time.time()
                    }
                except Exception as e:
                    if attempt == max_retries - 1:
                        logger.debug(f"[SCANNING] Payload test failed after {max_retries} attempts: {e}")
                        # Return a failed result
                        return {
                            "endpoint": url,
                            "payload": mutation,
                            "method": method,
                            "status_code": 0,
                            "content_length": 0,
                            "response_time": 0,
                            "baseline_status": baseline["status_code"],
                            "baseline_length": baseline["content_length"],
                            "baseline_time": baseline["response_time"],
                            "category": category,
                            "vulnerable": False,
                            "confidence": 0,
                            "reason": "Request failed",
                            "timestamp": time.time()
                        }
                    time.sleep(1)  # Wait before retry
            
            # If all retries failed for this mutation, try next
            if waf_bypass_attempted:
                continue
        
        # All mutations failed
        return {
            "endpoint": url,
            "payload": payload_value,
            "method": method,
            "status_code": 0,
            "content_length": 0,
            "response_time": 0,
            "baseline_status": baseline["status_code"],
            "baseline_length": baseline["content_length"],
            "baseline_time": baseline["response_time"],
            "category": category,
            "vulnerable": False,
            "confidence": 0,
            "reason": "All WAF bypass attempts failed",
            "timestamp": time.time()
        }

    def _is_waf_blocked(self, response) -> bool:
        """Detect if response indicates WAF blocking"""
        if response.status_code == 403:
            return True
        body = response.text.lower()
        waf_indicators = [
            "waf", "blocked", "forbidden", "access denied", "cloudflare",
            "akamai", "imperva", "sucuri", "mod_security", "firewall"
        ]
        return any(indicator in body for indicator in waf_indicators)

    def _apply_waf_bypass(self, payload: str, category: str) -> List[str]:
        """Apply multiple WAF bypass mutations"""
        mutations = []
        
        if category in ["sqli", "sql_injection"]:
            mutations = [
                payload.replace(" ", "/**/"),
                payload.replace("UNION", "UN/**/ION"),
                payload.replace("SELECT", "SEL/**/ECT"),
                payload.replace("'", "''"),
                payload.upper(),
                payload.replace(" ", "%20"),
                payload.replace(" ", "%0a"),
            ]
        elif category in ["xss"]:
            mutations = [
                payload.replace("<script>", "<scr<script>ipt>"),
                payload.replace("alert", "\\u0061lert"),
                base64.b64encode(payload.encode()).decode(),
                payload.replace("script", "ScRiPt"),
                payload.replace("<", "&lt;").replace(">", "&gt;"),
            ]
        elif category in ["rce", "command_injection"]:
            mutations = [
                payload.replace(" ", "${IFS}"),
                payload.replace(";", "`"),
                payload.replace("cat", "c\\at"),
                payload.replace(" ", "%20"),
            ]
        
        return mutations

    def analyze_response(self, response, baseline: Dict[str, Any], payload: Dict, category: str) -> Dict[str, Any]:
        """Analyze response for vulnerability indicators using baseline comparison and content analysis"""
        test_status = response.status_code
        test_length = len(response.text)
        test_time = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
        response_text = response.text.lower()

        base_status = baseline["status_code"]
        base_length = baseline["content_length"]
        base_time = baseline["response_time"]
        payload_value = payload.get("value", "").lower()

        analysis = {
            "vulnerable": False,
            "confidence": 0.0,
            "reason": "No indicators detected"
        }

        # 1. Keyword-based error detection
        error_keywords = {
            "sql_injection": [
                "sql syntax", "mysql", "ora-", "syntax error", "database error",
                "sqlite", "postgresql", "you have an error in your sql",
                "unclosed quotation mark", "invalid sql statement"
            ],
            "command_injection": [
                "command not found", "permission denied", "access denied",
                "/bin/sh", "/bin/bash", "exec", "system()"
            ],
            "file_inclusion": [
                "failed to open stream", "no such file", "include_once",
                "require_once", "root:", "boot.ini", "etc/passwd"
            ],
            "general": [
                "warning", "fatal error", "parse error", "exception",
                "stack trace", "unexpected token", "uncaught exception",
                "error 500", "internal server error"
            ]
        }

        keyword_score = 0.0
        detected_errors = []

        # Check category-specific keywords
        for kw in error_keywords.get(category, []):
            if kw in response_text:
                keyword_score += 0.3
                detected_errors.append(kw)

        # Check general error keywords
        for kw in error_keywords["general"]:
            if kw in response_text:
                keyword_score += 0.2
                detected_errors.append(kw)

        if detected_errors:
            analysis["confidence"] += keyword_score
            analysis["reason"] = f"Error keywords detected: {', '.join(detected_errors[:3])}"

        # 2. Reflection detection (for XSS and similar)
        reflection_score = 0.0
        if payload_value and len(payload_value) > 3:  # Avoid false positives with short payloads
            if payload_value in response_text:
                if category in ["xss", "html_injection"]:
                    reflection_score = 0.5
                    analysis["reason"] += f" (payload reflected in response)"
                else:
                    reflection_score = 0.2  # Less confident for other categories

        analysis["confidence"] += reflection_score

        # 3. Status code anomaly
        status_score = 0.0
        if test_status != base_status:
            if test_status in [500, 502, 503] and base_status == 200:
                status_score = 0.8
                analysis["reason"] = f"Status code changed from {base_status} to {test_status} (server error)"
            elif test_status == 200 and base_status != 200:
                status_score = 0.6
                analysis["reason"] = f"Status code changed from {base_status} to {test_status}"
            elif test_status >= 400 and base_status < 400:
                status_score = 0.4
                analysis["reason"] = f"Status code changed from {base_status} to {test_status} (client/server error)"

        analysis["confidence"] += status_score

        # 4. Content length anomaly
        length_score = 0.0
        if not analysis["vulnerable"]:  # Only if not already high confidence
            length_diff = abs(test_length - base_length)
            length_ratio = length_diff / max(base_length, 1)
            if length_ratio > 0.5:  # More than 50% difference
                length_score = 0.7
                analysis["reason"] = f"Content length changed significantly ({base_length} -> {test_length})"
            elif length_ratio > 0.2:  # More than 20% difference
                length_score = 0.3

        analysis["confidence"] += length_score

        # 5. Timing anomaly (for blind injections) - enhanced detection
        timing_score = 0.0
        time_diff = test_time - base_time
        
        # Different timing thresholds based on vulnerability type
        if category in ["sql_injection", "sqli"]:
            # SQL timing attacks (SLEEP, BENCHMARK, etc.)
            if test_time > 3 and base_time < 1:  # Strong indicator
                timing_score = 0.8
                analysis["reason"] = f"SQL timing attack detected ({base_time:.2f}s -> {test_time:.2f}s)"
            elif time_diff > 2:  # Moderate delay
                timing_score = 0.5
                analysis["reason"] = f"Response delayed by {time_diff:.2f}s (possible SQL injection)"
                
        elif category in ["command_injection", "rce"]:
            # Command execution timing
            if test_time > 2 and base_time < 0.5:  # Command execution delay
                timing_score = 0.7
                analysis["reason"] = f"Command execution delay detected ({base_time:.2f}s -> {test_time:.2f}s)"
            elif time_diff > 1:  # Moderate command delay
                timing_score = 0.4
                
        else:
            # General timing anomaly
            if test_time > 5 and base_time < 2:  # Significant delay
                timing_score = 0.6
                analysis["reason"] = f"Response time increased significantly ({base_time:.2f}s -> {test_time:.2f}s)"
            elif test_time > base_time * 2:  # Doubled time
                timing_score = 0.4

        analysis["confidence"] += timing_score

        # Determine if vulnerable based on confidence threshold
        if analysis["confidence"] >= 0.5:
            analysis["vulnerable"] = True
        elif analysis["confidence"] >= 0.3 and (keyword_score > 0 or reflection_score > 0):
            analysis["vulnerable"] = True  # Lower threshold for direct indicators

        # Cap confidence at 1.0
        analysis["confidence"] = min(analysis["confidence"], 1.0)

        return analysis

    def _detect_sqli_potential(self, endpoint: Dict[str, Any]) -> bool:
        """Detect if endpoint is likely vulnerable to SQLi"""
        parameters = endpoint.get("parameters", [])
        if not parameters:
            return False
        dangerous = {"id", "user", "uid", "page", "item", "cat", "query", "search", "q"}
        return any(str(p).lower() in dangerous for p in parameters)

    def _detect_xss_potential(self, endpoint: Dict[str, Any]) -> bool:
        """Detect if endpoint is likely vulnerable to XSS"""
        parameters = endpoint.get("parameters", [])
        return len(parameters) > 0

    def _get_auth_contexts(self) -> List[Dict[str, Any]]:
        """Return contexts for unauthenticated + authenticated role scans."""
        contexts = [{"role": "anonymous", "cookies": {}, "headers": {}}]
        sessions = self.state.get("authenticated_sessions", [])
        for item in sessions:
            if item.get("success"):
                contexts.append(
                    {
                        "role": item.get("role", "unknown"),
                        "cookies": item.get("cookies", {}) or {},
                        "headers": item.get("headers", {}) or {},
                    }
                )
            if len(contexts) >= 4:
                break
        return contexts

    def _run_sqlmap(self, url: str, parameters: List[str]):
        """Best-effort sqlmap execution for high-signal parameterized endpoints."""
        if not tool_available("sqlmap"):
            return
        marker = parameters[0] if parameters else "id"
        target = url if "?" in url else f"{url}?{marker}=1"
        cmd = ["sqlmap", "-u", target, "--batch", "--level=2", "--risk=1", "--smart"]
        ret, out, err = run_command(cmd, timeout=180)
        if ret == 0 and out:
            vuln = {"type": "sqli", "url": target, "tool": "sqlmap", "output": out[:2000]}
            current_vulns = self.state.get("vulnerabilities", [])
            current_vulns.append(vuln)
            self.state.update(vulnerabilities=current_vulns)
        elif ret not in (0, -1):
            logger.debug(f"[SCANNING] sqlmap non-zero for {target}: {err[:120]}")

    def _detect_xss_context(self, response_text: str) -> str:
        """Detect XSS context from response"""
        if '<script' in response_text.lower():
            return "javascript"
        elif 'href=' in response_text or 'src=' in response_text:
            return "attribute"
        else:
            return "html"
