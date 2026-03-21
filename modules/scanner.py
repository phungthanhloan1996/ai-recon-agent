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

    def run(self, progress_cb=None):
        """Execute vulnerability scanning pipeline"""
        logger.info("[SCANNING] Starting AI-driven vulnerability scanning")

        # ✅ FIX: fallback nhiều nguồn
        prioritized_endpoints = (
            self.state.get("prioritized_endpoints")
            or self.state.get("scan_targets")
            or []
        )

        logger.warning(f"[SCANNING] Received {len(prioritized_endpoints)} endpoints")

        if not prioritized_endpoints:
            logger.error("[SCANNING] No endpoints to scan → exiting")
            return

        budget = (self.state.get("scan_metadata", {}) or {}).get("budget", {})
        self.max_endpoints = int(
            self.state.get("max_endpoints", budget.get("scan_prioritized_endpoints", 140))
        )

        # Ensure file exists (tránh missing file)
        try:
            open(self.scan_results_file, "a").close()
        except Exception as e:
            logger.error(f"[SCANNING] Cannot create scan_results.json: {e}")

        # Use parallel execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(self.scan_endpoint, endpoint)
                for endpoint in prioritized_endpoints[:self.max_endpoints]
            ]

            for future in concurrent.futures.as_completed(futures, timeout=300):
                try:
                    result = future.result()

                    if result:
                        self.process_endpoint_results(result)
                        completed = sum(1 for f in futures if f.done())
                        self.state.update(payloads_tested=completed)
                    if progress_cb:
                        progress_cb(completed)
                except concurrent.futures.TimeoutError:
                    logger.error("[SCANNING] Endpoint scan timed out")

                except Exception as e:
                    logger.error(f"[SCANNING] Failed to scan endpoint: {e}")

        logger.info("[SCANNING] Completed scanning - results streamed to file")

    def process_endpoint_results(self, responses: List[Dict[str, Any]]):
        """Process and stream endpoint results to file"""
        confirmed = self.state.get("confirmed_vulnerabilities", []) or []
        
        with open(self.scan_results_file, 'a') as f:
            for response in responses:
                json.dump(response, f)
                f.write('\n')  # JSONL format
                
                # FIX: Propagate confirmed vulnerabilities to state during scanning
                if response.get("vulnerable") and response.get("confidence", 0) >= 0.5:
                    vuln = {
                        "name": f"{response.get('category', 'unknown')} detection",
                        "endpoint": response.get("endpoint"),
                        "url": response.get("endpoint"),
                        "type": response.get("category", "unknown"),
                        "source": "ai_scan",
                        "payload": response.get("payload"),
                        "confidence": response.get("confidence", 0),
                        "evidence": response.get("reason", ""),
                        "auth_role": response.get("auth_role", "anonymous"),
                        "exploitable": response.get("exploitable", False),
                        "exploit_context": response.get("exploit_context", {})
                    }
                    confirmed.append(vuln)
        
        # Update state with propagated vulnerabilities
        if confirmed:
            self.state.update(confirmed_vulnerabilities=confirmed)
            # 🔥 FIX: SYNC confirmed_vulnerabilities INTO vulnerabilities
            all_vulns = self.state.get("vulnerabilities", []) + confirmed
            self.state.update(vulnerabilities=all_vulns)
            logger.debug(f"[SCANNING] Synced {len(confirmed)} vulnerabilities to vulnerabilities field")

    def scan_endpoint(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan a single endpoint with AI-generated payloads"""
        # Defensive: normalize endpoint structure
        if not isinstance(endpoint, dict):
            logger.warning(f"[SCANNING] Invalid endpoint type: {type(endpoint)}, skipping")
            return []
        
        url = endpoint.get("url", "")
        url = url.replace('\\/', '/').replace('\\/','/')  # fix escaped slashes

        categories = endpoint.get("categories", []) or []
        parameters = endpoint.get("parameters", []) or []
        
        # FIX: If no URL, skip
        if not url or not isinstance(url, str):
            logger.warning(f"[SCANNING] Invalid URL: {url}, skipping")
            return []
        
        # BUG 4 FIX: Skip static assets
        _SKIP_EXT = {'.css','.js','.png','.jpg','.jpeg','.gif','.ico','.woff','.woff2','.ttf','.svg','.map','.webp'}
        _parsed = urllib.parse.urlparse(url)
        if any(_parsed.path.endswith(ext) for ext in _SKIP_EXT):
            logger.debug(f"[SCANNING] Skipping static asset: {url}")
            return []
        
        # FIX: Auto-detect categories if empty (fallback heuristic)
        if not categories:
            detected = []
            url_lower = url.lower()
            
            # 🔥 FIX: Thêm detection cho WordPress và XML-RPC
            if 'xmlrpc' in url_lower:
                detected.append("rpc")
                detected.append("command_injection")  # XML-RPC có thể dẫn đến RCE
            if 'wp-' in url_lower or 'wordpress' in url_lower:
                detected.append("wordpress")
            if any(kw in url_lower for kw in ["admin", "login", "auth", "panel", "wp-admin"]):
                detected.append("authentication")
            if any(kw in url_lower for kw in ["upload", "file", "attachment", "wp-content/uploads"]):
                detected.append("file_upload")
            if any(kw in url_lower for kw in ["api", "json", "graphql", "wp-json"]):
                detected.append("api_injection")
            if any(kw in url_lower for kw in ["search", "query", "id=", "q=", "p=", "cat="]):
                detected.append("injection")
                detected.append("command_injection")
            
            # 🔥 FIX: Fallback mặc định
            if not detected:
                detected.append("general")
                detected.append("injection")  # Luôn test injection
                categories = detected
            else:
                categories = detected
            
            logger.debug(f"[SCANNING] Auto-detected categories for {url}: {categories}")       
        # FIX: Auto-detect parameters from URL if empty
        if not parameters:
            parameters = ["q"]
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                params_dict = urllib.parse.parse_qs(parsed.query)
                parameters = list(params_dict.keys())
                if parameters:
                    logger.debug(f"[SCANNING] Auto-detected parameters from URL: {parameters}")
        
        logger.debug(f"[SCANNING] Scanning {url} (categories: {categories}, params: {parameters})")
        
        # Store first parameter for exploitation context
        first_param = parameters[0] if parameters else None

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
        # BUG 6 FIX: Only run on URLs with real query params or important keywords
        parsed_url = urllib.parse.urlparse(url)
        has_real_query_params = bool(parsed_url.query)
        important_keywords = ["wp-admin", "api", "login", "admin", "graphql"]
        url_lower = url.lower()
        has_important_keyword = any(kw in url_lower for kw in important_keywords)
        
        if (has_real_query_params or has_important_keyword):
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
                        payload_value = payload_item

                    elif isinstance(payload_item, dict):
                        payload_value = payload_item.get("value", "")
                    else:
                        logger.warning(f"Skipping unknown payload type: {type(payload_item)}")
                        continue
                    payload = {"value": payload_value, "method": "GET", "params": {}}

                    for auth_ctx in auth_contexts:
                        response = self.test_payload(url, payload, category, baseline_response, auth_ctx)
                        response["auth_role"] = auth_ctx.get("role")
                        responses.append(response)

                        if response.get("vulnerable"):
                            # FIX: Mark exploitable if confidence is high
                            if response.get("confidence", 0) >= 0.7:
                                response["exploitable"] = True
                                response["exploit_context"] = {
                                    "category": category,
                                    "injection_point": first_param or "url",
                                    "auth_role": auth_ctx.get("role", "anonymous")
                                }
                            else:
                                response["exploitable"] = False
                                response["exploit_context"] = {}
                            
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
        # BUG 5 FIX: Cap mutations to 3, not unlimited
        mutations = self.payload_mutator._apply_waf_bypass(payload_value)[:3]
        import random
        random.shuffle(mutations)  # Randomize order
        
        waf_bypass_failed = False
        for mutation in [payload_value] + mutations:  # Try original first, then mutations
            waf_bypass_attempted = mutation != payload_value
            
            for attempt in range(max_retries):
                try:
                    # Prepare request - TEST ALL PARAMETERS, NOT JUST FIRST
                    if method == "GET":
                        parsed = urllib.parse.urlparse(url)
                        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                        
                        if query_pairs:
                            # Test injection in each parameter
                            for param_idx in range(len(query_pairs)):
                                param_key = query_pairs[param_idx][0]
                                test_pairs = list(query_pairs)
                                test_pairs[param_idx] = (param_key, mutation)
                                new_query = urllib.parse.urlencode(test_pairs, doseq=True)
                                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                                try:
                                    response = self.http_client.get(test_url, timeout=10, headers=req_headers, cookies=req_cookies)
                                    if not self._is_waf_blocked(response):
                                        analysis = self.analyze_response(response, baseline, {"value": mutation}, category)
                                        if analysis.get("vulnerable"):
                                            return {"endpoint": url, "payload": mutation, "vulnerable": True, "confidence": analysis.get("confidence", 0), "param": param_key}
                                except:
                                    pass
                        else:
                            inject_key = next(iter(params.keys()), "q") if isinstance(params, dict) else "q"
                            query_pairs = [(inject_key, mutation)]
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
                            waf_bypass_failed = True
                            continue  # Try next attempt
                    
                    # If we reach here, WAF bypassed or no WAF
                    if waf_bypass_attempted:
                        logger.info(f"[WAF] Bypass successful with mutation for {url}")

                    # Analyze response with baseline comparison
                    analysis = self.analyze_response(response, baseline, {"value": mutation}, category)

                    if analysis.get("vulnerable"):
                        confidence = analysis.get("confidence", 0)

                        logger.info(f"[VULN] Potential {category} vulnerability detected on {url} (confidence: {confidence})")

                        # 🔥 FIX: PUSH VÀO confirmed_vulnerabilities
                        if confidence >= 0.5:
                            vuln = {
                                "type": category,
                                "url": url,
                                "payload": mutation,
                                "confidence": confidence,
                                "source": "ai",
                                "evidence": analysis.get("reason", "")
                            }

                            # 🔥 HIGH CONF → cho phép exploit phase dùng
                            if confidence >= 0.5:
                                vuln["exploitable"] = True
                                vuln["exploit_context"] = {
                                    "category": category,
                                    "injection_point": url
                                }

                            current_vulns = self.state.get("vulnerabilities", [])
                            current_vulns.append(vuln)
                            self.state.update(vulnerabilities=current_vulns)
                            
                            confirmed = self.state.get("confirmed_vulnerabilities", [])
                            confirmed.append(vuln)
                            self.state.update(confirmed_vulnerabilities=confirmed)

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
            
            # BUG 5 FIX: If all WAF bypass mutations failed, stop and return early
            if waf_bypass_attempted and waf_bypass_failed:
                logger.debug(f"[WAF] Max bypass attempts reached for {url}, skipping")
                return {
                    "endpoint": url,
                    "payload": payload_value,
                    "method": method,
                    "status_code": 403,
                    "content_length": 0,
                    "response_time": 0,
                    "baseline_status": baseline.get("status_code", 0),
                    "baseline_length": baseline.get("content_length", 0),
                    "baseline_time": baseline.get("response_time", 0),
                    "category": category,
                    "vulnerable": False,
                    "confidence": 0,
                    "reason": "WAF blocking - max bypass attempts reached",
                    "timestamp": time.time()
                }
            
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
        """
        Analyze response for vulnerability using SCIENTIFIC SCORING.
        
        Only marks as vulnerable if evidence is strong enough:
        - Payload reflected (XSS) +0.4
        - Response anomaly (DB error) +0.3
        - Confirmed by 2nd payload +0.3
        
        THRESHOLD: >= 0.5 only
        """
        test_status = response.status_code
        test_length = len(response.text)
        test_time = response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
        response_text = response.text

        base_status = baseline["status_code"]
        base_length = baseline["content_length"]
        base_time = baseline["response_time"]
        payload_value = payload.get("value", "")

        analysis = {
            "vulnerable": False,
            "confidence": 0.0,
            "reason": "No evidence detected",
            "evidence": []
        }

        # 1. EVIDENCE 1: Reflection Detection (STRONGEST) +0.4
        reflects = False
        if payload_value and len(payload_value) > 3:
            payload_lower = payload_value.lower()
            response_lower = response_text.lower()
            
            if payload_lower in response_lower:
                # Check that it's not just in error message
                idx = response_lower.find(payload_lower)
                context = response_lower[max(0, idx-50):idx]
                
                if not any(x in context for x in ['invalid', 'error', 'rejected', 'syntax error']):
                    reflects = True
                    analysis["confidence"] += 0.4
                    analysis["evidence"].append("Payload reflected in response")
        
        # 2. EVIDENCE 2: Response Anomaly (status or error keywords) +0.3 MAX
        anomaly_score = self._check_response_anomaly(
            response_text, baseline, test_status, base_status, test_time, base_time, category
        )
        if anomaly_score > 0:
            analysis["confidence"] += anomaly_score
            if test_status != base_status:
                analysis["evidence"].append(f"Status code: {base_status}→{test_status}")
        
        # 3. Content length anomaly - only if minor evidence
        if len(analysis["evidence"]) < 2 and base_length > 0:
            length_diff = abs(test_length - base_length)
            length_ratio = length_diff / base_length
            if length_ratio > 0.5:  # Significant change
                analysis["confidence"] += 0.1
                analysis["evidence"].append(f"Content length changed: {length_diff:+d} bytes")
        
        # Cap at 1.0
        analysis["confidence"] = min(analysis["confidence"], 1.0)
        
        # STRICT RULE: Only vulnerable if score >= 0.5
        if analysis["confidence"] >= 0.5:
            analysis["vulnerable"] = True
            analysis["reason"] = f"Evidence verified: {len(analysis['evidence'])} indicators"
        else:
            analysis["reason"] = f"Score {analysis['confidence']:.2f} below 0.5 threshold"
        
        return analysis
    
    def _check_response_anomaly(self, response_text: str, baseline: Dict, test_status, base_status, test_time, base_time, category: str) -> float:
        """
        Check for real response anomalies (not just random keywords).
        Max +0.3
        """
        score = 0.0
        
        # DB Error patterns (SQL injection specific)
        if category in ['sql_injection', 'sqli']:
            db_errors = [
                'sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-', 'odbc',
                'you have an error', 'unclosed quotation', 'syntax error near'
            ]
            response_lower = response_text.lower()
            found_errors = [e for e in db_errors if e in response_lower]
            if found_errors:
                score += 0.15
        
        # RCE/Command patterns
        elif category in ['command_injection', 'rce']:
            rce_patterns = ['uid=', 'root@', '/bin/', 'command not found']
            response_lower = response_text.lower()
            found_patterns = [p for p in rce_patterns if p in response_lower]
            if found_patterns:
                score += 0.15
        
        # Timing anomaly (blind injection) - ONLY for SQL timing attacks
        if category in ['sql_injection', 'sqli']:
            time_diff = test_time - base_time
            if time_diff > 3 and base_time < 1:  # Strong indicator
                score += 0.15
        
        # Status code anomalies (only relevant ones)
        if test_status == 500 and base_status != 500:
            # True server error, not input validation
            if 'exception' in response_text.lower() or 'error' in response_text.lower():
                score += 0.1
        
        return min(score, 0.3)

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