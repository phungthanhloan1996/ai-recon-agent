"""
modules/scanner.py - Scanning Engine
AI-driven vulnerability scanning with payload generation and mutation
"""

import json
import os
import logging
from typing import Dict, List, Any
import time

from core.state_manager import StateManager
from core.http_engine import HTTPClient
from ai.payload_gen import PayloadGenerator
from ai.payload_mutation import PayloadMutator

logger = logging.getLogger("recon.scanning")


class ScanningEngine:
    """
    Intelligent vulnerability scanning engine.
    Uses AI-generated payloads, applies mutations, and tests endpoints.
    """

    def __init__(self, state: StateManager, output_dir: str,
                 payload_gen: PayloadGenerator, payload_mutator: PayloadMutator):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.http_client = HTTPClient()
        self.payload_gen = payload_gen
        self.payload_mutator = payload_mutator

        self.scan_results_file = os.path.join(output_dir, "scan_results.json")

    def run(self):
        """Execute vulnerability scanning pipeline"""
        logger.info("[SCANNING] Starting AI-driven vulnerability scanning")

        prioritized_endpoints = self.state.get("prioritized_endpoints", [])
        scan_responses = []

        for endpoint in prioritized_endpoints[:50]:  # Increased limit
            try:
                responses = self.scan_endpoint(endpoint)
                scan_responses.extend(responses)
            except Exception as e:
                logger.debug(f"[SCANNING] Failed to scan endpoint {endpoint}: {e}")

        self.state.update(scan_responses=scan_responses)

        # Save results
        with open(self.scan_results_file, 'w') as f:
            json.dump(scan_responses, f, indent=2)

        logger.info(f"[SCANNING] Completed scanning: {len(scan_responses)} responses collected")

    def scan_endpoint(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan a single endpoint with AI-generated payloads"""
        url = endpoint.get("url", "")
        categories = endpoint.get("categories", [])
        parameters = endpoint.get("parameters", [])

        logger.debug(f"[SCANNING] Scanning {url} (categories: {categories})")

        responses = []

        # Generate payloads based on endpoint type
        for category in categories:
            payloads = self.payload_gen.generate_for_category(category, parameters)

            # Apply mutations
            mutated_payloads = self.payload_mutator.mutate_payloads(payloads)

            # Test payloads
            for payload in mutated_payloads[:5]:  # Limit per category
                try:
                    response = self.test_payload(url, payload, category)
                    responses.append(response)

                    # Small delay to avoid overwhelming
                    time.sleep(0.1)

                except Exception as e:
                    logger.debug(f"[SCANNING] Payload test failed: {e}")

        return responses

    def test_payload(self, url: str, payload: Dict[str, Any], category: str) -> Dict[str, Any]:
        """Test a single payload against an endpoint"""
        payload_value = payload.get("value", "")
        method = payload.get("method", "GET")
        params = payload.get("params", {})

        # Prepare request
        if method == "GET":
            test_url = url
            if "?" in url:
                test_url += f"&{payload_value}"
            else:
                test_url += f"?{payload_value}"
            response = self.http_client.get(test_url, timeout=5)
        elif method == "POST":
            response = self.http_client.post(url, data=params, timeout=5)
        else:
            # Default to GET
            response = self.http_client.get(url, timeout=5)

        # Analyze response
        analysis = self.analyze_response(response, payload, category)

        return {
            "endpoint": url,
            "payload": payload_value,
            "method": method,
            "status_code": response.status_code,
            "content_length": len(response.text),
            "response_time": response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
            "category": category,
            "vulnerable": analysis.get("vulnerable", False),
            "confidence": analysis.get("confidence", 0),
            "reason": analysis.get("reason", ""),
            "timestamp": time.time()
        }

    def analyze_response(self, response, payload: Dict, category: str) -> Dict[str, Any]:
        """Analyze response for vulnerability indicators"""
        content = response.text.lower()
        status = response.status_code

        analysis = {
            "vulnerable": False,
            "confidence": 0.0,
            "reason": "No vulnerability detected"
        }

        # Load vulnerability patterns
        try:
            with open("rules/vulnerability_patterns.json", 'r') as f:
                patterns = json.load(f)
        except Exception:
            patterns = {}

        vuln_patterns = patterns.get("patterns", {}).get(category, {})

        # Check for error indicators
        error_indicators = vuln_patterns.get("error_messages", [])
        for indicator in error_indicators:
            if indicator.lower() in content:
                analysis.update({
                    "vulnerable": True,
                    "confidence": 0.8,
                    "reason": f"Error message detected: {indicator}"
                })
                break

        # Check for success indicators
        if not analysis["vulnerable"]:
            success_indicators = vuln_patterns.get("success_indicators", [])
            for indicator in success_indicators:
                if indicator.lower() in content:
                    analysis.update({
                        "vulnerable": True,
                        "confidence": 0.7,
                        "reason": f"Success indicator detected: {indicator}"
                    })
                    break

        # Check response anomalies
        if status in [500, 502, 503]:  # Server errors
            analysis.update({
                "vulnerable": True,
                "confidence": 0.6,
                "reason": f"Server error response: {status}"
            })

        # Check for reflected input
        payload_value = payload.get("value", "").lower()
        if payload_value and payload_value in content:
            analysis.update({
                "vulnerable": True,
                "confidence": 0.5,
                "reason": "Payload reflected in response"
            })

        return analysis
