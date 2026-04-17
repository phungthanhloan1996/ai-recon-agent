"""
modules/race_condition.py - Race Condition / TOCTOU Detector
Detects race conditions in critical operations: payments, transfers, redemptions.
"""

import re
import time
import logging
import threading
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.race_condition")


class RaceConditionDetector:
    """
    Detects race condition vulnerabilities.

    Attack vectors:
    1. Parallel requests to single-use endpoints (promo codes, tokens)
    2. Concurrent balance operations (double-spend, negative balance)
    3. Account creation race (duplicate usernames)
    4. File write races
    5. TOCTOU in authentication flows
    """

    RACE_KEYWORDS = [
        "coupon", "promo", "voucher", "discount", "redeem", "code",
        "transfer", "payment", "pay", "purchase", "order", "buy",
        "withdraw", "deposit", "balance", "wallet", "credit",
        "register", "signup", "create.*account", "invite",
        "vote", "like", "claim", "reward", "bonus",
        "verify", "confirm", "activate", "reset",
        "upload", "submit", "checkout",
    ]

    RACE_CONCURRENCY = 15  # Number of simultaneous requests

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for race condition vulnerabilities."""
        logger.info(f"[RACE] Starting race condition detection on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "race_confirmed": 0,
        }

        # Filter for race-condition-susceptible endpoints
        candidates = self._filter_candidates(endpoints)
        logger.info(f"[RACE] Found {len(candidates)} race-condition candidates")

        for i, endpoint in enumerate(candidates):
            if progress_cb:
                progress_cb(i, len(candidates))

            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
                method = (endpoint.get("method") or "POST").upper()
                params = endpoint.get("parameters") or {}
            else:
                url = str(endpoint)
                method = "POST"
                params = {}

            if not url:
                continue

            vuln = self._test_race_condition(url, method, params)
            if vuln.get("vulnerable"):
                results["vulnerabilities"].append(vuln)
                results["race_confirmed"] += 1

            results["endpoints_tested"] += 1

        logger.info(f"[RACE] Found {results['race_confirmed']} race condition vulnerabilities")
        return results

    def _filter_candidates(self, endpoints: List[Any]) -> List[Any]:
        """Filter endpoints likely to have race conditions."""
        candidates = []
        for endpoint in endpoints:
            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint", "")
            else:
                url = str(endpoint)
            url_lower = url.lower()
            if any(re.search(kw, url_lower) for kw in self.RACE_KEYWORDS):
                candidates.append(endpoint)
        return candidates

    def _test_race_condition(self, url: str, method: str, params: Dict) -> Dict[str, Any]:
        """Test endpoint for race condition via parallel requests."""
        result = {
            "url": url,
            "method": method,
            "vulnerable": False,
            "confidence": 0.0,
            "evidence": {
                "total_requests": self.RACE_CONCURRENCY,
                "responses": [],
                "anomalies": [],
            },
        }

        responses = self._fire_parallel_requests(url, method, params)

        if not responses:
            return result

        analysis = self._analyze_responses(responses)
        if analysis["anomaly_detected"]:
            result["vulnerable"] = True
            result["confidence"] = analysis["confidence"]
            result["evidence"]["responses"] = analysis["summary"]
            result["evidence"]["anomalies"] = analysis["anomalies"]
            result["description"] = analysis["description"]
            result["severity"] = "HIGH"

        return result

    def _fire_parallel_requests(
        self, url: str, method: str, params: Dict
    ) -> List[Tuple[int, str, float]]:
        """Fire N requests as simultaneously as possible."""
        results = []
        barrier = threading.Barrier(self.RACE_CONCURRENCY)

        def make_request():
            try:
                barrier.wait(timeout=5)  # Synchronize all threads
                start = time.time()
                if method == "POST":
                    resp = self.http_client.post(url, data=params, timeout=15)
                else:
                    resp = self.http_client.get(url, timeout=15)
                elapsed = time.time() - start
                return (resp.status_code, resp.text[:200] if hasattr(resp, "text") else "", elapsed)
            except Exception as e:
                return (0, str(e)[:100], 0)

        with ThreadPoolExecutor(max_workers=self.RACE_CONCURRENCY) as executor:
            futures = [executor.submit(make_request) for _ in range(self.RACE_CONCURRENCY)]
            for future in as_completed(futures, timeout=30):
                try:
                    results.append(future.result())
                except Exception:
                    pass

        return results

    def _analyze_responses(self, responses: List[Tuple]) -> Dict[str, Any]:
        """Analyze parallel responses for race condition indicators."""
        if not responses:
            return {"anomaly_detected": False, "confidence": 0, "summary": [], "anomalies": [], "description": ""}

        status_counts: Dict[int, int] = {}
        success_responses = []
        anomalies = []

        for status, body, elapsed in responses:
            status_counts[status] = status_counts.get(status, 0) + 1
            if status == 200:
                success_responses.append(body)

        total = len(responses)
        success_count = status_counts.get(200, 0)

        # Anomaly 1: Multiple successes on idempotent endpoint
        if success_count > 1:
            # Check if responses look like successful operations (not just 200 OK homepage)
            operation_keywords = [
                "success", "confirmed", "applied", "redeemed", "accepted",
                "created", "processed", "completed", "approved",
            ]
            op_success = sum(
                1 for body in success_responses
                if any(kw in body.lower() for kw in operation_keywords)
            )
            if op_success > 1:
                anomalies.append({
                    "type": "multiple_successful_operations",
                    "description": f"{op_success} requests claimed success simultaneously",
                    "count": op_success,
                })
                return {
                    "anomaly_detected": True,
                    "confidence": min(0.5 + (op_success / total) * 0.4, 0.9),
                    "summary": [{"status": s, "count": c} for s, c in status_counts.items()],
                    "anomalies": anomalies,
                    "description": f"Race condition: {op_success}/{total} parallel requests succeeded",
                }

        # Anomaly 2: Inconsistent responses (mix of 200 and 4xx for same operation)
        if len(status_counts) > 2:
            anomalies.append({
                "type": "inconsistent_responses",
                "description": f"Got {len(status_counts)} different status codes: {list(status_counts.keys())}",
            })
            return {
                "anomaly_detected": True,
                "confidence": 0.5,
                "summary": [{"status": s, "count": c} for s, c in status_counts.items()],
                "anomalies": anomalies,
                "description": "Race condition: inconsistent responses under concurrent load",
            }

        # Anomaly 3: All requests succeeded AND at least one response body signals
        # a state-changing operation. Plain 200s on idempotent endpoints are normal.
        if success_count == total and total >= 5:
            operation_keywords = [
                "success", "confirmed", "applied", "redeemed", "accepted",
                "created", "processed", "completed", "approved", "coupon",
                "discount", "credited", "transferred", "deducted", "redeemed",
            ]
            op_body_hits = sum(
                1 for body in success_responses
                if any(kw in body.lower() for kw in operation_keywords)
            )
            if op_body_hits >= 2:
                anomalies.append({
                    "type": "all_requests_succeeded",
                    "description": f"All {total} parallel requests returned 200 with operation keywords in body",
                    "count": op_body_hits,
                })
                return {
                    "anomaly_detected": True,
                    "confidence": min(0.5 + (op_body_hits / total) * 0.35, 0.85),
                    "summary": [{"status": s, "count": c} for s, c in status_counts.items()],
                    "anomalies": anomalies,
                    "description": f"Possible race condition: {op_body_hits}/{total} concurrent requests show state-change keywords",
                }

        return {
            "anomaly_detected": False,
            "confidence": 0,
            "summary": [{"status": s, "count": c} for s, c in status_counts.items()],
            "anomalies": [],
            "description": "",
        }


def detect_race_condition(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for race condition detection."""
    detector = RaceConditionDetector(state=state)
    return detector.detect(endpoints, progress_cb)
