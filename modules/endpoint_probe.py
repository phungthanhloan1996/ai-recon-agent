import json
import logging
import os
import time
from typing import Any, Dict, List

from core.state_manager import StateManager

logger = logging.getLogger("recon.endpoint_probe")


def _normalize_target(endpoint: Any) -> Dict[str, Any] | None:
    if isinstance(endpoint, dict) and endpoint.get("url"):
        return endpoint
    if isinstance(endpoint, str) and endpoint:
        return {"url": endpoint}
    return None


def run_endpoint_probe(
    state: StateManager,
    output_dir: str,
    http_client,
    endpoints: List[Any],
    max_endpoints: int = 1,
    requests_per_endpoint: int = 2,
    delay_seconds: float = 0.5,
) -> List[Dict[str, Any]]:
    """
    Validate prioritized endpoints with a bounded, low-rate request pass.
    This is intentionally capped and is not a stress-testing or flooding routine.
    """
    selected: List[Dict[str, Any]] = []
    for endpoint in endpoints:
        normalized = _normalize_target(endpoint)
        if normalized:
            selected.append(normalized)
        if len(selected) >= max_endpoints:
            break

    results: List[Dict[str, Any]] = []
    for endpoint in selected:
        url = endpoint["url"]
        probe_result: Dict[str, Any] = {
            "url": url,
            "requests_attempted": 0,
            "successes": 0,
            "failures": 0,
            "status_codes": [],
            "avg_response_time_ms": 0.0,
            "timestamp": int(time.time()),
        }

        response_times: List[float] = []
        logger.warning(
            f"[PROBE] Validating {url} with {requests_per_endpoint} low-rate request(s)"
        )

        for index in range(requests_per_endpoint):
            probe_result["requests_attempted"] += 1
            started = time.time()
            try:
                response = http_client.get(url, timeout_mode="fast")
                elapsed_ms = round((time.time() - started) * 1000, 2)
                response_times.append(elapsed_ms)
                probe_result["successes"] += 1
                probe_result["status_codes"].append(response.status_code)
            except Exception as exc:
                elapsed_ms = round((time.time() - started) * 1000, 2)
                response_times.append(elapsed_ms)
                probe_result["failures"] += 1
                probe_result.setdefault("errors", []).append(str(exc)[:200])

            if index < requests_per_endpoint - 1:
                time.sleep(delay_seconds)

        if response_times:
            probe_result["avg_response_time_ms"] = round(
                sum(response_times) / len(response_times), 2
            )

        results.append(probe_result)

    state.update(endpoint_probe_results=results)

    output_path = os.path.join(output_dir, "endpoint_probe_results.json")
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    return results
