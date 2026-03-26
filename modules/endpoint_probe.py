import json
import logging
import os
import re
import time
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs

from core.state_manager import StateManager
from core.endpoint_analyzer import EndpointAnalyzer
from core.cve_matcher import get_hints_for_endpoint

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


def extract_endpoints_with_context(
    endpoints: List[Dict[str, Any]],
    technologies: List[str] = None,
) -> List[Dict[str, Any]]:
    """
    Enrich endpoints with comprehensive context:
    - Parameter extraction and classification
    - Technology-based vulnerability hints
    - Confidence scoring
    
    Args:
        endpoints: List of endpoint dictionaries
        technologies: List of detected technologies
    
    Returns:
        Enriched endpoints with additional context
    """
    enriched = []
    technologies = technologies or []
    
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            continue
        
        url = endpoint.get('url', '')
        if not url:
            continue
        
        # Create enriched endpoint
        enriched_ep = dict(endpoint)  # Keep existing data
        
        # Extract URL components
        parsed = urlparse(url)
        
        # Extract query string parameters
        query_params = parse_qs(parsed.query)
        query_params_list = list(query_params.keys())
        enriched_ep['query_parameters'] = query_params_list
        
        # Extract path-based indicators
        path = parsed.path.lower()
        enriched_ep['path_indicators'] = _extract_path_indicators(path)
        
        # Add technologies if provided
        enriched_ep['technologies'] = technologies
        
        # Generate vulnerability hints
        vulnerability_hints = EndpointAnalyzer.generate_vulnerability_hints(enriched_ep)
        endpoint_context_hints = get_hints_for_endpoint(enriched_ep)
        all_hints = list(set(vulnerability_hints + endpoint_context_hints))
        enriched_ep['vulnerability_hints'] = all_hints
        
        # Extract parameters with detail
        enriched_ep['parameters'] = EndpointAnalyzer.extract_parameter_details(enriched_ep)
        
        # Add confidence score
        if 'confidence' not in enriched_ep:
            enriched_ep['confidence'] = _calculate_endpoint_confidence(enriched_ep)
        
        enriched.append(enriched_ep)
    
    return enriched


def _extract_path_indicators(path: str) -> List[str]:
    """
    Extract security-relevant indicators from URL path.
    
    Returns:
        List of indicator strings
    """
    indicators = []
    path_lower = path.lower()
    
    # Admin paths
    if any(x in path_lower for x in ['admin', 'administrator', 'wp-admin', 'manager', 'console', 'dashboard']):
        indicators.append('admin_path')
    
    # Upload/file paths
    if any(x in path_lower for x in ['upload', 'file', 'attachment', 'media', 'content']):
        indicators.append('file_access_path')
    
    # API paths
    if any(x in path_lower for x in ['/api/', '/v1/', '/v2/', '/v3/', '/graphql']):
        indicators.append('api_path')
    
    # Auth paths
    if any(x in path_lower for x in ['login', 'signin', 'auth', 'authenticate', 'register', 'password']):
        indicators.append('auth_path')
    
    # Config/sensitive paths
    if any(x in path_lower for x in ['.env', 'config', 'settings', 'database', 'wp-config']):
        indicators.append('config_path')
    
    # WordPress paths
    if any(x in path_lower for x in ['wp-content', 'wp-includes', 'wp-json', 'wp-admin']):
        indicators.append('wordpress_path')
    
    # Debug/test paths
    if any(x in path_lower for x in ['debug', 'test', 'dev', 'staging', 'temp', 'tmp']):
        indicators.append('debug_path')
    
    # Backup files
    if any(path_lower.endswith(x) for x in ['.bak', '.sql', '.tar', '.zip', '.backup']):
        indicators.append('backup_file')
    
    # Git/version control
    if any(x in path_lower for x in ['.git', '.svn', '.hg']):
        indicators.append('vcs_path')
    
    return indicators


def _calculate_endpoint_confidence(endpoint: Dict[str, Any]) -> float:
    """
    Calculate confidence score for endpoint analysis.
    
    Args:
        endpoint: Endpoint dictionary
    
    Returns:
        Confidence score 0.0-1.0
    """
    score = 0.0
    
    # URL reachability
    if endpoint.get('reachable') or endpoint.get('status_code', 0) < 500:
        score += 0.2
    
    # Has parameters
    if endpoint.get('query_parameters') or endpoint.get('parameters'):
        score += 0.2
    
    # Has vulnerability hints
    if endpoint.get('vulnerability_hints'):
        score += 0.15
    
    # Identified endpoint type
    if endpoint.get('endpoint_type') and endpoint.get('endpoint_type') != 'unknown':
        score += 0.15
    
    # Has forms
    if endpoint.get('has_form') or endpoint.get('forms'):
        score += 0.15
    
    # Technologies detected
    if endpoint.get('technologies'):
        score += 0.15
    
    return min(score, 1.0)
