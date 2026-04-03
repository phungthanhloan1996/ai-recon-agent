"""
modules/parameter_miner.py - Parameter Miner
Discover hidden or undocumented parameters for known endpoints.
"""

import logging
import json
import ipaddress
from typing import Dict, List, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import difflib
from urllib.parse import urlencode, urlparse, parse_qs

import config
from core.http_engine import HTTPClient
from core.state_manager import StateManager
from core.scan_budget import ScanBudget

logger = logging.getLogger("recon.param_miner")


class ParameterMiner:
    """
    Discovers hidden or undocumented parameters for known endpoints.
    
    Methodology:
    1. Generate parameter candidates
    2. Send HTTP requests with parameters appended
    3. Analyze response differences
    4. Mark interesting parameters
    """

    # Common parameter names to test
    PARAMETER_CANDIDATES = [
        'id', 'user', 'username', 'email', 'token', 'api_key', 'apikey',
        'file', 'path', 'redirect', 'callback', 'next', 'url',
        'cmd', 'exec', 'command', 'query', 'search', 'q',
        'action', 'method', 'function', 'class', 'mode',
        'page', 'limit', 'offset', 'sort', 'order',
        'filter', 'where', 'group', 'join', 'select',
        'format', 'type', 'lang', 'encoding', 'charset',
        'auth', 'session', 'cookie', 'jwt', 'token',
        'data', 'payload', 'content', 'body',
        'admin', 'debug', 'test', 'dev', 'verbose',
        'output', 'response_type', 'callback_url',
        'include', 'exclude', 'fields', 'expand'
    ]

    def __init__(self, state: StateManager = None, budget: ScanBudget = None, 
                 http_client: HTTPClient = None, max_workers: int = 8):
        self.state = state
        self.budget = budget or ScanBudget()
        self.http_client = http_client or HTTPClient()
        self.max_workers = max_workers
        self.target = state.get("target") if state else ""
        self.interesting_params = {}
        self.request_timeout = config.PARAM_MINER_TIMEOUT
        self.max_endpoints = config.PARAM_MINER_MAX_ENDPOINTS
        self.max_candidates = config.PARAM_MINER_MAX_CANDIDATES
        self.local_max_candidates = config.PARAM_MINER_LOCAL_MAX_CANDIDATES
        self.static_extensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp",
            ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".mp3", ".mp4", ".avi",
            ".mov", ".woff", ".woff2", ".ttf", ".eot", ".css", ".map", ".js"
        }

    def mine_parameters(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Mine parameters for given endpoints.
        
        Args:
            endpoints: List of endpoint dicts with 'url', 'method', etc.
            
        Returns:
            Dict with mining results
        """
        selected_endpoints = self._select_endpoints(endpoints)
        logger.info(f"[PARAM_MINER] Mining parameters for {len(selected_endpoints)}/{len(endpoints)} endpoints")
        
        results = {
            'total_endpoints': len(selected_endpoints),
            'endpoints_tested': 0,
            'total_discovered_params': 0,
            'mining_results': []
        }
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for endpoint in selected_endpoints:
                future = executor.submit(self._mine_endpoint_params, endpoint)
                futures[future] = endpoint
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result['discovered_parameters'] or result['reflected_parameters']:
                        results['mining_results'].append(result)
                    results['endpoints_tested'] += 1
                    results['total_discovered_params'] += len(result['discovered_parameters'])
                    logger.debug(
                        f"[PARAM_MINER] Completed {results['endpoints_tested']}/{len(selected_endpoints)}: "
                        f"{result['endpoint']} ({len(result['discovered_parameters'])} discovered, "
                        f"{len(result['reflected_parameters'])} reflected)"
                    )
                except Exception as e:
                    logger.debug(f"[PARAM_MINER] Error mining parameters: {e}")
                    continue
        
        return results

    def _select_endpoints(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        selected: List[Dict[str, Any]] = []
        seen = set()
        preferred = []
        fallback = []

        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                continue

            url = (endpoint.get("url") or "").strip()
            if not url or url in seen:
                continue
            seen.add(url)

            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                continue

            path = (parsed.path or "").lower()
            if any(path.endswith(ext) for ext in self.static_extensions):
                continue

            params = endpoint.get("parameters", []) or list(parse_qs(parsed.query).keys())
            categories = endpoint.get("categories", []) or []
            is_promising = bool(
                params
                or parsed.query
                or any(cat in {"api", "api_injection", "injection", "authentication"} for cat in categories)
                or any(marker in url.lower() for marker in ["api", "login", "auth", "search", "query", "id="])
            )

            if is_promising:
                preferred.append(endpoint)
            else:
                fallback.append(endpoint)

        selected = preferred + fallback
        return selected[:self.max_endpoints]

    def _is_local_target(self) -> bool:
        host = (urlparse(self.target).hostname if self.target else "") or self.target or ""
        host = host.strip().lower()
        if not host:
            return False
        if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "localhost.localdomain"}:
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        except ValueError:
            pass
        if "." not in host:
            return True
        return host.endswith((".local", ".localhost", ".internal", ".lan", ".home", ".test"))

    def _mine_endpoint_params(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mine parameters for a single endpoint.
        
        Args:
            endpoint: Endpoint dict with 'url', 'method', etc.
            
        Returns:
            Dict with discovered parameters
        """
        endpoint_url = endpoint.get('url', '')
        method = (endpoint.get('method', 'GET') or 'GET').upper()
        
        if not endpoint_url:
            return {
                'endpoint': 'unknown',
                'discovered_parameters': [],
                'reflected_parameters': [],
                'suspicious_parameters': []
            }
        
        try:
            logger.debug(f"[PARAM_MINER] Testing endpoint: {endpoint_url}")
            # Get baseline response
            baseline = self._get_baseline_response(endpoint_url, method)
            if baseline is None:
                return {
                    'endpoint': endpoint_url,
                    'discovered_parameters': [],
                    'reflected_parameters': [],
                    'suspicious_parameters': []
                }
            
            discovered = set()
            reflected = set()
            suspicious = set()
            
            # Test each parameter candidate
            candidates = self.PARAMETER_CANDIDATES[:self.local_max_candidates] if self._is_local_target() else self.PARAMETER_CANDIDATES[:self.max_candidates]
            for param in candidates:
                test_result = self._test_parameter(
                    endpoint_url, method, param, baseline
                )
                
                if test_result['is_interesting']:
                    discovered.add(param)
                
                if test_result['is_reflected']:
                    reflected.add(param)
                
                if test_result['is_suspicious']:
                    suspicious.add(param)
            
            return {
                'endpoint': endpoint_url,
                'discovered_parameters': list(discovered),
                'reflected_parameters': list(reflected),
                'suspicious_parameters': list(suspicious),
                'baseline_status': baseline.get('status_code'),
                'baseline_length': baseline.get('content_length')
            }
        except Exception as e:
            logger.debug(f"[PARAM_MINER] Error mining {endpoint_url}: {e}")
            return {
                'endpoint': endpoint_url,
                'discovered_parameters': [],
                'reflected_parameters': [],
                'suspicious_parameters': [],
                'error': str(e)
            }

    def _get_baseline_response(self, endpoint_url: str, method: str) -> Dict[str, Any]:
        """Get baseline response without parameters."""
        try:
            if method == 'GET':
                response = self.http_client.get(endpoint_url, timeout=self.request_timeout)
            elif method == 'POST':
                response = self.http_client.post(endpoint_url, data={}, timeout=self.request_timeout)
            else:
                response = self.http_client.get(endpoint_url, timeout=self.request_timeout)
            
            return {
                'status_code': response.status_code,
                'content_length': len(response.text),
                'content': response.text[:2000],
                'headers': dict(response.headers)
            }
        except Exception as e:
            logger.debug(f"[PARAM_MINER] Error getting baseline: {e}")
            return None

    def _test_parameter(self, endpoint_url: str, method: str, param: str, 
                       baseline: Dict[str, Any]) -> Dict[str, Any]:
        """
        Test a single parameter on an endpoint.
        
        Args:
            endpoint_url: Target URL
            method: HTTP method
            param: Parameter to test
            baseline: Baseline response for comparison
            
        Returns:
            Dict with test results
        """
        try:
            # Build test payload
            test_value = f"test_{param}_{self._get_random_id()}"
            
            if method == 'GET':
                # Append to URL
                separator = '&' if '?' in endpoint_url else '?'
                test_url = f"{endpoint_url}{separator}{param}={test_value}"
                response = self.http_client.get(test_url, timeout=self.request_timeout)
            else:
                # POST with parameter
                response = self.http_client.post(
                    endpoint_url,
                    data={param: test_value},
                    timeout=self.request_timeout
                )
            
            # Analyze response
            response_text = response.text[:2000]
            
            is_interesting = False
            is_reflected = False
            is_suspicious = False
            
            # Check for reflection
            if test_value in response.text or param in response.text:
                is_reflected = True
                is_interesting = True
            
            # Check for response differences
            status_diff = response.status_code != baseline.get('status_code')
            length_diff = abs(len(response.text) - baseline.get('content_length', 0)) > 50
            
            if status_diff or length_diff:
                is_interesting = True
            
            # Check for suspicious behaviors
            if response.status_code == 500:
                is_suspicious = True
                is_interesting = True
            
            # Check for error messages
            error_indicators = ['error', 'exception', 'invalid', 'undefined']
            for indicator in error_indicators:
                if indicator in response_text.lower():
                    if test_value in response_text or param in response_text:
                        is_suspicious = True
                        is_interesting = True
                        break
            
            return {
                'parameter': param,
                'is_interesting': is_interesting,
                'is_reflected': is_reflected,
                'is_suspicious': is_suspicious,
                'status_code': response.status_code,
                'content_length': len(response.text)
            }
        except Exception as e:
            logger.debug(f"[PARAM_MINER] Error testing {param}: {e}")
            return {
                'parameter': param,
                'is_interesting': False,
                'is_reflected': False,
                'is_suspicious': False,
                'error': str(e)
            }

    def _get_random_id(self) -> str:
        """Generate random ID for testing."""
        import random
        import string
        return ''.join(random.choices(string.ascii_lowercase, k=8))

    def export_to_state(self, results: Dict[str, Any], state: StateManager = None) -> None:
        """Export mining results to state manager."""
        if state is None:
            state = self.state
        
        if not state:
            logger.warning("[PARAM_MINER] No state manager provided for export")
            return
        
        # Store mining results for later analysis
        param_mining_results = state.get("parameter_mining_results", []) or []
        param_mining_results.extend(results.get('mining_results', []))
        
        state.update(parameter_mining_results=param_mining_results)
        logger.info(f"[PARAM_MINER] Exported {len(results.get('mining_results', []))} "
                   f"mining results to state")


def mine_endpoint_parameters(state: StateManager, endpoints: List[Dict[str, Any]], 
                             budget: ScanBudget = None) -> Dict[str, Any]:
    """
    Standalone function to mine endpoint parameters.
    Integrates with existing scanning pipeline.
    """
    miner = ParameterMiner(state=state, budget=budget)
    results = miner.mine_parameters(endpoints)
    miner.export_to_state(results, state)
    return results
