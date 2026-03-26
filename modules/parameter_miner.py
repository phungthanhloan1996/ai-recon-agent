"""
modules/parameter_miner.py - Parameter Miner
Discover hidden or undocumented parameters for known endpoints.
"""

import logging
import json
from typing import Dict, List, Any, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import difflib
from urllib.parse import urlencode, urlparse, parse_qs

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

    def mine_parameters(self, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Mine parameters for given endpoints.
        
        Args:
            endpoints: List of endpoint dicts with 'url', 'method', etc.
            
        Returns:
            Dict with mining results
        """
        logger.info(f"[PARAM_MINER] Mining parameters for {len(endpoints)} endpoints")
        
        results = {
            'total_endpoints': len(endpoints),
            'endpoints_tested': 0,
            'total_discovered_params': 0,
            'mining_results': []
        }
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for endpoint in endpoints[:50]:  # Limit to 50 endpoints
                future = executor.submit(self._mine_endpoint_params, endpoint)
                futures[future] = endpoint
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result['discovered_parameters'] or result['reflected_parameters']:
                        results['mining_results'].append(result)
                        results['endpoints_tested'] += 1
                        results['total_discovered_params'] += len(result['discovered_parameters'])
                        
                        logger.info(f"[PARAM_MINER] {result['endpoint']}: "
                                   f"{len(result['discovered_parameters'])} params")
                except Exception as e:
                    logger.debug(f"[PARAM_MINER] Error mining parameters: {e}")
                    continue
        
        return results

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
            for param in self.PARAMETER_CANDIDATES:
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
                response = self.http_client.get(endpoint_url, timeout='fast')
            elif method == 'POST':
                response = self.http_client.post(endpoint_url, data={}, timeout='fast')
            else:
                response = self.http_client.get(endpoint_url, timeout='fast')
            
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
                response = self.http_client.get(test_url, timeout='fast')
            else:
                # POST with parameter
                response = self.http_client.post(
                    endpoint_url,
                    data={param: test_value},
                    timeout='fast'
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
