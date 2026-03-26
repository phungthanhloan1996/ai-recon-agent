"""
modules/js_endpoint_hunter.py - JavaScript Endpoint Hunter
Extract hidden endpoints, APIs, and parameters from JavaScript files.
"""

import re
import logging
import json
from typing import Dict, List, Any, Set
from urllib.parse import urljoin, urlparse
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.js_hunter")


class JSEndpointHunter:
    """
    Extracts hidden endpoints, APIs, and parameters from JavaScript files.
    
    Detects:
    - Absolute URLs
    - Relative paths
    - API endpoints
    - GraphQL endpoints
    - Parameters in API calls
    """

    # Regex patterns for endpoint detection
    ENDPOINT_PATTERNS = [
        r'["\']/(api|admin|upload|login|graphql|wp-json|v[12]|ajax|rest|internal|private)[^"\']*["\']',
        r'["\']https?://[^"\']+["\']',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.\w+\(["\']([^"\']+)["\']',
        r'XMLHttpRequest|\.open\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']',
        r'\.ajax\({[^}]*url\s*:\s*["\']([^"\']+)["\']',
    ]

    # Common parameter names
    COMMON_PARAMETERS = {
        'id', 'user', 'username', 'token', 'api_key', 'apikey', 'key',
        'file', 'path', 'redirect', 'callback', 'next', 'url',
        'cmd', 'exec', 'command', 'query', 'search', 'q',
        'email', 'password', 'auth', 'session', 'cookie',
        'data', 'payload', 'content', 'format', 'type',
        'page', 'limit', 'offset', 'sort', 'order',
        'filter', 'where', 'group', 'join',
        'action', 'method', 'function', 'class'
    }

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()
        self.target = state.get("target") if state else ""
        self.discovered_endpoints = {}
        self.discovered_parameters = set()

    def hunt_endpoints(self, js_urls: List[str]) -> Dict[str, Any]:
        """
        Hunt for endpoints in JavaScript files.
        
        Args:
            js_urls: List of JavaScript file URLs
            
        Returns:
            Dict with aggregated results
        """
        logger.info(f"[JS_HUNTER] Hunting endpoints in {len(js_urls)} JS files")
        
        all_endpoints = set()
        all_parameters = set()
        js_results = []
        
        for js_url in js_urls[:50]:  # Limit to 50 JS files
            try:
                result = self._analyze_js_file(js_url)
                if result['endpoints'] or result['parameters']:
                    js_results.append(result)
                    all_endpoints.update(result['endpoints'])
                    all_parameters.update(result['parameters'])
                    logger.info(f"[JS_HUNTER] {js_url}: {len(result['endpoints'])} endpoints, "
                               f"{len(result['parameters'])} parameters")
            except Exception as e:
                logger.debug(f"[JS_HUNTER] Error analyzing {js_url}: {e}")
                continue
        
        # Normalize and deduplicate endpoints
        normalized_endpoints = self._normalize_endpoints(all_endpoints)
        
        return {
            'total_js_files_analyzed': len(js_urls),
            'files_processed': len(js_results),
            'unique_endpoints': len(normalized_endpoints),
            'unique_parameters': len(all_parameters),
            'endpoints': list(normalized_endpoints),
            'parameters': list(all_parameters),
            'files': js_results
        }

    def _analyze_js_file(self, js_url: str) -> Dict[str, Any]:
        """
        Analyze a single JavaScript file.
        
        Args:
            js_url: URL of JavaScript file
            
        Returns:
            Dict with extracted endpoints and parameters
        """
        try:
            # Download JS content
            response = self.http_client.get(js_url, timeout='normal')
            if response.status_code != 200:
                return {'js_file': js_url, 'endpoints': [], 'parameters': [], 'interesting_routes': []}
            
            js_content = response.text
            
            # Extract endpoints
            endpoints = self._extract_endpoints_from_js(js_content, js_url)
            
            # Extract parameters
            parameters = self._extract_parameters_from_js(js_content)
            
            # Identify interesting routes
            interesting_routes = self._identify_interesting_routes(endpoints)
            
            return {
                'js_file': js_url,
                'endpoints': list(endpoints),
                'parameters': list(parameters),
                'interesting_routes': interesting_routes
            }
        except Exception as e:
            logger.debug(f"[JS_HUNTER] Error downloading {js_url}: {e}")
            return {'js_file': js_url, 'endpoints': [], 'parameters': [], 'interesting_routes': []}

    def _extract_endpoints_from_js(self, js_content: str, base_url: str) -> Set[str]:
        """Extract endpoints from JavaScript content."""
        endpoints = set()
        
        # Extract from common API calls
        fetch_pattern = r'fetch\s*\(\s*["\']([^"\']+)["\']'
        for match in re.finditer(fetch_pattern, js_content, re.IGNORECASE):
            endpoint = match.group(1)
            endpoints.add(endpoint)
        
        # Extract from axios/XMLHttpRequest
        axios_pattern = r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']'
        for match in re.finditer(axios_pattern, js_content, re.IGNORECASE):
            endpoint = match.group(1)
            endpoints.add(endpoint)
        
        xhr_pattern = r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\'],\s*["\']([^"\']+)["\']'
        for match in re.finditer(xhr_pattern, js_content, re.IGNORECASE):
            endpoint = match.group(1)
            endpoints.add(endpoint)
        
        # Extract from $.ajax
        ajax_pattern = r'(?:jQuery|)\s*\.\s*ajax\s*\(\s*{[^}]*url\s*:\s*["\']([^"\']+)["\']'
        for match in re.finditer(ajax_pattern, js_content, re.IGNORECASE):
            endpoint = match.group(1)
            endpoints.add(endpoint)
        
        # Extract quoted URLs with common API patterns
        url_pattern = r'["\'](/(?:api|admin|upload|login|graphql|wp-json|v[0-9]|ajax|rest|internal|private)[^"\']*)["\']'
        for match in re.finditer(url_pattern, js_content):
            endpoint = match.group(1)
            endpoints.add(endpoint)
        
        # Normalize relative URLs
        normalized = set()
        for endpoint in endpoints:
            if endpoint.startswith('/'):
                normalized.add(endpoint)
            elif endpoint.startswith('http'):
                # Extract path from full URL
                parsed = urlparse(endpoint)
                if parsed.path:
                    normalized.add(parsed.path + ('?' + parsed.query if parsed.query else ''))
        
        return normalized

    def _extract_parameters_from_js(self, js_content: str) -> Set[str]:
        """Extract parameter names from JavaScript content."""
        parameters = set()
        
        # Look for variable assignments with common parameter names
        for param in self.COMMON_PARAMETERS:
            patterns = [
                rf'{param}\s*:\s*',  # Object notation
                rf'{param}=',  # Assignment
                rf'["\']?{param}["\']?\s*:',  # JSON
                rf'[?&]{param}=',  # Query string
            ]
            
            for pattern in patterns:
                if re.search(pattern, js_content, re.IGNORECASE):
                    parameters.add(param)
        
        # Extract from URL patterns like ?key=value
        query_pattern = r'[?&]([a-zA-Z_][a-zA-Z0-9_]*?)(?:=|&)'
        for match in re.finditer(query_pattern, js_content):
            param = match.group(1)
            if len(param) > 1:  # Filter single letters
                parameters.add(param)
        
        # Extract from JSON payloads
        json_pattern = r'["\']([a-zA-Z_][a-zA-Z0-9_]*?)["\']?\s*:\s*'
        for match in re.finditer(json_pattern, js_content):
            param = match.group(1)
            if len(param) > 1 and param not in {'if', 'for', 'function', 'return'}:
                parameters.add(param)
        
        return parameters

    def _normalize_endpoints(self, endpoints: Set[str]) -> Set[str]:
        """Normalize and deduplicate endpoints."""
        normalized = set()
        
        for endpoint in endpoints:
            # Skip empty or invalid endpoints
            if not endpoint or len(endpoint) < 2:
                continue
            
            # Skip if it looks like a variable or code
            if endpoint.startswith('{') or endpoint.startswith('$') or endpoint.startswith('+'):
                continue
            
            # Skip encoded URLs
            if '%' in endpoint and len(endpoint) > 200:
                continue
            
            # Remove trailing slashes for consistency
            endpoint = endpoint.rstrip('/')
            
            # Skip duplicates
            if endpoint not in normalized:
                normalized.add(endpoint)
        
        return normalized

    def _identify_interesting_routes(self, endpoints: List[str]) -> List[str]:
        """Identify high-priority endpoints."""
        interesting = []
        priorities = [
            'admin', 'upload', 'login', 'auth', 'graphql',
            'api/v', 'plugin', 'theme', 'wp-admin',
            'config', 'backup', 'export', 'import'
        ]
        
        for endpoint in endpoints:
            for priority in priorities:
                if priority in endpoint.lower():
                    interesting.append(endpoint)
                    break
        
        return interesting[:20]  # Top 20 interesting routes

    def export_to_state(self, results: Dict[str, Any], state: StateManager = None) -> None:
        """Export hunting results to state manager."""
        if state is None:
            state = self.state
        
        if not state:
            logger.warning("[JS_HUNTER] No state manager provided for export")
            return
        
        # Merge with existing endpoints
        existing_endpoints = state.get("endpoints", []) or []
        existing_urls = {ep.get('url', '') for ep in existing_endpoints}
        
        new_endpoints = []
        for endpoint in results.get('endpoints', []):
            if endpoint not in existing_urls:
                new_endpoints.append({
                    'url': endpoint,
                    'source': 'js_hunter',
                    'method': 'GET',
                    'parameters': list(results.get('parameters', []))[:5]
                })
        
        logger.info(f"[JS_HUNTER] Adding {len(new_endpoints)} new endpoints to state")
        state.update(endpoints=existing_endpoints + new_endpoints)


def hunt_js_endpoints(state: StateManager, js_urls: List[str]) -> Dict[str, Any]:
    """
    Standalone function to hunt JS endpoints.
    Integrates with existing reconnaissance pipeline.
    """
    hunter = JSEndpointHunter(state=state)
    results = hunter.hunt_endpoints(js_urls)
    hunter.export_to_state(results, state)
    return results
