"""
modules/api_scanner.py - REST/GraphQL API Detection and Testing
Identifies API endpoints and tests for common vulnerabilities
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
import subprocess

logger = logging.getLogger("recon.api_scanner")


class APIScannerRunner:
    """Scan for REST and GraphQL APIs"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.api_endpoints = []
        self.graphql_endpoints = []
        self.swagger_endpoints = []
        self.openapi_endpoints = []

    def scan(self, url: str, content: str = "", headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Scan for APIs on given URL"""
        result = {
            "url": url,
            "apis_found": [],
            "rest_endpoints": [],
            "graphql_endpoints": [],
            "api_docs": [],
            "vulnerabilities": [],
            "raw_endpoints": []
        }

        # Detect API documentation endpoints
        self._find_api_docs(url, result)
        
        # Detect REST API endpoints
        self._find_rest_endpoints(url, content, result)
        
        # Detect GraphQL endpoints
        self._find_graphql_endpoints(url, content, result)
        
        # Test discovered endpoints
        self._test_endpoints(url, result)
        
        return result

    def _find_api_docs(self, base_url: str, result: Dict[str, Any]):
        """Find API documentation endpoints"""
        doc_endpoints = [
            "/swagger-ui.html",
            "/swagger-ui/",
            "/swagger-ui/index.html",
            "/api-docs",
            "/api/docs",
            "/api/v1/docs",
            "/api/v2/docs",
            "/api/v3/docs",
            "/docs",
            "/documentation",
            "/api/documentation",
            "/openapi.json",
            "/openapi.yaml",
            "/swagger.json",
            "/swagger.yaml",
            "/.well-known/openapi.json",
            "/.well-known/swagger.json",
            "/graphql",
            "/graphql/",
            "/graphql/playground",
            "/graphql/console",
            "/graphql/explorer",
            "/apollo/explorer",
        ]
        
        for endpoint in doc_endpoints:
            full_url = urljoin(base_url, endpoint)
            try:
                import urllib.request
                import socket
                
                # Set a short timeout for API doc probing
                socket.setdefaulttimeout(3)
                response = urllib.request.urlopen(full_url, timeout=3)
                if response.status == 200:
                    result["api_docs"].append({
                        "endpoint": endpoint,
                        "url": full_url,
                        "status": 200,
                        "type": self._identify_doc_type(endpoint)
                    })
                    logger.info(f"[API] Found documentation: {full_url}")
            except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, Exception):
                pass
            finally:
                socket.setdefaulttimeout(None)

    def _identify_doc_type(self, endpoint: str) -> str:
        """Identify API documentation type"""
        endpoint_lower = endpoint.lower()
        if "swagger" in endpoint_lower:
            return "Swagger/OpenAPI"
        elif "openapi" in endpoint_lower:
            return "OpenAPI"
        elif "graphql" in endpoint_lower:
            return "GraphQL"
        elif "apollo" in endpoint_lower:
            return "Apollo"
        else:
            return "API Docs"

    def _find_rest_endpoints(self, base_url: str, content: str, result: Dict[str, Any]):
        """Find REST API endpoints from content"""
        # Common REST endpoint patterns
        rest_patterns = [
            r'fetch\(["\'](/api/[^\s"\']+)["\']',  # JavaScript fetch calls
            r'href=["\'](/api/[^\s"\']+)["\']',     # Links to API
            r'action=["\'](/api/[^\s"\']+)["\']',   # Form actions
            r'url\s*:\s*["\']([/api][^\s"\']+)["\']',  # AJAX calls
            r'endpoint\s*:\s*["\']([^\s"\']+)["\']',   # Endpoint definitions
            r'"endpoint":\s*"([^\s"]+)"',             # JSON endpoint defs
        ]
        
        found_endpoints = set()
        
        for pattern in rest_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    endpoint = match[0]
                else:
                    endpoint = match
                
                if endpoint.startswith("/"):
                    found_endpoints.add(endpoint)
        
        # Common REST endpoints - only check first 5 for speed
        common_endpoints = [
            "/api",
            "/api/v1",
            "/api/users",
            "/api/products",
            "/rest",
        ]
        
        import urllib.request
        import socket
        import urllib.error
        
        for endpoint in common_endpoints:
            full_url = urljoin(base_url, endpoint)
            try:
                socket.setdefaulttimeout(2)
                response = urllib.request.urlopen(full_url, timeout=2)
                if response.status in [200, 201, 400, 401, 403]:
                    found_endpoints.add(endpoint)
                    logger.debug(f"[API] Found REST endpoint: {endpoint} ({response.status})")
            except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, Exception):
                pass
            finally:
                socket.setdefaulttimeout(None)
        
        result["rest_endpoints"] = list(found_endpoints)
        result["raw_endpoints"].extend(found_endpoints)

    def _find_graphql_endpoints(self, base_url: str, content: str, result: Dict[str, Any]):
        """Find GraphQL endpoints"""
        graphql_endpoints = [
            "/graphql",
            "/graphql/",
            "/api/graphql",
            "/api/v1/graphql",
            "/graphql/query",
            "/graphql/api",
            "/graph",
            "/apollo",
            "/relay",
        ]
        
        # Check for GraphQL in content
        graphql_indicators = [
            "GraphQL",
            "graphql",
            "__typename",
            "introspectionQuery",
            "apollo",
            "relay",
        ]
        
        has_graphql = any(indicator in content for indicator in graphql_indicators)
        
        found_endpoints = []
        
        for endpoint in graphql_endpoints:
            full_url = urljoin(base_url, endpoint)
            try:
                import urllib.request
                import socket
                import urllib.error
                # Test with introspection query
                query = {"query": "{ __typename }"}
                req = urllib.request.Request(
                    full_url,
                    data=json.dumps(query).encode(),
                    headers={"Content-Type": "application/json"}
                )
                socket.setdefaulttimeout(2)
                response = urllib.request.urlopen(req, timeout=2)
                
                if response.status in [200, 201, 400, 401, 403]:
                    found_endpoints.append(endpoint)
                    logger.debug(f"[API] Found GraphQL endpoint: {endpoint}")
            except (urllib.error.URLError, urllib.error.HTTPError, socket.timeout, Exception):
                pass
            finally:
                socket.setdefaulttimeout(None)
        
        if has_graphql or found_endpoints:
            result["graphql_endpoints"] = found_endpoints
            result["raw_endpoints"].extend(found_endpoints)

    def _test_endpoints(self, base_url: str, result: Dict[str, Any]):
        """Test discovered endpoints for vulnerabilities"""
        vulnerabilities = []
        
        # Test for common API vulnerabilities
        for endpoint in result.get("rest_endpoints", []):
            full_url = urljoin(base_url, endpoint)
            vuln = self._test_rest_endpoint(full_url)
            if vuln:
                vulnerabilities.extend(vuln)
        
        for endpoint in result.get("graphql_endpoints", []):
            full_url = urljoin(base_url, endpoint)
            vuln = self._test_graphql_endpoint(full_url)
            if vuln:
                vulnerabilities.extend(vuln)
        
        result["vulnerabilities"] = vulnerabilities

    def _test_rest_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """Test REST endpoint for vulnerabilities"""
        vulnerabilities = []
        
        try:
            import urllib.request
            import socket
            import urllib.error
            
            # Test 1: Check if endpoint requires authentication
            req = urllib.request.Request(url, method='GET')
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            try:
                socket.setdefaulttimeout(2)
                response = urllib.request.urlopen(req, timeout=2)
                if response.status == 200:
                    vulnerabilities.append({
                        "type": "Unauthenticated API Access",
                        "severity": "MEDIUM",
                        "url": url,
                        "description": "API endpoint accessible without authentication"
                    })
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    vulnerabilities.append({
                        "type": "Access Forbidden",
                        "severity": "LOW",
                        "url": url,
                        "description": "API endpoint exists but access is forbidden"
                    })
            except (urllib.error.URLError, socket.timeout):
                pass
            finally:
                socket.setdefaulttimeout(None)
            
            # Test 2: Check for CORS misconfiguration
            req = urllib.request.Request(url, method='OPTIONS')
            req.add_header('Origin', 'http://evil.com')
            
            try:
                socket.setdefaulttimeout(2)
                response = urllib.request.urlopen(req, timeout=2)
                allow_origin = response.headers.get('Access-Control-Allow-Origin', '')
                if '*' in allow_origin or 'evil.com' in allow_origin:
                    vulnerabilities.append({
                        "type": "CORS Misconfiguration",
                        "severity": "MEDIUM",
                        "url": url,
                        "description": f"Overly permissive CORS: {allow_origin}"
                    })
            except (urllib.error.URLError, socket.timeout):
                pass
            finally:
                socket.setdefaulttimeout(None)
        
        except Exception as e:
            logger.debug(f"Error testing endpoint {url}: {e}")
        
        return vulnerabilities

    def _test_graphql_endpoint(self, url: str) -> List[Dict[str, Any]]:
        """Test GraphQL endpoint for vulnerabilities"""
        vulnerabilities = []
        
        try:
            import urllib.request
            import socket
            import urllib.error
            
            # Test 1: Introspection query
            introspection_query = {
                "query": "{ __schema { types { name } } }"
            }
            
            req = urllib.request.Request(
                url,
                data=json.dumps(introspection_query).encode(),
                headers={"Content-Type": "application/json"}
            )
            
            try:
                socket.setdefaulttimeout(2)
                response = urllib.request.urlopen(req, timeout=2)
                if response.status == 200:
                    vulnerabilities.append({
                        "type": "GraphQL Introspection Enabled",
                        "severity": "MEDIUM",
                        "url": url,
                        "description": "GraphQL introspection is enabled, allowing schema discovery"
                    })
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    vulnerabilities.append({
                        "type": "GraphQL Access Denied",
                        "severity": "LOW",
                        "url": url,
                        "description": "GraphQL endpoint exists but introspection is blocked"
                    })
            except (urllib.error.URLError, socket.timeout):
                pass
            finally:
                socket.setdefaulttimeout(None)
            
            # Test 2: Error-based information disclosure
            error_query = {
                "query": "{ __typename invalid }"
            }
            
            req = urllib.request.Request(
                url,
                data=json.dumps(error_query).encode(),
                headers={"Content-Type": "application/json"}
            )
            
            try:
                socket.setdefaulttimeout(2)
                response = urllib.request.urlopen(req, timeout=2)
                content = response.read().decode()
                if "error" in content.lower():
                    vulnerabilities.append({
                        "type": "GraphQL Error Information Disclosure",
                        "severity": "LOW",
                        "url": url,
                        "description": "GraphQL errors reveal detailed information"
                    })
            except (urllib.error.URLError, socket.timeout):
                pass
            finally:
                socket.setdefaulttimeout(None)
        
        except Exception as e:
            logger.debug(f"Error testing GraphQL endpoint {url}: {e}")
        
        return vulnerabilities

    def scan_batch(self, urls: List[str], contents: List[str] = None) -> List[Dict[str, Any]]:
        """Scan multiple URLs"""
        results = []
        contents = contents or [""] * len(urls)
        
        for url, content in zip(urls, contents):
            results.append(self.scan(url, content))
        
        return results
