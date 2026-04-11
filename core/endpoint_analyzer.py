import urllib.parse
"""
core/endpoint_analyzer.py - Enhanced Endpoint Classification
Analyzes endpoints with HEAD/GET requests, content-type detection, and form extraction
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from html.parser import HTMLParser
import json
import requests
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("recon.endpoint_analyzer")


class FormExtractor(HTMLParser):
    """Extract forms from HTML"""
    
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.in_form = False
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        if tag == 'form':
            self.in_form = True
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET').upper(),
                'enctype': attrs_dict.get('enctype', ''),
                'fields': []
            }
        elif tag == 'input' and self.in_form:
            field = {
                'type': attrs_dict.get('type', 'text'),
                'name': attrs_dict.get('name', ''),
                'value': attrs_dict.get('value', ''),
                'required': 'required' in attrs_dict
            }
            if field['name']:
                self.current_form['fields'].append(field)
        elif tag == 'textarea' and self.in_form:
            field = {
                'type': 'textarea',
                'name': attrs_dict.get('name', ''),
                'required': 'required' in attrs_dict
            }
            if field['name']:
                self.current_form['fields'].append(field)
        elif tag == 'select' and self.in_form:
            field = {
                'type': 'select',
                'name': attrs_dict.get('name', ''),
                'required': 'required' in attrs_dict
            }
            if field['name']:
                self.current_form['fields'].append(field)
    
    def handle_endtag(self, tag):
        if tag == 'form' and self.in_form:
            if self.current_form and self.current_form['fields']:
                self.forms.append(self.current_form)
            self.in_form = False
            self.current_form = None


class EndpointAnalyzer:
    """
    Enhanced endpoint analyzer with:
    - HEAD/GET requests
    - Content-Type classification
    - Form extraction
    - Upload detection
    - Method support detection
    """

    STATIC_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff', '.woff2', '.ttf', '.svg', '.ico'}
    
    CONTENT_TYPE_MAP = {
        'text/html': 'html',
        'application/json': 'json',
        'application/xml': 'xml',
        'text/xml': 'xml',
        'text/plain': 'text',
        'application/x-www-form-urlencoded': 'form',
        'multipart/form-data': 'multipart',
        'image/': 'image',
        'text/css': 'css',
        'application/javascript': 'javascript',
        'text/javascript': 'javascript',
        'application/pdf': 'pdf',
    }

    @staticmethod
    def analyze(url: str, timeout: int = 5, follow_redirects: bool = True) -> Dict[str, Any]:
        """
        Analyze endpoint and classify it
        
        Returns:
            {
                'url': str,
                'reachable': bool,
                'status_code': int,
                'content_type': str,
                'endpoint_type': str,  # static, html, json, xml, api, upload, form
                'allows_methods': [str],
                'has_form': bool,
                'forms': List[Dict],
                'is_upload': bool,
                'encoding': str,
                'size_bytes': int,
                'has_query_params': bool,
                'params': [str],
                'confidence': float
            }
        """
        
        result = {
            'url': url,
            'reachable': False,
            'status_code': 0,
            'content_type': '',
            'endpoint_type': 'unknown',
            'allows_methods': [],
            'has_form': False,
            'forms': [],
            'is_upload': False,
            'encoding': '',
            'size_bytes': 0,
            'has_query_params': False,
            'params': [],
            'confidence': 0.0,
            'error': '',
            'technologies': [],
            'vulnerability_hints': [],
            'parameters': []
        }

        try:
            # Step 1: Try HEAD request first
            response = requests.head(
                url, 
                timeout=timeout, 
                allow_redirects=follow_redirects,
                verify=False
            )
            
            result['status_code'] = response.status_code
            result['reachable'] = response.status_code < 500
            
        except Exception as e:
            # Fallback to GET
            try:
                response = requests.get(
                    url,
                    timeout=timeout,
                    allow_redirects=follow_redirects,
                    verify=False,
                    stream=True
                )
                result['status_code'] = response.status_code
                result['reachable'] = response.status_code < 500
            except Exception as e2:
                result['error'] = str(e2)[:50]
                return result

        # Step 2: Extract Content-Type
        content_type = response.headers.get('Content-Type', '').lower()
        result['content_type'] = content_type

        # Step 3: Check for encoding
        if 'charset' in content_type:
            result['encoding'] = content_type.split('charset=')[-1].split(';')[0]

        # Step 4: Classify endpoint type
        result['endpoint_type'] = EndpointAnalyzer._classify_type(url, content_type)

        # Step 5: Check which methods are allowed
        allow_header = response.headers.get('Allow', '').upper()
        if allow_header:
            result['allows_methods'] = [m.strip() for m in allow_header.split(',')]

        # Step 6: Parse and analyze body if HTML
        if 'text/html' in content_type:
            try:
                if response.text:
                    result['size_bytes'] = len(response.text)
                    
                    # Extract forms
                    forms = EndpointAnalyzer._extract_forms(response.text, url)
                    if forms:
                        result['has_form'] = True
                        result['forms'] = forms
                        result['is_upload'] = any(f.get('enctype') == 'multipart/form-data' for f in forms)
                        result['endpoint_type'] = 'upload' if result['is_upload'] else 'form'
            except Exception as e:
                logger.warning(f"Failed to parse HTML from {url}: {str(e)[:50]}")

        # Step 7: Analyze query parameters
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            result['has_query_params'] = True
            result['params'] = list(parse_qs(parsed.query).keys())

        # Step 8: Calculate confidence
        result['confidence'] = EndpointAnalyzer._calculate_confidence(result)
        
        # Step 9: Generate vulnerability hints based on endpoint characteristics
        result['vulnerability_hints'] = EndpointAnalyzer.generate_vulnerability_hints(result)
        
        # Step 10: Extract detailed parameter information
        result['parameters'] = EndpointAnalyzer.extract_parameter_details(result)

        return result

    @staticmethod
    def _classify_type(url: str, content_type: str) -> str:
        """Classify endpoint type based on URL and content-type"""
        url_lower = url.lower()
        content_type_lower = content_type.lower()

        # Check for static files
        for ext in EndpointAnalyzer.STATIC_EXTENSIONS:
            if url_lower.endswith(ext):
                return 'static'

        # Check content-type mappings
        for ct, endpoint_type in EndpointAnalyzer.CONTENT_TYPE_MAP.items():
            if ct in content_type_lower:
                return endpoint_type

        # URL pattern analysis
        if 'api' in url_lower:
            return 'api'
        elif 'upload' in url_lower or 'file' in url_lower:
            return 'upload'
        elif 'login' in url_lower or 'auth' in url_lower:
            return 'auth'
        elif 'admin' in url_lower:
            return 'admin'
        elif 'search' in url_lower:
            return 'search'

        # Default to html if text-based
        if 'text' in content_type_lower:
            return 'html'

        return 'unknown'

    @staticmethod
    def _extract_forms(html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML"""
        try:
            extractor = FormExtractor()
            extractor.feed(html)
            
            forms = []
            for form in extractor.forms:
                # Normalize form action
                action = form.get('action', '')
                if action:
                    if action.startswith('/'):
                        parsed = urllib.parse.urlparse(base_url)
                        action = f"{parsed.scheme}://{parsed.netloc}{action}"
                    elif not action.startswith(('http://', 'https://')):
                        action = f"{base_url.rstrip('/')}/{action}"
                
                forms.append({
                    'action': action or base_url,
                    'method': form.get('method', 'GET'),
                    'enctype': form.get('enctype', ''),
                    'fields': form.get('fields', []),
                    'is_upload': form.get('enctype') == 'multipart/form-data'
                })
            
            return forms
        except Exception as e:
            logger.warning(f"Form extraction failed: {str(e)[:50]}")
            return []

    @staticmethod
    def _calculate_confidence(result: Dict) -> float:
        """Calculate confidence score for endpoint classification"""
        confidence = 0.0

        # Weight factors
        if result['reachable'] and result['status_code'] < 400:
            confidence += 0.3
        
        if result['content_type']:
            confidence += 0.2
        
        if result['endpoint_type'] != 'unknown':
            confidence += 0.25
        
        if result['endpoint_type'] in ('form', 'api', 'upload', 'auth', 'admin'):
            confidence += 0.15
        
        if result['has_form'] or result['has_query_params']:
            confidence += 0.1

        return min(confidence, 1.0)

    @staticmethod
    def should_send_payload(endpoint_type: str) -> bool:
        """Determine if endpoint should receive payloads"""
        # Don't send POST/PUT to static files
        no_payload_types = {'static', 'image', 'css', 'javascript', 'pdf'}
        return endpoint_type not in no_payload_types

    @staticmethod
    def generate_vulnerability_hints(result: Dict) -> List[str]:
        """
        Generate vulnerability hints based on endpoint characteristics.
        Returns list of vulnerability classes that may apply.
        """
        hints = []
        endpoint_type = result.get('endpoint_type', 'unknown')
        has_form = result.get('has_form', False)
        is_upload = result.get('is_upload', False)
        params = result.get('params', [])
        forms = result.get('forms', [])

        # File upload endpoints
        if endpoint_type == 'upload' or is_upload:
            hints.extend(['file_upload', 'rce_via_upload', 'arbitrary_file_upload'])

        # Form-based endpoints
        if endpoint_type == 'form' or has_form:
            hints.append('form_injection')
            # Check for specific parameters
            all_params = params + [f.get('name', '') for form in forms for f in form.get('fields', [])]
            for param in all_params:
                param_lower = param.lower()
                if 'file' in param_lower or 'path' in param_lower:
                    hints.append('lfi')
                if 'url' in param_lower or 'redirect' in param_lower:
                    hints.append('ssrf')
                if 'search' in param_lower or 'q' in param_lower:
                    hints.append('injection')

        # API endpoints
        if endpoint_type == 'api':
            hints.extend(['api_abuse', 'injection', 'auth_bypass'])

        # Authentication endpoints
        if endpoint_type == 'auth':
            hints.extend(['auth_bypass', 'credential_leak', 'user_enumeration'])

        # Admin endpoints
        if endpoint_type == 'admin':
            hints.extend(['privilege_escalation', 'auth_bypass', 'admin_access'])

        # Search/query endpoints
        if endpoint_type == 'search':
            hints.extend(['injection', 'xss'])

        # Parameter-based hints
        for param in params:
            param_lower = param.lower()
            if param_lower in ('id', 'user_id', 'userid', 'uid'):
                hints.append('enumeration')
            elif param_lower in ('file', 'path', 'dir', 'include', 'page', 'template'):
                hints.append('lfi')
            elif param_lower in ('url', 'redirect', 'callback', 'forward'):
                hints.append('ssrf')
            elif param_lower in ('cmd', 'exec', 'command', 'shell'):
                hints.append('rce')

        # Remove duplicates and return
        return list(set(hints))

    @staticmethod
    def extract_parameter_details(result: Dict) -> List[Dict]:
        """
        Extract detailed parameter information from forms and query strings.
        Returns list of parameter dictionaries with metadata.
        """
        parameters = []
        
        # From query string parameters
        for param in result.get('params', []):
            parameters.append({
                'name': param,
                'source': 'query_string',
                'required': False,
                'type': 'unknown'
            })
        
        # From form fields
        for form in result.get('forms', []):
            form_method = form.get('method', 'GET').upper()
            fields = form.get('fields', [])
            for field in fields:
                field_type = field.get('type', 'text')
                parameters.append({
                    'name': field.get('name', ''),
                    'source': f'form_{form_method}',
                    'required': field.get('required', False),
                    'type': field_type,
                    'value': field.get('value', '')
                })
        
        return parameters

    @staticmethod
    def enrich_with_technologies(result: Dict, technologies: List[str]) -> Dict:
        """
        Enrich endpoint result with technology information.
        Updates result dict in-place with tech-based hints.
        """
        result['technologies'] = technologies
        
        # Add tech-based vulnerability hints
        tech_hints = EndpointAnalyzer._get_tech_hints(technologies)
        existing_hints = EndpointAnalyzer.generate_vulnerability_hints(result)
        result['vulnerability_hints'] = list(set(existing_hints + tech_hints))
        
        return result

    @staticmethod
    def _get_tech_hints(technologies: List[str]) -> List[str]:
        """Map technologies to vulnerability classes."""
        hints = []
        techs_lower = [t.lower() for t in (technologies or [])]
        
        # WordPress
        if any('wordpress' in t or 'wp' in t for t in techs_lower):
            hints.extend(['file_upload', 'plugin_vuln', 'rce_via_plugin', 'privilege_escalation'])
        
        # PHP
        if any('php' in t for t in techs_lower):
            hints.extend(['file_inclusion', 'file_upload_rce', 'insecure_deserialization'])
        
        # Apache
        if any('apache' in t for t in techs_lower):
            hints.extend(['path_traversal', 'directory_listing', 'htaccess_bypass'])
        
        # Nginx
        if any('nginx' in t for t in techs_lower):
            hints.append('path_normalization_bypass')
        
        # IIS/ASP
        if any('iis' in t or 'asp' in t for t in techs_lower):
            hints.extend(['path_traversal', 'null_byte_injection'])
        
        # Node.js
        if any('node' in t or 'express' in t for t in techs_lower):
            hints.extend(['prototype_pollution', 'injection'])
        
        # Java
        if any('java' in t or 'tomcat' in t for t in techs_lower):
            hints.append('deserialization_rce')
        
        # MySQL
        if any('mysql' in t or 'mariadb' in t for t in techs_lower):
            hints.append('sqli')
        
        return hints
