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
            'error': ''
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
        parsed = urlparse(url)
        if parsed.query:
            result['has_query_params'] = True
            result['params'] = list(parse_qs(parsed.query).keys())

        # Step 8: Calculate confidence
        result['confidence'] = EndpointAnalyzer._calculate_confidence(result)

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
                        parsed = urlparse(base_url)
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
