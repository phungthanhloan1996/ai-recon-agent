"""
ai/endpoint_classifier.py - Endpoint Classifier
Rule-based endpoint classification for vulnerability scanning
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger("recon.endpoint_classifier")


class EndpointClassifier:
    """
    Rule-based endpoint classification.
    Classifies URLs by potential vulnerabilities and risk levels.
    """

    def __init__(self):
        pass  # No API key needed

    def classify(self, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an endpoint using rule-based analysis

        Args:
            endpoint_data: Dict containing 'url', 'path', 'parameters', 'context'

        Returns:
            Dict with 'categories', 'risk_level', 'confidence', 'reasoning'
        """
        url = endpoint_data.get('url', '').lower()
        path = endpoint_data.get('path', '').lower()
        params = endpoint_data.get('parameters', [])
        context = endpoint_data.get('context', '').lower()

        # RULE: Block static files completely
        if self._is_static_file(path):
            return {
                'categories': ['static_file'],
                'risk_level': 'INFO',
                'confidence': 0,
                'reasoning': 'Static file - excluded from scanning'
            }

        categories = self._determine_categories(url, path, params, context)
        risk_level = self._calculate_risk_level(categories, params)
        confidence = self._calculate_confidence(categories, params)

        return {
            'categories': categories,
            'risk_level': risk_level,
            'confidence': confidence,
            'reasoning': self._build_reasoning(categories, params)
        }

    def _determine_categories(self, url: str, path: str, params: List[str], context: str) -> List[str]:
        """Determine vulnerability categories based on rules"""
        categories = []

        # STRICT RULE: admin/auth ONLY for wp-admin or specific endpoints
        # NOT for files with parameters that happen to have "ver=" 
        if '/wp-admin' in path:
            categories.append('admin_panel')
        elif any(keyword in path for keyword in ['wp-login.php', 'login.php', 'admin.php']) and not self._is_static_file(path):
            if 'login' in path:
                categories.append('authentication')
            else:
                categories.append('admin_panel')

        # Dynamic endpoint if has parameters (but not static files with ver=)
        if params and not self._is_static_file(path):
            categories.append('dynamic_endpoint')

        # File upload
        if any(keyword in path for keyword in ['upload', 'file', 'image', 'attachment']) and not self._is_static_file(path):
            categories.append('file_upload')

        # API endpoints
        if 'api' in path or any(param in ['api', 'json', 'xml'] for param in params):
            categories.append('api_endpoint')

        # Search functionality
        if any(keyword in path for keyword in ['search', 'query', 'find']):
            categories.append('search')

        # File operations
        if any(keyword in path for keyword in ['download', 'export', 'backup']):
            categories.append('file_download')

        # User data
        if any(keyword in path for keyword in ['profile', 'user', 'account']):
            categories.append('user_data')

        # Potential SQL injection - ONLY if truly dynamic (not static files)
        if params and any(keyword in path for keyword in ['id', 'page', 'search', 'query']) and not self._is_static_file(path):
            categories.append('sql_injection')

        # Potential XSS - ONLY if truly dynamic (not static files)
        if params and any(keyword in path for keyword in ['comment', 'message', 'text', 'input']) and not self._is_static_file(path):
            categories.append('xss')

        # Command injection
        if any(keyword in path for keyword in ['exec', 'cmd', 'command', 'shell']):
            categories.append('command_injection')

        # If no specific categories, mark as other (not static)
        if not categories and not self._is_static_file(path):
            categories.append('other')

        return categories

    def _calculate_risk_level(self, categories: List[str], params: List[str]) -> str:
        """Calculate overall risk level"""
        high_risk = ['admin_panel', 'file_upload', 'command_injection', 'file_inclusion']
        medium_risk = ['authentication', 'api_endpoint', 'sql_injection', 'xss']
        low_risk = ['search', 'file_download', 'user_data', 'dynamic_endpoint']

        if any(cat in high_risk for cat in categories):
            return 'HIGH'
        elif any(cat in medium_risk for cat in categories):
            return 'MEDIUM'
        elif any(cat in low_risk for cat in categories):
            return 'LOW'
        else:
            return 'INFO'

    def _calculate_confidence(self, categories: List[str], params: List[str]) -> float:
        """Calculate classification confidence"""
        base_confidence = 0.5
        if params:
            base_confidence += 0.2  # Parameters increase confidence
        if len(categories) > 1:
            base_confidence += 0.1  # Multiple categories increase confidence
        return min(base_confidence, 1.0)

    def _build_reasoning(self, categories: List[str], params: List[str]) -> str:
        """Build reasoning string"""
        reasons = []
        if params:
            reasons.append("Has parameters")
        if categories:
            reasons.append(f"Categories: {', '.join(categories)}")
        return "; ".join(reasons)

    def _is_static_file(self, path: str) -> bool:
        """
        Check if path is a static file that should NOT be scanned.
        RULE: Do NOT scan static files
        """
        static_extensions = {
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg',
            '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm',
            '.ico', '.map', '.json', '.xml', '.txt'
        }
        
        # Check extension
        for ext in static_extensions:
            if path.endswith(ext):
                return True
        
        # Check static file patterns
        static_patterns = [
            '/static/', '/assets/', '/dist/', '/build/', '/public/',
            '/images/', '/img/', '/fonts/', '/styles/', '/scripts/',
            '/vendor/', '/node_modules/', '/media/'
        ]
        for pattern in static_patterns:
            if pattern in path:
                return True
        
        return False