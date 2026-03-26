"""
ai/endpoint_classifier.py - Endpoint Classifier
Rule-based and AI-based endpoint classification for vulnerability scanning
"""

import logging
import json
from typing import Dict, Any, List, Optional

logger = logging.getLogger("recon.endpoint_classifier")

# ─── SYSTEM PROMPT FOR ENDPOINT CLASSIFICATION ──────────────────────────────────
_ENDPOINT_CLASSIFIER_SYSTEM = """You are an elite web security reconnaissance AI.

Your task is to classify discovered URLs and identify potential attack surfaces.

Analyze the given endpoint and determine:

1. endpoint_type
Choose one:
- api
- admin_panel
- authentication
- upload
- file_download
- data_import
- form
- static
- unknown

2. technologies
Identify possible technologies if visible:
wordpress, php, laravel, node, java, asp, nginx, apache

3. attack_surface
Detect possible attack surfaces:
- parameters
- file upload
- authentication
- database interaction
- admin functionality
- api endpoint
- file handling

4. interest_level
Score the endpoint:
- high (write operations, upload, import, admin)
- medium (API or forms)
- low (static content)

5. notes
Short reasoning (1 sentence).

Return ONLY valid JSON."""


class EndpointClassifier:
    """
    Rule-based and AI-based endpoint classification.
    Classifies URLs by potential vulnerabilities and risk levels.
    """

    def __init__(self, groq_client=None):
        self.groq = groq_client  # Optional Groq client for AI classification

    def classify(self, endpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classify an endpoint using AI or rule-based analysis

        Args:
            endpoint_data: Dict containing 'url', 'path', 'parameters', 'context'

        Returns:
            Dict with 'categories', 'risk_level', 'confidence', 'reasoning', 'endpoint_type', etc.
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
                'reasoning': 'Static file - excluded from scanning',
                'endpoint_type': 'static',
                'attack_surface': [],
                'interest_level': 'low'
            }

        # Try AI classification if Groq client available
        if self.groq:
            try:
                ai_result = self._classify_with_ai(endpoint_data)
                if ai_result:
                    # Merge AI results with rule-based confidence
                    rule_result = self._classify_rules_based(url, path, params, context)
                    return self._merge_classifications(ai_result, rule_result)
            except Exception as e:
                logger.debug(f"[CLASSIFIER] AI classification failed: {e}, falling back to rules")

        # Fallback to rule-based classification
        return self._classify_rules_based(url, path, params, context)

    def _classify_rules_based(self, url: str, path: str, params: List[str], context: str) -> Dict[str, Any]:
        """Rule-based classification method"""

    def _classify_rules_based(self, url: str, path: str, params: List[str], context: str) -> Dict[str, Any]:
        """Rule-based classification method"""
        categories = self._determine_categories(url, path, params, context)
        risk_level = self._calculate_risk_level(categories, params)
        confidence = self._calculate_confidence(categories, params)

        return {
            'categories': categories,
            'risk_level': risk_level,
            'confidence': confidence,
            'reasoning': self._build_reasoning(categories, params),
            'endpoint_type': self._map_categories_to_type(categories),
            'attack_surface': categories,
            'interest_level': self._map_risk_to_interest(risk_level)
        }

    def _classify_with_ai(self, endpoint_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Use Groq AI to classify endpoint.
        Returns enriched classification with AI insights.
        """
        try:
            endpoint_str = json.dumps({
                'url': endpoint_data.get('url', ''),
                'path': endpoint_data.get('path', ''),
                'parameters': endpoint_data.get('parameters', []),
                'context': endpoint_data.get('context', '')
            }, indent=2)
            
            prompt = f"""Classify this endpoint:

{endpoint_str}

Provide classification in JSON format with endpoint_type, technologies, attack_surface, interest_level, and notes."""

            response = self.groq.generate(
                prompt=prompt,
                system=_ENDPOINT_CLASSIFIER_SYSTEM,
                temperature=0.2
            )
            
            # Parse JSON response
            try:
                result = json.loads(response)
                logger.debug(f"[CLASSIFIER] AI classification: {result}")
                return result
            except json.JSONDecodeError:
                logger.debug(f"[CLASSIFIER] Failed to parse AI response: {response}")
                return None
        except Exception as e:
            logger.debug(f"[CLASSIFIER] AI classification error: {e}")
            return None

    def _merge_classifications(self, ai_result: Dict, rule_result: Dict) -> Dict[str, Any]:
        """Merge AI and rule-based classifications"""
        merged = rule_result.copy()
        
        if ai_result:
            # Use AI endpoint_type if available
            if 'endpoint_type' in ai_result:
                merged['endpoint_type'] = ai_result['endpoint_type']
            
            # Merge technologies
            if 'technologies' in ai_result:
                merged['technologies'] = ai_result['technologies']
            
            # Use AI attack_surface if more comprehensive
            if 'attack_surface' in ai_result and len(ai_result['attack_surface']) > len(merged.get('attack_surface', [])):
                merged['attack_surface'] = ai_result['attack_surface']
            
            # Use AI interest_level
            if 'interest_level' in ai_result:
                merged['interest_level'] = ai_result['interest_level']
            
            # Add AI notes
            if 'notes' in ai_result:
                merged['ai_notes'] = ai_result['notes']
            
            # Boost confidence for AI-confirmed classifications
            merged['confidence'] = min(merged.get('confidence', 0.5) + 0.15, 1.0)
        
        return merged

    def _map_categories_to_type(self, categories: List[str]) -> str:
        """Map categories to endpoint type"""
        if not categories:
            return 'unknown'
        
        category = categories[0]  # Use first/primary category
        
        mapping = {
            'admin_panel': 'admin_panel',
            'authentication': 'authentication',
            'file_upload': 'upload',
            'file_download': 'file_download',
            'api_endpoint': 'api',
            'static_file': 'static',
            'dynamic_endpoint': 'form'
        }
        
        return mapping.get(category, 'unknown')

    def _map_risk_to_interest(self, risk_level: str) -> str:
        """Map risk level to interest level"""
        mapping = {
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'INFO': 'low'
        }
        return mapping.get(risk_level, 'low')

    def _determine_categories(self, url: str, path: str, params: List[str], context: str) -> List[str]:
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