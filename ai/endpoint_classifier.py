"""
ai/endpoint_classifier.py - Endpoint Classifier
Rule-based and AI-based endpoint classification for vulnerability scanning
"""

import logging
import json
from typing import Dict, Any, List, Optional

logger = logging.getLogger("recon.endpoint_classifier")

# ─── SYSTEM PROMPT FOR ENDPOINT CLASSIFICATION ──────────────────────────────────
_ENDPOINT_CLASSIFIER_SYSTEM = """You are an elite penetration tester AI specializing in attack surface reconnaissance.

Your task is to identify HIGH-IMPACT attack vectors, not generic vulnerabilities.

Think like a professional attacker planning a real compromise:
- What endpoints lead to RCE, admin access, or database compromise?
- What are the realistic exploitation chains?
- Where can I write files, upload code, or escalate privileges?

Analyze the given endpoint and determine:

1. endpoint_type
Choose MOST RELEVANT:
- file_upload (CRITICAL: direct RCE potential)
- plugin_management (CRITICAL: arbitrary code)
- authentication (HIGH: bypass = access)
- admin_action (HIGH: privileged functionality)
- api_endpoint (HIGH: often unprotected)
- import_export (HIGH: data manipulation or upload)
- webhook_handler (HIGH: SSRF potential)
- configuration (MEDIUM: information disclosure)
- form (MEDIUM: injection points)
- file_download (MEDIUM: LFI potential)
- data_endpoint (MEDIUM: IDOR potential)
- static (LOW: info gathering only)
- unknown (ANALYZE FURTHER)

2. technologies
Identify framework, version hints:
wordpress, php, laravel, node, java, asp, python, ruby

3. high_impact_indicators
Does this endpoint have:
- file write capability? (upload, import, export)
- admin/privileged actions? (delete, create, modify settings)
- API access without strong auth?
- plugin/extension installation?
- custom code execution? (templates, imports, webhooks)
- direct filesystem access? (download, backup restore)

4. exploitation_hints
What specific attacks should be tested:
- file upload bypass (double ext, polyglot, MIME)
- authentication bypass (weak validation, IDOR)
- privilege escalation (role bypass, API abuse)
- command injection (parameters to system calls)
- SSRF (webhook, callback, remote_url parameters)

5. chain_potential
How could this endpoint lead to compromise:
- upload webshell → RCE
- auth bypass → admin panel → plugin install → RCE
- API abuse → data theft or privilege escalation
- configuration leak → credential extraction

6. interest_level
Score realistically:
- CRITICAL (file upload, plugin mgmt, auth bypass, admin actions)
- HIGH (APIs, import/export, webhooks, file operations)
- MEDIUM (data endpoints, forms, authentication endpoints)
- LOW (static content, informational)

7. notes
Brief exploitation scenario (1-2 sentences). WHY is this dangerous?

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
                temperature=0.2,
                max_tokens=2000,
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

        # ─── PRIORITY 1: WordPress oEmbed DETECTION ──────────────────────────────
        # oEmbed endpoints are low-value and cause excessive scanning
        # They typically only have 'url' or 'format' parameters
        if self._is_wordpress_oembed(url, path, params):
            return [{
                'category': 'oembed_endpoint',
                'risk_level': 'INFO',
                'skip_scanning': True,
                'reason': 'WordPress oEmbed endpoint - low exploitation value'
            }]

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

    def _is_wordpress_oembed(self, url: str, path: str, params: List[str]) -> bool:
        """
        Detect WordPress oEmbed endpoints that should be deprioritized.
        
        oEmbed endpoints are low-value for exploitation:
        - Path contains /oembed/ or /wp-json/oembed/
        - Only has 'url' or 'format' parameters (not injection-prone)
        - Used for embedding content, not security-critical
        
        Returns:
            True if this is a WordPress oEmbed endpoint that should be skipped
        """
        # Check for oEmbed path patterns
        oembed_patterns = [
            '/oembed/',
            '/wp-json/oembed/',
            '/wp-oembed',
            'oembed.php',
            '/embed/',  # Common WordPress embed path
        ]
        
        is_oembed_path = any(pattern in path for pattern in oembed_patterns)
        if not is_oembed_path:
            return False
        
        # Check if parameters are only low-risk ones (url, format, maxwidth, maxheight)
        low_risk_params = {'url', 'format', 'maxwidth', 'maxheight', 'discover', 'json', 'xml'}
        
        # Normalize params to lowercase for comparison
        param_names = set()
        for p in params:
            if isinstance(p, str):
                param_names.add(p.lower().split('=')[0])
            elif isinstance(p, dict):
                param_names.add(str(p.get('name', '')).lower())
        
        # If all parameters are low-risk, this is a low-value oEmbed endpoint
        if param_names and param_names.issubset(low_risk_params):
            logger.debug(f"[CLASSIFIER] Detected low-value oEmbed endpoint: {url[:100]}")
            return True
        
        # If no parameters at all, still low-value
        if not param_names:
            logger.debug(f"[CLASSIFIER] Detected oEmbed endpoint (no params): {url[:100]}")
            return True
        
        return False
