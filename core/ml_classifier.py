import urllib.parse
"""
core/ml_classifier.py - ML-based endpoint classification

Provides machine learning capabilities for automatic endpoint classification,
vulnerability prediction, and smart target prioritization.
"""

import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import re
import hashlib
import json
import time
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class EndpointType(Enum):
    """Classification types for endpoints"""
    API = "api"
    WEB = "web"
    ADMIN = "admin"
    AUTH = "auth"
    UPLOAD = "upload"
    STATIC = "static"
    UNKNOWN = "unknown"


class VulnerabilityCategory(Enum):
    """Categories of vulnerabilities"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    LFI = "lfi"
    RCE = "rce"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    XXE = "xxe"
    COMMAND_INJECTION = "command_injection"
    FILE_UPLOAD = "file_upload"
    PATH_TRAVERSAL = "path_traversal"


@dataclass
class EndpointFeatures:
    """Features extracted from an endpoint for ML classification"""
    url: str
    path_length: int
    path_depth: int
    has_parameters: bool
    parameter_count: int
    has_numeric_segments: bool
    has_special_chars: bool
    path_segments: List[str] = field(default_factory=list)
    file_extension: str = ""
    http_method: str = "GET"
    response_code: int = 200
    response_size: int = 0
    response_time: float = 0.0
    has_auth_header: bool = False
    content_type: str = ""
    keywords_present: List[str] = field(default_factory=list)
    tech_indicators: List[str] = field(default_factory=list)


@dataclass
class ClassificationResult:
    """Result of endpoint classification"""
    endpoint: str
    predicted_type: EndpointType
    confidence: float
    probabilities: Dict[str, float] = field(default_factory=dict)
    features: Optional[EndpointFeatures] = None
    reasoning: str = ""


@dataclass
class VulnerabilityPrediction:
    """Prediction of potential vulnerabilities"""
    endpoint: str
    vulnerability_type: VulnerabilityCategory
    probability: float
    confidence: str  # low, medium, high
    indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class MLClassifier:
    """
    Machine learning-based classifier for endpoints and vulnerability prediction.
    
    Features:
    - Rule-based classification with ML-like scoring
    - Pattern matching for endpoint type detection
    - Vulnerability prediction based on endpoint characteristics
    - Adaptive learning from scan results
    - Feature extraction and analysis
    """
    
    def __init__(self):
        # Keyword patterns for endpoint classification
        self.api_patterns = [
            r'/api/', r'/v\d+/', r'/rest/', r'/graphql', r'/soap',
            r'/rpc/', r'/service/', r'/endpoint', r'/action/',
            r'\.json$', r'\.xml$', r'\.api$',
        ]
        
        self.admin_patterns = [
            r'/admin', r'/dashboard', r'/panel', r'/console',
            r'/manager', r'/control', r'/manage/', r'/backend',
            r'/wp-admin', r'/administrator', r'/cpanel',
        ]
        
        self.auth_patterns = [
            r'/login', r'/auth', r'/signin', r'/signup',
            r'/register', r'/oauth', r'/saml', r'/sso',
            r'/token', r'/session', r'/logout', r'/password',
        ]
        
        self.upload_patterns = [
            r'/upload', r'/download', r'/file', r'/attachment',
            r'/media', r'/asset', r'/image', r'/document',
            r'/import', r'/export', r'/backup',
        ]
        
        self.static_patterns = [
            r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|ttf|eot)$',
            r'/static/', r'/assets/', r'/public/', r'/dist/',
            r'/cdn/', r'/media/', r'/images/',
        ]
        
        # Vulnerability indicators
        self.vuln_indicators = {
            VulnerabilityCategory.SQL_INJECTION: {
                'patterns': [
                    r'[?&](id|user|page|sort|order|filter|search|query)=',
                    r'/\d+/',  # Numeric ID in path
                    r'[?&](name|email|username)=',
                ],
                'keywords': ['select', 'union', 'drop', 'insert', 'update', 'delete'],
                'weight': 0.8,
            },
            VulnerabilityCategory.XSS: {
                'patterns': [
                    r'[?&](q|search|query|keyword|text|content)=',
                    r'[?&](name|title|description|comment)=',
                ],
                'keywords': ['script', 'alert', 'document', 'eval', 'innerHTML'],
                'weight': 0.7,
            },
            VulnerabilityCategory.LFI: {
                'patterns': [
                    r'[?&](file|path|page|include|template|document)=',
                    r'\.\./', r'%2e%2e/', r'..%2f',
                ],
                'keywords': ['etc/passwd', 'boot.ini', 'win.ini'],
                'weight': 0.9,
            },
            VulnerabilityCategory.RCE: {
                'patterns': [
                    r'[?&](cmd|command|exec|execute|system|shell)=',
                    r'/cgi-bin/', r'/shell/', r'/cmd/',
                ],
                'keywords': ['exec', 'system', 'passthru', 'shell_exec'],
                'weight': 0.95,
            },
            VulnerabilityCategory.IDOR: {
                'patterns': [
                    r'/\d+/',  # Numeric IDs
                    r'[?&](id|user_id|account_id|order_id)=',
                    r'/user/\d+', r'/account/\d+',
                ],
                'keywords': ['id', 'user_id', 'account', 'profile'],
                'weight': 0.75,
            },
            VulnerabilityCategory.SSRF: {
                'patterns': [
                    r'[?&](url|uri|link|redirect|next|return)=',
                    r'[?&](fetch|load|retrieve|download)=',
                ],
                'keywords': ['http://', 'https://', 'ftp://', 'file://'],
                'weight': 0.85,
            },
        }
        
        # Tech stack indicators
        self.tech_patterns = {
            'WordPress': [r'/wp-', r'/wp-content', r'/wp-includes', r'wp-'],
            'Joomla': [r'/index.php', r'/component/', r'option=com_'],
            'Drupal': [r'/node/', r'/sites/', r'drupal'],
            'Laravel': [r'/api/', r'/sanctum/', r'/breeze/'],
            'Django': [r'/admin/', r'/static/', r'/media/'],
            'Express': [r'/api/', r'/public/', r'/routes/'],
            'Spring': [r'/api/', r'/actuator/', r'/swagger'],
        }
        
        # Learning data
        self.classification_history: List[ClassificationResult] = []
        self.vulnerability_history: List[VulnerabilityPrediction] = []
        self.confidence_scores: Dict[str, List[float]] = defaultdict(list)
        
        # Statistics
        self.stats = {
            'classifications': 0,
            'predictions': 0,
            'high_confidence': 0,
            'low_confidence': 0,
        }
    
    def extract_features(self, url: str, response_data: Dict = None) -> EndpointFeatures:
        """Extract features from URL and response data"""
        from urllib.parse import urlparse, parse_qs
        
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        query_params = parse_qs(parsed.query)
        
        # Basic path analysis
        path_segments = [s for s in path.split('/') if s]
        path_length = len(path)
        path_depth = len(path_segments)
        
        # Parameter analysis
        has_parameters = bool(query_params)
        parameter_count = sum(len(v) for v in query_params.values())
        
        # Numeric and special character analysis
        has_numeric_segments = any(s.isdigit() for s in path_segments)
        has_special_chars = bool(re.search(r'[%&=?\-_.]', path))
        
        # File extension
        file_extension = ""
        if '.' in path_segments[-1] if path_segments else "":
            file_extension = path_segments[-1].split('.')[-1].lower()
        
        # Keywords detection
        keywords_present = []
        path_lower = path.lower()
        for keyword in ['api', 'admin', 'login', 'upload', 'user', 'search', 'query']:
            if keyword in path_lower:
                keywords_present.append(keyword)
        
        # Tech indicators
        tech_indicators = []
        for tech, patterns in self.tech_patterns.items():
            if any(re.search(p, path_lower) for p in patterns):
                tech_indicators.append(tech)
        
        # Response data analysis
        response_code = 200
        response_size = 0
        response_time = 0.0
        content_type = ""
        has_auth_header = False
        
        if response_data:
            response_code = response_data.get('status_code', 200)
            response_size = len(response_data.get('body', ''))
            response_time = response_data.get('response_time', 0.0)
            content_type = response_data.get('content_type', '')
            headers = response_data.get('headers', {})
            has_auth_header = 'authorization' in headers or 'cookie' in headers
        
        return EndpointFeatures(
            url=url,
            path_length=path_length,
            path_depth=path_depth,
            has_parameters=has_parameters,
            parameter_count=parameter_count,
            has_numeric_segments=has_numeric_segments,
            has_special_chars=has_special_chars,
            path_segments=path_segments,
            file_extension=file_extension,
            http_method=response_data.get('method', 'GET') if response_data else 'GET',
            response_code=response_code,
            response_size=response_size,
            response_time=response_time,
            has_auth_header=has_auth_header,
            content_type=content_type,
            keywords_present=keywords_present,
            tech_indicators=tech_indicators,
        )
    
    def classify_endpoint(self, url: str, response_data: Dict = None) -> ClassificationResult:
        """
        Classify an endpoint using pattern matching and scoring.
        
        Returns ClassificationResult with predicted type and confidence.
        """
        features = self.extract_features(url, response_data)
        self.stats['classifications'] += 1
        
        # Score for each endpoint type
        scores = {
            EndpointType.API: 0.0,
            EndpointType.WEB: 0.3,  # Base score for web
            EndpointType.ADMIN: 0.0,
            EndpointType.AUTH: 0.0,
            EndpointType.UPLOAD: 0.0,
            EndpointType.STATIC: 0.0,
            EndpointType.UNKNOWN: 0.0,
        }
        
        path_lower = url.lower()
        
        # Check API patterns
        for pattern in self.api_patterns:
            if re.search(pattern, path_lower):
                scores[EndpointType.API] += 0.3
                break
        
        # Check admin patterns
        for pattern in self.admin_patterns:
            if re.search(pattern, path_lower):
                scores[EndpointType.ADMIN] += 0.4
                break
        
        # Check auth patterns
        for pattern in self.auth_patterns:
            if re.search(pattern, path_lower):
                scores[EndpointType.AUTH] += 0.4
                break
        
        # Check upload patterns
        for pattern in self.upload_patterns:
            if re.search(pattern, path_lower):
                scores[EndpointType.UPLOAD] += 0.4
                break
        
        # Check static patterns
        for pattern in self.static_patterns:
            if re.search(pattern, path_lower):
                scores[EndpointType.STATIC] += 0.5
                break
        
        # Feature-based adjustments
        if features.has_parameters and features.parameter_count > 2:
            scores[EndpointType.API] += 0.1
            scores[EndpointType.WEB] += 0.05
        
        if features.has_numeric_segments:
            scores[EndpointType.API] += 0.05
            scores[EndpointType.IDOR] = scores.get(EndpointType.IDOR, 0) + 0.1
        
        if features.file_extension in ['json', 'xml']:
            scores[EndpointType.API] += 0.2
        
        if features.file_extension in ['css', 'js', 'png', 'jpg', 'svg']:
            scores[EndpointType.STATIC] += 0.3
        
        if 'api' in features.keywords_present:
            scores[EndpointType.API] += 0.15
        
        if 'admin' in features.keywords_present:
            scores[EndpointType.ADMIN] += 0.15
        
        if 'login' in features.keywords_present or 'auth' in features.keywords_present:
            scores[EndpointType.AUTH] += 0.15
        
        if features.has_auth_header:
            scores[EndpointType.API] += 0.05
            scores[EndpointType.ADMIN] += 0.05
        
        # Normalize scores to probabilities
        total_score = sum(scores.values()) or 1.0
        probabilities = {k.value: v / total_score for k, v in scores.items()}
        
        # Determine predicted type
        predicted_type = max(scores, key=scores.get)
        confidence = scores[predicted_type] / total_score
        
        # Generate reasoning
        reasoning = self._generate_reasoning(predicted_type, features, scores)
        
        result = ClassificationResult(
            endpoint=url,
            predicted_type=predicted_type,
            confidence=confidence,
            probabilities=probabilities,
            features=features,
            reasoning=reasoning,
        )
        
        # Track confidence scores
        self.confidence_scores[predicted_type.value].append(confidence)
        
        if confidence >= 0.7:
            self.stats['high_confidence'] += 1
        else:
            self.stats['low_confidence'] += 1
        
        self.classification_history.append(result)
        
        return result
    
    def _generate_reasoning(self, predicted_type: EndpointType, features: EndpointFeatures, scores: Dict) -> str:
        """Generate human-readable reasoning for classification"""
        reasons = []
        
        if predicted_type == EndpointType.API:
            if features.file_extension in ['json', 'xml']:
                reasons.append(f"File extension: {features.file_extension}")
            if features.has_parameters:
                reasons.append(f"Has {features.parameter_count} parameters")
            if 'api' in features.keywords_present:
                reasons.append("Contains 'api' keyword")
            if features.tech_indicators:
                reasons.append(f"Tech indicators: {', '.join(features.tech_indicators)}")
        
        elif predicted_type == EndpointType.ADMIN:
            if 'admin' in features.keywords_present:
                reasons.append("Contains 'admin' keyword")
            if features.has_auth_header:
                reasons.append("Requires authentication")
        
        elif predicted_type == EndpointType.AUTH:
            if 'login' in features.keywords_present or 'auth' in features.keywords_present:
                reasons.append("Contains auth-related keywords")
        
        elif predicted_type == EndpointType.STATIC:
            if features.file_extension in ['css', 'js', 'png', 'jpg']:
                reasons.append(f"Static file extension: {features.file_extension}")
        
        return "; ".join(reasons) if reasons else "Pattern-based classification"
    
    def predict_vulnerabilities(self, url: str, response_data: Dict = None) -> List[VulnerabilityPrediction]:
        """
        Predict potential vulnerabilities for an endpoint.
        
        Returns list of VulnerabilityPrediction with probability scores.
        """
        features = self.extract_features(url, response_data)
        self.stats['predictions'] += 1
        
        predictions = []
        path_lower = url.lower()
        
        for vuln_type, config in self.vuln_indicators.items():
            score = 0.0
            indicators = []
            
            # Check patterns
            for pattern in config['patterns']:
                if re.search(pattern, path_lower):
                    score += 0.3
                    indicators.append(f"Pattern match: {pattern}")
            
            # Check keywords in URL
            for keyword in config['keywords']:
                if keyword in path_lower:
                    score += 0.2
                    indicators.append(f"Keyword: {keyword}")
            
            # Feature-based indicators
            if vuln_type == VulnerabilityCategory.IDOR and features.has_numeric_segments:
                score += 0.15
                indicators.append("Numeric segments in path")
            
            if vuln_type == VulnerabilityCategory.SQL_INJECTION and features.parameter_count > 1:
                score += 0.1
                indicators.append(f"Multiple parameters ({features.parameter_count})")
            
            # Apply weight
            score *= config['weight']
            
            # Cap score at 1.0
            score = min(score, 1.0)
            
            if score > 0.2:  # Only report if score is significant
                # Determine confidence level
                if score >= 0.7:
                    confidence = "high"
                elif score >= 0.4:
                    confidence = "medium"
                else:
                    confidence = "low"
                
                # Generate recommendations
                recommendations = self._generate_recommendations(vuln_type, score)
                
                prediction = VulnerabilityPrediction(
                    endpoint=url,
                    vulnerability_type=vuln_type,
                    probability=score,
                    confidence=confidence,
                    indicators=indicators,
                    recommendations=recommendations,
                )
                predictions.append(prediction)
        
        # Sort by probability
        predictions.sort(key=lambda p: p.probability, reverse=True)
        
        self.vulnerability_history.extend(predictions)
        
        return predictions
    
    def _generate_recommendations(self, vuln_type: VulnerabilityCategory, probability: float) -> List[str]:
        """Generate testing recommendations based on vulnerability prediction"""
        recommendations = {
            VulnerabilityCategory.SQL_INJECTION: [
                "Test with SQLi payloads in parameters",
                "Try boolean-based blind SQLi",
                "Test for time-based blind SQLi",
                "Check for error-based SQLi",
            ],
            VulnerabilityCategory.XSS: [
                "Test with XSS payloads in query parameters",
                "Check for reflected XSS",
                "Test for stored XSS if applicable",
                "Verify CSP headers",
            ],
            VulnerabilityCategory.LFI: [
                "Test with path traversal sequences",
                "Try null byte injection",
                "Check for wrapper abuse (php://filter)",
                "Test encoding bypass techniques",
            ],
            VulnerabilityCategory.RCE: [
                "Test command injection payloads",
                "Check for unsafe deserialization",
                "Verify input validation",
                "Test with OS command chaining",
            ],
            VulnerabilityCategory.IDOR: [
                "Test with different user IDs",
                "Check authorization on each request",
                "Test with enumerated IDs",
                "Verify horizontal and vertical access control",
            ],
            VulnerabilityCategory.SSRF: [
                "Test with internal IP addresses",
                "Try URL encoding bypass",
                "Check for DNS rebinding",
                "Test with different protocols",
            ],
        }
        
        base_recommendations = recommendations.get(vuln_type, ["Manual testing required"])
        
        if probability >= 0.7:
            return ["HIGH PRIORITY: " + r for r in base_recommendations[:3]]
        elif probability >= 0.4:
            return base_recommendations[:3]
        else:
            return base_recommendations[:2]
    
    def classify_batch(
        self,
        urls: List[str],
        response_data_map: Dict[str, Dict] = None,
    ) -> List[ClassificationResult]:
        """Classify multiple endpoints at once"""
        results = []
        response_data_map = response_data_map or {}
        
        for url in urls:
            response_data = response_data_map.get(url)
            result = self.classify_endpoint(url, response_data)
            results.append(result)
        
        return results
    
    def get_endpoint_stats(self) -> Dict:
        """Get statistics about endpoint classifications"""
        type_counts = defaultdict(int)
        confidence_avg = {}
        
        for result in self.classification_history:
            type_counts[result.predicted_type.value] += 1
        
        for endpoint_type, scores in self.confidence_scores.items():
            if scores:
                confidence_avg[endpoint_type] = sum(scores) / len(scores)
        
        return {
            'total_classifications': len(self.classification_history),
            'type_distribution': dict(type_counts),
            'average_confidence': confidence_avg,
            'stats': self.stats,
        }
    
    def get_vulnerability_stats(self) -> Dict:
        """Get statistics about vulnerability predictions"""
        vuln_counts = defaultdict(int)
        confidence_distribution = defaultdict(int)
        
        for prediction in self.vulnerability_history:
            vuln_counts[prediction.vulnerability_type.value] += 1
            confidence_distribution[prediction.confidence] += 1
        
        return {
            'total_predictions': len(self.vulnerability_history),
            'vulnerability_distribution': dict(vuln_counts),
            'confidence_distribution': dict(confidence_distribution),
            'stats': self.stats,
        }
    
    def export_results(self, output_path: str):
        """Export classification and prediction results to JSON"""
        data = {
            'classifications': [
                {
                    'endpoint': r.endpoint,
                    'predicted_type': r.predicted_type.value,
                    'confidence': r.confidence,
                    'probabilities': r.probabilities,
                    'reasoning': r.reasoning,
                }
                for r in self.classification_history
            ],
            'vulnerability_predictions': [
                {
                    'endpoint': p.endpoint,
                    'vulnerability_type': p.vulnerability_type.value,
                    'probability': p.probability,
                    'confidence': p.confidence,
                    'indicators': p.indicators,
                    'recommendations': p.recommendations,
                }
                for p in self.vulnerability_history
            ],
            'stats': {
                'classification_stats': self.get_endpoint_stats(),
                'vulnerability_stats': self.get_vulnerability_stats(),
            },
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported ML classification results to {output_path}")


# Convenience function
def classify_endpoints(urls: List[str], response_data: Dict = None) -> List[ClassificationResult]:
    """
    Convenience function to classify multiple endpoints.
    
    Args:
        urls: List of URLs to classify
        response_data: Optional dict mapping URLs to response data
        
    Returns:
        List of ClassificationResult objects
    """
    classifier = MLClassifier()
    return classifier.classify_batch(urls, response_data)


def predict_vulnerabilities(urls: List[str], response_data: Dict = None) -> List[VulnerabilityPrediction]:
    """
    Convenience function to predict vulnerabilities for multiple endpoints.
    
    Args:
        urls: List of URLs to analyze
        response_data: Optional dict mapping URLs to response data
        
    Returns:
        List of VulnerabilityPrediction objects
    """
    classifier = MLClassifier()
    all_predictions = []
    response_data_map = response_data or {}
    
    for url in urls:
        predictions = classifier.predict_vulnerabilities(url, response_data_map.get(url))
        all_predictions.extend(predictions)
    
    return all_predictions