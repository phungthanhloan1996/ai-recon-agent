"""
core/behavioral_analyzer.py - Behavioral Parameter Analysis Engine
Analyzes endpoint parameters and recommends targeted payload types.
Implements CONSTRAINT 1: Match payload type to parameter logic.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple
from enum import Enum

logger = logging.getLogger("recon.behavioral_analyzer")


class ParameterType(Enum):
    """Parameter classification."""
    ID = "id"  # Database ID - SQLi/XSS
    SEARCH = "search"  # Search term - SQLi/XSS
    QUERY = "q"  # Query parameter - SQLi/XSS
    REDIRECT = "redirect"  # URL redirect - Open Redirect/SSRF
    URL = "url"  # URL parameter - Open Redirect/SSRF
    FILE = "file"  # File path - LFI/RFI
    PATH = "path"  # Path parameter - LFI/RFI
    UPLOAD = "upload"  # File upload - File Upload Bypass/RCE
    COMMAND = "cmd"  # Command parameter - RCE/Command Injection
    ADMIN = "admin"  # Admin functions - Authentication/IDOR
    EMAIL = "email"  # Email - Email Injection/SQLi
    NAME = "name"  # Name field - XSS/SQLi
    UNKNOWN = "unknown"  # Unknown - Start with low-risk payloads


class VulnerabilityType(Enum):
    """Vulnerability classification."""
    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    FILE_UPLOAD = "file_upload"
    IDOR = "idor"
    AUTHENTICATION = "authentication"


class BehavioralAnalyzer:
    """
    Analyzes endpoint parameters and recommends targeted vulnerability types.
    KEY STRATEGY: Do NOT spray all payloads on all endpoints.
    Match payload type to parameter logic.
    """

    # Parameter name patterns
    PARAM_PATTERNS = {
        ParameterType.ID: [
            r'^id$', r'^pid$', r'^uid$', r'^user_id$', r'^article_id$', 
            r'^post_id$', r'^product_id$', r'^page_id$', r'^item_id$'
        ],
        ParameterType.SEARCH: [
            r'^search$', r'^s$', r'^q$', r'^query$', r'^keyword$',
            r'^find$', r'^searchterm$', r'^searchquery$'
        ],
        ParameterType.QUERY: [
            r'^q$', r'^query$', r'^search$', r'^term$'
        ],
        ParameterType.REDIRECT: [
            r'^redirect$', r'^redirect_uri$', r'^return$', r'^returnurl$',
            r'^return_url$', r'^goto$', r'^next$', r'^url$'
        ],
        ParameterType.URL: [
            r'^url$', r'^link$', r'^target$', r'^webpage$', r'^page$'
        ],
        ParameterType.FILE: [
            r'^file$', r'^attachment$', r'^document$', r'^pdf$',
            r'^download$', r'^doc$', r'^filename$'
        ],
        ParameterType.PATH: [
            r'^path$', r'^filepath$', r'^dir$', r'^directory$',
            r'^folder$', r'^location$'
        ],
        ParameterType.UPLOAD: [
            r'^upload$', r'^file_upload$', r'^media$', r'^image$',
            r'^avatar$', r'^profile_pic$', r'^document$'
        ],
        ParameterType.COMMAND: [
            r'^cmd$', r'^command$', r'^exec$', r'^execute$',
            r'^code$', r'^shell$'
        ],
        ParameterType.EMAIL: [
            r'^email$', r'^mail$', r'^recipient$', r'^to$',
            r'^from$', r'^sender$'
        ],
        ParameterType.NAME: [
            r'^name$', r'^username$', r'^user$', r'^author$',
            r'^title$', r'^subject$'
        ],
    }

    # Value-based patterns (detect from actual parameter values)
    VALUE_PATTERNS = {
        ParameterType.ID: [
            r'^\d+$',  # Numeric ID
            r'^[a-f0-9]{8,}$'  # UUID-like
        ],
        ParameterType.EMAIL: [
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        ],
        ParameterType.URL: [
            r'^https?://',  # URL starts with scheme
            r'^www\.',  # Domain
        ]
    }

    def __init__(self):
        self.param_history = {}  # Track params we've analyzed
        self.effectiveness_scores = {}  # Track what works

    def classify_parameter(self, param_name: str, param_value: Optional[str] = None) -> ParameterType:
        """
        Classify a parameter into vulnerability types.
        Strategy: Name-based first (most reliable), then value-based.
        
        Returns: ParameterType enum
        """
        # Normalize parameter name
        normalized = param_name.lower().strip()
        
        # Check name-based patterns (highest priority)
        for param_type, patterns in self.PARAM_PATTERNS.items():
            for pattern in patterns:
                if re.match(pattern, normalized, re.IGNORECASE):
                    logger.debug(f"[BEHAVIOR] Parameter '{param_name}' classified as {param_type.value} (name match)")
                    return param_type
        
        # Check value-based patterns (secondary)
        if param_value:
            value_str = str(param_value).lower()
            for param_type, patterns in self.VALUE_PATTERNS.items():
                for pattern in patterns:
                    if re.match(pattern, value_str, re.IGNORECASE):
                        logger.debug(f"[BEHAVIOR] Parameter '{param_name}' classified as {param_type.value} (value match)")
                        return param_type
        
        logger.debug(f"[BEHAVIOR] Parameter '{param_name}' classified as UNKNOWN (no matches)")
        return ParameterType.UNKNOWN

    def recommend_vulnerabilities(self, param_type: ParameterType) -> List[Tuple[VulnerabilityType, float]]:
        """
        Recommend vulnerability types to test for a given parameter.
        Returns: List of (VulnerabilityType, priority_score) tuples, sorted by priority.
        
        Priority scores: 1.0 = highest priority, 0.5 = medium, 0.2 = low
        """
        recommendations = []

        if param_type == ParameterType.ID:
            # Database IDs are prime targets for SQLi and IDOR
            recommendations = [
                (VulnerabilityType.SQLI, 1.0),
                (VulnerabilityType.IDOR, 0.9),
                (VulnerabilityType.XSS, 0.3),  # Could be reflected
            ]
        elif param_type == ParameterType.SEARCH:
            # Search parameters: SQLi and XSS
            recommendations = [
                (VulnerabilityType.SQLI, 1.0),
                (VulnerabilityType.XSS, 1.0),
            ]
        elif param_type == ParameterType.QUERY:
            # Query parameters: SQLi and XSS
            recommendations = [
                (VulnerabilityType.SQLI, 0.9),
                (VulnerabilityType.XSS, 0.9),
            ]
        elif param_type == ParameterType.REDIRECT:
            # Redirect parameters: Open Redirect and SSRF
            recommendations = [
                (VulnerabilityType.OPEN_REDIRECT, 1.0),
                (VulnerabilityType.SSRF, 0.8),
            ]
        elif param_type == ParameterType.URL:
            # URL parameters: Open Redirect, SSRF
            recommendations = [
                (VulnerabilityType.OPEN_REDIRECT, 1.0),
                (VulnerabilityType.SSRF, 0.9),
            ]
        elif param_type == ParameterType.FILE:
            # File parameters: LFI and RFI
            recommendations = [
                (VulnerabilityType.LFI, 1.0),
                (VulnerabilityType.RFI, 0.8),
            ]
        elif param_type == ParameterType.PATH:
            # Path parameters: LFI
            recommendations = [
                (VulnerabilityType.LFI, 1.0),
            ]
        elif param_type == ParameterType.UPLOAD:
            # Upload parameters: File Upload Bypass, RCE
            recommendations = [
                (VulnerabilityType.FILE_UPLOAD, 1.0),
                (VulnerabilityType.RCE, 0.8),
            ]
        elif param_type == ParameterType.COMMAND:
            # Command parameters: RCE
            recommendations = [
                (VulnerabilityType.RCE, 1.0),
            ]
        elif param_type == ParameterType.EMAIL:
            # Email parameters: Email Injection, SSRF
            recommendations = [
                (VulnerabilityType.SQLI, 0.7),
                (VulnerabilityType.XSS, 0.6),
                (VulnerabilityType.SSRF, 0.4),  # LDAP injection, etc.
            ]
        elif param_type == ParameterType.NAME:
            # Name fields: XSS, SQLi
            recommendations = [
                (VulnerabilityType.XSS, 0.9),
                (VulnerabilityType.SQLI, 0.7),
            ]
        else:  # UNKNOWN
            # Conservative approach for unknown parameters
            recommendations = [
                (VulnerabilityType.XSS, 0.5),  # XSS is often least risky
                (VulnerabilityType.SQLI, 0.5),
            ]

        return sorted(recommendations, key=lambda x: x[1], reverse=True)

    def get_priority_payloads(
        self,
        param_type: ParameterType,
        max_payloads: int = 5
    ) -> Dict[VulnerabilityType, int]:
        """
        Get recommended payload counts per vulnerability type.
        
        Returns: Dict mapping VulnerabilityType -> max_payload_count
        
        CONSTRAINT: Resource conservation - limit total payloads based on priority.
        """
        recommendations = self.recommend_vulnerabilities(param_type)
        payload_budget = {}

        for vuln_type, priority in recommendations:
            if priority >= 0.9:
                # High priority: test more payloads
                payload_budget[vuln_type] = min(10, max_payloads)
            elif priority >= 0.6:
                # Medium priority: moderate payloads
                payload_budget[vuln_type] = min(5, max_payloads // 2)
            elif priority >= 0.3:
                # Low priority: minimal payloads
                payload_budget[vuln_type] = min(2, max_payloads // 4)
            # Below 0.3: skip entirely (too low priority)

        return payload_budget

    def should_test_parameter(
        self,
        param_name: str,
        endpoint_url: str,
        tested_count: int = 0,
        max_params_per_endpoint: int = 3
    ) -> bool:
        """
        Decide whether to test a parameter on an endpoint.
        
        CONSTRAINT: Resource conservation
        - Limit parameters per endpoint to avoid test explosion
        - Skip obviously safe parameters (static, etc.)
        
        Returns: True if should test, False otherwise
        """
        # Skip obvious static files
        static_extensions = {'.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.woff', '.svg', '.ico'}
        if any(endpoint_url.lower().endswith(ext) for ext in static_extensions):
            logger.debug(f"[BEHAVIOR] Skipping parameter '{param_name}' on static endpoint: {endpoint_url}")
            return False

        # Check if we've already tested too many parameters on this endpoint
        if tested_count >= max_params_per_endpoint:
            logger.debug(f"[BEHAVIOR] Skipping parameter '{param_name}' - already tested {tested_count} params on {endpoint_url}")
            return False

        # Classify parameter
        param_type = self.classify_parameter(param_name)
        
        # Skip truly unknown parameters if we're resource-constrained
        if param_type == ParameterType.UNKNOWN:
            logger.debug(f"[BEHAVIOR] Skipping UNKNOWN parameter '{param_name}' (resource conservation)")
            return False

        return True

    def analyze_endpoint(self, url: str, parameters: Dict[str, str]) -> Dict:
        """
        Comprehensive endpoint analysis.
        
        Returns: {
            'url': str,
            'parameter_analysis': [
                {
                    'name': str,
                    'type': ParameterType,
                    'recommended_vulns': [(VulnerabilityType, priority), ...],
                    'payload_budget': {VulnerabilityType: count, ...},
                    'test_priority': int (1=highest)
                },
                ...
            ],
            'total_recommended_payloads': int,
            'estimated_test_time': str,
        }
        """
        analysis = {
            'url': url,
            'parameter_analysis': [],
            'total_recommended_payloads': 0,
            'estimated_test_time': 'unknown'
        }

        # Sort parameters by test probability (high-value first)
        sorted_params = sorted(
            parameters.items(),
            key=lambda x: self.classify_parameter(x[0]).value
        )

        for idx, (param_name, param_value) in enumerate(sorted_params):
            if idx >= 3:  # CONSTRAINT: Max 3 params per endpoint
                break

            param_type = self.classify_parameter(param_name, param_value)
            recommendations = self.recommend_vulnerabilities(param_type)
            payload_budget = self.get_priority_payloads(param_type)

            param_analysis = {
                'name': param_name,
                'value_sample': str(param_value)[:50],
                'type': param_type.value,
                'recommended_vulns': [(v.value, p) for v, p in recommendations],
                'payload_budget': {v.value: c for v, c in payload_budget.items()},
                'test_priority': idx + 1,
            }

            analysis['parameter_analysis'].append(param_analysis)
            analysis['total_recommended_payloads'] += sum(payload_budget.values())

        # Estimate test time (rough: ~1-2 seconds per payload)
        estimated_seconds = analysis['total_recommended_payloads'] * 1.5
        analysis['estimated_test_time'] = f"{estimated_seconds:.0f}s ({estimated_seconds/60:.1f}m)"

        logger.info(f"[BEHAVIOR] Endpoint {url} analysis: {len(analysis['parameter_analysis'])} params, "
                   f"{analysis['total_recommended_payloads']} total payloads, {analysis['estimated_test_time']}")

        return analysis

    def record_effectiveness(self, param_name: str, vuln_type: str, success: bool):
        """Record effectiveness of vulnerability type for parameter."""
        key = f"{param_name}:{vuln_type}"
        if key not in self.effectiveness_scores:
            self.effectiveness_scores[key] = {'success': 0, 'total': 0}
        self.effectiveness_scores[key]['total'] += 1
        if success:
            self.effectiveness_scores[key]['success'] += 1

    def get_adjusted_priority(self, param_name: str, vuln_type: str, base_priority: float) -> float:
        """
        Adjust priority based on historical effectiveness.
        
        Returns: Adjusted priority score (0.0-1.0)
        """
        key = f"{param_name}:{vuln_type}"
        if key not in self.effectiveness_scores or self.effectiveness_scores[key]['total'] == 0:
            return base_priority

        eff = self.effectiveness_scores[key]
        success_rate = eff['success'] / eff['total']
        
        # Boost successful combinations, reduce unsuccessful ones
        adjusted = base_priority * (0.5 + success_rate)
        return min(1.0, adjusted)
