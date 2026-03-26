"""
core/cve_matcher.py - Version/range matching helpers for CVE applicability.
"""

import re
from typing import Iterable, Optional, Tuple


def normalize_version(v: str) -> Optional[Tuple[int, ...]]:
    if not v:
        return None
    v = str(v).strip().lower()
    if v in {"unknown", "n/a", "na", "none", "-"}:
        return None
    parts = re.findall(r"\d+", v)
    if not parts:
        return None
    return tuple(int(p) for p in parts[:4])


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    ln = max(len(a), len(b))
    aa = a + (0,) * (ln - len(a))
    bb = b + (0,) * (ln - len(b))
    if aa < bb:
        return -1
    if aa > bb:
        return 1
    return 0


def match_single_range(version: str, rule: str) -> Optional[bool]:
    v = normalize_version(version)
    if v is None:
        return None
    rule = (rule or "").strip()
    if not rule:
        return None

    # range syntax: "1.2.0-1.4.7"
    if "-" in rule and not rule.startswith("-"):
        lo, hi = [x.strip() for x in rule.split("-", 1)]
        vlo = normalize_version(lo)
        vhi = normalize_version(hi)
        if vlo is None or vhi is None:
            return None
        return _cmp(v, vlo) >= 0 and _cmp(v, vhi) <= 0

    for op in ("<=", ">=", "<", ">", "==", "="):
        if rule.startswith(op):
            rv = normalize_version(rule[len(op):].strip())
            if rv is None:
                return None
            c = _cmp(v, rv)
            if op == "<=":
                return c <= 0
            if op == ">=":
                return c >= 0
            if op == "<":
                return c < 0
            if op == ">":
                return c > 0
            return c == 0

    # bare version means exact match
    rv = normalize_version(rule)
    if rv is None:
        return None
    return _cmp(v, rv) == 0


def match_any_range(version: str, rules: Iterable[str]) -> Optional[bool]:
    known = False
    for r in rules or []:
        m = match_single_range(version, str(r))
        if m is None:
            continue
        known = True
        if m:
            return True
    return False if known else None


# Technology-to-vulnerability hint mapping
TECH_VULN_HINTS = {
    'wordpress': {
        'hint_classes': ['file_upload', 'plugin_vuln', 'rce_via_plugin', 'privilege_escalation', 'auth_bypass'],
        'patterns': {
            '<5.0': ['path_traversal', 'xss'],
            '<4.8': ['sqli', 'privilege_escalation'],
            '<4.0': ['file_inclusion', 'remote_code_execution']
        }
    },
    'php': {
        'hint_classes': ['file_inclusion', 'file_upload_rce', 'insecure_deserialization', 'code_injection'],
        'patterns': {
            '<5.3': ['file_inclusion', 'register_globals'],
            '<5.6': ['insecure_hash'],
            '<7.0': ['type_juggling']
        }
    },
    'apache': {
        'hint_classes': ['path_traversal', 'directory_listing', 'htaccess_bypass', 'misc_config_bypass'],
        'patterns': {
            '<2.4.49': ['path_traversal', 'rce'],
            '<2.4.30': ['privilege_escalation']
        }
    },
    'nginx': {
        'hint_classes': ['path_normalization_bypass', 'directory_traversal'],
        'patterns': {
            '<1.16': ['off_by_one_read'],
            '<1.19': ['http_splitting']
        }
    },
    'mysql': {
        'hint_classes': ['sqli', 'privilege_escalation'],
        'patterns': {
            '<5.7': ['weak_auth', 'file_access'],
            '<5.5': ['multiple_vulns']
        }
    },
    'nodejs': {
        'hint_classes': ['prototype_pollution', 'code_injection', 'rce'],
        'patterns': {}
    },
    'java': {
        'hint_classes': ['deserialization_rce', 'type_confusion'],
        'patterns': {}
    },
    'express': {
        'hint_classes': ['prototype_pollution', 'injection'],
        'patterns': {}
    },
    'django': {
        'hint_classes': ['template_injection', 'sql_injection'],
        'patterns': {}
    },
    'flask': {
        'hint_classes': ['template_injection', 'debug_mode'],
        'patterns': {}
    },
}


def get_vulnerability_hints_for_tech(technology: str, version: Optional[str] = None) -> list:
    """
    Get vulnerability hint classes for a given technology and version.
    
    Args:
        technology: Technology name (e.g., 'wordpress', 'php', 'apache')
        version: Optional version string to check against patterns
    
    Returns:
        List of vulnerability hint classes
    """
    tech_lower = (technology or '').lower().strip()
    
    if not tech_lower:
        return []
    
    hints = []
    
    # Check for exact match
    if tech_lower in TECH_VULN_HINTS:
        tech_info = TECH_VULN_HINTS[tech_lower]
        hints.extend(tech_info.get('hint_classes', []))
        
        # Check version-specific patterns
        if version:
            patterns = tech_info.get('patterns', {})
            for version_range, version_hints in patterns.items():
                if match_single_range(version, version_range):
                    hints.extend(version_hints)
    
    # Fallback: partial matches for tech stacks
    tech_lower_parts = tech_lower.split()
    for tech_key in TECH_VULN_HINTS:
        if any(part in tech_key or tech_key in part for part in tech_lower_parts):
            if tech_key not in hints:
                tech_info = TECH_VULN_HINTS[tech_key]
                hints.extend(tech_info.get('hint_classes', []))
    
    # Remove duplicates while preserving order
    seen = set()
    unique_hints = []
    for hint in hints:
        if hint not in seen:
            seen.add(hint)
            unique_hints.append(hint)
    
    return unique_hints


def get_hints_for_endpoint(endpoint_data: dict) -> list:
    """
    Get comprehensive vulnerability hints for an endpoint based on:
    - Endpoint type
    - Parameters
    - Technologies
    - URL patterns
    
    Args:
        endpoint_data: Dictionary with endpoint information
    
    Returns:
        List of vulnerability hint classes
    """
    hints = []
    
    # Existing hints from endpoint analysis
    hints.extend(endpoint_data.get('vulnerability_hints', []))
    
    # Tech-based hints
    technologies = endpoint_data.get('technologies', [])
    for tech in technologies:
        hints.extend(get_vulnerability_hints_for_tech(tech))
    
    # Parameter-based hints (enhanced)
    parameters = endpoint_data.get('parameters', [])
    for param in parameters:
        param_name = (param.get('name', '') or '').lower()
        param_type = (param.get('type', '') or '').lower()
        
        # Check parameter names for specific vulnerabilities
        if param_name in ('cmd', 'exec', 'command', 'shell', 'system'):
            hints.append('command_injection')
        elif param_name in ('url', 'uri', 'redirect', 'callback', 'forward', 'fetch'):
            hints.append('ssrf')
        elif param_name in ('file', 'path', 'dir', 'include', 'require', 'template', 'page'):
            hints.append('lfi')
        elif param_name in ('email', 'username', 'user', 'login'):
            hints.append('user_enumeration')
        
        # Check parameter types
        if param_type == 'file':
            hints.append('file_upload')
    
    # Remove duplicates
    return list(set(hints))
