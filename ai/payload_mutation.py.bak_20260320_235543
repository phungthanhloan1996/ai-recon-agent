"""
ai/payload_mutation.py - Payload Mutation Engine
Transforms and mutates payloads to increase detection coverage
"""

import re
import logging
import base64
import urllib.parse
from typing import List

logger = logging.getLogger("recon.payload_mutation")


class PayloadMutator:
    """
    Mutates payloads through various transformations:
    - Encoding variations
    - Syntax mutations
    - Delimiter changes
    - Obfuscation techniques
    """

    def __init__(self):
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
        """Base64 encode the payload"""
        return base64.b64encode(payload.encode()).decode()

    def _url_encode(self, payload: str) -> str:
        """URL encode the payload"""
        return urllib.parse.quote(payload)

    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode the payload"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    def _html_encode(self, payload: str) -> str:
        """HTML encode special characters"""
        return (payload.replace('&', '&amp;')
                      .replace('<', '&lt;')
                      .replace('>', '&gt;')
                      .replace('"', '&quot;')
                      .replace("'", '&#x27;'))

    def _unicode_escape(self, payload: str) -> str:
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    def _hex_encode(self, payload: str) -> str:
        """Hex encode the payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    # Mutation methods
    def _case_variation(self, payload: str) -> List[str]:
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
        """Apply case mixing for WAF bypass"""
        variations = []
        # Convert to mixed case
        mixed = ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        variations.append(mixed)
        return variations

    def _waf_add_spaces(self, payload: str) -> List[str]:
        """Add spaces between characters for WAF bypass"""
        variations = []
        spaced = ' '.join(payload)
        variations.append(spaced)
        return variations

    def _waf_replace_keywords(self, payload: str) -> List[str]:
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
        """Random case variation for WAF bypass"""
        import random
        variations = []
        random_cased = ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
        variations.append(random_cased)
        return variations



    def _keyword_split(self, payload: str) -> List[str]:
        variations = []
        keywords = ['UNION', 'SELECT', 'SCRIPT', 'ALERT', 'EVAL']

        for keyword in keywords:
            pattern = re.compile(keyword, re.IGNORECASE)
            if pattern.search(payload):
                split = keyword[:2] + '/**/' + keyword[2:]
                variations.append(pattern.sub(split, payload))

        return variations

    def _comment_injection(self, payload: str) -> List[str]:
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