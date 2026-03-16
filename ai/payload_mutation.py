"""
ai/payload_mutation.py - Payload Mutation Engine
Transforms and mutates payloads to increase detection coverage
"""

import re
import logging
import base64
import urllib.parse
from typing import List
import random

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

    def mutate_payloads(self, payloads: List[str]) -> List[str]:
        """Generate mutated versions of input payloads"""
        mutated = []

        for payload in payloads:
            # Apply various mutations
            mutated.extend(self._apply_encodings(payload))
            mutated.extend(self._apply_mutations(payload))
            mutated.extend(self._combine_transformations(payload))

        # Remove duplicates and original payloads
        mutated = list(set(mutated))
        mutated = [p for p in mutated if p not in payloads]

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

    def _html_encode(self, payload: str) -> str:
        """HTML encode special characters"""
        return (payload.replace('&', '&amp;')
                      .replace('<', '&lt;')
                      .replace('>', '&gt;')
                      .replace('"', '&quot;')
                      .replace("'", '&#x27;'))

    def _unicode_escape(self, payload: str) -> str:
        """Unicode escape the payload"""
        return payload.encode().decode('unicode_escape')

    def _hex_encode(self, payload: str) -> str:
        """Hex encode the payload"""
        return ''.join(f'\\x{ord(c):02x}' for c in payload)

    # Mutation methods
    def _case_variation(self, payload: str) -> List[str]:
        """Generate case variations"""
        variations = []
        variations.append(payload.upper())
        variations.append(payload.lower())

        # Random case mixing for keywords
        keywords = ['union', 'select', 'script', 'alert', 'eval', 'exec', 'system']
        for keyword in keywords:
            if keyword in payload.lower():
                # Mix case for this keyword
                mixed = payload
                for match in re.finditer(keyword, mixed, re.IGNORECASE):
                    replacement = ''.join(
                        c.upper() if random.choice([True, False]) else c.lower()
                        for c in match.group()
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

        # Add random whitespace
        noisy = re.sub(r'\s+', lambda m: m.group() + ' ' * random.randint(1, 3), payload)
        variations.append(noisy)

        # Add random comments
        if random.choice([True, False]):
            variations.extend(self._add_comments(payload))

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