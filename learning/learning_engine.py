"""
learning/learning_engine.py - Learning Engine
Learns from successful/failed payloads and adapts scanning strategy
"""

import json
import os
import logging
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger("recon.learning_engine")


class LearningEngine:
    """
    Machine learning component that:
    - Stores successful and failed payloads
    - Analyzes patterns in failures
    - Suggests payload mutations
    - Adapts scanning strategy based on results
    """

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.successful_payloads_file = os.path.join(output_dir, "learning", "successful_payloads.json")
        self.failed_payloads_file = os.path.join(output_dir, "learning", "failed_payloads.json")

        # Create learning directory
        os.makedirs(os.path.dirname(self.successful_payloads_file), exist_ok=True)

        # Load existing data
        self.successful_payloads = self._load_payloads(self.successful_payloads_file)
        self.failed_payloads = self._load_payloads(self.failed_payloads_file)

    def _load_payloads(self, filepath: str) -> List[Dict[str, Any]]:
        """Load payloads from JSON file"""
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load {filepath}: {e}")
        return []

    def _save_payloads(self, payloads: List[Dict[str, Any]], filepath: str):
        """Save payloads to JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(payloads, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save {filepath}: {e}")

    def learn_from_iteration(self, state):
        """Learn from the current iteration's results"""
        # Extract successful exploits
        exploit_results = state.get("exploit_results", [])
        for result in exploit_results:
            if result.get("success"):
                payload_data = {
                    "payload": result.get("payload", ""),
                    "endpoint": result.get("endpoint", ""),
                    "vuln_type": result.get("vuln_type", ""),
                    "timestamp": datetime.now().isoformat(),
                    "chain": result.get("chain", "")
                }
                self.successful_payloads.append(payload_data)

        # Extract failed scan responses
        scan_responses = state.get("scan_responses", [])
        for response in scan_responses:
            if not response.get("vulnerable", False):
                payload_data = {
                    "payload": response.get("payload", ""),
                    "endpoint": response.get("endpoint", ""),
                    "response_code": response.get("status_code", 0),
                    "response_size": response.get("content_length", 0),
                    "timestamp": datetime.now().isoformat(),
                    "reason": response.get("reason", "no_vuln_detected")
                }
                self.failed_payloads.append(payload_data)

        # Save updated data
        self._save_payloads(self.successful_payloads, self.successful_payloads_file)
        self._save_payloads(self.failed_payloads, self.failed_payloads_file)

        logger.info(f"[LEARNING] Recorded {len(exploit_results)} exploit results, {len(scan_responses)} scan responses")

    def get_failed_payloads(self) -> List[str]:
        """Get list of failed payloads for mutation"""
        return [p.get("payload", "") for p in self.failed_payloads[-50:]]  # Last 50 failures

    def get_successful_payloads(self) -> List[str]:
        """Get list of successful payloads"""
        return [p.get("payload", "") for p in self.successful_payloads]

    def analyze_failure_patterns(self) -> Dict[str, Any]:
        """Analyze patterns in failed payloads to understand WAF/filtering"""
        patterns = {
            "common_rejections": {},
            "payload_length_issues": 0,
            "encoding_issues": 0,
            "keyword_filtering": {},
            "response_codes": {}
        }

        for failure in self.failed_payloads[-100:]:  # Analyze last 100 failures
            payload = failure.get("payload", "")
            response_code = failure.get("response_code", 0)

            # Count response codes
            patterns["response_codes"][str(response_code)] = patterns["response_codes"].get(str(response_code), 0) + 1

            # Check for common rejection patterns
            if response_code in [403, 406, 419]:
                patterns["common_rejections"][str(response_code)] = patterns["common_rejections"].get(str(response_code), 0) + 1

            # Check payload length issues
            if len(payload) > 1000:  # Arbitrary threshold
                patterns["payload_length_issues"] += 1

            # Check for encoding issues
            if any(enc in payload for enc in ['%3C', '%3E', 'base64', 'javascript:']):
                patterns["encoding_issues"] += 1

            # Check for keyword filtering
            dangerous_keywords = ['union', 'select', 'script', 'alert', 'eval', 'exec', 'system', 'cmd']
            for keyword in dangerous_keywords:
                if keyword in payload.lower():
                    patterns["keyword_filtering"][keyword] = patterns["keyword_filtering"].get(keyword, 0) + 1

        return patterns

    def suggest_mutations(self) -> List[str]:
        """Suggest mutation strategies based on learning"""
        suggestions = []
        patterns = self.analyze_failure_patterns()

        # If many 403 responses, suggest encoding
        if patterns["response_codes"].get("403", 0) > 10:
            suggestions.append("Use URL encoding to bypass WAF")

        # If keyword filtering detected
        if patterns["keyword_filtering"]:
            top_filtered = max(patterns["keyword_filtering"], key=patterns["keyword_filtering"].get)
            suggestions.append(f"Obfuscate '{top_filtered}' keyword")

        # If encoding issues
        if patterns["encoding_issues"] > 5:
            suggestions.append("Try double encoding")

        # If length issues
        if patterns["payload_length_issues"] > 5:
            suggestions.append("Split long payloads")

        return suggestions

    def get_adaptive_payloads(self, base_payloads: List[str], vuln_type: str) -> List[str]:
        """Generate adaptive payloads based on learning"""
        adaptive = []

        # Get successful patterns for this vuln type
        successful_for_type = [
            p for p in self.successful_payloads
            if p.get("vuln_type") == vuln_type
        ]

        if successful_for_type:
            # Extract successful patterns
            successful_patterns = [p.get("payload", "") for p in successful_for_type]

            # Apply similar patterns to base payloads
            for base in base_payloads:
                for pattern in successful_patterns[:3]:  # Use top 3 successful patterns
                    # Simple pattern adaptation (this could be more sophisticated)
                    if vuln_type == "sqli" and "union" in pattern.lower():
                        adaptive.append(f"{base} UNION SELECT 1,2,3--")
                    elif vuln_type == "xss" and "<script>" in pattern:
                        adaptive.append(f"<script>{base}</script>")
                    elif vuln_type == "rce" and ";" in pattern:
                        adaptive.append(f";{base};")

        return list(set(adaptive))  # Remove duplicates

    def export_learning_data(self) -> Dict[str, Any]:
        """Export all learning data for analysis"""
        return {
            "successful_payloads": self.successful_payloads,
            "failed_payloads": self.failed_payloads,
            "failure_patterns": self.analyze_failure_patterns(),
            "mutation_suggestions": self.suggest_mutations(),
            "stats": {
                "total_successful": len(self.successful_payloads),
                "total_failed": len(self.failed_payloads),
                "success_rate": len(self.successful_payloads) / max(1, len(self.successful_payloads) + len(self.failed_payloads))
            }
        }