import urllib.parse
"""
modules/false_positive_filter.py - False Positive Filter

Analyzes scan results to identify and filter out false positives using:
- Statistical analysis of response patterns
- Cross-validation with multiple indicators
- Historical false positive patterns
- Context-aware scoring

This module improves the signal-to-noise ratio before exploitation,
reducing wasted effort on non-exploitable findings.
"""

import json
import os
import logging
import re
import time
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
from urllib.parse import urlparse

from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.false_positive_filter")


class FalsePositiveFilter:
    """
    Filters false positives from vulnerability scan results.
    Uses statistical analysis and pattern matching to improve accuracy.
    """
    
    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.http_client = HTTPClient()
        self.findings_file = os.path.join(output_dir, "false_positive_analysis.json")
        
        # Known false positive patterns
        self.fp_patterns = {
            "waf_responses": [
                r"cloudflare",
                r"akamai",
                r"incapsula",
                r"sucuri",
                r"wordfence",
                r"blocked",
                r"access denied",
                r"forbidden",
                r"not acceptable",
            ],
            "generic_errors": [
                r"404 not found",
                r"403 forbidden",
                r"400 bad request",
                r"500 internal server error",
                r"502 bad gateway",
                r"503 service unavailable",
            ],
            "false_sqli_indicators": [
                r"invalid syntax",  # Could be application error, not SQL
                r"unexpected token",
                r"parse error",
            ],
            "false_xss_indicators": [
                r"<script>",  # Escaped - not actual XSS
                r"<img",
                r"html encoded",
            ],
        }
        
        # Historical false positive patterns (learned over time)
        self.historical_fp = self._load_historical_fp()
    
    def filter_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], progress_cb=None) -> Dict[str, Any]:
        """
        Filter a list of vulnerabilities for false positives.
        
        Args:
            vulnerabilities: List of vulnerability dicts
            progress_cb: Optional progress callback
            
        Returns:
            Filtered results with confidence adjustments
        """
        results = {
            "status": "completed",
            "original_count": len(vulnerabilities),
            "filtered": [],
            "confirmed": [],
            "suspicious": [],
            "removed": [],
            "summary": {
                "original": len(vulnerabilities),
                "confirmed": 0,
                "suspicious": 0,
                "removed": 0,
                "fp_rate": 0.0
            }
        }
        
        if not vulnerabilities:
            logger.info("[FP_FILTER] No vulnerabilities to filter")
            return results
        
        logger.info(f"[FP_FILTER] Filtering {len(vulnerabilities)} vulnerabilities")
        
        for idx, vuln in enumerate(vulnerabilities):
            try:
                if progress_cb:
                    progress_cb(f"Filtering {vuln.get('type', 'unknown')} on {vuln.get('endpoint', '')[:30]}...")
                
                analysis = self.analyze_vulnerability(vuln)
                
                if analysis["is_false_positive"]:
                    results["removed"].append({
                        "vulnerability": vuln,
                        "reason": analysis["reason"],
                        "confidence": analysis["fp_confidence"]
                    })
                    results["summary"]["removed"] += 1
                elif analysis["confidence"] >= 0.8:
                    results["confirmed"].append({
                        "vulnerability": vuln,
                        "adjusted_confidence": analysis["confidence"],
                        "analysis": analysis
                    })
                    results["summary"]["confirmed"] += 1
                else:
                    results["suspicious"].append({
                        "vulnerability": vuln,
                        "adjusted_confidence": analysis["confidence"],
                        "analysis": analysis
                    })
                    results["summary"]["suspicious"] += 1
                
            except Exception as e:
                logger.error(f"[FP_FILTER] Error analyzing vulnerability: {e}")
                results["suspicious"].append({
                    "vulnerability": vuln,
                    "error": str(e),
                    "adjusted_confidence": 0.5
                })
                results["summary"]["suspicious"] += 1
        
        # Calculate FP rate
        if results["summary"]["original"] > 0:
            results["summary"]["fp_rate"] = (
                results["summary"]["removed"] / results["summary"]["original"]
            )
        
        # Save results
        self._save_results(results)
        
        # Update state
        self._update_state(results)
        
        logger.info(f"[FP_FILTER] Complete - Confirmed: {results['summary']['confirmed']}, "
                   f"Suspicious: {results['summary']['suspicious']}, "
                   f"Removed: {results['summary']['removed']} "
                   f"(FP rate: {results['summary']['fp_rate']:.1%})")
        
        return results
    
    def analyze_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single vulnerability for false positive indicators.
        
        Args:
            vuln: Vulnerability dictionary
            
        Returns:
            Analysis result with confidence and FP indicators
        """
        result = {
            "is_false_positive": False,
            "fp_confidence": 0.0,
            "confidence": vuln.get("confidence", 0.5),
            "reason": "",
            "indicators": [],
            "recommendations": []
        }
        
        vuln_type = vuln.get("type", "").lower()
        endpoint = vuln.get("endpoint") or vuln.get("url", "")
        payload = vuln.get("payload", "")
        evidence = vuln.get("evidence", "")
        status_code = vuln.get("status_code", 0)
        
        # Check 1: WAF/Security response patterns
        waf_match = self._check_waf_response(evidence)
        if waf_match:
            result["is_false_positive"] = True
            result["fp_confidence"] = 0.9
            result["reason"] = f"WAF/Security response detected: {waf_match}"
            result["indicators"].append("waf_response")
            return result
        
        # Check 2: Generic error responses
        if status_code in [400, 401, 403, 404, 500, 502, 503]:
            if self._is_generic_error(evidence):
                result["confidence"] *= 0.3  # Reduce confidence significantly
                result["indicators"].append("generic_error")
                result["recommendations"].append("Verify with different payload")
        
        # Check 3: Type-specific false positive patterns
        type_fp = self._check_type_specific_fp(vuln_type, evidence)
        if type_fp:
            result["is_false_positive"] = True
            result["fp_confidence"] = 0.8
            result["reason"] = f"Known false positive pattern for {vuln_type}: {type_fp}"
            result["indicators"].append("type_specific_fp")
            return result
        
        # Check 4: Historical false positive check
        hist_fp = self._check_historical_fp(endpoint, vuln_type, payload)
        if hist_fp:
            result["confidence"] *= 0.4
            result["indicators"].append("historical_fp")
            result["recommendations"].append("This endpoint/payload combination has high FP rate historically")
        
        # Check 5: Response content analysis
        content_fp = self._analyze_response_content(evidence, vuln_type)
        if content_fp["is_fp"]:
            result["confidence"] *= (1 - content_fp["score"])
            result["indicators"].append("content_analysis")
            result["reason"] = content_fp["reason"]
        
        # Check 6: Endpoint pattern analysis
        endpoint_fp = self._analyze_endpoint_pattern(endpoint, vuln_type)
        if endpoint_fp["is_fp"]:
            result["confidence"] *= 0.5
            result["indicators"].append("endpoint_pattern")
            result["reason"] = endpoint_fp["reason"]
        
        # Check 7: Cross-validation score
        cross_score = self._cross_validate(vuln)
        if cross_score < 0.3:
            result["confidence"] *= 0.3
            result["indicators"].append("low_cross_validation")
            result["recommendations"].append("Low cross-validation score - verify manually")
        
        # Final determination
        if result["confidence"] < 0.3:
            result["is_false_positive"] = True
            result["fp_confidence"] = 1 - result["confidence"]
            result["reason"] = result["reason"] or "Multiple low-confidence indicators"
        
        return result
    
    def _check_waf_response(self, evidence: str) -> Optional[str]:
        """Check if evidence indicates WAF/security response."""
        evidence_lower = evidence.lower()
        for pattern in self.fp_patterns["waf_responses"]:
            if re.search(pattern, evidence_lower, re.IGNORECASE):
                return pattern
        return None
    
    def _is_generic_error(self, evidence: str) -> bool:
        """Check if evidence is a generic error response."""
        evidence_lower = evidence.lower()
        for pattern in self.fp_patterns["generic_errors"]:
            if re.search(pattern, evidence_lower, re.IGNORECASE):
                return True
        return False
    
    def _check_type_specific_fp(self, vuln_type: str, evidence: str) -> Optional[str]:
        """Check for type-specific false positive patterns."""
        evidence_lower = evidence.lower()
        
        if vuln_type in ["xss", "reflected_xss"]:
            for pattern in self.fp_patterns["false_xss_indicators"]:
                if re.search(pattern, evidence_lower):
                    return pattern
        
        if vuln_type in ["sql_injection", "sqli"]:
            for pattern in self.fp_patterns["false_sqli_indicators"]:
                if re.search(pattern, evidence_lower):
                    return pattern
        
        return None
    
    def _check_historical_fp(self, endpoint: str, vuln_type: str, payload: str) -> bool:
        """Check against historical false positive patterns."""
        # Check endpoint pattern
        for fp_endpoint_pattern in self.historical_fp.get("endpoints", []):
            if re.search(fp_endpoint_pattern, endpoint, re.IGNORECASE):
                return True
        
        # Check payload pattern
        for fp_payload_pattern in self.historical_fp.get("payloads", []):
            if re.search(fp_payload_pattern, payload, re.IGNORECASE):
                return True
        
        return False
    
    def _analyze_response_content(self, evidence: str, vuln_type: str) -> Dict[str, Any]:
        """Analyze response content for false positive indicators."""
        result = {"is_fp": False, "score": 0.0, "reason": ""}
        
        if not evidence:
            return result
        
        # Check for escaped content (common XSS FP)
        if vuln_type in ["xss", "reflected_xss"]:
            if "<" in evidence or ">" in evidence or "&" in evidence:
                result["is_fp"] = True
                result["score"] = 0.7
                result["reason"] = "Content appears HTML-encoded (likely not actual XSS)"
        
        # Check for very short responses (often FP)
        if len(evidence) < 50:
            result["score"] += 0.2
            result["reason"] = "Very short response (possible FP)"
        
        # Check for standard error pages
        error_page_patterns = [
            r"<title>404</title>",
            r"<title>403</title>",
            r"<title>500</title>",
            r"<h1>Not Found</h1>",
            r"<h1>Forbidden</h1>",
        ]
        for pattern in error_page_patterns:
            if re.search(pattern, evidence, re.IGNORECASE):
                result["score"] += 0.3
                result["reason"] = "Standard error page detected"
        
        return result
    
    def _analyze_endpoint_pattern(self, endpoint: str, vuln_type: str) -> Dict[str, Any]:
        """Analyze endpoint pattern for false positive likelihood."""
        result = {"is_fp": False, "reason": ""}
        
        # Static file extensions (unlikely to be vulnerable)
        static_extensions = {'.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.svg', '.map'}
        parsed = urllib.parse.urlparse(endpoint)
        path = parsed.path.lower()
        
        if any(path.endswith(ext) for ext in static_extensions):
            result["is_fp"] = True
            result["reason"] = f"Static file endpoint ({path.split('.')[-1]})"
        
        # Known non-vulnerable paths
        safe_paths = ['/robots.txt', '/sitemap.xml', '/favicon.ico', '/.well-known/']
        for safe_path in safe_paths:
            if safe_path in endpoint.lower():
                result["is_fp"] = True
                result["reason"] = f"Known safe endpoint ({safe_path})"
        
        return result
    
    def _cross_validate(self, vuln: Dict[str, Any]) -> float:
        """
        Cross-validate vulnerability using multiple indicators.
        Returns score 0.0-1.0 (higher = more likely real)
        """
        score = 0.0
        checks = 0
        
        # Check 1: Payload reflection
        payload = vuln.get("payload", "")
        evidence = vuln.get("evidence", "")
        if payload and evidence and payload.lower() in evidence.lower():
            score += 0.3
        checks += 1
        
        # Check 2: Status code consistency
        status_code = vuln.get("status_code", 0)
        if status_code == 200:
            score += 0.2
        elif status_code in [500, 502, 503]:
            score += 0.1
        checks += 1
        
        # Check 3: Evidence length (longer = more likely real)
        if len(evidence) > 200:
            score += 0.2
        checks += 1
        
        # Check 4: Confidence from source
        original_confidence = vuln.get("confidence", 0.5)
        score += original_confidence * 0.3
        checks += 1
        
        return score / checks if checks > 0 else 0.0
    
    def _load_historical_fp(self) -> Dict[str, List[str]]:
        """Load historical false positive patterns from state."""
        return {
            "endpoints": [
                r"\.js$",
                r"\.css$",
                r"\.png$",
                r"\.jpg$",
                r"/robots\.txt$",
                r"/favicon\.ico$",
            ],
            "payloads": [
                r"^'$",  # Single quote alone
                r"^<$",  # Single bracket
                r"^>$",  # Single bracket
            ]
        }
    
    def _save_results(self, results: Dict[str, Any]):
        """Save filtering results to file."""
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.debug(f"[FP_FILTER] Results saved to {self.findings_file}")
        except Exception as e:
            logger.error(f"[FP_FILTER] Failed to save results: {e}")
    
    def _update_state(self, results: Dict[str, Any]):
        """Update state manager with filtering results."""
        # Update confirmed vulnerabilities (high confidence)
        confirmed_vulns = []
        for item in results.get("confirmed", []):
            vuln_data = item["vulnerability"].copy()
            vuln_data["fp_filtered"] = True
            vuln_data["fp_confidence"] = item["adjusted_confidence"]
            confirmed_vulns.append(vuln_data)
        
        current_confirmed = self.state.get("fp_confirmed_vulnerabilities", []) or []
        current_confirmed.extend(confirmed_vulns)
        self.state.update(fp_confirmed_vulnerabilities=current_confirmed)
        
        # Update suspicious vulnerabilities (medium confidence)
        suspicious_vulns = []
        for item in results.get("suspicious", []):
            vuln_data = item["vulnerability"].copy()
            vuln_data["fp_filtered"] = True
            vuln_data["fp_confidence"] = item["adjusted_confidence"]
            vuln_data["fp_suspicious"] = True
            suspicious_vulns.append(vuln_data)
        
        current_suspicious = self.state.get("fp_suspicious_vulnerabilities", []) or []
        current_suspicious.extend(suspicious_vulns)
        self.state.update(fp_suspicious_vulnerabilities=current_suspicious)
        
        # Update FP stats
        self.state.update(fp_stats=results["summary"])
        
        # Update main vulnerabilities with FP flags
        all_vulns = self.state.get("vulnerabilities", []) or []
        removed_endpoints = {
            item["vulnerability"].get("endpoint") 
            for item in results.get("removed", [])
        }
        
        for v in all_vulns:
            endpoint = v.get("endpoint", "")
            if endpoint in removed_endpoints:
                v["fp_removed"] = True
                v["exploitable"] = False
        
        self.state.update(vulnerabilities=all_vulns)
        
        logger.debug(f"[FP_FILTER] State updated - {len(confirmed_vulns)} confirmed, "
                    f"{len(suspicious_vulns)} suspicious, "
                    f"{len(results.get('removed', []))} removed")
    
    def get_exploitable_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Get list of vulnerabilities that passed FP filtering and are exploitable.
        """
        confirmed = self.state.get("fp_confirmed_vulnerabilities", []) or []
        suspicious = self.state.get("fp_suspicious_vulnerabilities", []) or []
        
        # Return confirmed + suspicious with confidence > 0.5
        exploitable = [v for v in confirmed]
        exploitable.extend([
            v for v in suspicious 
            if v.get("fp_confidence", 0) >= 0.5
        ])
        
        return exploitable