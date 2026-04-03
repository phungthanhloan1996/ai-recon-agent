"""
core/chain_validator.py - Attack Chain Validator

Validates attack chains before execution to ensure:
- Prerequisites are satisfied
- Chain is logically sound
- Success probability is acceptable
- Required tools/capabilities are available

This module prevents wasted effort on chains that cannot succeed.
"""

import json
import os
import logging
import re
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("recon.chain_validator")


class ChainStatus(Enum):
    VALID = "valid"
    INVALID = "invalid"
    INCOMPLETE = "incomplete"
    LOW_PROBABILITY = "low_probability"


@dataclass
class ValidationResult:
    """Result of chain validation."""
    chain_id: str
    status: ChainStatus
    confidence: float
    issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    prerequisites_met: Dict[str, bool] = field(default_factory=dict)
    estimated_success_rate: float = 0.0
    
    @property
    def is_valid(self) -> bool:
        return self.status == ChainStatus.VALID
    
    @property
    def can_execute(self) -> bool:
        return self.status in [ChainStatus.VALID, ChainStatus.LOW_PROBABILITY]


class ChainValidator:
    """
    Validates attack chains before execution.
    Ensures prerequisites are met and chains are logically sound.
    """
    
    def __init__(self, state_manager=None, output_dir: str = "."):
        self.state = state_manager
        self.output_dir = output_dir
        self.validation_file = os.path.join(output_dir, "chain_validations.json")
        
        # Required capabilities for different attack types
        self.required_capabilities = {
            "sql_injection": ["sqli_tool", "database_access"],
            "xss": ["browser_simulation", "session_handling"],
            "command_injection": ["shell_access", "command_execution"],
            "file_upload": ["upload_endpoint", "file_execution"],
            "lfi": ["file_read_access", "path_traversal"],
            "rce": ["command_execution", "shell_access"],
            "ssrf": ["network_access", "internal_scanning"],
            "xxe": ["xml_parsing", "file_read_access"],
            "auth_bypass": ["auth_testing", "session_handling"],
            "privilege_escalation": ["shell_access", "system_enumeration"],
        }
        
        # Tool requirements for different attack types
        self.tool_requirements = {
            "sql_injection": ["sqlmap", "http_client"],
            "xss": ["browser", "http_client"],
            "command_injection": ["http_client"],
            "file_upload": ["http_client", "file_handler"],
            "lfi": ["http_client"],
            "rce": ["http_client", "shell_handler"],
            "ssrf": ["http_client", "network_scanner"],
            "xxe": ["http_client", "xml_parser"],
            "auth_bypass": ["http_client", "auth_tester"],
            "privilege_escalation": ["shell_access", "enum_tools"],
        }
        
        # Chain templates with known success rates
        self.chain_templates = self._load_chain_templates()
    
    def validate_chain(self, chain: Dict[str, Any], context: Dict[str, Any]) -> ValidationResult:
        """
        Validate a single attack chain.
        
        Args:
            chain: Chain definition with steps and prerequisites
            context: Execution context (target info, capabilities, etc.)
            
        Returns:
            Validation result with status and issues
        """
        chain_id = chain.get("name", chain.get("id", "unknown"))
        
        result = ValidationResult(
            chain_id=chain_id,
            status=ChainStatus.INVALID,
            confidence=0.0
        )
        
        # Check 1: Prerequisites
        prereqs = chain.get("prerequisites", [])
        prereq_results = self._check_prerequisites(prereqs, context)
        result.prerequisites_met = prereq_results
        
        missing_prereqs = [p for p, met in prereq_results.items() if not met]
        if missing_prereqs:
            result.issues.append(f"Missing prerequisites: {', '.join(missing_prereqs)}")
            result.recommendations.append(self._get_prereq_recommendation(missing_prereqs))
        
        # Check 2: Required capabilities
        chain_type = chain.get("type", chain.get("attack_type", "unknown"))
        capabilities_ok, missing_caps = self._check_capabilities(chain_type, context)
        if not capabilities_ok:
            result.issues.append(f"Missing capabilities: {', '.join(missing_caps)}")
        
        # Check 3: Tool availability
        tools_ok, missing_tools = self._check_tools(chain_type, context)
        if not tools_ok:
            result.issues.append(f"Missing tools: {', '.join(missing_tools)}")
        
        # Check 4: Step validation
        steps = chain.get("steps", [])
        steps_ok, step_issues = self._validate_steps(steps, context)
        if not steps_ok:
            result.issues.extend(step_issues)
        
        # Check 5: Chain logic
        logic_ok, logic_issues = self._validate_chain_logic(chain)
        if not logic_ok:
            result.issues.extend(logic_issues)
        
        # Check 6: Estimate success rate
        success_rate = self._estimate_success_rate(chain, context, prereq_results)
        result.estimated_success_rate = success_rate
        
        # Calculate overall confidence
        total_checks = 6
        passed_checks = 0
        
        if not missing_prereqs:
            passed_checks += 1
        if capabilities_ok:
            passed_checks += 1
        if tools_ok:
            passed_checks += 1
        if steps_ok:
            passed_checks += 1
        if logic_ok:
            passed_checks += 1
        if success_rate > 0.3:
            passed_checks += 1
        
        result.confidence = passed_checks / total_checks
        
        # Determine final status
        if not missing_prereqs and capabilities_ok and tools_ok and steps_ok and logic_ok:
            if success_rate >= 0.5:
                result.status = ChainStatus.VALID
            else:
                result.status = ChainStatus.LOW_PROBABILITY
                result.issues.append(f"Low estimated success rate: {success_rate:.0%}")
        elif not missing_prereqs:
            result.status = ChainStatus.INCOMPLETE
        else:
            result.status = ChainStatus.INVALID
        
        return result
    
    def validate_chains(self, chains: List[Dict[str, Any]], context: Dict[str, Any]) -> List[ValidationResult]:
        """
        Validate multiple attack chains.
        
        Args:
            chains: List of chain definitions
            context: Execution context
            
        Returns:
            List of validation results
        """
        results = []
        for chain in chains:
            try:
                result = self.validate_chain(chain, context)
                results.append(result)
            except Exception as e:
                logger.error(f"[CHAIN_VAL] Error validating chain {chain.get('name', 'unknown')}: {e}")
                results.append(ValidationResult(
                    chain_id=chain.get("name", "unknown"),
                    status=ChainStatus.INVALID,
                    confidence=0.0,
                    issues=[f"Validation error: {str(e)}"]
                ))
        
        # Sort by confidence descending
        results.sort(key=lambda r: r.confidence, reverse=True)
        
        # Save results
        self._save_validations(results)
        
        return results
    
    def get_executable_chains(self, chains: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get chains that are ready for execution.
        
        Args:
            chains: List of chain definitions
            context: Execution context
            
        Returns:
            List of executable chains with validation data
        """
        results = self.validate_chains(chains, context)
        
        executable = []
        for chain, result in zip(chains, results):
            if result.can_execute:
                chain_copy = chain.copy()
                chain_copy["validation"] = {
                    "status": result.status.value,
                    "confidence": result.confidence,
                    "estimated_success_rate": result.estimated_success_rate,
                    "issues": result.issues,
                }
                executable.append(chain_copy)
        
        return executable
    
    def _check_prerequisites(self, prerequisites: List[str], context: Dict[str, Any]) -> Dict[str, bool]:
        """Check if all prerequisites are satisfied."""
        results = {}
        
        for prereq in prerequisites:
            prereq_lower = prereq.lower()
            met = False
            
            # Check technology prerequisites
            if "wordpress" in prereq_lower:
                met = context.get("technologies", {}).get("wordpress", {}).get("detected", False)
            
            elif "drupal" in prereq_lower:
                met = context.get("technologies", {}).get("drupal", {}).get("detected", False)
            
            elif "joomla" in prereq_lower:
                met = context.get("technologies", {}).get("joomla", {}).get("detected", False)
            
            # Check endpoint prerequisites
            elif "login" in prereq_lower:
                login_eps = context.get("login_endpoints", [])
                met = len(login_eps) > 0
            
            elif "upload" in prereq_lower:
                upload_eps = context.get("upload_endpoints", [])
                met = len(upload_eps) > 0
            
            elif "api" in prereq_lower:
                api_eps = context.get("api_endpoints", [])
                met = len(api_eps) > 0
            
            # Check vulnerability prerequisites
            elif "sqli" in prereq_lower or "sql_injection" in prereq_lower:
                vulns = context.get("vulnerabilities", [])
                met = any(v.get("type", "").lower() in ["sql_injection", "sqli"] for v in vulns)
            
            elif "xss" in prereq_lower:
                vulns = context.get("vulnerabilities", [])
                met = any(v.get("type", "").lower() == "xss" for v in vulns)
            
            elif "rce" in prereq_lower:
                vulns = context.get("vulnerabilities", [])
                met = any(v.get("type", "").lower() == "rce" for v in vulns)
            
            # Check authentication prerequisites
            elif "auth" in prereq_lower:
                met = context.get("has_auth", False) or context.get("authenticated", False)
            
            elif "admin" in prereq_lower:
                met = context.get("admin_access", False)
            
            # Check tool prerequisites
            elif "sqlmap" in prereq_lower:
                met = context.get("tools", {}).get("sqlmap", False)
            
            # Default: assume met if we can't determine
            else:
                met = True  # Optimistic default
            
            results[prereq] = met
        
        return results
    
    def _check_capabilities(self, chain_type: str, context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Check if required capabilities are available."""
        required = self.required_capabilities.get(chain_type, [])
        available = context.get("capabilities", [])
        
        missing = [cap for cap in required if cap not in available]
        return len(missing) == 0, missing
    
    def _check_tools(self, chain_type: str, context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Check if required tools are available."""
        required = self.tool_requirements.get(chain_type, [])
        available_tools = context.get("tools", {})
        
        missing = [tool for tool in required if not available_tools.get(tool, False)]
        return len(missing) == 0, missing
    
    def _validate_steps(self, steps: List[Dict[str, Any]], context: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate chain steps for completeness and validity."""
        issues = []
        
        if not steps:
            issues.append("Chain has no steps defined")
            return False, issues
        
        for i, step in enumerate(steps):
            step_num = i + 1
            
            # Check step has required fields
            if not step.get("name"):
                issues.append(f"Step {step_num}: Missing name")
            
            if not step.get("action"):
                issues.append(f"Step {step_num}: Missing action")
            
            # Check step has target
            target = step.get("target") or step.get("endpoint") or ""
            if not target:
                issues.append(f"Step {step_num}: Missing target/endpoint")
            else:
                # STRICT URL VALIDATION: Validate URL format before execution
                url_validation = self._validate_step_url(target, step_num)
                if url_validation:
                    issues.append(url_validation)
            
            # Check step has expected outcome
            if not step.get("success_indicator"):
                issues.append(f"Step {step_num}: Missing success indicator")
            
            # Check step has payload if action requires it
            action = step.get("action", "")
            if action in ["payload_injection", "code_execution", "file_upload", "exploit"]:
                if not step.get("payload"):
                    issues.append(f"Step {step_num}: Missing payload for action '{action}'")
        
        return len(issues) == 0, issues

    def _validate_step_url(self, url: str, step_num: int) -> Optional[str]:
        """
        STRICT URL VALIDATION: Validate URL format for chain steps.
        Returns error message if invalid, None if valid.
        """
        from urllib.parse import urlparse
        
        if not url or not isinstance(url, str):
            return f"Step {step_num}: Empty or invalid URL"
        
        url = url.strip()
        
        # Check for valid URL structure
        try:
            parsed = urlparse(url)
        except Exception as e:
            return f"Step {step_num}: URL parse error: {e}"
        
        # Must have scheme
        if not parsed.scheme:
            return f"Step {step_num}: URL missing scheme (http:// or https://): {url[:80]}"
        
        if parsed.scheme not in ['http', 'https']:
            return f"Step {step_num}: Invalid URL scheme '{parsed.scheme}': {url[:80]}"
        
        # Must have netloc (domain)
        if not parsed.netloc:
            return f"Step {step_num}: URL missing domain: {url[:80]}"
        
        # Check for invalid characters in hostname
        hostname = parsed.hostname or ''
        if not hostname:
            return f"Step {step_num}: URL has no valid hostname: {url[:80]}"
        
        # Check for obviously malformed hostnames
        invalid_chars = ['<', '>', '"', "'", ' ']
        if any(c in hostname for c in invalid_chars):
            return f"Step {step_num}: Hostname contains invalid characters: {hostname}"
        
        # Check for localhost/internal addresses (usually not exploitable remotely)
        internal_patterns = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        if hostname in internal_patterns:
            return f"Step {step_num}: URL points to localhost/internal address (not exploitable): {url[:80]}"
        
        return None  # Valid URL
    
    def _validate_chain_logic(self, chain: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate chain logic and flow."""
        issues = []
        
        steps = chain.get("steps", [])
        
        # Check for circular dependencies
        step_names = [s.get("name", "") for s in steps]
        if len(step_names) != len(set(step_names)):
            issues.append("Chain has duplicate step names (possible circular dependency)")
        
        # Check chain has at least one step
        if not steps:
            issues.append("Chain has no steps")
        
        # Check chain has a goal
        if not chain.get("goal") and not chain.get("objective"):
            issues.append("Chain has no defined goal/objective")
        
        # Check for reasonable chain length
        if len(steps) > 20:
            issues.append("Chain is excessively long (>20 steps)")
        
        # Check step dependencies make sense
        for i, step in enumerate(steps):
            deps = step.get("depends_on", [])
            for dep in deps:
                if dep not in step_names[:i]:
                    issues.append(f"Step '{step.get('name')}' depends on unknown step '{dep}'")
        
        # ─── PRIORITY 8: SIMILAR ENDPOINT LIMIT ─────────────────────────────────────
        # Prevent chains with >10 similar endpoints to avoid redundant scanning
        similar_endpoint_count = self._count_similar_endpoints_in_chain(chain)
        if similar_endpoint_count > 10:
            issues.append(f"Chain has {similar_endpoint_count} similar endpoints (max 10 allowed)")
        
        return len(issues) == 0, issues

    def _count_similar_endpoints_in_chain(self, chain: Dict[str, Any]) -> int:
        """
        Count similar endpoints in a chain.
        Groups endpoints by base path and returns the max count.
        
        PRIORITY 8: If >10 endpoints target similar paths, chain is likely redundant.
        """
        from urllib.parse import urlparse
        from collections import Counter
        
        endpoints = []
        steps = chain.get("steps", [])
        
        for step in steps:
            target = step.get("target", "")
            if target:
                try:
                    parsed = urlparse(target)
                    # Normalize to host + base path
                    path = parsed.path.rstrip('/').split('?')[0]
                    path_parts = path.strip('/').split('/')
                    base_path = '/' + '/'.join(path_parts[:2]) if path_parts[0] else '/'
                    endpoint_key = f"{parsed.netloc}{base_path}"
                    endpoints.append(endpoint_key)
                except Exception:
                    endpoints.append(target)
        
        if not endpoints:
            return 0
        
        # Count occurrences of each endpoint pattern
        counts = Counter(endpoints)
        return max(counts.values()) if counts else 0
    
    def _estimate_success_rate(self, chain: Dict[str, Any], context: Dict[str, Any], 
                              prereq_results: Dict[str, bool]) -> float:
        """Estimate chain success rate based on various factors."""
        rate = 0.5  # Base rate
        
        # Adjust based on prerequisites met
        if prereq_results:
            prereq_rate = sum(1 for met in prereq_results.values() if met) / len(prereq_results)
            rate += (prereq_rate - 0.5) * 0.3
        
        # Adjust based on chain type historical data
        chain_type = chain.get("type", "unknown")
        historical_rate = self.chain_templates.get(chain_type, {}).get("success_rate", 0.5)
        rate += (historical_rate - 0.5) * 0.2
        
        # Adjust based on target complexity
        tech_count = len(context.get("technologies", {}))
        if tech_count > 5:
            rate -= 0.1  # Complex targets are harder
        
        # Adjust based on available intelligence
        vuln_count = len(context.get("vulnerabilities", []))
        if vuln_count > 3:
            rate += 0.1  # More vulns = more options
        
        # Clamp to valid range
        return max(0.0, min(1.0, rate))
    
    def _get_prereq_recommendation(self, missing_prereqs: List[str]) -> str:
        """Get recommendation for addressing missing prerequisites."""
        recommendations = []
        
        for prereq in missing_prereqs:
            if "wordpress" in prereq.lower():
                recommendations.append("Run WordPress detection first")
            elif "login" in prereq.lower():
                recommendations.append("Discover login endpoints via crawling")
            elif "upload" in prereq.lower():
                recommendations.append("Scan for file upload functionality")
            elif "sqli" in prereq.lower():
                recommendations.append("Run SQL injection detection")
            elif "sqlmap" in prereq.lower():
                recommendations.append("Install sqlmap tool")
        
        return "; ".join(recommendations) if recommendations else "Address missing prerequisites before execution"
    
    def _load_chain_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load chain templates with historical success rates."""
        return {
            "wordpress_exploit": {
                "success_rate": 0.7,
                "description": "WordPress exploitation chain"
            },
            "sql_injection": {
                "success_rate": 0.6,
                "description": "SQL injection exploitation"
            },
            "xss_to_session_hijack": {
                "success_rate": 0.4,
                "description": "XSS to session hijacking"
            },
            "file_upload_rce": {
                "success_rate": 0.5,
                "description": "File upload to RCE"
            },
            "lfi_to_rce": {
                "success_rate": 0.4,
                "description": "LFI to RCE chain"
            },
            "auth_bypass": {
                "success_rate": 0.3,
                "description": "Authentication bypass"
            },
            "ssrf_to_internal_scan": {
                "success_rate": 0.6,
                "description": "SSRF to internal scanning"
            },
        }
    
    def _save_validations(self, results: List[ValidationResult]):
        """Save validation results to file."""
        try:
            data = []
            for r in results:
                data.append({
                    "chain_id": r.chain_id,
                    "status": r.status.value,
                    "confidence": r.confidence,
                    "estimated_success_rate": r.estimated_success_rate,
                    "issues": r.issues,
                    "recommendations": r.recommendations,
                    "prerequisites_met": r.prerequisites_met,
                })
            
            with open(self.validation_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.debug(f"[CHAIN_VAL] Saved {len(data)} validations to {self.validation_file}")
        except Exception as e:
            logger.error(f"[CHAIN_VAL] Failed to save validations: {e}")
    
    def get_chain_statistics(self, results: List[ValidationResult]) -> Dict[str, Any]:
        """Get statistics about chain validation results."""
        stats = {
            "total": len(results),
            "valid": sum(1 for r in results if r.status == ChainStatus.VALID),
            "invalid": sum(1 for r in results if r.status == ChainStatus.INVALID),
            "incomplete": sum(1 for r in results if r.status == ChainStatus.INCOMPLETE),
            "low_probability": sum(1 for r in results if r.status == ChainStatus.LOW_PROBABILITY),
            "avg_confidence": sum(r.confidence for r in results) / len(results) if results else 0,
            "avg_success_rate": sum(r.estimated_success_rate for r in results) / len(results) if results else 0,
        }
        return stats