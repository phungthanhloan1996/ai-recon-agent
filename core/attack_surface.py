"""
core/attack_surface.py - Attack Surface Intelligence Tracker

Maintains a structured representation of the target's attack surface,
accumulating clues from all reconnaissance and scanning phases.

All exploitation modules must consult this structure before executing.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Any
from collections import defaultdict

logger = logging.getLogger("recon.attack_surface")


@dataclass
class Clue:
    """A single piece of intelligence about the target."""
    clue_type: str  # cms, plugin, endpoint, auth, api, container, framework, header, error, tech
    value: str
    source: str  # which tool/phase discovered this
    confidence: float  # 0.0-1.0
    evidence: str = ""
    timestamp: float = 0.0


@dataclass
class AttackSurface:
    """
    Structured representation of the target's attack surface.
    Built incrementally from reconnaissance clues.
    """
    # Technology detection
    technologies: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # name -> {version, confidence, source}
    cms: Dict[str, Any] = field(default_factory=dict)  # {name, version, confidence, plugins, themes}
    frameworks: Set[str] = field(default_factory=set)
    
    # Endpoints and paths
    endpoints: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # url -> {method, type, params}
    login_endpoints: List[str] = field(default_factory=list)
    admin_endpoints: List[str] = field(default_factory=list)
    upload_endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    
    # Authentication flows
    auth_flows: Dict[str, Any] = field(default_factory=dict)  # {type, endpoints, mfa_detected, oauth, saml}
    oauth_endpoints: List[str] = field(default_factory=list)
    saml_endpoints: List[str] = field(default_factory=list)
    mfa_indicators: List[str] = field(default_factory=list)
    
    # API patterns
    api_patterns: Set[str] = field(default_factory=set)  # REST, GraphQL, SOAP, etc.
    
    # Container/cloud indicators
    container_indicators: List[str] = field(default_factory=list)  # docker headers, k8s indicators
    
    # Server information
    server_headers: Dict[str, str] = field(default_factory=dict)
    unusual_responses: List[str] = field(default_factory=list)
    
    # WordPress specific
    wp_plugins: List[Dict[str, Any]] = field(default_factory=list)
    wp_themes: List[Dict[str, Any]] = field(default_factory=list)
    wp_users: List[str] = field(default_factory=list)
    wp_version: str = ""
    
    # All raw clues for reference
    all_clues: List[Clue] = field(default_factory=list)
    
    # Hypothesis tracking
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)  # Generated attack hypotheses


class AttackSurfaceTracker:
    """
    Manages the attack surface state, accumulating clues from all phases.
    Provides query methods for modules to check if they should execute.
    """
    
    def __init__(self):
        self.surface = AttackSurface()
        self._clue_index: Dict[str, List[Clue]] = defaultdict(list)
    
    def add_clue(self, clue_type: str, value: str, source: str, 
                 confidence: float = 0.8, evidence: str = ""):
        """Add a new clue to the attack surface."""
        clue = Clue(
            clue_type=clue_type,
            value=value,
            source=source,
            confidence=confidence,
            evidence=evidence
        )
        self.surface.all_clues.append(clue)
        self._clue_index[clue_type].append(clue)
        
        # Process clue based on type
        self._process_clue(clue)
        
        logger.debug(f"[ATTACK_SURFACE] Added clue: {clue_type}={value} (from {source})")
    
    def _process_clue(self, clue: Clue):
        """Process a clue and update the attack surface structure."""
        if clue.clue_type == "cms":
            self.surface.cms = {
                "name": clue.value,
                "version": clue.evidence.split(":")[-1].strip() if ":" in clue.evidence else "",
                "confidence": clue.confidence,
                "source": clue.source
            }
        
        elif clue.clue_type == "plugin":
            plugin_info = {"name": clue.value, "source": clue.source}
            if clue.evidence:
                plugin_info["version"] = clue.evidence
            if clue.confidence > 0.7:
                self.surface.wp_plugins.append(plugin_info)
        
        elif clue.clue_type == "tech":
            parts = clue.value.split(":")
            name = parts[0].strip()
            version = parts[1].strip() if len(parts) > 1 else ""
            self.surface.technologies[name] = {
                "version": version,
                "confidence": clue.confidence,
                "source": clue.source
            }
        
        elif clue.clue_type == "framework":
            self.surface.frameworks.add(clue.value)
        
        elif clue.clue_type == "endpoint":
            ep_type = clue.evidence if clue.evidence else "general"
            self.surface.endpoints[clue.value] = {
                "type": ep_type,
                "source": clue.source,
                "confidence": clue.confidence
            }
            if "login" in clue.value.lower() or "auth" in clue.value.lower():
                self.surface.login_endpoints.append(clue.value)
            if "admin" in clue.value.lower():
                self.surface.admin_endpoints.append(clue.value)
            if "upload" in clue.value.lower() or "file" in clue.value.lower():
                self.surface.upload_endpoints.append(clue.value)
            if "api" in clue.value.lower() or "graphql" in clue.value.lower() or "rest" in clue.value.lower():
                self.surface.api_endpoints.append(clue.value)
        
        elif clue.clue_type == "auth":
            if "oauth" in clue.value.lower():
                self.surface.oauth_endpoints.append(clue.value)
            elif "saml" in clue.value.lower():
                self.surface.saml_endpoints.append(clue.value)
            elif "mfa" in clue.value.lower() or "2fa" in clue.value.lower():
                self.surface.mfa_indicators.append(clue.value)
        
        elif clue.clue_type == "api":
            self.surface.api_patterns.add(clue.value)
        
        elif clue.clue_type == "container":
            self.surface.container_indicators.append(clue.value)
        
        elif clue.clue_type == "header":
            parts = clue.value.split(":", 1)
            if len(parts) == 2:
                self.surface.server_headers[parts[0].strip()] = parts[1].strip()
        
        elif clue.clue_type == "error":
            self.surface.unusual_responses.append(clue.value)
    
    def has_wordpress(self) -> bool:
        """Check if WordPress is detected."""
        return bool(self.surface.cms.get("name") and "wordpress" in self.surface.cms["name"].lower())
    
    def has_container_indicators(self) -> bool:
        """Check if container environment indicators exist."""
        return len(self.surface.container_indicators) > 0
    
    def has_oauth_saml(self) -> bool:
        """Check if OAuth/SAML endpoints are detected."""
        return len(self.surface.oauth_endpoints) > 0 or len(self.surface.saml_endpoints) > 0
    
    def has_mfa(self) -> bool:
        """Check if MFA is detected."""
        return len(self.surface.mfa_indicators) > 0
    
    def has_upload_endpoints(self) -> bool:
        """Check if file upload endpoints exist."""
        return len(self.surface.upload_endpoints) > 0
    
    def has_api_endpoints(self) -> bool:
        """Check if API endpoints exist."""
        return len(self.surface.api_endpoints) > 0
    
    def has_login_endpoints(self) -> bool:
        """Check if login endpoints exist."""
        return len(self.surface.login_endpoints) > 0
    
    def get_vulnerable_plugins(self) -> List[Dict[str, Any]]:
        """Get plugins that may have known vulnerabilities."""
        return [p for p in self.surface.wp_plugins if p.get("vulnerabilities")]
    
    def generate_hypotheses(self) -> List[Dict[str, Any]]:
        """
        Generate attack hypotheses based on accumulated clues.
        Returns prioritized list of attack paths to investigate.
        """
        hypotheses = []
        
        # WordPress attack chains
        if self.has_wordpress():
            hypotheses.append({
                "type": "wordpress_exploit",
                "priority": 1,
                "description": "WordPress exploitation chain",
                "evidence": f"WordPress {self.surface.cms.get('version', '')} detected",
                "actions": ["enumerate_plugins", "check_versions", "exploit_vulnerable_plugin"]
            })
            
            if self.surface.wp_plugins:
                hypotheses.append({
                    "type": "wp_plugin_exploit",
                    "priority": 1,
                    "description": "WordPress plugin exploitation",
                    "evidence": f"{len(self.surface.wp_plugins)} plugins detected",
                    "actions": ["version_check", "cve_lookup", "exploit"]
                })
        
        # File upload RCE
        if self.has_upload_endpoints():
            hypotheses.append({
                "type": "upload_rce",
                "priority": 2,
                "description": "File upload to RCE chain",
                "evidence": f"Upload endpoints: {self.surface.upload_endpoints[:3]}",
                "actions": ["test_upload", "bypass_validation", "upload_webshell"]
            })
        
        # Authentication attacks
        if self.has_login_endpoints():
            hypotheses.append({
                "type": "auth_attack",
                "priority": 2,
                "description": "Authentication bypass/brute force",
                "evidence": f"Login endpoints: {self.surface.login_endpoints[:3]}",
                "actions": ["test_default_creds", "brute_force", "bypass_auth"]
            })
        
        # OAuth/SAML attacks
        if self.has_oauth_saml():
            hypotheses.append({
                "type": "oauth_saml_exploit",
                "priority": 2,
                "description": "OAuth/SAML flow exploitation",
                "evidence": "OAuth/SAML endpoints detected",
                "actions": ["analyze_flow", "test_redirect_uri", "token_manipulation"]
            })
        
        # MFA bypass
        if self.has_mfa():
            hypotheses.append({
                "type": "mfa_bypass",
                "priority": 3,
                "description": "MFA bypass techniques",
                "evidence": f"MFA indicators: {self.surface.mfa_indicators[:3]}",
                "actions": ["identify_mfa_type", "test_bypass_methods"]
            })
        
        # API attacks
        if self.has_api_endpoints():
            hypotheses.append({
                "type": "api_exploit",
                "priority": 3,
                "description": "API vulnerability exploitation",
                "evidence": f"API endpoints: {self.surface.api_endpoints[:3]}",
                "actions": ["fuzz_parameters", "test_idor", "test_injection"]
            })
        
        # Container escape
        if self.has_container_indicators():
            hypotheses.append({
                "type": "container_escape",
                "priority": 2,
                "description": "Container/cloud escape",
                "evidence": f"Container indicators: {self.surface.container_indicators[:3]}",
                "actions": ["verify_container", "check_mounts", "escape_attempt"]
            })
        
        # Sort by priority
        hypotheses.sort(key=lambda h: h["priority"])
        self.surface.hypotheses = hypotheses
        return hypotheses
    
    def should_run_module(self, module_name: str) -> bool:
        """
        Check if a module should be executed based on available evidence.
        Returns (should_run: bool, reason: str)
        """
        module_gates = {
            "container_escape": (self.has_container_indicators(), 
                                "Container environment indicators detected"),
            "oauth_saml_exploit": (self.has_oauth_saml(),
                                  "OAuth/SAML authentication endpoints detected"),
            "ssl_pinning_bypass": (len(self.surface.api_endpoints) > 0 or 
                                  len(self.surface.frameworks & {"react-native", "flutter", "xamarin"}) > 0,
                                  "Mobile API patterns detected"),
            "mfa_bypass": (self.has_mfa() and self.has_login_endpoints(),
                          "MFA with login endpoint detected"),
            "zero_day_detection": (len(self.surface.unusual_responses) > 0 or
                                  len(self.get_vulnerable_plugins()) > 0,
                                  "Unknown plugins or unusual responses detected"),
            "ddos_attacker": (False, "DDoS module disabled for automatic execution"),
        }
        
        if module_name in module_gates:
            should_run, reason = module_gates[module_name]
            return should_run, reason
        
        # Default: allow execution
        return True, "No specific gating rules"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert attack surface to dictionary for state persistence."""
        return {
            "technologies": self.surface.technologies,
            "cms": self.surface.cms,
            "frameworks": list(self.surface.frameworks),
            "endpoints": self.surface.endpoints,
            "login_endpoints": self.surface.login_endpoints,
            "admin_endpoints": self.surface.admin_endpoints,
            "upload_endpoints": self.surface.upload_endpoints,
            "api_endpoints": self.surface.api_endpoints,
            "auth_flows": self.surface.auth_flows,
            "oauth_endpoints": self.surface.oauth_endpoints,
            "saml_endpoints": self.surface.saml_endpoints,
            "mfa_indicators": self.surface.mfa_indicators,
            "api_patterns": list(self.surface.api_patterns),
            "container_indicators": self.surface.container_indicators,
            "server_headers": self.surface.server_headers,
            "unusual_responses": self.surface.unusual_responses,
            "wp_plugins": self.surface.wp_plugins,
            "wp_themes": self.surface.wp_themes,
            "wp_users": self.surface.wp_users,
            "wp_version": self.surface.wp_version,
            "hypotheses": self.surface.hypotheses
        }
    
    def from_dict(self, data: Dict[str, Any]):
        """Restore attack surface from dictionary."""
        if "technologies" in data:
            self.surface.technologies = data["technologies"]
        if "cms" in data:
            self.surface.cms = data["cms"]
        if "frameworks" in data:
            self.surface.frameworks = set(data["frameworks"])
        if "endpoints" in data:
            self.surface.endpoints = data["endpoints"]
        if "login_endpoints" in data:
            self.surface.login_endpoints = data["login_endpoints"]
        if "admin_endpoints" in data:
            self.surface.admin_endpoints = data["admin_endpoints"]
        if "upload_endpoints" in data:
            self.surface.upload_endpoints = data["upload_endpoints"]
        if "api_endpoints" in data:
            self.surface.api_endpoints = data["api_endpoints"]
        if "oauth_endpoints" in data:
            self.surface.oauth_endpoints = data["oauth_endpoints"]
        if "saml_endpoints" in data:
            self.surface.saml_endpoints = data["saml_endpoints"]
        if "mfa_indicators" in data:
            self.surface.mfa_indicators = data["mfa_indicators"]
        if "api_patterns" in data:
            self.surface.api_patterns = set(data["api_patterns"])
        if "container_indicators" in data:
            self.surface.container_indicators = data["container_indicators"]
        if "server_headers" in data:
            self.surface.server_headers = data["server_headers"]
        if "unusual_responses" in data:
            self.surface.unusual_responses = data["unusual_responses"]
        if "wp_plugins" in data:
            self.surface.wp_plugins = data["wp_plugins"]
        if "wp_themes" in data:
            self.surface.wp_themes = data["wp_themes"]
        if "wp_users" in data:
            self.surface.wp_users = data["wp_users"]
        if "wp_version" in data:
            self.surface.wp_version = data["wp_version"]
        if "hypotheses" in data:
            self.surface.hypotheses = data["hypotheses"]