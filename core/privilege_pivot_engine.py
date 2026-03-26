"""
core/privilege_pivot_engine.py - Privilege Pivot Engine
Identify privilege escalation and pivot opportunities between endpoints.
"""

import logging
import json
import uuid
from typing import Dict, List, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum

logger = logging.getLogger("recon.privilege_pivot")


class PrivilegeLevelEnum(str, Enum):
    """Privilege levels in exploitation chain."""
    UNAUTHENTICATED = "unauthenticated"
    AUTHENTICATED = "authenticated"
    USER = "user"
    ADMIN = "admin"
    SYSTEM = "system"
    CODE_EXECUTION = "code_execution"


@dataclass
class PivotStep:
    """Single step in a privilege escalation chain."""
    step_number: int
    endpoint: str
    action: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    payload_type: str = ""
    current_privilege: str = PrivilegeLevelEnum.UNAUTHENTICATED
    resulting_privilege: str = PrivilegeLevelEnum.AUTHENTICATED
    success_indicator: str = ""
    description: str = ""


@dataclass
class ExploitationChain:
    """Complete exploitation chain from discovery to impact."""
    chain_id: str
    name: str
    steps: List[PivotStep]
    initial_privilege: str = PrivilegeLevelEnum.UNAUTHENTICATED
    final_privilege: str = PrivilegeLevelEnum.CODE_EXECUTION
    impact: str = ""
    confidence: float = 0.0
    likelihood: float = 0.0
    complexity: str = "medium"  # low, medium, high
    technologies: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'chain_id': self.chain_id,
            'name': self.name,
            'steps': [asdict(step) for step in self.steps],
            'initial_privilege': self.initial_privilege,
            'final_privilege': self.final_privilege,
            'impact': self.impact,
            'confidence': self.confidence,
            'likelihood': self.likelihood,
            'complexity': self.complexity,
            'technologies': self.technologies,
            'prerequisites': self.prerequisites
        }


class PrivilegePivotEngine:
    """
    Identifies privilege escalation and pivot opportunities.
    
    Analyzes:
    - Authentication endpoints
    - Admin panels
    - Upload endpoints
    - Vulnerable endpoints
    - Service misconfigurations
    
    Builds privilege escalation chains from low privilege to RCE.
    """

    def __init__(self):
        self.chains = []
        self.endpoints_by_privilege = {}  # privilege_level -> [endpoints]
        self.vulnerability_map = {}  # endpoint -> [vulnerabilities]

    def analyze_privileges(self, endpoints: List[Dict[str, Any]], 
                          vulnerabilities: List[Dict[str, Any]]) -> List[ExploitationChain]:
        """
        Analyze endpoints and vulnerabilities to identify privilege escalation chains.
        
        Args:
            endpoints: List of discovered endpoints
            vulnerabilities: List of discovered vulnerabilities
            
        Returns:
            List of ExploitationChain objects
        """
        logger.info(f"[PIVOT] Analyzing {len(endpoints)} endpoints for pivot opportunities")
        
        # Classify endpoints by privilege requirements
        self._classify_endpoints_by_privilege(endpoints)
        
        # Build vulnerability map
        self._build_vulnerability_map(vulnerabilities)
        
        # Generate pivot chains
        chains = self._generate_pivot_chains(endpoints, vulnerabilities)
        
        logger.info(f"[PIVOT] Generated {len(chains)} privilege escalation chains")
        return chains

    def _classify_endpoints_by_privilege(self, endpoints: List[Dict[str, Any]]) -> None:
        """
        Classify endpoints by required privilege level.
        
        Args:
            endpoints: List of endpoint dictionaries
        """
        for endpoint in endpoints:
            url = endpoint.get('url', '').lower()
            endpoint_type = endpoint.get('endpoint_type', '').lower()
            
            privilege = PrivilegeLevelEnum.UNAUTHENTICATED
            
            # Classify based on endpoint patterns
            if any(x in url for x in ['login', 'auth', 'signin']):
                privilege = PrivilegeLevelEnum.AUTHENTICATED
            elif any(x in url for x in ['admin', 'dashboard', 'settings']):
                privilege = PrivilegeLevelEnum.ADMIN
            elif any(x in url for x in ['upload', 'file', 'profile']):
                privilege = PrivilegeLevelEnum.AUTHENTICATED
            elif endpoint_type == 'api':
                privilege = PrivilegeLevelEnum.AUTHENTICATED
            
            if privilege not in self.endpoints_by_privilege:
                self.endpoints_by_privilege[privilege] = []
            
            self.endpoints_by_privilege[privilege].append(endpoint)

    def _build_vulnerability_map(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Build map of vulnerabilities to endpoints."""
        for vuln in vulnerabilities:
            endpoint = vuln.get('url') or vuln.get('endpoint', '')
            if endpoint:
                if endpoint not in self.vulnerability_map:
                    self.vulnerability_map[endpoint] = []
                self.vulnerability_map[endpoint].append(vuln)

    def _generate_pivot_chains(self, endpoints: List[Dict[str, Any]], 
                              vulnerabilities: List[Dict[str, Any]]) -> List[ExploitationChain]:
        """
        Generate privilege escalation chains from discovered vulnerabilities and endpoints.
        
        Args:
            endpoints: Discovered endpoints
            vulnerabilities: Discovered vulnerabilities
            
        Returns:
            List of exploitation chains
        """
        chains = []
        
        # Pattern 1: SQLi on login -> Admin creation -> Plugin upload -> RCE
        sqli_chains = self._build_sqli_chains(endpoints, vulnerabilities)
        chains.extend(sqli_chains)
        
        # Pattern 2: File upload -> Shell execution -> RCE
        upload_chains = self._build_upload_chains(endpoints, vulnerabilities)
        chains.extend(upload_chains)
        
        # Pattern 3: Auth bypass -> Admin panel -> Config change -> RCE
        auth_chains = self._build_auth_chains(endpoints, vulnerabilities)
        chains.extend(auth_chains)
        
        # Pattern 4: IDOR -> Admin access -> Plugin upload -> RCE
        idor_chains = self._build_idor_chains(endpoints, vulnerabilities)
        chains.extend(idor_chains)
        
        # Pattern 5: Template injection -> Code execution
        injection_chains = self._build_injection_chains(endpoints, vulnerabilities)
        chains.extend(injection_chains)
        
        # Pattern 6: Misconfiguration exploitation
        misconfig_chains = self._build_misconfiguration_chains(endpoints)
        chains.extend(misconfig_chains)
        
        return chains

    def _build_sqli_chains(self, endpoints: List[Dict[str, Any]], 
                          vulnerabilities: List[Dict[str, Any]]) -> List[ExploitationChain]:
        """Build SQLi-based privilege escalation chains."""
        chains = []
        
        for vuln in vulnerabilities:
            if vuln.get('type') != 'sqli':
                continue
            
            endpoint = vuln.get('url', '')
            
            # Look for login endpoints with SQLi
            if any(x in endpoint.lower() for x in ['login', 'auth', 'user']):
                chain = ExploitationChain(
                    chain_id=str(uuid.uuid4()),
                    name="SQLi Login Bypass -> Admin Creation -> Plugin Upload -> RCE",
                    steps=[
                        PivotStep(
                            step_number=1,
                            endpoint=endpoint,
                            action="Execute SQL injection to bypass authentication",
                            method="POST",
                            parameters=[
                                p.get('name', '') for p in vuln.get('parameters', [])[:3]
                            ],
                            payload_type="sqli",
                            current_privilege=PrivilegeLevelEnum.UNAUTHENTICATED,
                            resulting_privilege=PrivilegeLevelEnum.ADMIN,
                            success_indicator="Successful login",
                            description="Use SQLi to authenticate as admin without password"
                        ),
                        PivotStep(
                            step_number=2,
                            endpoint="/wp-admin/ or admin panel",
                            action="Create new admin user via SQL injection",
                            method="POST",
                            payload_type="sqli",
                            current_privilege=PrivilegeLevelEnum.ADMIN,
                            resulting_privilege=PrivilegeLevelEnum.ADMIN,
                            success_indicator="Admin user created",
                            description="Insert new admin account into database"
                        ),
                        PivotStep(
                            step_number=3,
                            endpoint="/wp-admin/plugins.php or plugin management",
                            action="Upload malicious plugin",
                            method="POST",
                            parameters=['plugin', 'file'],
                            payload_type="file_upload",
                            current_privilege=PrivilegeLevelEnum.ADMIN,
                            resulting_privilege=PrivilegeLevelEnum.CODE_EXECUTION,
                            success_indicator="Plugin uploaded and active",
                            description="Upload webshell or backdoor plugin"
                        ),
                    ],
                    impact="Complete system compromise - Remote Code Execution",
                    confidence=0.85,
                    likelihood=0.7,
                    complexity="medium"
                )
                chains.append(chain)
        
        return chains

    def _build_upload_chains(self, endpoints: List[Dict[str, Any]], 
                            vulnerabilities: List[Dict[str, Any]]) -> List[ExploitationChain]:
        """Build file upload-based chains."""
        chains = []
        
        upload_endpoints = [
            ep for ep in endpoints 
            if 'upload' in ep.get('url', '').lower()
        ]
        
        for endpoint in upload_endpoints[:3]:
            chain = ExploitationChain(
                chain_id=str(uuid.uuid4()),
                name="File Upload -> Webshell Execution -> RCE",
                steps=[
                    PivotStep(
                        step_number=1,
                        endpoint=endpoint.get('url', ''),
                        action="Upload PHP webshell with double extension bypass",
                        method="POST",
                        parameters=['file', 'upload'],
                        payload_type="file_upload",
                        current_privilege=PrivilegeLevelEnum.UNAUTHENTICATED,
                        resulting_privilege=PrivilegeLevelEnum.CODE_EXECUTION,
                        success_indicator="File uploaded to accessible path",
                        description="Upload webshell.php.jpg or similar bypass"
                    ),
                    PivotStep(
                        step_number=2,
                        endpoint="/uploads/ or /files/",
                        action="Access uploaded webshell",
                        method="GET",
                        payload_type="rce",
                        current_privilege=PrivilegeLevelEnum.UNAUTHENTICATED,
                        resulting_privilege=PrivilegeLevelEnum.CODE_EXECUTION,
                        success_indicator="Webshell responsive to commands",
                        description="Execute system commands via webshell"
                    ),
                ],
                impact="Remote Code Execution - Full system compromise",
                confidence=0.9,
                likelihood=0.8,
                complexity="low",
                technologies=['PHP']
            )
            chains.append(chain)
        
        return chains

    def _build_auth_chains(self, endpoints: List[Dict[str, Any]], 
                          vulnerabilities: List[Dict[str, Any]]) -> List[ExploitationChain]:
        """Build authentication bypass chains."""
        chains = []
        
        auth_vulns = [
            v for v in vulnerabilities 
            if v.get('type') in ['auth_bypass', 'broken_auth', 'credential_exposure']
        ]
        
        for vuln in auth_vulns[:2]:
            chain = ExploitationChain(
                chain_id=str(uuid.uuid4()),
                name="Authentication Bypass -> Admin Access -> Privilege Escalation",
                steps=[
                    PivotStep(
                        step_number=1,
                        endpoint=vuln.get('url', ''),
                        action="Bypass authentication mechanism",
                        method="POST",
                        payload_type=vuln.get('type', 'auth_bypass'),
                        current_privilege=PrivilegeLevelEnum.UNAUTHENTICATED,
                        resulting_privilege=PrivilegeLevelEnum.AUTHENTICATED,
                        success_indicator="Access granted",
                        description="Exploit authentication bypass vulnerability"
                    ),
                    PivotStep(
                        step_number=2,
                        endpoint="/admin/ or admin dashboard",
                        action="Access admin panel with bypassed authentication",
                        method="GET",
                        current_privilege=PrivilegeLevelEnum.AUTHENTICATED,
                        resulting_privilege=PrivilegeLevelEnum.ADMIN,
                        success_indicator="Admin panel accessible",
                        description="Enumerate admin functionality"
                    ),
                ],
                impact="Administrative access and potential RCE",
                confidence=0.75,
                likelihood=0.6,
                complexity="medium"
            )
            chains.append(chain)
        
        return chains

    def _build_idor_chains(self, endpoints: List[Dict[str, Any]], 
                          vulnerabilities: List[Dict[str, Any]]) -> List[ExploitationChain]:
        """Build IDOR-based chains."""
        chains = []
        
        idor_vulns = [
            v for v in vulnerabilities 
            if v.get('type') in ['idor', 'insecure_direct_object_reference']
        ]
        
        for vuln in idor_vulns[:2]:
            chain = ExploitationChain(
                chain_id=str(uuid.uuid4()),
                name="IDOR -> Admin Account Access -> Configuration Change",
                steps=[
                    PivotStep(
                        step_number=1,
                        endpoint=vuln.get('url', ''),
                        action="Access admin object via IDOR",
                        method="GET",
                        parameters=['id', 'user_id', 'admin_id'],
                        payload_type="idor",
                        current_privilege=PrivilegeLevelEnum.UNAUTHENTICATED,
                        resulting_privilege=PrivilegeLevelEnum.ADMIN,
                        success_indicator="Admin data accessible",
                        description="Enumerate objects to find admin ID and access admin account"
                    ),
                ],
                impact="Admin account compromise",
                confidence=0.8,
                likelihood=0.7,
                complexity="low"
            )
            chains.append(chain)
        
        return chains

    def _build_injection_chains(self, endpoints: List[Dict[str, Any]], 
                               vulnerabilities: List[Dict[str, Any]]) -> List[ExploitationChain]:
        """Build template/code injection chains."""
        chains = []
        
        injection_vulns = [
            v for v in vulnerabilities 
            if v.get('type') in ['template_injection', 'code_injection', 'ssti']
        ]
        
        for vuln in injection_vulns[:2]:
            chain = ExploitationChain(
                chain_id=str(uuid.uuid4()),
                name="Template Injection -> Remote Code Execution",
                steps=[
                    PivotStep(
                        step_number=1,
                        endpoint=vuln.get('url', ''),
                        action="Inject malicious template code",
                        method="POST",
                        parameters=[p.get('name', '') for p in vuln.get('parameters', [])[:1]],
                        payload_type="ssti",
                        current_privilege=PrivilegeLevelEnum.UNAUTHENTICATED,
                        resulting_privilege=PrivilegeLevelEnum.CODE_EXECUTION,
                        success_indicator="Code execution confirmed",
                        description="Use template injection for RCE"
                    ),
                ],
                impact="Remote Code Execution",
                confidence=0.85,
                likelihood=0.75,
                complexity="medium"
            )
            chains.append(chain)
        
        return chains

    def _build_misconfiguration_chains(self, endpoints: List[Dict[str, Any]]) -> List[ExploitationChain]:
        """Build misconfiguration-based chains."""
        chains = []
        
        # Detect debug panels
        debug_endpoints = [
            ep for ep in endpoints 
            if any(x in ep.get('url', '').lower() for x in ['debug', 'dev', 'test', 'admin'])
        ]
        
        for endpoint in debug_endpoints[:2]:
            chain = ExploitationChain(
                chain_id=str(uuid.uuid4()),
                name="Debug Panel Access -> Configuration Manipulation -> RCE",
                steps=[
                    PivotStep(
                        step_number=1,
                        endpoint=endpoint.get('url', ''),
                        action="Access exposed debug/admin panel",
                        method="GET",
                        current_privilege=PrivilegeLevelEnum.UNAUTHENTICATED,
                        resulting_privilege=PrivilegeLevelEnum.ADMIN,
                        success_indicator="Panel accessible",
                        description="Find and access misconfigured debug panel"
                    ),
                ],
                impact="Administrative access via misconfiguration",
                confidence=0.7,
                likelihood=0.5,
                complexity="low"
            )
            chains.append(chain)
        
        return chains

    def export_chains(self, chains: List[ExploitationChain]) -> List[Dict[str, Any]]:
        """Export chains to JSON-serializable format."""
        return [chain.to_dict() for chain in chains]


def analyze_privilege_escalation(endpoints: List[Dict[str, Any]], 
                                 vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Standalone function to analyze privilege escalation opportunities.
    Integrates with attack graph pipeline.
    """
    engine = PrivilegePivotEngine()
    chains = engine.analyze_privileges(endpoints, vulnerabilities)
    return engine.export_chains(chains)
