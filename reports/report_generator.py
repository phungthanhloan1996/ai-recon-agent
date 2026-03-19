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
        report_data = {
            "assessment_info": {
                "target": self.state.get("target", ""),
                "start_time": self.state.get("start_time", ""),
                "end_time": datetime.now().isoformat(),
                "duration": self._calculate_duration(),
                "agent_version": "1.0.0"
            },
            "summary": self._build_summary(),
            "findings": {
                "subdomains": self.state.get("subdomains", []),
                "live_hosts": self.state.get("live_hosts", []),
                "endpoints": self.state.get("prioritized_endpoints", []),
                "vulnerabilities": self.state.get("confirmed_vulnerabilities", []),
                "exploit_chains": self._format_chains_for_json(),
                "external_findings": self.state.get("external_findings", []),
            },
            "attack_surface": {
                "total_endpoints": len(self.state.get("endpoints", [])),
                "prioritized_endpoints": len(self.state.get("prioritized_endpoints", [])),
                "vulnerable_endpoints": len(self.state.get("confirmed_vulnerabilities", [])),
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

        # Critical Findings
        lines.extend(self._build_findings_section())
        lines.append("")

        # Manual validation queue
        lines.extend(self._build_manual_validation_section())
        lines.append("")

        # Exploit Chains
        lines.extend(self._build_chains_section())
        lines.append("")

        # Manual playbook
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

        return {
            "subdomains_discovered": len(self.state.get("subdomains", [])),
            "live_hosts_found": len(self.state.get("live_hosts", [])),
            "endpoints_analyzed": len(endpoints),
            "vulnerabilities_found": len(vulns),
            "exploit_chains_planned": len(chains),
            "critical_vulns": len([v for v in vulns if v.get("severity") == "CRITICAL"]),
            "high_vulns": len([v for v in vulns if v.get("severity") == "HIGH"]),
            "successful_exploits": len([r for r in self.state.get("exploit_results", []) if r.get("success")])
        }

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
                f"- **Confidence:** {vuln.get('confidence', 0):.2f}",
                f"- **Manual Validation Required:** {manual_flag}",
                ""
            ])

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
        if pending_critical:
            return "CRITICAL (PENDING MANUAL VALIDATION)"

        if critical > 0 or chains > 3:
            return "CRITICAL"
        elif high > 2 or chains > 1:
            return "HIGH"
        elif high > 0 or chains > 0:
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
