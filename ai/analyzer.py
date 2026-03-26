"""
ai/analyzer.py - AI Report Generator
Tổng hợp toàn bộ scan results và tạo báo cáo cuối
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional

from core.state_manager import StateManager

logger = logging.getLogger("recon.analyzer")


class AIAnalyzer:
    """
    Generates the final AI-powered security report.
    Uses Claude API if available, falls back to structured static report.
    """

    def __init__(self, state: StateManager, output_dir: str, ai_client=None):
        self.state = state
        self.output_dir = output_dir
        self.ai_client = ai_client
        self.report_file = os.path.join(output_dir, "ai_final_report.txt")
        self.cache_file = os.path.join(output_dir, "ai_cache.json")

    def generate_report(self) -> str:
        """Generate the final security report"""
        logger.info(f"\n{'='*60}")
        logger.info("  FINAL REPORT GENERATION")
        logger.info(f"{'='*60}")

        self.state.set_phase("reporting")

        # Gather all data
        report_data = self._collect_report_data()

        # Try AI-powered report if client available
        report_text = None
        if self.ai_client:
            try:
                report_text = self._generate_ai_report(report_data)
            except Exception as e:
                logger.warning(f"[REPORT] AI generation failed: {e}, using static report")

        # Fallback to structured static report
        if not report_text:
            report_text = self._generate_static_report(report_data)

        # Save report
        with open(self.report_file, "w") as f:
            f.write(report_text)

        logger.info(f"[REPORT] Report saved → {self.report_file}")
        print(f"\n{'='*60}")
        print(f"  FINAL REPORT: {self.report_file}")
        print(f"{'='*60}\n")

        return report_text

    def build_attack_context(self) -> Dict:
        """
        Build comprehensive attack context for chain planning and AI reasoning.
        
        Returns:
            Dictionary with structured intelligence for chain generation
        """
        s = self.state
        
        # Collect endpoints with enhanced context
        endpoints = s.get("prioritized_endpoints", []) or []
        technologies = s.get("technologies", {})
        
        # Process endpoints to include comprehensive context
        endpoint_context = []
        for ep in endpoints[:30]:  # Top 30 endpoints
            ep_data = dict(ep) if isinstance(ep, dict) else {"url": str(ep)}
            
            # Enrich with technologies
            technologies_list = []
            if technologies and isinstance(technologies, dict):
                for url, techs in technologies.items():
                    if url in ep_data.get('url', '') or ep_data.get('url', '') in url:
                        technologies_list = techs if isinstance(techs, list) else [techs]
                        break
            
            ep_data['technologies'] = technologies_list
            
            # Add vulnerability insights
            if 'vulnerability_hints' not in ep_data:
                ep_data['vulnerability_hints'] = []
            
            # Calculate risk score
            ep_data['risk_score'] = self._score_endpoint_risk(ep_data)
            
            endpoint_context.append(ep_data)
        
        # Collect vulnerability hints across system
        all_hints = set()
        discovered_vulns = []
        
        for ep in endpoint_context:
            hints = ep.get('vulnerability_hints', [])
            all_hints.update(hints)
            
            # If specific vulnerabilities found
            vuln_info = {
                'endpoint': ep.get('url'),
                'hints': hints,
                'parameters': ep.get('parameters', []),
                'technologies': ep.get('technologies', [])
            }
            if hints:
                discovered_vulns.append(vuln_info)
        
        # Collect confirmed vulnerabilities
        confirmed_vulns = s.get("confirmed_vulnerabilities", []) or []
        confirmed_vulns.extend(s.get("vulnerabilities", []) or [])
        
        # WordPress-specific context
        wp_context = {
            'detected': s.get("wordpress_detected", False),
            'users': s.get("wp_users", []),
            'plugins': [p for p in (s.get("wp_plugins", []) or []) if p.get('vulnerabilities')],
            'version': s.get("wp_version", "unknown"),
            'themes': s.get("wp_themes", [])
        }
        
        # Build context object for chain planner
        context = {
            'target': s.get("target", ""),
            'endpoints': endpoint_context,
            'parameters': self._extract_all_parameters(endpoint_context),
            'technologies': technologies if isinstance(technologies, list) else list(technologies.keys() if isinstance(technologies, dict) else []),
            'vulnerability_hints': list(all_hints),
            'discovered_vulnerabilities': discovered_vulns,
            'confirmed_vulnerabilities': confirmed_vulns,
            'wordpress': wp_context,
            'misconfigurations': self._detect_misconfigurations(endpoint_context),
            'attack_surface': {
                'file_upload_endpoints': [e for e in endpoint_context if 'file_upload' in e.get('vulnerability_hints', [])],
                'auth_endpoints': [e for e in endpoint_context if 'auth' in e.get('endpoint_type', '')],
                'api_endpoints': [e for e in endpoint_context if 'api' in e.get('endpoint_type', '')],
                'admin_endpoints': [e for e in endpoint_context if 'admin' in e.get('endpoint_type', '')]
            },
            'chain_patterns': self._identify_chain_patterns(endpoint_context, all_hints)
        }
        
        return context

    def _extract_all_parameters(self, endpoint_context: List[Dict]) -> List[Dict]:
        """Extract and deduplicate all parameters from endpoints."""
        all_params = {}
        
        for ep in endpoint_context:
            params = ep.get('parameters', [])
            for param in params:
                param_name = param.get('name', '')
                param_key = param_name.lower()
                
                if param_key not in all_params:
                    all_params[param_key] = {
                        'name': param_name,
                        'sources': [],
                        'types': set(),
                        'endpoints': []
                    }
                
                all_params[param_key]['sources'].append(param.get('source', 'unknown'))
                all_params[param_key]['types'].add(param.get('type', 'unknown'))
                all_params[param_key]['endpoints'].append(ep.get('url', ''))
        
        # Convert back to list format
        result = []
        for param_info in all_params.values():
            result.append({
                'name': param_info['name'],
                'sources': list(set(param_info['sources'])),
                'types': list(param_info['types']),
                'endpoints_count': len(param_info['endpoints'])
            })
        
        return result

    def _detect_misconfigurations(self, endpoint_context: List[Dict]) -> List[Dict]:
        """Detect common misconfigurations in endpoints."""
        misconfigs = []
        
        for ep in endpoint_context:
            url = ep.get('url', '').lower()
            endpoint_type = ep.get('endpoint_type', '')
            
            # Debug endpoints exposed
            if 'debug' in url or 'test' in url or 'dev' in url:
                misconfigs.append({
                    'type': 'debug_endpoint_exposed',
                    'endpoint': url,
                    'severity': 'MEDIUM',
                    'description': 'Debug/test endpoint accessible in production'
                })
            
            # Backup files
            if url.endswith(('.bak', '.backup', '.sql', '.tar', '.zip')):
                misconfigs.append({
                    'type': 'backup_file_exposed',
                    'endpoint': url,
                    'severity': 'HIGH',
                    'description': 'Backup file accessible'
                })
            
            # Admin panels without authentication indicator
            if 'admin' in endpoint_type and ep.get('status_code', 0) != 401:
                misconfigs.append({
                    'type': 'admin_panel_unauthenticated',
                    'endpoint': url,
                    'severity': 'CRITICAL',
                    'description': 'Admin panel accessible without authentication'
                })
            
            # Directory listing
            if endpoint_type == 'html' and any(x in url for x in ['/', '/files', '/downloads']):
                misconfigs.append({
                    'type': 'directory_listing_possible',
                    'endpoint': url,
                    'severity': 'MEDIUM',
                    'description': 'Directory listing may be enabled'
                })
        
        return misconfigs

    def _identify_chain_patterns(self, endpoint_context: List[Dict], all_hints: set) -> List[Dict]:
        """Identify attack chain patterns from endpoints and hints."""
        patterns = []
        
        # Pattern: file upload + execution
        if 'file_upload' in all_hints:
            upload_eps = [e for e in endpoint_context if 'file_upload' in e.get('vulnerability_hints', [])]
            if upload_eps:
                # Check if any endpoints can execute files
                exec_possible = any('rce' in e.get('vulnerability_hints', []) for e in endpoint_context)
                if exec_possible or 'rce_via_upload' in all_hints:
                    patterns.append({
                        'name': 'file_upload_to_rce',
                        'description': 'File upload leading to RCE',
                        'upload_endpoint': upload_eps[0].get('url'),
                        'probability': 0.8
                    })
        
        # Pattern: auth bypass + escalation
        if 'auth_bypass' in all_hints and 'privilege_escalation' in all_hints:
            patterns.append({
                'name': 'auth_bypass_to_privilege_escalation',
                'description': 'Authentication bypass leading to privilege escalation',
                'probability': 0.7
            })
        
        # Pattern: SSRF + internal access
        if 'ssrf' in all_hints:
            patterns.append({
                'name': 'ssrf_chain',
                'description': 'SSRF to internal resource access',
                'probability': 0.6
            })
        
        # Pattern: information disclosure + exploitation
        if 'user_enumeration' in all_hints or 'information_disclosure' in all_hints:
            if 'auth_bypass' in all_hints:
                patterns.append({
                    'name': 'enum_then_attack',
                    'description': 'Enumerate users/info then attack specific target',
                    'probability': 0.7
                })
        
        return patterns

    def _score_endpoint_risk(self, endpoint: Dict) -> float:
        """Score endpoint risk based on characteristics."""
        score = 0.0
        
        # Base score from endpoint type
        ep_type = endpoint.get('endpoint_type', '').lower()
        if ep_type == 'upload':
            score += 0.3
        elif ep_type == 'admin':
            score += 0.25
        elif ep_type == 'auth':
            score += 0.2
        elif ep_type == 'api':
            score += 0.15
        
        # Vulnerability hints
        hints = endpoint.get('vulnerability_hints', [])
        score += len(hints) * 0.05
        
        # Parameters
        params = endpoint.get('parameters', [])
        score += len([p for p in params if p.get('type') not in ['hidden', 'submit']]) * 0.02
        
        # Status code risk
        status = endpoint.get('status_code', 0)
        if status == 200:
            score += 0.1
        elif 300 <= status < 400:
            score += 0.05
        elif status >= 400:
            score -= 0.1
        
        return min(score, 1.0)

    def _collect_report_data(self) -> Dict:
        """Collect all scan data for report"""
        s = self.state

        # STRICT FILTERING: Only include validated vulnerabilities
        all_vulns = s.get("vulnerabilities", [])
        vulns = self._filter_valid_vulnerabilities(all_vulns)
        
        logger.info(f"[ANALYZER] Filtering: {len(all_vulns)} total → {len(vulns)} validated vulns")
        
        exploit_results = s.get("exploit_results", [])
        wp_plugins = s.get("wp_plugins", [])

        # Count severities (ONLY for valid vulns)
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            sev = v.get("severity", "INFO").upper()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Risk level
        risk_level = "LOW"
        if severity_counts["CRITICAL"] > 0 or any(r.get("success") for r in exploit_results):
            risk_level = "CRITICAL"
        elif severity_counts["HIGH"] > 0:
            risk_level = "HIGH"
        elif severity_counts["MEDIUM"] > 0:
            risk_level = "MEDIUM"

        # Successful exploits
        successful = [r for r in exploit_results if r.get("success")]

        # Vuln plugins
        vuln_plugins = [p for p in wp_plugins if p.get("vulnerabilities")]

        return {
            "target": s.get("target"),
            "scan_id": s.get("scan_id"),
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "risk_level": risk_level,
            "summary": s.summary(),
            "severity_counts": severity_counts,
            "subdomains": s.get("subdomains", []),
            "live_hosts": s.get("live_hosts", []),
            "technologies": s.get("technologies", {}),
            "top_endpoints": s.get("prioritized_endpoints", [])[:20],
            "vulnerabilities": vulns,
            "wordpress": {
                "detected": s.get("wordpress_detected", False),
                "users": s.get("wp_users", []),
                "plugins": wp_plugins,
                "vuln_plugins": vuln_plugins,
                "themes": s.get("wp_themes", []),
            },
            "exploit_results": exploit_results,
            "successful_exploits": successful,
        }

    def _filter_valid_vulnerabilities(self, vulns: List[Dict]) -> List[Dict]:
        """
        STRICT FILTERING: Remove false positives AND duplicates.
        Only keep vulnerabilities with:
        - Confidence >= 0.5
        - Evidence from actual code execution or strong indicators
        - Not from static files
        - NOT duplicates
        """
        valid = []
        seen = set()  # Track unique vulns (type + url + payload)
        
        for v in vulns:
            # Rule 1: Must have confidence >= 0.5
            confidence = v.get('confidence', 0)
            if confidence < 0.5:
                logger.debug(f"[FILTER] Rejecting {v.get('type')} (confidence {confidence:.2f} < 0.5)")
                continue
            
            # Rule 2: Must NOT be from static files
            url = v.get('url', '').lower()
            if any(ext in url for ext in ['.css', '.js', '.png', '.jpg', '.svg', '.woff']):
                logger.debug(f"[FILTER] Rejecting {v.get('type')} @ {url} (static file)")
                continue

            # Rule 2.5: Skip URLs with malformed structure
            malformed_patterns = ['&lt;', '&gt;', '<script', '>script', 'nameresolutionerror']
            if any(pattern in url for pattern in malformed_patterns):
                logger.debug(f"[FILTER] Rejecting {v.get('type')} @ {url[:80]} (malformed URL)")
                continue
            
            # Rule 3: Must have evidence
            evidence = v.get('evidence', []) or v.get('indicators', [])
            if not evidence:
                logger.debug(f"[FILTER] Rejecting {v.get('type')} (no evidence)")
                continue
            
            # Rule 4: Must be valid endpoint
            endpoint = v.get('url', '') or v.get('endpoint', '')
            if not endpoint or endpoint == 'unknown':
                logger.debug(f"[FILTER] Rejecting {v.get('type')} (invalid endpoint)")
                continue
            
            # RULE 5: DEDUPLICATION - Skip exact duplicates
            vuln_key = (
                v.get('type'),
                endpoint,
                v.get('payload', '')[:50]  # First 50 chars of payload
            )
            
            if vuln_key in seen:
                logger.debug(f"[FILTER] Skipping duplicate: {v.get('type')} @ {endpoint}")
                continue
            
            seen.add(vuln_key)
            valid.append(v)
        
        return valid

    def _generate_static_report(self, data: Dict) -> str:
        """Generate a comprehensive static report"""
        lines = []
        target = data["target"]
        risk = data["risk_level"]
        scan_date = data["scan_date"]
        summary = data["summary"]
        sev = data["severity_counts"]
        successful = data["successful_exploits"]

        # Header
        lines.extend([
            "=" * 80,
            "                    AI RECON AGENT - SECURITY ASSESSMENT REPORT",
            "=" * 80,
            f"  Target     : {target}",
            f"  Scan Date  : {scan_date}",
            f"  Scan ID    : {data['scan_id']}",
            f"  Risk Level : {'🔴 ' if risk == 'CRITICAL' else '🟠 ' if risk == 'HIGH' else '🟡 '}{risk}",
            "=" * 80,
            "",
        ])

        # Executive Summary
        lines.extend([
            "EXECUTIVE SUMMARY",
            "-" * 40,
            f"This automated security assessment of {target} identified the following:",
            "",
            f"  • {summary['subdomains']} subdomains discovered",
            f"  • {summary['live_hosts']} live/active hosts found",
            f"  • {summary['urls']} URLs crawled",
            f"  • {summary['endpoints']} high-risk endpoints identified",
            f"  • {summary['vulnerabilities']} vulnerabilities detected",
            f"  • {len(successful)} successful exploit attempts",
            "",
        ])

        # Risk Summary
        lines.extend([
            "VULNERABILITY SEVERITY BREAKDOWN",
            "-" * 40,
            f"  🔴 CRITICAL : {sev['CRITICAL']}",
            f"  🟠 HIGH     : {sev['HIGH']}",
            f"  🟡 MEDIUM   : {sev['MEDIUM']}",
            f"  🟢 LOW      : {sev['LOW']}",
            f"  ⚪ INFO      : {sev['INFO']}",
            "  ─────────────",
            f"  TOTAL      : {sum(sev.values())}",
            "",
        ])

        # Successful Exploits
        if successful:
            lines.extend([
                "⚠️  CONFIRMED EXPLOITS",
                "-" * 40,
            ])
            for exploit in successful:
                lines.extend([
                    f"  TYPE     : {exploit.get('exploit_type', 'unknown').upper()}",
                    f"  URL      : {exploit.get('url', 'N/A')}",
                    f"  SEVERITY : {exploit.get('severity', 'HIGH')}",
                    f"  PAYLOAD  : {exploit.get('payload', 'N/A')[:80]}",
                    "",
                ])

        # Infrastructure
        lines.extend([
            "INFRASTRUCTURE DISCOVERED",
            "-" * 40,
        ])

        lines.append(f"  Subdomains ({summary['subdomains']} total):")
        for sub in data["subdomains"][:20]:
            lines.append(f"    • {sub}")
        if len(data["subdomains"]) > 20:
            lines.append(f"    ... and {len(data['subdomains']) - 20} more")

        lines.append("")
        lines.append(f"  Live Hosts ({summary['live_hosts']} total):")
        for host in data["live_hosts"][:15]:
            tech_str = ", ".join(host.get("tech", [])[:3]) if host.get("tech") else "unknown"
            lines.append(f"    • [{host.get('status', '?')}] {host.get('url', '')} | {tech_str}")
        lines.append("")

        # Technologies
        if data["technologies"]:
            lines.extend([
                "TECHNOLOGIES DETECTED",
                "-" * 40,
            ])
            for domain, techs in list(data["technologies"].items())[:10]:
                lines.append(f"  {domain}: {', '.join(techs[:5])}")
            lines.append("")

        # Top Risky Endpoints
        if data["top_endpoints"]:
            lines.extend([
                "HIGH-RISK ENDPOINTS",
                "-" * 40,
            ])
            for ep in data["top_endpoints"][:15]:
                risk_icon = "🔴" if ep.get("score", 0) >= 9 else "🟠" if ep.get("score", 0) >= 7 else "🟡"
                lines.append(f"  {risk_icon} [{ep.get('risk_level', '?'):8s}] Score:{ep.get('score', 0)}/10  {ep.get('url', '')}")
            lines.append("")

        # Vulnerabilities Detail
        if data["vulnerabilities"]:
            lines.extend([
                "VULNERABILITIES DETAIL",
                "-" * 40,
            ])
            critical_high = [v for v in data["vulnerabilities"]
                             if v.get("severity", "").upper() in ("CRITICAL", "HIGH")]
            for v in critical_high[:20]:
                lines.extend([
                    f"  [{v.get('severity', 'UNK'):8s}] {v.get('name', 'Unknown')}",
                    f"             URL      : {v.get('url', 'N/A')}",
                    f"             Tool     : {v.get('tool', 'N/A')}",
                    f"             Template : {v.get('template', 'N/A')}",
                ])
                if v.get("cve"):
                    lines.append(f"             CVE      : {', '.join(v['cve'])}")
                if v.get("description"):
                    lines.append(f"             Info     : {v['description'][:100]}")
                lines.append("")

        # WordPress Section
        wp = data["wordpress"]
        if wp["detected"]:
            lines.extend([
                "WORDPRESS ANALYSIS",
                "-" * 40,
                "  WordPress Detected: YES",
                f"  Users Found: {', '.join(wp['users'][:10]) or 'None'}",
                f"  Plugins: {len(wp['plugins'])} total, {len(wp['vuln_plugins'])} vulnerable",
                f"  Themes: {len(wp['themes'])} total",
                "",
            ])

            if wp["vuln_plugins"]:
                lines.append("  ⚠️  Vulnerable Plugins:")
                for plugin in wp["vuln_plugins"]:
                    vuln_count = len(plugin.get("vulnerabilities", []))
                    lines.append(f"    • {plugin['name']} v{plugin.get('version', '?')} — {vuln_count} CVE(s)")
                    for vuln in plugin.get("vulnerabilities", [])[:3]:
                        lines.append(f"      - {vuln.get('title', 'Unknown')}")
                        if vuln.get("cve"):
                            lines.append(f"        CVE: {', '.join(vuln['cve'])}")
                lines.append("")

        # Recommendations
        lines.extend([
            "RECOMMENDATIONS",
            "-" * 40,
        ])

        recs = self._generate_recommendations(data)
        for i, rec in enumerate(recs, 1):
            lines.append(f"  {i}. {rec}")

        lines.extend([
            "",
            "=" * 80,
            "  DISCLAIMER: This report was generated by an automated security scanner.",
            "  All findings should be verified by a qualified security professional.",
            "  Unauthorized testing is illegal. Only use on systems you own or have",
            "  explicit written permission to test.",
            "=" * 80,
            f"  Report generated: {scan_date}",
            "=" * 80,
        ])

        return "\n".join(lines)

    def _generate_recommendations(self, data: Dict) -> List[str]:
        """Generate security recommendations based on findings"""
        recs = []
        vulns = data["vulnerabilities"]
        wp = data["wordpress"]
        successful = data["successful_exploits"]

        # Critical findings first
        if successful:
            recs.append("IMMEDIATE ACTION REQUIRED: Confirmed exploits detected. Take systems offline for emergency patching.")

        if any(v.get("severity") == "CRITICAL" for v in vulns):
            recs.append("Apply emergency patches for all CRITICAL vulnerabilities immediately.")

        # SQLi
        if any("sql" in v.get("name", "").lower() for v in vulns):
            recs.append("Fix SQL injection vulnerabilities: use parameterized queries / prepared statements.")

        # XSS
        if any("xss" in v.get("name", "").lower() or "cross-site" in v.get("name", "").lower() for v in vulns):
            recs.append("Implement Content Security Policy (CSP) and proper output encoding to prevent XSS.")

        # WordPress
        if wp["detected"]:
            if wp["users"]:
                recs.append("Disable WordPress user enumeration via REST API and hide author slugs.")
            if wp["vuln_plugins"]:
                recs.append(f"Update or remove {len(wp['vuln_plugins'])} vulnerable WordPress plugin(s) immediately.")
            recs.append("Consider adding a WAF (ModSecurity, Cloudflare) in front of WordPress.")
            recs.append("Disable XML-RPC if not needed (/xmlrpc.php) to prevent bruteforce attacks.")
            recs.append("Enable two-factor authentication on all WordPress admin accounts.")

        # File upload
        if any(r.get("exploit_type") == "file_upload" for r in data["exploit_results"]):
            recs.append("Fix file upload vulnerabilities: validate file type by content (not extension), store outside webroot.")

        # LFI
        if any(r.get("exploit_type") == "lfi" for r in data["exploit_results"]):
            recs.append("Fix LFI vulnerabilities: validate and sanitize all file path parameters, use allowlists.")

        # General
        recs.extend([
            "Implement a Web Application Firewall (WAF) to filter malicious requests.",
            "Enable security headers: CSP, X-Frame-Options, HSTS, X-Content-Type-Options.",
            "Regularly update all server software, CMS, plugins, and dependencies.",
            "Implement rate limiting on all authentication endpoints.",
            "Set up centralized logging and alerting for suspicious activity.",
            "Conduct regular penetration testing and vulnerability assessments.",
        ])

        return recs[:15]  # Top 15 recommendations

    def _generate_ai_report(self, data: Dict) -> Optional[str]:
        """Generate AI-enhanced report using Claude API"""
        logger.info("[REPORT] Generating AI-enhanced report...")

        # Build a comprehensive prompt
        prompt = f"""You are a professional penetration tester writing a security assessment report.

Target: {data['target']}
Scan Date: {data['scan_date']}

=== FINDINGS ===

Infrastructure:
- {data['summary']['subdomains']} subdomains discovered
- {data['summary']['live_hosts']} live hosts
- {data['summary']['urls']} URLs crawled

Vulnerability Summary:
- CRITICAL: {data['severity_counts']['CRITICAL']}
- HIGH: {data['severity_counts']['HIGH']}  
- MEDIUM: {data['severity_counts']['MEDIUM']}
- LOW: {data['severity_counts']['LOW']}

Key Vulnerabilities Found:
{json.dumps(data['vulnerabilities'][:10], indent=2)}

Successful Exploits:
{json.dumps(data['successful_exploits'], indent=2)}

WordPress Data:
{json.dumps(data['wordpress'], indent=2)}

Top Risky Endpoints:
{json.dumps(data['top_endpoints'][:10], indent=2)}

=== TASK ===
Write a professional, detailed security assessment report with:
1. Executive Summary (for management, non-technical)
2. Technical Findings (detailed for security team)
3. Risk Analysis
4. Exploitation Evidence (if any successful exploits)
5. Prioritized Remediation Recommendations
6. Conclusion

Format the report clearly with sections and subsections."""

        # Try to use AI client if available (injected from agent.py)
        if hasattr(self.ai_client, "generate"):
            response = self.ai_client.generate(prompt)
            if response:
                return response

        return None

    def save_ai_cache(self, data: Dict):
        """Save intermediate AI analysis cache"""
        try:
            with open(self.cache_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.debug(f"[REPORT] Cache save failed: {e}")
