"""
ai/gap_analyzer.py - Iterative Exploit Chain Gap Analyzer

Implements a think→act→check loop:
  1. Look at chains + what we already have
  2. Ask Groq: "given what we know NOW, what single condition is most impactful to probe next?"
  3. Dispatch to the correct existing module OR run a shell probe command directly
  4. If found → update state, remove condition from chain.preconditions_missing
  5. Check if any chain is now fully executable → if yes, stop and return it
  6. If not → repeat with updated context (Groq now knows what was found)
  7. Stop when: chain executable, no progress, or max iterations reached

Two probe modes:
  - module: call existing Python module (default_creds, wp_scan, etc.)
  - shell_probe: run curl/httpx directly to verify an endpoint exists
"""

import json
import logging
import re
import shlex
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger("recon.gap_analyzer")

# ─── System prompt for single-step reasoning ─────────────────────────────────
_NEXT_STEP_SYSTEM = """You are an offensive security strategist building an exploit chain piece by piece.

Each round you are told:
- The target's technology stack (CMS, language, server, detected plugins/versions)
- What vulnerabilities and endpoints are already confirmed
- What preconditions are already fulfilled (pieces already found)
- What is still missing to make at least one chain executable
- The specific chain goal (e.g. "upload webshell → RCE via WordPress plugin")

Your job: pick the SINGLE most impactful missing condition to probe for next.
Use the technology context to make targeted decisions:
  - If WordPress + plugin detected → wp_scan to get version, then look up known upload bypass
  - If auth_surface missing → fill auth first via default_creds (other modules need auth context)
  - If upload_surface missing AND auth just fulfilled → probe upload endpoint WITH credentials
  - If version_info present → use it to determine which specific exploit path is viable
  - If nuclei already flagged a template → check what that template needs to be fully exploited

Available modules (use exactly these names):
  shell_probe     — fastest: run curl/httpx directly to verify an endpoint exists (use when you know the exact path)
  default_creds   — test default/weak credentials on login panels
  dirbust         — directory/file bruteforce (gobuster/ffuf)
  wp_scan         — WordPress version, plugins, themes, known CVEs
  api_scan        — REST/GraphQL API discovery and testing
  swagger         — OpenAPI/Swagger spec discovery and endpoint extraction
  crawler         — targeted crawl to find new endpoints
  parameter_miner — fuzz hidden parameters on known endpoints

Use shell_probe when:
  - You know the exact path to check (e.g. '/wp-login.php', '/wp-json/cf7/v1/')
  - You want to quickly verify if an endpoint returns 200/302/401 (exists)
  - You want to check a JSON response field (e.g. WordPress version from /wp-json/)

Return ONLY valid JSON (single object, no array):
{
  "condition": "exact condition string from the missing list",
  "module": "module_name from the list above",
  "rationale": "one sentence — why this condition, why now, why this module given the specific tech stack",
  "target_scope": "specific path to probe (e.g. '/wp-login.php', '/wp-json/cf7/v1/contact-forms') for shell_probe; keyword for others"
}"""

# ─── Map abstract signal names → human-readable descriptions ──────────────────
_SIGNAL_DESCRIPTIONS = {
    "auth_surface":         "login/authentication endpoint available",
    "upload_surface":       "file upload endpoint or form available",
    "state_change_surface": "endpoint that modifies server state (POST/PUT/DELETE)",
    "api_surface":          "REST or GraphQL API accessible",
    "enum_surface":         "user/resource enumeration possible (IDs, usernames)",
    "redirect_surface":     "open redirect or URL parameter present",
    "file_param_surface":   "file path or include parameter (potential LFI)",
    "admin_surface":        "admin panel or privileged endpoint accessible",
}


# ─── Condition → default module (used when Groq unavailable) ─────────────────
_CONDITION_MODULE_MAP = {
    "authenticated_session": "default_creds",
    "authentication_required": "default_creds",
    "login_required": "default_creds",
    "admin_access": "default_creds",
    "valid_credentials": "default_creds",
    "file_upload_available": "swagger",
    "upload_endpoint": "swagger",
    "upload_capability": "crawler",
    "version_info": "wp_scan",
    "plugin_version": "wp_scan",
    "wordpress_version": "wp_scan",
    "xmlrpc_enabled": "wp_scan",
    "xmlrpc_available": "wp_scan",
    "api_endpoint": "api_scan",
    "api_access": "api_scan",
    "rest_api": "api_scan",
    "graphql_endpoint": "api_scan",
    "swagger_available": "swagger",
    "openapi_spec": "swagger",
    "admin_panel": "dirbust",
    "admin_accessible": "dirbust",
    "hidden_path": "dirbust",
    "backup_file": "dirbust",
    "config_exposed": "dirbust",
    "parameter_available": "parameter_miner",
    "injectable_param": "parameter_miner",
    "endpoint_discovery": "crawler",
}

# Dependency order: fill these first because other probes benefit from them
_FILL_PRIORITY = [
    "authenticated_session", "authentication_required", "login_required",
    "admin_access", "valid_credentials",
    "version_info", "plugin_version", "wordpress_version",
    "xmlrpc_enabled", "xmlrpc_available",
    "api_endpoint", "rest_api", "graphql_endpoint",
    "swagger_available", "openapi_spec",
    "file_upload_available", "upload_endpoint", "upload_capability",
    "admin_panel", "admin_accessible", "hidden_path",
    "parameter_available", "injectable_param",
    "endpoint_discovery",
]


class GapAnalyzer:
    """
    Iterative reasoning loop: think what's missing → act (module) → check chain
    → think again with updated context → repeat.
    """

    def __init__(
        self,
        state,
        http_client=None,
        groq_client=None,
        output_dir: str = "/tmp",
    ):
        self.state = state
        self.http_client = http_client
        self.groq_client = groq_client
        self.output_dir = output_dir
        self.target = (state.get("target") if state else "") or ""
        self._base_url = self._resolve_base_url()

    def _resolve_base_url(self) -> str:
        live_hosts = (self.state.get("live_hosts") if self.state else None) or []
        if live_hosts:
            first = live_hosts[0]
            url = (
                (first.get("url") or first.get("host") or "")
                if isinstance(first, dict)
                else str(first)
            )
            return url.rstrip("/")
        t = self.target
        if t and not t.startswith("http"):
            t = f"https://{t}"
        return t.rstrip("/")

    # ─── MAIN LOOP ────────────────────────────────────────────────────────────

    def analyze_loop(
        self,
        chains: List[Dict],
        max_iterations: int = 4,
    ) -> Dict[str, Any]:
        """
        Iterative gap-fill loop.

        After each module run, re-asks Groq with the updated picture:
        "Given I just found X, what is the NEXT most important thing to probe?"

        Returns:
          {
            "executable_chain": dict or None,
            "iterations": int,
            "new_findings": list,
            "fulfilled": list,
          }
        """
        fulfilled: Set[str] = set(
            self.state.get("fulfilled_preconditions") or []
        )
        # Also treat any conditions whose chains are already met
        for chain in chains:
            for cond in (chain.get("preconditions_met") or []):
                fulfilled.add(cond.lower())

        total_new_findings: List[Dict] = []
        tried_conditions: Set[str] = set()  # don't retry the same condition

        logger.info(
            "[GAP] Starting iterative gap loop: %d chains, already fulfilled=%s",
            len(chains),
            list(fulfilled)[:5],
        )

        for iteration in range(max_iterations):
            # ── 1. Compute what's still missing across ALL chains ──────────
            all_missing = self._collect_missing(chains, fulfilled)
            if not all_missing:
                logger.info("[GAP] All conditions fulfilled after %d iterations", iteration)
                break

            # Exclude conditions we already tried with no result
            actionable = [c for c in all_missing if c not in tried_conditions]
            if not actionable:
                logger.info("[GAP] No more actionable conditions — stopping")
                break

            # ── 2. Ask Groq (or heuristic): what to probe NEXT? ───────────
            confirmed = (self.state.get("confirmed_vulnerabilities") or [])
            gap = self._ask_next_step(
                missing=actionable,
                confirmed_vulns=confirmed,
                fulfilled=list(fulfilled),
                iteration=iteration,
            )
            if not gap:
                logger.info("[GAP] No gap selected in iteration %d — stopping", iteration)
                break

            condition = gap.get("condition", "").lower()
            module_name = gap.get("module", "")
            logger.info(
                "[GAP] Iteration %d: probing condition='%s' via module='%s' — %s",
                iteration + 1, condition, module_name, gap.get("rationale", ""),
            )

            tried_conditions.add(condition)

            # ── 3. Dispatch to existing module ────────────────────────────
            module_result = self._dispatch(module_name, gap)

            if module_result.get("condition_met"):
                fulfilled.add(condition)
                findings = module_result.get("findings", [])
                total_new_findings.extend(findings)
                for f in findings:
                    self._update_state(condition, f)

                # Persist concrete produced values so the next iteration's Groq
                # call can reference real data (e.g. cracked credentials, user list)
                produced = module_result.get("produces") or {}
                if not produced and findings:
                    # Auto-extract common produced values from findings
                    produced = self._extract_produced(condition, findings)
                if produced and self.state:
                    existing = self.state.get("step_produced_data") or {}
                    existing.update(produced)
                    self.state.update(step_produced_data=existing)

                logger.info(
                    "[GAP] Condition '%s' FILLED — %d findings, produced=%s, total fulfilled=%d",
                    condition, len(findings), list(produced.keys()), len(fulfilled),
                )

                # ── 4. Update preconditions_missing on all chains ─────────
                for chain in chains:
                    chain["preconditions_missing"] = [
                        m for m in (chain.get("preconditions_missing") or [])
                        if m.lower() not in fulfilled
                    ]

                # ── 5. Check if any chain is now executable ───────────────
                for chain in chains:
                    if not chain.get("preconditions_missing"):
                        logger.info(
                            "[GAP] Chain '%s' is now executable after %d iterations",
                            chain.get("name"), iteration + 1,
                        )
                        return {
                            "executable_chain": chain,
                            "iterations": iteration + 1,
                            "new_findings": total_new_findings,
                            "fulfilled": list(fulfilled),
                        }
            else:
                logger.info(
                    "[GAP] Condition '%s' could not be filled via %s",
                    condition, module_name,
                )

        return {
            "executable_chain": None,
            "iterations": min(max_iterations, len(tried_conditions) + 1),
            "new_findings": total_new_findings,
            "fulfilled": list(fulfilled),
        }

    # ─── CONDITION COLLECTION ─────────────────────────────────────────────────

    def _collect_missing(
        self, chains: List[Dict], fulfilled: Set[str]
    ) -> List[str]:
        """Unique missing conditions across all chains, not yet fulfilled."""
        seen: Set[str] = set()
        ordered: List[str] = []
        for chain in chains:
            for cond in (chain.get("preconditions_missing") or []):
                key = cond.lower()
                if key not in seen and key not in fulfilled:
                    seen.add(key)
                    ordered.append(key)
        # Sort by known priority order (auth before upload, etc.)
        def _prio(c):
            try:
                return _FILL_PRIORITY.index(c)
            except ValueError:
                return len(_FILL_PRIORITY)
        return sorted(ordered, key=_prio)

    # ─── GROQ NEXT-STEP REASONING ─────────────────────────────────────────────

    def _ask_next_step(
        self,
        missing: List[str],
        confirmed_vulns: List[Dict],
        fulfilled: List[str],
        iteration: int,
    ) -> Optional[Dict]:
        """Ask Groq: given current context, what's the single best next probe?"""
        if self.groq_client:
            try:
                return self._groq_next_step(missing, confirmed_vulns, fulfilled, iteration)
            except Exception as e:
                logger.warning("[GAP] Groq call failed: %s — using heuristic", e)
        return self._heuristic_next_step(missing)

    def _groq_next_step(
        self,
        missing: List[str],
        confirmed_vulns: List[Dict],
        fulfilled: List[str],
        iteration: int,
    ) -> Optional[Dict]:
        # ── Enrich confirmed vulns with evidence details ──────────────────────
        vuln_summary = [
            {
                "type": v.get("type") or v.get("vuln_type", "?"),
                "url": v.get("url") or v.get("endpoint", ""),
                "severity": v.get("severity", "MEDIUM"),
                "evidence": (v.get("evidence") or [])[:3],
                "confidence": v.get("confidence", 0),
            }
            for v in confirmed_vulns[:10]
        ]

        # ── Tech stack from live_hosts fingerprints ───────────────────────────
        tech_stack = []
        if self.state:
            for host in (self.state.get("live_hosts") or [])[:3]:
                if isinstance(host, dict):
                    techs = host.get("technologies") or host.get("tech") or []
                    if techs:
                        tech_stack.extend(techs[:5])
            tech_stack = list(dict.fromkeys(tech_stack))  # dedup

        # ── Plugin/version info from wp_scan ─────────────────────────────────
        detected_plugins = []
        if self.state:
            wp_results = self.state.get("wp_scan_results") or {}
            for _url, info in (wp_results.items() if isinstance(wp_results, dict) else []):
                if not info:
                    continue
                if info.get("version"):
                    detected_plugins.append({"cms": "WordPress", "version": info["version"]})
                for p in (info.get("plugins") or [])[:6]:
                    if isinstance(p, dict):
                        detected_plugins.append({
                            "name": p.get("name") or p.get("slug", "?"),
                            "version": p.get("version", "unknown"),
                            "vulnerabilities": p.get("vulnerabilities") or p.get("vulns") or [],
                        })

        # ── Nuclei/toolkit findings ───────────────────────────────────────────
        nuclei_hits = []
        if self.state:
            for f in (self.state.get("nuclei_findings") or [])[:5]:
                if isinstance(f, dict):
                    nuclei_hits.append({
                        "template": f.get("template_id") or f.get("template", "?"),
                        "severity": f.get("severity", "?"),
                        "url": f.get("url") or f.get("matched_at", ""),
                    })

        # ── Known endpoints (top interesting ones) ────────────────────────────
        known_endpoints = []
        if self.state:
            for ep in (self.state.get("endpoints") or [])[:15]:
                url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
                if any(kw in url.lower() for kw in ("upload", "admin", "api", "login", "wp-", "form", "file")):
                    known_endpoints.append(url)

        # ── Map abstract signal names to readable descriptions ────────────────
        missing_readable = [
            f"{c} ({_SIGNAL_DESCRIPTIONS.get(c, 'probe required')})"
            for c in missing
        ]
        fulfilled_readable = [
            f"{c} ({_SIGNAL_DESCRIPTIONS.get(c, 'confirmed')})"
            for c in fulfilled
        ]

        parts = [
            f"Iteration: {iteration + 1}",
            f"Target: {self.target} ({self._base_url})",
        ]
        if tech_stack:
            parts.append(f"\nTECHNOLOGY STACK: {', '.join(tech_stack)}")
        if detected_plugins:
            parts.append(f"\nDETECTED PLUGINS/CMS:\n{json.dumps(detected_plugins, indent=2)}")
        if nuclei_hits:
            parts.append(f"\nNUCLEI/SCANNER FINDINGS:\n{json.dumps(nuclei_hits, indent=2)}")
        if known_endpoints:
            parts.append(f"\nKNOWN INTERESTING ENDPOINTS:\n{json.dumps(known_endpoints)}")
        if vuln_summary:
            parts.append(f"\nCONFIRMED VULNERABILITIES:\n{json.dumps(vuln_summary, indent=2)}")
        parts.append(f"\nALREADY FULFILLED (pieces found):\n{json.dumps(fulfilled_readable)}")

        # Include actual produced data from fulfilled steps so Groq knows
        # what concrete values are available to pass into the next step
        produced_data: dict = {}
        if self.state:
            produced_data = self.state.get("step_produced_data") or {}
        if produced_data:
            parts.append(
                f"\nDATA PRODUCED BY COMPLETED STEPS (use these as inputs):\n"
                + json.dumps(produced_data, indent=2)
            )

        parts.append(
            f"\nSTILL MISSING (fill one to unlock a chain):\n{json.dumps(missing_readable)}"
        )
        parts.append(
            "\nUsing the technology context and any produced data above, pick the SINGLE "
            "most impactful condition to probe next. Think about which MISSING condition, "
            "when filled, creates the longest connected chain toward RCE using the "
            "already-confirmed vulns. Be specific in target_scope. Return JSON only."
        )

        prompt = "\n".join(parts)
        raw = self.groq_client.generate(prompt, system=_NEXT_STEP_SYSTEM, temperature=0.15)
        return self._parse_single_gap(raw)

    def _parse_single_gap(self, raw: str) -> Optional[Dict]:
        try:
            text = re.sub(r"```(?:json)?", "", raw).strip().rstrip("`").strip()
            m = re.search(r"\{.*\}", text, re.DOTALL)
            if not m:
                return None
            gap = json.loads(m.group(0))
            if "condition" in gap and "module" in gap:
                return gap
        except Exception as e:
            logger.debug("[GAP] parse error: %s", e)
        return None

    def _extract_produced(self, condition: str, findings: List[Dict]) -> Dict:
        """Auto-extract concrete produced values from findings for data-flow passing."""
        produced: Dict = {}
        for f in findings:
            if not isinstance(f, dict):
                continue
            # Credentials
            creds = f.get("credentials") or f.get("credential")
            if creds:
                produced.setdefault("valid_credentials", [])
                produced["valid_credentials"].append(str(creds))
            username = f.get("username") or f.get("user")
            password = f.get("password") or f.get("pass")
            if username and password:
                produced.setdefault("valid_credentials", [])
                produced["valid_credentials"].append(f"{username}:{password}")
            # Usernames
            if "user_enum" in condition or "username" in condition:
                uname = f.get("username") or f.get("user") or f.get("name")
                if uname:
                    produced.setdefault("username_list", [])
                    produced["username_list"].append(str(uname))
            # Session / auth token
            token = f.get("token") or f.get("session") or f.get("cookie")
            if token:
                produced["session_token"] = str(token)
            # URLs / paths produced
            url = f.get("url") or f.get("endpoint") or f.get("path")
            if url:
                produced.setdefault("discovered_urls", [])
                produced["discovered_urls"].append(str(url))
        # Tag with condition name
        if produced:
            produced["_from_condition"] = condition
        return produced

    def _heuristic_next_step(self, missing: List[str]) -> Optional[Dict]:
        """Pick the highest-priority missing condition and map to module."""
        if not missing:
            return None
        condition = missing[0]  # already sorted by _FILL_PRIORITY
        module = self._condition_to_module(condition)
        desc = _SIGNAL_DESCRIPTIONS.get(condition, condition)
        return {
            "condition": condition,
            "module": module,
            "rationale": f"Heuristic: {desc}",
            "target_scope": "full",
        }

    def _condition_to_module(self, condition: str) -> str:
        for key, module in _CONDITION_MODULE_MAP.items():
            if key in condition or condition in key:
                return module
        return "dirbust"

    # ─── MODULE DISPATCHER ────────────────────────────────────────────────────

    def _dispatch(self, module_name: str, gap: Dict) -> Dict:
        table = {
            "shell_probe":     self._run_shell_probe,
            "default_creds":   self._run_default_creds,
            "dirbust":         self._run_dirbust,
            "wp_scan":         self._run_wp_scan,
            "api_scan":        self._run_api_scan,
            "swagger":         self._run_swagger,
            "crawler":         self._run_crawler,
            "parameter_miner": self._run_parameter_miner,
        }
        runner = table.get(module_name, self._run_dirbust)
        try:
            return runner(gap)
        except Exception as e:
            logger.warning("[GAP] Module '%s' raised: %s", module_name, e)
            return {"condition_met": False, "findings": [], "error": str(e)}

    # ── shell_probe ───────────────────────────────────────────────────────────

    def _run_shell_probe(self, gap: Dict) -> Dict:
        """
        Directly verify an endpoint exists using curl/httpx.
        Groq provides target_scope = specific path (e.g. '/wp-login.php').
        We probe it and check: 200/301/302/401/403 = endpoint exists.
        Also extracts JSON fields when the response is JSON (e.g. /wp-json/).
        """
        from core.executor import run_command

        scope = gap.get("target_scope", "")
        condition = gap.get("condition", "unknown")

        # Build the full URL to probe
        if scope and scope not in ("full", "") and not scope.startswith("http"):
            probe_url = f"{self._base_url}{scope if scope.startswith('/') else '/' + scope}"
        elif scope and scope.startswith("http"):
            probe_url = scope
        else:
            probe_url = self._base_url

        logger.info("[GAP:shell_probe] Probing %s for condition '%s'", probe_url, condition)

        # ── curl: get status code + body (truncated) ──────────────────────────
        rc, stdout, stderr = run_command(
            ["curl", "-sk", "-o", "-", "-w", "\n__STATUS__%{http_code}", "--max-time", "10",
             "-L", "--max-redirs", "3", probe_url],
            timeout=20,
        )

        if rc not in (0,):
            logger.debug("[GAP:shell_probe] curl failed rc=%s stderr=%s", rc, stderr[:200])
            return {"condition_met": False, "findings": []}

        # Parse status code from the sentinel we appended
        status_code = 0
        body = stdout
        if "__STATUS__" in stdout:
            parts = stdout.rsplit("__STATUS__", 1)
            body = parts[0]
            try:
                status_code = int(parts[1].strip())
            except ValueError:
                status_code = 0

        # Endpoint exists if HTTP response is meaningful (not 404/5xx)
        endpoint_exists = status_code in (200, 201, 204, 301, 302, 307, 308, 401, 403)

        if not endpoint_exists:
            logger.debug("[GAP:shell_probe] %s → HTTP %s (not accessible)", probe_url, status_code)
            return {"condition_met": False, "findings": []}

        # ── Try to extract useful data from JSON responses ─────────────────────
        extracted = {}
        if body.strip().startswith("{") or body.strip().startswith("["):
            try:
                data = json.loads(body[:8192])
                if isinstance(data, dict):
                    # WordPress /wp-json/ → extract name, description, version hint
                    extracted["wp_name"] = data.get("name", "")
                    extracted["wp_description"] = data.get("description", "")
                    extracted["namespaces"] = data.get("namespaces", [])
                    # WPScan-style /wp-json/wp/v2/users → usernames
                    if isinstance(data.get("data"), list):
                        extracted["items"] = [
                            {"id": u.get("id"), "name": u.get("name"), "slug": u.get("slug")}
                            for u in data["data"][:5]
                            if isinstance(u, dict)
                        ]
                elif isinstance(data, list) and data:
                    extracted["items"] = [
                        {"id": u.get("id"), "name": u.get("name"), "slug": u.get("slug")}
                        for u in data[:5]
                        if isinstance(u, dict)
                    ]
            except Exception:
                pass

        evidence = [f"HTTP {status_code} at {probe_url}"]
        if extracted.get("namespaces"):
            evidence.append(f"API namespaces: {extracted['namespaces'][:5]}")
        if extracted.get("items"):
            evidence.append(f"Items found: {extracted['items']}")

        finding = {
            "type": condition,
            "url": probe_url,
            "severity": "INFO",
            "confidence": 0.85,
            "evidence": evidence,
            "source": "gap_analyzer:shell_probe",
            "http_status": status_code,
            "extracted": extracted,
        }

        logger.info(
            "[GAP:shell_probe] %s → HTTP %s — condition '%s' VERIFIED",
            probe_url, status_code, condition,
        )
        return {"condition_met": True, "findings": [finding]}

    # ── default_creds ─────────────────────────────────────────────────────────

    def _run_default_creds(self, gap: Dict) -> Dict:
        from modules.default_creds_scanner import DefaultCredsScanner
        scanner = DefaultCredsScanner(output_dir=self.output_dir, timeout=20)
        # If Groq identified a specific login path, target it directly
        scope = gap.get("target_scope", "")
        target_url = (
            f"{self._base_url}{scope}" if scope and scope not in ("full", "")
            and not scope.startswith("http") else self._base_url
        )
        raw = scanner.scan(target_url)
        hits = raw.get("successful_logins") or raw.get("credentials_found") or []
        findings = [
            {
                "type": "default_credentials",
                "url": h.get("url", self._base_url),
                "severity": "CRITICAL",
                "confidence": 0.95,
                "evidence": [f"Default creds: {h.get('username')}:{h.get('password')}"],
                "source": "gap_analyzer:default_creds",
            }
            for h in hits
        ]
        return {"condition_met": bool(findings), "findings": findings}

    # ── dirbust ───────────────────────────────────────────────────────────────

    def _run_dirbust(self, gap: Dict) -> Dict:
        from integrations.dirbusting_runner import DirBustingRunner
        runner = DirBustingRunner(output_dir=self.output_dir)
        scope = gap.get("target_scope", "")
        target_url = (
            f"{self._base_url}{scope}" if scope and scope not in ("full", "")
            and not scope.startswith("http") else self._base_url
        )
        raw = runner.run(target_url, timeout=120)
        found = (
            raw.get("admin_panels", [])
            + raw.get("sensitive_files", [])
            + raw.get("interesting", [])
            + raw.get("found_paths", [])
        )
        findings = [
            {
                "type": "hidden_path",
                "url": p if isinstance(p, str) else p.get("url", ""),
                "severity": "MEDIUM",
                "confidence": 0.7,
                "evidence": [f"Found via dirbusting: {p}"],
                "source": "gap_analyzer:dirbust",
            }
            for p in found[:20]
        ]
        return {"condition_met": bool(findings), "findings": findings}

    # ── wp_scan ───────────────────────────────────────────────────────────────

    def _run_wp_scan(self, gap: Dict) -> Dict:
        from modules.wp_scanner import WordPressScannerEngine
        engine = WordPressScannerEngine(state=self.state, output_dir=self.output_dir)
        raw = engine.scan_wordpress_sites([self._base_url])
        findings = []
        for site_url, info in (raw or {}).items():
            if not info:
                continue
            version = info.get("version", "")
            plugins = info.get("plugins", []) or []
            vulns = info.get("vulnerabilities", []) or []
            if version:
                findings.append({
                    "type": "version_info",
                    "url": site_url,
                    "severity": "INFO",
                    "confidence": 0.9,
                    "evidence": [f"WordPress {version}, {len(plugins)} plugins"],
                    "source": "gap_analyzer:wp_scan",
                    "detail": {"version": version, "plugins": plugins},
                })
            for v in vulns:
                findings.append({
                    "type": v.get("type", "wordpress_vuln"),
                    "url": v.get("url", site_url),
                    "severity": v.get("severity", "HIGH"),
                    "confidence": v.get("confidence", 0.8),
                    "evidence": v.get("evidence", []),
                    "source": "gap_analyzer:wp_scan",
                })
        return {"condition_met": bool(findings), "findings": findings}

    # ── api_scan ──────────────────────────────────────────────────────────────

    def _run_api_scan(self, gap: Dict) -> Dict:
        from modules.api_scanner import APIScannerRunner
        runner = APIScannerRunner(output_dir=self.output_dir)
        raw = runner.scan(self._base_url)
        found_apis = (
            raw.get("apis_found", [])
            + raw.get("rest_endpoints", [])
            + raw.get("graphql_endpoints", [])
        )
        vulns = raw.get("vulnerabilities", [])
        findings = [
            {
                "type": "api_endpoint_found",
                "url": ep if isinstance(ep, str) else ep.get("url", ""),
                "severity": "INFO",
                "confidence": 0.75,
                "evidence": ["Discovered via api_scan"],
                "source": "gap_analyzer:api_scan",
            }
            for ep in found_apis[:15]
        ] + [
            {
                "type": v.get("type", "api_vuln"),
                "url": v.get("url", self._base_url),
                "severity": v.get("severity", "MEDIUM"),
                "confidence": v.get("confidence", 0.7),
                "evidence": v.get("evidence", []),
                "source": "gap_analyzer:api_scan",
            }
            for v in vulns
        ]
        return {
            "condition_met": bool(found_apis or vulns),
            "findings": findings,
        }

    # ── swagger ───────────────────────────────────────────────────────────────

    def _run_swagger(self, gap: Dict) -> Dict:
        from modules.swagger_exploiter import SwaggerExploiter
        exploiter = SwaggerExploiter(http_client=self.http_client, state=self.state)
        specs = exploiter.discover_swagger(self._base_url) or []
        findings = []
        for spec in specs:
            for ep in spec.get("endpoints", [])[:20]:
                findings.append({
                    "type": "swagger_endpoint",
                    "url": ep.get("url", ""),
                    "method": ep.get("method", "GET"),
                    "severity": "INFO",
                    "confidence": 0.8,
                    "evidence": [f"From OpenAPI spec: {spec.get('source_url', '')}"],
                    "source": "gap_analyzer:swagger",
                    "parameters": ep.get("parameters", []),
                })
            for v in spec.get("vulnerabilities", []):
                findings.append({
                    "type": v.get("type", "swagger_vuln"),
                    "url": v.get("url", self._base_url),
                    "severity": v.get("severity", "HIGH"),
                    "confidence": v.get("confidence", 0.8),
                    "evidence": v.get("evidence", []),
                    "source": "gap_analyzer:swagger",
                })
        return {"condition_met": bool(findings), "findings": findings}

    # ── crawler ───────────────────────────────────────────────────────────────

    def _run_crawler(self, gap: Dict) -> Dict:
        from modules.crawler import DiscoveryEngine
        engine = DiscoveryEngine(state=self.state, output_dir=self.output_dir)
        new_eps = engine.discover_from_url(self._base_url)
        scope_kw = gap.get("target_scope", "")
        if scope_kw and scope_kw != "full":
            new_eps = [
                ep for ep in new_eps
                if scope_kw.lower() in (ep.get("url") or "").lower()
            ]
        findings = [
            {
                "type": "discovered_endpoint",
                "url": ep.get("url", ""),
                "method": ep.get("method", "GET"),
                "severity": "INFO",
                "confidence": 0.65,
                "evidence": [f"Crawled for gap: {gap.get('condition')}"],
                "source": "gap_analyzer:crawler",
                "parameters": ep.get("parameters", []),
            }
            for ep in new_eps[:30]
        ]
        if new_eps and self.state:
            existing = self.state.get("endpoints") or []
            existing_urls = {e.get("url") for e in existing if isinstance(e, dict)}
            added = [ep for ep in new_eps if ep.get("url") not in existing_urls]
            if added:
                self.state.update(endpoints=existing + added)
                logger.info("[GAP] Crawler merged %d new endpoints into state", len(added))
        return {"condition_met": bool(findings), "findings": findings}

    # ── parameter_miner ───────────────────────────────────────────────────────

    def _run_parameter_miner(self, gap: Dict) -> Dict:
        from modules.parameter_miner import ParameterMiner
        endpoints = (self.state.get("endpoints") or []) if self.state else []
        injectable = [
            ep for ep in endpoints
            if isinstance(ep, dict)
            and (
                "api" in (ep.get("url") or "").lower()
                or ep.get("parameters")
                or "?" in (ep.get("url") or "")
            )
        ][:20] or [{"url": self._base_url, "method": "GET"}]
        miner = ParameterMiner(state=self.state)
        raw = miner.mine_parameters(injectable)
        discovered = (
            raw.get("discovered_parameters", [])
            or raw.get("parameters", [])
            or []
        )
        findings = [
            {
                "type": "discovered_parameter",
                "url": p.get("url", self._base_url),
                "severity": "INFO",
                "confidence": 0.7,
                "evidence": [f"Parameter: {p.get('name')} ({p.get('method', 'GET')})"],
                "source": "gap_analyzer:parameter_miner",
                "parameter": p.get("name"),
            }
            for p in discovered[:30]
        ]
        return {"condition_met": bool(findings), "findings": findings}

    # ─── STATE UPDATE ─────────────────────────────────────────────────────────

    def _update_state(self, condition: str, finding: Dict) -> None:
        if not self.state:
            return
        gap_findings = self.state.get("gap_findings") or []
        gap_findings.append(finding)
        self.state.update(gap_findings=gap_findings)

        fulfilled = self.state.get("fulfilled_preconditions") or []
        if condition not in fulfilled:
            fulfilled.append(condition)
            self.state.update(fulfilled_preconditions=fulfilled)

        # Promote high-confidence non-INFO findings to confirmed_vulnerabilities
        if (
            finding.get("confidence", 0) >= 0.8
            and finding.get("severity", "INFO") not in ("INFO",)
        ):
            confirmed = self.state.get("confirmed_vulnerabilities") or []
            confirmed.append(finding)
            self.state.update(confirmed_vulnerabilities=confirmed)


def run_gap_analysis(
    state,
    http_client=None,
    groq_client=None,
    rejected_chains: List[Dict] = None,
    output_dir: str = "/tmp",
) -> Dict[str, Any]:
    """
    Standalone entry point for agent.py.

    Returns the same keys the agent.py hook expects:
      gaps_found, gaps_filled, new_findings, executable_chain
    """
    analyzer = GapAnalyzer(
        state=state,
        http_client=http_client,
        groq_client=groq_client,
        output_dir=output_dir,
    )
    chains = rejected_chains or []
    loop_result = analyzer.analyze_loop(chains, max_iterations=4)
    # Normalise to what the agent.py hook reads
    return {
        "gaps_found": sum(
            len(c.get("preconditions_missing") or []) for c in chains
        ),
        "gaps_filled": len(loop_result.get("fulfilled", [])),
        "new_findings": loop_result.get("new_findings", []),
        "executable_chain": loop_result.get("executable_chain"),
        "iterations": loop_result.get("iterations", 0),
        "fulfilled": loop_result.get("fulfilled", []),
    }
