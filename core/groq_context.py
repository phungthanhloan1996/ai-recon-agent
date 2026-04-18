"""
core/groq_context.py - Shared Groq reasoning context accumulated across scan phases.
Serialized to results/<target>/groq_context.json after each phase so it survives crashes.
"""
import json
import logging
import os
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List

logger = logging.getLogger("recon.groq_context")


@dataclass
class GroqScanContext:
    target: str = ""
    live_hosts: List[Dict[str, Any]] = field(default_factory=list)
    tech_stack: Dict[str, Any] = field(default_factory=dict)
    confirmed_vulns: List[Dict[str, Any]] = field(default_factory=list)
    endpoints_with_params: List[Dict[str, Any]] = field(default_factory=list)
    auth_surfaces: List[Dict[str, Any]] = field(default_factory=list)
    exposed_services: List[Dict[str, Any]] = field(default_factory=list)
    wp_findings: Dict[str, Any] = field(default_factory=dict)
    js_secrets: List[str] = field(default_factory=list)
    failed_attempts: List[Dict[str, Any]] = field(default_factory=list)
    phases_completed: List[str] = field(default_factory=list)

    def append_phase(self, phase_name: str, data: Dict[str, Any]) -> None:
        """Append findings from a completed phase into the accumulator."""
        if phase_name not in self.phases_completed:
            self.phases_completed.append(phase_name)

        for h in (data.get("live_hosts") or []):
            if isinstance(h, dict) and h not in self.live_hosts:
                self.live_hosts.append(h)

        stack = data.get("technologies") or data.get("tech_stack") or {}
        if isinstance(stack, dict):
            self.tech_stack.update(stack)

        for key in ("confirmed_vulnerabilities", "vulnerabilities"):
            for v in (data.get(key) or []):
                if isinstance(v, dict) and v not in self.confirmed_vulns:
                    self.confirmed_vulns.append(v)

        eps = data.get("prioritized_endpoints") or data.get("endpoints") or []
        for ep in eps:
            if isinstance(ep, dict) and ep.get("params"):
                if ep not in self.endpoints_with_params:
                    self.endpoints_with_params.append(ep)

        for s in (data.get("auth_surfaces") or []):
            if s not in self.auth_surfaces:
                self.auth_surfaces.append(s)

        svcs = data.get("exposed_services") or data.get("open_ports") or []
        for s in svcs:
            if s not in self.exposed_services:
                self.exposed_services.append(s)

        wp = data.get("wp_findings") or {}
        if not wp and ("wp_version" in data or "wp_users" in data):
            wp = {
                "version": data.get("wp_version"),
                "users": data.get("wp_users", []),
                "plugins": data.get("wp_plugins", []),
                "vulnerabilities": data.get("wp_vulnerabilities", []),
            }
        if wp:
            self.wp_findings.update(wp)

        for s in (data.get("js_secrets") or []):
            if s not in self.js_secrets:
                self.js_secrets.append(s)

        for a in (data.get("failed_attempts") or []):
            if isinstance(a, dict) and a not in self.failed_attempts:
                self.failed_attempts.append(a)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_summary(self) -> str:
        """Compact JSON summary suitable as LLM context input."""
        summary = {
            "target": self.target,
            "live_hosts_count": len(self.live_hosts),
            "live_hosts_sample": self.live_hosts[:5],
            "tech_stack": self.tech_stack,
            "confirmed_vulns": self.confirmed_vulns[:20],
            "endpoints_with_params_count": len(self.endpoints_with_params),
            "top_endpoints": self.endpoints_with_params[:10],
            "auth_surfaces": self.auth_surfaces[:10],
            "exposed_services": self.exposed_services[:10],
            "wp_findings": self.wp_findings,
            "js_secrets_count": len(self.js_secrets),
            "js_secrets_sample": self.js_secrets[:5],
            "failed_attempts": self.failed_attempts[-10:],
            "phases_completed": self.phases_completed,
        }
        return json.dumps(summary, indent=2, default=str)

    def save(self, output_dir: str) -> None:
        try:
            path = os.path.join(output_dir, "groq_context.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.to_dict(), f, indent=2, default=str)
        except Exception as e:
            logger.warning(f"[GROQ_CTX] Failed to save: {e}")

    @classmethod
    def load(cls, output_dir: str) -> "GroqScanContext":
        try:
            path = os.path.join(output_dir, "groq_context.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                ctx = cls()
                for k, v in data.items():
                    if hasattr(ctx, k):
                        setattr(ctx, k, v)
                return ctx
        except Exception as e:
            logger.warning(f"[GROQ_CTX] Failed to load: {e}")
        return cls()
