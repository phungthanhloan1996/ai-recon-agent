"""
reports/dashboard_enhanced.py - Enhanced Terminal Dashboard
Live scan progress, findings feed, phase tracking, severity breakdown.
Uses only stdlib — no third-party dependencies.
"""

import os
import sys
import time
import threading
import logging
from typing import Dict, List, Any, Optional, Deque
from collections import deque
from datetime import datetime
from dataclasses import dataclass, asdict, field

logger = logging.getLogger("dashboard")

# ── ANSI colours (degrade gracefully when not a TTY) ─────────────────────────
_IS_TTY = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _IS_TTY else text

def RED(t):    return _c("31", t)
def YELLOW(t): return _c("33", t)
def GREEN(t):  return _c("32", t)
def CYAN(t):   return _c("36", t)
def BLUE(t):   return _c("34", t)
def MAGENTA(t):return _c("35", t)
def BOLD(t):   return _c("1",  t)
def DIM(t):    return _c("2",  t)
def WHITE(t):  return _c("97", t)

_SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     YELLOW,
    "MEDIUM":   CYAN,
    "LOW":      GREEN,
    "INFO":     DIM,
}

_PHASE_ICON = {
    "recon":           "🔍",
    "live":            "🌐",
    "toolkit":         "🔧",
    "crawl":           "🕷 ",
    "scan":            "⚡",
    "exploit":         "💥",
    "ssrf":            "🎯",
    "ssti":            "🎯",
    "xxe":             "📄",
    "jwt":             "🔑",
    "cors":            "🌍",
    "nosql":           "🗄 ",
    "ldap":            "📂",
    "open_redirect":   "↪ ",
    "graphql":         "◈ ",
    "deserialization": "📦",
    "race_condition":  "⏱ ",
    "pwd_reset":       "🔓",
    "http_smuggling":  "📨",
    "crlf_injection":  "⤵ ",
    "idor":            "🔓",
    "xss":             "💬",
    "sqli_exploit":    "🗃 ",
    "report":          "📝",
    "done":            "✅",
    "error":           "❌",
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class DashboardMetrics:
    total_endpoints: int = 0
    vulnerabilities_found: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    exploits_attempted: int = 0
    exploits_successful: int = 0
    scan_duration: float = 0.0


@dataclass
class PhaseRecord:
    name: str
    status: str = "pending"   # pending | running | done | error | skipped
    started_at: float = 0.0
    ended_at: float = 0.0
    detail: str = ""


# ── EnhancedDashboard ─────────────────────────────────────────────────────────

class EnhancedDashboard:
    """
    Rich terminal dashboard for the AI Recon Agent.

    Keeps a rolling live-feed of events and draws a compact status panel
    to stdout.  Thread-safe via an internal lock.
    """

    WIDTH = 90

    def __init__(self, title: str = "AI Recon Agent", target: str = ""):
        self.title = title
        self.target = target
        self.start_time = time.monotonic()
        self.metrics = DashboardMetrics()

        self._lock = threading.Lock()
        self._findings: Deque[Dict[str, Any]] = deque(maxlen=200)
        self._feed: Deque[str] = deque(maxlen=15)
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=20)
        self._phases: Dict[str, PhaseRecord] = {}
        self._current_phase: str = ""
        self._current_detail: str = ""

        # Background render thread (optional; call start_live() to activate)
        self._render_thread: Optional[threading.Thread] = None
        self._running = False

    # ── Public API ────────────────────────────────────────────────────────────

    def add_finding(self, finding: Dict[str, Any]) -> None:
        sev = str(finding.get("severity", "INFO")).upper()
        vuln_type = finding.get("type", "unknown")
        url = (finding.get("url") or finding.get("endpoint") or "")[:60]
        with self._lock:
            self._findings.append({"ts": time.monotonic(), "finding": finding})
            color = _SEV_COLOR.get(sev, DIM)
            self._feed.append(
                f"{color(f'[{sev:<8}]')} {CYAN(vuln_type):<28} {DIM(url)}"
            )
            # Update metrics
            self.metrics.vulnerabilities_found += 1
            if sev == "CRITICAL":   self.metrics.critical_issues += 1
            elif sev == "HIGH":     self.metrics.high_issues += 1
            elif sev == "MEDIUM":   self.metrics.medium_issues += 1
            else:                   self.metrics.low_issues += 1

    def add_alert(self, alert: str, severity: str = "info") -> None:
        with self._lock:
            self._alerts.append({
                "ts": datetime.now().strftime("%H:%M:%S"),
                "alert": alert,
                "severity": severity,
            })

    def update_metrics(self, metrics: DashboardMetrics) -> None:
        with self._lock:
            self.metrics = metrics

    def set_phase(self, phase: str, status: str = "running", detail: str = "") -> None:
        with self._lock:
            self._current_phase = phase
            self._current_detail = detail
            now = time.monotonic()
            rec = self._phases.setdefault(phase, PhaseRecord(name=phase))
            if status == "running" and rec.started_at == 0.0:
                rec.started_at = now
            elif status in ("done", "error", "skipped"):
                rec.ended_at = now
            rec.status = status
            rec.detail = detail

    def feed_event(self, icon: str, event: str, target: str, detail: str) -> None:
        with self._lock:
            ts = datetime.now().strftime("%H:%M:%S")
            self._feed.append(f"{DIM(ts)} {icon} {BOLD(event):<18} {target[:30]:<30} {DIM(detail[:30])}")

    # ── Rendering ─────────────────────────────────────────────────────────────

    def render(self) -> str:
        with self._lock:
            return self._render_locked()

    def _render_locked(self) -> str:
        W = self.WIDTH
        elapsed = time.monotonic() - self.start_time
        h, rem = divmod(int(elapsed), 3600)
        m, s = divmod(rem, 60)
        elapsed_str = f"{h:02d}:{m:02d}:{s:02d}"
        lines: List[str] = []

        bar = "─" * W
        lines.append(BOLD(f"┌{'─' * (W - 2)}┐"))

        # Title row
        title_txt = f"  {BOLD(self.title)}"
        target_txt = f"{CYAN(self.target)}  ⏱ {elapsed_str}  "
        pad = W - 4 - len(self.title) - len(self.target) - len(elapsed_str) - 8
        lines.append(f"│{title_txt}{'':>{max(0, pad)}}{target_txt}│")
        lines.append(f"├{bar[:-2]}┤")

        # Severity counters
        crit = self.metrics.critical_issues
        high = self.metrics.high_issues
        med  = self.metrics.medium_issues
        low  = self.metrics.low_issues
        total = self.metrics.vulnerabilities_found
        sev_line = (
            f"  Findings: {BOLD(str(total))}   "
            f"{RED(f'CRIT {crit}')}  "
            f"{YELLOW(f'HIGH {high}')}  "
            f"{CYAN(f'MED {med}')}  "
            f"{GREEN(f'LOW {low}')}"
        )
        lines.append(f"│{sev_line:<{W + 30}}│")

        # Endpoints / exploits
        stats_line = (
            f"  Endpoints: {BOLD(str(self.metrics.total_endpoints))}   "
            f"Exploits: {GREEN(str(self.metrics.exploits_successful))}/{self.metrics.exploits_attempted}"
        )
        lines.append(f"│{stats_line:<{W + 20}}│")
        lines.append(f"├{bar[:-2]}┤")

        # Current phase
        icon = _PHASE_ICON.get(self._current_phase, "▶ ")
        phase_line = f"  Phase: {BOLD(self._current_phase or '-'):<20} {icon}  {DIM(self._current_detail[:45])}"
        lines.append(f"│{phase_line:<{W + 20}}│")
        lines.append(f"├{bar[:-2]}┤")

        # Live feed (last 8 events)
        lines.append(f"│  {BOLD('Live Feed'):<{W - 3}}│")
        feed_items = list(self._feed)[-8:]
        for item in feed_items:
            lines.append(f"│  {item:<{W + 40}}│")
        for _ in range(8 - len(feed_items)):
            lines.append(f"│{'':<{W - 2}}│")

        lines.append(f"└{'─' * (W - 2)}┘")
        return "\n".join(lines)

    def display(self) -> None:
        """Print current state to stdout."""
        print(self.render(), flush=True)

    # ── Live mode (optional background refresh) ───────────────────────────────

    def start_live(self, interval: float = 2.0) -> None:
        """Start background thread that refreshes the terminal display."""
        if self._render_thread and self._render_thread.is_alive():
            return
        self._running = True
        self._render_thread = threading.Thread(
            target=self._live_loop, args=(interval,), daemon=True
        )
        self._render_thread.start()

    def stop_live(self) -> None:
        self._running = False

    def _live_loop(self, interval: float) -> None:
        while self._running:
            try:
                self._clear_and_render()
            except Exception:
                pass
            time.sleep(interval)

    def _clear_and_render(self) -> None:
        if _IS_TTY:
            # Move cursor to top of previously rendered block (approx 20 lines)
            sys.stdout.write("\033[20A\033[J")
        print(self.render(), flush=True)

    # ── Summary report ────────────────────────────────────────────────────────

    def summary(self) -> str:
        """Return a plain-text summary suitable for log files."""
        elapsed = time.monotonic() - self.start_time
        lines = [
            "=" * 60,
            f"  Scan Summary — {self.target}",
            f"  Duration : {elapsed/60:.1f} min",
            f"  Findings : {self.metrics.vulnerabilities_found} total",
            f"    CRITICAL {self.metrics.critical_issues}  HIGH {self.metrics.high_issues}"
            f"  MEDIUM {self.metrics.medium_issues}  LOW {self.metrics.low_issues}",
            f"  Exploits : {self.metrics.exploits_successful}/{self.metrics.exploits_attempted}",
        ]
        if self._findings:
            lines.append("")
            lines.append("  Top Findings:")
            for rec in list(self._findings)[:10]:
                f = rec["finding"]
                sev = f.get("severity", "INFO")
                lines.append(f"    [{sev}] {f.get('type', '?')} — {f.get('url', '')[:60]}")
        lines.append("=" * 60)
        return "\n".join(lines)


# ── format_state_for_display (used by agent.py) ───────────────────────────────

def format_state_for_display(state: Dict[str, Any]) -> str:
    """Compact state snapshot for debug logging."""
    lines = ["[STATE SNAPSHOT]"]
    scalar_keys = [
        "target", "current_phase", "scan_incomplete",
        "payloads_tested", "waf_blocked",
    ]
    for k in scalar_keys:
        v = state.get(k)
        if v is not None:
            lines.append(f"  {k}: {v}")

    list_keys = [
        "live_hosts", "endpoints", "prioritized_endpoints",
        "vulnerabilities", "confirmed_vulnerabilities",
        "verified_vulnerabilities", "exploit_chains",
    ]
    for k in list_keys:
        v = state.get(k)
        if isinstance(v, list):
            lines.append(f"  {k}: {len(v)} items")

    return "\n".join(lines)
