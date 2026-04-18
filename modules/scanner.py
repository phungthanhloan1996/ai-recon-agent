"""
modules/scanner.py - Scanning Engine
AI-driven vulnerability scanning with payload generation and mutation
"""

import json
import math
import os
import logging
from typing import Dict, List, Any
import time
import base64
import concurrent.futures
import threading
import urllib.parse
from urllib.parse import urlparse
import config
from urllib3.exceptions import NameResolutionError

from core.endpoint_registry import EndpointRegistry
from core.finding_normalizer import normalize_finding, finding_identity
from core.phase_admission import PhaseAdmission
from core.state_manager import StateManager
from core.http_engine import HTTPClient
from ai.groq_client import GroqClient
from ai.payload_gen import PayloadGenerator
from ai.payload_mutation import PayloadMutator
from learning.learning_engine import LearningEngine
from integrations.dalfox_runner import DalfoxRunner
from integrations.nuclei_runner import NucleiRunner
from integrations.sqlmap_runner import SQLMapRunner
from core.executor import run_command, tool_available
from core.resource_manager import get_nuclei_pool, get_concurrency_manager
from core.host_filter import HostFilter
from core.scan_optimizer import get_optimizer

logger = logging.getLogger("recon.scanning")


class ScanningEngine:
    """
    Intelligent vulnerability scanning engine.
    Uses AI-generated payloads, applies mutations, and tests endpoints.
    """

    def __init__(
        self,
        state: StateManager,
        output_dir: str,
        payload_gen: PayloadGenerator,
        payload_mutator: PayloadMutator,
        learning_engine: LearningEngine,
    ):
        self.state = state
        self.output_dir = output_dir
        self.target = state.get("target")
        self.http_client = HTTPClient()
        self.payload_gen = payload_gen
        self.payload_mutator = payload_mutator
        self.learning_engine = learning_engine
        self.dalfox_runner = DalfoxRunner(output_dir)
        self.nuclei_runner = NucleiRunner(output_dir)
        self.sqlmap_runner = SQLMapRunner(output_dir)

        self.scan_results_file = os.path.join(output_dir, "scan_results.json")
        self.manifest_file = os.path.join(output_dir, "scanner_manifest.json")
        allowed_domains = list(state.get("allowed_domains", []) or [])
        if self.target:
            allowed_domains.append(self.target)
            parsed_target = urllib.parse.urlparse(
                self.target if "://" in str(self.target) else f"https://{self.target}"
            )
            if parsed_target.netloc:
                allowed_domains.append(parsed_target.netloc)
            if parsed_target.hostname:
                allowed_domains.append(parsed_target.hostname)
        # Include all live host IPs/hostnames so that endpoints discovered via DNS
        # resolution (e.g., 127.0.0.1 for portal-news.internal.test) are not
        # erroneously filtered out by the scope check.
        for lh in (state.get("live_hosts", []) or []):
            lh_url = lh.get("url") or lh.get("host") or ""
            if not lh_url:
                continue
            parsed_lh = urllib.parse.urlparse(
                lh_url if "://" in lh_url else f"https://{lh_url}"
            )
            if parsed_lh.hostname:
                allowed_domains.append(parsed_lh.hostname)
            if parsed_lh.netloc:
                allowed_domains.append(parsed_lh.netloc)
        # Deduplicate while preserving order
        seen_domains: set = set()
        deduped_domains = []
        for d in allowed_domains:
            if d and d not in seen_domains:
                seen_domains.add(d)
                deduped_domains.append(d)
        allowed_domains = deduped_domains
        self.host_filter = HostFilter(
            skip_dev_test=True,
            target_domain=self.target,
            allowed_domains=allowed_domains,
        )
        self.endpoint_registry = EndpointRegistry()
        self.phase_admission = PhaseAdmission(
            state, registry=self.endpoint_registry, host_filter=self.host_filter
        )
        self._baseline_cache: Dict[str, Dict[str, Any]] = {}
        self._host_last_scan_at: Dict[str, float] = {}
        self._host_gate_lock = threading.Lock()
        self._blacklisted_hosts_logged = set()
        # Thread-safe tracking of scanned endpoints within this run
        self._scanned_in_run: set = set()
        self._scanned_lock = threading.Lock()

    def _is_url_in_scope(self, url: str) -> bool:
        if not url:
            return False
        try:
            if self.host_filter._is_third_party(url):
                return False
            if self.host_filter.allowed_domains:
                return self.host_filter._is_in_allowed_domains(url)
            return self.host_filter._is_target_domain(url)
        except Exception:
            return True

    def _log_blacklisted_host_once(self, hostname: str, stage: str):
        if not hostname or hostname in self._blacklisted_hosts_logged:
            return
        self._blacklisted_hosts_logged.add(hostname)
        logger.info(f"[SCANNING] Pruned blacklisted host before {stage}: {hostname}")

    def _apply_host_backpressure(self, hostname: str, min_interval: float = 0.15):
        if not hostname:
            return
        with self._host_gate_lock:
            last_scan = self._host_last_scan_at.get(hostname, 0.0)
            now = time.time()
            sleep_for = min_interval - (now - last_scan)
            if sleep_for > 0:
                time.sleep(sleep_for)
            self._host_last_scan_at[hostname] = time.time()

    def _set_scan_incomplete(self, reason: str):
        scan_meta = self.state.get("scan_metadata", {}) or {}
        reasons = scan_meta.get("scan_incomplete_reasons", []) or []
        if reason not in reasons:
            reasons.append(reason)
        scan_meta["scan_incomplete_reasons"] = reasons[-10:]
        self.state.update(scan_incomplete=True, scan_metadata=scan_meta)
        logger.warning(f"[SCANNING] Marked scan incomplete: {reason}")

    def _mark_endpoint_state(self, url: str, **updates):
        record = self.endpoint_registry.register({"url": url, **updates})
        if not record:
            return
        self.state.upsert_endpoint(record)

    def _prepare_scan_candidates(self, endpoints: List[Any]) -> List[Dict[str, Any]]:
        optimizer = get_optimizer()
        seen: Dict[str, int] = {}
        scanned = set(self.state.get("scanned_endpoints", []) or [])
        candidates: List[Dict[str, Any]] = []
        fallback_pool: List[Dict[str, Any]] = []
        reductions = {
            "invalid": 0,
            "duplicate": 0,
            "blacklisted": 0,
            "already_scanned": 0,
            "rejected": 0,
        }

        for endpoint in endpoints or []:
            record = self.phase_admission.register(endpoint)
            if not record or not self.phase_admission.is_valid_endpoint(record):
                reductions["invalid"] += 1
                continue

            if self._is_url_in_scope(record.get("url", "")) and self._is_valid_url(
                record.get("url", "")
            ):
                fallback_pool.append(record)

            fingerprint = record.get("fingerprint")
            if fingerprint in seen:
                reductions["duplicate"] += 1
                candidates[seen[fingerprint]] = self.endpoint_registry.merge_records(
                    candidates[seen[fingerprint]], record
                )
                continue
            seen[fingerprint] = len(candidates)

            hostname = record.get("host") or ""
            if hostname and optimizer.is_host_blacklisted(hostname):
                reductions["blacklisted"] += 1
                self._log_blacklisted_host_once(hostname, "scan scheduling")
                continue

            if record["url"] in scanned:
                reductions["already_scanned"] += 1
                continue

            if not self.phase_admission.is_phase_candidate(record, "scan"):
                reductions["rejected"] += 1
                continue

            candidates.append(record)

        if not candidates and endpoints:
            canonical_fallback = [
                record
                for record in self.phase_admission.canonical_seed_records()
                if self._is_url_in_scope(record.get("url", ""))
                and self._is_valid_url(record.get("url", ""))
            ]
            fallback_candidates = canonical_fallback or fallback_pool
            deduped_fallback = []
            fallback_seen = set()
            for record in fallback_candidates:
                fingerprint = record.get("exact_fingerprint") or record.get("url")
                if fingerprint in fallback_seen:
                    continue
                fallback_seen.add(fingerprint)
                deduped_fallback.append(record)
            if deduped_fallback:
                candidates = deduped_fallback
                logger.warning(
                    "[SCANNING] Preserved %s canonical/fallback endpoint(s) to avoid empty scan scheduling",
                    len(candidates),
                )

        if any(reductions.values()):
            logger.info(
                "[SCANNING] Scheduling reduced %s -> %s (invalid=%s duplicate=%s blacklisted=%s already_scanned=%s rejected=%s)",
                len(endpoints or []),
                len(candidates),
                reductions["invalid"],
                reductions["duplicate"],
                reductions["blacklisted"],
                reductions["already_scanned"],
                reductions["rejected"],
            )
        return candidates

    def _canonicalize_scan_url(self, url: str) -> str:
        if not url:
            return url
        try:
            parsed = urllib.parse.urlparse(url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            live_hosts = self.state.get("live_hosts", []) or []
            for item in live_hosts:
                live_url = item.get("url", "")
                live_parsed = urllib.parse.urlparse(live_url)
                live_port = live_parsed.port or (
                    443 if live_parsed.scheme == "https" else 80
                )
                if (parsed.hostname or "").lower() == (
                    live_parsed.hostname or ""
                ).lower() and port == live_port:
                    return urllib.parse.urlunparse(
                        parsed._replace(
                            scheme=live_parsed.scheme, netloc=live_parsed.netloc
                        )
                    )
        except Exception:
            pass
        return url

    def _tool_confidence(self, value: Any, default: float = 0.0) -> float:
        try:
            if isinstance(value, str):
                cleaned = value.strip()
                if cleaned.endswith("%"):
                    return float(cleaned[:-1]) / 100.0
                return float(cleaned)
            if isinstance(value, (int, float)):
                return float(value)
        except (TypeError, ValueError):
            pass
        return default

    def _severity_confidence(self, severity: str) -> float:
        mapping = {
            "CRITICAL": 0.95,
            "HIGH": 0.85,
            "MEDIUM": 0.7,
            "LOW": 0.55,
            "INFO": 0.35,
        }
        return mapping.get(str(severity or "INFO").upper(), 0.5)

    def _append_unique_vulnerability(
        self, vuln: Dict[str, Any], confirmed: bool = False
    ):
        vuln = normalize_finding(vuln, self.endpoint_registry.normalizer)
        if not vuln:
            return
        vulnerabilities = self.state.get("vulnerabilities", []) or []
        key = (
            vuln.get("url") or vuln.get("endpoint"),
            vuln.get("type"),
            vuln.get("tool") or vuln.get("source"),
            vuln.get("payload"),
            vuln.get("artifact_path"),
        )
        existing_keys = {
            (
                item.get("url") or item.get("endpoint"),
                item.get("type"),
                item.get("tool") or item.get("source"),
                item.get("payload"),
                item.get("artifact_path"),
            )
            for item in vulnerabilities
            if isinstance(item, dict)
        }
        if key not in existing_keys:
            vulnerabilities.append(vuln)
            self.state.update(vulnerabilities=vulnerabilities)

        if confirmed:
            confirmed_vulns = self.state.get("confirmed_vulnerabilities", []) or []
            confirmed_keys = {
                (
                    item.get("url") or item.get("endpoint"),
                    item.get("type"),
                    item.get("tool") or item.get("source"),
                    item.get("payload"),
                    item.get("artifact_path"),
                )
                for item in confirmed_vulns
                if isinstance(item, dict)
            }
            if key not in confirmed_keys:
                confirmed_vulns.append(vuln)
                self.state.update(confirmed_vulnerabilities=confirmed_vulns)

    def _extract_nuclei_tags(
        self, url: str, categories: List[str], parameters: List[str]
    ) -> List[str]:
        tags = set()
        category_map = {
            "wordpress": ["wordpress"],
            "authentication": ["auth", "panel"],
            "admin": ["auth", "panel"],
            "api_injection": ["api"],
            "api": ["api"],
            "file_upload": ["upload", "files"],
            "rpc": ["xmlrpc", "wordpress"],
            "injection": ["sqli"],
            "sql_injection": ["sqli"],
            "sqli": ["sqli"],
            "xss": ["xss"],
            "command_injection": ["rce"],
            "rce": ["rce"],
        }
        for category in categories or []:
            for tag in category_map.get(str(category).lower(), []):
                tags.add(tag)

        url_lower = (url or "").lower()
        if "wp-admin" in url_lower or "wp-json" in url_lower:
            tags.update(["wordpress", "auth"])
        if "xmlrpc" in url_lower:
            tags.update(["wordpress", "xmlrpc"])
        if parameters:
            tags.add("fuzz")
        return sorted(tags)

    def _build_tool_plan(
        self,
        endpoint: Dict[str, Any],
        url: str,
        categories: List[str],
        parameters: List[str],
        endpoint_score: int,
    ) -> Dict[str, Any]:
        category_set = {str(c).lower() for c in (categories or [])}
        url_lower = (url or "").lower()
        hints = " ".join(
            str(h) for h in (endpoint.get("vulnerability_hints", []) or [])
        ).lower()

        # Detect REST API paths where sqlmap is a poor fit:
        # - WP REST API (/wp-json/) uses $wpdb->prepare() by default
        # - Versioned REST paths (/api/v1/, /rest/, /graphql) rarely expose raw SQL
        _is_rest_api_path = (
            "/wp-json/" in url_lower
            or "/api/v" in url_lower
            or "/rest/" in url_lower
            or "/graphql" in url_lower
        )

        if _is_rest_api_path:
            # For REST API paths: only run sqlmap when there is an *explicit* SQLi signal —
            # a category that directly names the vuln type AND a classically SQL-injectable
            # parameter name (e.g. "id", "item", "uid").  "api_injection" / "injection" /
            # URL tokens like "page=" or "q=" are NOT sufficient on their own.
            _sqli_direct_params = {"id", "user", "uid", "item", "cat"}
            _has_direct_param = any(
                str(p).lower() in _sqli_direct_params for p in (parameters or [])
            )
            sqli_interest = bool(parameters) and _has_direct_param and bool(
                {"sql_injection", "sqli"} & category_set or "sql" in hints
            )
            if not sqli_interest:
                logger.debug(
                    "[SCAN] Skipping sqlmap on REST API path (no direct SQLi signal): %s", url[:80]
                )
        else:
            sqli_interest = bool(parameters) and (
                self._detect_sqli_potential(endpoint)
                or {"injection", "sql_injection", "sqli"} & category_set
                or any(
                    token in url_lower
                    for token in ["id=", "cat=", "page=", "item=", "query=", "search="]
                )
                or "sql" in hints
            )
        xss_interest = bool(parameters) and (
            self._detect_xss_potential(endpoint)
            or {"xss", "api_injection", "authentication"} & category_set
            or any(
                token in url_lower
                for token in ["search", "query", "q=", "input=", "callback="]
            )
            or "xss" in hints
        )
        nuclei_platform_signal = bool(
            {
                "wordpress",
                "authentication",
                "api_injection",
                "file_upload",
                "rpc",
                "admin",
            }
            & category_set
        ) or any(
            token in url_lower
            for token in [
                "wp-admin",
                "xmlrpc",
                "api",
                "login",
                "admin",
                "upload",
                "graphql",
            ]
        )
        # Skip nuclei on generic WP REST API paths — they're covered by sqlmap/payload
        # testing and nuclei generates noise (GOOGLE_API errors) without real findings.
        _is_wp_rest = "/wp-json/" in url_lower
        nuclei_interest = (
            not _is_wp_rest
            and endpoint_score >= config.NUCLEI_MIN_ENDPOINT_SCORE  # strict threshold (default 8)
            and (
                nuclei_platform_signal
                or (bool(parameters) and not (sqli_interest or xss_interest))
            )
        )

        return {
            "sqlmap": sqli_interest,
            "dalfox": xss_interest,
            "nuclei": nuclei_interest,
            "nuclei_tags": self._extract_nuclei_tags(url, categories, parameters),
            "nuclei_severity": ["critical", "high", "medium"],
            "sqlmap_timeout": 120 if endpoint_score < 8 else 180,
            "dalfox_timeout": 20 if endpoint_score < 8 else 35,
            "nuclei_timeout": 90 if endpoint_score < 8 else 180,
        }

    def _promote_sqlmap_result(self, target: str, result: Dict[str, Any]):
        if not result.get("vulnerable"):
            return
        vuln = {
            "name": "SQL Injection",
            "type": "sqli",
            "url": target,
            "endpoint": target,
            "tool": "sqlmap",
            "source": "sqlmap",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "verified": True,
            "output": result.get("output", "")[:2000],
            "findings": result.get("findings", []),
            "dbms": result.get("dbms"),
            "evidence": "; ".join(
                f.get("evidence", "")
                for f in result.get("findings", [])[:3]
                if isinstance(f, dict)
            )
            or result.get("dbms", ""),
            "artifact_path": result.get("artifact_path"),
            "raw_output_path": result.get("raw_output_path"),
            "exploitable": True,
            "exploit_context": {"tool": "sqlmap", "dbms": result.get("dbms")},
        }
        self._append_unique_vulnerability(vuln, confirmed=True)

        # Sync to boolean_sqli_findings.json immediately so next phase reads it
        sqli_file = os.path.join(self.output_dir, "boolean_sqli_findings.json")
        try:
            existing = []
            if os.path.exists(sqli_file):
                with open(sqli_file) as _f:
                    _d = json.load(_f)
                    existing = _d if isinstance(_d, list) else _d.get("vulnerabilities", [])
            existing.append(vuln)
            with open(sqli_file, "w") as _f:
                json.dump({"vulnerabilities": existing}, _f, indent=2)
        except Exception as _e:
            logger.debug(f"[SCANNING] boolean_sqli_findings.json sync failed: {_e}")

    def _promote_dalfox_result(self, url: str, result: Dict[str, Any]):
        findings = result.get("findings", []) or []
        # Guard: skip if dalfox produced no real output — empty artifact = false positive
        artifact_path = result.get("artifact_path", "")
        if artifact_path and os.path.exists(artifact_path):
            try:
                artifact_size = os.path.getsize(artifact_path)
                if artifact_size == 0 and not findings:
                    logger.debug(f"[SCANNING] Dalfox artifact is empty for {url}, skipping")
                    return
            except OSError:
                pass
        if not result.get("success") and not findings:
            return
        has_verified_poc = any(
            isinstance(f, dict) and f.get("verified") for f in findings
        )
        evidence = ""
        if findings:
            first = findings[0] if isinstance(findings[0], dict) else {}
            evidence = first.get("evidence", "") or first.get("message", "")
        confidence = 0.95 if has_verified_poc else (0.8 if findings else 0.65)
        vuln = {
            "name": "Cross-Site Scripting",
            "type": "xss",
            "url": url,
            "endpoint": url,
            "tool": "dalfox",
            "source": "dalfox",
            "severity": "HIGH",
            "confidence": confidence,
            "verified": has_verified_poc,
            "output": result.get("output", "")[:2000],
            "findings": findings,
            "evidence": evidence,
            "artifact_path": result.get("artifact_path"),
            "exploitable": confidence >= 0.7,
            "exploit_context": {"tool": "dalfox"},
        }
        self._append_unique_vulnerability(vuln, confirmed=confidence >= 0.7)

        # Sync to xss_findings.json so module-level file stays up to date
        xss_file = os.path.join(self.output_dir, "xss_findings.json")
        try:
            existing_vulns = []
            if os.path.exists(xss_file):
                with open(xss_file) as _f:
                    _d = json.load(_f)
                    existing_vulns = _d if isinstance(_d, list) else _d.get("vulnerabilities", [])
            existing_vulns.append(vuln)
            with open(xss_file, "w") as _f:
                json.dump({"vulnerabilities": existing_vulns}, _f, indent=2)
        except Exception as _e:
            logger.debug(f"[SCANNING] xss_findings.json sync failed: {_e}")

    def _promote_nuclei_result(self, url: str, result: Dict[str, Any]):
        findings = result.get("findings", []) or []
        if not findings:
            return
        for finding in findings:
            info = finding.get("info", {}) if isinstance(finding, dict) else {}
            severity = str(info.get("severity", result.get("severity", "INFO"))).upper()
            confidence = self._severity_confidence(severity)
            vuln = {
                "name": info.get("name", finding.get("template-id", "Nuclei Finding")),
                "type": finding.get("template-id", "general"),
                "url": finding.get("matched-at", url) or url,
                "endpoint": finding.get("matched-at", url) or url,
                "tool": "nuclei",
                "source": "nuclei",
                "severity": severity,
                "confidence": confidence,
                "evidence": finding.get("matcher-name", "")
                or info.get("description", ""),
                "artifact_path": result.get("artifact_path"),
                "findings": [finding],
                "tags": info.get("tags", []) or result.get("tags", []),
                "exploitable": severity in {"CRITICAL", "HIGH", "MEDIUM"},
                "exploit_context": {
                    "tool": "nuclei",
                    "template_id": finding.get("template-id"),
                },
            }
            self._append_unique_vulnerability(vuln, confirmed=confidence >= 0.7)
            # Sync high-confidence nuclei findings to confirmed_vulnerabilities.json
            if confidence >= 0.7:
                nfile = os.path.join(self.output_dir, "confirmed_vulnerabilities.json")
                try:
                    existing = []
                    if os.path.exists(nfile):
                        with open(nfile) as _f:
                            _d = json.load(_f)
                            existing = _d if isinstance(_d, list) else _d.get("vulnerabilities", [])
                    existing.append(vuln)
                    with open(nfile, "w") as _f:
                        json.dump({"vulnerabilities": existing}, _f, indent=2)
                except Exception as _ne:
                    logger.debug(f"[SCANNING] confirmed_vulnerabilities.json sync failed: {_ne}")

    def _is_valid_url(self, url: str) -> bool:
        """Kiểm tra URL hợp lệ trước khi gửi request"""
        if not url or not isinstance(url, str):
            return False
        if len(url) > config.MAX_URL_LENGTH:
            return False
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            hostname = parsed.netloc or parsed.hostname or ""
            if not hostname:
                return False
            invalid_chars = ["<", ">", '"', "'", "&lt;", "&gt;"]
            if any(c in hostname for c in invalid_chars):
                return False
            try:
                port = parsed.port
            except ValueError:
                return False
            if port is not None and not str(port).isdigit():
                return False
            return True
        except Exception:
            return False

    def run(self, progress_cb=None):
        """Execute vulnerability scanning pipeline with resume support."""
        logger.info("[SCANNING] Starting AI-driven vulnerability scanning")
        scan_meta = self.state.get("scan_metadata", {}) or {}

        # ── Resume detection ─────────────────────────────────────────────────
        # If a previous run was incomplete and left scan_targets + scanned_endpoints
        # in state, resume from where it stopped rather than re-scanning everything.
        was_incomplete = self.state.get("scan_incomplete", False)
        prev_targets = self.state.get("scan_targets", []) or []
        prev_scanned = set(self.state.get("scanned_endpoints", []) or [])
        is_resuming = was_incomplete and bool(prev_targets) and bool(prev_scanned)

        if is_resuming:
            remaining = [t for t in prev_targets if (t.get("url") if isinstance(t, dict) else t) not in prev_scanned]
            logger.warning(
                "[SCANNING] Resuming incomplete scan: %d/%d endpoints remaining",
                len(remaining), len(prev_targets),
            )
        else:
            remaining = []

        scan_meta.pop("scan_incomplete_reasons", None)
        self.state.update(scan_incomplete=False, scan_metadata=scan_meta)

        # All endpoints from the previous run are already scanned — nothing left to do.
        # Return immediately so the agent marks the scan phase done and moves forward.
        if is_resuming and not remaining:
            logger.info(
                "[SCANNING] All %d endpoints already scanned in previous run — scan complete",
                len(prev_targets),
            )
            return

        # Reset per-run tool dedup so a new scan iteration can rescan endpoints intentionally.
        if hasattr(self.dalfox_runner, "seen_urls"):
            self.dalfox_runner.seen_urls.clear()

        if is_resuming and remaining:
            # Use the already-scheduled remaining list directly
            prioritized_endpoints = remaining
        else:
            # Normal path: read from state prioritized_endpoints
            prioritized_endpoints = (
                self.state.get("prioritized_endpoints")
                or self.state.get("scan_targets")
                or []
            )

        logger.warning(f"[SCANNING] Received {len(prioritized_endpoints)} endpoints")

        if not prioritized_endpoints:
            logger.error("[SCANNING] No endpoints to scan → exiting")
            return

        try:
            if not os.path.exists(self.scan_results_file):
                with open(self.scan_results_file, "w", encoding="utf-8"):
                    pass
        except Exception as e:
            logger.error(f"[SCANNING] Cannot prepare scan_results.json: {e}")

        candidates = self._prepare_scan_candidates(prioritized_endpoints)
        if not candidates:
            logger.warning(
                "[SCANNING] No normalized endpoints available after fallback preservation"
            )
            return

        budget = (self.state.get("scan_metadata", {}) or {}).get("budget", {})
        self.max_endpoints = int(
            self.state.get(
                "max_endpoints", budget.get("scan_prioritized_endpoints", 140)
            )
        )
        scheduled = candidates[: self.max_endpoints]

        # Persist scan_targets only on a FRESH run (not on resume) so that
        # future resumes can always diff against the original full list.
        if not is_resuming:
            self.state.update(scan_targets=scheduled)

        # Initialise in-memory scanned set from what state already knows
        with self._scanned_lock:
            persisted = set(self.state.get("scanned_endpoints", []) or [])
            self._scanned_in_run.update(persisted)

        # Use parallel execution
        max_workers = max(1, min(config.SCANNING_MAX_WORKERS, len(scheduled)))
        total = len(scheduled)
        logger.info(
            "[SCAN] Dispatching %d endpoints with %d workers", total, max_workers
        )
        # Per-endpoint budget: sqlmap_timeout + nuclei_timeout + payload buffer.
        # Scale with the number of batches but cap at SCAN_MAX_TOTAL_SECONDS so a
        # large endpoint list never blocks the pipeline indefinitely.
        per_endpoint_budget = 180 + 180 + 60  # 420s worst-case per slot
        batches = math.ceil(total / max_workers)
        pool_timeout = min(
            batches * per_endpoint_budget + 120,
            config.SCAN_MAX_TOTAL_SECONDS,
        )
        logger.info(
            "[SCAN] pool_timeout=%ds (batches=%d, cap=%ds)",
            pool_timeout, batches, config.SCAN_MAX_TOTAL_SECONDS,
        )
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        try:
            # Attach index so per-endpoint logs show N/total
            future_to_idx = {
                executor.submit(self.scan_endpoint, endpoint): (i + 1, endpoint.get("url", "?")[:70])
                for i, endpoint in enumerate(scheduled)
            }

            completed = 0
            try:
                for future in concurrent.futures.as_completed(future_to_idx, timeout=pool_timeout):
                    idx, ep_url = future_to_idx[future]
                    try:
                        result = future.result()
                        completed += 1
                        self.state.update(payloads_tested=completed)
                        if result:
                            self.process_endpoint_results(result)
                        logger.info(
                            "[SCAN] [%d/%d] Done: %s", completed, total, ep_url
                        )
                        if progress_cb:
                            progress_cb(completed)
                    except concurrent.futures.TimeoutError:
                        self._set_scan_incomplete("endpoint future timeout")
                        logger.error("[SCAN] [%d/%d] Timed out: %s", idx, total, ep_url)
                    except Exception as e:
                        self._set_scan_incomplete(
                            f"endpoint future error: {str(e)[:120]}"
                        )
                        logger.error("[SCAN] [%d/%d] Error on %s: %s", idx, total, ep_url, e)
            except concurrent.futures.TimeoutError:
                self._set_scan_incomplete("scanner worker pool timeout")
                logger.warning(
                    "[SCAN] Worker pool timeout after %ds — %d/%d completed", pool_timeout, completed, total
                )
        finally:
            # Don't block shutdown waiting for hung threads (sqlmap/nuclei subprocesses
            # have their own timeouts and will clean up on their own).
            executor.shutdown(wait=False, cancel_futures=True)
            # Flush the in-memory scanned set to state so resume is accurate
            with self._scanned_lock:
                self.state.update(scanned_endpoints=sorted(self._scanned_in_run))

        logger.info("[SCANNING] Completed scanning - results streamed to file")
        self._write_manifest()

    def process_endpoint_results(self, responses: List[Dict[str, Any]]):
        """Process and stream endpoint results to file"""
        confirmed = self.state.get("confirmed_vulnerabilities", []) or []
        new_vulns = []

        with open(self.scan_results_file, "a") as f:
            for response in responses:
                endpoint = self.endpoint_registry.normalizer.normalize_url(
                    response.get("endpoint") or response.get("url") or ""
                )
                if endpoint:
                    response["endpoint"] = endpoint
                    response.setdefault("url", endpoint)
                if not self._is_url_in_scope(endpoint):
                    logger.debug(f"[SCANNING] Dropping off-scope response: {endpoint}")
                    continue
                json.dump(response, f)
                f.write("\n")  # JSONL format

                # Propagate to confirmed_vulnerabilities: require confidence >= 0.65
                # (conf 0.5 is "might be" / heuristic — not a confirmed finding)
                if response.get("vulnerable") and response.get("confidence", 0) >= 0.65:
                    category = response.get("category") or "unknown"
                    vuln = {
                        "name": f"{category} detection",
                        "endpoint": endpoint,
                        "url": endpoint,
                        "type": category,
                        "source": "ai_scan",
                        "payload": response.get("payload"),
                        "confidence": response.get("confidence", 0),
                        "evidence": response.get("reason", ""),
                        "auth_role": response.get("auth_role", "anonymous"),
                        "exploitable": response.get("exploitable", False),
                        "exploit_context": response.get("exploit_context", {}),
                    }
                    new_vulns.append(vuln)

        # Update state with propagated vulnerabilities
        if confirmed or new_vulns:
            confirmed = self._dedupe_vulnerabilities(confirmed + new_vulns)
            self.state.update(confirmed_vulnerabilities=confirmed)
            # 🔥 FIX: SYNC confirmed_vulnerabilities INTO vulnerabilities
            existing_vulns = self.state.get("vulnerabilities", []) or []
            all_vulns = self._dedupe_vulnerabilities(existing_vulns + confirmed)
            self.state.update(vulnerabilities=all_vulns)
            logger.debug(
                f"[SCANNING] Synced {len(confirmed)} vulnerabilities to vulnerabilities field"
            )

    def _dedupe_vulnerabilities(
        self, vulns: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        deduped = {}
        for vuln in vulns:
            normalized_vuln = normalize_finding(vuln, self.endpoint_registry.normalizer)
            if not normalized_vuln:
                continue
            key = finding_identity(normalized_vuln, self.endpoint_registry.normalizer)
            current = deduped.get(key)
            if current is None or float(
                normalized_vuln.get("confidence", 0) or 0
            ) >= float(current.get("confidence", 0) or 0):
                deduped[key] = normalized_vuln
        return list(deduped.values())

    def _write_manifest(self):
        """Write a lightweight manifest of scanner artifacts for later phases and resume/debug."""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            vulnerabilities = self.state.get("vulnerabilities", []) or []
            artifact_entries = []
            for vuln in vulnerabilities:
                artifact_path = vuln.get("artifact_path")
                raw_output_path = vuln.get("raw_output_path")
                if artifact_path or raw_output_path:
                    artifact_entries.append(
                        {
                            "tool": vuln.get("tool", vuln.get("source", "unknown")),
                            "url": vuln.get("url") or vuln.get("endpoint", ""),
                            "type": vuln.get("type", ""),
                            "artifact_path": artifact_path,
                            "raw_output_path": raw_output_path,
                        }
                    )

            manifest = {
                "phase": "scanner",
                "scan_results_file": self.scan_results_file,
                "counts": {
                    "vulnerabilities": len(vulnerabilities),
                    "confirmed_vulnerabilities": len(
                        self.state.get("confirmed_vulnerabilities", []) or []
                    ),
                },
                "tool_artifacts": artifact_entries,
            }
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
        except Exception as e:
            logger.warning(f"[SCANNING] Failed to write manifest: {e}")

    def scan_endpoint(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Scan a single endpoint with AI-generated payloads"""
        record = self.phase_admission.register(endpoint)
        if not record or not self.phase_admission.is_phase_candidate(record, "scan"):
            return []

        url = self._canonicalize_scan_url(record.get("url", ""))
        record = self.endpoint_registry.register({**record, "url": url})
        if not record or not self.phase_admission.is_phase_candidate(record, "scan"):
            return []

        hostname = record.get("host") or ""
        if hostname and get_optimizer().is_host_blacklisted(hostname):
            self._log_blacklisted_host_once(hostname, "scan execution")
            return []

        # Thread-safe check: skip endpoints already scanned in this or a previous run
        with self._scanned_lock:
            if url in self._scanned_in_run:
                logger.debug(f"[SCANNING] Endpoint already scanned, skipping: {url[:80]}")
                return []
        url = url.replace("\\/", "/").replace("\\/", "/")  # fix escaped slashes

        if not self._is_valid_url(url):
            logger.warning(f"[SCANNING] Skipping malformed URL: {url[:100]}")
            return []
        if not self._is_url_in_scope(url):
            logger.debug(f"[SCANNING] Skipping off-scope URL: {url}")
            return []

        categories = record.get("categories", []) or []
        parameters = record.get("parameters", []) or []

        # FIX: If no URL, skip
        if not url or not isinstance(url, str):
            logger.warning(f"[SCANNING] Invalid URL: {url}, skipping")
            return []

        # BUG 4 FIX: Skip static assets
        _parsed = urllib.parse.urlparse(url)
        if self.endpoint_registry.normalizer.is_static_asset(record):
            logger.debug(f"[SCANNING] Skipping static asset: {url}")
            return []

        # FIX: Auto-detect categories if empty (fallback heuristic)
        if not categories:
            detected = []
            url_lower = url.lower()

            # 🔥 FIX: Thêm detection cho WordPress và XML-RPC
            if "xmlrpc" in url_lower:
                detected.append("rpc")
                detected.append("command_injection")  # XML-RPC có thể dẫn đến RCE
            if "wp-" in url_lower or "wordpress" in url_lower:
                detected.append("wordpress")
            if any(
                kw in url_lower
                for kw in ["admin", "login", "auth", "panel", "wp-admin"]
            ):
                detected.append("authentication")
            if any(
                kw in url_lower
                for kw in ["upload", "file", "attachment", "wp-content/uploads"]
            ):
                detected.append("file_upload")
            if any(kw in url_lower for kw in ["api", "json", "graphql", "wp-json"]):
                detected.append("api_injection")
            if any(
                kw in url_lower for kw in ["search", "query", "id=", "q=", "p=", "cat="]
            ):
                detected.append("injection")
                detected.append("command_injection")

            # 🔥 FIX: Fallback mặc định
            if not detected:
                detected.append("general")
                detected.append("injection")  # Luôn test injection
                categories = detected
            else:
                categories = detected

            logger.debug(f"[SCANNING] Auto-detected categories for {url}: {categories}")
        # FIX: Auto-detect parameters from URL if empty
        if not parameters:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                params_dict = urllib.parse.parse_qs(parsed.query)
                parameters = list(params_dict.keys())
                logger.debug(
                    f"[SCANNING] Auto-detected parameters from URL: {parameters}"
                )
            else:
                logger.debug(
                    f"[SCANNING] No parameters found for {url} - will skip payload generation"
                )

        logger.debug(
            f"[SCANNING] Scanning {url} (categories: {categories}, params: {parameters})"
        )

        host = _parsed.hostname or _parsed.netloc or url
        if host in getattr(self.http_client, "_dead_hosts", set()):
            logger.debug(f"[SCANNING] Skipping dead host before scan: {host}")
            return []
        if not self._is_valid_url(url):
            logger.debug(
                f"[SCANNING] Skipping invalid endpoint before payload generation: {url}"
            )
            return []

        # Store first parameter for exploitation context
        first_param = parameters[0] if parameters else None

        responses = []
        auth_contexts = self._get_auth_contexts()

        # Get baseline response (normal request without payload)
        self._apply_host_backpressure(host)
        baseline_response = self.get_baseline_response(url)
        if not baseline_response:
            logger.debug(f"[SCANNING] Failed to get baseline for {url}")
            self._mark_endpoint_state(
                url,
                baseline_unreliable=True,
                reachable=False,
                categories=categories,
                parameters=parameters,
            )
        else:
            self._mark_endpoint_state(
                url,
                baseline_unreliable=False,
                reachable=True,
                baseline_status=baseline_response.get("status_code", 0),
                baseline_response_time=baseline_response.get("response_time", 0),
                categories=categories,
                parameters=parameters,
            )

        # Mark as scanned in the thread-safe in-memory set (flushed to state at pool teardown)
        with self._scanned_lock:
            self._scanned_in_run.add(url)

        if not baseline_response:
            return []

        endpoint_score = self._estimate_endpoint_score(url, categories, parameters)

        tool_plan = self._build_tool_plan(
            record, url, categories, parameters, endpoint_score
        )

        _tools_selected = [t for t in ("sqlmap", "dalfox", "nuclei") if tool_plan.get(t)]
        logger.info(
            "[SCAN] %s | score=%d | tools=%s | params=%s",
            url[:80],
            endpoint_score,
            ",".join(_tools_selected) or "payload-only",
            ",".join(str(p) for p in parameters[:5]) or "none",
        )

        # Decision logic: build tool execution from endpoint metadata and prior recon context.
        if tool_plan["sqlmap"]:
            _t0 = time.time()
            logger.info("[SCAN] sqlmap starting → %s (timeout=%ds)", url[:70], tool_plan["sqlmap_timeout"])
            self._apply_host_backpressure(host)
            sqlmap_result = self._run_sqlmap(
                url, parameters, timeout=tool_plan["sqlmap_timeout"]
            )
            _elapsed = time.time() - _t0
            if sqlmap_result.get("error") and "timeout" in str(sqlmap_result.get("error", "")).lower():
                self._set_scan_incomplete(f"sqlmap timeout on {url}")
                logger.warning("[SCAN] sqlmap timed out after %.0fs → %s", _elapsed, url[:70])
            else:
                logger.info("[SCAN] sqlmap done in %.0fs → %s | vuln=%s", _elapsed, url[:70], sqlmap_result.get("vulnerable", False))
        if tool_plan["dalfox"]:
            _t0 = time.time()
            logger.info("[SCAN] dalfox starting → %s (timeout=%ds)", url[:70], tool_plan["dalfox_timeout"])
            self._apply_host_backpressure(host)
            dalfox_result = self.dalfox_runner.run(
                url, timeout=tool_plan["dalfox_timeout"]
            )
            _elapsed = time.time() - _t0
            self._promote_dalfox_result(url, dalfox_result)
            if dalfox_result.get("error") == "timeout":
                self._set_scan_incomplete(f"dalfox timeout on {url}")
                logger.warning("[SCAN] dalfox timed out after %.0fs → %s", _elapsed, url[:70])
            else:
                logger.info("[SCAN] dalfox done in %.0fs → %s | findings=%d", _elapsed, url[:70], len(dalfox_result.get("findings", [])))

        # Resource Management: Initialize nuclei pool and concurrency manager on first use
        if not hasattr(self, "_nuclei_pool"):
            self._nuclei_pool = get_nuclei_pool(max_workers=3, default_timeout=300)
            # Use a local semaphore sized to match the pool to avoid threads
            # blocking indefinitely waiting for queued nuclei futures.
            self._nuclei_concurrency = threading.Semaphore(3)
            self._nuclei_concurrency_slots: set = set()
            self._nuclei_concurrency_lock = threading.Lock()

        # Run nuclei for general scan using NucleiWorkerPool
        # BUG 6 FIX: Only run on URLs with real query params or important keywords
        parsed_url = urllib.parse.urlparse(url)
        has_real_query_params = bool(parsed_url.query)
        important_keywords = ["wp-admin", "api", "login", "admin", "graphql"]
        url_lower = url.lower()
        has_important_keyword = any(kw in url_lower for kw in important_keywords)

        if tool_plan["nuclei"] and (
            has_real_query_params or has_important_keyword or tool_plan["nuclei_tags"]
        ):
            # Resource Management: Use NucleiWorkerPool with concurrency control
            # Semaphore sized to pool max_workers=3 so callers don't pile up waiting
            if self._nuclei_concurrency.acquire(blocking=True, timeout=30):
                try:
                    self._apply_host_backpressure(host)
                    # Submit scan to the worker pool for managed execution
                    scan = self._nuclei_pool.submit_scan(
                        url,
                        lambda u, timeout: self.nuclei_runner.run(
                            u,
                            timeout=tool_plan["nuclei_timeout"],
                            tags=tool_plan["nuclei_tags"],
                            severity=tool_plan["nuclei_severity"],
                        ),
                    )
                    # Wait for result with timeout
                    try:
                        nuclei_result = scan["future"].result(timeout=tool_plan["nuclei_timeout"] + 30)
                        self._promote_nuclei_result(url, nuclei_result)
                        if not nuclei_result.get("success") and nuclei_result.get("error"):
                            err_str = str(nuclei_result.get("error", ""))
                            # Ignore known non-critical nuclei stderr warnings that are not
                            # real scan failures (missing API keys, info-level messages, etc.)
                            _noncrit = (
                                "GOOGLE_API_KEY" in err_str
                                or "GOOGLE_API_CX" in err_str
                                or "No results" in err_str
                                or err_str.strip() == ""
                            )
                            if not _noncrit:
                                self._set_scan_incomplete(
                                    f"nuclei issue on {url}: {err_str[:80]}"
                                )
                            else:
                                logger.debug(
                                    "[SCAN] nuclei non-critical warning on %s: %s",
                                    url[:60], err_str[:80]
                                )
                    except concurrent.futures.TimeoutError:
                        self._set_scan_incomplete(f"nuclei timeout on {url}")
                        logger.warning(f"[SCANNING] Nuclei scan timed out for {url}")
                except Exception as e:
                    self._set_scan_incomplete(
                        f"nuclei pool error on {url}: {str(e)[:80]}"
                    )
                    logger.error(f"[SCANNING] Nuclei pool error for {url}: {e}")
                finally:
                    self._nuclei_concurrency.release()
            else:
                self._set_scan_incomplete(f"nuclei concurrency saturation on {url}")
                logger.warning(
                    f"[SCANNING] Could not acquire concurrency slot for nuclei on {url}"
                )

        # Generate payloads based on endpoint type
        if parameters:
            for category in categories:
                allow_ai_payloads = endpoint_score >= config.AI_PAYLOAD_MIN_SCORE
                if category == "xss":
                    payload_values = self.payload_gen.generate_xss(
                        self._detect_xss_context(baseline_response.get("content", "")),
                        self.get_max_payloads_for_category(category),
                        endpoint_url=url,
                        tech_stack=list(self.state.get("tech_stack", []) or []),
                    )
                else:
                    payload_items = self.payload_gen.generate_for_category(
                        category,
                        parameters,
                        include_ai=allow_ai_payloads,
                        endpoint_url=url,
                        tech_stack=list(self.state.get("tech_stack", []) or []),
                    )
                    payload_values = [
                        item.get("value", "")
                        for item in payload_items
                        if isinstance(item, dict) and item.get("value")
                    ]

                if not payload_values:
                    continue

                score_based_max = min(
                    config.PAYLOAD_MUTATION_MAX, max(4, endpoint_score)
                )
                if endpoint_score >= config.PAYLOAD_MUTATION_MIN_SCORE:
                    mutated_payloads = self.payload_mutator.mutate_payloads(
                        payload_values
                    )[:score_based_max]
                    candidate_payloads = self._dedupe_payloads(
                        payload_values + mutated_payloads
                    )
                else:
                    candidate_payloads = self._dedupe_payloads(payload_values)[
                        :score_based_max
                    ]
                logger.debug(
                    f"[SCANNING] Endpoint score: {endpoint_score} → {len(candidate_payloads)} payloads for {url}"
                )

                # Determine payload count based on category risk
                max_payloads = self.get_max_payloads_for_category(category)

                # Test payloads
                for payload_item in candidate_payloads[:max_payloads]:
                    payload = {}
                    try:
                        # Normalize payload to dictionary format
                        if isinstance(payload_item, str):
                            payload_value = payload_item

                        elif isinstance(payload_item, dict):
                            payload_value = payload_item.get("value", "")
                        else:
                            logger.warning(
                                f"Skipping unknown payload type: {type(payload_item)}"
                            )
                            continue
                        payload = {
                            "value": payload_value,
                            "method": "GET",
                            "params": {},
                        }

                        payload_succeeded = False
                        for auth_ctx in auth_contexts:
                            response = self.test_payload(
                                url, payload, category, baseline_response, auth_ctx
                            )
                            response["auth_role"] = auth_ctx.get("role")
                            responses.append(response)
                            self._run_ai_scan(url, payload_value, response)

                            if response.get("vulnerable"):
                                payload_succeeded = True
                                # FIX: Mark exploitable if confidence is high
                                if response.get("confidence", 0) >= 0.7:
                                    response["exploitable"] = True
                                    response["exploit_context"] = {
                                        "category": category,
                                        "injection_point": first_param or "url",
                                        "auth_role": auth_ctx.get("role", "anonymous"),
                                    }
                                self.learning_engine.add_successful_payload(
                                    payload, category
                                )
                            else:
                                response["exploitable"] = False
                                response["exploit_context"] = {}

                        if (
                            not payload_succeeded
                            and endpoint_score >= config.PAYLOAD_MUTATION_MIN_SCORE
                        ):
                            # Mutate and retry on failure - using the original string value
                            payload_value = payload.get("value", "")
                            if not isinstance(payload_value, str):
                                continue  # Cannot mutate non-string value

                            mutated = self.payload_mutator.mutate_payloads(
                                [payload_value]
                            )
                            for p_str in mutated[:2]:
                                # Normalize again for testing
                                p = {"value": p_str, "method": "GET", "params": {}}
                                resp = self.test_payload(
                                    url, p, category, baseline_response, auth_ctx
                                )
                                resp["auth_role"] = auth_ctx.get("role")
                                responses.append(resp)
                                self._run_ai_scan(url, p_str, resp)
                                if resp.get("vulnerable"):
                                    self.learning_engine.add_successful_payload(
                                        p, category
                                    )
                                    break

                        # Small delay to avoid overwhelming
                        time.sleep(config.SCAN_PAYLOAD_DELAY)

                    except Exception as e:
                        if self._is_name_resolution_error(e):
                            logger.warning(
                                f"[SCANNING] DNS resolution failed for {url}; skipping remaining payloads"
                            )
                            break
                        logger.error(
                            f"[PAYLOAD] Failed to test payload on {url}: {e} (payload: {payload})"
                        )
        else:
            logger.debug(
                f"[SCANNING] Skipping payload generation for {url} - no parameters detected (00-param endpoint)"
            )

        if not responses and baseline_response:
            responses.append(
                {
                    "endpoint": url,
                    "url": url,
                    "method": "GET",
                    "status_code": baseline_response.get("status_code", 0),
                    "content_length": baseline_response.get("content_length", 0),
                    "response_time": baseline_response.get("response_time", 0),
                    "baseline_status": baseline_response.get("status_code", 0),
                    "baseline_length": baseline_response.get("content_length", 0),
                    "baseline_time": baseline_response.get("response_time", 0),
                    "category": "baseline",
                    "vulnerable": False,
                    "confidence": 0,
                    "reason": "baseline_only_seed_scan",
                    "timestamp": time.time(),
                }
            )

        return responses

    def _estimate_endpoint_score(
        self, url: str, categories: List[str], parameters: List[str]
    ) -> int:
        score = 5
        if "api" in categories or "/api/" in url or "/json" in url:
            score = 8
        if "authentication" in categories or "/login" in url or "/auth" in url:
            score = max(score, 7)
        if "command_injection" in categories or "sql_injection" in categories:
            score = max(score, 9)
        if len(parameters) > 2:
            score += 2
        if "?" in url:
            score += 1
        return min(10, score)

    def _dedupe_payloads(self, payloads: List[str]) -> List[str]:
        seen = set()
        merged = []
        for payload in payloads:
            if not payload or payload in seen:
                continue
            seen.add(payload)
            merged.append(payload)
        return merged

    def get_baseline_response(self, url: str) -> Dict[str, Any]:
        """Get baseline response for comparison and tech fingerprinting"""
        normalized_url = self.endpoint_registry.normalizer.normalize_url(url)
        if not normalized_url or not self._is_valid_url(normalized_url):
            logger.debug(f"[SCANNING] Skipping baseline for invalid URL: {url[:100]}")
            return None
        if normalized_url in self._baseline_cache:
            return self._baseline_cache[normalized_url]

        try:
            response = self.http_client.get(normalized_url, timeout=10)

            # Detect tech stack
            tech_detected = self._detect_tech_stack(response)
            if tech_detected:
                current_tech = set(self.state.get("tech_stack", []))
                current_tech.update(tech_detected)
                self.state.update(tech_stack=list(current_tech))

            baseline = {
                "status_code": response.status_code,
                "content_length": len(response.text),
                "response_time": response.elapsed.total_seconds()
                if hasattr(response, "elapsed")
                else 0,
                "content": response.text,
                "headers": dict(response.headers),
                "tech": tech_detected,
            }
            self._baseline_cache[normalized_url] = baseline
            return baseline
        except ConnectionError as e:
            if self._is_name_resolution_error(e) or "Skipping dead host:" in str(e):
                logger.warning(
                    f"[SCANNING] Skipping unreachable host {normalized_url}: {e}"
                )
                self._baseline_cache[normalized_url] = None
                return None
            logger.debug(
                f"[SCANNING] Baseline request failed for {normalized_url}: {e}"
            )
            self._baseline_cache[normalized_url] = None
            return None
        except Exception as e:
            logger.debug(
                f"[SCANNING] Baseline request failed for {normalized_url}: {e}"
            )
            self._baseline_cache[normalized_url] = None
            return None

    def _is_name_resolution_error(self, error: Exception) -> bool:
        current = error
        visited = set()
        while current and id(current) not in visited:
            visited.add(id(current))
            if isinstance(current, NameResolutionError):
                return True
            if (
                "name resolution" in str(current).lower()
                or "failed to resolve" in str(current).lower()
            ):
                return True
            current = getattr(current, "__cause__", None) or getattr(
                current, "__context__", None
            )
        return False

    def _detect_tech_stack(self, response) -> set:
        """Detect technology stack from response"""
        tech = set()
        headers = response.headers
        body = response.text.lower()

        # Server headers
        server = headers.get("server", "").lower()
        if "apache" in server:
            tech.add("apache")
        if "nginx" in server:
            tech.add("nginx")
        if "iis" in server:
            tech.add("iis")

        # Powered by
        powered_by = headers.get("x-powered-by", "").lower()
        if "php" in powered_by:
            tech.add("php")
        if "asp.net" in powered_by:
            tech.add("asp.net")
        if "nodejs" in powered_by or "node" in powered_by:
            tech.add("nodejs")

        # Body patterns
        if "wp-content" in body or "wordpress" in body:
            tech.add("wordpress")
        if "laravel" in body or "csrf-token" in body:
            tech.add("laravel")
        if "jquery" in body:
            tech.add("jquery")
        if "bootstrap" in body:
            tech.add("bootstrap")
        if "react" in body:
            tech.add("react")
        if "vue" in body:
            tech.add("vue")
        if "angular" in body:
            tech.add("angular")

        # API patterns
        if "/api/" in body or "swagger" in body:
            tech.add("api")
        if "graphql" in body:
            tech.add("graphql")

        return tech

    def get_max_payloads_for_category(self, category: str) -> int:
        """Determine maximum payloads to test based on category risk"""
        high_risk = ["sql_injection", "command_injection", "xss", "file_inclusion"]
        if category in high_risk:
            return 20  # More payloads for high-risk categories
        return 10  # Default

    def test_payload(
        self,
        url: str,
        payload: Dict[str, Any],
        category: str,
        baseline: Dict[str, Any],
        auth_ctx: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Test a single payload against an endpoint with baseline comparison and WAF bypass"""
        safe_baseline = baseline or {
            "status_code": 0,
            "content_length": 0,
            "response_time": 0,
            "content": "",
            "headers": {},
        }

        if not self._is_valid_url(url):
            logger.debug(f"[SCANNING] Skipping invalid absolute URL: {url[:100]}")
            return {
                "endpoint": url,
                "payload": payload.get("value", ""),
                "method": payload.get("method", "GET"),
                "status_code": 0,
                "content_length": 0,
                "response_time": 0,
                "baseline_status": safe_baseline.get("status_code", 0),
                "baseline_length": safe_baseline.get("content_length", 0),
                "baseline_time": safe_baseline.get("response_time", 0),
                "category": category,
                "vulnerable": False,
                "confidence": 0,
                "reason": "Invalid absolute URL",
                "timestamp": time.time(),
            }

        # FILTER: Skip non-scannable URLs (mailto:, tel:, javascript:, data:, etc.)
        # These URLs cannot be exploited and waste WAF bypass attempts
        from urllib.parse import urlparse

        parsed_url = urllib.parse.urlparse(url)
        if parsed_url.scheme in ["mailto", "tel", "javascript", "data", "file", "ftp"]:
            logger.debug(f"[SCANNING] Skipping non-scannable URL scheme: {url[:100]}")
            return {
                "endpoint": url,
                "payload": payload.get("value", ""),
                "method": "GET",
                "status_code": 0,
                "content_length": 0,
                "response_time": 0,
                "baseline_status": safe_baseline.get("status_code", 0),
                "baseline_length": safe_baseline.get("content_length", 0),
                "baseline_time": safe_baseline.get("response_time", 0),
                "category": category,
                "vulnerable": False,
                "confidence": 0,
                "reason": "Non-scannable URL scheme (mailto/tel/javascript/data/file/ftp)",
                "timestamp": time.time(),
            }

        # FILTER: Skip URLs with no path or just root path and no query params
        # These are unlikely to have injection points
        if not parsed_url.path or parsed_url.path == "/":
            if not parsed_url.query:
                logger.debug(f"[SCANNING] Skipping URL with no path/query: {url[:100]}")
                return {
                    "endpoint": url,
                    "payload": payload.get("value", ""),
                    "method": "GET",
                    "status_code": 0,
                    "content_length": 0,
                    "response_time": 0,
                    "baseline_status": safe_baseline.get("status_code", 0),
                    "baseline_length": safe_baseline.get("content_length", 0),
                    "baseline_time": safe_baseline.get("response_time", 0),
                    "category": category,
                    "vulnerable": False,
                    "confidence": 0,
                    "reason": "URL has no injectable path or query parameters",
                    "timestamp": time.time(),
                }

        payload_value = payload.get("value", "")
        method = payload.get("method", "GET")
        params = payload.get("params", {})
        auth_ctx = auth_ctx or {}
        req_headers = auth_ctx.get("headers", {}) or {}
        req_cookies = auth_ctx.get("cookies", {}) or {}

        max_retries = 3
        # BUG 5 FIX: Cap mutations to 3, not unlimited
        mutations = self.payload_mutator._apply_waf_bypass(payload_value)[:3]
        import random

        random.shuffle(mutations)  # Randomize order

        waf_bypass_failed = False
        for mutation in [
            payload_value
        ] + mutations:  # Try original first, then mutations
            waf_bypass_attempted = mutation != payload_value

            for attempt in range(max_retries):
                try:
                    response = None
                    # Prepare request - TEST ALL PARAMETERS, NOT JUST FIRST
                    if method == "GET":
                        parsed = urllib.parse.urlparse(url)
                        query_pairs = urllib.parse.parse_qsl(
                            parsed.query, keep_blank_values=True
                        )

                        if query_pairs:
                            # Test injection in each parameter
                            for param_idx in range(len(query_pairs)):
                                param_key = query_pairs[param_idx][0]
                                test_pairs = list(query_pairs)
                                test_pairs[param_idx] = (param_key, mutation)
                                new_query = urllib.parse.urlencode(
                                    test_pairs, doseq=True
                                )
                                test_url = urllib.parse.urlunparse(
                                    parsed._replace(query=new_query)
                                )
                                try:
                                    if not self._is_valid_url(test_url):
                                        logger.debug(
                                            f"[SCANNING] Skipping invalid test URL: {test_url[:100]}"
                                        )
                                        continue
                                    response = self.http_client.get(
                                        test_url,
                                        timeout=10,
                                        headers=req_headers,
                                        cookies=req_cookies,
                                    )
                                    if not self._is_waf_blocked(response):
                                        analysis = self.analyze_response(
                                            response,
                                            safe_baseline,
                                            {"value": mutation},
                                            category,
                                        )
                                        if analysis.get("vulnerable"):
                                            return {
                                                "endpoint": url,
                                                "payload": mutation,
                                                "method": method,
                                                "status_code": response.status_code,
                                                "content_length": len(response.text),
                                                "response_time": response.elapsed.total_seconds()
                                                if hasattr(response, "elapsed")
                                                else 0,
                                                "baseline_status": safe_baseline.get(
                                                    "status_code", 0
                                                ),
                                                "baseline_length": safe_baseline.get(
                                                    "content_length", 0
                                                ),
                                                "baseline_time": safe_baseline.get(
                                                    "response_time", 0
                                                ),
                                                "category": category,
                                                "vulnerable": True,
                                                "confidence": analysis.get(
                                                    "confidence", 0
                                                ),
                                                "reason": analysis.get("reason", ""),
                                                "param": param_key,
                                                "timestamp": time.time(),
                                            }
                                except Exception as inner_error:
                                    logger.debug(
                                        f"[SCANNING] Parameter payload request failed for {test_url[:100]}: {inner_error}"
                                    )
                        else:
                            inject_key = (
                                next(iter(params.keys()), "q")
                                if isinstance(params, dict)
                                else "q"
                            )
                            safe_mutation = urllib.parse.quote(mutation, safe="")
                            new_query = f"{inject_key}={safe_mutation}"
                            test_url = urllib.parse.urlunparse(
                                parsed._replace(query=new_query)
                            )
                            if not self._is_valid_url(test_url):
                                logger.debug(
                                    f"[SCANNING] Skipping invalid test URL: {test_url[:100]}"
                                )
                                continue
                            response = self.http_client.get(
                                test_url,
                                timeout=10,
                                headers=req_headers,
                                cookies=req_cookies,
                            )
                    elif method == "POST":
                        post_data = dict(params) if isinstance(params, dict) else {}
                        if post_data:
                            first_key = next(iter(post_data.keys()))
                            post_data[first_key] = mutation
                        else:
                            post_data = {"q": mutation}
                        response = self.http_client.post(
                            url,
                            data=post_data,
                            timeout=10,
                            headers=req_headers,
                            cookies=req_cookies,
                        )
                    else:
                        # Default to GET
                        response = self.http_client.get(
                            url, timeout=10, headers=req_headers, cookies=req_cookies
                        )

                    if response is None:
                        raise ValueError(
                            "No valid request could be issued for payload test"
                        )

                    # Check for WAF blocking
                    if self._is_waf_blocked(response):
                        if not waf_bypass_attempted:
                            break  # Try next mutation
                        else:
                            logger.debug(f"[WAF] Bypass failed for {url}")
                            waf_bypass_failed = True
                            continue  # Try next attempt

                    # If we reach here, WAF bypassed or no WAF
                    if waf_bypass_attempted:
                        logger.info(f"[WAF] Bypass successful with mutation for {url}")

                    # Analyze response with baseline comparison
                    analysis = self.analyze_response(
                        response, safe_baseline, {"value": mutation}, category
                    )

                    if analysis.get("vulnerable"):
                        confidence = analysis.get("confidence", 0)

                        logger.info(
                            f"[VULN] Potential {category} vulnerability detected on {url} (confidence: {confidence})"
                        )

                        # 🔥 FIX: PUSH VÀO confirmed_vulnerabilities
                        if confidence >= 0.5:
                            vuln = {
                                "type": category,
                                "url": url,
                                "payload": mutation,
                                "confidence": confidence,
                                "source": "ai",
                                "evidence": analysis.get("reason", ""),
                            }

                            # 🔥 HIGH CONF → cho phép exploit phase dùng
                            if confidence >= 0.5:
                                vuln["exploitable"] = True
                                vuln["exploit_context"] = {
                                    "category": category,
                                    "injection_point": url,
                                }

                            current_vulns = self.state.get("vulnerabilities", [])
                            current_vulns.append(vuln)
                            self.state.update(
                                vulnerabilities=self._dedupe_vulnerabilities(
                                    current_vulns
                                )
                            )

                            confirmed = self.state.get("confirmed_vulnerabilities", [])
                            confirmed.append(vuln)
                            self.state.update(
                                confirmed_vulnerabilities=self._dedupe_vulnerabilities(
                                    confirmed
                                )
                            )

                    return {
                        "endpoint": url,
                        "payload": mutation,
                        "method": method,
                        "status_code": response.status_code,
                        "content_length": len(response.text),
                        "response_time": response.elapsed.total_seconds()
                        if hasattr(response, "elapsed")
                        else 0,
                        "baseline_status": safe_baseline["status_code"],
                        "baseline_length": safe_baseline["content_length"],
                        "baseline_time": safe_baseline["response_time"],
                        "category": category,
                        "vulnerable": analysis.get("vulnerable", False),
                        "confidence": analysis.get("confidence", 0),
                        "reason": analysis.get("reason", ""),
                        "timestamp": time.time(),
                    }
                except Exception as e:
                    if self._is_name_resolution_error(e):
                        logger.warning(
                            f"[SCANNING] DNS resolution failed for {url}; skipping remaining payloads"
                        )
                        return {
                            "endpoint": url,
                            "payload": payload_value,
                            "method": method,
                            "status_code": 0,
                            "content_length": 0,
                            "response_time": 0,
                            "baseline_status": safe_baseline.get("status_code", 0),
                            "baseline_length": safe_baseline.get("content_length", 0),
                            "baseline_time": safe_baseline.get("response_time", 0),
                            "category": category,
                            "vulnerable": False,
                            "confidence": 0,
                            "reason": "DNS resolution failed - malformed URL",
                            "timestamp": time.time(),
                        }
                    if attempt == max_retries - 1:
                        logger.debug(
                            f"[SCANNING] Payload test failed after {max_retries} attempts: {e}"
                        )
                        # Return a failed result
                        return {
                            "endpoint": url,
                            "payload": mutation,
                            "method": method,
                            "status_code": 0,
                            "content_length": 0,
                            "response_time": 0,
                            "baseline_status": safe_baseline["status_code"],
                            "baseline_length": safe_baseline["content_length"],
                            "baseline_time": safe_baseline["response_time"],
                            "category": category,
                            "vulnerable": False,
                            "confidence": 0,
                            "reason": "Request failed",
                            "timestamp": time.time(),
                        }
                    time.sleep(1)  # Wait before retry

            # BUG 5 FIX: If all WAF bypass mutations failed, stop and return early
            if waf_bypass_attempted and waf_bypass_failed:
                logger.debug(f"[WAF] Max bypass attempts reached for {url}, skipping")
                return {
                    "endpoint": url,
                    "payload": payload_value,
                    "method": method,
                    "status_code": 403,
                    "content_length": 0,
                    "response_time": 0,
                    "baseline_status": safe_baseline.get("status_code", 0),
                    "baseline_length": safe_baseline.get("content_length", 0),
                    "baseline_time": safe_baseline.get("response_time", 0),
                    "category": category,
                    "vulnerable": False,
                    "confidence": 0,
                    "reason": "WAF blocking - max bypass attempts reached",
                    "timestamp": time.time(),
                }

            # If all retries failed for this mutation, try next
            if waf_bypass_attempted:
                continue

        # All mutations failed
        return {
            "endpoint": url,
            "payload": payload_value,
            "method": method,
            "status_code": 0,
            "content_length": 0,
            "response_time": 0,
            "baseline_status": safe_baseline["status_code"],
            "baseline_length": safe_baseline["content_length"],
            "baseline_time": safe_baseline["response_time"],
            "category": category,
            "vulnerable": False,
            "confidence": 0,
            "reason": "All WAF bypass attempts failed",
            "timestamp": time.time(),
        }

    def _is_waf_blocked(self, response) -> bool:
        """Detect if response indicates WAF blocking - IMPROVED

        FIX: Phân biệt rõ WAF block vs các lỗi khác để giảm false positive.
        Chỉ coi là WAF block khi có bằng chứng rõ ràng (WAF signatures).
        """
        # Case 1: 403/406 status codes - need to check for WAF signatures
        if response.status_code in [403, 406]:
            headers_str = str(response.headers).lower()
            body = response.text.lower()

            # Strong WAF signatures only (specific WAF products)
            strong_waf_signs = [
                "cloudflare",
                "akamai",
                "sucuri",
                "mod_security",
                "wordfence",
                "imperva",
                "x-sucuri-id",
                "cf-ray",
                "aws waf",
                "f5 traefik",
                "big-ip",
                "netscaler",
            ]

            if any(sign in headers_str or sign in body for sign in strong_waf_signs):
                logger.debug(
                    f"[WAF] Confirmed WAF blocking (status {response.status_code})"
                )
                return True

            # 403/406 without WAF signature is likely auth/authz issue, not WAF
            logger.debug(
                f"[WAF] Status {response.status_code} without WAF signature - likely auth issue, not WAF"
            )
            return False

        # Case 2: Connection errors (status 0) are NOT WAF blocks
        if response.status_code == 0:
            logger.debug(f"[WAF] Connection error (status 0) - not WAF block")
            return False

        # Case 3: Rate limiting (429) is not WAF block per se
        if response.status_code == 429:
            logger.debug(f"[WAF] Rate limiting (429) - not WAF block")
            return False

        # Case 4: Server errors (5xx) are not WAF blocks
        if response.status_code >= 500:
            logger.debug(f"[WAF] Server error ({response.status_code}) - not WAF block")
            return False

        return False

    def _apply_waf_bypass(self, payload: str, category: str) -> List[str]:
        """Apply multiple WAF bypass mutations - FIX 4: Enhanced with more techniques"""
        mutations = []

        if category in ["sqli", "sql_injection"]:
            mutations = [
                # Standard comment injection
                payload.replace(" ", "/**/"),
                payload.replace("UNION", "UN/**/ION"),
                payload.replace("SELECT", "SEL/**/ECT"),
                # Quote handling
                payload.replace("'", "''"),
                payload.replace("'", "\\'"),
                # Case mangling
                payload.upper(),
                payload.swapcase(),
                # Whitespace alternatives
                payload.replace(" ", "%20"),
                payload.replace(" ", "%0a"),
                payload.replace(" ", "%09"),  # Tab
                # Nested comments
                payload.replace("SELECT", "SEL/*comment*/ECT"),
                payload.replace("UNION", "UNI/*x*/ON"),
                # Encoding
                urllib.parse.quote(payload),
                urllib.parse.quote(urllib.parse.quote(payload)),
            ]
        elif category in ["xss"]:
            mutations = [
                # Case variation
                payload.replace("script", "ScRiPt"),
                payload.replace("SCRIPT", "ScRiPt"),
                payload.replace("alert", "AlErT"),
                # Null byte
                payload.replace("<", "<%00"),
                payload.replace(">", ">%00"),
                # HTML entities
                payload.replace("<", "&lt;").replace(">", "&gt;"),
                # Encoded
                base64.b64encode(payload.encode()).decode(),
                # Alternative tags
                payload.replace("<script>", "<img src=x onerror=>"),
                payload.replace("<script>", "<svg onload=>"),
                payload.replace("<script>", "<iframe src=javascript:>"),
                # Comment injection
                payload.replace("<script>", "<scr<!-- -->ipt>"),
                # Unicode
                payload.replace("alert", "\\u0061lert"),
                # Mixed encoding
                "<scr".upper() + "ipt>",
            ]
        elif category in ["rce", "command_injection"]:
            mutations = [
                # IFS bypass
                payload.replace(" ", "${IFS}"),
                payload.replace(" ", "${IFS}"),
                payload.replace(" ", "%20"),
                payload.replace(" ", "%09"),
                # Command separators
                payload.replace(";", "|"),
                payload.replace(";", "`"),
                payload.replace(";", "&&"),
                payload.replace(";", "||"),
                # Case variation
                payload.swapcase(),
                # Encoded
                urllib.parse.quote(payload),
                # Alternative commands
                payload.replace("cat", "c\\at"),
                payload.replace("cat", "head"),
                payload.replace("id", "/bi\\n/id"),
            ]
        elif category in ["lfi"]:
            mutations = [
                payload.replace("../", "....//"),
                payload.replace("../", "..././"),
                payload.replace("/etc/passwd", "/etc/passwd%00"),
                urllib.parse.quote(payload),
            ]

        # Deduplicate and return
        seen = set()
        result = []
        for m in mutations:
            if m and m not in seen:
                seen.add(m)
                result.append(m)

        return result[:15]  # Limit to 15 mutations

    def analyze_response(
        self, response, baseline: Dict[str, Any], payload: Dict, category: str
    ) -> Dict[str, Any]:
        """
        Analyze response for vulnerability using SCIENTIFIC SCORING.

        Only marks as vulnerable if evidence is strong enough:
        - Payload reflected (XSS) +0.4
        - Response anomaly (DB error) +0.3
        - Confirmed by 2nd payload +0.3

        THRESHOLD: >= 0.5 only
        """
        test_status = response.status_code
        test_length = len(response.text)
        test_time = (
            response.elapsed.total_seconds() if hasattr(response, "elapsed") else 0
        )
        response_text = response.text

        base_status = baseline["status_code"]
        base_length = baseline["content_length"]
        base_time = baseline["response_time"]
        payload_value = payload.get("value", "")

        analysis = {
            "vulnerable": False,
            "confidence": 0.0,
            "reason": "No evidence detected",
            "evidence": [],
        }

        # 1. EVIDENCE 1: Reflection Detection (STRONGEST) +0.4
        reflects = False
        if payload_value and len(payload_value) > 3:
            payload_lower = payload_value.lower()
            response_lower = response_text.lower()

            if payload_lower in response_lower:
                # Check that it's not just in error message
                idx = response_lower.find(payload_lower)
                context = response_lower[max(0, idx - 50) : idx]

                if not any(
                    x in context
                    for x in ["invalid", "error", "rejected", "syntax error"]
                ):
                    reflects = True
                    analysis["confidence"] += 0.4
                    analysis["evidence"].append("Payload reflected in response")

        # 2. EVIDENCE 2: Response Anomaly (status or error keywords) +0.3 MAX
        anomaly_score = self._check_response_anomaly(
            response_text,
            baseline,
            test_status,
            base_status,
            test_time,
            base_time,
            category,
        )
        if anomaly_score > 0:
            analysis["confidence"] += anomaly_score
            if test_status != base_status:
                analysis["evidence"].append(f"Status code: {base_status}→{test_status}")

        # 3. Content length anomaly - only if minor evidence
        if len(analysis["evidence"]) < 2 and base_length > 0:
            length_diff = abs(test_length - base_length)
            length_ratio = length_diff / base_length
            if length_ratio > 0.5:  # Significant change
                analysis["confidence"] += 0.1
                analysis["evidence"].append(
                    f"Content length changed: {length_diff:+d} bytes"
                )

        # Cap at 1.0
        analysis["confidence"] = min(analysis["confidence"], 1.0)

        # STRICT RULE: Only vulnerable if score >= 0.5
        if analysis["confidence"] >= 0.5:
            analysis["vulnerable"] = True
            analysis["reason"] = (
                f"Evidence verified: {len(analysis['evidence'])} indicators"
            )
        else:
            analysis["reason"] = (
                f"Score {analysis['confidence']:.2f} below 0.5 threshold"
            )

        return analysis

    def _check_response_anomaly(
        self,
        response_text: str,
        baseline: Dict,
        test_status,
        base_status,
        test_time,
        base_time,
        category: str,
    ) -> float:
        """
        Check for real response anomalies (not just random keywords).
        Max +0.3
        """
        score = 0.0

        # DB Error patterns (SQL injection specific)
        if category in ["sql_injection", "sqli"]:
            db_errors = [
                "sql syntax",
                "mysql",
                "postgresql",
                "sqlite",
                "ora-",
                "odbc",
                "you have an error",
                "unclosed quotation",
                "syntax error near",
            ]
            response_lower = response_text.lower()
            found_errors = [e for e in db_errors if e in response_lower]
            if found_errors:
                score += 0.15

        # RCE/Command patterns
        elif category in ["command_injection", "rce"]:
            rce_patterns = ["uid=", "root@", "/bin/", "command not found"]
            response_lower = response_text.lower()
            found_patterns = [p for p in rce_patterns if p in response_lower]
            if found_patterns:
                score += 0.15

        # Timing anomaly (blind injection) - ONLY for SQL timing attacks
        if category in ["sql_injection", "sqli"]:
            time_diff = test_time - base_time
            if time_diff > 3 and base_time < 1:  # Strong indicator
                score += 0.15

        # Status code anomalies (only relevant ones)
        if test_status == 500 and base_status != 500:
            # True server error, not input validation
            if "exception" in response_text.lower() or "error" in response_text.lower():
                score += 0.1

        return min(score, 0.3)

    def _detect_sqli_potential(self, endpoint: Dict[str, Any]) -> bool:
        """Detect if endpoint is likely vulnerable to SQLi"""
        parameters = endpoint.get("parameters", [])
        if not parameters:
            return False
        dangerous = {"id", "user", "uid", "page", "item", "cat", "query", "search", "q"}
        return any(str(p).lower() in dangerous for p in parameters)

    def _detect_xss_potential(self, endpoint: Dict[str, Any]) -> bool:
        """Detect if endpoint is likely vulnerable to XSS"""
        parameters = endpoint.get("parameters", [])
        return len(parameters) > 0

    def _get_auth_contexts(self) -> List[Dict[str, Any]]:
        """Return contexts for unauthenticated + authenticated role scans."""
        contexts = [{"role": "anonymous", "cookies": {}, "headers": {}}]
        sessions = self.state.get("authenticated_sessions", [])
        for item in sessions:
            if item.get("success"):
                contexts.append(
                    {
                        "role": item.get("role", "unknown"),
                        "cookies": item.get("cookies", {}) or {},
                        "headers": item.get("headers", {}) or {},
                    }
                )
            if len(contexts) >= 4:
                break
        return contexts

    def _run_sqlmap(
        self, url: str, parameters: List[str], timeout: int = 180
    ) -> Dict[str, Any]:
        """Best-effort sqlmap execution for high-signal parameterized endpoints using SQLMapRunner."""
        if not self.sqlmap_runner.is_sqlmap_available():
            return {"success": False, "error": "sqlmap unavailable"}
        # FIX: Skip sqlmap on placeholder parameters like FUZZ
        if any(p == "FUZZ" for p in parameters):
            logger.debug("[SCANNING] Skipping sqlmap on placeholder parameters")
            return {"success": False, "error": "placeholder parameter"}
        marker = parameters[0] if parameters else "id"
        target = url if "?" in url else f"{url}?{marker}=1"

        # Use SQLMapRunner integration instead of manual implementation
        result = self.sqlmap_runner.run_sqlmap_json(
            url=target,
            level=2,
            risk=1,
            timeout=timeout,
            batch=True,
            additional_args=["--smart"],
        )

        if result.get("vulnerable"):
            self._promote_sqlmap_result(target, result)
            logger.warning(f"[SCANNING] SQLMap found SQLi on {target}")
            # Sync confirmed finding to boolean_sqli_findings.json
            sqli_file = os.path.join(self.output_dir, "boolean_sqli_findings.json")
            try:
                existing_vulns = []
                if os.path.exists(sqli_file):
                    with open(sqli_file) as _f:
                        _d = json.load(_f)
                        existing_vulns = _d if isinstance(_d, list) else _d.get("vulnerabilities", [])
                existing_vulns.append({
                    "url": target,
                    "type": "sql_injection",
                    "severity": "CRITICAL",
                    "confidence": 0.95,
                    "evidence": (result.get("output") or "")[:500],
                    "dbms": result.get("dbms"),
                    "source": "sqlmap",
                    "verified": True,
                })
                with open(sqli_file, "w") as _f:
                    json.dump({"vulnerabilities": existing_vulns}, _f, indent=2)
            except Exception as _e:
                logger.debug(f"[SCANNING] boolean_sqli_findings.json sync failed: {_e}")
        elif result.get("error"):
            logger.debug(
                f"[SCANNING] sqlmap error for {target}: {result['error'][:120]}"
            )
        return result

    def _detect_xss_context(self, response_text: str) -> str:
        """Detect XSS context from response"""
        if "<script" in response_text.lower():
            return "javascript"
        elif "href=" in response_text or "src=" in response_text:
            return "attribute"
        else:
            return "html"

    def _run_ai_scan(self, url: str, payload: str, response: Dict[str, Any]):
        """Run best-effort AI analysis for each tested response."""
        if not config.ENABLE_AI_RESPONSE_SCAN:
            return

        if not hasattr(self, "_ai_response_scan_calls"):
            self._ai_response_scan_calls = 0
        if self._ai_response_scan_calls >= config.AI_RESPONSE_SCAN_MAX_CALLS:
            return

        suspicious = (
            response.get("vulnerable")
            or response.get("confidence", 0) >= config.AI_RESPONSE_SCAN_MIN_CONFIDENCE
            or response.get("status_code", 0) >= 500
        )
        if not suspicious:
            return

        if not hasattr(self, "_groq"):
            self._groq = GroqClient(
                api_key=os.getenv("GROQ_API_KEY"),
                openrouter_api_key=os.getenv("OPENROUTER_API_KEY"),
            )

        try:
            self._ai_response_scan_calls += 1
            ai_result = self._groq.generate(f"""
Analyze this HTTP response for vulnerabilities.

Payload: {payload}
URL: {url}
Response:
{str(response)[:1000]}

Return JSON:
{{
    "vulnerable": true/false,
    "type": "...",
    "confidence": 0-1,
    "next_payload": "..."
}}
""")

            logger.debug("[AI SCAN] %s", ai_result)

        except Exception as e:
            logger.debug("[AI SCAN] error: %s", e)
