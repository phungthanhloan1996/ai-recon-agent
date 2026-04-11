import urllib.parse
"""
core/phase_admission.py - Shared admission control for phase handoff
"""

import logging
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse, urlunparse

from core.endpoint_registry import EndpointRegistry
from core.host_filter import HostFilter
from core.scan_optimizer import get_optimizer

logger = logging.getLogger("recon.phase_admission")

PHASE_RULES = {
    "rank": {"require_candidate_surface": True, "require_baseline": False},
    "probe": {"require_candidate_surface": True, "require_baseline": False},
    "scan": {"require_candidate_surface": True, "require_baseline": False},
    "differential_fuzz": {"require_candidate_surface": True, "require_baseline": True},
    "exploit": {"require_candidate_surface": False, "require_baseline": True},
}


class PhaseAdmission:
    def __init__(
        self,
        state: Any = None,
        registry: Optional[EndpointRegistry] = None,
        host_filter: Optional[HostFilter] = None,
    ):
        self.state = state
        self.registry = registry or EndpointRegistry()
        self.optimizer = get_optimizer()
        self.host_filter = host_filter or self._build_host_filter(state)
        self.last_stats: Dict[str, int] = {}

    def _state_get(self, key: str, default=None):
        if self.state is None:
            return default
        getter = getattr(self.state, "get", None)
        if callable(getter):
            return getter(key, default)
        return getattr(self.state, key, default)

    def _build_host_filter(self, state: Any) -> Optional[HostFilter]:
        if state is None:
            return None
        allowed_domains = list(self._state_get("allowed_domains", []) or [])
        target = self._state_get("target", "") or ""
        parsed_target = urllib.parse.urlparse(target if "://" in str(target) else f"https://{target}") if target else None
        if target:
            allowed_domains.append(target)
        if parsed_target:
            if parsed_target.netloc:
                allowed_domains.append(parsed_target.netloc)
            if parsed_target.hostname:
                allowed_domains.append(parsed_target.hostname)
        for seed in self._state_get("urls", []) or []:
            if isinstance(seed, str) and seed:
                allowed_domains.append(seed)
        try:
            return HostFilter(
                skip_dev_test=True,
                target_domain=target or (parsed_target.hostname if parsed_target else None),
                allowed_domains=allowed_domains,
            )
        except Exception:
            return None

    def register(self, endpoint: Any, base_url: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.registry.register(endpoint, base_url=base_url)

    def _iter_seed_inputs(self) -> List[str]:
        seeds: List[str] = []
        target = self._state_get("target", "") or ""
        if isinstance(target, str) and target:
            seeds.append(target)

        for value in self._state_get("urls", []) or []:
            if isinstance(value, str) and value:
                seeds.append(value)
            elif isinstance(value, dict) and value.get("url"):
                seeds.append(value["url"])

        live_hosts = self._state_get("live_hosts", []) or []
        for value in live_hosts:
            if isinstance(value, dict) and value.get("url"):
                seeds.append(value["url"])

        return list(dict.fromkeys(seeds))

    def _seed_variants(self, raw_url: str) -> List[str]:
        record = self.register(raw_url)
        if not record:
            return []

        parsed = urllib.parse.urlparse(record.get("url", ""))
        path = parsed.path or "/"
        normalized_path = path.rstrip("/") or "/"
        paths = list(dict.fromkeys([normalized_path, "/" if normalized_path != "/" else "/", f"{normalized_path}/" if normalized_path != "/" else "/"]))
        schemes = list(dict.fromkeys([parsed.scheme, "http", "https"]))
        variants: List[str] = []
        for scheme in schemes:
            for candidate_path in paths:
                variants.append(urlunparse((scheme, parsed.netloc, candidate_path, "", parsed.query, "")))
        return list(dict.fromkeys(variants))

    def canonical_seed_records(self) -> List[Dict[str, Any]]:
        records: List[Dict[str, Any]] = []
        seen = set()
        for seed in self._iter_seed_inputs():
            for variant in self._seed_variants(seed) or [seed]:
                record = self.register(variant)
                if not record:
                    continue
                fingerprint = record.get("exact_fingerprint") or record.get("url")
                if fingerprint in seen:
                    continue
                seen.add(fingerprint)
                records.append(record)
        return records

    def _is_canonical_seed(self, endpoint: Any) -> bool:
        record = endpoint if isinstance(endpoint, dict) else self.register(endpoint)
        if not record or not self.host_filter:
            return False

        hostname = (record.get("host") or "").lower()
        port = record.get("port")
        if not self.host_filter._matches_scope(
            hostname,
            port,
            getattr(self.host_filter, "target_aliases", set()),
            getattr(self.host_filter, "target_host_ports", set()),
        ):
            return False

        target = self._state_get("target", "") or ""
        if not target:
            return True

        parsed_target = urllib.parse.urlparse(target if "://" in str(target) else f"https://{target}")
        target_path = (parsed_target.path or "/").rstrip("/") or "/"
        record_path = (record.get("path") or "/").rstrip("/") or "/"
        return record_path == target_path or record_path == "/"

    def is_valid_endpoint(self, endpoint: Any, base_url: Optional[str] = None) -> bool:
        record = self.register(endpoint, base_url=base_url)
        if not record:
            return False
        if self._is_canonical_seed(record):
            return True
        if not self.registry.normalizer.is_valid_endpoint(record):
            return False
        if self.host_filter:
            url = record.get("url", "")
            if self.host_filter._is_third_party(url):
                return False
            if self.host_filter.allowed_domains:
                if not self.host_filter._is_in_allowed_domains(url):
                    return False
            elif not self.host_filter._is_target_domain(url):
                return False
        return True

    def is_phase_candidate(self, endpoint: Any, phase: str, state: Any = None) -> bool:
        if state is not None and state is not self.state:
            self.state = state
            self.host_filter = self._build_host_filter(state)

        record = self.register(endpoint)
        if not record or not self.is_valid_endpoint(record):
            return False
        if self._is_canonical_seed(record) and phase in {"rank", "probe", "scan", "differential_fuzz"}:
            return True

        url = record.get("url", "")
        host = record.get("host") or urllib.parse.urlparse(url).hostname or ""
        if host and self.optimizer.is_host_blacklisted(host):
            return False

        rules = PHASE_RULES.get(phase, {})
        require_candidate_surface = bool(rules.get("require_candidate_surface"))
        require_baseline = bool(rules.get("require_baseline"))
        return self.registry.normalizer.is_phase_candidate(
            record,
            phase=phase,
            require_candidate_surface=require_candidate_surface,
            require_baseline=require_baseline,
        )

    def filter_candidates(
        self,
        endpoints: Iterable[Any],
        phase: str,
        state: Any = None,
        base_url: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        if state is not None and state is not self.state:
            self.state = state
            self.host_filter = self._build_host_filter(state)

        filtered: List[Dict[str, Any]] = []
        seen: Dict[str, int] = {}
        stats = {
            "input": 0,
            "invalid": 0,
            "duplicate": 0,
            "blacklisted": 0,
            "rejected": 0,
            "accepted": 0,
        }

        for endpoint in endpoints or []:
            stats["input"] += 1
            record = self.register(endpoint, base_url=base_url)
            if not record:
                stats["invalid"] += 1
                continue

            fingerprint = record.get("fingerprint")
            if fingerprint in seen:
                stats["duplicate"] += 1
                filtered[seen[fingerprint]] = self.registry.merge_records(filtered[seen[fingerprint]], record)
                continue
            seen[fingerprint] = len(filtered)

            host = record.get("host") or ""
            if host and self.optimizer.is_host_blacklisted(host):
                record["blacklisted"] = True
                stats["blacklisted"] += 1
                continue

            if not self.is_phase_candidate(record, phase):
                stats["rejected"] += 1
                continue

            filtered.append(record)
            stats["accepted"] += 1

        if not filtered and stats["input"]:
            fallback_records = [
                record for record in self.canonical_seed_records()
                if self.is_valid_endpoint(record) and self.is_phase_candidate(record, phase)
            ]
            if fallback_records:
                filtered = fallback_records
                stats["accepted"] = len(filtered)
                logger.warning(
                    "[ADMISSION] %s preserved %s canonical seed endpoint(s) to avoid empty handoff",
                    phase,
                    len(filtered),
                )

        self.last_stats = stats
        if stats["input"] and stats["accepted"] != stats["input"]:
            logger.info(
                "[ADMISSION] %s reduced %s -> %s (invalid=%s duplicate=%s blacklisted=%s rejected=%s)",
                phase,
                stats["input"],
                stats["accepted"],
                stats["invalid"],
                stats["duplicate"],
                stats["blacklisted"],
                stats["rejected"],
            )
        return filtered
