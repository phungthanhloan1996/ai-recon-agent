"""
core/endpoint_registry.py - Shared canonical endpoint records
Additive helper for synchronizing endpoint lifecycle across phases.
"""

import logging
from typing import Any, Dict, Iterable, List, Optional, Set

from core.url_normalizer import URLNormalizer

logger = logging.getLogger("recon.endpoint_registry")


def _merge_param_variants(existing: Optional[Dict[str, List[str]]], incoming: Optional[Dict[str, List[str]]]) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {}
    for source in (existing or {}, incoming or {}):
        for key, values in source.items():
            current = list(merged.get(key) or [])
            for value in values or []:
                if value not in current:
                    current.append(value)
            merged[key] = current
    return merged


def _merge_ordered_lists(existing: Optional[List[Any]], incoming: Optional[List[Any]]) -> List[Any]:
    flat: List[Any] = []
    for value in list(existing or []) + list(incoming or []):
        if value not in flat:
            flat.append(value)
    return flat


class EndpointRegistry:
    """
    Build canonical endpoint records without forcing a broad refactor.
    The registry is intentionally lightweight so existing modules can adopt it
    at narrow choke points and keep their current interfaces.
    """

    def __init__(self, normalizer: Optional[URLNormalizer] = None):
        self.normalizer = normalizer or URLNormalizer()

    def register(
        self,
        endpoint: Any,
        source: Optional[str] = None,
        base_url: Optional[str] = None,
        extra_tags: Optional[Iterable[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        normalized = self.normalizer.normalize_endpoint(endpoint, base_url=base_url)
        if not normalized:
            return None

        record = dict(normalized)
        tags = set(record.get("tags") or [])

        explicit_source = source or record.get("source")
        if explicit_source:
            record["source"] = explicit_source
            tags.add(str(explicit_source))

        if self.normalizer.is_static_asset(record):
            tags.add("static")
        if self.normalizer.has_candidate_surface(record):
            tags.add("candidate_param")

        url_lower = record.get("url", "").lower()
        if "/api/" in url_lower or "/graphql" in url_lower or "/rest/" in url_lower:
            tags.add("api")
        if any(token in url_lower for token in ("/login", "/signin", "/auth", "/register", "/password")):
            tags.add("auth")
        if any(token in url_lower for token in ("/admin", "/dashboard", "/console", "/panel", "/manager")):
            tags.add("admin")
        if record.get("baseline_unreliable"):
            tags.add("baseline_unreliable")
        if record.get("blacklisted"):
            tags.add("blacklisted")
        if record.get("malformed"):
            tags.add("malformed")

        if extra_tags:
            for tag in extra_tags:
                if tag:
                    tags.add(str(tag))

        record["tags"] = sorted(tags)
        return record

    def register_many(
        self,
        endpoints: Iterable[Any],
        source: Optional[str] = None,
        base_url: Optional[str] = None,
        extra_tags: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        registered: Dict[str, Dict[str, Any]] = {}
        ordered: List[str] = []
        for endpoint in endpoints or []:
            record = self.register(endpoint, source=source, base_url=base_url, extra_tags=extra_tags)
            if not record:
                continue
            fingerprint = record.get("fingerprint") or record.get("url")
            if fingerprint not in registered:
                registered[fingerprint] = record
                ordered.append(fingerprint)
            else:
                registered[fingerprint] = self.merge_records(registered[fingerprint], record)
        return [registered[fingerprint] for fingerprint in ordered]

    def merge_records(self, existing: Optional[Dict[str, Any]], incoming: Dict[str, Any]) -> Dict[str, Any]:
        if not existing:
            return dict(incoming)

        merged = dict(existing)
        for key, value in incoming.items():
            if key == "tags":
                merged["tags"] = sorted(set(merged.get("tags") or []) | set(value or []))
            elif key == "source":
                sources = set()
                if merged.get("source"):
                    sources.add(str(merged.get("source")))
                if value:
                    sources.add(str(value))
                merged["source"] = ",".join(sorted(sources))
            elif key in {"raw_url_variants", "normalized_url_variants"}:
                merged[key] = _merge_ordered_lists(merged.get(key), value)
            elif key in {"parameter_value_variants", "query_params"}:
                merged[key] = _merge_param_variants(merged.get(key), value)
            elif value not in (None, "", [], {}):
                merged[key] = value

        if merged.get("normalized_url_variants"):
            merged.setdefault("url", merged["normalized_url_variants"][0])
            merged.setdefault("normalized_url", merged["normalized_url_variants"][0])
        if merged.get("raw_url_variants"):
            merged.setdefault("original_url", merged["raw_url_variants"][0])
        return merged
