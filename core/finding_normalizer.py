"""
core/finding_normalizer.py - Backward-compatible finding normalization
"""

from typing import Any, Dict

from core.url_normalizer import URLNormalizer


def _confidence_value(value: Any, default: float = 0.0) -> float:
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


def normalize_finding(vuln: Dict[str, Any], normalizer: URLNormalizer = None) -> Dict[str, Any]:
    if not isinstance(vuln, dict):
        return {}

    normalizer = normalizer or URLNormalizer()
    normalized = dict(vuln)
    endpoint = normalized.get("endpoint") or normalized.get("url") or normalized.get("target") or ""
    normalized_url = normalizer.normalize_url(endpoint)
    if normalized_url:
        normalized["endpoint"] = normalized_url
        normalized["url"] = normalized_url

    normalized["confidence"] = _confidence_value(normalized.get("confidence", 0.0))
    normalized["source"] = normalized.get("source") or normalized.get("tool") or "unknown"
    if normalized.get("tool"):
        normalized.setdefault("source", normalized.get("tool"))

    severity = str(normalized.get("severity", "") or "").upper()
    finding_type = str(normalized.get("type", "") or "").lower()
    signal_type = str(normalized.get("signal_type", "") or "").lower()
    title = str(normalized.get("title", "") or "")
    if not severity:
        confidence = normalized["confidence"]
        severity = "CRITICAL" if confidence >= 0.9 else "HIGH" if confidence >= 0.75 else "MEDIUM" if confidence >= 0.4 else "LOW"
    title_lower = title.lower()
    speculative_pattern = title_lower.startswith("potential") and "vulnerable" in title_lower
    if finding_type in {"signal", "surface", "exposure", "tech_detect", "info_leak", "misconfig", "anomaly", "interesting_endpoint"} or signal_type or speculative_pattern:
        if speculative_pattern:
            normalized["type"] = "signal"
            normalized["title"] = title.replace("(unknown)", "").strip() or "Surface observation"
        if severity not in {"INFO", "LOW"}:
            severity = "LOW"
    normalized["severity"] = severity

    if normalized.get("payload") is None:
        normalized["payload"] = ""
    if normalized.get("evidence") is None:
        normalized["evidence"] = ""
    if normalized.get("auth_role") is None:
        normalized["auth_role"] = "anonymous"

    return normalized


def finding_identity(vuln: Dict[str, Any], normalizer: URLNormalizer = None):
    """Return a canonical identity for merging repeated observations of the same finding."""
    normalized = normalize_finding(vuln, normalizer=normalizer)
    if not normalized:
        return ("", "unknown", "anonymous")
    endpoint = normalized.get("endpoint") or normalized.get("url") or ""
    finding_type = normalized.get("type") or normalized.get("name") or "unknown"
    auth_role = normalized.get("auth_role") or "anonymous"
    return (
        str(endpoint).strip().lower(),
        str(finding_type).strip().lower(),
        str(auth_role).strip().lower(),
    )
