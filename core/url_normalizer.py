import urllib.parse
"""
core/url_normalizer.py - URL Normalization Engine
Compatibility-preserving URL and endpoint normalization helpers.
"""

import logging
import posixpath
import re
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

logger = logging.getLogger("recon.url_normalizer")

DEFAULT_PORTS = {"http": 80, "https": 443}
EMBEDDED_URL_RE = re.compile(r"https?://", re.IGNORECASE)
HOST_LIKE_RE = re.compile(r"^[A-Za-z0-9.-]+(?::\d+)?(?:/.*)?$")
STATIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp", ".avif",
    ".css", ".scss", ".sass", ".less", ".js", ".mjs", ".map",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
}
HIGH_VALUE_HINTS = (
    "/api/", "/rest/", "/graphql", "/auth", "/login", "/signin", "/admin",
    "/dashboard", "/wp-", "/upload", "/file", "/export", "/import",
    "/search", "/query", "/filter",
)
INTENDED_EMBEDDED_URL_HINTS = (
    "/redirect/", "/return/", "/next/", "/continue/", "/dest/", "/target/",
    "/callback/", "/proxy/", "/fetch/", "/image/", "/url/",
)


def _sorted_query(query: str) -> str:
    if not query:
        return ""
    return urlencode(sorted(parse_qsl(query, keep_blank_values=True)), doseq=True)


def _is_numeric_param_value(value: Any) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    if not text:
        return False
    if text.isdigit():
        return True
    try:
        float(text)
        return True
    except ValueError:
        return False


def _query_variants(query: str) -> Dict[str, List[str]]:
    variants: Dict[str, List[str]] = defaultdict(list)
    for key, value in parse_qsl(query or "", keep_blank_values=True):
        if value not in variants[key]:
            variants[key].append(value)
    return {k: list(v) for k, v in sorted(variants.items())}


def _wildcard_query(query: str) -> str:
    if not query:
        return ""

    wildcard_pairs = []
    for key, value in sorted(parse_qsl(query, keep_blank_values=True)):
        wildcard_pairs.append((key, "*" if _is_numeric_param_value(value) else value))
    return urlencode(wildcard_pairs, doseq=True)


def _normalize_path(path: str) -> str:
    raw_path = (path or "/").replace("\\", "/")
    collapsed = re.sub(r"/{2,}", "/", raw_path)
    normalized = posixpath.normpath(collapsed)
    if collapsed.endswith("/") and not normalized.endswith("/"):
        normalized += "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    if normalized in {"/.", "/.."}:
        return "/"
    return normalized


def _is_host_like(value: str) -> bool:
    if not value or " " in value:
        return False
    if value.startswith("/"):
        return False
    return bool(HOST_LIKE_RE.match(value))


def _fingerprint_from_url(url: str, wildcard_numeric: bool = False) -> str:
    parsed = urllib.parse.urlparse(url)
    port = parsed.port or DEFAULT_PORTS.get(parsed.scheme)
    query = _wildcard_query(parsed.query) if wildcard_numeric else _sorted_query(parsed.query)
    return f"{parsed.scheme}://{(parsed.hostname or '').lower()}:{port}{parsed.path}?{query}"


class URLNormalizer:
    """
    Stable compatibility surface for URL normalization.
    Existing callers can continue using `normalize_url(s)` while newer code can
    also normalize endpoint objects and apply lightweight phase gating helpers.
    """

    def __init__(self):
        self.seen_urls = set()
        self._logged_rejections = set()
        self._logged_sanitized = set()

    def _log_once(self, seen: set, level: int, message: str):
        if message in seen:
            return
        seen.add(message)
        logger.log(level, message)

    def _canonical_netloc(self, parsed) -> Optional[str]:
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return None

        try:
            port = parsed.port
        except ValueError:
            return None

        auth = ""
        if parsed.username:
            auth = parsed.username
            if parsed.password:
                auth += f":{parsed.password}"
            auth += "@"

        default_port = DEFAULT_PORTS.get(parsed.scheme)
        if port and port != default_port:
            return f"{auth}{hostname}:{port}"
        return f"{auth}{hostname}"

    def _looks_like_intended_embedded_url(self, path: str) -> bool:
        lowered = (path or "").lower()
        return any(hint in lowered for hint in INTENDED_EMBEDDED_URL_HINTS)

    def normalize_url(self, url: str, base_url: Optional[str] = None) -> str:
        """Normalize a single URL. Returns an empty string when rejected."""
        raw_url = (url or "")
        if not isinstance(raw_url, str):
            return ""

        candidate = raw_url.strip().replace("\\/", "/")
        if not candidate:
            return ""

        if base_url and not candidate.startswith(("http://", "https://")):
            candidate = urljoin(base_url, candidate)
        elif not candidate.startswith(("http://", "https://")) and _is_host_like(candidate):
            candidate = f"https://{candidate}"

        try:
            parsed = urllib.parse.urlparse(candidate)
        except Exception as exc:
            self._log_once(
                self._logged_rejections,
                logging.WARNING,
                f"[NORMALIZE] Rejected unparsable URL {raw_url[:160]}: {exc}",
            )
            return ""

        if parsed.scheme not in DEFAULT_PORTS or not parsed.netloc:
            self._log_once(
                self._logged_rejections,
                logging.WARNING,
                f"[NORMALIZE] Rejected invalid URL {raw_url[:160]}",
            )
            return ""

        path = parsed.path or "/"
        if EMBEDDED_URL_RE.search(path):
            leading = path.lstrip("/")
            if leading.startswith(("http://", "https://")):
                salvaged = leading
                if parsed.query:
                    salvaged = f"{salvaged}?{parsed.query}"
                self._log_once(
                    self._logged_sanitized,
                    logging.INFO,
                    f"[NORMALIZE] Salvaged embedded absolute URL from {raw_url[:160]} -> {salvaged[:160]}",
                )
                return self.normalize_url(salvaged)

            if not self._looks_like_intended_embedded_url(path):
                self._log_once(
                    self._logged_rejections,
                    logging.WARNING,
                    f"[NORMALIZE] Rejected malformed embedded URL path {raw_url[:160]}",
                )
                return ""

        netloc = self._canonical_netloc(parsed)
        if not netloc:
            self._log_once(
                self._logged_rejections,
                logging.WARNING,
                f"[NORMALIZE] Rejected URL with invalid host/port {raw_url[:160]}",
            )
            return ""

        normalized_path = _normalize_path(path)
        normalized_query = _sorted_query(parsed.query)
        normalized = urlunparse((
            parsed.scheme.lower(),
            netloc,
            normalized_path,
            parsed.params,
            normalized_query,
            "",
        ))

        if normalized != candidate:
            self._log_once(
                self._logged_sanitized,
                logging.INFO,
                f"[NORMALIZE] Sanitized URL {raw_url[:160]} -> {normalized[:160]}",
            )
        return normalized

    def normalize_urls(self, urls: List[str]) -> List[str]:
        """Normalize and deduplicate a list of URLs."""
        normalized: List[str] = []
        batch_seen = set()
        for url in urls or []:
            norm_url = self.normalize_url(url)
            if not norm_url:
                continue
            fingerprint = _fingerprint_from_url(norm_url, wildcard_numeric=False)
            if fingerprint in batch_seen or fingerprint in self.seen_urls:
                continue
            batch_seen.add(fingerprint)
            self.seen_urls.add(fingerprint)
            normalized.append(norm_url)
        return normalized

    def normalize_endpoint(self, endpoint: Any, base_url: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Normalize a raw endpoint string or endpoint dict into a canonical dict.
        """
        if isinstance(endpoint, str):
            normalized_url = self.normalize_url(endpoint, base_url=base_url)
            if not normalized_url:
                return None
            parsed = urllib.parse.urlparse(normalized_url)
            query_params = _query_variants(parsed.query)
            return {
                "original_url": endpoint,
                "url": normalized_url,
                "normalized_url": normalized_url,
                "scheme": parsed.scheme,
                "host": parsed.hostname or "",
                "port": parsed.port or DEFAULT_PORTS.get(parsed.scheme),
                "path": parsed.path or "/",
                "fingerprint": _fingerprint_from_url(normalized_url, wildcard_numeric=True),
                "dedup_fingerprint": _fingerprint_from_url(normalized_url, wildcard_numeric=True),
                "exact_fingerprint": _fingerprint_from_url(normalized_url, wildcard_numeric=False),
                "query_params": query_params,
                "parameter_value_variants": query_params,
                "raw_url_variants": [endpoint],
                "normalized_url_variants": [normalized_url],
            }

        if not isinstance(endpoint, dict):
            return None

        raw_url = endpoint.get("url") or endpoint.get("endpoint") or ""
        candidate_base = base_url or endpoint.get("base_url")
        if not candidate_base and isinstance(endpoint.get("source"), str) and endpoint.get("source", "").startswith(("http://", "https://")):
            candidate_base = endpoint.get("source")
        normalized_url = self.normalize_url(raw_url, base_url=candidate_base)
        if not normalized_url:
            return None

        parsed = urllib.parse.urlparse(normalized_url)
        normalized_endpoint = dict(endpoint)
        normalized_endpoint.setdefault("original_url", raw_url)
        normalized_endpoint["url"] = normalized_url
        normalized_endpoint["normalized_url"] = normalized_url
        normalized_endpoint["scheme"] = parsed.scheme
        normalized_endpoint["host"] = parsed.hostname or ""
        normalized_endpoint["port"] = parsed.port or DEFAULT_PORTS.get(parsed.scheme)
        normalized_endpoint["path"] = parsed.path or "/"
        query_params = _query_variants(parsed.query)
        normalized_endpoint["fingerprint"] = _fingerprint_from_url(normalized_url, wildcard_numeric=True)
        normalized_endpoint["dedup_fingerprint"] = _fingerprint_from_url(normalized_url, wildcard_numeric=True)
        normalized_endpoint["exact_fingerprint"] = _fingerprint_from_url(normalized_url, wildcard_numeric=False)
        existing_query_params = normalized_endpoint.get("query_params")
        if not isinstance(existing_query_params, dict) or not existing_query_params:
            normalized_endpoint["query_params"] = query_params
        existing_variants = normalized_endpoint.get("parameter_value_variants")
        if not isinstance(existing_variants, dict) or not existing_variants:
            normalized_endpoint["parameter_value_variants"] = query_params
        raw_variants = normalized_endpoint.get("raw_url_variants")
        if not isinstance(raw_variants, list) or not raw_variants:
            normalized_endpoint["raw_url_variants"] = [raw_url]
        elif raw_url and raw_url not in raw_variants:
            normalized_endpoint["raw_url_variants"] = raw_variants + [raw_url]
        normalized_variants = normalized_endpoint.get("normalized_url_variants")
        if not isinstance(normalized_variants, list) or not normalized_variants:
            normalized_endpoint["normalized_url_variants"] = [normalized_url]
        elif normalized_url not in normalized_variants:
            normalized_endpoint["normalized_url_variants"] = normalized_variants + [normalized_url]
        if "parameters" not in normalized_endpoint and query_params:
            normalized_endpoint["parameters"] = list(query_params.keys())
        if "endpoint" in normalized_endpoint and normalized_endpoint.get("endpoint"):
            normalized_endpoint["endpoint"] = normalized_url
        return normalized_endpoint

    def normalize_endpoints(self, endpoints: Iterable[Any], base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        seen = {}
        ordered: List[str] = []
        for endpoint in endpoints or []:
            normalized = self.normalize_endpoint(endpoint, base_url=base_url)
            if not normalized:
                continue
            fingerprint = normalized.get("fingerprint") or normalized.get("url")
            if fingerprint not in seen:
                seen[fingerprint] = normalized
                ordered.append(fingerprint)
                continue
            existing = seen[fingerprint]
            existing_variants = existing.get("normalized_url_variants") or []
            for variant in normalized.get("normalized_url_variants") or []:
                if variant not in existing_variants:
                    existing_variants.append(variant)
            existing["normalized_url_variants"] = existing_variants
            raw_variants = existing.get("raw_url_variants") or []
            for variant in normalized.get("raw_url_variants") or []:
                if variant not in raw_variants:
                    raw_variants.append(variant)
            existing["raw_url_variants"] = raw_variants
            merged_param_variants = existing.get("parameter_value_variants") or {}
            for key, values in (normalized.get("parameter_value_variants") or {}).items():
                current = list(merged_param_variants.get(key) or [])
                for value in values or []:
                    if value not in current:
                        current.append(value)
                merged_param_variants[key] = current
            existing["parameter_value_variants"] = merged_param_variants
        return [seen[fingerprint] for fingerprint in ordered]

    def is_static_asset(self, endpoint: Any) -> bool:
        normalized = endpoint if isinstance(endpoint, dict) else self.normalize_endpoint(endpoint)
        if not normalized:
            return True
        path = (normalized.get("path") or "").lower()
        return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)

    def has_candidate_surface(self, endpoint: Any) -> bool:
        normalized = endpoint if isinstance(endpoint, dict) else self.normalize_endpoint(endpoint)
        if not normalized:
            return False

        url = normalized.get("url", "")
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            return True
        if normalized.get("parameters"):
            return True
        if any(tag in (normalized.get("tags") or []) for tag in ("api", "auth", "admin", "candidate_param")):
            return True
        lowered = url.lower()
        return any(hint in lowered for hint in HIGH_VALUE_HINTS)

    def is_valid_endpoint(self, endpoint: Any) -> bool:
        normalized = endpoint if isinstance(endpoint, dict) else self.normalize_endpoint(endpoint)
        if not normalized:
            return False

        url = normalized.get("url", "")
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in DEFAULT_PORTS:
            return False
        if not parsed.hostname:
            return False
        if EMBEDDED_URL_RE.search(parsed.path or "") and not self._looks_like_intended_embedded_url(parsed.path or ""):
            return False
        return True

    def is_phase_candidate(
        self,
        endpoint: Any,
        phase: str = "",
        require_candidate_surface: bool = False,
        require_baseline: bool = False,
    ) -> bool:
        normalized = endpoint if isinstance(endpoint, dict) else self.normalize_endpoint(endpoint)
        if not normalized or not self.is_valid_endpoint(normalized):
            return False
        if normalized.get("malformed") or normalized.get("blacklisted"):
            return False
        if self.is_static_asset(normalized):
            return False
        if require_baseline and normalized.get("baseline_unreliable"):
            return False
        if require_candidate_surface and not self.has_candidate_surface(normalized):
            return False
        if phase in {"scan", "probe"} and normalized.get("reachable") is False:
            return False
        return True

    def deduplicate_urls(self, urls: List[str]) -> List[str]:
        """Compatibility helper: normalize then deduplicate."""
        return self.normalize_urls(urls)
