import urllib.parse
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_engine import HTTPClient
from core.response_analyzer import ResponseAnalyzer

logger = logging.getLogger("recon.differential_fuzz")


class DifferentialFuzzer:
    """Lightweight differential fuzzing for logic anomaly detection."""

    RELEVANT_SOURCES = {
        "auth_scanner",
        "auth",
        "idor_detector",
        "idor",
        "api_scanner",
        "api_vuln",
        "api_vuln_scanner",
    }

    def __init__(self, http_client: Optional[HTTPClient] = None, max_requests_per_endpoint: int = 10):
        self.http_client = http_client or HTTPClient()
        self.response_analyzer = ResponseAnalyzer()
        self.max_requests_per_endpoint = max(2, int(max_requests_per_endpoint))

    def _is_numeric_like(self, value: Any) -> bool:
        if value is None:
            return False
        value_str = str(value).strip()
        if not value_str:
            return False
        try:
            float(value_str)
            return True
        except ValueError:
            return value_str.isdigit()

    def _build_mutations(self, original_value: Any) -> List[Tuple[str, str]]:
        """Return <=10 mutation operations per parameter."""
        numeric_mutations = ["1", "01", "1.0", "1e1"]
        boundary_mutations = ["-1", "0", "999999"]
        encoding_mutations = ["%31", "%30%31"]
        null_byte_mutations = ["%00"]

        mutations: List[Tuple[str, str]] = []
        if self._is_numeric_like(original_value):
            mutations.extend(("replace", m) for m in numeric_mutations)

        mutations.extend(("replace", m) for m in encoding_mutations)
        mutations.extend(("replace", m) for m in null_byte_mutations)
        mutations.extend(("replace", m) for m in boundary_mutations)

        # Array mutation strategy: param[]=value
        mutations.append(("array", str(original_value)))

        # Stable dedupe + cap to <=10
        seen = set()
        deduped: List[Tuple[str, str]] = []
        for item in mutations:
            if item in seen:
                continue
            seen.add(item)
            deduped.append(item)
            if len(deduped) >= 10:
                break
        return deduped

    def _extract_url(self, endpoint: Any) -> str:
        if isinstance(endpoint, dict):
            return str(endpoint.get("url") or endpoint.get("endpoint") or "").strip()
        return str(endpoint or "").strip()

    def _extract_variant_urls(self, endpoint: Any) -> List[str]:
        if not isinstance(endpoint, dict):
            url = self._extract_url(endpoint)
            return [url] if url else []

        variants = []
        for candidate in endpoint.get("normalized_url_variants", []) or []:
            value = str(candidate or "").strip()
            if value and value not in variants:
                variants.append(value)

        fallback = self._extract_url(endpoint)
        if fallback and fallback not in variants:
            variants.append(fallback)
        return variants

    def _normalize_response(self, response: Any) -> Dict[str, Any]:
        body = ""
        headers = {}
        if response is not None:
            body = getattr(response, "text", "") or ""
            headers = dict(getattr(response, "headers", {}) or {})
        return {
            "status_code": int(getattr(response, "status_code", 0) or 0),
            "content_length": len(body),
            "body": body,
            "headers": headers,
        }

    def _is_relevant_endpoint(self, url: str, state) -> bool:
        all_vulns = (state.get("vulnerabilities", []) or []) + (state.get("confirmed_vulnerabilities", []) or [])
        for vuln in all_vulns:
            if not isinstance(vuln, dict):
                continue
            source = str(vuln.get("source") or vuln.get("tool") or "").lower()
            endpoint = str(vuln.get("endpoint") or vuln.get("url") or "")
            if source in self.RELEVANT_SOURCES and endpoint == url:
                return True
        return False

    def _mutation_cases(self, parsed, query_params: Dict[str, List[str]]) -> List[Dict[str, str]]:
        cases: List[Dict[str, str]] = []
        budget = self.max_requests_per_endpoint - 1  # reserve 1 for baseline
        for param, values in query_params.items():
            original = values[0] if values else ""
            for op, mutation in self._build_mutations(original):
                if len(cases) >= budget:
                    return cases
                copied = {k: list(v) for k, v in query_params.items()}
                if op == "array":
                    copied.pop(param, None)
                    copied[f"{param}[]"] = [mutation]
                    mutation_label = "param[]"
                else:
                    copied[param] = [mutation]
                    mutation_label = mutation

                mutated_query = urlencode(copied, doseq=True)
                mutated_url = urlunparse(parsed._replace(query=mutated_query))
                cases.append({
                    "endpoint": urlunparse(parsed),
                    "url": mutated_url,
                    "parameter": param,
                    "original": str(original),
                    "mutation": mutation_label,
                })
        return cases

    def run(self, endpoints, state):
        findings: List[Dict[str, Any]] = []
        threshold = float((state.get("scan_metadata", {}) or {}).get("differential_fuzz_threshold", 0.65))

        for endpoint in endpoints or []:
            variant_urls = self._extract_variant_urls(endpoint)[:5]
            if not variant_urls:
                continue
            canonical_url = self._extract_url(endpoint) or variant_urls[0]
            if not any(self._is_relevant_endpoint(candidate_url, state) for candidate_url in [canonical_url] + variant_urls):
                continue

            for url in variant_urls:
                parsed = urllib.parse.urlparse(url)
                query_params = parse_qs(parsed.query, keep_blank_values=True)
                if not query_params:
                    continue

                logger.info(f"[DIFF_FUZZ] Testing endpoint {parsed.path or url}")

                try:
                    baseline_raw = self.http_client.get(url, timeout=10)
                except Exception as e:
                    logger.warning(f"[DIFF_FUZZ] Baseline request failed for {url}: {e}")
                    continue

                baseline = self._normalize_response(baseline_raw)
                for case in self._mutation_cases(parsed, query_params):
                    try:
                        mutated_raw = self.http_client.get(case["url"], timeout=10)
                    except Exception as e:
                        logger.debug(f"[DIFF_FUZZ] Mutation request failed for {case['url']}: {e}")
                        continue

                    mutated = self._normalize_response(mutated_raw)
                    diff_score = self.response_analyzer.compare_responses(baseline, mutated)
                    logger.info(
                        f"[DIFF_FUZZ] Mutation id={case['mutation']} produced response difference score {diff_score:.2f}"
                    )

                    if diff_score < threshold:
                        continue

                    findings.append(
                        {
                            "type": "logic_anomaly",
                            "endpoint": canonical_url,
                            "variant_url": url,
                            "parameter": case["parameter"],
                            "confidence": round(diff_score, 2),
                            "evidence": {
                                "mutation": case["mutation"],
                                "original_value": case["original"],
                                "variant_url": url,
                                "baseline_status": baseline.get("status_code", 0),
                                "mutated_status": mutated.get("status_code", 0),
                                "baseline_length": baseline.get("content_length", 0),
                                "mutated_length": mutated.get("content_length", 0),
                                "diff_score": round(diff_score, 2),
                            },
                        }
                    )

        if findings:
            candidates = []
            for finding in findings:
                candidates.append(
                    {
                        "type": "logic_anomaly",
                        "severity": "MEDIUM",
                        "confidence": finding["confidence"],
                        "source": "differential_fuzz",
                        "endpoint": finding["endpoint"],
                        "url": finding["endpoint"],
                        "parameter": finding["parameter"],
                        "evidence": finding["evidence"],
                    }
                )
            state.update(vulnerabilities=candidates)

        return findings
