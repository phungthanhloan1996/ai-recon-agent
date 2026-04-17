"""
modules/http_smuggling.py - HTTP Request Smuggling Detector
Detects CL.TE, TE.CL, and TE.TE desync vulnerabilities.
"""

import logging
import time
import socket
import ssl
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger("recon.http_smuggling")

# Timing-based detection: a successful CL.TE probe causes the backend to wait
# for additional bytes that never arrive, producing a measurable delay.
_CL_TE_PROBE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"
)

_TE_CL_PROBE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5c\r\n"
    "GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n"
    "0\r\n"
    "\r\n"
)

_TE_TE_PROBE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Transfer-Encoding: identity\r\n"
    "\r\n"
    "5e\r\n"
    "GPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n"
    "0\r\n"
    "\r\n"
)

# Socket timeout for probes (seconds)
_PROBE_TIMEOUT = 12
_TIMING_THRESHOLD = 4.0  # seconds delay considered a timing hit


def _raw_request(host: str, port: int, use_ssl: bool, payload: str, timeout: float) -> Optional[float]:
    """
    Send raw HTTP bytes over a plain socket and return elapsed seconds,
    or None on connection error.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        t0 = time.monotonic()
        sock.sendall(payload.encode("utf-8", errors="replace"))
        try:
            sock.recv(4096)
        except socket.timeout:
            pass
        elapsed = time.monotonic() - t0
        sock.close()
        return elapsed
    except Exception as e:
        logger.debug(f"[SMUGGLING] Socket error ({host}:{port}): {e}")
        return None


def _probe_host(url: str) -> Dict[str, Any]:
    """Run all three smuggling probes against a single URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    path = parsed.path or "/"

    findings: List[Dict[str, Any]] = []

    probes = [
        ("CL.TE", _CL_TE_PROBE),
        ("TE.CL", _TE_CL_PROBE),
        ("TE.TE", _TE_TE_PROBE),
    ]

    for variant, template in probes:
        payload = template.format(host=host, path=path)
        elapsed = _raw_request(host, port, use_ssl, payload, _PROBE_TIMEOUT)
        if elapsed is None:
            continue
        logger.debug(f"[SMUGGLING] {variant} probe on {host}: {elapsed:.2f}s")
        if elapsed >= _TIMING_THRESHOLD:
            findings.append({
                "type": "http_request_smuggling",
                "variant": variant,
                "url": url,
                "evidence": f"Timing delay {elapsed:.2f}s ≥ {_TIMING_THRESHOLD}s on {variant} probe",
                "severity": "CRITICAL",
                "confidence": 0.7,
                "source": "http_smuggling_detector",
            })
            logger.warning(f"[SMUGGLING] Potential {variant} smuggling on {url} (delay={elapsed:.2f}s)")
            break  # One confirmed variant per host is sufficient

    return {"url": url, "findings": findings, "probes_run": len(probes)}


def detect_http_smuggling(
    state: Any,
    endpoints: List[Any],
    http_client: Any = None,
) -> Dict[str, Any]:
    """
    Tier-3 entry point. Tests live hosts (not every endpoint) for
    HTTP Request Smuggling via raw socket probes.
    """
    vulnerabilities: List[Dict[str, Any]] = []
    tested = 0

    # Work at the host level to avoid redundant probes
    seen_hosts: set = set()
    candidate_urls: List[str] = []

    for ep in endpoints or []:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url:
            continue
        parsed = urlparse(url)
        host_key = f"{parsed.scheme}://{parsed.netloc}"
        if host_key in seen_hosts:
            continue
        seen_hosts.add(host_key)
        candidate_urls.append(host_key + "/")

    # Also probe live hosts from state
    for lh in (getattr(state, "get", lambda k, d=None: d)("live_hosts", []) or []):
        lh_url = lh.get("url", "") if isinstance(lh, dict) else ""
        if not lh_url:
            continue
        parsed = urlparse(lh_url)
        host_key = f"{parsed.scheme}://{parsed.netloc}"
        if host_key not in seen_hosts:
            seen_hosts.add(host_key)
            candidate_urls.append(host_key + "/")

    for url in candidate_urls[:8]:  # cap at 8 hosts to stay fast
        try:
            result = _probe_host(url)
            tested += 1
            vulnerabilities.extend(result.get("findings", []))
        except Exception as e:
            logger.debug(f"[SMUGGLING] Probe error for {url}: {e}")

    logger.info(f"[SMUGGLING] Tested {tested} hosts, found {len(vulnerabilities)} potential issues")
    return {
        "vulnerabilities": vulnerabilities,
        "endpoints_tested": tested,
        "smuggling_confirmed": len(vulnerabilities),
    }
