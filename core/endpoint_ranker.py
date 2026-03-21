"""
core/endpoint_ranker.py - Risk Scoring Engine
Đánh giá endpoint nguy hiểm, AI hỗ trợ phân loại
"""

import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("recon.ranker")

# Static scoring rules
SCORING_RULES = [
    # Upload endpoints - highest risk
    (r"upload|file_upload|fileupload", 9, "File Upload"),
    (r"shell|webshell|cmd|exec|command", 10, "Command Execution"),
    
    # Admin panels
    (r"admin|administrator|wp-admin|manager|console|dashboard|panel", 8, "Admin Panel"),
    (r"phpmyadmin|adminer|cpanel|plesk|webmin", 9, "DB/Server Admin"),
    
    # Authentication
    (r"login|signin|auth|authenticate|session", 7, "Authentication"),
    (r"register|signup|create.?account", 6, "Registration"),
    (r"forgot|reset|recover|password", 7, "Password Reset"),
    
    # API
    (r"/api/|/v[0-9]/|/graphql|/rest/", 7, "API Endpoint"),
    (r"token|apikey|api.key|secret", 8, "Credentials Exposure"),
    
    # File access
    (r"download|file|document|attachment|export|import", 6, "File Access"),
    (r"backup|\.bak|\.sql|\.tar|\.zip|\.gz", 9, "Backup File"),
    (r"\.env|config|settings|\.ini|\.cfg|\.conf", 9, "Config Exposure"),
    (r"\.git|\.svn|\.htaccess|web\.config", 8, "SCM/Server Config"),
    
    # Injection points
    (r"\?.*=|search|query|q=|s=|keyword", 6, "Search/Injection Point"),
    (r"id=|user=|page=|file=|path=|dir=|include=", 7, "Parameter Injection"),
    
    # WordPress specific
    (r"wp-login|xmlrpc|wp-json|wp-content/uploads", 8, "WordPress"),
    (r"wp-cron|wp-mail|wp-trackback", 7, "WordPress Internal"),
    
    # Debug/dev
    (r"debug|test|dev|staging|demo|sample|temp|tmp", 5, "Debug/Dev"),
    (r"phpinfo|server.?info|status|health|ping|alive", 6, "Server Info"),
    
    # LFI/Path traversal
    (r"page=|include=|require=|path=|template=|view=", 7, "Potential LFI"),
    
    # SSRF
    (r"url=|redirect=|callback=|fetch=|proxy=|forward=", 8, "Potential SSRF"),
    
    # Low risk
    (r"\.(css|js|png|jpg|jpeg|gif|ico|woff|svg)$", 1, "Static Asset"),
]

PARAM_BONUS = {
    "file": 3, "path": 3, "dir": 3, "include": 3,
    "url": 3, "redirect": 3, "callback": 3,
    "cmd": 5, "exec": 5, "shell": 5,
    "id": 1, "user": 1, "page": 1, "q": 1, "search": 1,
    "token": 2, "key": 2, "pass": 2, "password": 2,
}

EXTENSION_SCORES = {
    ".php": 2, ".asp": 2, ".aspx": 2, ".jsp": 2,
    ".cgi": 3, ".pl": 2, ".py": 1, ".rb": 1,
    ".bak": 5, ".sql": 5, ".tar": 4, ".zip": 4,
    ".env": 6, ".config": 4, ".conf": 4, ".ini": 4,
    ".log": 3, ".txt": 1, ".xml": 2, ".json": 2,
}


class EndpointRanker:
    def __init__(self, ai_client=None):
        self.ai_client = ai_client

    def score_endpoint(self, url: str) -> Dict:
        """Score a single endpoint and return detailed scoring info"""
        score = 0
        reasons = []

        try:
            parsed = urlparse(url)
            path = parsed.path.lower()
            query = parsed.query.lower()
            full = (path + "?" + query).lower() if query else path

            # Apply scoring rules
            for pattern, points, label in SCORING_RULES:
                if re.search(pattern, full, re.IGNORECASE):
                    score += points
                    reasons.append(f"{label} (+{points})")

            # Extension bonus
            ext_match = re.search(r'\.[a-z]{2,4}$', path)
            if ext_match:
                ext = ext_match.group(0).lower()
                if ext in EXTENSION_SCORES:
                    bonus = EXTENSION_SCORES[ext]
                    score += bonus
                    reasons.append(f"Extension {ext} (+{bonus})")

            # Parameter analysis
            if query:
                params = parse_qs(query)
                for param in params:
                    param_l = param.lower()
                    for key, bonus in PARAM_BONUS.items():
                        if key in param_l:
                            score += bonus
                            reasons.append(f"Param '{param}' (+{bonus})")
                            break

            # Normalize score 0-10
            score = min(10, max(0, score))

        except Exception as e:
            logger.debug(f"[RANKER] Error scoring {url}: {e}")
            score = 3
            reasons = ["parse_error"]

        return {
            "url": url,
            "score": score,
            "risk_level": self._risk_level(score),
            "reasons": reasons[:5],  # top 5 reasons
        }

    def _risk_level(self, score: int) -> str:
        if score >= 9:
            return "CRITICAL"
        elif score >= 7:
            return "HIGH"
        elif score >= 5:
            return "MEDIUM"
        elif score >= 3:
            return "LOW"
        return "INFO"

    def rank_endpoints(self, urls: List[str], top_n: Optional[int] = None) -> List[Dict]:
        """Score and rank all endpoints"""
        logger.info(f"[RANKER] Scoring {len(urls)} endpoints...")
        
        scored = []
        for url in urls:
            result = self.score_endpoint(url)
            scored.append(result)

        # Sort by score descending
        scored.sort(key=lambda x: x["score"], reverse=True)

        # Stats
        stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for s in scored:
            stats[s["risk_level"]] += 1

        logger.info(f"[RANKER] Results: {stats}")

        if top_n:
            scored = scored[:top_n]

        return scored

    def filter_high_risk(self, ranked: List[Dict], min_score: int = 6) -> List[Dict]:
        """Filter only high-risk endpoints"""
        return [e for e in ranked if e["score"] >= min_score]

    def print_top(self, ranked: List[Dict], n: int = 20):
        """Print top N endpoints"""
        print(f"\n{'='*60}")
        print(f"  TOP {n} RISKY ENDPOINTS")
        print(f"{'='*60}")
        for i, ep in enumerate(ranked[:n], 1):
            # Use safe access to prevent KeyError
            risk_level = ep.get('risk_level', 'UNKNOWN')
            score = ep.get('score', 0)
            url = ep.get('url') or ep.get('full_url') or ep.get('path') or 'unknown'
            reasons = ep.get('reasons', [])
            print(f"[{i:2d}] [{risk_level:8s}] Score:{score}/10  {url}")
            if reasons:
                print(f"       Reasons: {', '.join(reasons[:3])}")
        print(f"{'='*60}\n")

    def categorize_endpoints(self, endpoints: List[Dict]) -> Dict[str, List[Dict]]:
        """Categorize endpoints into groups"""
        categories = {
            "auth": [],
            "upload": [],
            "api": [],
            "admin": [],
            "debug": [],
            "config": [],
            "backup": [],
            "other": []
        }

        for ep in endpoints:
            # Use safe access to prevent KeyError
            url = (ep.get("url") or ep.get("full_url") or ep.get("path") or "").lower()
            if not url:
                categories["other"].append(ep)
                continue
                
            if re.search(r"login|auth|token|signin|register|password", url):
                categories["auth"].append(ep)
            elif re.search(r"upload|file|import|attachment", url):
                categories["upload"].append(ep)
            elif re.search(r"/api/|/v\d+/|/graphql|/rest/", url):
                categories["api"].append(ep)
            elif re.search(r"admin|dashboard|panel|manager|console", url):
                categories["admin"].append(ep)
            elif re.search(r"debug|test|dev|staging|demo|phpinfo|server.?info", url):
                categories["debug"].append(ep)
            elif re.search(r"config|setting|\.env|\.ini|\.cfg", url):
                categories["config"].append(ep)
            elif re.search(r"backup|\.bak|\.sql|\.tar|\.zip", url):
                categories["backup"].append(ep)
            else:
                categories["other"].append(ep)

        return categories
