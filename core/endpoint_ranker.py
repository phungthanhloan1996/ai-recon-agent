import urllib.parse
"""
core/endpoint_ranker.py - Risk Scoring Engine
Đánh giá endpoint nguy hiểm, AI hỗ trợ phân loại
"""

import re
import logging
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, parse_qs
from core.url_normalizer import URLNormalizer

logger = logging.getLogger("recon.ranker")

# Static file extensions that should be EXCLUDED from scanning
STATIC_EXTENSIONS: Set[str] = {
    '.css', '.js', '.map', '.json',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico', '.webp', '.tiff',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
    '.txt', '.rtf', '.csv',
    '.xml', '.yaml', '.yml', '.toml', '.ini', '.conf',
    '.html', '.htm', '.xhtml',
    '.swf', '.jar', '.class',
}

# WordPress static upload paths that should be EXCLUDED
WORDPRESS_STATIC_PATHS = [
    '/wp-content/uploads/',
    '/wp-includes/',
    '/wp-content/cache/',
    '/wp-content/plugins/',  # Only static assets, not PHP files
]

# Static scoring rules - ENHANCED with higher scores for parameterized endpoints
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
    
    # Injection points - HIGHER SCORES
    (r"\?.*=", 8, "Has Query Parameters"),  # Any URL with = in query string
    (r"search|query|q=|s=|keyword", 7, "Search/Injection Point"),
    (r"id=|user=|page=|file=|path=|dir=|include=", 8, "Parameter Injection"),
    
    # WordPress specific
    (r"wp-login|xmlrpc|wp-json", 8, "WordPress Critical"),
    (r"wp-cron|wp-mail|wp-trackback", 7, "WordPress Internal"),
    # Lower score for wp-content/uploads (mostly static)
    (r"wp-content/uploads(?!.*\.php)", 2, "WordPress Uploads (Static)"),
    # Higher score for wp-content/uploads with PHP
    (r"wp-content/uploads.*\.php", 9, "WordPress Upload PHP"),
    
    # Debug/dev
    (r"debug|test|dev|staging|demo|sample|temp|tmp", 5, "Debug/Dev"),
    (r"phpinfo|server.?info|status|health|ping|alive", 6, "Server Info"),
    
    # LFI/Path traversal
    (r"page=|include=|require=|path=|template=|view=", 7, "Potential LFI"),
    
    # SSRF
    (r"url=|redirect=|callback=|fetch=|proxy=|forward=", 8, "Potential SSRF"),
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
        self._normalizer = URLNormalizer()

    def validate_url_structure(self, url: str) -> bool:
        """Kiểm tra URL có cấu trúc hợp lệ, không chứa ký tự HTML"""
        if not url:
            return False

        invalid_patterns = ['<', '>', '"', "'", '&lt;', '&gt;', 'script', 'alert']

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.netloc or parsed.hostname or ''

            for pattern in invalid_patterns:
                if pattern in hostname.lower():
                    logger.debug(f"[RANKER] Invalid URL (host contains {pattern}): {url[:100]}")
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

    def score_endpoint(self, url: str) -> Dict:
        """Score a single endpoint and return detailed scoring info"""
        if not self.validate_url_structure(url):
            return {
                "url": url,
                "score": 0,
                "risk_level": "INFO",
                "reasons": ["invalid_url_structure"]
            }

        score = 0
        reasons = []

        try:
            parsed = urllib.parse.urlparse(url)
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

        # Canonical dedup before ranking (input >= deduped >= ranked)
        normalized_inputs = self._normalizer.normalize_urls(urls or [])
        logger.info(f"[RANKER] Deduped canonical endpoints: {len(normalized_inputs)}")
        
        scored = []
        for url in normalized_inputs:
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

        # Return a finalized copy to avoid accidental downstream mutation
        return [dict(item) for item in scored]

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

    def is_static_file(self, url: str) -> bool:
        """Check if URL points to a static file that should be excluded"""
        if not url:
            return True
        
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        url_lower = url.lower()
        
        # Check for static file extensions
        for ext in STATIC_EXTENSIONS:
            if path.endswith(ext):
                return True
        
        # Check for WordPress static paths
        for wp_path in WORDPRESS_STATIC_PATHS:
            if wp_path in url_lower:
                # Allow PHP files in wp-content/uploads (potential shells)
                if '/wp-content/uploads/' in url_lower:
                    # Check if it's a PHP file - these are NOT static
                    if path.endswith('.php'):
                        return False
                    # Check if it has query parameters - could be dynamic
                    if parsed.query:
                        return False
                # All other files in WordPress static paths are static
                return True
        
        # Check for common static asset directories
        static_dirs = [
            '/assets/', '/static/', '/css/', '/js/', '/images/', '/img/',
            '/fonts/', '/media/', '/download/',
        ]
        for dir_path in static_dirs:
            if dir_path in path:
                # But allow if it has query parameters (could be dynamic)
                if not parsed.query:
                    return True
        
        return False

    def has_parameters(self, url: str) -> bool:
        """Check if URL has query parameters"""
        if not url:
            return False
        parsed = urllib.parse.urlparse(url)
        return bool(parsed.query)

    def filter_endpoints(
        self, 
        endpoints: List[Dict], 
        min_score: int = 5,
        require_parameters: bool = False,
        exclude_static: bool = True
    ) -> List[Dict]:
        """
        Filter endpoints based on multiple criteria.
        
        Args:
            endpoints: List of endpoint dictionaries
            min_score: Minimum score threshold (0-10)
            require_parameters: Only include endpoints with query parameters
            exclude_static: Exclude static files
        
        Returns:
            Filtered list of endpoints
        """
        filtered = []
        stats = {
            "total": len(endpoints),
            "static_filtered": 0,
            "no_params_filtered": 0,
            "low_score_filtered": 0,
            "passed": 0
        }
        
        for ep in endpoints:
            url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
            if not url:
                continue
            
            # Filter 1: Exclude static files
            if exclude_static and self.is_static_file(url):
                stats["static_filtered"] += 1
                continue
            
            # Filter 2: Require parameters (optional)
            if require_parameters and not self.has_parameters(url):
                stats["no_params_filtered"] += 1
                continue
            
            # Filter 3: Score threshold
            score = ep.get("score", 0) if isinstance(ep, dict) else 0
            if score < min_score:
                # Re-score if not already scored
                if not isinstance(ep, dict) or "score" not in ep:
                    score_result = self.score_endpoint(url)
                    score = score_result["score"]
                    if score < min_score:
                        stats["low_score_filtered"] += 1
                        continue
                else:
                    stats["low_score_filtered"] += 1
                    continue
            
            stats["passed"] += 1
            filtered.append(ep)
        
        logger.info(f"[RANKER] Filter: {stats['total']} → {stats['passed']} passed, "
                   f"{stats['static_filtered']} static, {stats['no_params_filtered']} no-params, "
                   f"{stats['low_score_filtered']} low-score")
        
        return filtered

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
