import urllib.parse
"""
core/host_filter.py - Intelligent Host Filtering and Deduplication
Lọc và phân loại hosts để ưu tiên scan production, loại bỏ sub-paths, deduplicate
"""

import re
import logging
import socket
from typing import List, Dict, Set, Tuple, Optional
from urllib.parse import urlparse
from collections import defaultdict

logger = logging.getLogger("recon.host_filter")

# ─── THIRD-PARTY DOMAINS TO EXCLUDE ──────────────────────────────────────────
# These are external services, not part of the target scope
THIRD_PARTY_DOMAINS = {
    'vimeo.com', 'www.vimeo.com',
    'instagram.com', 'www.instagram.com',
    'facebook.com', 'www.facebook.com',
    'google.com', 'www.google.com',
    'googletagmanager.com', 'www.googletagmanager.com',
    'youtu.be', 'youtube.com', 'www.youtube.com',
    'twitter.com', 'www.twitter.com',
    'linkedin.com', 'www.linkedin.com',
    'github.com', 'www.github.com',
    'gravatar.com', 'www.gravatar.com',
    'cloudflare.com', 'www.cloudflare.com',
    'jsdelivr.net', 'www.jsdelivr.net',
    'bootstrapcdn.com', 'www.bootstrapcdn.com',
    'fontawesome.com', 'www.fontawesome.com',
    'googleapis.com', 'www.googleapis.com',
    'gstatic.com', 'www.gstatic.com',
    'doubleclick.net', 'www.doubleclick.net',
    'google-analytics.com', 'www.google-analytics.com',
}

# ─── FREE HOSTING/BLOG DOMAINS TO EXCLUDE ────────────────────────────────────
# These are free hosting platforms, not target-owned properties
FREE_HOSTING_DOMAINS = {
    'wordpress.com', 'www.wordpress.com',
    'blogspot.com', 'www.blogspot.com',
    'blogspot.co.uk', 'blogspot.fr', 'blogspot.de', 'blogspot.es',
    'blogspot.it', 'blogspot.jp', 'blogspot.com.br', 'blogspot.in',
    'wixsite.com', 'weebly.com', 'tumblr.com', 'medium.com',
    'ghost.io', 'github.io', 'gitlab.io', 'pages.dev',
    'netlify.app', 'vercel.app', 'herokuapp.com', 'firebaseapp.com',
    'azurewebsites.net', '000webhostapp.com', 'infinityfreeapp.com',
    'rf.gd', 'epizy.com',
}

# ─── PATTERNS FOR AUTO-GENERATED/SUSPICIOUS SUBDOMAINS ───────────────────────
# These match randomly generated or abnormally long subdomains
SUSPICIOUS_SUBDOMAIN_PATTERNS = [
    r'^[a-z0-9]{32,}\.',           # 32+ char random strings
    r'^[a-z0-9]{20,}[0-9]+\.',     # Long alphanumeric with numbers
    r'^[a-z0-9]*[0-9]{5,}[a-z0-9]*\.',  # Contains 5+ consecutive digits
]

# Maximum subdomain label length (each part between dots)
MAX_SUBDOMAIN_LABEL_LENGTH = 50

# Maximum total hostname length
MAX_HOSTNAME_LENGTH = 253

# Patterns indicating dev/test environments
DEV_TEST_PATTERNS = [
    # Subdomain patterns (e.g., dev.example.com, test.example.com)
    r'://dev[0-9]*\.',           # ://dev., ://dev1.
    r'://test[0-9]*\.',          # ://test., ://test1.
    r'://staging[0-9]*\.',       # ://staging.
    r'://qa[0-9]*\.',            # ://qa.
    r'://uat[0-9]*\.',           # ://uat.
    r'://local[0-9]*\.',         # ://local.
    
    # Embedded dev/test in hostname (e.g., elodev.example.com, cdmsdev.example.com)
    r'://[a-zA-Z0-9-]*dev[0-9]*\.',    # ://*dev., ://*dev1.
    r'://[a-zA-Z0-9-]*test[0-9]*\.',   # ://*test., ://*test1.
    r'://[a-zA-Z0-9-]*staging[0-9]*\.', # ://*staging.
    
    # Testing subdomain
    r'://testing\.',             # ://testing.
    
    # Path-based patterns
    r'/dev/',                   # /dev/ path
    r'/test/',                  # /test/ path
    r'/staging/',               # /staging/ path
    r'/login',                  # /login path (often dev/test)
]

# Sub-path patterns (URLs that are paths of a parent domain, not separate hosts)
SUB_PATH_PATTERNS = [
    r'/wp-admin/',
    r'/wp-login\.php',
    r'/wp-content/',
    r'/wp-includes/',
    r'/author/',
    r'/blog/',
    r'/products/',
    r'/technical-news/',
    r'/technology/',
    r'/login',
    r'/register',
    r'/dashboard/',
]

# Production indicators
PRODUCTION_INDICATORS = [
    r'^(www|app|api|mail|cdn|static|portal|secure)\.',
    r'^(www|app|api|mail|cdn|static|portal|secure)[0-9]*\.',
]


class HostFilter:
    """
    Intelligent host filtering to:
    1. Deduplicate hosts (same hostname:port)
    2. Identify and filter sub-paths (not separate hosts)
    3. Prioritize production over dev/test
    4. Group related hosts
    5. Filter third-party domains
    6. Filter free hosting platforms
    7. Filter suspicious/auto-generated subdomains
    8. MULTI-DOMAIN FILTERING: Allow URLs from multiple target domains (from targets.txt)
    """
    
    def __init__(self, skip_dev_test: bool = False, target_domain: str = None, allowed_domains: list = None):
        """
        Args:
            skip_dev_test: If True, skip dev/test environments entirely
            target_domain: Primary target domain for strict filtering (e.g., "elo.edu.vn") - deprecated, use allowed_domains
            allowed_domains: List of allowed target domains from targets.txt (e.g., ["elo.edu.vn", "hiu.vn", ...])
        """
        self.skip_dev_test = skip_dev_test
        self.target_domain = target_domain  # Kept for backward compatibility
        self.allowed_domains: Set[str] = set()
        self.allowed_host_ports: Set[str] = set()
        self.target_aliases: Set[str] = set()
        self.target_host_ports: Set[str] = set()
        target_host, target_port = self._normalize_scope_seed(target_domain)
        if target_host:
            self.target_domain = target_host
            self._register_scope_host(target_host, target_port, target=True)
        if allowed_domains:
            for d in allowed_domains:
                host, port = self._normalize_scope_seed(d)
                self._register_scope_host(host, port)
        self.seen_hosts: Set[str] = set()  # Track seen hostname:port combos
        self.host_groups: Dict[str, List[str]] = defaultdict(list)  # Group related hosts
        self._blacklisted_log_sent: Set[str] = set()  # Track which hosts we've logged for blacklist
        self.stats = {
            'total': 0,
            'duplicates': 0,
            'sub_paths': 0,
            'dev_test': 0,
            'production': 0,
            'passed': 0,
            'domain_filtered': 0,  # NEW: Track domain-filtered hosts
        }

    def _normalize_scope_seed(self, value: Optional[str]) -> Tuple[str, Optional[int]]:
        text = str(value or "").strip().lower()
        if not text:
            return "", None

        if "://" not in text:
            text = f"http://{text}"

        try:
            parsed = urllib.parse.urlparse(text)
            return (parsed.hostname or "").lower(), parsed.port
        except Exception:
            return "", None

    def _expand_host_aliases(self, host: str) -> Set[str]:
        aliases: Set[str] = set()
        host = (host or "").strip().lower()
        if not host:
            return aliases

        aliases.add(host)
        if host.startswith("www."):
            aliases.add(host[4:])

        try:
            for info in socket.getaddrinfo(host, None):
                ip = (info[4][0] or "").strip().lower()
                if ip:
                    aliases.add(ip)
        except socket.gaierror:
            pass
        except Exception:
            pass

        return aliases

    def _register_scope_host(self, host: str, port: Optional[int], target: bool = False):
        if not host:
            return

        aliases = self._expand_host_aliases(host)
        self.allowed_domains.update(aliases)
        if port:
            self.allowed_host_ports.update({f"{alias}:{port}" for alias in aliases})

        if target:
            self.target_aliases.update(aliases)
            if port:
                self.target_host_ports.update({f"{alias}:{port}" for alias in aliases})

    def _matches_scope(self, hostname: str, port: Optional[int], aliases: Set[str], scoped_host_ports: Set[str]) -> bool:
        hostname = (hostname or "").strip().lower()
        if not hostname:
            return False
        if hostname not in aliases:
            return False
        if not scoped_host_ports or port is None:
            return True
        return f"{hostname}:{port}" in scoped_host_ports
    
    def _normalize_url(self, url: str) -> Tuple[str, str, str]:
        """
        Normalize URL to extract base host, port, and path.
        Returns: (hostname:port, scheme, path)
        """
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or parsed.netloc or ''
        port = parsed.port
        scheme = parsed.scheme or 'http'
        path = parsed.path or '/'
        
        # Build normalized host:port
        if port:
            host_port = f"{hostname}:{port}"
        else:
            # Default ports
            if scheme == 'https':
                host_port = hostname if port != 443 else hostname
            else:
                host_port = hostname if port != 80 else hostname
        
        return host_port, scheme, path
    
    def _is_duplicate(self, url: str) -> bool:
        """Check if this host:port has been seen before"""
        host_port, _, _ = self._normalize_url(url)
        if host_port in self.seen_hosts:
            return True
        self.seen_hosts.add(host_port)
        return False
    
    def _is_sub_path(self, url: str) -> bool:
        """
        Check if URL is a sub-path of another domain rather than a separate host.
        Sub-paths are like /wp-admin/, /author/, etc. - they should be treated as 
        endpoints of the parent host, not separate scan targets.
        """
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.lower()
        
        # Check if path has multiple segments (indicating it's a path, not root)
        path_segments = [s for s in path.split('/') if s]
        
        # If path has content and matches sub-path patterns
        for pattern in SUB_PATH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                return True
        
        # If path is deep (more than 2 segments) and URL has no subdomain
        if len(path_segments) >= 2:
            hostname = parsed.hostname or ''
            # Check if it's a root domain (no subdomain) with a deep path
            parts = hostname.split('.')
            if len(parts) == 2:  # example.com (no subdomain)
                return True
        
        return False
    
    def _is_dev_test(self, url: str) -> bool:
        """Check if URL appears to be a dev/test environment"""
        url_lower = url.lower()
        
        for pattern in DEV_TEST_PATTERNS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _is_production(self, url: str) -> bool:
        """Check if URL appears to be a production environment"""
        url_lower = url.lower()
        hostname = urllib.parse.urlparse(url).hostname or ''
        
        # Check production indicators
        for pattern in PRODUCTION_INDICATORS:
            if re.search(pattern, hostname.lower(), re.IGNORECASE):
                return True
        
        # If it's not dev/test, consider it production by default
        if not self._is_dev_test(url):
            return True
        
        return False
    
    def _is_third_party(self, url: str) -> bool:
        """Check if URL belongs to a third-party domain (not target scope)"""
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or '').lower()
        
        # Check exact match
        if hostname in THIRD_PARTY_DOMAINS:
            return True
        
        # Check if it's a subdomain of a third-party domain
        for domain in THIRD_PARTY_DOMAINS:
            if hostname.endswith('.' + domain):
                return True
        
        return False
    
    def _is_free_hosting(self, url: str) -> bool:
        """Check if URL is a subdomain of a free hosting/blog platform.
        
        This filters user sites on free platforms (e.g., example.wordpress.com)
        but NOT the platform's own main domain (e.g., wordpress.com itself)
        or its www subdomain (e.g., www.wordpress.com).
        """
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or '').lower()
        
        # Only check if it's a SUBDOMAIN of a free hosting platform
        # e.g., example.wordpress.com, mysite.blogspot.com
        # We do NOT filter:
        # - The main domain itself (wordpress.com, blogspot.com)
        # - The www subdomain (www.wordpress.com)
        # because those are the platform owners, not free users
        for domain in FREE_HOSTING_DOMAINS:
            if hostname.endswith('.' + domain):
                # Get the subdomain part (everything before the domain)
                subdomain = hostname[:-(len(domain) + 1)]
                # Only filter if it's NOT just 'www' (standard www subdomain)
                if subdomain and subdomain != 'www':
                    return True
        
        return False
    
    def _is_suspicious_subdomain(self, url: str) -> bool:
        """Check if URL has auto-generated or suspicious subdomain patterns"""
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or '').lower()
        
        # Check total hostname length
        if len(hostname) > MAX_HOSTNAME_LENGTH:
            return True
        
        # Check each label in the hostname
        labels = hostname.split('.')
        for label in labels:
            # Check individual label length
            if len(label) > MAX_SUBDOMAIN_LABEL_LENGTH:
                return True
            
            # Check for suspicious patterns (only for non-TLD labels)
            for pattern in SUSPICIOUS_SUBDOMAIN_PATTERNS:
                if re.match(pattern, label + '.'):
                    return True
        
        return False

    def _is_target_domain(self, url: str) -> bool:
        """
        STRICT DOMAIN FILTER: Check if URL belongs to the target domain or its subdomains.
        This is the primary filter to eliminate foreign domains from archived data.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL belongs to target domain or subdomains, False otherwise
        """
        # If no target domain configured, allow all (backward compatibility)
        if not self.target_domain:
            return True
        
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or '').lower()
        port = parsed.port

        if self._matches_scope(hostname, port, self.target_aliases, self.target_host_ports):
            return True

        target = (self.target_domain or "").lower()
        if not target:
            return False

        if hostname == target or hostname.endswith('.' + target):
            return True

        if target.startswith('www.'):
            target_no_www = target[4:]
            if hostname == target_no_www or hostname.endswith('.' + target_no_www):
                return True

        if not target.startswith('www.'):
            target_with_www = 'www.' + target
            if hostname == target_with_www or hostname.endswith('.' + target_with_www):
                return True

        return False

    def _is_in_allowed_domains(self, url: str) -> bool:
        """
        MULTI-DOMAIN FILTER: Check if URL belongs to any of the allowed target domains.
        This supports scanning multiple targets from targets.txt simultaneously.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL belongs to any allowed domain or its subdomains, False otherwise.
            If allowed_domains is empty, returns True (backward compatibility).
        """
        # If no allowed_domains configured, allow all (backward compatibility)
        if not self.allowed_domains:
            return True
        
        parsed = urllib.parse.urlparse(url)
        hostname = (parsed.hostname or '').lower()
        port = parsed.port

        if self._matches_scope(hostname, port, self.allowed_domains, self.allowed_host_ports):
            return True

        for domain in self.allowed_domains:
            if hostname == domain or hostname.endswith('.' + domain):
                return True
            if domain.startswith('www.'):
                domain_no_www = domain[4:]
                if hostname == domain_no_www or hostname.endswith('.' + domain_no_www):
                    return True
            if not domain.startswith('www.'):
                domain_with_www = 'www.' + domain
                if hostname == domain_with_www or hostname.endswith('.' + domain_with_www):
                    return True
        
        return False
    
    def _get_host_priority(self, url: str) -> int:
        """
        Assign priority to host (higher = more important to scan)
        0 = skip, 1 = low, 2 = medium, 3 = high
        """
        if self._is_sub_path(url):
            return 0  # Skip sub-paths
        
        if self._is_dev_test(url):
            if self.skip_dev_test:
                return 0  # Skip dev/test if configured
            return 1  # Low priority
        
        if self._is_production(url):
            return 3  # High priority
        
        return 2  # Medium priority
    
    def filter_hosts(
        self, 
        hosts: List[Dict], 
        max_hosts: Optional[int] = None
    ) -> List[Dict]:
        """
        Filter and prioritize hosts for scanning.
        
        Args:
            hosts: List of host dictionaries with 'url' key
            max_hosts: Maximum number of hosts to return
        
        Returns:
            Filtered and prioritized list of hosts
        """
        self.stats['total'] = len(hosts)
        
        scored_hosts = []
        
        for host in hosts:
            url = host.get('url', '')
            if not url:
                continue
            
            # Check for duplicates
            if self._is_duplicate(url):
                self.stats['duplicates'] += 1
                logger.debug(f"[HOST_FILTER] Duplicate host: {url}")
                continue
            
            # Check for sub-paths
            if self._is_sub_path(url):
                self.stats['sub_paths'] += 1
                logger.debug(f"[HOST_FILTER] Sub-path (will be endpoint): {url}")
                # Mark as sub-path but don't add to scan list
                host['_is_sub_path'] = True
                continue
            
            # Check for dev/test
            if self._is_dev_test(url):
                self.stats['dev_test'] += 1
                if self.skip_dev_test:
                    logger.debug(f"[HOST_FILTER] Dev/test skipped: {url}")
                    continue
                else:
                    logger.debug(f"[HOST_FILTER] Dev/test (low priority): {url}")
            
            # Calculate priority
            priority = self._get_host_priority(url)
            if priority == 0:
                continue
            
            if self._is_production(url):
                self.stats['production'] += 1
            
            host['_priority'] = priority
            host['_url'] = url
            scored_hosts.append(host)
        
        # Sort by priority (descending) then by URL
        scored_hosts.sort(key=lambda h: (-h.get('_priority', 0), h.get('_url', '')))
        
        # Apply max_hosts limit
        if max_hosts:
            scored_hosts = scored_hosts[:max_hosts]
        
        self.stats['passed'] = len(scored_hosts)
        
        logger.info(f"[HOST_FILTER] Filtered: {self.stats['total']} → {self.stats['passed']} "
                   f"(duplicates: {self.stats['duplicates']}, sub_paths: {self.stats['sub_paths']}, "
                   f"dev/test: {self.stats['dev_test']})")
        
        return scored_hosts
    
    def filter_urls(
        self,
        urls: List[str],
        target_domain: Optional[str] = None,
        skip_third_party: bool = True,
        skip_free_hosting: bool = True,
        skip_suspicious: bool = True,
        skip_dev_test: bool = True,
        strict_domain_filter: bool = True  # NEW: Enable strict domain filtering
    ) -> List[str]:
        """
        Comprehensive URL filtering with all optimization filters.
        
        Args:
            urls: List of URLs to filter
            target_domain: Primary target domain (for context)
            skip_third_party: Filter out third-party domains
            skip_free_hosting: Filter out free hosting/blog platforms
            skip_suspicious: Filter out suspicious/auto-generated subdomains
            skip_dev_test: Filter out dev/test/staging environments
            strict_domain_filter: NEW - Only allow target domain and subdomains
        
        Returns:
            Filtered list of URLs
        """
        filtered = []
        seen = set()
        
        # Use instance target_domain if not provided
        effective_target = target_domain or self.target_domain
        
        # Update stats tracking
        filter_stats = {
            'total': len(urls),
            'third_party': 0,
            'free_hosting': 0,
            'suspicious': 0,
            'dev_test': 0,
            'duplicates': 0,
            'domain_filtered': 0,  # NEW: Track domain-filtered URLs
            'passed': 0,
        }
        
        for url in urls:
            url = (url or '').strip()
            if not url:
                continue
            
            # Check for duplicates
            if url in seen:
                filter_stats['duplicates'] += 1
                continue
            seen.add(url)
            
            # STRICT DOMAIN FILTER (NEW - highest priority)
            # Only allow URLs from target domain and its subdomains
            if strict_domain_filter and effective_target:
                # Temporarily set target_domain for this check
                original_target = self.target_domain
                self.target_domain = effective_target
                if not self._is_target_domain(url):
                    filter_stats['domain_filtered'] += 1
                    logger.debug(f"[HOST_FILTER] Domain filtered (not target): {url[:80]}")
                    self.target_domain = original_target
                    continue
                self.target_domain = original_target
            
            # Filter third-party domains
            if skip_third_party and self._is_third_party(url):
                filter_stats['third_party'] += 1
                logger.debug(f"[HOST_FILTER] Third-party filtered: {url[:80]}")
                continue
            
            # Filter free hosting platforms
            if skip_free_hosting and self._is_free_hosting(url):
                filter_stats['free_hosting'] += 1
                logger.debug(f"[HOST_FILTER] Free hosting filtered: {url[:80]}")
                continue
            
            # Filter suspicious/auto-generated subdomains
            if skip_suspicious and self._is_suspicious_subdomain(url):
                filter_stats['suspicious'] += 1
                logger.debug(f"[HOST_FILTER] Suspicious subdomain filtered: {url[:80]}")
                continue
            
            # Filter dev/test environments
            if skip_dev_test and self._is_dev_test(url):
                filter_stats['dev_test'] += 1
                logger.debug(f"[HOST_FILTER] Dev/test filtered: {url[:80]}")
                continue
            
            filtered.append(url)
        
        filter_stats['passed'] = len(filtered)
        
        logger.info(f"[HOST_FILTER] URL filtering: {filter_stats['total']} → {filter_stats['passed']} "
                   f"(domain_filtered: {filter_stats['domain_filtered']}, "
                   f"third_party: {filter_stats['third_party']}, free_hosting: {filter_stats['free_hosting']}, "
                   f"suspicious: {filter_stats['suspicious']}, dev_test: {filter_stats['dev_test']}, "
                   f"duplicates: {filter_stats['duplicates']})")
        
        return filtered
    
    def group_related_hosts(self, hosts: List[Dict]) -> Dict[str, List[str]]:
        """
        Group hosts by their root domain for analysis.
        Example: *.elo.edu.vn would be grouped together.
        """
        groups = defaultdict(list)
        
        for host in hosts:
            url = host.get('url', '') or host.get('_url', '')
            if not url:
                continue
            
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ''
            
            # Extract root domain (last 2-3 parts)
            parts = hostname.split('.')
            if len(parts) >= 2:
                # Root domain is last 2 parts (e.g., elo.edu.vn -> edu.vn)
                # or last 3 if it's a known TLD+1 like .co.uk
                if len(parts) > 2 and parts[-2] in ('co', 'com', 'edu', 'gov', 'org', 'net'):
                    root = '.'.join(parts[-3:])
                else:
                    root = '.'.join(parts[-2:])
                groups[root].append(url)
        
        return dict(groups)
    
    def get_stats(self) -> Dict:
        """Get filtering statistics"""
        return self.stats.copy()
    
    def reset(self):
        """Reset state for new filtering session"""
        self.seen_hosts.clear()
        self.host_groups.clear()
        self.stats = {k: 0 for k in self.stats}
