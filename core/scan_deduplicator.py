"""
core/scan_deduplicator.py - Scan Deduplication Engine
Tracks what has been scanned to prevent redundant scanning.
Enhanced with: static file filtering, no-parameter URL skipping, intelligent deduplication.
"""

import json
import os
import logging
import time
import hashlib
import re
from typing import Dict, Set, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("recon.deduplicator")

# Static file extensions that should be skipped (low vulnerability potential)
STATIC_FILE_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp', '.avif',
    # Stylesheets
    '.css', '.scss', '.sass', '.less',
    # JavaScript (external files)
    '.js', '.jsx', '.ts', '.tsx', '.mjs',
    # Fonts
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    # Media
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    # Archives
    '.zip', '.tar', '.gz', '.rar', '.7z',
    # Data files
    '.json', '.xml', '.yaml', '.yml', '.toml', '.ini', '.conf',
    # Other static assets
    '.swf', '.wasm', '.manifest', '.appcache',
}

# URL patterns that indicate static/dynamic content worth scanning
DYNAMIC_URL_PATTERNS = [
    r'/api/', r'/rest/', r'/graphql', r'/action=', r'/cmd=',
    r'/search', r'/query', r'/filter', r'/admin/', r'/wp-',
    r'/login', r'/auth/', r'/upload', r'/download', r'/export',
    r'/import', r'/process', r'/submit', r'/update', r'/delete',
    r'/create', r'/edit', r'/view', r'/list', r'/fetch',
]

# File extensions that indicate dynamic/processable content
DYNAMIC_FILE_EXTENSIONS = {
    '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py',
    '.rb', '.aspx', '.ashx', '.asmx', '.svc', '.xaml',
}


class ScanDeduplicator:
    """
    Prevents redundant scanning by tracking:
    - URLs that have been scanned
    - Tools that have been run on specific hosts
    - Endpoints that have been probed
    - Timestamps of scans for TTL-based expiration
    """
    
    def __init__(self, output_dir: str, ttl_hours: int = 24):
        self.output_dir = output_dir
        self.ttl_seconds = ttl_hours * 3600
        self.cache_file = os.path.join(output_dir, "scan_dedup_cache.json")
        
        # In-memory tracking
        self.scanned_urls: Set[str] = set()
        self.scanned_hosts: Set[str] = set()
        self.tool_runs: Dict[str, Set[str]] = {}  # host -> set of tools run
        self.endpoint_probes: Set[str] = set()  # URLs that have been probed
        self.scan_timestamps: Dict[str, float] = {}  # key -> timestamp
        
        # Statistics
        self.stats = {
            "urls_deduplicated": 0,
            "hosts_deduplicated": 0,
            "tools_deduplicated": 0,
            "total_checks": 0,
        }
        
        self._load_cache()
    
    def _generate_url_hash(self, url: str) -> str:
        """Generate a normalized hash for a URL"""
        parsed = urlparse(url)
        # Normalize: lowercase scheme and host, sort query params
        normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
        if parsed.query:
            # Sort query parameters for consistent hashing
            params = sorted(parsed.query.split('&'))
            normalized += "?" + "&".join(params)
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def _load_cache(self):
        """Load deduplication cache from file"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                
                self.scanned_urls = set(data.get('scanned_urls', []))
                self.scanned_hosts = set(data.get('scanned_hosts', []))
                self.tool_runs = {k: set(v) for k, v in data.get('tool_runs', {}).items()}
                self.endpoint_probes = set(data.get('endpoint_probes', []))
                self.scan_timestamps = data.get('scan_timestamps', {})
                self.stats = data.get('stats', self.stats)
                
                # Clean expired entries
                self._cleanup_expired()
                
                logger.info(f"[DEDUP] Loaded cache: {len(self.scanned_urls)} URLs, "
                           f"{len(self.scanned_hosts)} hosts")
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"[DEDUP] Corrupted cache, starting fresh: {e}")
    
    def _cleanup_expired(self):
        """Remove expired entries based on TTL"""
        now = time.time()
        expired_keys = [
            key for key, ts in self.scan_timestamps.items()
            if now - ts > self.ttl_seconds
        ]
        
        for key in expired_keys:
            # Remove from appropriate sets based on key prefix
            if key.startswith('url:'):
                url_hash = key[4:]
                self.scanned_urls.discard(url_hash)
            elif key.startswith('host:'):
                host = key[5:]
                self.scanned_hosts.discard(host)
                if host in self.tool_runs:
                    del self.tool_runs[host]
            elif key.startswith('probe:'):
                probe_hash = key[6:]
                self.endpoint_probes.discard(probe_hash)
            
            del self.scan_timestamps[key]
        
        if expired_keys:
            logger.debug(f"[DEDUP] Cleaned up {len(expired_keys)} expired entries")
    
    def _save_cache(self):
        """Save deduplication cache to file"""
        data = {
            'scanned_urls': list(self.scanned_urls),
            'scanned_hosts': list(self.scanned_hosts),
            'tool_runs': {k: list(v) for k, v in self.tool_runs.items()},
            'endpoint_probes': list(self.endpoint_probes),
            'scan_timestamps': self.scan_timestamps,
            'stats': self.stats,
        }
        
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"[DEDUP] Failed to save cache: {e}")
    
    def is_url_scanned(self, url: str) -> bool:
        """Check if a URL has already been scanned"""
        self.stats["total_checks"] += 1
        url_hash = self._generate_url_hash(url)
        
        if url_hash in self.scanned_urls:
            self.stats["urls_deduplicated"] += 1
            return True
        return False
    
    def mark_url_scanned(self, url: str):
        """Mark a URL as scanned"""
        url_hash = self._generate_url_hash(url)
        self.scanned_urls.add(url_hash)
        self.scan_timestamps[f'url:{url_hash}'] = time.time()
        self._save_cache()
    
    def is_host_scanned(self, host: str) -> bool:
        """Check if a host has been scanned"""
        self.stats["total_checks"] += 1
        
        if host in self.scanned_hosts:
            self.stats["hosts_deduplicated"] += 1
            return True
        return False
    
    def mark_host_scanned(self, host: str):
        """Mark a host as scanned"""
        self.scanned_hosts.add(host)
        self.scan_timestamps[f'host:{host}'] = time.time()
        self._save_cache()
    
    def is_tool_run_on_host(self, host: str, tool_name: str) -> bool:
        """Check if a specific tool has been run on a host"""
        self.stats["total_checks"] += 1
        
        if host in self.tool_runs:
            if tool_name in self.tool_runs[host]:
                self.stats["tools_deduplicated"] += 1
                return True
        return False
    
    def mark_tool_run(self, host: str, tool_name: str):
        """Mark a tool as having been run on a host"""
        if host not in self.tool_runs:
            self.tool_runs[host] = set()
        self.tool_runs[host].add(tool_name)
        self._save_cache()
    
    def is_endpoint_probed(self, url: str) -> bool:
        """Check if an endpoint has been probed"""
        self.stats["total_checks"] += 1
        url_hash = self._generate_url_hash(url)
        
        if url_hash in self.endpoint_probes:
            return True
        return False
    
    def mark_endpoint_probed(self, url: str):
        """Mark an endpoint as probed"""
        url_hash = self._generate_url_hash(url)
        self.endpoint_probes.add(url_hash)
        self.scan_timestamps[f'probe:{url_hash}'] = time.time()
        self._save_cache()
    
    def filter_unscanned_urls(self, urls: List[str]) -> List[str]:
        """Filter out URLs that have already been scanned"""
        unscanned = []
        for url in urls:
            if not self.is_url_scanned(url):
                unscanned.append(url)
                self.mark_url_scanned(url)
        return unscanned
    
    def filter_unscanned_hosts(self, hosts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter out hosts that have already been scanned"""
        unscanned = []
        for host in hosts:
            host_url = host.get('url', '')
            if not host_url:
                continue
            parsed = urlparse(host_url)
            hostname = parsed.hostname or parsed.netloc
            
            if not self.is_host_scanned(hostname):
                unscanned.append(host)
                self.mark_host_scanned(hostname)
        return unscanned
    
    def filter_tools_for_host(self, host: str, tools: List[str]) -> List[str]:
        """Filter out tools that have already been run on a host"""
        unrun = []
        for tool in tools:
            if not self.is_tool_run_on_host(host, tool):
                unrun.append(tool)
                self.mark_tool_run(host, tool)
        return unrun
    
    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics"""
        return {
            **self.stats,
            'cached_urls': len(self.scanned_urls),
            'cached_hosts': len(self.scanned_hosts),
            'cached_tool_runs': sum(len(tools) for tools in self.tool_runs.values()),
            'cached_probes': len(self.endpoint_probes),
        }
    
    def is_static_file(self, url: str) -> bool:
        """
        Check if URL points to a static file that should be skipped.
        Static files have low vulnerability potential and waste scan budget.
        
        Args:
            url: URL to check
            
        Returns:
            True if the URL is a static file, False otherwise
        """
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        
        # Check file extension
        for ext in STATIC_FILE_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        
        # Check for common static asset directories
        static_dirs = [
            '/static/', '/assets/', '/public/', '/dist/', '/build/',
            '/node_modules/', '/vendor/', '/cdn/', '/media/',
            '/uploads/images/', '/uploads/files/', '/uploads/docs/',
        ]
        for dir_pattern in static_dirs:
            if dir_pattern in path_lower:
                # But allow dynamic files in these directories
                for dyn_ext in DYNAMIC_FILE_EXTENSIONS:
                    if path_lower.endswith(dyn_ext):
                        return False
                return True
        
        return False
    
    def has_scanable_parameters(self, url: str) -> bool:
        """
        Check if URL has parameters that can be tested for vulnerabilities.
        URLs without parameters are low-value targets for vulnerability scanning.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL has scanable parameters, False otherwise
        """
        parsed = urlparse(url)
        
        # Check for query parameters
        if parsed.query:
            params = parse_qs(parsed.query)
            if params:
                return True
        
        # Check for path parameters (e.g., /users/123, /api/v1/posts/42)
        path_segments = [s for s in parsed.path.split('/') if s]
        for segment in path_segments:
            # Numeric segments likely indicate IDs
            if segment.isdigit():
                return True
            # Segments that look like UUIDs
            if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', segment, re.IGNORECASE):
                return True
            # Segments with mixed alphanumeric that could be identifiers
            if len(segment) > 2 and segment.replace('-', '').replace('_', '').isdigit():
                return True
        
        # Check for dynamic URL patterns
        path_lower = parsed.path.lower()
        for pattern in DYNAMIC_URL_PATTERNS:
            if re.search(pattern, path_lower):
                return True
        
        # Check for dynamic file extensions
        for ext in DYNAMIC_FILE_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        
        # Check for common API patterns
        if '/api/' in path_lower or '/rest/' in path_lower or '/graphql' in path_lower:
            return True
        
        # Check for WordPress patterns
        if '/wp-' in path_lower or '/wp-admin' in path_lower or '/wp-content' in path_lower:
            return True
        
        return False
    
    def classify_url(self, url: str) -> Tuple[str, str]:
        """
        Classify URL by scan priority and reason.
        
        Returns:
            Tuple of (priority, reason) where priority is:
            - 'high': Has multiple parameters or injection-prone patterns
            - 'medium': Has some parameters or dynamic content
            - 'low': No parameters, static content, or low-value target
            - 'skip': Should be skipped entirely
        """
        # Check if static file - skip entirely
        if self.is_static_file(url):
            return ('skip', 'static_file')
        
        # Check for scanable parameters
        if not self.has_scanable_parameters(url):
            return ('low', 'no_parameters')
        
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        
        # High priority patterns
        high_priority_patterns = [
            r'/admin/', r'/login', r'/auth/', r'/api/',
            r'\bid\b=', r'\buserid\b=', r'\biduser\b=',
            r'\bpage\b=', r'\bsearch\b=', r'\bquery\b=',
            r'\bfile\b=', r'\bpath\b=', r'\burl\b=',
            r'\bredirect\b=', r'\bnext\b=', r'\bcmd\b=',
            r'\bexec\b=', r'\baction\b=', r'\bmethod\b=',
        ]
        
        query_lower = parsed.query.lower() if parsed.query else ''
        for pattern in high_priority_patterns:
            if re.search(pattern, path_lower) or re.search(pattern, query_lower):
                return ('high', 'injection_prone')
        
        # Check parameter count for medium priority
        if parsed.query:
            params = parse_qs(parsed.query)
            if len(params) >= 2:
                return ('high', 'multiple_parameters')
            elif len(params) == 1:
                return ('medium', 'single_parameter')
        
        # Dynamic file extensions are medium priority
        for ext in DYNAMIC_FILE_EXTENSIONS:
            if path_lower.endswith(ext):
                return ('medium', 'dynamic_file')
        
        # Path with numeric segments is medium priority
        path_segments = [s for s in parsed.path.split('/') if s]
        for segment in path_segments:
            if segment.isdigit():
                return ('medium', 'path_parameter')
        
        return ('low', 'generic_endpoint')
    
    def filter_urls_for_scanning(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        Filter and categorize URLs for scanning based on priority.
        This is the main method to reduce noise in scanning.
        
        Args:
            urls: List of URLs to filter
            
        Returns:
            Dictionary with categorized URLs:
            - 'high': High priority URLs (scan first)
            - 'medium': Medium priority URLs (scan if time permits)
            - 'low': Low priority URLs (scan last)
            - 'skipped': URLs that should be skipped
        """
        results = {
            'high': [],
            'medium': [],
            'low': [],
            'skipped': [],
        }
        
        stats = {
            'static_files': 0,
            'no_parameters': 0,
            'duplicates': 0,
            'high_priority': 0,
            'medium_priority': 0,
            'low_priority': 0,
        }
        
        seen_urls: Set[str] = set()
        
        for url in urls:
            # Check for duplicates first
            url_hash = self._generate_url_hash(url)
            if url_hash in seen_urls:
                stats['duplicates'] += 1
                results['skipped'].append(url)
                continue
            seen_urls.add(url_hash)
            
            # Classify URL
            priority, reason = self.classify_url(url)
            
            if priority == 'skip':
                stats['static_files'] += 1
                results['skipped'].append(url)
            elif priority == 'high':
                stats['high_priority'] += 1
                results['high'].append(url)
            elif priority == 'medium':
                stats['medium_priority'] += 1
                results['medium'].append(url)
            else:
                stats['no_parameters'] += 1
                results['low'].append(url)
        
        # Log statistics
        logger.info(f"[DEDUP] URL filtering: {len(urls)} total -> "
                   f"{stats['high_priority']} high, {stats['medium_priority']} medium, "
                   f"{stats['no_parameters']} low, {stats['static_files']} static, "
                   f"{stats['duplicates']} duplicates")
        
        # Update stats
        self.stats['static_files_skipped'] = self.stats.get('static_files_skipped', 0) + stats['static_files']
        self.stats['no_param_urls_skipped'] = self.stats.get('no_param_urls_skipped', 0) + stats['no_parameters']
        self.stats['duplicates_removed'] = self.stats.get('duplicates_removed', 0) + stats['duplicates']
        
        return results
    
    def get_priority_urls(self, urls: List[str], max_high: int = 100, 
                          max_medium: int = 200) -> List[str]:
        """
        Get prioritized list of URLs for scanning within budget.
        
        Args:
            urls: List of URLs to prioritize
            max_high: Maximum high-priority URLs to return
            max_medium: Maximum medium-priority URLs to return
            
        Returns:
            Prioritized list of URLs within scan budget
        """
        filtered = self.filter_urls_for_scanning(urls)
        
        result = []
        
        # Add all high priority (up to limit)
        result.extend(filtered['high'][:max_high])
        
        # Add medium priority (up to limit)
        result.extend(filtered['medium'][:max_medium])
        
        # Add low priority only if we have room
        remaining = max(0, max_high + max_medium - len(result))
        if remaining > 0:
            result.extend(filtered['low'][:remaining])
        
        logger.info(f"[DEDUP] Prioritized {len(result)} URLs from {len(urls)} total")
        
        return result

    def clear(self):
        """Clear all deduplication data"""
        self.scanned_urls.clear()
        self.scanned_hosts.clear()
        self.tool_runs.clear()
        self.endpoint_probes.clear()
        self.scan_timestamps.clear()
        self.stats = {
            "urls_deduplicated": 0,
            "hosts_deduplicated": 0,
            "tools_deduplicated": 0,
            "total_checks": 0,
        }
        if os.path.exists(self.cache_file):
            os.remove(self.cache_file)
        logger.info("[DEDUP] Cleared all deduplication data")
