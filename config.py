# config.py - Configuration settings for the Autonomous Security Testing Agent

import os

# Timeout Configuration (GLOBAL)
# OPTIMIZATION: Aggressively reduced timeouts for faster fail-fast
DEFAULT_TIMEOUT = 60  # Default timeout for lightweight operations (reduced from 90)
HEAVY_TOOL_TIMEOUT = 90  # Timeout for heavy tools (reduced from 120)
GROQ_TIMEOUT = 10  # Groq API timeout (reduced from 15)
HTTP_TIMEOUT = 20  # HTTP request timeout (reduced from 10 for faster fail-fast)
AMASS_TIMEOUT = int(os.getenv('AMASS_TIMEOUT', 45))  # Amass timeout (reduced from 60)
CT_API_TIMEOUT = int(os.getenv('CT_API_TIMEOUT', 8))  # Certificate Transparency lookups (reduced from 10)

# Circuit Breaker Configuration (NEW)
CIRCUIT_BREAKER_THRESHOLD = int(os.getenv('CIRCUIT_BREAKER_THRESHOLD', 2))  # Failures before skipping host
CIRCUIT_BREAKER_WINDOW = int(os.getenv('CIRCUIT_BREAKER_WINDOW', 300))  # Time window in seconds for counting failures

# AI Configuration
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY')

# WordPress Scanning - API token removed (no longer using WPScan API)

# Limits for Exploitation
MAX_SQLI_TARGETS = int(os.getenv('MAX_SQLI_TARGETS', 6))
MAX_UPLOAD_TARGETS = int(os.getenv('MAX_UPLOAD_TARGETS', 4))
MAX_LFI_TARGETS = int(os.getenv('MAX_LFI_TARGETS', 5))
MAX_XSS_TARGETS = int(os.getenv('MAX_XSS_TARGETS', 10))
MAX_WP_PLUGINS = int(os.getenv('MAX_WP_PLUGINS', 4))

# Scanning Parameters
CRAWL_DEPTH = int(os.getenv('CRAWL_DEPTH', 4))
CRAWL_PARALLEL_HOSTS = int(os.getenv('CRAWL_PARALLEL_HOSTS', 6))
NIKTO_PARALLEL = int(os.getenv('NIKTO_PARALLEL', 4))
NIKTO_MAX_HOSTS = int(os.getenv('NIKTO_MAX_HOSTS', 10))
RANK_TOP = int(os.getenv('RANK_TOP', 150))
SCANNING_MAX_WORKERS = int(os.getenv('SCANNING_MAX_WORKERS', 4))
NUCLEI_MIN_ENDPOINT_SCORE = int(os.getenv('NUCLEI_MIN_ENDPOINT_SCORE', 8))
AI_PAYLOAD_MIN_SCORE = int(os.getenv('AI_PAYLOAD_MIN_SCORE', 8))
PAYLOAD_MUTATION_MIN_SCORE = int(os.getenv('PAYLOAD_MUTATION_MIN_SCORE', 7))
PAYLOAD_MUTATION_MAX = int(os.getenv('PAYLOAD_MUTATION_MAX', 12))
SCAN_PAYLOAD_DELAY = float(os.getenv('SCAN_PAYLOAD_DELAY', '0.05'))

# System Settings
OUTPUT_DIR = os.getenv('OUTPUT_DIR', 'results')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
SSL_VERIFY = os.getenv('SSL_VERIFY', 'false').lower() == 'true'
LOCAL_HTTP_ONLY = os.getenv('LOCAL_HTTP_ONLY', 'true').lower() == 'true'

# AI Models
PRIMARY_AI_MODEL = 'llama-3.3-70b-versatile'  # or 'llama'
FALLBACK_AI_MODEL = 'anthropic'

# Groq Controls
GROQ_ENABLE_PAYLOADS = os.getenv('GROQ_ENABLE_PAYLOADS', 'true').lower() == 'true'
GROQ_ALLOWED_CATEGORIES = tuple(
    part.strip().lower()
    for part in os.getenv(
        'GROQ_ALLOWED_CATEGORIES',
        'sql_injection,command_injection,file_inclusion,file_upload,sqli,rce,lfi'
    ).split(',')
    if part.strip()
)
GROQ_MAX_CONCURRENCY = int(os.getenv('GROQ_MAX_CONCURRENCY', 1))
GROQ_MIN_INTERVAL = float(os.getenv('GROQ_MIN_INTERVAL', '2.5'))
GROQ_MAX_RETRIES = int(os.getenv('GROQ_MAX_RETRIES', 2))
GROQ_CACHE_TTL_SECONDS = int(os.getenv('GROQ_CACHE_TTL_SECONDS', 3600))
GROQ_429_COOLDOWN_SECONDS = int(os.getenv('GROQ_429_COOLDOWN_SECONDS', 120))
GROQ_429_CIRCUIT_BREAKER = int(os.getenv('GROQ_429_CIRCUIT_BREAKER', 5))
ENABLE_AI_RESPONSE_SCAN = os.getenv('ENABLE_AI_RESPONSE_SCAN', 'false').lower() == 'true'
AI_RESPONSE_SCAN_MAX_CALLS = int(os.getenv('AI_RESPONSE_SCAN_MAX_CALLS', 10))
AI_RESPONSE_SCAN_MIN_CONFIDENCE = float(os.getenv('AI_RESPONSE_SCAN_MIN_CONFIDENCE', '0.75'))

# HTTP Backpressure
HTTP_MIN_DELAY = float(os.getenv('HTTP_MIN_DELAY', '0.75'))
HTTP_MAX_DELAY = float(os.getenv('HTTP_MAX_DELAY', '5.0'))
HTTP_BACKOFF_FACTOR = float(os.getenv('HTTP_BACKOFF_FACTOR', '1.0'))
HTTP_POOL_SIZE = int(os.getenv('HTTP_POOL_SIZE', 50))  # Increased from 20 (was causing pool exhaustion)
HTTP_CONSECUTIVE_FAILURES_BLACKLIST = int(os.getenv('HTTP_CONSECUTIVE_FAILURES_BLACKLIST', 8))  # Blacklist after N consecutive failures

# Tool Execution
CRAWLER_TOOL_MAX_RETRIES = int(os.getenv('CRAWLER_TOOL_MAX_RETRIES', 1))
CRAWLER_RETRY_ON_TIMEOUT = os.getenv('CRAWLER_RETRY_ON_TIMEOUT', 'false').lower() == 'true'
KATANA_CONCURRENCY = int(os.getenv('KATANA_CONCURRENCY', 10))
KATANA_RATE_LIMIT = int(os.getenv('KATANA_RATE_LIMIT', 30))
KATANA_TIMEOUT = int(os.getenv('KATANA_TIMEOUT', 120))  # FIXED: Reduced from 600s to 120s per-url
KATANA_RUN_TIMEOUT = int(os.getenv('KATANA_RUN_TIMEOUT', 300))  # FIXED: Reduced from 600s to 300s total
HAKRAWLER_THREADS = int(os.getenv('HAKRAWLER_THREADS', 8))
HAKRAWLER_RUN_TIMEOUT = int(os.getenv('HAKRAWLER_RUN_TIMEOUT', 180))  # FIXED: Reduced from 300s to 180s
NUCLEI_CONCURRENCY = int(os.getenv('NUCLEI_CONCURRENCY', 3))
NUCLEI_RATE_LIMIT = int(os.getenv('NUCLEI_RATE_LIMIT', 5))
NUCLEI_TEMPLATE_TIMEOUT = int(os.getenv('NUCLEI_TEMPLATE_TIMEOUT', 20))
NUCLEI_RUN_TIMEOUT = int(os.getenv('NUCLEI_RUN_TIMEOUT', 300))
NUCLEI_MAX_RETRIES = int(os.getenv('NUCLEI_MAX_RETRIES', 1))
PARAM_MINER_TIMEOUT = int(os.getenv('PARAM_MINER_TIMEOUT', 8))
PARAM_MINER_MAX_ENDPOINTS = int(os.getenv('PARAM_MINER_MAX_ENDPOINTS', 20))
PARAM_MINER_MAX_CANDIDATES = int(os.getenv('PARAM_MINER_MAX_CANDIDATES', 24))
PARAM_MINER_LOCAL_MAX_CANDIDATES = int(os.getenv('PARAM_MINER_LOCAL_MAX_CANDIDATES', 12))

# URL Validation & Error Recovery
MAX_URL_LENGTH = int(os.getenv('MAX_URL_LENGTH', 8192))
SKIP_MALFORMED_URLS = os.getenv('SKIP_MALFORMED_URLS', 'true').lower() == 'true'
ARJUN_IGNORE_ERRORS = os.getenv('ARJUN_IGNORE_ERRORS', 'true').lower() == 'true'
WAYBACK_PAGINATION_SIZE = int(os.getenv('WAYBACK_PAGINATION_SIZE', 5000))  # Pagination limit for Wayback (was hard 2000)
WAYBACK_PAGINATION_OFFSET = int(os.getenv('WAYBACK_PAGINATION_OFFSET', 5000))  # Amount to step each pagination
URL_DEDUP_ENABLED = os.getenv('URL_DEDUP_ENABLED', 'true').lower() == 'true'  # Normalize URLs, strip noise params
WAF_BYPASS_FILTER_NO_PARAMS = os.getenv('WAF_BYPASS_FILTER_NO_PARAMS', 'true').lower() == 'true'  # Skip WAF bypass for URLs without parameters

# Adaptive Timeout
ADAPTIVE_TIMEOUT_ENABLED = os.getenv('ADAPTIVE_TIMEOUT_ENABLED', 'true').lower() == 'true'
CRAWLER_TIMEOUT_ON_SLOW_SITE = int(os.getenv('CRAWLER_TIMEOUT_ON_SLOW_SITE', 900))

# Error Recovery
MAX_RETRIES_FOR_INVALID_URL = int(os.getenv('MAX_RETRIES_FOR_INVALID_URL', 0))
ERROR_RECOVERY_SKIP_PHASE_AFTER = int(os.getenv('ERROR_RECOVERY_SKIP_PHASE_AFTER', 3))

# Crawler Fallback
ENABLE_CRAWLER_FALLBACK = os.getenv('ENABLE_CRAWLER_FALLBACK', 'true').lower() == 'true'
FALLBACK_TO_ARCHIVED_ON_TIMEOUT = os.getenv('FALLBACK_TO_ARCHIVED_ON_TIMEOUT', 'true').lower() == 'true'
MIN_LIVE_HOSTS_FOR_FALLBACK = int(os.getenv('MIN_LIVE_HOSTS_FOR_FALLBACK', 3))

# Per-Target Resource Isolation
MAX_CONCURRENT_TARGETS = int(os.getenv('MAX_CONCURRENT_TARGETS', 2))  # Process 2 targets at a time max (reduced from 5)
PER_TARGET_HTTP_POOL_SIZE = int(os.getenv('PER_TARGET_HTTP_POOL_SIZE', 25))  # Pool size per target
PER_TARGET_CRAWLER_WORKERS = int(os.getenv('PER_TARGET_CRAWLER_WORKERS', 8))  # Workers per target

# Global Rate Limiter (NEW - Token Bucket Algorithm)
GLOBAL_RATE_LIMIT = int(os.getenv('GLOBAL_RATE_LIMIT', 50))  # Max requests per second globally
GLOBAL_RATE_LIMIT_ENABLED = os.getenv('GLOBAL_RATE_LIMIT_ENABLED', 'true').lower() == 'true'
RATE_LIMIT_BURST = int(os.getenv('RATE_LIMIT_BURST', 10))  # Max burst size for token bucket

# Tor Integration
TOR_ENABLED = os.getenv('TOR_ENABLED', 'false').lower() == 'true'
TOR_PROXY_PORT = int(os.getenv('TOR_PROXY_PORT', 9050))
TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', 9051))
TOR_PROXY_URL = os.getenv('TOR_PROXY_URL', f'socks5://127.0.0.1:{TOR_PROXY_PORT}')

# ═══════════════════════════════════════════════════════════════════
# NEW: Async Scanner Configuration
# ═══════════════════════════════════════════════════════════════════
ASYNC_MAX_CONCURRENT = int(os.getenv('ASYNC_MAX_CONCURRENT', 50))
ASYNC_RATE_LIMIT = float(os.getenv('ASYNC_RATE_LIMIT', 100.0))
ASYNC_CACHE_TTL = int(os.getenv('ASYNC_CACHE_TTL', 3600))

# ═══════════════════════════════════════════════════════════════════
# NEW: Distributed Engine Configuration
# ═══════════════════════════════════════════════════════════════════
DISTRIBUTED_ENABLED = os.getenv('DISTRIBUTED_ENABLED', 'false').lower() == 'true'
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

# ═══════════════════════════════════════════════════════════════════
# NEW: Metasploit Configuration
# ═══════════════════════════════════════════════════════════════════
METASPLOIT_ENABLED = os.getenv('METASPLOIT_ENABLED', 'false').lower() == 'true'
METASPLOIT_HOST = os.getenv('METASPLOIT_HOST', '127.0.0.1')
METASPLOIT_PORT = int(os.getenv('METASPLOIT_PORT', 55553))
METASPLOIT_PASSWORD = os.getenv('METASPLOIT_PASSWORD', '')

# ═══════════════════════════════════════════════════════════════════
# NEW: Burp Suite Configuration
# ═══════════════════════════════════════════════════════════════════
BURP_ENABLED = os.getenv('BURP_ENABLED', 'false').lower() == 'true'
BURP_HOST = os.getenv('BURP_HOST', '127.0.0.1')
BURP_PORT = int(os.getenv('BURP_PORT', 1337))
BURP_API_KEY = os.getenv('BURP_API_KEY', '')

# ═══════════════════════════════════════════════════════════════════
# NEW: ML Classifier Configuration
# ═══════════════════════════════════════════════════════════════════
ML_CLASSIFIER_ENABLED = os.getenv('ML_CLASSIFIER_ENABLED', 'true').lower() == 'true'
ML_MIN_CONFIDENCE = float(os.getenv('ML_MIN_CONFIDENCE', '0.5'))

# ═══════════════════════════════════════════════════════════════════
# NEW: Exploit Chain Optimizer
# ═══════════════════════════════════════════════════════════════════
CHAIN_OPTIMIZER_ENABLED = os.getenv('CHAIN_OPTIMIZER_ENABLED', 'true').lower() == 'true'
CHAIN_OPTIMIZATION_STRATEGY = os.getenv('CHAIN_OPTIMIZATION_STRATEGY', 'balanced')

# ═══════════════════════════════════════════════════════════════════
# NEW: LLM Analyzer
# ═══════════════════════════════════════════════════════════════════
LLM_ANALYZER_ENABLED = os.getenv('LLM_ANALYZER_ENABLED', 'true').lower() == 'true'
LLM_FALLBACK_RULE_BASED = os.getenv('LLM_FALLBACK_RULE_BASED', 'true').lower() == 'true'
