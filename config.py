# config.py - Configuration settings for the Autonomous Security Testing Agent

import os

# Timeout Configuration (GLOBAL)
DEFAULT_TIMEOUT = 180  # Default timeout for lightweight operations
HEAVY_TOOL_TIMEOUT = 600  # Timeout for heavy tools: Katana, Hakrawler, Nuclei, WPScan
GROQ_TIMEOUT = 15  # Groq API timeout
HTTP_TIMEOUT = 10  # HTTP request timeout

# AI Configuration
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')

# WordPress Scanning
WPSCAN_API_TOKEN = os.getenv('WPSCAN_API_TOKEN')
NVD_API_KEY = os.getenv('NVD_API_KEY')

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
HTTP_POOL_SIZE = int(os.getenv('HTTP_POOL_SIZE', 20))

# Tool Execution
CRAWLER_TOOL_MAX_RETRIES = int(os.getenv('CRAWLER_TOOL_MAX_RETRIES', 1))
CRAWLER_RETRY_ON_TIMEOUT = os.getenv('CRAWLER_RETRY_ON_TIMEOUT', 'false').lower() == 'true'
KATANA_CONCURRENCY = int(os.getenv('KATANA_CONCURRENCY', 10))
KATANA_RATE_LIMIT = int(os.getenv('KATANA_RATE_LIMIT', 30))
KATANA_TIMEOUT = int(os.getenv('KATANA_TIMEOUT', 600))
KATANA_RUN_TIMEOUT = int(os.getenv('KATANA_RUN_TIMEOUT', 600))
HAKRAWLER_THREADS = int(os.getenv('HAKRAWLER_THREADS', 8))
HAKRAWLER_RUN_TIMEOUT = int(os.getenv('HAKRAWLER_RUN_TIMEOUT', 300))
WPSCAN_TIMEOUT = int(os.getenv('WPSCAN_TIMEOUT', 180))
NUCLEI_CONCURRENCY = int(os.getenv('NUCLEI_CONCURRENCY', 3))
NUCLEI_RATE_LIMIT = int(os.getenv('NUCLEI_RATE_LIMIT', 5))
NUCLEI_TEMPLATE_TIMEOUT = int(os.getenv('NUCLEI_TEMPLATE_TIMEOUT', 20))
NUCLEI_RUN_TIMEOUT = int(os.getenv('NUCLEI_RUN_TIMEOUT', 300))
NUCLEI_MAX_RETRIES = int(os.getenv('NUCLEI_MAX_RETRIES', 1))

# URL Validation & Error Recovery
MAX_URL_LENGTH = int(os.getenv('MAX_URL_LENGTH', 8192))
SKIP_MALFORMED_URLS = os.getenv('SKIP_MALFORMED_URLS', 'true').lower() == 'true'
ARJUN_IGNORE_ERRORS = os.getenv('ARJUN_IGNORE_ERRORS', 'true').lower() == 'true'

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
