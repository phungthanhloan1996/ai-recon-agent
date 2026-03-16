# config.py - Configuration settings for the Autonomous Security Testing Agent

import os

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

# System Settings
OUTPUT_DIR = os.getenv('OUTPUT_DIR', 'results')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

# AI Models
PRIMARY_AI_MODEL = 'mixtral'  # or 'llama'
FALLBACK_AI_MODEL = 'anthropic'