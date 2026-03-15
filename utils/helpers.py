import re
import hashlib

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════╗
║         🤖 AI PENTEST AGENT v4.0 - HYBRID              ║
║          Rule-based + AI decision engine                ║
╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def extract_urls(text):
    """Extract URLs from text"""
    url_pattern = r'https?://[^\s\'"]+'
    return re.findall(url_pattern, text)

def hash_data(data):
    """Create hash for caching"""
    return hashlib.md5(str(data).encode()).hexdigest()

def parse_version(version_str):
    """Parse version string to tuple"""
    try:
        return tuple(map(int, version_str.split('.')))
    except:
        return (0, 0, 0)
