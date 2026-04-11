import urllib.parse
import time
import random
import json
from urllib.parse import urlparse
from ddgs import DDGS
from tqdm import tqdm
import re
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from collections import defaultdict, deque
import warnings
import sys
import ipaddress


warnings.filterwarnings('ignore', message='Unverified HTTPS request')
def is_ip(domain):
    """Kiểm tra xem domain có phải là địa chỉ IP (IPv4 hoặc IPv6) không"""
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def looks_like_cdn_or_api(domain):
    """Kiểm tra domain có vẻ là CDN, cloud service, API endpoint hay không"""
    suspicious_keywords = [
        'cloudflare', 'akamai', 'fastly', 'cloudfront', 'azureedge', 'cdn',
        'googleusercontent', 'ggpht', 'gstatic', 'apis', 'api', 'graphql',
        'wp-api', 'json', 'rest', 'cdn.', 'edge.', 'proxy.', 'cache.',
        's3.', 'amazonaws', 'storage.googleapis', 'firebase', 'vercel',
        'netlify', 'herokuapp', 'pages.dev'
    ]
    
    domain_lower = domain.lower()
    
    if any(kw in domain_lower for kw in suspicious_keywords):
        return True
    
    if domain.count('.') >= 4:
        return True
    
    cdn_patterns = [
        r'^[a-z0-9-]+\.cdn\.',
        r'^[a-z0-9-]+\.edge\.',
        r'^[a-z0-9-]+\.api\.',
        r'^[a-z0-9-]+\.wpengine\.',
        r'^[a-z0-9-]+\.kinsta\.'
    ]
    
    for pattern in cdn_patterns:
        if re.search(pattern, domain_lower):
            return True
    
    return False

# Cấu hình - GIẢM TIMEOUT
DORKS = [
    '"Powered by WordPress" site:.vn',
    '"Powered by WordPress" site:.com.vn',
    'intext:"WordPress" site:.vn generator:"WordPress"',
    '"index of" inurl:wp-content site:.vn',
    'inurl:/wp-content/plugins/ site:.vn',
    'inurl:/wp-admin/ intitle:"Log In" site:.vn',
    'inurl:wp-login.php site:.vn',
    '"Powered by WordPress" inurl:.vn -inurl:(forum OR blogspot OR wordpress.com)',
    'inurl:/wp-content/themes/ site:.vn',
    'inurl:wp-config.php site:.vn',
    '"index of /wp-content/uploads/" site:.vn',
    'inurl:/wp-content/plugins/elementor/ site:.vn',
    'inurl:/wp-content/plugins/woocommerce/ site:.vn',
    'inurl:/wp-content/plugins/contact-form-7/ site:.vn',
    'inurl:/wp-content/plugins/revslider/ site:.vn',
    'site:.com.vn "WordPress"',
    'site:.vn inurl:wp-json',
    'site:.vn "xmlrpc.php"',
]

# DANH SÁCH PLUGIN PHỔ BIẾN
POPULAR_PLUGINS = {
    'yoast-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
    'wordpress-seo': {'name': 'Yoast SEO', 'category': 'SEO', 'installs': '10M+'},
    'elementor': {'name': 'Elementor', 'category': 'Page Builder', 'installs': '10M+'},
    'contact-form-7': {'name': 'Contact Form 7', 'category': 'Forms', 'installs': '10M+'},
    'woocommerce': {'name': 'WooCommerce', 'category': 'E-commerce', 'installs': '7M+'},
    'wordfence': {'name': 'Wordfence Security', 'category': 'Security', 'installs': '5M+'},
    'wp-mail-smtp': {'name': 'WP Mail SMTP', 'category': 'Email', 'installs': '5M+'},
    'google-site-kit': {'name': 'Site Kit by Google', 'category': 'Analytics', 'installs': '5M+'},
    'litespeed-cache': {'name': 'LiteSpeed Cache', 'category': 'Performance', 'installs': '7M+'},
    'revslider': {'name': 'Revolution Slider', 'category': 'Slider', 'installs': '10M+'},
}

CVE_DATABASE = {
    'wordpress': {
        '5.0-5.9': ['CVE-2020-28032', 'CVE-2021-44223'],
        '4.0-4.9': ['CVE-2019-17671', 'CVE-2020-11025'],
        '<4.0': ['CVE-2018-20148', 'CVE-2019-9787']
    },
    'elementor': {
        '<3.5.0': ['CVE-2022-29455'],
        '<3.2.0': ['CVE-2021-25028']
    },
    'revslider': {
        '<6.0.0': ['CVE-2021-38392'],
        '<5.0.0': ['CVE-2018-15505']
    },
    'woocommerce': {
        '<5.0.0': ['CVE-2021-24153'],
        '<4.0.0': ['CVE-2020-13225']
    },
    'contact-form-7': {
        '<5.4.0': ['CVE-2020-35489']
    }
}

# GIẢM TIMEOUT XUỐNG
NUM_RESULTS_PER_DORK = 50
OUTPUT_FILE = "wp_vn_domains.txt"
DOMAIN_VULN_FILE = "targets.txt"
ENHANCED_OUTPUT_FILE = "wp_enhanced_recon.json"
DELAY_MIN = 2.0  # Giảm delay
DELAY_MAX = 4.0
MAX_WORKERS_DISCOVERY = 5  # Tăng workers
MAX_WORKERS_RECON = 8     # Tăng workers
TIMEOUT = 6              # GIẢM từ 10 xuống 6
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
}

stop_flag = False

class WordPressReconEnhanced:
    def __init__(self, domain):
        self.domain = domain
        self.url = f"http://{domain}"
        self.https_url = f"https://{domain}"
        self.base_url = None
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        self.confidence = 0
        self.wp_signatures = []
        self.results = self._init_schema()
        
    def _init_schema(self):
        return {
            "target": self.domain,
            "scan_timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "wp": {"detected": False, "confidence": 0, "version": ""},
            "server": {"webserver": "", "php": ""},
            "plugins": [],
            "theme": {"name": "", "version": ""},
            "endpoints": {"xmlrpc": False, "rest_api": False},
            "security_indicators": {"waf_detected": "", "directory_listing": False},
            "vulnerability_indicators": {"risk_score": 0, "cve_matches": []},
            "scan_metadata": {"duration": 0, "requests_made": 0, "status": "pending"}
        }
    
    def _make_request(self, url, method='GET', allow_redirects=True, timeout=TIMEOUT):
        if stop_flag:
            return None
        try:
            response = self.session.request(
                method=method, url=url, allow_redirects=allow_redirects, timeout=timeout
            )
            self.results['scan_metadata']['requests_made'] += 1
            return response
        except:
            return None
    
    def _detect_wp_signatures(self):
        response = self._make_request(self.base_url, timeout=4)
        if not response:
            return False
        
        html = response.text
        
        if '/wp-content/' in html:
            self.wp_signatures.append('wp_content_structure')
        
        login_response = self._make_request(f"{self.base_url}/wp-login.php", timeout=3)
        if login_response and login_response.status_code < 400:
            self.wp_signatures.append('wp_login_page')
            self.results['endpoints']['xmlrpc'] = True
        
        rest_response = self._make_request(f"{self.base_url}/wp-json/", timeout=3)
        if rest_response and rest_response.status_code == 200:
            self.wp_signatures.append('wp_json_api')
            self.results['endpoints']['rest_api'] = True
        
        if 'WordPress' in html and 'generator' in html.lower():
            self.wp_signatures.append('wp_generator_tag')
        
        if '/wp-includes/' in html:
            self.wp_signatures.append('wp_includes')
        
        return len(self.wp_signatures) > 0
    
    def _calculate_wp_confidence(self):
        confidence = 0
        signature_weights = {
            'wp_content_structure': 20, 'wp_login_page': 25,
            'wp_json_api': 15, 'wp_generator_tag': 10,
            'wp_includes': 15
        }
        
        for signature in self.wp_signatures:
            if signature in signature_weights:
                confidence += signature_weights[signature]
        
        self.results['wp']['confidence'] = min(confidence, 100)
        self.results['wp']['detected'] = confidence >= 30
    
    def _detect_wp_version_enhanced(self):
        version_sources = []
        detected_version = ""
        
        response = self._make_request(self.base_url, timeout=3)
        if response:
            html = response.text
            meta_match = re.search(r'content=["\']WordPress ([\d.]+)["\']', html)
            if meta_match:
                detected_version = meta_match.group(1)
                version_sources.append(('meta', detected_version))
            
            if not detected_version:
                script_match = re.search(r'wp-embed\.js\?ver=([\d.]+)', html)
                if script_match:
                    detected_version = script_match.group(1)
                    version_sources.append(('script', detected_version))
        
        if detected_version:
            self.results['wp']['version'] = detected_version
            try:
                if int(detected_version.split('.')[0]) < 6:
                    self.results['vulnerability_indicators']['risk_score'] += 30
            except:
                pass
    
    def _detect_plugins_enhanced(self):
        plugins_found = []
        response = self._make_request(self.base_url, timeout=3)
        if not response:
            return
        
        html = response.text
        html_slugs = set(re.findall(r'/wp-content/plugins/([^/]+)/', html))
        
        for plugin_slug in list(html_slugs)[:15]:
            plugin_data = {
                "slug": plugin_slug,
                "detected": False,
                "version": None,
                "popular": False
            }
            
            plugin_key = plugin_slug.lower().replace('_', '-')
            if plugin_key in POPULAR_PLUGINS:
                plugin_data["popular"] = True
            
            readme_url = f"{self.base_url}/wp-content/plugins/{plugin_slug}/readme.txt"
            readme_resp = self._make_request(readme_url, timeout=3)
            
            if readme_resp and readme_resp.status_code == 200:
                plugin_data["detected"] = True
                content = readme_resp.text
                version_match = re.search(r'Stable tag:\s*([\d.]+)', content, re.IGNORECASE)
                if version_match:
                    plugin_data["version"] = version_match.group(1).strip()
            
            if plugin_data["detected"]:
                plugins_found.append(plugin_data)
        
        self.results["plugins"] = plugins_found
    
    def _check_cve_vulnerabilities(self):
        cve_matches = []
        wp_version = self.results['wp']['version']
        
        if wp_version:
            for version_range, cves in CVE_DATABASE.get('wordpress', {}).items():
                if self._check_version_in_range(wp_version, version_range):
                    for cve in cves:
                        cve_matches.append({'component': 'wordpress', 'cve': cve})
        
        for plugin in self.results['plugins']:
            if plugin.get('version') and plugin.get('slug'):
                plugin_slug = plugin['slug']
                plugin_version = plugin['version']
                
                for plugin_name in CVE_DATABASE.keys():
                    if plugin_name != 'wordpress' and plugin_name in plugin_slug.lower():
                        for version_range, cves in CVE_DATABASE.get(plugin_name, {}).items():
                            if self._check_version_in_range(plugin_version, version_range):
                                for cve in cves:
                                    cve_matches.append({'component': plugin_name, 'cve': cve})
        
        self.results['vulnerability_indicators']['cve_matches'] = cve_matches
        self.results['vulnerability_indicators']['risk_score'] += len(cve_matches) * 25
    
    def _check_version_in_range(self, version, version_range):
        try:
            if version_range.startswith('<'):
                max_version = version_range[1:]
                return self._compare_versions(version, max_version) < 0
            elif '-' in version_range:
                min_ver, max_ver = version_range.split('-')
                return (self._compare_versions(version, min_ver) >= 0 and 
                       self._compare_versions(version, max_ver) <= 0)
            return False
        except:
            return False
    
    def _compare_versions(self, v1, v2):
        v1_parts = list(map(int, v1.split('.')[:3]))
        v2_parts = list(map(int, v2.split('.')[:3]))
        while len(v1_parts) < 3: v1_parts.append(0)
        while len(v2_parts) < 3: v2_parts.append(0)
        for i in range(3):
            if v1_parts[i] != v2_parts[i]:
                return v1_parts[i] - v2_parts[i]
        return 0
    
    def scan(self):
        start_time = time.time()
        
        for test_url in [self.https_url, self.url]:
            response = self._make_request(test_url, timeout=4)
            if response and response.status_code < 400:
                self.base_url = test_url
                break
        
        if not self.base_url:
            self.results['scan_metadata']['status'] = 'failed_no_access'
            return self.results
        
        self._detect_wp_signatures()
        self._calculate_wp_confidence()
        
        if not self.results['wp']['detected']:
            self.results['scan_metadata']['status'] = 'failed_not_wordpress'
            return self.results
        
        self._detect_wp_version_enhanced()
        self._detect_plugins_enhanced()
        self._check_cve_vulnerabilities()
        
        self.results['scan_metadata']['duration'] = round(time.time() - start_time, 2)
        self.results['scan_metadata']['status'] = 'completed'
        
        return self.results
    
    def get_summary(self):
        if not self.results['wp']['detected']:
            return None
        
        return {
            'domain': self.domain,
            'wp_detected': self.results['wp']['detected'],
            'wp_version': self.results['wp']['version'] or 'Unknown',
            'plugins_count': len(self.results['plugins']),
            'risk_score': self.results['vulnerability_indicators']['risk_score'],
            'cve_count': len(self.results['vulnerability_indicators']['cve_matches'])
        }

# =================== V12 DISCOVERY ENGINE ===================
def v12_discovery_source():
    """Lấy domain từ GitHub và RapidDNS - REAL-TIME PROCESSING"""
    discovered = set()
    
    sources = [
        "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
        "https://rapiddns.io/subdomain/wp-content?full=1"
    ]
    
    for src in sources:
        try:
            r = requests.get(src, timeout=8, verify=False)  # GIẢM TIMEOUT
            raw_domains = re.findall(
                r'([a-zA-Z0-9.-]+\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn))',
                r.text
            )
            
            for d in raw_domains:
                domain = d.lower().replace("www.", "")
                discovered.add(domain)
                
        except Exception as e:
            print(f"  [!] V12 source error ({src}): {str(e)[:50]}")
            continue
    
    return discovered

def extract_domain_func(url):
    """Trích xuất domain từ URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        if domain.startswith('www.'):
            domain = domain[4:]
        
        pattern = r'^([a-z0-9][a-z0-9-]*\.)*[a-z0-9][a-z0-9-]*\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn)$'
        
        if re.match(pattern, domain):
            return domain
        return None
    except:
        return None

def v12_discovery_filter(domain):
    """Filter domain - NHANH HƠN"""
    if is_ip(domain):
        return {"accept": False, "scan_immediately": False}
    
    if domain.count('.') > 4:
        return {"accept": False, "scan_immediately": False}
    
    if looks_like_cdn_or_api(domain):
        return {"accept": False, "scan_immediately": False}
    
    # DOMAIN "NHIỀU MÁU" → SCAN NGAY
    high_value_patterns = [
        r'\.gov\.vn$', r'\.edu\.vn$', r'bank', r'credit', 
        r'payment', r'\.com\.vn$', r'shop', r'store'
    ]
    
    for pattern in high_value_patterns:
        if re.search(pattern, domain, re.I):
            return {"accept": True, "scan_immediately": True}
    
    return {"accept": True, "scan_immediately": False}

def collect_from_rapiddns(domain_keyword):
    """Lấy domain từ RapidDNS - NHANH HƠN"""
    domains = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain_keyword}?full=1"
        resp = requests.get(url, headers=HEADERS, timeout=6, verify=False)  # GIẢM TIMEOUT
        if resp.status_code == 200:
            matches = re.findall(
                r'([a-zA-Z0-9.-]+\.(?:vn|com\.vn|net\.vn|org\.vn|edu\.vn|gov\.vn))',
                resp.text
            )
            for domain_raw in matches:
                domain = domain_raw.lower().replace("www.", "")
                if extract_domain_func(f"http://{domain}"):
                    domains.add(domain)
    except Exception as e:
        print(f"\r\033[K  [!] RapidDNS timeout: {domain_keyword}")
    return domains

# =================== REAL-TIME DISPLAY ===================
def display_realtime_result(domain, result):
    """Hiển thị kết quả REAL-TIME lên terminal"""
    if result['wp_detected']:
        risk_score = result['risk_score']
        
        if risk_score >= 70:
            color = '\033[91m'  # RED
            status = "CRITICAL"
        elif risk_score >= 50:
            color = '\033[93m'  # YELLOW
            status = "HIGH"
        elif risk_score >= 30:
            color = '\033[33m'  # ORANGE
            status = "MEDIUM"
        else:
            color = '\033[92m'  # GREEN
            status = "LOW"
        
        print(f"\r\033[K{color}[REAL-TIME] {domain:<40} WP:{result['wp_version'][:8]:<8} "
              f"Plugins:{result['plugins_count']:<3} Risk:{risk_score:<3} {status}\033[0m")
    else:
        print(f"\r\033[K\033[90m[SKIP] {domain:<40} Not WordPress\033[0m")

# =================== MAIN DISCOVERY FUNCTION ===================
def collect_wp_domains_parallel():
    """Thu thập và xử lý domain REAL-TIME"""
    global stop_flag
    
    all_domains = set()
    rapiddns_seeds = set()
    new_domains_queue = deque()
    domain_state = {}
    
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            all_domains = {line.strip() for line in f if line.strip()}
        print(f"✓ Đã load {len(all_domains):,} domain cũ")
    
    print(f"\n{'='*60}")
    print(f"BẮT ĐẦU THU THẬP DOMAIN WORDPRESS - REAL-TIME")
    print(f"{'='*60}\n")
    
    lock = threading.Lock()
    processed_dorks = 0
    total_dorks = len(DORKS)
    enhanced_results = {}
    scan_count = 0
    vulnerable_domains = []
    
    if os.path.exists(DOMAIN_VULN_FILE):
        os.remove(DOMAIN_VULN_FILE)
    
    # =================== V12 SOURCE - PROCESS IMMEDIATELY ===================
    print("[1/3] V12 Discovery Source (GitHub + RapidDNS)...")
    v12_domains = v12_discovery_source()
    
    v12_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS_RECON)
    v12_futures = {}
    
    for domain in v12_domains:
        if stop_flag:
            break
            
        if domain in all_domains:
            continue
        
        # FILTER NGAY
        filter_result = v12_discovery_filter(domain)
        if not filter_result["accept"]:
            continue
        
        with lock:
            all_domains.add(domain)
            new_domains_queue.append(domain)
            domain_state[domain] = {"source": "v12", "processed": False}
        
        # SCAN NGAY NẾU "NHIỀU MÁU"
        if filter_result["scan_immediately"]:
            future = v12_executor.submit(scan_domain_immediately, domain)
            v12_futures[future] = domain
            print(f"\r\033[K\033[94m[SCAN-NOW] {domain} - High priority\033[0m")
    
    # Chờ scan hoàn thành
    for future in as_completed(v12_futures):
        if stop_flag:
            break
        domain = v12_futures[future]
        result = future.result()
        if result:
            display_realtime_result(domain, result)
    
    v12_executor.shutdown(wait=False)
    print(f"\n✓ V12: {len(v12_domains)} domains, {len(v12_futures)} scanned immediately")
    
    # =================== DUCKDUCKGO - PROCESS IMMEDIATELY ===================
    print(f"\n[2/3] DuckDuckGo ({len(DORKS)} dorks)...")
    
    def process_dork_realtime(dork_idx, dork):
        nonlocal processed_dorks
        
        if stop_flag:
            return dork_idx, 0, dork
        
        try:
            time.sleep(random.uniform(DELAY_MIN, DELAY_MAX))
            
            local_new_domains = []
            with DDGS() as ddgs:
                results = ddgs.text(
                    query=dork,
                    region="vn-vn",
                    safesearch="off",
                    max_results=NUM_RESULTS_PER_DORK,
                    timeout=10  # GIẢM TIMEOUT
                )
                
                for result in results:
                    if stop_flag:
                        break
                    
                    url = result.get('href', '') or result.get('url', '')
                    if url:
                        domain = extract_domain_func(url)
                        if domain and domain not in all_domains:
                            
                            # FILTER NGAY
                            filter_result = v12_discovery_filter(domain)
                            if not filter_result["accept"]:
                                continue
                            
                            with lock:
                                all_domains.add(domain)
                                new_domains_queue.append(domain)
                                local_new_domains.append(domain)
                                domain_state[domain] = {"source": "ddg", "processed": False}
                            
                            # SCAN NGAY NẾU "NHIỀU MÁU"
                            if filter_result["scan_immediately"]:
                                result = scan_domain_immediately(domain)
                                if result:
                                    display_realtime_result(domain, result)
                            
                            # DNS expansion seed
                            if not looks_like_cdn_or_api(domain) and domain.count('.') <= 3:
                                rapiddns_seeds.add(domain.replace("www.", ""))
                    
                    time.sleep(random.uniform(0.3, 0.8))  # GIẢM DELAY
            
            with lock:
                processed_dorks += 1
            
            return dork_idx, len(local_new_domains), dork
            
        except Exception as e:
            with lock:
                processed_dorks += 1
            return dork_idx, 0, dork
    
    # Chạy DuckDuckGo với real-time processing
    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_DISCOVERY) as executor:
            futures = [executor.submit(process_dork_realtime, i, d) 
                      for i, d in enumerate(DORKS) if not stop_flag]
            
            for future in as_completed(futures):
                if stop_flag:
                    break
                dork_idx, new_count, dork = future.result()
                if new_count > 0:
                    print(f"  ✓ Dork {dork_idx+1:2d}: {dork[:50]:<50} → {new_count} domain")
                    
    except KeyboardInterrupt:
        print("\n\n⚠️  Đã dừng theo yêu cầu người dùng")
        stop_flag = True
    
    # =================== RAPIDDNS - PROCESS IMMEDIATELY ===================
    print(f"\n[3/3] RapidDNS Expansion ({len(rapiddns_seeds)} seeds)...")
    
    rapiddns_domains = set()
    for seed in list(rapiddns_seeds)[:50]:  # Giới hạn 50 seeds
        if stop_flag:
            break
        domains = collect_from_rapiddns(seed)
        rapiddns_domains.update(domains)
        print(f"\r\033[K  Processing {seed} → {len(domains)} domains", end="")
    
    print(f"\n✓ RapidDNS: {len(rapiddns_domains)} domains found")
    
    # Xử lý domain từ RapidDNS ngay
    rapiddns_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS_RECON)
    rapiddns_futures = {}
    
    for domain in rapiddns_domains:
        if stop_flag:
            break
            
        if domain in all_domains:
            continue
        
        with lock:
            all_domains.add(domain)
            new_domains_queue.append(domain)
            domain_state[domain] = {"source": "rapiddns", "processed": False}
        
        # SCAN NGAY nếu là domain quan trọng
        filter_result = v12_discovery_filter(domain)
        if filter_result["scan_immediately"]:
            future = rapiddns_executor.submit(scan_domain_immediately, domain)
            rapiddns_futures[future] = domain
    
    # Hiển thị kết quả scan từ RapidDNS
    for future in as_completed(rapiddns_futures):
        if stop_flag:
            break
        domain = rapiddns_futures[future]
        result = future.result()
        if result:
            display_realtime_result(domain, result)
    
    rapiddns_executor.shutdown(wait=False)
    
    # =================== SAVE RESULTS ===================
    if all_domains:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for domain in sorted(all_domains):
                f.write(f"{domain}\n")
        
        print(f"\n✓ Đã lưu {len(all_domains)} domain vào {OUTPUT_FILE}")
    
    # =================== SCAN REMAINING DOMAINS ===================
    print(f"\n[FINAL] Scanning remaining domains ({len(new_domains_queue)})...")
    
    domains_to_scan = [d for d in new_domains_queue 
                      if d in domain_state and not domain_state[d].get("processed", False)]
    
    if domains_to_scan:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS_RECON) as executor:
            futures = {}
            for domain in domains_to_scan[:100]:  # Giới hạn 100 domains
                if stop_flag:
                    break
                future = executor.submit(scan_domain_immediately, domain)
                futures[future] = domain
            
            for future in as_completed(futures):
                if stop_flag:
                    break
                domain = futures[future]
                result = future.result()
                if result:
                    display_realtime_result(domain, result)
                    with lock:
                        domain_state[domain]["processed"] = True
                        scan_count += 1
    
    print(f"\n{'='*60}")
    print(f"TỔNG KẾT: {len(all_domains)} domains | {scan_count} scanned | Real-time processing")
    print(f"{'='*60}")
    
    return all_domains, scan_count, len(vulnerable_domains)

def scan_domain_immediately(domain):
    """Scan domain NGAY LẬP TỨC"""
    try:
        recon = WordPressReconEnhanced(domain)
        result = recon.scan()
        
        if result['wp']['detected']:
            # Lưu domain với đầy đủ http:// hoặc https://
            url = recon.base_url if recon.base_url else f"https://{domain}"
            
            # Lưu TẤT CẢ domain WordPress vào file riêng
            try:
                with open("all_wp_domains.txt", "a", encoding="utf-8") as f:
                    f.write(f"{url}\n")
            except:
                pass
            
            # Lưu domain có vấn đề vào targets.txt
            risk = result['vulnerability_indicators']['risk_score']
            cves = len(result['vulnerability_indicators']['cve_matches'])
            if risk >= 10 or cves > 0:
                try:
                    with open(DOMAIN_VULN_FILE, "a", encoding="utf-8") as f:
                        f.write(f"{url}\n")
                except:
                    pass
            
            return recon.get_summary()
        return None
    except Exception as e:
        return None

def main():
    """Hàm chính"""
    global stop_flag
    
    print("=" * 80)
    print("WORDPRESS DOMAIN COLLECTOR - REAL-TIME PROCESSING")
    print("VERSION 2.3 - IMMEDIATE SCAN & DISPLAY")
    print("=" * 80)
    
    try:
        domains, scanned_count, vuln_count = collect_wp_domains_parallel()
        
        if not domains:
            print("Không có domain nào để scan!")
            return
        
        print(f"\n📁 KẾT QUẢ LƯU TẠI:")
        print(f"  • Danh sách domain: {OUTPUT_FILE}")
        print(f"  • Domain có vấn đề: {DOMAIN_VULN_FILE}")
        print(f"  • Real-time processing completed")
        print(f"{'='*80}\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Đã dừng theo yêu cầu người dùng")
        stop_flag = True
    except Exception as e:
        print(f"\n❌ Lỗi: {e}")

if __name__ == "__main__":
    main()