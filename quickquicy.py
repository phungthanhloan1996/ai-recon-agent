import requests
import re
import concurrent.futures
import urllib3
import random
import socket
import time
from threading import Lock
from urllib.parse import urlparse
from tqdm import tqdm
import os

# Cấu hình hệ thống
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
R, G, Y, B, C, W = '\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[96m', '\033[0m'

class ShadowStrikeV13:
    def __init__(self):
        self.raw_seeds = set()
        self.processed_hosts = set() # Chống quét trùng lặp
        self.found_vulns = []
        self.lock = Lock()
        self.file_lock = Lock()  # Lock riêng cho file operations
        self.session = requests.Session()
        self.session.max_redirects = 3
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        ]
        self.targets_file = "targets.txt"
        # Không cần load existing_domains từ đầu nữa, sẽ kiểm tra trực tiếp file mỗi lần

    def append_new_domains(self, domains):
        """Thêm domain mới vào file targets.txt - thread-safe"""
        with self.file_lock:  # Đảm bảo chỉ một thread ghi file tại một thời điểm
            try:
                # Đọc các domain hiện có từ file
                existing = set()
                if os.path.exists(self.targets_file):
                    with open(self.targets_file, 'r') as f:
                        existing = set(line.strip().lower() for line in f if line.strip())
                
                # Lọc domain mới
                new_domains = [d for d in domains if d.lower() not in existing]
                
                if new_domains:
                    # Ghi domain mới vào file
                    with open(self.targets_file, 'a') as f:
                        for domain in new_domains:
                            f.write(domain + '\n')
                            f.flush()  # Đảm bảo ghi ngay lập tức
                    
                    print(f"{G}[+] Added to targets.txt: {', '.join(new_domains)}{W}")
                    
                    # Optional: thông báo cho app khác nếu cần
                    # os.system(f'touch {self.targets_file}')  # Để trigger file watcher nếu có
                    
            except Exception as e:
                print(f"{R}[!] Error writing to {self.targets_file}: {e}{W}")

    # =========================================================
    # PHASE 1: DISCOVERY (VÉT SEED)
    # =========================================================
    def discovery_phase(self):
        print(f"{B}[*] PHASE 1: Đang thu thập Domain từ các nguồn hạt giống...{W}")
        sources = [
            "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
            "https://rapiddns.io/subdomain/wp-content?full=1",
            "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/master/chaos-bugbounty-list.json"
        ]
        for url in sources:
            try:
                r = requests.get(url, timeout=15, headers={'User-Agent': random.choice(self.user_agents)})
                found = re.findall(r'(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})', r.text)
                self.raw_seeds.update([d.lower() for d in found if not d.endswith(('.jpg', '.png', '.css'))])
            except: pass
        print(f"{G}[✓] Đã sẵn sàng {len(self.raw_seeds):,} mục tiêu để chạy luồng dọc.{W}")

    # =========================================================
    # THE VERTICAL PIPELINE: ALIVE -> WP -> AUDIT (TIERED)
    # =========================================================
    def process_one_domain(self, domain, pbar):
        try:
            # 1. DNS Pre-check (Alive cơ bản)
            socket.gethostbyname(domain)
            
            final_url = None
            # 2. Check Alive & Get Final URL (HEAD -> GET)
            for proto in ['https://', 'http://']:
                try:
                    u = f"{proto}{domain}"
                    r = self.session.head(u, timeout=4, verify=False, allow_redirects=True)
                    if r.status_code in [403, 405]: 
                        r = self.session.get(u, timeout=4, verify=False, allow_redirects=True)
                    
                    if r.status_code < 500:
                        netloc = urlparse(r.url).netloc.lower()
                        with self.lock:
                            if netloc in self.processed_hosts: return # Đã có luồng khác làm host này
                            self.processed_hosts.add(netloc)
                        final_url = r.url.rstrip('/')
                        break
                except: continue
            
            if not final_url: return

            # 3. Tier 1 Audit: Fingerprint & Version (Check WP?)
            r_main = self.session.get(final_url, timeout=5, verify=False)
            body = r_main.text.lower()
            
            # Nếu không phải WordPress -> Abort (Dừng luồng ngay)
            if 'wp-content' not in body and 'wp-includes' not in body:
                return

            # Nhận diện Version
            ver = "Unknown"
            v_match = re.search(r'content="WordPress\s?([\d.]+)"', body) or re.search(r'ver=([\d.]+)', body)
            if v_match: ver = v_match.group(1)

            # 4. Tier 2 Audit: Surface Check (Mở/Khóa)
            weak_score = 0
            findings = []
            
            # Check XML-RPC & Login
            for path in ['/xmlrpc.php', '/wp-login.php']:
                try:
                    rv = self.session.get(final_url + path, timeout=4, verify=False)
                    if rv.status_code in [200, 405]:
                        weak_score += 2
                        findings.append(f"Accessible: {path}")
                except: pass

            # 5. Tier 3 Audit: Deep Leak (Chỉ chạy nếu Tier 2 có dấu hiệu)
            if weak_score >= 2:
                # Check User Enum
                r_usr = self.session.get(final_url + '/wp-json/wp/v2/users', timeout=4, verify=False)
                if r_usr.status_code == 200 and 'slug' in r_usr.text:
                    weak_score += 5
                    findings.append("Leak: User Enumeration")

                # Check Sensitive Files
                for spath, slabel in [('/.env', 'Env Leak'), ('/wp-config.php.bak', 'Backup Leak')]:
                    rs = self.session.get(final_url + spath, timeout=4, verify=False)
                    if rs.status_code == 200 and any(k in rs.text for k in ['DB_', 'APP_ENV']):
                        weak_score += 10
                        findings.append(f"CRITICAL: {slabel}")

            # Kết quả cuối cùng
            if weak_score >= 4 or any("CRITICAL" in f for f in findings):
                with self.lock:
                    self.found_vulns.append({'url': final_url, 'ver': ver, 'findings': findings})
                    
                    # Thêm domain vào targets.txt NGAY LẬP TỨC
                    domain_to_add = urlparse(final_url).netloc
                    self.append_new_domains([domain_to_add])  # Gọi hàm ghi file
                    
                    # In kết quả
                    print(f"\n{G}[🎯] TARGET FOUND: {final_url} (Ver: {ver}){W}")
                    for f in findings: 
                        print(f"  |-- {f}")
                    print(W, end='', flush=True)

        except: pass
        finally:
            pbar.update(1)

    # =========================================================
    # EXECUTION ENGINE
    # =========================================================
    def run_once(self, threads=100):
        start_t = time.time()
        self.discovery_phase()
        
        seeds = list(self.raw_seeds)
        random.shuffle(seeds)
        
        print(f"{Y}[*] Đang chạy luồng dọc (Vertical Pipeline: Alive -> WP -> Audit)...{W}")
        pbar = tqdm(total=len(seeds), desc="Hunting", unit="site")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for d in seeds:
                ex.submit(self.process_one_domain, d, pbar)
        
        pbar.close()
        self.save_final_report()
        
        print(f"\n{B}✅ HOÀN THÀNH SAU {time.time()-start_t:.1f}s{W}")
        print(f"{G}[*] Tổng số WP yếu/lỗi tìm được: {len(self.found_vulns)}{W}")

    def run_continuous(self, threads=100, interval=300):  # 5 minutes interval
        print(f"{B}[*] Starting continuous domain hunting...{W}")
        while True:
            try:
                self.raw_seeds.clear()
                self.processed_hosts.clear()
                self.found_vulns.clear()
                self.run_once(threads)
                print(f"{Y}[*] Waiting {interval} seconds before next hunt...{W}")
                time.sleep(interval)
            except KeyboardInterrupt:
                print(f"\n{R}[!] Stopped by user.{W}")
                break
            except Exception as e:
                print(f"{R}[!] Error: {e}{W}")
                time.sleep(60)

    def save_final_report(self):
        with open("V13_FINAL_RESULTS.txt", "w") as f:
            for item in self.found_vulns:
                f.write(f"SITE: {item['url']} | VERSION: {item['ver']}\n")
                f.write("FINDINGS: " + " | ".join(item['findings']) + "\n")
                f.write("-" * 60 + "\n")

if __name__ == "__main__":
    try:
        hunter = ShadowStrikeV13()
        hunter.run_continuous(threads=150)
    except KeyboardInterrupt:
        print(f"\n{R}[!] Đã dừng bởi người dùng.{W}")