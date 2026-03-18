import argparse
import logging
import os
import sys
import json
import time
import signal
import concurrent.futures
from datetime import datetime, timedelta
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional

# ─── Suppress DEBUG logs from libraries ────────────────────────────────────
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("chardet").setLevel(logging.WARNING)

# ─── Core Components ─────────────────────────────────────────────────────────
from core.state_manager import StateManager
from core.endpoint_ranker import EndpointRanker
from core.http_engine import HTTPClient
from core.response_analyzer import ResponseAnalyzer
from core.attack_graph import AttackGraph
from core.session_manager import SessionManager

# ─── AI Components ───────────────────────────────────────────────────────────
from ai.endpoint_classifier import EndpointClassifier
from ai.payload_gen import PayloadGenerator
from ai.payload_mutation import PayloadMutator
from ai.analyzer import AIAnalyzer
from ai.chain_planner import ChainPlanner

# ─── Constants ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

from modules.wp_scanner import WordPressScannerEngine

# ─── Learning & Rules ────────────────────────────────────────────────────────
from learning.learning_engine import LearningEngine

# ─── Reports ─────────────────────────────────────────────────────────────────
from reports.report_generator import ReportGenerator

# ─── Modules ─────────────────────────────────────────────────────────────────
from modules.recon import ReconEngine
from modules.crawler import DiscoveryEngine
from modules.scanner import ScanningEngine
from modules.exploiter import ExploitTestEngine
from modules.live_hosts import LiveHostEngine


# ─── API Key Check ───────────────────────────────────────────────────────────
def check_api_keys() -> dict:
    """Kiểm tra trạng thái các API key cần thiết."""
    groq_key = os.environ.get("GROQ_API_KEY", "")
    wps_token = os.environ.get("WPScan_API_TOKEN", "")
    nvd_key = os.environ.get("NVD_API_KEY", "")

    def status(key):
        return "✓" if key else "✗"

    return {
        "Groq": status(groq_key),
        "WPScan": status(wps_token),
        "NVD": status(nvd_key)
    }


# ─── BATCH DISPLAY SYSTEM ───────────────────────────────────────────────────
class BatchDisplay:
    """
    Hiển thị real-time cho continuous batch mode
    Đơn giản, chỉ hiển thị đúng những gì đang chạy
    """
    def __init__(self, api_status: Optional[dict] = None, max_workers: int = 5, targets_file: str = "targets.txt"):
        self.api_status = api_status or {}
        self.domains = {}  # domain -> scan data
        self.completed = deque(maxlen=10)
        self.failed = deque(maxlen=5)
        self.queue = deque()  # domains đang chờ
        self.total_domains = 0  # tổng số domain trong file
        self.max_workers = max_workers
        self.targets_file = targets_file
        self.lock = threading.Lock()
        self.running = True
        self.start_time = time.time()
        self.last_render_time = 0
        self.last_file_check = time.time()
        
        # Stats tổng hợp
        self.total_vulns = 0
        self.total_exploited = 0
        self.total_endpoints = 0
        self.total_live = 0
        self.total_wordpress = 0
        
        # Live feed - 5 sự kiện gần nhất
        self.live_feed = deque(maxlen=5)
        
        # Start render thread
        self.render_thread = threading.Thread(target=self._render_loop)
        self.render_thread.daemon = True
        self.render_thread.start()
    
    def stop(self):
        self.running = False
    
    def update_total_domains(self, count: int):
        """Cập nhật tổng số domain trong file"""
        with self.lock:
            self.total_domains = count
    
    def add_to_queue(self, domain):
        """Thêm domain vào queue"""
        with self.lock:
            if domain not in self.domains and domain not in [q[0] for q in self.queue]:
                self.queue.append((domain, datetime.now()))
    
    def promote_from_queue(self):
        """Lấy domain từ queue lên active"""
        with self.lock:
            if self.queue and len(self.domains) < self.max_workers:
                domain, added_time = self.queue.popleft()
                return domain
        return None
    
    def update(self, domain, data):
        """Update hoặc thêm mới domain data"""
        with self.lock:
            if domain not in self.domains:
                data['start_time'] = time.time()
            self.domains[domain] = data
    
    def mark_completed(self, domain, summary):
        """Domain đã scan xong"""
        with self.lock:
            if domain in self.domains:
                data = self.domains[domain]
                stats = data.get('stats', {})
                
                self.total_vulns += stats.get('vulns', 0)
                self.total_exploited += stats.get('exploited', 0)
                self.total_endpoints += stats.get('eps', 0)
                self.total_live += stats.get('live', 0)
                self.total_wordpress += 1 if stats.get('wp') else 0
                
                del self.domains[domain]
            
            vulns = summary.get('vulns', 0)
            exploited = summary.get('exploited', 0)
            self.completed.appendleft((domain, vulns, exploited, datetime.now().strftime("%H:%M:%S")))
            
            if vulns > 0:
                self._add_to_feed("✅", "Completed", domain, f"{vulns} vulns, {exploited} exploited")
            else:
                self._add_to_feed("✅", "Completed", domain, "0 vulns")
    
    def mark_failed(self, domain, reason):
        """Domain bị lỗi"""
        with self.lock:
            if domain in self.domains:
                del self.domains[domain]
            self.failed.appendleft((domain, reason, datetime.now().strftime("%H:%M:%S")))
            self._add_to_feed("❌", "Failed", domain, reason)
    
    def _add_to_feed(self, icon: str, event: str, domain: str, detail: str):
        """Thêm sự kiện vào live feed"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.live_feed.appendleft((timestamp, icon, event, domain, detail))
    
    def _get_progress_text(self, data: dict) -> str:
        """Tạo progress text dựa trên phase"""
        phase = data.get('phase', 'init')
        stats = data.get('stats', {})
        phase_detail = data.get('phase_detail', '')
        
        if phase == 'recon':
            return f"{stats.get('subs', 0)} subs"
        elif phase == 'live':
            live = stats.get('live', 0)
            total = stats.get('total_hosts', 0)
            return f"{live}/{total} live"
        elif phase == 'wp':
            return f"scanning WP"
        elif phase == 'crawl':
            return f"{stats.get('eps', 0)} eps"
        elif phase == 'scan':
            tested = stats.get('payloads_tested', 0)
            return f"{tested}/100 payloads"
        elif phase == 'exploit':
            chains = data.get('chains', [])
            exploited = sum(1 for c in chains if c.get('exploited'))
            return f"{exploited}/{len(chains)} chains"
        else:
            return phase_detail or "working..."
    
    def _render_loop(self):
        """Thread render liên tục - 2 lần/giây"""
        while self.running:
            current_time = time.time()
            if current_time - self.last_render_time >= 0.5:
                self._render()
                self.last_render_time = current_time
            time.sleep(0.1)
    
    def _render(self):
        """Vẽ giao diện đơn giản"""
        with self.lock:
            sys.stdout.write('\033[2J\033[H')
            
            # Header
            elapsed = int(time.time() - self.start_time)
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            
            active_count = len(self.domains)
            queue_count = len(self.queue)
            completed_count = len(self.completed)
            failed_count = len(self.failed)
            
            print("┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐")
            print(f"│  ⚡ AI RECON AGENT ⚡  [CONTINUOUS BATCH MODE]                       uptime: {hours:02d}:{minutes:02d}:{seconds:02d}                  │")
            
            # API Status
            api_parts = [f"{k}: {v}" for k, v in self.api_status.items()]
            api_line = " | ".join(api_parts)
            print(f"│  API: {api_line:<92} │")
            
            # Config
            print(f"│  Config: max-workers={self.max_workers} | scan-depth=5 | timeout=30s                                    │")
            
            # Targets file info
            print(f"│  Targets file: {self.targets_file} ({self.total_domains} domains total)                                │")
            print("├──────────────────────────────────────────────────────────────────────────────────────────────────────┤")
            print("│                                                                                                      │")
            print("│  ┌─ QUEUE ─────────────────────────────────────────────────────────────────────────────────────────┐")
            
            # Active targets
            print("│  │                                                                                                  │")
            print(f"│  │  ▶️  ACTIVE ({active_count}/{self.max_workers}):                                                                              │")
            if active_count > 0:
                for idx, (domain, data) in enumerate(list(self.domains.items())[:self.max_workers], 1):
                    phase = data.get('phase', 'init')
                    phase_detail = data.get('phase_detail', '')
                    iter_info = f"iter {data.get('iter', 1)}/{data.get('max_iter', 5)}"
                    
                    phase_icon = {
                        'recon': '🔍', 'live': '🌐', 'wp': '🎯', 'crawl': '📁',
                        'classify': '🤖', 'rank': '📊', 'scan': '⚡', 'analyze': '🔬',
                        'graph': '🕸️', 'chain': '🔗', 'exploit': '💥', 'learn': '🧠',
                        'init': '⚙️', 'report': '📋'
                    }.get(phase, '⚙️')
                    
                    progress = self._get_progress_text(data)
                    domain_display = domain[:30] if len(domain) <= 30 else domain[:27] + "..."
                    
                    print(f"│  │     #{idx} {domain_display:<30} [{phase_icon} {phase.capitalize()}] {iter_info:<10} | {progress:<20} │")
            else:
                print("│  │     No active targets                                                                          │")
            
            # Waiting queue
            print("│  │                                                                                                  │")
            print(f"│  │  ⏳ WAITING ({queue_count}):                                                                                │")
            if queue_count > 0:
                for domain, added_time in list(self.queue)[:3]:
                    wait_time = int((time.time() - added_time.timestamp()) / 60)
                    domain_display = domain[:30] if len(domain) <= 30 else domain[:27] + "..."
                    print(f"│  │     • {domain_display:<30} (added {wait_time}m ago)                                         │")
                if queue_count > 3:
                    print(f"│  │     • ... and {queue_count - 3} more                                                          │")
            else:
                print("│  │     No waiting targets                                                                         │")
            
            # Completed
            print("│  │                                                                                                  │")
            print(f"│  │  ✅ DONE ({completed_count}):                                                                                   │")
            if completed_count > 0:
                completed_text = []
                for domain, vulns, exploited, ts in list(self.completed)[:3]:
                    completed_text.append(f"{domain} ({vulns} vulns)")
                print(f"│  │     • {'  • '.join(completed_text)}                                 │")
                if completed_count > 3:
                    print(f"│  │     • ... and {completed_count - 3} more                                                      │")
            else:
                print("│  │     No completed targets                                                                       │")
            
            # Failed
            print("│  │                                                                                                  │")
            print(f"│  │  ❌ FAILED ({failed_count}):                                                                                 │")
            if failed_count > 0:
                for domain, reason, ts in list(self.failed)[:2]:
                    domain_display = domain[:25] if len(domain) <= 25 else domain[:22] + "..."
                    print(f"│  │     • {domain_display:<25} ({reason})                                           │")
            else:
                print("│  │     No failed targets                                                                         │")
            
            print("│  └─────────────────────────────────────────────────────────────────────────────────────────────────┘")
            
            # Details section - chỉ hiển thị cho 2 domain active đầu tiên
            if active_count > 0:
                print("│                                                                                                      │")
                print("│  ┌─ DETAILS ───────────────────────────────────────────────────────────────────────────────────────┐")
                
                for idx, (domain, data) in enumerate(list(self.domains.items())[:2], 1):
                    stats = data.get('stats', {})
                    chains = data.get('chains', [])
                    vulns = stats.get('vulns', 0)
                    
                    print(f"│  │                                                                                                  │")
                    print(f"│  │  {domain}:                                                                                             │")
                    
                    if vulns > 0:
                        print(f"│  │  ├─ 🐞 Found: {vulns} vulnerabilities                                                          │")
                    
                    if chains:
                        exploited = sum(1 for c in chains if c.get('exploited'))
                        print(f"│  │  ├─ 🔗 Chains: {len(chains)} total, {exploited} exploited                                       │")
                    
                    if data.get('endpoints'):
                        eps = data.get('endpoints', {})
                        print(f"│  │  ├─ 📁 Endpoints: {eps.get('total', 0)} total, API:{eps.get('api', 0)} Admin:{eps.get('admin', 0)}              │")
                    
                    last_action = data.get('last_action', '')[:50]
                    if last_action:
                        print(f"│  │  └─ ⏱️  {last_action}                                                    │")
                
                print("│  └─────────────────────────────────────────────────────────────────────────────────────────────────┘")
            
            # Live feed
            if self.live_feed:
                print("│                                                                                                      │")
                print("│  ┌─ LIVE ──────────────────────────────────────────────────────────────────────────────────────────┐")
                for timestamp, icon, event, domain, detail in list(self.live_feed)[:5]:
                    domain_display = domain[:20] + ".." if len(domain) > 20 else domain.ljust(22)
                    print(f"│  │  {timestamp} │ {icon} {event:<12} │ {domain_display} │ {detail:<35} │")
                print("│  └─────────────────────────────────────────────────────────────────────────────────────────────────┘")
            
            # Footer với stats tổng hợp
            print("└──────────────────────────────────────────────────────────────────────────────────────────────────────┘")
            
            sys.stdout.flush()


# ─── DOMAIN DISPLAY (Single mode) ───────────────────────────────────────────
class DomainDisplay:
    """Hiển thị cho single domain mode"""
    def __init__(self, target, api_status: Optional[dict] = None, target_index: int = 1, total_targets: int = 1):
        self.target = target
        self.api_status = api_status or {}
        self.target_index = target_index
        self.total_targets = total_targets
        self.start_time = time.time()
        self.last_render_time = 0
        self.data = {
            'phase': 'init',
            'iter': 1,
            'max_iter': 5,
            'stats': {'subs': 0, 'live': 0, 'eps': 0, 'vulns': 0, 'exploited': 0, 'wp': 0},
            'chains': [],
            'last_action': 'initializing...',
            'phase_detail': '',
            'tech': {},
            'endpoints': {'api': 0, 'admin': 0, 'upload': 0, 'total': 0},
            'vuln_types': defaultdict(int),
            'learning': {'mutated': 0, 'confidence': 0.0}
        }
        self.running = True
        
        self.render_thread = threading.Thread(target=self._render_loop)
        self.render_thread.daemon = True
        self.render_thread.start()
    
    def stop(self):
        self.running = False
    
    def update(self, **kwargs):
        for key, value in kwargs.items():
            if key == 'stats':
                self.data['stats'].update(value)
            elif key == 'chains':
                self.data['chains'] = value
            elif key == 'vuln_types':
                self.data['vuln_types'].update(value)
            elif key == 'endpoints':
                self.data['endpoints'].update(value)
            elif key == 'learning':
                self.data['learning'].update(value)
            else:
                self.data[key] = value
    
    def _render_loop(self):
        while self.running:
            current_time = time.time()
            if current_time - self.last_render_time >= 0.5:
                self._render()
                self.last_render_time = current_time
            time.sleep(0.1)
    
    def _render(self):
        sys.stdout.write('\033[2J\033[H')
        
        d = self.data
        stats = d['stats']
        
        elapsed = int(time.time() - self.start_time)
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        phase_icon = {
            'recon': '🔍', 'live': '🌐', 'wp': '🎯', 'crawl': '📁',
            'classify': '🤖', 'rank': '📊', 'scan': '⚡', 'analyze': '🔬',
            'graph': '🕸️', 'chain': '🔗', 'exploit': '💥', 'learn': '🧠',
            'init': '⚙️', 'report': '📋'
        }.get(d['phase'], '⚙️')
        
        print("┌────────────────────────────────────────────────────────────────────────────────┐")
        print(f"│  ⚡ AI RECON AGENT ⚡   Target {self.target_index}/{self.total_targets}                                      │")
        
        api_parts = [f"{k}: {v}" for k, v in self.api_status.items()]
        api_line = " | ".join(api_parts)
        print(f"│  API: {api_line:<78} │")
        
        domain_display = self.target[:50] if len(self.target) <= 50 else self.target[:47] + "..."
        print(f"│  {domain_display} [{phase_icon} {d['phase']}] iter {d['iter']}/{d['max_iter']}  elapsed: {time_str}        │")
        print("├────────────────────────────────────────────────────────────────────────────────┤")
        
        # Stats
        print("│  🔍 DISCOVERY                                                                   │")
        print(f"│  ├─ Subdomains: {stats.get('subs', 0):<4} | Live hosts: {stats.get('live', 0):<4}                              │")
        print(f"│  ├─ Endpoints: {stats.get('eps', 0):<5} | WordPress: {'✓' if stats.get('wp') else '✗'}                                     │")
        
        # Tech
        tech_list = list(d['tech'].keys())
        if tech_list:
            tech_str = f"Tech: {', '.join(tech_list[:3])}"
            if len(tech_list) > 3:
                tech_str += f" (+{len(tech_list)-3})"
            print(f"│  └─ {tech_str:<70} │")
        else:
            print(f"│  └─ Tech: detecting...                                                     │")
        
        # Endpoints
        eps = d['endpoints']
        if eps['total'] > 0:
            print("│                                                                              │")
            print("│  📁 ENDPOINTS                                                               │")
            print(f"│  ├─ Total : {eps['total']:<5}                                               │")
            print(f"│  ├─ API   : {eps['api']:<5}                                                 │")
            print(f"│  ├─ Admin : {eps['admin']:<5}                                               │")
            print(f"│  └─ Upload: {eps['upload']:<5}                                              │")
        
        # Vulns
        vuln_types = dict(d['vuln_types'])
        if vuln_types:
            print("│                                                                              │")
            print("│  🐞 VULNERABILITIES                                                          │")
            total_vulns = sum(vuln_types.values())
            print(f"│  ├─ Total: {total_vulns}                                                     │")
            for vtype, count in list(vuln_types.items())[:3]:
                print(f"│  ├─ {vtype}: {count}                                                       │")
        
        # Chains
        chains = d['chains']
        if chains:
            print("│                                                                              │")
            print("│  🕸️ ATTACK CHAINS                                                            │")
            exploited_count = sum(1 for c in chains if c.get('exploited'))
            print(f"│  ├─ Total: {len(chains)} | Exploited: {exploited_count}                                     │")
        
        # Learning
        learning = d['learning']
        if learning['mutated'] > 0:
            print("│                                                                              │")
            print("│  🧠 LEARNING                                                                 │")
            print(f"│  ├─ Mutated: {learning['mutated']} payloads                                            │")
        
        # Current action
        print("│                                                                              │")
        print(f"│  ⚡ {d['last_action']:<77} │")
        print("└────────────────────────────────────────────────────────────────────────────────┘")
        sys.stdout.flush()


# ─── LOGGING SETUP ─────────────────────────────────────────────────────────
def setup_logging(output_dir: str, verbose: bool = False) -> logging.Logger:
    """File logging only - console handled by display system"""
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "agent.log")
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(logging.Formatter("%(message)s"))
    
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(file_handler)
    root.addHandler(console_handler)
    
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.ERROR)
    
    return logging.getLogger("recon.agent")


# ─── MAIN AGENT ───────────────────────────────────────────────────────────
class ReconAgent:
    def __init__(self, target: str, output_dir: str, options: dict,
                 wps_token: str = "", nvd_key: str = "", 
                 urls_file: str = "", subdomains_file: str = "", force_recon: bool = False,
                 batch_display: BatchDisplay = None,
                 api_status: Optional[dict] = None,
                 target_index: int = 1,
                 total_targets: int = 1):
        
        self.target = target.lower().strip()
        self.output_dir = output_dir
        self.options = options
        self.wps_token = wps_token
        self.nvd_key = nvd_key
        self.urls_file = urls_file
        self.subdomains_file = subdomains_file
        self.force_recon = force_recon
        self.batch_display = batch_display
        self.api_status = api_status or {}
        self.target_index = target_index
        self.total_targets = total_targets
        self.scan_start_time = time.time()
        
        if batch_display:
            self.display = None
            self.batch_id = target
        else:
            self.display = DomainDisplay(target, api_status=self.api_status,
                                         target_index=self.target_index,
                                         total_targets=self.total_targets)
        
        # Initialize components
        self.state = StateManager(self.target, output_dir)
        self.session = SessionManager(self.output_dir)
        self.http_client = HTTPClient(self.session)
        self.response_analyzer = ResponseAnalyzer()
        self.learning_engine = LearningEngine(output_dir)
        
        groq_key = os.environ.get("GROQ_API_KEY", "")
        self.endpoint_classifier = EndpointClassifier()
        self.payload_gen = PayloadGenerator(groq_key)
        self.payload_mutator = PayloadMutator()
        self.vuln_analyzer = AIAnalyzer(self.state, output_dir, groq_key)
        self.chain_planner = ChainPlanner(
            self.state,
            learning_engine=self.learning_engine
        )
        
        self.recon_engine = ReconEngine(self.state, output_dir)
        self.live_host_engine = LiveHostEngine(self.state, output_dir)
        self.discovery_engine = DiscoveryEngine(self.state, output_dir)
        self.scanning_engine = ScanningEngine(self.state, output_dir, self.payload_gen, self.payload_mutator)
        self.exploit_engine = ExploitTestEngine(self.state, output_dir)
        self.wp_scanner = WordPressScannerEngine(self.state, output_dir)
        
        self.logger = logging.getLogger("recon.agent")
        self.iteration_count = 0
        self.max_iterations = 5
        self.confidence_threshold = 0.8
        
        self.stats = {
            'subs': 0, 'live': 0, 'eps': 0, 'vulns': 0, 
            'exploited': 0, 'wp': 0,
            'payloads_tested': 0, 'total_payloads': 100,
            'total_hosts': 0
        }
        self.chains_data = []
        self.vuln_types = defaultdict(int)
        self.endpoint_stats = {'api': 0, 'admin': 0, 'upload': 0, 'total': 0}
        self.tech_stack = {}
        self.last_action = "starting..."
        self.current_phase = "init"
        self.phase_detail = ""
        self.learning_stats = {'mutated': 0, 'confidence': 0.0}
        
        self._update_display()

    def _update_display(self):
        if self.batch_display:
            self.batch_display.update(self.batch_id, {
                'phase': self.current_phase,
                'phase_detail': self.phase_detail,
                'iter': self.iteration_count,
                'max_iter': self.max_iterations,
                'stats': self.stats.copy(),
                'chains': self.chains_data,
                'tech': self.tech_stack.copy(),
                'endpoints': self.endpoint_stats.copy(),
                'last_action': self.last_action,
                'start_time': self.scan_start_time
            })
        else:
            if self.display:
                self.display.update(
                    phase=self.current_phase,
                    phase_detail=self.phase_detail,
                    iter=self.iteration_count,
                    stats=self.stats.copy(),
                    chains=self.chains_data,
                    vuln_types=dict(self.vuln_types),
                    endpoints=self.endpoint_stats.copy(),
                    tech=self.tech_stack.copy(),
                    learning=self.learning_stats.copy(),
                    last_action=self.last_action
                )

    def run(self):
        self._update_display()
        self.logger.info(f"Target: {self.target} | Output: {self.output_dir}")

        self._load_manual_inputs()

        try:
            attack_graph = AttackGraph()
            
            while self.iteration_count < self.max_iterations:
                self.iteration_count += 1
                
                # Phase 1: Recon
                if self.iteration_count == 1 and not self._should_skip_phase("recon"):
                    self.current_phase = "recon"
                    self.phase_detail = "enum"
                    self._update_display()
                    self._run_recon_phase()
                
                # Phase 2: Live Hosts
                if self.iteration_count == 1 and not self._should_skip_phase("live_hosts"):
                    self.current_phase = "live"
                    self.phase_detail = "detect"
                    self._update_display()
                    self._run_live_hosts_phase()
                
                # Phase 3: WordPress
                if self.iteration_count == 1 and not self._should_skip_phase("wordpress"):
                    self.current_phase = "wp"
                    self.phase_detail = "scan"
                    self._update_display()
                    self._run_wordpress_phase()
                
                # Phase 4: Discovery
                if self.iteration_count == 1 and not self._should_skip_phase("discovery"):
                    self.current_phase = "crawl"
                    self.phase_detail = "spider"
                    self._update_display()
                    self._run_discovery_phase()
                
                # Phase 5: Classification
                self.current_phase = "classify"
                self.phase_detail = "ai"
                self._update_display()
                self._run_classification_phase()
                
                # Phase 6: Prioritization
                self.current_phase = "rank"
                self.phase_detail = "scoring"
                self._update_display()
                self._run_prioritization_phase()
                
                # Phase 7: Scanning
                if not self._should_skip_phase("scan"):
                    self.current_phase = "scan"
                    self.phase_detail = "active"
                    self._update_display()
                    self._run_scanning_phase()
                
                # Phase 8: Analysis
                self.current_phase = "analyze"
                self.phase_detail = "ai"
                self._update_display()
                self._run_analysis_phase()
                
                # Phase 9: Attack Graph
                self.current_phase = "graph"
                self.phase_detail = "build"
                self._update_display()
                self._run_attack_graph_phase(attack_graph)
                
                # Phase 10: Chain Planning
                self.current_phase = "chain"
                self.phase_detail = "plan"
                self._update_display()
                self._run_chain_planning_phase(attack_graph)
                
                # Phase 11: Exploit Testing
                if not self._should_skip_phase("exploit"):
                    self.current_phase = "exploit"
                    self.phase_detail = "test"
                    self._update_display()
                    self._run_exploit_phase()
                
                # Phase 12: Learning
                self.current_phase = "learn"
                self.phase_detail = "adapt"
                self._update_display()
                self._run_learning_phase()
                
                self._update_stats()
                
                if self._check_confidence_threshold():
                    break
                    
                self._adapt_for_next_iteration()
            
            # Final
            self.current_phase = "report"
            self.last_action = "generating final report..."
            self._update_display()
            self._generate_final_report()
            
            if self.batch_display:
                self.batch_display.mark_completed(self.target, {
                    'vulns': self.stats['vulns'],
                    'chains': len(self.chains_data),
                    'exploited': self.stats['exploited']
                })
            else:
                self.display.stop()
            
        except KeyboardInterrupt:
            self.last_action = "interrupted by user"
            self._update_display()
            self.logger.warning("Scan interrupted")
            self.state.save()
            self._generate_final_report()
            if self.batch_display:
                self.batch_display.mark_failed(self.target, "interrupted")
        except Exception as e:
            self.last_action = f"error: {str(e)[:30]}"
            self._update_display()
            self.logger.error(f"Fatal error: {e}", exc_info=True)
            self.state.add_error(str(e))
            if self.batch_display:
                self.batch_display.mark_failed(self.target, str(e)[:30])

    def _update_stats(self):
        summary = self.state.summary()
        self.stats.update({
            'subs': summary.get('subdomains', 0),
            'live': summary.get('live_hosts', 0),
            'eps': summary.get('endpoints', 0),
            'vulns': summary.get('vulnerabilities', 0),
            'wp': 1 if summary.get('wordpress') else 0
        })
        
        vulns = self.state.get("confirmed_vulnerabilities", [])
        self.vuln_types.clear()
        for v in vulns:
            vtype = v.get('type', 'unknown')
            self.vuln_types[vtype] += 1
        
        self._update_display()

    def _load_manual_inputs(self):
        if hasattr(self, 'urls_file') and self.urls_file:
            try:
                with open(self.urls_file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    if urls:
                        self.state.update(urls=urls)
                        self.last_action = f"loaded {len(urls)} URLs from file"
                        self._update_display()
            except Exception as e:
                self.last_action = f"failed to load URLs: {str(e)[:20]}"
                self._update_display()
                self.logger.error(f"Failed to load URLs file: {e}")

        if hasattr(self, 'subdomains_file') and self.subdomains_file:
            try:
                with open(self.subdomains_file, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                    if subdomains:
                        self.state.update(subdomains=subdomains)
                        self.last_action = f"loaded {len(subdomains)} subs from file"
                        self._update_display()
            except Exception as e:
                self.last_action = f"failed to load subs: {str(e)[:20]}"
                self._update_display()
                self.logger.error(f"Failed to load subdomains file: {e}")

        if hasattr(self, 'force_recon') and self.force_recon:
            self.last_action = "force recon enabled"
            self._update_display()
            self.state.save()

    def _should_skip_phase(self, phase: str) -> bool:
        skip_map = {
            "recon": "skip_recon",
            "live_hosts": "skip_live_hosts",
            "wordpress": "skip_wordpress",
            "discovery": "skip_crawl", 
            "scan": "skip_scan",
            "exploit": "skip_exploit"
        }
        return self.options.get(skip_map.get(phase, ""), False)

    def _run_recon_phase(self):
        before = len(self.state.get("subdomains", []))
        self.recon_engine.run()
        after = len(self.state.get("subdomains", []))
        if after > before:
            self.stats['subs'] = after
            self.last_action = f"recon: +{after-before} subdomains"
            if self.batch_display:
                self.batch_display._add_to_feed("➕", "Subdomain", self.target, f"Found {after-before} new")
        self._update_stats()

    def _run_live_hosts_phase(self):
        before = len(self.state.get("live_hosts", []))
        self.stats['total_hosts'] = len(self.state.get("subdomains", []))
        self.live_host_engine.detect_live_hosts(self.state.get("subdomains", []))
        after = len(self.state.get("live_hosts", []))
        if after > before:
            self.stats['live'] = after
            self.last_action = f"live hosts: +{after-before} live"
            if self.batch_display:
                self.batch_display._add_to_feed("🌐", "Live", self.target, f"Found {after-before} live")
        self._update_stats()

    def _run_wordpress_phase(self):
        live_hosts = self.state.get("live_hosts", [])
        target_urls = [host.get("url", "") for host in live_hosts if host.get("url")]
        if target_urls:
            wp_sites = self.wp_scanner.scan_wordpress_sites(target_urls)
            if wp_sites:
                self.stats['wp'] = len(wp_sites)
                self.last_action = f"wordpress: {len(wp_sites)} sites"
                if self.batch_display:
                    self.batch_display._add_to_feed("🎯", "WordPress", self.target, f"Found {len(wp_sites)} sites")
        self._update_stats()

    def _run_discovery_phase(self):
        before = len(self.state.get("endpoints", []))
        self.discovery_engine.run()
        after = len(self.state.get("endpoints", []))
        if after > before:
            self.endpoint_stats['total'] = after
            self.stats['eps'] = after
            self.last_action = f"crawl: +{after-before} endpoints"
            if self.batch_display:
                self.batch_display._add_to_feed("📁", "Endpoint", self.target, f"Found {after-before} new")
        self._update_stats()

    def _run_classification_phase(self):
        endpoints = self.state.get("endpoints", [])
        if endpoints:
            api_count = sum(1 for e in endpoints if 'api' in e.get('url', ''))
            admin_count = sum(1 for e in endpoints if 'admin' in e.get('url', ''))
            upload_count = sum(1 for e in endpoints if 'upload' in e.get('url', ''))
            
            self.endpoint_stats.update({
                'api': api_count,
                'admin': admin_count,
                'upload': upload_count
            })
            
            self.last_action = f"classified {len(endpoints)} endpoints"
        self._update_stats()

    def _run_prioritization_phase(self):
        self._run_endpoint_ranking()

    def _run_scanning_phase(self):
        before = len(self.state.get("confirmed_vulnerabilities", []))
        self.scanning_engine.run()
        after = len(self.state.get("confirmed_vulnerabilities", []))
        
        self.stats['payloads_tested'] = min(self.stats.get('payloads_tested', 0) + 25, 100)
        
        if after > before:
            self.stats['vulns'] = after
            new_vulns = after - before
            self.last_action = f"scan: +{new_vulns} vulns found"
            
            vulns = self.state.get("confirmed_vulnerabilities", [])
            if vulns and self.batch_display:
                for vuln in vulns[-new_vulns:]:
                    vtype = vuln.get('type', 'unknown')
                    icon = "🐞" if vtype == "sqli" else "⚠️"
                    self.batch_display._add_to_feed(icon, vtype.upper(), self.target, vuln.get('url', '')[:30])
            
            self._update_stats()
        
        # Load scan results
        scan_results_file = os.path.join(self.output_dir, "scan_results.json")
        scan_responses = []
        if os.path.exists(scan_results_file):
            with open(scan_results_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            scan_responses.append(json.loads(line))
                        except json.JSONDecodeError:
                            self.logger.warning(f"Invalid JSON line in scan_results: {line}")
        self.state.update(scan_responses=scan_responses)

    def _run_analysis_phase(self):
        responses = self.state.get("scan_responses", [])
        vulnerabilities = []
        for response in responses:
            if response.get("vulnerable"):
                vulnerabilities.append({
                    "url": response.get("endpoint"),
                    "type": response.get("category"),
                    "payload": response.get("payload"),
                    "confidence": response.get("confidence", 0),
                    "evidence": response.get("reason", "")
                })
        self.state.update(confirmed_vulnerabilities=vulnerabilities)
        
        if vulnerabilities:
            self.last_action = f"analysis: {len(vulnerabilities)} confirmed"
            self._update_stats()
        self._update_display()

    def _run_attack_graph_phase(self, attack_graph: AttackGraph):
        vulnerabilities = self.state.get("confirmed_vulnerabilities", [])
        if vulnerabilities:
            attack_graph.build_from_vulnerabilities(vulnerabilities)
            graph_file = os.path.join(self.output_dir, "attack_graph.json")
            attack_graph.save_to_file(graph_file)
            self.last_action = f"graph: built from {len(vulnerabilities)} vulns"
        self._update_display()

    def _run_chain_planning_phase(self, attack_graph: AttackGraph):
        chains = self.chain_planner.plan_chains_from_graph(attack_graph)
        
        self.chains_data = []
        for i, chain in enumerate(chains[:5], 1):
            chain_info = {
                'name': f"CHAIN-{i:02d}",
                'risk': chain.get('risk', 'MEDIUM'),
                'exploited': False,
                'partial': False,
                'steps': [],
                'result': ''
            }
            
            steps = chain.get('steps', [])
            for step in steps[:3]:
                step_info = {
                    'desc': step.get('description', ''),
                    'success': step.get('exploited', False),
                    'partial': step.get('partial', False),
                    'payload': step.get('payload', '')
                }
                chain_info['steps'].append(step_info)
            
            self.chains_data.append(chain_info)
        
        self.state.update(exploit_chains=chains)
        if chains:
            self.last_action = f"chains: {len(chains)} attack paths"
        self._update_display()

    def _run_exploit_phase(self):
        chains = self.state.get("exploit_chains", [])
        if chains:
            results = []
            exploited_count = 0
            
            for i, chain in enumerate(chains[:3]):
                result = self.exploit_engine.test_chain(chain)
                results.append(result)
                
                if i < len(self.chains_data):
                    if result.get("success"):
                        self.chains_data[i]['exploited'] = True
                        self.chains_data[i]['result'] = result.get('output', '')[:40]
                        exploited_count += 1
                        
                        if self.batch_display:
                            self.batch_display._add_to_feed("💥", "Exploited", self.target, f"Chain-{i+1} success")
                    
                    elif result.get("partial"):
                        self.chains_data[i]['partial'] = True
                        self.chains_data[i]['result'] = result.get('reason', '')[:40]
            
            self.stats['exploited'] = exploited_count
            self.state.update(exploit_results=results)
            
            if exploited_count > 0:
                self.last_action = f"exploit: {exploited_count} chains successful"
            else:
                self.last_action = "exploit: no success"
            
            self._update_display()

    def _run_learning_phase(self):
        self.learning_engine.learn_from_iteration(self.state)
        
        failed_payloads = self.learning_engine.get_failed_payloads()
        self.learning_stats['mutated'] = len(failed_payloads)
        
        self._update_display()

    def _check_confidence_threshold(self) -> bool:
        vulnerabilities = self.state.get("confirmed_vulnerabilities", [])
        exploit_results = self.state.get("exploit_results", [])
        
        if vulnerabilities and exploit_results:
            successful = len([r for r in exploit_results if r.get("success")])
            confidence = successful / len(vulnerabilities)
            return confidence >= self.confidence_threshold
        return False

    def _adapt_for_next_iteration(self):
        failed_payloads = self.learning_engine.get_failed_payloads()
        if failed_payloads:
            mutated = self.payload_mutator.mutate_payloads(failed_payloads)
            self.state.update(mutated_payloads=mutated)
            self.learning_stats['mutated'] = len(mutated)
            self.last_action = f"learning: mutated {len(mutated)} payloads"
            if self.batch_display and mutated:
                self.batch_display._add_to_feed("🧠", "Learning", self.target, f"Mutated {len(mutated)} payloads")
            self._update_display()

    def _run_endpoint_ranking(self):
        urls = self.state.get("urls", [])
        endpoints = self.state.get("endpoints", [])
        all_urls = list(set(urls + [ep.get("url", "") for ep in endpoints if ep.get("url")]))

        if not all_urls:
            return

        ranker = EndpointRanker()
        ranked = ranker.rank_endpoints(all_urls)
        rank_top = int(os.environ.get("RANK_TOP", "150"))
        self.state.update(prioritized_endpoints=ranked[:rank_top])

        ranked_file = os.path.join(self.output_dir, "endpoints_ranked.json")
        with open(ranked_file, "w") as f:
            json.dump(ranked[:rank_top], f, indent=2)

    def _generate_final_report(self):
        report_gen = ReportGenerator(self.state, self.output_dir)
        report_gen.generate()


# ─── CLI ───────────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="AI Recon Agent - Continuous Batch Mode",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-f", "--file", default="targets.txt", help="File with targets (default: targets.txt)")
    parser.add_argument("-o", "--output", default=None, help="Output dir")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--no-exploit", action="store_true", help="Disable exploitation")
    parser.add_argument("--skip-recon", action="store_true", help="Skip recon")
    parser.add_argument("--skip-live", action="store_true", help="Skip live host detection")
    parser.add_argument("--skip-crawl", action="store_true", help="Skip crawling")
    parser.add_argument("--skip-scan", action="store_true", help="Skip scanning")
    parser.add_argument("--skip-wp", action="store_true", help="Skip WordPress scanning")
    parser.add_argument("--wps-token", default="", help="WPScan API token")
    parser.add_argument("--urls-file", help="File with manual URLs")
    parser.add_argument("--subdomains-file", help="File with manual subdomains")
    parser.add_argument("--force-recon", action="store_true", help="Force continue if recon fails")
    parser.add_argument("--max-workers", type=int, default=5, help="Max concurrent workers (default: 5)")

    return parser.parse_args()


def load_targets(filepath: str) -> tuple[list, int]:
    """Load domains from file, trả về (list domains, tổng số dòng)"""
    if not os.path.exists(filepath):
        return [], 0
    
    targets = []
    total_lines = 0
    try:
        with open(filepath, 'r') as f:
            for line in f:
                total_lines += 1
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                line = line.replace("https://", "").replace("http://", "").split("/")[0].strip()
                if line:
                    targets.append(line.lower())
    except Exception as e:
        logging.error(f"Error reading targets file: {e}")
        return [], 0
    
    # Deduplicate
    seen = set()
    unique_targets = [t for t in targets if not (t in seen or seen.add(t))]
    
    return unique_targets, total_lines


def process_single_target(domain: str, output_dir: str, options: dict, args, batch_display: BatchDisplay):
    """Process one target (for batch mode)"""
    try:
        setup_logging(output_dir, options.get("verbose", False))
        agent = ReconAgent(
            target=domain,
            output_dir=output_dir,
            options=options,
            wps_token=args.wps_token,
            urls_file=getattr(args, 'urls_file', ''),
            subdomains_file=getattr(args, 'subdomains_file', ''),
            force_recon=getattr(args, 'force_recon', False),
            batch_display=batch_display,
            api_status=check_api_keys()
        )
        agent.run()
    except Exception as e:
        logging.getLogger("batch").error(f"{domain} failed: {e}")
        batch_display.mark_failed(domain, str(e)[:30])


def run_batch(targets_file: str, options: dict, args):
    """Continuous batch mode - monitor file for changes"""
    base_output = args.output or os.path.join(BASE_DIR, "results")
    os.makedirs(base_output, exist_ok=True)
    
    # Setup logging
    batch_log = os.path.join(base_output, "batch.log")
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[logging.FileHandler(batch_log)]
    )
    
    # Initialize display
    api_status = check_api_keys()
    display = BatchDisplay(api_status=api_status, max_workers=args.max_workers, targets_file=targets_file)
    
    # Track active scans
    futures = {}  # domain -> future
    processed = set()  # domains đã từng thấy
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            while True:
                # Đọc targets hiện tại
                current_targets, total_lines = load_targets(targets_file)
                
                # Cập nhật tổng số domain
                display.update_total_domains(total_lines)
                
                # Thêm targets mới vào queue
                for domain in current_targets:
                    if domain not in processed:
                        display.add_to_queue(domain)
                        processed.add(domain)
                        display._add_to_feed("📥", "New target", domain, "Added to queue")
                
                # Promote từ queue lên active nếu còn worker
                while len(futures) < args.max_workers:
                    domain = display.promote_from_queue()
                    if not domain:
                        break
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    domain_safe = domain.replace(".", "_")
                    domain_output = os.path.join(base_output, f"{domain_safe}_{timestamp}")
                    
                    future = executor.submit(
                        process_single_target, 
                        domain, domain_output, options, args, display
                    )
                    futures[domain] = future
                    display._add_to_feed("▶️", "Started", domain, "Scan began")
                
                # Clean up completed futures
                done = []
                for domain, future in futures.items():
                    if future.done():
                        try:
                            future.result()
                        except Exception as e:
                            logging.error(f"Scan failed for {domain}: {e}")
                        done.append(domain)
                
                for domain in done:
                    del futures[domain]
                
                time.sleep(10)
                
    except KeyboardInterrupt:
        display.stop()
        print("\n\n⚡ Batch scan stopped by user")
    finally:
        display.stop()


def main():
    args = parse_args()

    options = {
        "skip_recon": args.skip_recon,
        "skip_live_hosts": args.skip_live,
        "skip_crawl": args.skip_crawl,
        "skip_scan": args.skip_scan,
        "skip_wordpress": args.skip_wp,
        "skip_exploit": args.no_exploit,
        "verbose": args.verbose,
    }

    # Chạy batch mode
    run_batch(args.file, options, args)


if __name__ == "__main__":
    main()