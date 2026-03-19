import argparse
import logging
import os
import sys
import json
import time
import signal
import concurrent.futures
from datetime import datetime, timedelta
from glob import glob
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any

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
from core.scan_budget import ScanBudget

# ─── AI Components ───────────────────────────────────────────────────────────
from ai.endpoint_classifier import EndpointClassifier
from ai.payload_gen import PayloadGenerator
from ai.payload_mutation import PayloadMutator
from ai.analyzer import AIAnalyzer
from ai.chain_planner import ChainPlanner

# ─── Constants ──────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GO_BIN = os.path.expanduser("~/go/bin")
LOCAL_BIN = os.path.expanduser("~/.local/bin")
if GO_BIN not in os.environ.get("PATH", ""):
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + GO_BIN
if LOCAL_BIN not in os.environ.get("PATH", ""):
    os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + LOCAL_BIN


def load_env_file(env_path: str = ".env"):
    """Load simple KEY=VALUE pairs from .env if not already in process env."""
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        pass


load_env_file(os.path.join(BASE_DIR, ".env"))

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
from modules.auth_scanner import AuthScannerEngine
from modules.toolkit_scanner import ToolkitScanner


# ─── API Key Check ───────────────────────────────────────────────────────────
def check_api_keys() -> dict:
    """Kiểm tra trạng thái các API key cần thiết."""
    groq_key = os.environ.get("GROQ_API_KEY", "") or os.environ.get("GROQ_APIKEY", "")
    wps_token = os.environ.get("WPScan_API_TOKEN", "") or os.environ.get("WPSCAN_API_TOKEN", "")
    nvd_key = os.environ.get("NVD_API_KEY", "") or os.environ.get("NVDAPI_KEY", "")

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
            chains = summary.get('chains', 0)
            top_chain = summary.get('top_chain', '')
            self.completed.appendleft((domain, vulns, exploited, chains, top_chain, datetime.now().strftime("%H:%M:%S")))
            
            if vulns > 0:
                chain_txt = f", {chains} chains" if chains else ""
                self._add_to_feed("✅", "Completed", domain, f"{vulns} vulns, {exploited} exploited{chain_txt}")
            else:
                chain_txt = f", {chains} chains" if chains else ""
                self._add_to_feed("✅", "Completed", domain, f"0 vulns{chain_txt}")
            if chains > 0:
                shown = (top_chain or "top chain available")[:45]
                self._add_to_feed("🔗", "Chains", domain, shown)
    
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
                    phase_tool = data.get('phase_tool', '') or 'n/a'
                    phase_status = data.get('phase_status', 'idle')
                    iter_info = f"iter {data.get('iter', 1)}/{data.get('max_iter', 5)}"
                    
                    phase_icon = {
                        'recon': '🔍', 'live': '🌐', 'wp': '🎯', 'crawl': '📁',
                        'auth': '🔐',
                        'toolkit': '🛠️',
                        'classify': '🤖', 'rank': '📊', 'scan': '⚡', 'analyze': '🔬',
                        'graph': '🕸️', 'chain': '🔗', 'exploit': '💥', 'learn': '🧠',
                        'init': '⚙️', 'report': '📋'
                    }.get(phase, '⚙️')
                    
                    progress = self._get_progress_text(data)
                    domain_display = domain[:30] if len(domain) <= 30 else domain[:27] + "..."
                    
                    print(f"│  │     #{idx} {domain_display:<30} [{phase_icon} {phase.capitalize()}] {iter_info:<10} | {progress:<12} │")
                    print(f"│  │        tool={phase_tool[:20]:<20} status={phase_status[:14]:<14}                                      │")
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
                for domain, vulns, exploited, chains, top_chain, ts in list(self.completed)[:3]:
                    if chains:
                        completed_text.append(f"{domain} ({vulns}v/{chains}c)")
                    else:
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
                    phase = data.get('phase', 'init')
                    phase_tool = data.get('phase_tool', '') or 'n/a'
                    phase_status = data.get('phase_status', 'idle')
                    print(f"│  │  ├─ ⚙️  Phase: {phase:<10} Tool: {phase_tool[:28]:<28} Status: {phase_status:<10} │")
                    
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
            'stats': {'subs': 0, 'live': 0, 'eps': 0, 'vulns': 0, 'exploited': 0, 'wp': 0, 'tech_detected': 0},
            'chains': [],
            'last_action': 'initializing...',
            'phase_detail': '',
            'phase_tool': '',
            'phase_status': 'idle',
            'tech': {},
            'endpoints': {'api': 0, 'admin': 0, 'upload': 0, 'total': 0},
            'vuln_types': defaultdict(int),
            'learning': {'mutated': 0, 'confidence': 0.0},
            'toolkit_metrics': {'tech': 0, 'ports': 0, 'dirs': 0, 'api': 0, 'vulns': 0}
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
            'auth': '🔐',
            'toolkit': '🛠️',
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
        tool = (d.get('phase_tool') or 'n/a')[:24]
        status = (d.get('phase_status') or 'idle')[:16]
        print(f"│  Tool: {tool:<24} | Status: {status:<16}                                   │")
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
        
        # Toolkit Metrics
        toolkit_m = d.get('toolkit_metrics', {})
        if any([toolkit_m.get(k, 0) > 0 for k in ['tech', 'ports', 'dirs', 'api', 'vulns']]):
            print("│                                                                              │")
            print("│  🛠️ TOOLKIT SCAN RESULTS                                                    │")
            if toolkit_m.get('tech', 0) > 0:
                print(f"│  ├─ Technologies: {toolkit_m.get('tech', 0):<3}                                        │")
            if toolkit_m.get('ports', 0) > 0:
                print(f"│  ├─ Ports Open  : {toolkit_m.get('ports', 0):<3}                                        │")
            if toolkit_m.get('dirs', 0) > 0:
                print(f"│  ├─ Directories : {toolkit_m.get('dirs', 0):<3}                                        │")
            if toolkit_m.get('api', 0) > 0:
                print(f"│  ├─ API Endpoints: {toolkit_m.get('api', 0):<3}                                        │")
            if toolkit_m.get('vulns', 0) > 0:
                print(f"│  └─ CVEs Found : {toolkit_m.get('vulns', 0):<3}                                        │")
        
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

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # Avoid duplicate handlers when running many targets in batch mode.
    has_file = False
    has_console = False
    for h in root.handlers:
        if isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "") == os.path.abspath(log_file):
            has_file = True
        if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler):
            has_console = True

    if not has_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        root.addHandler(file_handler)

    if not has_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(console_handler)
    
    logging.getLogger("urllib3").setLevel(logging.ERROR)
    logging.getLogger("requests").setLevel(logging.ERROR)
    
    return logging.getLogger("recon.agent")


# ─── MAIN AGENT ───────────────────────────────────────────────────────────
class ReconAgent:
    def __init__(self, target: str, output_dir: str, options: dict,
                 wps_token: str = "", nvd_key: str = "", 
                 urls_file: str = "", subdomains_file: str = "", auth_file: str = "", force_recon: bool = False,
                 batch_display: BatchDisplay = None,
                 api_status: Optional[dict] = None,
                 target_index: int = 1,
                 total_targets: int = 1):
        
        self.target = target.lower().strip()
        self.output_dir = output_dir
        self.options = options
        self.wps_token = wps_token or os.environ.get("WPScan_API_TOKEN", "") or os.environ.get("WPSCAN_API_TOKEN", "")
        self.nvd_key = nvd_key or os.environ.get("NVD_API_KEY", "") or os.environ.get("NVDAPI_KEY", "")
        self.urls_file = urls_file
        self.subdomains_file = subdomains_file
        self.auth_file = auth_file
        self.force_recon = force_recon
        self.batch_display = batch_display
        self.api_status = api_status or {}
        self.target_index = target_index
        self.total_targets = total_targets
        self.scan_start_time = time.time()
        # Force full profile by default (no scan-strength selection).
        self.budget = ScanBudget.build(self.target, aggressive=True)
        
        if batch_display:
            self.display = None
            self.batch_id = target
        else:
            self.display = DomainDisplay(target, api_status=self.api_status,
                                         target_index=self.target_index,
                                         total_targets=self.total_targets)
        
        # Initialize components
        self.state = StateManager(self.target, output_dir)
        self.resumed_from_state = self.state.load()
        scan_meta = self.state.get("scan_metadata", {}) or {}
        scan_meta["budget"] = self.budget.to_dict()
        scan_meta["aggressive"] = True
        self.state.update(scan_metadata=scan_meta)
        self.session = SessionManager(self.output_dir)
        self.http_client = HTTPClient(self.session)
        self.response_analyzer = ResponseAnalyzer()
        self.learning_engine = LearningEngine(output_dir)
        
        groq_key = os.environ.get("GROQ_API_KEY", "") or os.environ.get("GROQ_APIKEY", "")
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
        self.scanning_engine = ScanningEngine(self.state, output_dir, self.payload_gen, self.payload_mutator, self.learning_engine)
        self.exploit_engine = ExploitTestEngine(self.state, output_dir, self.learning_engine)
        self.wp_scanner = WordPressScannerEngine(self.state, output_dir, self.wps_token)
        self.auth_engine = AuthScannerEngine(self.state, output_dir, self.session)
        self.toolkit = ToolkitScanner(self.state, output_dir, aggressive=True)
        
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
        self.phase_tool = ""
        self.phase_status = "idle"
        self.learning_stats = {'mutated': 0, 'confidence': 0.0}
        self.toolkit_metrics = {'tech': 0, 'ports': 0, 'dirs': 0, 'api': 0, 'vulns': 0}
        scan_meta = self.state.get("scan_metadata", {}) or {}
        self.completed_phases = set(scan_meta.get("completed_phases", []) or [])
        if self.resumed_from_state:
            previous_phase = self.state.get("current_phase", "unknown")
            self.last_action = f"resumed from state ({previous_phase})"
            self._update_stats()
        self._update_display()

    def _update_display(self):
        if self.batch_display:
            self.batch_display.update(self.batch_id, {
                'phase': self.current_phase,
                'phase_detail': self.phase_detail,
                'phase_tool': self.phase_tool,
                'phase_status': self.phase_status,
                'iter': self.iteration_count,
                'max_iter': self.max_iterations,
                'stats': self.stats.copy(),
                'chains': self.chains_data,
                'tech': self.tech_stack.copy(),
                'endpoints': self.endpoint_stats.copy(),
                'toolkit_metrics': self.toolkit_metrics.copy(),
                'last_action': self.last_action,
                'start_time': self.scan_start_time
            })
        else:
            if self.display:
                self.display.update(
                    phase=self.current_phase,
                    phase_detail=self.phase_detail,
                    phase_tool=self.phase_tool,
                    phase_status=self.phase_status,
                    iter=self.iteration_count,
                    stats=self.stats.copy(),
                    chains=self.chains_data,
                    vuln_types=dict(self.vuln_types),
                    endpoints=self.endpoint_stats.copy(),
                    tech=self.tech_stack.copy(),
                    learning=self.learning_stats.copy(),
                    toolkit_metrics=self.toolkit_metrics.copy(),
                    last_action=self.last_action
                )

    def _set_activity(self, tool: str, status: str, detail: str = ""):
        self.phase_tool = tool
        self.phase_status = status
        if detail:
            self.phase_detail = detail
        self._update_display()

    def _progress_callback(self, phase: str, tool: str, status: str):
        # Keep current phase aligned with the module emitting progress.
        if phase:
            self.current_phase = phase
        self._set_activity(tool=tool, status=status)

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
                    self.phase_tool = "subfinder"
                    self.phase_status = "queued"
                    self._update_display()
                    self._run_recon_phase()
                
                # Phase 2: Live Hosts
                if self.iteration_count == 1 and not self._should_skip_phase("live_hosts"):
                    self.current_phase = "live"
                    self.phase_detail = "detect"
                    self.phase_tool = "httpx+requests"
                    self.phase_status = "queued"
                    self._update_display()
                    self._run_live_hosts_phase()
                    if self._should_abort_no_live_hosts():
                        break
                
                # Phase 3: WordPress
                if self.iteration_count == 1 and not self._should_skip_phase("wordpress"):
                    self.current_phase = "wp"
                    self.phase_detail = "scan"
                    self.phase_tool = "wpscan+fingerprint"
                    self.phase_status = "queued"
                    self._update_display()
                    self._run_wordpress_phase()

                # Phase 3.5: External toolkit scan (Kali tools)
                if self.iteration_count == 1 and not self._should_skip_phase("toolkit"):
                    self.current_phase = "toolkit"
                    self.phase_detail = "kali-tools"
                    self.phase_tool = "whatweb/wafw00f/nikto/nmap"
                    self.phase_status = "queued"
                    self._update_display()
                    self._run_toolkit_phase()
                
                # Phase 4: Discovery
                if self.iteration_count == 1 and not self._should_skip_phase("discovery"):
                    self.current_phase = "crawl"
                    self.phase_detail = "spider"
                    self.phase_tool = "parser+browser+katana"
                    self.phase_status = "queued"
                    self._update_display()
                    self._run_discovery_phase()
                    if self._should_abort_low_signal():
                        break

                # Phase 4.5: Authenticated sessions bootstrap
                if self.iteration_count == 1 and self.auth_file and not self._should_skip_phase("auth"):
                    self.current_phase = "auth"
                    self.phase_detail = "roles"
                    self.phase_tool = "session-bootstrap"
                    self.phase_status = "queued"
                    self._update_display()
                    self._run_auth_phase()
                
                # Phase 5: Classification
                if "classify" not in self.completed_phases:
                    self.current_phase = "classify"
                    self.phase_detail = "ai"
                    self.phase_tool = "endpoint-classifier"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_classification_phase()
                
                # Phase 6: Prioritization
                if "rank" not in self.completed_phases:
                    self.current_phase = "rank"
                    self.phase_detail = "scoring"
                    self.phase_tool = "endpoint-ranker"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_prioritization_phase()
                
                # Phase 7: Scanning
                if not self._should_skip_phase("scan"):
                    self.current_phase = "scan"
                    self.phase_detail = "active"
                    self.phase_tool = "nuclei/sqlmap/dalfox"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_scanning_phase()
                
                # Phase 8: Analysis
                if "analyze" not in self.completed_phases:
                    self.current_phase = "analyze"
                    self.phase_detail = "ai"
                    self.phase_tool = "ai-analyzer"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_analysis_phase()
                
                # Phase 9: Attack Graph
                if "graph" not in self.completed_phases:
                    self.current_phase = "graph"
                    self.phase_detail = "build"
                    self.phase_tool = "attack-graph"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_attack_graph_phase(attack_graph)
                
                # Phase 10: Chain Planning
                if "chain" not in self.completed_phases:
                    self.current_phase = "chain"
                    self.phase_detail = "plan"
                    self.phase_tool = "chain-planner"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_chain_planning_phase(attack_graph)
                
                # Phase 11: Exploit Testing
                if not self._should_skip_phase("exploit"):
                    self.current_phase = "exploit"
                    self.phase_detail = "test"
                    self.phase_tool = "exploit-validator"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_exploit_phase()
                
                # Phase 12: Learning
                if "learn" not in self.completed_phases:
                    self.current_phase = "learn"
                    self.phase_detail = "adapt"
                    self.phase_tool = "learning-engine"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_learning_phase()
                
                self._update_stats()
                
                if self._check_confidence_threshold():
                    break
                    
                self._adapt_for_next_iteration()
            
            # Final
            self.current_phase = "report"
            self.last_action = "generating final report..."
            self.phase_tool = "report-generator"
            self.phase_status = "running"
            self._update_display()
            self._generate_final_report()
            self._mark_phase_done("report")
            self.phase_status = "done"
            self._update_display()
            
            if self.batch_display:
                top_chain = ""
                if self.chains_data:
                    top_chain = self.chains_data[0].get("name", "")
                self.batch_display.mark_completed(self.target, {
                    'vulns': self.stats['vulns'],
                    'chains': len(self.chains_data),
                    'exploited': self.stats['exploited'],
                    'top_chain': top_chain
                })
            else:
                self.display.stop()
            
        except KeyboardInterrupt:
            self.last_action = "interrupted by user"
            self.phase_status = "interrupted"
            self._update_display()
            self.logger.warning("Scan interrupted")
            self.state.save()
            self._generate_final_report()
            if self.batch_display:
                self.batch_display.mark_failed(self.target, "interrupted")
        except Exception as e:
            self.last_action = f"error: {str(e)[:30]}"
            self.phase_status = "failed"
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
            "toolkit": "skip_toolkit",
            "discovery": "skip_crawl", 
            "auth": "skip_auth",
            "scan": "skip_scan",
            "exploit": "skip_exploit"
        }
        if self.options.get(skip_map.get(phase, ""), False):
            return True
        return phase in self.completed_phases

    def _mark_phase_done(self, phase: str):
        if not phase:
            return
        self.completed_phases.add(phase)
        scan_meta = self.state.get("scan_metadata", {}) or {}
        scan_meta["completed_phases"] = sorted(self.completed_phases)
        self.state.update(scan_metadata=scan_meta)

    def _run_recon_phase(self):
        before = len(self.state.get("subdomains", []))
        self._set_activity("subfinder", "running", "enum")
        self.recon_engine.run(progress_cb=self._progress_callback)
        self._set_activity("recon-engine", "done", "enum")
        after = len(self.state.get("subdomains", []))
        if after > before:
            self.stats['subs'] = after
            self.last_action = f"recon: +{after-before} subdomains"
            if self.batch_display:
                self.batch_display._add_to_feed("➕", "Subdomain", self.target, f"Found {after-before} new")
        self._update_stats()
        self._mark_phase_done("recon")

    def _run_live_hosts_phase(self):
        before = len(self.state.get("live_hosts", []))
        if before >= int((self.budget.to_dict() if hasattr(self, "budget") else {}).get("live_secondary_targets", 90)):
            self.last_action = f"live hosts: reused {before} from recon cache"
            self.phase_status = "done"
            self._update_display()
            self._mark_phase_done("live_hosts")
            return
        self._set_activity("live-host-detector", "running", "detect")
        self.stats['total_hosts'] = len(self.state.get("subdomains", []))
        self.live_host_engine.detect_live_hosts(self.state.get("subdomains", []))
        self._set_activity("live-host-detector", "done", "detect")
        after = len(self.state.get("live_hosts", []))
        if after > before:
            self.stats['live'] = after
            self.last_action = f"live hosts: +{after-before} live"
            if self.batch_display:
                self.batch_display._add_to_feed("🌐", "Live", self.target, f"Found {after-before} live")
        self._update_stats()
        self._mark_phase_done("live_hosts")

    def _should_abort_no_live_hosts(self) -> bool:
        """Abort early when the target has no reachable live hosts."""
        live_hosts = self.state.get("live_hosts", [])
        if live_hosts:
            return False
        self.last_action = "no live hosts detected; aborting deep scan"
        self.state.add_error("No live hosts reachable for target")
        self._update_display()
        return True

    def _should_abort_low_signal(self) -> bool:
        """
        Abort deep phases when signal is too low to justify expensive scans.
        """
        eps = len(self.state.get("endpoints", []) or [])
        prioritized = len(self.state.get("prioritized_endpoints", []) or [])
        wp = bool(self.state.get("wordpress_detected", False))
        live = len(self.state.get("live_hosts", []) or [])
        if live == 0:
            return True
        if eps == 0 and prioritized == 0 and not wp:
            self.last_action = "low-signal target; skipping deep exploit phases"
            self.phase_status = "done"
            self._update_display()
            return True
        return False

    def _run_wordpress_phase(self):
        self._set_activity("wpscan+wp-fingerprint", "running", "scan")
        live_hosts = self._select_live_hosts_for_deep_scan(limit=40)
        from urllib.parse import urlparse
        target_urls = []
        seen = set()
        for host in live_hosts:
            u = host.get("url", "")
            if not u:
                continue
            try:
                p = urlparse(u)
                if not p.scheme or not p.netloc:
                    continue
                root = f"{p.scheme}://{p.netloc.lower()}"
            except Exception:
                continue
            if root not in seen:
                seen.add(root)
                target_urls.append(root)
        if target_urls:
            wp_sites = self.wp_scanner.scan_wordpress_sites(target_urls)
            if wp_sites:
                self.stats['wp'] = len(wp_sites)
                self.last_action = f"wordpress: {len(wp_sites)} sites"
                if self.batch_display:
                    self.batch_display._add_to_feed("🎯", "WordPress", self.target, f"Found {len(wp_sites)} sites")
        self._set_activity("wpscan+wp-fingerprint", "done", "scan")
        self._update_stats()
        self._mark_phase_done("wordpress")

    def _run_toolkit_phase(self):
        """Enhanced toolkit scanning with detailed tracking of all sub-modules"""
        live_hosts = self._select_live_hosts_for_deep_scan(limit=30)
        
        if not live_hosts:
            self.last_action = "toolkit: no live hosts for scanning"
            self._mark_phase_done("toolkit")
            return
        
        self._set_activity("kali-toolkit", "running", "kali-tools")
        self.logger.info(f"[TOOLKIT] Starting comprehensive scan on {len(live_hosts)} hosts")
        
        # Run toolkit with progress tracking
        findings = self.toolkit.run(live_hosts, progress_cb=self._progress_callback)
        self._set_activity("kali-toolkit", "processing", "kali-tools")
        
        # Process and aggregate findings
        toolkit_metrics = self._process_toolkit_findings(findings)
        
        # Store metrics for display update
        self.toolkit_metrics = {
            'tech': toolkit_metrics.get('tech_count', 0),
            'ports': toolkit_metrics.get('ports_count', 0),
            'dirs': toolkit_metrics.get('directories_count', 0),
            'api': toolkit_metrics.get('api_count', 0),
            'vulns': len(toolkit_metrics.get('vulnerabilities', []))
        }
        
        self._set_activity("kali-toolkit", "done", "kali-tools")
        self.logger.info(f"[TOOLKIT] Scan complete: {toolkit_metrics['summary']}")
        
        # Update display with detailed metrics
        if toolkit_metrics['total'] > 0:
            self.last_action = f"toolkit: {toolkit_metrics['summary']}"
            if self.batch_display:
                detail_msg = f"Tech: {toolkit_metrics['tech_count']} | Ports: {toolkit_metrics['ports_count']} | API: {toolkit_metrics['api_count']}"
                self.batch_display._add_to_feed("🛠️", "Toolkit", self.target, detail_msg)
        else:
            self.last_action = "toolkit: no findings"
        
        self._update_display()
        self._mark_phase_done("toolkit")

    def _process_toolkit_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Process and aggregate toolkit findings into metrics"""
        metrics = {
            'total': len(findings),
            'tech_count': 0,
            'tech_list': set(),
            'ports_count': 0,
            'directories_count': 0,
            'api_count': 0,
            'vulnerabilities': [],
            'summary': ''
        }
        
        for finding in findings:
            tool_name = finding.get('tool', 'unknown')
            
            if tool_name == 'whatweb':
                data = finding.get('data', {})
                techs = data.get('technologies', [])
                metrics['tech_count'] += len(techs)
                metrics['tech_list'].update([t.get('name', '') for t in techs])
                
                vulns = data.get('vulnerabilities', [])
                metrics['vulnerabilities'].extend(vulns)
                
                self.logger.info(f"[WHATWEB] {finding.get('url')}: {len(techs)} techs, {len(vulns)} CVEs")
                
            elif tool_name == 'naabu':
                data = finding.get('data', {})
                ports = data.get('ports', [])
                metrics['ports_count'] += len(ports)
                services = data.get('services', {})
                
                self.logger.info(f"[NAABU] {finding.get('host')}: {len(ports)} ports open")
                for port, service_info in services.items():
                    self.logger.debug(f"  ├─ {port}: {service_info.get('service', 'unknown')}")
                
            elif tool_name == 'dirbusting':
                data = finding.get('data', {})
                dirs = data.get('directories', [])
                files = data.get('files', [])
                suspicious = data.get('suspicious', [])
                metrics['directories_count'] += len(dirs) + len(files)
                
                self.logger.info(f"[DIRBUSTING] {finding.get('url')}: {len(dirs)} dirs, {len(files)} files, {len(suspicious)} suspicious")
                
            elif tool_name == 'api_scanner':
                data = finding.get('data', {})
                rest_endpoints = data.get('rest_endpoints', [])
                graphql_endpoints = data.get('graphql_endpoints', [])
                api_docs = data.get('api_docs', [])
                api_total = len(rest_endpoints) + len(graphql_endpoints) + len(api_docs)
                metrics['api_count'] += api_total
                
                self.logger.info(f"[API-SCANNER] {finding.get('url')}: {len(rest_endpoints)} REST, {len(graphql_endpoints)} GraphQL, {len(api_docs)} docs")
                
                vulns = data.get('vulnerabilities', [])
                metrics['vulnerabilities'].extend(vulns)
                for vuln in vulns:
                    self.logger.warning(f"[API-VULN] {vuln.get('type')}: {finding.get('url')}")
            
            elif tool_name == 'wafw00f':
                self.logger.info(f"[WAFW00F] WAF detection: {finding.get('severity')}")
            
            elif tool_name == 'nikto':
                self.logger.info(f"[NIKTO] Scan completed: {finding.get('url')}")
            
            elif tool_name == 'nmap':
                self.logger.info(f"[NMAP] Port scan completed: {finding.get('host')}")
        
        # Build summary
        summary_parts = []
        if metrics['tech_count'] > 0:
            summary_parts.append(f"{metrics['tech_count']} tech")
        if metrics['ports_count'] > 0:
            summary_parts.append(f"{metrics['ports_count']} ports")
        if metrics['directories_count'] > 0:
            summary_parts.append(f"{metrics['directories_count']} dirs")
        if metrics['api_count'] > 0:
            summary_parts.append(f"{metrics['api_count']} API")
        if metrics['vulnerabilities']:
            summary_parts.append(f"{len(metrics['vulnerabilities'])} vulns")
        
        metrics['summary'] = ' | '.join(summary_parts) if summary_parts else 'no data'
        
        # Update state with discovered data
        self._merge_toolkit_data_into_state(metrics)
        
        return metrics

    def _merge_toolkit_data_into_state(self, metrics: Dict[str, Any]):
        """Merge toolkit findings into state manager"""
        # Update technologies
        if metrics['tech_list']:
            current_tech = self.state.get('technologies', {}) or {}
            for tech in metrics['tech_list']:
                if tech and tech not in current_tech:
                    current_tech[tech] = {'detected': True}
            self.state.update(technologies=current_tech)
        
        # Update stats
        if metrics['tech_count'] > 0:
            current_stats = self.stats.copy()
            current_stats['tech_detected'] = metrics['tech_count']
            self.stats = current_stats
        
        # Update vulnerabilities
        if metrics['vulnerabilities']:
            current_vulns = self.state.get('vulnerabilities', []) or []
            for vuln in metrics['vulnerabilities']:
                if vuln not in current_vulns:
                    current_vulns.append(vuln)
            self.state.update(vulnerabilities=current_vulns)
            self.stats['vulns'] = len(current_vulns)


    def _run_discovery_phase(self):
        before = len(self.state.get("endpoints", []))
        self._set_activity("crawler", "running", "spider")
        prioritized_hosts = [h.get("url", "") for h in self._select_live_hosts_for_deep_scan(limit=80) if h.get("url")]
        if prioritized_hosts:
            merged_urls = list(dict.fromkeys(prioritized_hosts + self.state.get("urls", [])))
            self.state.update(urls=merged_urls)
        self.discovery_engine.run(progress_cb=self._progress_callback)
        self._set_activity("crawler", "done", "spider")
        after = len(self.state.get("endpoints", []))
        if after > before:
            self.endpoint_stats['total'] = after
            self.stats['eps'] = after
            self.last_action = f"crawl: +{after-before} endpoints"
            if self.batch_display:
                self.batch_display._add_to_feed("📁", "Endpoint", self.target, f"Found {after-before} new")
        self._update_stats()
        self._mark_phase_done("discovery")

    def _run_auth_phase(self):
        self._set_activity("session-bootstrap", "running", "roles")
        results = self.auth_engine.run(self.auth_file)
        self._set_activity("session-bootstrap", "done", "roles")
        success = sum(1 for r in results if r.get("success"))
        self.last_action = f"auth: {success}/{len(results)} roles authenticated"
        if self.batch_display:
            self.batch_display._add_to_feed("🔐", "Auth", self.target, self.last_action)
        self._update_display()
        self._mark_phase_done("auth")

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
        self.phase_status = "done"
        self._update_stats()
        self._mark_phase_done("classify")

    def _run_prioritization_phase(self):
        self._run_endpoint_ranking()
        self.phase_status = "done"
        self._update_display()
        self._mark_phase_done("rank")

    def _run_scanning_phase(self):
        before = len(self.state.get("confirmed_vulnerabilities", []))
        self._set_activity("nuclei/sqlmap/dalfox", "running", "active")
        self.scanning_engine.run()
        self._set_activity("nuclei/sqlmap/dalfox", "done", "active")
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
        self._mark_phase_done("scan")

    def _run_analysis_phase(self):
        responses = self.state.get("scan_responses", [])
        vulnerabilities = []
        manual_queue = []
        for response in responses:
            if response.get("vulnerable"):
                confidence = float(response.get("confidence", 0) or 0)
                severity = "CRITICAL" if confidence >= 0.9 else "HIGH" if confidence >= 0.75 else "MEDIUM"
                requires_manual = severity in ("CRITICAL", "HIGH")
                vuln = {
                    "name": f"{response.get('category', 'unknown')} finding",
                    "endpoint": response.get("endpoint"),
                    "url": response.get("endpoint"),
                    "type": response.get("category"),
                    "severity": severity,
                    "payload": response.get("payload"),
                    "confidence": confidence,
                    "evidence": response.get("reason", ""),
                    "auth_role": response.get("auth_role", "anonymous"),
                    "requires_manual_validation": requires_manual,
                    "validated": False
                }
                vulnerabilities.append(vuln)
                if requires_manual:
                    manual_queue.append(
                        {
                            "id": f"{response.get('endpoint')}::{response.get('category')}::{len(manual_queue)+1}",
                            "endpoint": response.get("endpoint"),
                            "type": response.get("category"),
                            "severity": severity,
                            "evidence": response.get("reason", ""),
                            "status": "pending_manual_review"
                        }
                    )
        self.state.update(confirmed_vulnerabilities=vulnerabilities)
        self.state.update(manual_validation_required=manual_queue)
        if manual_queue:
            queue_file = os.path.join(self.output_dir, "manual_validation_queue.json")
            with open(queue_file, "w") as f:
                json.dump(manual_queue, f, indent=2)
        
        if vulnerabilities:
            self.last_action = f"analysis: {len(vulnerabilities)} confirmed"
            self._update_stats()
        self.phase_status = "done"
        self._update_display()
        self._mark_phase_done("analyze")

    def _run_attack_graph_phase(self, attack_graph: AttackGraph):
        confirmed = self.state.get("confirmed_vulnerabilities", [])
        wp_vulns = self.state.get("wp_vulnerabilities", []) or []

        vulnerabilities = list(confirmed)
        for wp_vuln in wp_vulns:
            vulnerabilities.append({
                "name": wp_vuln.get("type", "wordpress"),
                "endpoint": wp_vuln.get("url", "wordpress"),
                "severity": wp_vuln.get("severity", "MEDIUM"),
                "type": f"wordpress_{wp_vuln.get('type', 'issue')}",
                "confidence": wp_vuln.get("confidence", 0.5),
                "prerequisites": ["WordPress detected"],
                "consequences": [wp_vuln.get("type", "")],
            })
        if vulnerabilities:
            attack_graph.build_from_vulnerabilities(vulnerabilities)
            graph_file = os.path.join(self.output_dir, "attack_graph.json")
            attack_graph.save_to_file(graph_file)
            self.last_action = f"graph: built from {len(vulnerabilities)} vulns"
        self.phase_status = "done"
        self._update_display()
        self._mark_phase_done("graph")

    def _run_chain_planning_phase(self, attack_graph: AttackGraph):
        chains = self.chain_planner.plan_chains_from_graph(attack_graph)
        manual_playbook = self.chain_planner.build_manual_playbook(chains)
        
        self.chains_data = []
        for i, chain in enumerate(chains[:5], 1):
            chain_name = chain.get("name") if isinstance(chain, dict) else getattr(chain, "name", f"Chain-{i}")
            chain_risk = chain.get("risk") if isinstance(chain, dict) else getattr(chain, "risk_level", "MEDIUM")
            chain_steps = chain.get("steps", []) if isinstance(chain, dict) else getattr(chain, "steps", [])
            chain_info = {
                'name': chain_name or f"CHAIN-{i:02d}",
                'risk': chain_risk or 'MEDIUM',
                'exploited': False,
                'partial': False,
                'steps': [],
                'result': ''
            }
            
            for step in chain_steps[:3]:
                step_desc = step.get('description', '') if isinstance(step, dict) else getattr(step, "name", "")
                step_payload = step.get('payload', '') if isinstance(step, dict) else getattr(step, "payload", "")
                step_info = {
                    'desc': step_desc,
                    'success': step.get('exploited', False) if isinstance(step, dict) else False,
                    'partial': step.get('partial', False) if isinstance(step, dict) else False,
                    'payload': step_payload
                }
                chain_info['steps'].append(step_info)
            
            self.chains_data.append(chain_info)
        
        serializable_chains = []
        for chain in chains:
            if isinstance(chain, dict):
                serializable_chains.append(chain)
            else:
                serializable_chains.append(
                    {
                        "name": getattr(chain, "name", ""),
                        "description": getattr(chain, "description", ""),
                        "risk_level": getattr(chain, "risk_level", "MEDIUM"),
                        "estimated_time": getattr(chain, "estimated_time", "unknown"),
                        "steps": [
                            {
                                "name": getattr(s, "name", ""),
                                "action": getattr(s, "action", ""),
                                "target": getattr(s, "target", ""),
                                "tool": getattr(s, "tool", ""),
                                "payload": getattr(s, "payload", ""),
                                "success_indicator": getattr(s, "success_indicator", ""),
                            }
                            for s in getattr(chain, "steps", [])
                        ],
                    }
                )
        self.state.update(exploit_chains=serializable_chains)
        self.state.update(manual_attack_playbook=manual_playbook)
        playbook_file = os.path.join(self.output_dir, "manual_attack_playbook.json")
        with open(playbook_file, "w") as f:
            json.dump(manual_playbook, f, indent=2)
        if chains:
            self.last_action = f"chains: {len(chains)} attack paths"
        else:
            self.last_action = "chains: generated manual playbook"
        self.phase_status = "done"
        self._update_display()
        self._mark_phase_done("chain")

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
            self.phase_status = "done"
            self._update_display()
        self._mark_phase_done("exploit")

    def _run_learning_phase(self):
        self.learning_engine.learn_from_iteration(self.state)
        
        failed_payloads = self.learning_engine.get_failed_payloads()
        self.learning_stats['mutated'] = len(failed_payloads)
        self.phase_status = "done"
        self._update_display()
        self._mark_phase_done("learn")

    def _select_live_hosts_for_deep_scan(self, limit: int = 50) -> List[Dict]:
        live_hosts = self.state.get("live_hosts", []) or []
        scored = []
        for host in live_hosts:
            url = host.get("url", "")
            if not url:
                continue
            score = 0
            code = int(host.get("status_code", 0) or 0)
            if code == 200:
                score += 35
            elif 300 <= code < 400:
                score += 20
            elif 400 <= code < 500:
                score += 10
            low = url.lower()
            if any(k in low for k in ("wp", "admin", "login", "api", "graphql", "auth")):
                score += 25
            if any(k in low for k in ("staging", "dev", "test", "beta")):
                score += 10
            scored.append((score, host))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [h for _, h in scored[:limit]]

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
    parser.add_argument("-t", "--target", default="", help="Single target domain (one-shot mode)")
    parser.add_argument("-o", "--output", default=None, help="Output dir")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--no-exploit", action="store_true", help="Disable exploitation")
    parser.add_argument("--skip-recon", action="store_true", help="Skip recon")
    parser.add_argument("--skip-live", action="store_true", help="Skip live host detection")
    parser.add_argument("--skip-crawl", action="store_true", help="Skip crawling")
    parser.add_argument("--skip-scan", action="store_true", help="Skip scanning")
    parser.add_argument("--skip-wp", action="store_true", help="Skip WordPress scanning")
    parser.add_argument("--skip-toolkit", action="store_true", help="Skip external Kali toolkit phase")
    parser.add_argument("--wps-token", default="", help="WPScan API token")
    parser.add_argument("--urls-file", help="File with manual URLs")
    parser.add_argument("--subdomains-file", help="File with manual subdomains")
    parser.add_argument("--auth-file", help="JSON file with role-based login credentials")
    parser.add_argument("--force-recon", action="store_true", help="Force continue if recon fails")
    parser.add_argument("--max-workers", type=int, default=5, help="Max concurrent workers (default: 5)")
    parser.add_argument("--skip-auth", action="store_true", help="Skip authenticated session bootstrap")
    parser.add_argument("--once", action="store_true", help="Run one scheduling cycle and exit")
    parser.add_argument("--no-resume", action="store_true", help="Always start fresh run (disable auto-resume)")
    parser.add_argument("--aggressive", action="store_true", help=argparse.SUPPRESS)

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


def _find_resume_dir(base_output: str, domain: str) -> Optional[str]:
    """
    Find latest incomplete run folder for a domain.
    Incomplete means state exists but final_report.json is not present.
    """
    domain_safe = domain.replace(".", "_")
    patterns = [
        os.path.join(base_output, f"{domain_safe}_*"),
        os.path.join(base_output, f"{domain}_*"),
    ]
    candidates = []
    for pattern in patterns:
        candidates.extend([p for p in glob(pattern) if os.path.isdir(p)])
    candidates = list(dict.fromkeys(candidates))
    if not candidates:
        return None

    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    for folder in candidates:
        state_file = os.path.join(folder, "state.json")
        final_report = os.path.join(folder, "final_report.json")
        if os.path.exists(state_file) and not os.path.exists(final_report):
            return folder
    return None


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
            auth_file=getattr(args, 'auth_file', ''),
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
                    domain_output = None
                    if not getattr(args, "no_resume", False):
                        domain_output = _find_resume_dir(base_output, domain)
                        if domain_output:
                            display._add_to_feed("♻️", "Resume", domain, f"Continue {os.path.basename(domain_output)}")

                    if not domain_output:
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
                
                if getattr(args, "once", False) and processed and not futures:
                    break

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
        "skip_auth": args.skip_auth,
        "skip_scan": args.skip_scan,
        "skip_wordpress": args.skip_wp,
        "skip_toolkit": args.skip_toolkit,
        "skip_exploit": args.no_exploit,
        "verbose": args.verbose,
        "aggressive": True
    }

    if args.target:
        target_file = "/tmp/ai_recon_single_target.txt"
        with open(target_file, "w") as f:
            f.write(args.target.strip() + "\n")
        args.file = target_file
        args.once = True

    # Chạy batch mode
    run_batch(args.file, options, args)


if __name__ == "__main__":
    main()
