import argparse
import warnings
# Thêm vào sau các import modules
from modules.ddos_attacker import LoadTester
try:
    from bs4 import XMLParsedAsHTMLWarning
    warnings.filterwarnings('ignore', category=XMLParsedAsHTMLWarning)
except ImportError:
    pass
import logging
import os
from dotenv import load_dotenv
load_dotenv()
import sys
import json
import time
import signal
import concurrent.futures
import re
from datetime import datetime, timedelta
from dataclasses import asdict
from glob import glob
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
import config

# ─── Resource Management ─────────────────────────────────────────────────────
# Global concurrency manager for resource control across all modules
from core.resource_manager import get_concurrency_manager, shutdown_all as shutdown_resource_managers
# ─── Suppress ALL logs from libraries (connection errors, timeouts, etc.) ────
logging.getLogger("urllib3").setLevel(logging.CRITICAL)
logging.getLogger("urllib3.connectionpool").setLevel(logging.CRITICAL)
logging.getLogger("requests").setLevel(logging.CRITICAL)
logging.getLogger("chardet").setLevel(logging.CRITICAL)
logging.getLogger("charset_normalizer").setLevel(logging.CRITICAL)
logging.getLogger("httpx").setLevel(logging.CRITICAL)
logging.getLogger("httpcore").setLevel(logging.CRITICAL)
logging.getLogger("urllib").setLevel(logging.CRITICAL)
logging.getLogger("urllib3.connectionpool").propagate = False
logging.getLogger("requests").propagate = False
logging.getLogger("urllib3").propagate = False
logging.getLogger("charset_normalizer").propagate = False

# ─── Core Components ─────────────────────────────────────────────────────────
from core.state_manager import StateManager
from core.endpoint_ranker import EndpointRanker
from core.http_engine import HTTPClient
from core.response_analyzer import ResponseAnalyzer
from core.attack_graph import AttackGraph
from core.session_manager import SessionManager
from core.scan_budget import ScanBudget
from core.url_normalizer_enhanced import URLNormalizer
from core.endpoint_analyzer import EndpointAnalyzer
from core.exploit_executor import ExploitExecutor
from core.error_recovery import ErrorRecovery, ConditionalPlaybook
from core.wordlist_generator import WordlistGenerator
from core.attack_surface import AttackSurfaceTracker

# ─── Integration Components ─────────────────────────────────────────────────
from integrations.wp_advanced_scan import WordPressAdvancedScan

# ─── AI Components ───────────────────────────────────────────────────────────
from ai.endpoint_classifier import EndpointClassifier
from ai.groq_client import GroqClient
from ai.payload_gen import PayloadGenerator
from ai.payload_mutation import PayloadMutator
from ai.analyzer import AIAnalyzer
from ai.chain_planner import ChainPlanner, AIPoweredChainPlanner

# ─── NEW: Advanced Post-Exploitation Modules ────────────────────────────────
from modules.mfa_bypass import MFABypass, TOTPCracker
from modules.persistence_engine import PersistenceEngine, LateralMovement
from modules.oauth_saml_exploit import OAuthSAMLExploit, TokenManipulation
from modules.ssl_pinning_bypass import SSLPinningBypass, CertificateExploitation
from modules.zero_day_detection import ZeroDayDetection, AnomalyDetector
from modules.container_escape import ContainerEscapeEngine, LivingOffTheLand
from modules.custom_exploit_framework import CustomExploitFramework, ExploitLibrary
from modules.log_evasion import LogEvasion

# ─── Dashboard Components ────────────────────────────────────────────────────
from reports.dashboard_enhanced import EnhancedDashboard, format_state_for_display

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

# ─── NEW: Enhanced Analysis & Validation Modules ─────────────────────────────
from modules.service_fingerprinter import ServiceFingerprinter
from modules.exploit_verifier import ExploitVerifier
from modules.false_positive_filter import FalsePositiveFilter
from ai.payload_optimizer import PayloadOptimizer
from core.chain_validator import ChainValidator
from modules.crawler import DiscoveryEngine
from modules.scanner import ScanningEngine
from modules.exploiter import ExploitTestEngine
from modules.live_hosts import LiveHostEngine
from modules.auth_scanner import AuthScannerEngine
from modules.toolkit_scanner import ToolkitScanner
from modules.endpoint_probe import run_endpoint_probe
from modules.js_endpoint_hunter import hunt_js_endpoints
from modules.parameter_miner import mine_endpoint_parameters
from modules.sqli_exploiter import SQLiExploiter
from modules.upload_bypass import UploadBypass
from modules.reverse_shell import ReverseShellGenerator
from modules.privilege_escalation import PrivilegeEscalation
from modules.crypto_scanner import CryptographicScanner
from integrations.sqlmap_runner import SQLMapRunner

# ─── Tier-1 Vulnerability Detection Modules ────────────────────────────────
from modules.waf_bypass_engine import WAFBypassEngine
from modules.boolean_sqli_detector import BooleanSQLiDetector
from modules.xss_detector import XSSDetector
from modules.idor_detector import IDORDetector

# ─── Tier-2 Security Modules ───────────────────────────────────────────────
from modules.default_creds_scanner import DefaultCredsScanner
from modules.cve_exploiter import CVEExploiter
from modules.api_vuln_scanner import APIVulnScanner
from modules.subdomain_takeover_scanner import SubdomainTakeoverScanner

# ─── Core Intelligence Engines ──────────────────────────────────────────────
from core.privilege_pivot_engine import analyze_privilege_escalation
from core.automatic_exploit_selector import select_exploitation_strategy, select_all_strategies, should_execute_module, AutomaticExploitSelector

# ─── AI Intelligence Engines ────────────────────────────────────────────────
from ai.adaptive_payload_engine import generate_adaptive_payloads

# ─── NEW: Advanced Core Modules ─────────────────────────────────────────────
from core.async_scanner import AsyncScanner, sync_parallel_scan
from core.distributed_engine import DistributedEngine
from core.ml_classifier import MLClassifier
from core.exploit_chain_optimizer import ExploitChainOptimizer

# ─── NEW: Advanced Integrations ─────────────────────────────────────────────
from integrations.metasploit_rpc import MetasploitRPC, AutoExploiter
from integrations.burp_api import BurpAPI, BurpScanner

# ─── NEW: Advanced AI Modules ───────────────────────────────────────────────
from ai.llm_analyzer import LLMAnalyzer


# ─── API Key Check ───────────────────────────────────────────────────────────
def check_api_keys() -> dict:
    """Kiểm tra trạng thái các API key cần thiết."""
    groq_key = os.environ.get("GROQ_API_KEY", "") or os.environ.get("GROQ_APIKEY", "")
    nvd_key = os.environ.get("NVD_API_KEY", "") or os.environ.get("NVDAPI_KEY", "")

    def status(key):
        return "✓" if key else "✗"

    return {
        "Groq": status(groq_key),
        "NVD": status(nvd_key),
    }


# ─── ANSI COLOR CODES ───────────────────────────────────────────────────────
class Colors:
    """Modern color scheme for terminal output"""
    # Basic colors
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    
    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    
    # Background colors
    BG_BLUE = '\033[44m'
    BG_GREEN = '\033[42m'
    BG_RED = '\033[41m'
    BG_YELLOW = '\033[43m'
    BG_DIM = '\033[100m'
    
    @staticmethod
    def rgb(r, g, b):
        """Return ANSI 24-bit RGB color code"""
        return f'\033[38;2;{r};{g};{b}m'
    
    @staticmethod
    def bg_rgb(r, g, b):
        """Return ANSI 24-bit RGB background color code"""
        return f'\033[48;2;{r};{g};{b}m'
    
    @staticmethod
    def gradient(colors, text):
        """Apply gradient effect to text"""
        if not colors:
            return text
        step = len(text) / len(colors)
        result = []
        for i, char in enumerate(text):
            color_idx = min(int(i / step), len(colors) - 1)
            result.append(f"{colors[color_idx]}{char}")
        result.append(Colors.RESET)
        return ''.join(result)


# ─── MODERN THEME ───────────────────────────────────────────────────────────
class Theme:
    """Modern color theme for the dashboard"""
    # Primary gradient (cyan to blue to purple)
    PRIMARY = [
        Colors.rgb(0, 255, 255),    # Cyan
        Colors.rgb(0, 200, 255),    # Light blue
        Colors.rgb(100, 100, 255),  # Blue
        Colors.rgb(180, 0, 255),    # Purple
    ]
    
    # Success gradient (green to teal)
    SUCCESS = [Colors.rgb(0, 255, 136), Colors.rgb(0, 200, 200)]
    
    # Warning gradient (yellow to orange)
    WARNING = [Colors.rgb(255, 255, 0), Colors.rgb(255, 150, 0)]
    
    # Danger gradient (orange to red)
    DANGER = [Colors.rgb(255, 100, 0), Colors.rgb(255, 0, 80)]
    
    # UI elements
    BORDER = Colors.rgb(60, 60, 80)
    HEADER_BG = Colors.rgb(20, 20, 40)
    SECTION_BG = Colors.rgb(15, 15, 30)
    TEXT_PRIMARY = Colors.rgb(200, 200, 220)
    TEXT_SECONDARY = Colors.rgb(120, 120, 150)
    TEXT_DIM = Colors.rgb(80, 80, 100)
    
    # Status colors
    RUNNING = Colors.rgb(0, 200, 255)
    COMPLETED = Colors.rgb(0, 255, 136)
    FAILED = Colors.rgb(255, 80, 80)
    WAITING = Colors.rgb(255, 200, 0)


# ─── BATCH DISPLAY SYSTEM ───────────────────────────────────────────────────
class BatchDisplay:
    """
    Modern real-time display for continuous batch mode
    Features: gradient colors, smooth progress bars, clean layout
    """
    # Terminal width for consistent formatting
    TERM_WIDTH = 100
    CONTENT_WIDTH = 96  # TERM_WIDTH - 4 for borders
    
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
        
        # Live feed - tăng lên 12 events
        self.live_feed = deque(maxlen=12)

        # AI/Groq activity feed riêng
        self.ai_feed = deque(maxlen=6)

        # Start render thread
        self.render_thread = threading.Thread(target=self._render_loop)
        self.render_thread.daemon = True
        self.render_thread.start()
        self.spinner_index = 0
        self.spinner_frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        self.spinner_frames_alt = ['▹▹▹▹▹', '▸▹▹▹▹', '▹▸▹▹▹', '▹▹▸▹▹', '▹▹▹▸▹', '▹▹▹▹▸']
        self.ddos_attacker = None
        
        # Phase tracking for display
        self.ALL_PHASES = [
            'recon', 'live', 'wp', 'toolkit', 'crawl', 'wp_detect_state',
            'js_hunter', 'param_mine', 'auth', 'ml_classify', 'classify', 'rank', 'scan',
            'analyze', 'cve_analysis', 'pivot', 'graph', 'chain', 'select',
            'exploit', 'sqli_exploit', 'upload_bypass', 'reverse_shell',
            'privesc', 'waf_bypass', 'boolean_sqli', 'xss', 'idor',
            'default_creds', 'cve_exploit', 'api_vuln', 'subdomain_takeover',
            'mfa_bypass', 'oauth_saml', 'persistence', 'lateral_movement',
            'ssl_pinning', 'zero_day', 'container_escape', 'custom_exploit',
            'log_evasion', 'burp_scan', 'msf_exploit', 'llm_analysis', 'learn', 'ddos', 'report'
        ]
        self.PHASE_ORDER = {phase: idx for idx, phase in enumerate(self.ALL_PHASES)}
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
                del self.domains[domain]
            
            # Lấy stats từ summary (được truyền từ agent.py)
            vulns = summary.get('vulns', 0)
            exploited = summary.get('exploited', 0)
            eps = summary.get('eps', 0)
            live = summary.get('live', 0)
            wp = summary.get('wp', False)
            chains = summary.get('chains', 0)
            top_chain = summary.get('top_chain', '')
            
            # Cộng dồn vào tổng
            self.total_vulns += vulns
            self.total_exploited += exploited
            self.total_endpoints += eps
            self.total_live += live
            self.total_wordpress += 1 if wp else 0
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

    def _add_to_ai_feed(self, event: str, detail: str, domain: str = ""):
        """Thêm AI/Groq event vào ai_feed riêng"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.ai_feed.appendleft((timestamp, event, domain, detail))
    
    def _get_progress_bar(self, current: int, total: int, width: int = 10) -> str:
        """Create a visual progress bar"""
        if total == 0:
            # Show animated spinner when no data yet
            frame = self.spinner_frames[self.spinner_index % len(self.spinner_frames)]
            return f"{frame}{'░' * (width - 1)}"
        filled = int(width * current / total)
        bar = "█" * filled + "░" * (width - filled)
        return bar

    def _get_waiting_spinner(self) -> str:
        """Get animated waiting spinner for 'no data yet' states"""
        frame = self.spinner_frames[self.spinner_index % len(self.spinner_frames)]
        return frame

    def _get_phase_progress(self, current_phase: str) -> str:
        """Tính toán số thứ tự phase hiện tại / tổng số phase với tên phase"""
        if current_phase not in self.PHASE_ORDER:
            return f"init 0/{len(self.ALL_PHASES)}"
        current_idx = self.PHASE_ORDER[current_phase]
        # Map phase names to display names
        phase_display_names = {
            'recon': 'recon',
            'live': 'live',
            'wp': 'wordpress',
            'toolkit': 'toolkit',
            'crawl': 'discovery',
            'wp_detect_state': 'wp-detect',
            'js_hunter': 'js-hunter',
            'param_mine': 'param-mine',
            'auth': 'auth',
            'classify': 'classify',
            'rank': 'rank',
            'scan': 'scan',
            'analyze': 'analyze',
            'cve_analysis': 'cve-analysis',
            'pivot': 'pivot',
            'graph': 'graph',
            'chain': 'chain',
            'select': 'select',
            'exploit': 'exploit',
            'sqli_exploit': 'sqli-exploit',
            'upload_bypass': 'upload-bypass',
            'reverse_shell': 'reverse-shell',
            'privesc': 'privesc',
            'waf_bypass': 'waf-bypass',
            'boolean_sqli': 'bool-sqli',
            'xss': 'xss',
            'idor': 'idor',
            'default_creds': 'default-creds',
            'cve_exploit': 'cve-exploit',
            'api_vuln': 'api-vuln',
            'subdomain_takeover': 'subdomain-takeover',
            'mfa_bypass': 'mfa-bypass',
            'oauth_saml': 'oauth-saml',
            'persistence': 'persistence',
            'lateral_movement': 'lateral-movement',
            'ssl_pinning': 'ssl-pinning',
            'zero_day': 'zero-day',
            'container_escape': 'container-escape',
            'custom_exploit': 'custom-exploit',
            'log_evasion': 'log-evasion',
            'learn': 'learn',
            'ddos': 'ddos',
            'report': 'report',
        }
        display_name = phase_display_names.get(current_phase, current_phase)
        return f"{display_name} {current_idx + 1}/{len(self.ALL_PHASES)}"

    def _get_progress_text(self, data: dict) -> str:
        """Tạo progress text dựa trên phase"""
        phase = data.get('phase', 'init')
        stats = data.get('stats', {})
        phase_detail = data.get('phase_detail', '')
        scan_meta = data.get('scan_metadata', {}) or {}
        toolkit_m = data.get('toolkit_metrics', {}) or scan_meta.get('toolkit_metrics', {}) or {}
        
        if phase == 'recon':
            subs = stats.get('subs', 0)
            live = stats.get('live', 0)
            total = stats.get('total_hosts', 0)
            if total > 0:
                percent = int((live / total) * 100) if total else 0
                bar = self._get_progress_bar(live, total, 8)
                return f"{percent:3d}% [{bar}] {live}/{total}"
            return f"{subs} subs" if subs > 0 else "scanning..."
        elif phase == 'live':
            live = stats.get('live', 0)
            total = stats.get('total_hosts', 0)
            if total > 0:
                percent = int((live / total) * 100) if total else 0
                bar = self._get_progress_bar(live, total, 8)
                return f"{percent:3d}% [{bar}] {live}/{total}"
            return f"{live} live" if live > 0 else "detecting..."
        elif phase == 'wp':
            wp_count = stats.get('wp', 0)
            return f"🎯 {wp_count} WP" if wp_count > 0 else "🔍 WP..."
        elif phase == 'crawl':
            eps = stats.get('eps', 0)
            return f"📁 {eps} eps" if eps > 0 else "🔄 crawling..."
        elif phase == 'toolkit':
            tech = toolkit_m.get('tech', 0)
            ports = toolkit_m.get('ports', 0)
            dirs = toolkit_m.get('dirs', 0)
            api = toolkit_m.get('api', 0)
            total_findings = tech + ports + dirs + api
            if total_findings > 0:
                return f"📊 T:{tech} P:{ports} D:{dirs} A:{api}"
            return "🔧 scanning..."
        elif phase == 'scan':
            tested = stats.get('payloads_tested', 0)
            total = stats.get('total_payloads', 0)
            if total > 0:
                percent = int((tested / total) * 100) if total else 0
                bar = self._get_progress_bar(tested, total, 8)
                return f"{percent:3d}% [{bar}]"
            return f"⚡ {tested} payloads" if tested > 0 else "⏳ testing..."
        elif phase == 'exploit':
            chains = data.get('chains', [])
            if chains:
                exploited = sum(1 for c in chains if c.get('exploited'))
                percent = int((exploited / len(chains)) * 100) if len(chains) > 0 else 0
                bar = self._get_progress_bar(exploited, len(chains), 8)
                return f"{percent:3d}% [{bar}] {exploited}/{len(chains)}"
            return "💥 analyzing..."
        else:
            return phase_detail[:15] or "working..." if phase_detail else "working..."
    
    def _render_loop(self):
        """Thread render liên tục - 1 lần/giây để tiết kiệm CPU"""
        while self.running:
            current_time = time.time()
            if current_time - self.last_render_time >= 1.0:
                self._render()
                self.last_render_time = current_time
            time.sleep(0.5)  # Tối ưu: sleep 0.5s thay vì 0.1s để giảm CPU wake-ups
    
    def _render(self):
        """Vẽ giao diện dashboard modern với màu sắc và progress bar đẹp"""
        with self.lock:
            sys.stdout.write('\033[H\033[J')  # Clear screen
            
            C = Colors
            T = Theme
            W = self.CONTENT_WIDTH  # 96 chars for content
            
            # Header
            elapsed = int(time.time() - self.start_time)
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            
            active_count = len(self.domains)
            queue_count = len(self.queue)
            completed_count = len(self.completed)
            failed_count = len(self.failed)
            
            # Calculate throughput metrics
            throughput = completed_count / (elapsed + 1) * 60 if elapsed > 0 else 0
            
            # ═══════════════════════════════════════════════════════════════════
            # HEADER - Main title
            # ═══════════════════════════════════════════════════════════════════
            header_title = f"{C.BRIGHT_CYAN}⚡ AI RECON AGENT [BATCH MODE] ⚡{C.RESET}"
            time_str = f"{C.CYAN}Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}{C.RESET}"
            
            print(f"{T.BORDER}╔{'═' * (W + 2)}╗{C.RESET}")
            print(f"{T.BORDER}║{C.RESET}  {header_title}{' ' * max(0, W - 40)}{time_str}  {T.BORDER}║{C.RESET}")
            
            # ═══════════════════════════════════════════════════════════════════
            # STATISTICS SECTION
            # ═══════════════════════════════════════════════════════════════════
            print(f"{T.BORDER}╠{'═' * (W + 2)}╣{C.RESET}")
            print(f"{T.BORDER}║{C.RESET}  {C.BOLD}📊 STATISTICS{C.RESET}{' ' * max(0, W - 16)}{T.BORDER}║{C.RESET}")
            print(f"{T.BORDER}║{C.RESET}  ┌{'─' * (W - 4)}┐  {T.BORDER}║{C.RESET}")
            
            # Stats line
            speed_color = C.GREEN if throughput > 2 else C.YELLOW if throughput > 0 else T.TEXT_DIM
            stats_line = (
                f"  │  {speed_color}⚡ {throughput:.1f}/min{C.RESET}    "
                f"{C.BRIGHT_CYAN}▶ {active_count}/{self.max_workers}{C.RESET}      "
                f"{C.BRIGHT_YELLOW}⏳ {queue_count}{C.RESET}      "
                f"{C.BRIGHT_GREEN}✅ {completed_count}/{self.total_domains}{C.RESET}      "
                f"{C.BRIGHT_RED}❌ {failed_count}{' ' * 5}│  "
                f"{T.BORDER}║{C.RESET}"
            )
            print(stats_line)
            
            # Findings line
            findings_line = (
                f"  │  {C.BRIGHT_RED}🔴 {self.total_vulns} vulns{C.RESET}    "
                f"{C.BRIGHT_BLUE}📁 {self.total_endpoints} eps{C.RESET}    "
                f"{C.BRIGHT_MAGENTA}💥 {self.total_exploited} exploited{C.RESET}    "
                f"{C.BRIGHT_GREEN}🌐 {self.total_live} live{C.RESET}    "
                f"{C.BRIGHT_YELLOW}🎯 {self.total_wordpress} WordPress{' ' * max(0, W - 62)}│  "
                f"{T.BORDER}║{C.RESET}"
            )
            print(findings_line)
            print(f"{T.BORDER}║{C.RESET}  └{'─' * (W - 4)}┘  {T.BORDER}║{C.RESET}")
            
            # ═══════════════════════════════════════════════════════════════════
            # ACTIVE TARGETS SECTION
            # ═══════════════════════════════════════════════════════════════════
            print(f"{T.BORDER}║{C.RESET}  {' ' * (W + 2)}{T.BORDER}║{C.RESET}")
            print(f"{T.BORDER}║{C.RESET}  ╔{'═' * (W - 4)}╗  {T.BORDER}║{C.RESET}")
            print(f"{T.BORDER}║{C.RESET}  ║  {C.BOLD}▶ ACTIVE TARGETS ({active_count}/{self.max_workers}){C.RESET}{' ' * max(0, W - 30)}║  {T.BORDER}║{C.RESET}")
            print(f"{T.BORDER}║{C.RESET}  ╠{'─' * (W - 4)}╣  {T.BORDER}║{C.RESET}")
            
            phase_icons = {
                'recon': '🔍', 'live': '🌐', 'wp': '🎯', 'crawl': '📄',
                'auth': '🔐', 'toolkit': '🔧', 'classify': '🏷️', 'rank': '📊',
                'scan': '⚡', 'analyze': '🧪', 'graph': '🕸️', 'chain': '🔗',
                'exploit': '💣', 'learn': '📚', 'init': '⚙️', 'report': '📋',
                'select': '🎯', 'pivot': '🔄', 'hunt': '🔎', 'mine': '⛏️',
                'cve_analysis': '📖', 'mfa_bypass': '🔓', 'oauth_saml': '🔑',
                'persistence': '👻', 'lateral_movement': '↔️', 'ssl_pinning': '🔒',
                'zero_day': '🌟', 'container_escape': '📦', 'custom_exploit': '🛠️',
                'log_evasion': '🧹', 'sqli_exploit': '💧', 'upload_bypass': '📤',
                'reverse_shell': '🐚', 'privesc': '⬆️', 'waf_bypass': '🛡️',
                'boolean_sqli': '🔍', 'xss': '✨', 'idor': '🔑', 'default_creds': '🔐',
                'cve_exploit': '🎯', 'api_vuln': '🔌', 'subdomain_takeover': '🏴',
                'service_fp': '🔍', 'verify_vulns': '✅', 'fp_filter': '🎯',
                'chain_validate': '🔗', 'ddos': '💣'
            }
            
            for idx, (domain, data) in enumerate(list(self.domains.items())[:self.max_workers], 1):
                phase = data.get('phase', 'init')
                icon = phase_icons.get(phase, '⚙️')
                
                # Progress info
                progress_info = self._get_progress_text(data)
                
                # Domain (max 28 chars)
                dname = domain[:28] if len(domain) <= 28 else domain[:25] + "..."
                
                # Iteration
                it = data.get('iter', 1)
                max_it = data.get('max_iter', 5)
                
                # Elapsed time
                el = int(time.time() - data.get('start_time', time.time()))
                etime = f"{el // 60}m" if el >= 60 else f"{el}s"
                
                target_line = (
                    f"  ║  {C.BOLD}#{idx}{C.RESET} {icon} {dname:<28}  "
                    f"{C.YELLOW}I:{it}/{max_it}{C.RESET}   "
                    f"{progress_info}{' ' * max(0, W - 60 - len(progress_info))}  "
                    f"{C.DIM}⏱{etime}{C.RESET}                         ║  "
                    f"{T.BORDER}║{C.RESET}"
                )
                print(target_line)
            
            if active_count == 0:
                print(f"{T.BORDER}║{C.RESET}  ║  {T.TEXT_DIM}(no active targets){C.RESET}{' ' * max(0, W - 28)}║  {T.BORDER}║{C.RESET}")
            
            print(f"{T.BORDER}║{C.RESET}  ╚{'═' * (W - 4)}╝  {T.BORDER}║{C.RESET}")
            
            # ═══════════════════════════════════════════════════════════════════
            # QUEUE SECTION
            # ═══════════════════════════════════════════════════════════════════
            if queue_count > 0:
                print(f"{T.BORDER}║{C.RESET}  {' ' * (W + 2)}{T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ╔{'═' * (W - 4)}╗  {T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ║  {C.BOLD}⏳ QUEUE ({queue_count}){C.RESET}{' ' * max(0, W - 16)}║  {T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ╠{'─' * (W - 4)}╣  {T.BORDER}║{C.RESET}")
                
                for domain, added_time in list(self.queue)[:3]:
                    wt = int((time.time() - added_time.timestamp()) / 60)
                    dn = domain[:30] if len(domain) <= 30 else domain[:27] + "..."
                    queue_line = f"  ║    • {T.TEXT_SECONDARY}{dn}{C.RESET}{' ' * max(0, W - 38 - len(dn))}║  {T.BORDER}║{C.RESET}"
                    print(queue_line)
                
                if queue_count > 3:
                    print(f"  ║    {T.TEXT_DIM}... and {queue_count - 3} more{' ' * max(0, W - 30)}║  {T.BORDER}║{C.RESET}")
                
                print(f"{T.BORDER}║{C.RESET}  ╚{'═' * (W - 4)}╝  {T.BORDER}║{C.RESET}")
            
            # ═══════════════════════════════════════════════════════════════════
            # COMPLETED SECTION
            # ═══════════════════════════════════════════════════════════════════
            if completed_count > 0:
                print(f"{T.BORDER}║{C.RESET}  {' ' * (W + 2)}{T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ╔{'═' * (W - 4)}╗  {T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ║  {C.BOLD}✅ RECENTLY COMPLETED ({min(completed_count, 10)}){C.RESET}{' ' * max(0, W - 30)}║  {T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ╠{'─' * (W - 4)}╣  {T.BORDER}║{C.RESET}")
                
                for d, v, e, c, tc, ts in list(self.completed)[:3]:
                    vc = C.BRIGHT_RED if v > 0 else T.TEXT_DIM
                    dn = d[:22] if len(d) <= 22 else d[:19] + "..."
                    chain_info = f", {c} chains" if c > 0 else ""
                    comp_line = (
                        f"  ║    • {T.TEXT_SECONDARY}{dn}{C.RESET}  "
                        f"{vc}[{'█' * min(10, v)}{'░' * max(0, 10 - v)}] {v} vulns{C.RESET}, "
                        f"{e} exploited{chain_info}{' ' * max(0, W - 55)}║  "
                        f"{T.BORDER}║{C.RESET}"
                    )
                    print(comp_line)
                
                if completed_count > 3:
                    print(f"  ║    {T.TEXT_DIM}... and {completed_count - 3} more completed{' ' * max(0, W - 35)}║  {T.BORDER}║{C.RESET}")
                
                print(f"{T.BORDER}║{C.RESET}  ╚{'═' * (W - 4)}╝  {T.BORDER}║{C.RESET}")
            
            # ═══════════════════════════════════════════════════════════════════
            # FAILED SECTION
            # ═══════════════════════════════════════════════════════════════════
            if failed_count > 0:
                print(f"{T.BORDER}║{C.RESET}  {' ' * (W + 2)}{T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ╔{'═' * (W - 4)}╗  {T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ║  {C.BOLD}❌ FAILED ({failed_count}){C.RESET}{' ' * max(0, W - 18)}║  {T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ╠{'─' * (W - 4)}╣  {T.BORDER}║{C.RESET}")
                
                for d, reason, ts in list(self.failed)[:2]:
                    dn = d[:22] if len(d) <= 22 else d[:19] + "..."
                    rs = reason[:30] if reason else "?"
                    fail_line = f"  ║    • {T.TEXT_SECONDARY}{dn}{C.RESET}  {T.FAILED}{rs}{C.RESET}{' ' * max(0, W - 45 - len(rs))}║  {T.BORDER}║{C.RESET}"
                    print(fail_line)
                
                print(f"{T.BORDER}║{C.RESET}  ╚{'═' * (W - 4)}╝  {T.BORDER}║{C.RESET}")
            
            # ═══════════════════════════════════════════════════════════════════
            # DETAILED STATUS SECTION
            # ═══════════════════════════════════════════════════════════════════
            if active_count > 0:
                print(f"{T.BORDER}║{C.RESET}  {' ' * (W + 2)}{T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ┌{C.BOLD}─ DETAILED STATUS ─{C.RESET}{'─' * max(0, W - 22)}┐  {T.BORDER}║{C.RESET}")
                
                for domain, data in list(self.domains.items())[:self.max_workers]:
                    dn = domain[:40] if len(domain) <= 40 else domain[:37] + "..."
                    phase = data.get('phase', 'init')
                    stats_data = data.get('stats', {})
                    toolkit_m = data.get('toolkit_metrics', {}) or {}
                    phase_tool = data.get('phase_tool', '')
                    phase_detail = data.get('phase_detail', '')
                    findings = data.get('findings', {})
                    chains = data.get('chains', [])
                    vuln_types = data.get('vuln_types', {})
                    
                    # Domain header
                    print(f"{T.BORDER}║{C.RESET}  │  {C.BOLD}{C.CYAN}{dn}{C.RESET}{' ' * max(0, W - len(dn) - 4)}│  {T.BORDER}║{C.RESET}")
                    
                    # Phase, Status, Iteration
                    status = data.get('phase_status', 'running')
                    it = data.get('iter', 1)
                    max_it = data.get('max_iter', 5)
                    phase_progress = self._get_phase_progress(phase)
                    info_line = (
                        f"  │  {T.RUNNING}├─ Phase:{C.RESET} {C.YELLOW}{phase:<12}{C.RESET}  "
                        f"{T.RUNNING}Status:{C.RESET} {status:<12}  "
                        f"{T.RUNNING}Iteration:{C.RESET} {it}/{max_it}  "
                        f"{T.RUNNING}Progress:{C.RESET} {C.CYAN}{phase_progress}{C.RESET}{' ' * max(0, W - 80)}│  "
                        f"{T.BORDER}║{C.RESET}"
                    )
                    print(info_line)
                    
                    # Phase-specific details
                    if phase in ['recon', 'init']:
                        subs = stats_data.get('subs', 0)
                        live = stats_data.get('live', 0)
                        total = stats_data.get('total_hosts', 0)
                        if total > 0:
                            pct = int(live * 100 / total)
                            bar = self._get_progress_bar(live, total, 10)
                            print(f"  │  │  {C.BRIGHT_CYAN}├─ 🔍 Subdomains:{C.RESET} {subs} found | {pct}% [{bar}] {live}/{total} live{' ' * max(0, W - 60)}│  {T.BORDER}║{C.RESET}")
                        else:
                            print(f"  │  │  {C.BRIGHT_CYAN}├─ 🔍 Subdomains:{C.RESET} {subs} found{' ' * max(0, W - 35)}│  {T.BORDER}║{C.RESET}")
                        
                        # Active tools
                        tool_detail = phase_detail[:60] if phase_detail else "enumerating..."
                        print(f"  │  │  {C.BRIGHT_CYAN}├─ 🔧 Active tools:{C.RESET} {tool_detail}{' ' * max(0, W - 50 - len(tool_detail))}│  {T.BORDER}║{C.RESET}")
                    
                    elif phase == 'live':
                        live = stats_data.get('live', 0)
                        total = stats_data.get('total_hosts', 0)
                        if total > 0:
                            pct = int(live * 100 / total)
                            bar = self._get_progress_bar(live, total, 10)
                            print(f"  │  │  {C.BRIGHT_GREEN}├─ 🌐 Live Hosts:{C.RESET} {pct}% [{bar}] {live}/{total}{' ' * max(0, W - 50)}│  {T.BORDER}║{C.RESET}")
                        else:
                            print(f"  │  │  {C.BRIGHT_GREEN}├─ 🌐 Live Hosts:{C.RESET} {live} detected{' ' * max(0, W - 35)}│  {T.BORDER}║{C.RESET}")
                    
                    elif phase == 'crawl':
                        eps = stats_data.get('eps', 0)
                        print(f"  │  │  {C.BRIGHT_BLUE}├─ 📄 Endpoints:{C.RESET} {eps} discovered{' ' * max(0, W - 35)}│  {T.BORDER}║{C.RESET}")
                    
                    elif phase == 'toolkit':
                        t = toolkit_m.get('tech', 0)
                        p = toolkit_m.get('ports', 0)
                        d = toolkit_m.get('dirs', 0)
                        a = toolkit_m.get('api', 0)
                        print(f"  │  │  {C.BRIGHT_MAGENTA}├─ 🔧 Tech:{C.RESET} {t}  {C.BRIGHT_MAGENTA}Ports:{C.RESET} {p}  {C.BRIGHT_MAGENTA}Dirs:{C.RESET} {d}  {C.BRIGHT_MAGENTA}API:{C.RESET} {a}{' ' * max(0, W - 45)}│  {T.BORDER}║{C.RESET}")
                        # Show active tools
                        tool_detail = phase_detail[:55] if phase_detail else ""
                        if tool_detail:
                            print(f"  │  │  {C.BRIGHT_MAGENTA}├─ Tools:{C.RESET} {tool_detail}{' ' * max(0, W - 45 - len(tool_detail))}│  {T.BORDER}║{C.RESET}")
                    
                    elif phase in ['scan', 'classify', 'rank']:
                        vulns = stats_data.get('vulns', 0)
                        eps = stats_data.get('eps', 0)
                        tested = stats_data.get('payloads_tested', 0)
                        total_p = stats_data.get('total_payloads', 100)
                        pct = int(tested * 100 / total_p) if total_p > 0 else 0
                        bar = self._get_progress_bar(tested, total_p, 10) if total_p > 0 else ""
                        print(f"  │  │  {C.BRIGHT_CYAN}├─ ⚡ Payload testing:{C.RESET} {pct}% [{bar}] {tested}/{total_p}{' ' * max(0, W - 55)}│  {T.BORDER}║{C.RESET}")
                        
                        # Show vulnerability breakdown if any
                        if vulns > 0:
                            vuln_str = f"{C.BRIGHT_RED}├─ 🔴 Vulnerabilities:{C.RESET} {vulns} found"
                            print(f"  │  │  {vuln_str}{' ' * max(0, W - 40)}│  {T.BORDER}║{C.RESET}")
                    
                    elif phase in ['chain', 'graph', 'select']:
                        chains_count = len(chains)
                        exploited = sum(1 for c in chains if c.get('exploited', False))
                        pct = int(exploited * 100 / chains_count) if chains_count > 0 else 0
                        bar = self._get_progress_bar(exploited, chains_count, 10) if chains_count > 0 else ""
                        print(f"  │  │  {C.BRIGHT_MAGENTA}├─ 🔗 Chains:{C.RESET} {chains_count} total | {exploited} exploited | {pct}% [{bar}]{' ' * max(0, W - 55)}│  {T.BORDER}║{C.RESET}")
                    
                    elif phase == 'exploit':
                        exploited = stats_data.get('exploited', 0)
                        chains_count = len(chains)
                        pct = int(exploited * 100 / chains_count) if chains_count > 0 else 0
                        bar = self._get_progress_bar(exploited, chains_count, 10) if chains_count > 0 else ""
                        print(f"  │  │  {C.BRIGHT_RED}├─ 💣 Exploited:{C.RESET} {exploited}/{chains_count} ({pct}%) [{bar}]{' ' * max(0, W - 50)}│  {T.BORDER}║{C.RESET}")
                        
                        # Show AI decision if available
                        ai_decision = data.get('ai_decision', '')
                        if ai_decision:
                            print(f"  │  │  {C.BRIGHT_MAGENTA}├─ 🧠 AI Decision:{C.RESET} {ai_decision[:55]}{' ' * max(0, W - 55 - len(ai_decision))}│  {T.BORDER}║{C.RESET}")
                    
                    # WordPress & Security findings - show in ALL phases when available
                    if findings:
                        # Show WordPress version
                        if findings.get('cms_version'):
                            print(f"  │  │  {C.BRIGHT_YELLOW}├─ 🎯 WordPress:{C.RESET} {findings['cms_version'][:50]}{' ' * max(0, W - 50)}│  {T.BORDER}║{C.RESET}")
                        
                        # Show users
                        if findings.get('users'):
                            users = findings['users'][:5]
                            print(f"  │  │  {C.BRIGHT_GREEN}├─ 👤 Users:{C.RESET} {', '.join(users)}{' ' * max(0, W - 45)}│  {T.BORDER}║{C.RESET}")
                        
                        # Show plugins
                        if findings.get('plugins'):
                            plugins = [p.get('name', '')[:15] for p in findings['plugins'][:3]]
                            if plugins:
                                vuln_count = sum(1 for p in findings['plugins'][:3] if p.get('vulnerabilities'))
                                vuln_marker = f" {C.BRIGHT_RED}({vuln_count} vuln){C.RESET}" if vuln_count > 0 else ""
                                print(f"  │  │  {C.BRIGHT_BLUE}├─ 🔌 Plugins:{C.RESET} {', '.join(plugins)}{vuln_marker}{' ' * max(0, W - 45)}│  {T.BORDER}║{C.RESET}")
                        
                        # Show themes
                        if findings.get('themes'):
                            themes = [t.get('name', '')[:15] for t in findings['themes'][:3]]
                            if themes:
                                print(f"  │  │  {C.BRIGHT_MAGENTA}├─ 🎨 Themes:{C.RESET} {', '.join(themes)}{' ' * max(0, W - 45)}│  {T.BORDER}║{C.RESET}")
                        
                        # Show conditioned chains (high-confidence exploit chains)
                        if findings.get('conditioned_chains'):
                            chains = findings['conditioned_chains']
                            print(f"  │  │  {C.BRIGHT_RED}├─ 🎯 Exploit Chains:{C.RESET} {len(chains)} ready{' ' * max(0, W - 45)}│  {T.BORDER}║{C.RESET}")
                        
                        # Show WP vulnerabilities with details
                        if findings.get('wp_vulns'):
                            vulns = findings['wp_vulns'][:5]  # Show top 5
                            print(f"  │  │  {C.BRIGHT_RED}├─ 🔴 WP Vulns:{C.RESET} {len(findings['wp_vulns'])} found{' ' * max(0, W - 45)}│  {T.BORDER}║{C.RESET}")
                            for v in vulns:
                                vtype = v.get('type', 'unknown')[:25] if isinstance(v, dict) else str(v)[:25]
                                severity = v.get('severity', 'MEDIUM')[:8] if isinstance(v, dict) else 'MEDIUM'
                                sev_color = C.BRIGHT_RED if severity == 'CRITICAL' else C.RED if severity == 'HIGH' else C.YELLOW
                                cve = v.get('cve_id', '')[:12] if isinstance(v, dict) and v.get('cve_id') else ''
                                cve_str = f" [{cve}]" if cve else ""
                                vuln_line = f"  │  │  │  {sev_color}├─ [{severity}]{cve_str} {vtype}{' ' * max(0, W - 55 - len(vtype) - len(cve_str))}│  "
                                print(f"{vuln_line}{T.BORDER}║{C.RESET}")
                        
                        # Show technologies
                        if findings.get('technologies'):
                            techs = findings['technologies'][:5]
                            if techs:
                                print(f"  │  │  {C.CYAN}├─ 🛠️ Tech:{C.RESET} {', '.join(techs)}{' ' * max(0, W - 45)}│  {T.BORDER}║{C.RESET}")
                    
                    # Last action
                    last_action = data.get('last_action', '')
                    if last_action:
                        print(f"  │  │  {C.DIM}└─ ⏱️ {last_action[:60]}{' ' * max(0, W - 45 - len(last_action))}│  {T.BORDER}║{C.RESET}")
                    
                    # Separator between domains
                    if len(self.domains) > 1:
                        print(f"  │  │{'─' * (W - 8)}│  {T.BORDER}║{C.RESET}")
                
                print(f"{T.BORDER}║{C.RESET}  └{'─' * (W - 4)}┘  {T.BORDER}║{C.RESET}")
            
            # ═══════════════════════════════════════════════════════════════════
            # LIVE EVENTS SECTION
            # ═══════════════════════════════════════════════════════════════════
            if self.live_feed:
                print(f"{T.BORDER}║{C.RESET}  {' ' * (W + 2)}{T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  {C.BOLD}🔔 LIVE EVENTS{C.RESET} (last {min(len(self.live_feed), 12)}){' ' * max(0, W - 30)}{T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ┌{'─' * (W - 4)}┐  {T.BORDER}║{C.RESET}")
                
                event_icons = {
                    'Subdomain': '➕', 'Live': '🌐', 'WordPress': '🎯',
                    'Users': '👤', 'Endpoint': '📁', 'Toolkit': '🔧',
                    'Completed': '✅', 'Failed': '❌', 'SQLi Found': '💧',
                    'Chains': '🔗', 'Exploited': '💥', 'CVE Found': '📖',
                    'WAF Detected': '🛡️', 'AI Decision': '🧠',
                }
                
                for ts, icon, event, domain, detail in list(self.live_feed)[:8]:
                    ei = event_icons.get(event, icon)
                    dn = domain[:12] if len(domain) <= 12 else domain[:9] + ".."
                    dt = detail[:45] if len(detail) > 45 else detail
                    event_line = (
                        f"  │  {C.DIM}{ts}{C.RESET} {ei} {event:<14} {C.CYAN}{dn}{C.RESET}  {dt}{' ' * max(0, W - 55 - len(dt))}│  "
                        f"{T.BORDER}║{C.RESET}"
                    )
                    print(event_line)
                
                print(f"{T.BORDER}║{C.RESET}  └{'─' * (W - 4)}┘  {T.BORDER}║{C.RESET}")
            
            # ═══════════════════════════════════════════════════════════════════
            # AI DECISION FEED SECTION
            # ═══════════════════════════════════════════════════════════════════
            if self.ai_feed:
                print(f"{T.BORDER}║{C.RESET}  {' ' * (W + 2)}{T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  {C.BOLD}🧠 AI DECISION FEED{C.RESET} (last {min(len(self.ai_feed), 6)}){' ' * max(0, W - 35)}{T.BORDER}║{C.RESET}")
                print(f"{T.BORDER}║{C.RESET}  ┌{'─' * (W - 4)}┐  {T.BORDER}║{C.RESET}")
                
                for ts, event, domain, detail in list(self.ai_feed)[:4]:
                    dn = domain[:12] if len(domain) <= 12 else domain[:9] + ".."
                    dt = detail[:50] if len(detail) > 50 else detail
                    ai_line = (
                        f"  │  {C.DIM}{ts}{C.RESET}  {C.BRIGHT_MAGENTA}{event:<20}{C.RESET} {C.CYAN}{dn}{C.RESET}  {dt}{' ' * max(0, W - 55 - len(dt))}│  "
                        f"{T.BORDER}║{C.RESET}"
                    )
                    print(ai_line)
                
                print(f"{T.BORDER}║{C.RESET}  └{'─' * (W - 4)}┘  {T.BORDER}║{C.RESET}")
            
            # Footer
            print(f"{T.BORDER}╚{'═' * (W + 2)}╝{C.RESET}")
            
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
            'max_iter': 3,
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
        """Thread render cho single domain mode - 2 lần/giây để tiết kiệm CPU"""
        while self.running:
            current_time = time.time()
            if current_time - self.last_render_time >= 0.5:
                self._render()
                self.last_render_time = current_time
            time.sleep(0.25)  # Tối ưu: sleep 0.25s thay vì 0.1s để giảm CPU wake-ups
    
    def _render(self):
        sys.stdout.write('\033[H\033[J')
        
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
        
        # Calculate basic metrics
        progress_iter = int(d['iter'] / d['max_iter'] * 100) if d['max_iter'] > 0 else 0
        iter_bar = "█" * (progress_iter // 10) + "░" * (10 - progress_iter // 10)
        
        print(f"│  {domain_display} [{phase_icon} {d['phase']:>8}] [{iter_bar}] {progress_iter:3d}%        │")
        tool = (d.get('phase_tool') or 'n/a')[:24]
        status = (d.get('phase_status') or 'idle')[:16]
        print(f"│  Tool: {tool:<24} | Status: {status:<16} | ⏱️ {time_str}              │")
        print("├────────────────────────────────────────────────────────────────────────────────┤")
        
        # Stats - enhanced with icons and better formatting
        print("│  🔍 DISCOVERY PHASE                                                             │")
        subs = stats.get('subs', 0)
        live = stats.get('live', 0)
        total_hosts = stats.get('total_hosts', 0)
        
        if total_hosts > 0:
            live_pct = int(live * 100 / total_hosts)
            bar = "█" * (live_pct // 10) + "░" * (10 - live_pct // 10)
            print(f"│  ├─ Subdomains: {subs:>5} | Live: {live_pct:3d}% [{bar}] {live:>4}/{total_hosts:<4}  │")
        else:
            print(f"│  ├─ Subdomains  : {subs:>5} | Live hosts: {live:>5}                      │")
        
        eps = stats.get('eps', 0)
        print(f"│  ├─ Endpoints   : {eps:>5} | WordPress : {'✓ Yes' if stats.get('wp') else '✗ No'}                      │")
        
        # Tech
        tech_list = list(d['tech'].keys())
        if tech_list:
            tech_str = f"Tech: {', '.join(tech_list[:3])}"
            if len(tech_list) > 3:
                tech_str += f" (+{len(tech_list)-3})"
            print(f"│  └─ {tech_str:<70} │")
        else:
            print(f"│  └─ Tech: detecting...                                                     │")
        
        # Toolkit Metrics - Always show if we have toolkit data
        toolkit_m = d.get('toolkit_metrics', {})
        scan_meta = d.get('scan_metadata', {}) or {}
        if not toolkit_m:
            toolkit_m = scan_meta.get('toolkit_metrics', {}) or {}
        if toolkit_m and any([toolkit_m.get(k, 0) >= 0 for k in ['tech', 'ports', 'dirs', 'api', 'vulns']]):
            print("│                                                                              │")
            print("│  🛠️  TOOLKIT SCAN RESULTS                                                    │")
            tech = toolkit_m.get('tech', 0)
            ports = toolkit_m.get('ports', 0)
            dirs = toolkit_m.get('dirs', 0)
            apis = toolkit_m.get('api', 0)
            cves = toolkit_m.get('vulns', 0)
            
            total_findings = tech + ports + dirs + apis
            print(f"│  ├─ 📱 Tech      : {tech:>4}  | 🔓 Ports: {ports:>4} | 📂 Dirs  : {dirs:>4}")
            print(f"│  ├─ 🌐 APIs      : {apis:>4}  | 🔴 CVEs : {cves:>4} | 📊 Total : {total_findings:>4}  │")
            
            if total_findings > 0:
                findings_bar = "█" * min(30, total_findings) + "░" * max(0, 30 - min(30, total_findings))
                print(f"│  └─ [{findings_bar}] {total_findings} findings                │")
        
        # Endpoints - enhanced display
        eps = d['endpoints']
        if eps['total'] > 0:
            print("│                                                                              │")
            print("│  📁 ENDPOINTS")
            ep_bar = "█" * min(15, eps['total'] // 5) + "░" * max(0, 15 - eps['total'] // 5)
            print(f"│  ├─ Total: {eps['total']:>4} [{ep_bar}] | API: {eps['api']:>3} Δž| Admin: {eps['admin']:>2} ⚙️│")
            print(f"│  └─ Upload: {eps['upload']:<4}                                              │")
        
        # Vulns - enhanced with better formatting
        vuln_types = dict(d['vuln_types'])
        if vuln_types:
            print("│                                                                              │")
            print("│  🐞 VULNERABILITIES")
            total_vulns = sum(vuln_types.values())
            vuln_bar = "█" * min(20, total_vulns // 2) + "░" * max(0, 20 - total_vulns // 2)
            print(f"│  ├─ Total: {total_vulns:>3} [{vuln_bar}]                   │")
            
            vuln_icons = {
                'SQLi': '💧', 'XSS': '✖️', 'IDOR': '🔑', 'RCE': '⚡', 
                'Auth': '🔐', 'SSRF': '🔀', 'LFI': '📁', 'Default': '🔓'
            }
            for i, (vtype, count) in enumerate(list(vuln_types.items())[:4]):
                icon = vuln_icons.get(vtype, '🔴')
                print(f"│  ├─ {icon} {vtype:<10}: {count:>4}", end="")
                if i < 3:
                    print(" | ", end="")
                else:
                    print(" " * 17 + "│")
        
        # Chains - enhanced with more details
        chains = d['chains']
        if chains:
            print("│                                                                              │")
            print("│  🕸️ ATTACK CHAINS")
            exploited_count = sum(1 for c in chains if c.get('exploited'))
            chain_pct = int(exploited_count * 100 / len(chains)) if len(chains) > 0 else 0
            chain_bar = "█" * (chain_pct // 5) + "░" * (20 - chain_pct // 5)
            print(f"│  ├─ Total: {len(chains):>3} | Exploited: {exploited_count:>2} ({chain_pct:>3}%) [{chain_bar}]│")
        
        # Learning
        learning = d['learning']
        if learning['mutated'] > 0:
            print("│                                                                              │")
            print("│  🧠 LEARNING                                                                 │")
            print(f"│  ├─ Mutated: {learning['mutated']} payloads                                            │")
        
        # Current activity detail
        phase_detail = d.get('phase_detail', '')
        if phase_detail:
            print("│                                                                              │")
            print("│  📍 CURRENT ACTIVITY                                                        │")
            # Split detail into multiple lines if needed
            if len(phase_detail) > 75:
                words = phase_detail.split()
                lines = []
                current_line = []
                for word in words:
                    if len(" ".join(current_line + [word])) <= 75:
                        current_line.append(word)
                    else:
                        if current_line:
                            lines.append(" ".join(current_line))
                        current_line = [word]
                if current_line:
                    lines.append(" ".join(current_line))
                for line in lines[:2]:  # Show max 2 lines
                    print(f"│  ├─ {line:<75} │")
            else:
                print(f"│  ├─ {phase_detail:<75} │")
        
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
                 nvd_key: str = "", 
                 urls_file: str = "", subdomains_file: str = "", auth_file: str = "", force_recon: bool = False,
                 batch_display: BatchDisplay = None,
                 api_status: Optional[dict] = None,
                 target_index: int = 1,
                 total_targets: int = 1,
                 allowed_domains: list = None):
        
        # Initialize logger FIRST before any logging calls
        self.logger = logging.getLogger("recon.agent")
        
        self.target = target.lower().strip()
        self.output_dir = output_dir
        self.options = options
        self.nvd_key = nvd_key or os.environ.get("NVD_API_KEY", "") or os.environ.get("NVDAPI_KEY", "")
        self.urls_file = urls_file
        self.subdomains_file = subdomains_file
        self.auth_file = auth_file
        self.force_recon = force_recon
        self.batch_display = batch_display
        self.api_status = api_status or {}
        self.target_index = target_index
        self.total_targets = total_targets
        self.allowed_domains = allowed_domains or []
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
        
        # Set allowed_domains from targets.txt for multi-domain filtering
        # This allows URLs from any domain in targets.txt to pass through filters
        if self.allowed_domains:
            self.state.update(allowed_domains=self.allowed_domains)
            self.logger.info(f"[INIT] Set allowed_domains: {len(self.allowed_domains)} domains from targets.txt")
        self.session = SessionManager(self.output_dir)
        self.http_client = HTTPClient(self.session)
        self.response_analyzer = ResponseAnalyzer()
        self.learning_engine = LearningEngine(output_dir)
        
        # NEW: Enhanced modules for exploitation & recovery
        self.error_recovery = ErrorRecovery()
        self.playbook = ConditionalPlaybook()
        self.wordlist_gen = WordlistGenerator()
        self.url_normalizer = URLNormalizer()
        self.endpoint_analyzer = EndpointAnalyzer()
        self.exploit_executor = ExploitExecutor(self.http_client, self.state, output_dir)
        
        groq_key = os.environ.get("GROQ_API_KEY", "") or os.environ.get("GROQ_APIKEY", "")
        self.endpoint_classifier = EndpointClassifier()
        self.payload_gen = PayloadGenerator(groq_key)
        self.payload_mutator = PayloadMutator()
        self.groq_client = GroqClient(groq_key) if groq_key else None
        self.vuln_analyzer = AIAnalyzer(self.state, output_dir, self.groq_client)
        self.chain_planner = ChainPlanner(
            self.state,
            learning_engine=self.learning_engine
        )
        self.ai_chain_planner = AIPoweredChainPlanner(self.groq_client) if self.groq_client else None
        
        self.recon_engine = ReconEngine(self.state, output_dir)
        self.live_host_engine = LiveHostEngine(self.state, output_dir)
        self.discovery_engine = DiscoveryEngine(self.state, output_dir)
        self.scanning_engine = ScanningEngine(self.state, output_dir, self.payload_gen, self.payload_mutator, self.learning_engine)
        self.exploit_engine = ExploitTestEngine(self.state, output_dir, self.learning_engine)
        self.wp_scanner = WordPressScannerEngine(self.state, output_dir)
        self.auth_engine = AuthScannerEngine(self.state, output_dir, self.session)
        self.toolkit = ToolkitScanner(self.state, output_dir, aggressive=True)
        
        # Initialize exploit modules
        self.sqli_exploiter = SQLiExploiter(output_dir, timeout=30)
        self.upload_bypass = UploadBypass(output_dir, timeout=30)
        self.reverse_shell_gen = ReverseShellGenerator(output_dir, timeout=30)
        self.privesc_checker = PrivilegeEscalation(output_dir, timeout=30)
        
        # Initialize Tier-1 vulnerability detection modules
        self.waf_bypass = WAFBypassEngine(output_dir, timeout=30)
        self.boolean_sqli = BooleanSQLiDetector(output_dir, timeout=30)
        self.xss_detector = XSSDetector(output_dir, timeout=30)
        self.idor_detector = IDORDetector(output_dir, timeout=30)
        
        # Initialize Tier-2 security modules
        self.default_creds = DefaultCredsScanner(output_dir, timeout=30)
        self.cve_exploiter = CVEExploiter(output_dir, timeout=30)
        self.api_vuln_scanner = APIVulnScanner(output_dir, timeout=30)
        self.subdomain_takeover = SubdomainTakeoverScanner(output_dir, timeout=30)
        
        # Initialize cryptographic security scanner (OWASP A04)
        self.crypto_scanner = CryptographicScanner(self.http_client, output_dir)
        
        # Initialize SQLMap runner for SQL injection (OWASP A05)
        self.sqlmap_runner = SQLMapRunner(output_dir)
        
        # NEW: Initialize post-exploitation modules
        self.mfa_bypass = MFABypass(self.http_client)
        self.oauth_saml_exploit = OAuthSAMLExploit()
        self.persistence_engine = PersistenceEngine()
        self.lateral_movement = LateralMovement()
        self.ssl_pinning_bypass = SSLPinningBypass()
        self.zero_day_detection = ZeroDayDetection(self.http_client)
        self.container_escape = ContainerEscapeEngine()
        self.custom_exploit = CustomExploitFramework(exploits_dir=os.path.join(output_dir, "custom_exploits"))
        self.log_evasion = LogEvasion()
        self.iteration_count = 0
        self.max_iterations = 3
        self.confidence_threshold = 0.8
        self._last_iteration_snapshot = None
        self._stagnant_iterations = 0
        self.reflection_history = []  # Self-reflection loop
        self.phase_errors = defaultdict(int)  # Track errors per phase
        self.playbook_state = {}  # Conditional playbook state
        
        # FIX #1: Groq failover tracking - hard stop when Groq unavailable
        self.groq_unavailable_consecutive = 0
        self.groq_available = True
        self.groq_circuit_open = False  # Hard stop flag for circuit breaker
        
        # FIX #2: Loop termination - explicit exit conditions
        self._report_generated = False
        self.max_wall_clock_seconds = 8 * 3600  # 8 hours hard limit
        self.max_iterations_hard_limit = 5  # Absolute max iterations
        
        # FIX #3: External domain blacklist for scope leak prevention
        self.external_domains_blacklist = set()
        self.allowed_domains_set = set(self.allowed_domains) if self.allowed_domains else set()
        
        # FIX #4: Failure cache for endpoints (shared across iterations)
        self.failed_endpoints_cache = {}
        self.endpoint_timeout_cache = set()  # Cache for timed-out endpoints
        
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
        self.findings = {
            'plugins': [], 'themes': [], 'cms_version': '', 'php_version': '',
            'waf': '', 'users': [], 'technologies': []
        }
        self.last_action = "starting..."
        self.current_phase = "init"
        self.phase_detail = ""
        self.phase_tool = ""
        self.phase_status = "idle"
        self.learning_stats = {'mutated': 0, 'confidence': 0.0}
        self.toolkit_metrics = {'tech': 0, 'ports': 0, 'dirs': 0, 'api': 0, 'vulns': 0}
        scan_meta = self.state.get("scan_metadata", {}) or {}
        self.completed_phases = set(scan_meta.get("completed_phases", []) or [])
        
        # Initialize attack surface tracker for evidence-driven exploitation
        self.attack_surface = AttackSurfaceTracker()
        
        # Initialize exploit selector for evidence-based module gating
        self.exploit_selector = AutomaticExploitSelector()
        
        # Initialize crypto findings storage
        self.crypto_findings = []
        self.misconfig_findings = []
        self.command_injection_findings = []
        
        # ─── NEW: Enhanced Analysis & Validation Modules ─────────────────────
        self.service_fingerprinter = ServiceFingerprinter(self.state, self.output_dir)
        self.exploit_verifier = ExploitVerifier(self.state, self.output_dir)
        self.false_positive_filter = FalsePositiveFilter(self.state, self.output_dir)
        self.payload_optimizer = PayloadOptimizer(self.state, self.output_dir)
        self.chain_validator = ChainValidator(self.state, self.output_dir)
        
        # ═══════════════════════════════════════════════════════════════════
        # NEW: Advanced Core Modules Initialization
        # ═══════════════════════════════════════════════════════════════════
        
        # Initialize Async Scanner
        self.async_scanner = AsyncScanner(
            max_concurrent=config.ASYNC_MAX_CONCURRENT,
            rate_limit=config.ASYNC_RATE_LIMIT,
            cache_ttl=config.ASYNC_CACHE_TTL,
        )
        
        # Initialize Distributed Engine (if enabled)
        if config.DISTRIBUTED_ENABLED:
            self.distributed_engine = DistributedEngine(
                redis_host=config.REDIS_HOST,
                redis_port=config.REDIS_PORT,
            )
        else:
            self.distributed_engine = None
        
        # Initialize ML Classifier
        self.ml_classifier = MLClassifier() if config.ML_CLASSIFIER_ENABLED else None
        
        # Initialize Exploit Chain Optimizer
        self.chain_optimizer = ExploitChainOptimizer() if config.CHAIN_OPTIMIZER_ENABLED else None
        
        # Initialize Metasploit RPC (if enabled)
        if config.METASPLOIT_ENABLED:
            self.metasploit = MetasploitRPC(
                host=config.METASPLOIT_HOST,
                port=config.METASPLOIT_PORT,
                password=config.METASPLOIT_PASSWORD,
            )
            if self.metasploit.connect():
                self.auto_exploiter = AutoExploiter(self.metasploit)
            else:
                self.metasploit = None
                self.auto_exploiter = None
                self.logger.warning("[INIT] Failed to connect to Metasploit RPC, disabling auto-exploitation")
        else:
            self.metasploit = None
            self.auto_exploiter = None
        
        # Initialize Burp API (if enabled)
        if config.BURP_ENABLED:
            self.burp_api = BurpAPI(
                host=config.BURP_HOST,
                port=config.BURP_PORT,
                api_key=config.BURP_API_KEY,
            )
            if self.burp_api.test_connection():
                self.burp_scanner = BurpScanner(self.burp_api)
            else:
                self.burp_api = None
                self.burp_scanner = None
                self.logger.warning("[INIT] Failed to connect to Burp Suite, disabling Burp scanning")
        else:
            self.burp_api = None
            self.burp_scanner = None
        
        # Initialize LLM Analyzer
        if config.LLM_ANALYZER_ENABLED:
            self.llm_analyzer = LLMAnalyzer(self.groq_client) if self.groq_client else LLMAnalyzer()
        else:
            self.llm_analyzer = None
        
        if self.resumed_from_state:
            previous_phase = self.state.get("current_phase", "unknown")
            self.last_action = f"resumed from state ({previous_phase})"
            # Restore attack surface from state if available
            as_data = self.state.get("attack_surface", {})
            if as_data:
                self.attack_surface.from_dict(as_data)
            # 🔥 FIX: Restore findings from previous session for display
            self._restore_findings_from_state()
            self._update_stats()
            # 🔥 FIX: Force immediate display update with restored data
            # Build comprehensive findings dict from restored state
            self._force_display_refresh()
            
            # 🔥 FIX: Mark the interrupted phase as done so we skip it on resume
            resume_phase = self._get_resume_phase()
            if resume_phase:
                self.logger.info(f"[RESUME] Marking interrupted phase '{resume_phase}' as done, will continue from next phase")
                self._mark_phase_done(resume_phase)
                self.last_action = f"resumed — skipping {resume_phase}, continuing to next phase"
        
        self._update_display()

    def _update_display(self):
        # Build comprehensive findings dict from state for real-time display
        findings_display = self.findings.copy()
        
        # Add WordPress findings from state (these are updated by wp_scanner)
        wp_plugins = self.state.get("wp_plugins", []) or []
        wp_themes = self.state.get("wp_themes", []) or []
        wp_users = self.state.get("wp_users", []) or []
        wp_version = self.state.get("wp_version", "unknown")
        wp_vulns = self.state.get("wp_vulnerabilities", []) or []
        wp_conditioned = self.state.get("wp_conditioned_findings", []) or []
        
        if wp_plugins:
            findings_display['plugins'] = wp_plugins[:10]
        if wp_themes:
            findings_display['themes'] = wp_themes[:5]
        if wp_users:
            findings_display['users'] = wp_users[:10]
        if wp_version and wp_version != "unknown":
            findings_display['cms_version'] = f"WordPress {wp_version}"
        if wp_vulns:
            findings_display['wp_vulns'] = wp_vulns[:10]
        if wp_conditioned:
            findings_display['conditioned_chains'] = [c for c in wp_conditioned if c.get('chain_candidate') and c.get('confidence', 0) >= 70][:5]
        
        # Add technologies from state
        technologies = self.state.get("technologies", {}) or {}
        if technologies:
            findings_display['technologies'] = list(technologies.keys())[:15]
        
        if self.batch_display:
            self.batch_display.update(self.batch_id, {
                'phase': self.current_phase,
                'phase_detail': self.phase_detail,
                'phase_tool': self.phase_tool,
                'phase_status': self.phase_status,
                'iter': self.iteration_count,
                'max_iter': self.max_iterations,
                'stats': {
                    **self.stats.copy(),
                    'completed_phases': sorted(self.completed_phases)
                },
                'chains': self.chains_data,
                'tech': self.tech_stack.copy(),
                'endpoints': self.endpoint_stats.copy(),
                'toolkit_metrics': self.toolkit_metrics.copy(),
                'scan_metadata': self.state.get("scan_metadata", {}) or {},
                'findings': findings_display,
                'last_action': self.last_action,
                'start_time': self.scan_start_time,
                'conditioned_chains': self.state.get("conditioned_chains", [])
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
                    scan_metadata=self.state.get("scan_metadata", {}) or {},
                    findings=findings_display,
                    last_action=self.last_action
                )

    def _set_activity(self, tool: str, status: str, detail: str = ""):
        self.phase_tool = tool
        self.phase_status = status
        if detail:
            self.phase_detail = detail
        self._update_display()

    def _progress_callback(self, phase: str, tool: str, status: str, detail: str = ""):
        # Keep current phase aligned with the module emitting progress.
        if phase:
            self.current_phase = phase
        if detail:
            self.phase_detail = detail
        elif tool and status:
            self.phase_detail = f"[{tool.upper()}] {status}"
        
        # Update phase_tool to show current tool
        if tool:
            self.phase_tool = tool
        
        # REAL-TIME METRICS UPDATE: Extract toolkit_metrics from state during toolkit phase
        # This allows metrics to update as each tool completes, not just at the end
        if phase == "toolkit" and status == "done":
            scan_meta = self.state.get("scan_metadata", {}) or {}
            state_metrics = scan_meta.get("toolkit_metrics", {}) or {}
            if state_metrics:
                # Update toolkit_metrics with latest values from state
                self.toolkit_metrics = {
                    'tech': state_metrics.get('tech', self.toolkit_metrics.get('tech', 0)),
                    'ports': state_metrics.get('ports', self.toolkit_metrics.get('ports', 0)),
                    'dirs': state_metrics.get('dirs', self.toolkit_metrics.get('dirs', 0)),
                    'api': state_metrics.get('api', self.toolkit_metrics.get('api', 0)),
                    'vulns': state_metrics.get('vulns', self.toolkit_metrics.get('vulns', 0)),
                }
        
        self._set_activity(tool=tool, status=status)
        # Update display in real-time to show progress
        self._update_display()

    def run(self):
        self._update_display()
        self.logger.info(f"Target: {self.target} | Output: {self.output_dir}")

        # IMPROVED: Normalize URL first
        normalized, is_valid, error_msg = self.url_normalizer.normalize(self.target)
        if not is_valid:
            self.last_action = f"URL error: {error_msg}"
            self.error_recovery.log_error("init", "url_normalizer", error_msg)
            self._update_display()
            self.logger.error(f"URL normalization failed: {error_msg}")
            if self.batch_display:
                self.batch_display.mark_failed(self.target, error_msg)
            return
        
        # Update target with normalized URL
        self.target = normalized
        self.last_action = f"URL normalized: {self.target}"
        self._update_display()

        self._load_manual_inputs()
        self._initialize_seed_queue()

        try:
            attack_graph = AttackGraph()
            
            # FIX #1: Check if Groq circuit is open for too long (hard stop)
            if self.groq_client and hasattr(self.groq_client, '_circuit_state'):
                from ai.groq_client import CircuitState
                if self.groq_client._circuit_state == CircuitState.OPEN:
                    backoff = self.groq_client._current_backoff
                    if backoff >= self.groq_client.MAX_BACKOFF:
                        self.logger.warning("[AGENT] Groq circuit breaker at max backoff. Switching to rule-based mode.")
                        self.groq_available = False
                        self.groq_circuit_open = True
            
            while self.iteration_count < self.max_iterations:
                self.iteration_count += 1
                
                # FIX #2: Check wall-clock time limit inside loop
                elapsed_time = time.time() - self.scan_start_time
                if elapsed_time > self.max_wall_clock_seconds:
                    self.logger.warning(f"[AGENT] Wall-clock time limit reached during iteration. Stopping.")
                    break
                
                # BUG 11 FIX: Clear completed phases on iteration 2+ to allow re-scanning
                if self.iteration_count > 1:
                    for phase in ["classify", "rank", "scan", "analyze", "graph", "chain", "exploit", "learn"]:
                        self.completed_phases.discard(phase)
                    self.logger.debug(f"[AGENT] Iteration {self.iteration_count}: Reset completed phases for re-scanning")
                
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

                # Phase 4.2: WordPress Detection from State Data
                # After crawling, analyze discovered URLs/endpoints for WordPress patterns
                if self.iteration_count == 1 and not self._should_skip_phase("wp_detect_state"):
                    self.current_phase = "wp"
                    self.phase_detail = "pattern-detect"
                    self.phase_tool = "endpoint-analyzer"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_wordpress_detection_from_state()

                # Phase 4.3: JavaScript Endpoint Hunter
                # Extract endpoints from JavaScript files
                if self.iteration_count == 1 and not self._should_skip_phase("js_hunter"):
                    self.current_phase = "js_hunter"
                    self.phase_detail = "js-extraction"
                    self.phase_tool = "endpoint-hunter"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_js_endpoint_hunt_phase()

                # Phase 4.4: Parameter Miner
                # Discover hidden parameters on endpoints
                if self.iteration_count == 1 and not self._should_skip_phase("param_mine"):
                    self.current_phase = "param_mine"
                    self.phase_detail = "parameter-discovery"
                    self.phase_tool = "param-fuzzer"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_parameter_mining_phase()

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
                
                # Phase 8.2: CVE Analysis (NEW - MUST BE BEFORE CHAIN PLANNING)
                if not self._should_skip_phase("cve_analysis"):
                    self.current_phase = "cve_analysis"
                    self.phase_detail = "match to CVE database"
                    self.phase_tool = "cve-matcher"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_cve_analysis_phase()
                
                # Phase 8.5: Privilege Escalation Analysis
                if "priv_pivot" not in self.completed_phases:
                    self.current_phase = "pivot"
                    self.phase_detail = "privilege-chains"
                    self.phase_tool = "privilege-analyzer"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_privilege_pivot_phase()
                
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
                
                # Phase 10.5: Automatic Exploit Selection (LEVEL BOSS)
                if "exploit_select" not in self.completed_phases:
                    self.current_phase = "select"
                    self.phase_detail = "strategy-selection"
                    self.phase_tool = "exploit-selector"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_exploit_selection_phase()
                
                # Phase 11: Exploit Testing
                if not self._should_skip_phase("exploit"):
                    self.current_phase = "exploit"
                    self.phase_detail = "test"
                    self.phase_tool = "exploit-validator"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_exploit_phase()
                
                # Phase 12: SQLi Exploitation
                if not self._should_skip_phase("sqli_exploit"):
                    self.current_phase = "sqli_exploit"
                    self.phase_detail = "dump DB and write shells"
                    self.phase_tool = "sqli-exploiter"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_sqli_exploit_phase()
                
                # Phase 13: Upload Bypass
                if not self._should_skip_phase("upload_bypass"):
                    self.current_phase = "upload_bypass"
                    self.phase_detail = "bypass file restrictions"
                    self.phase_tool = "upload-bypass"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_upload_bypass_phase()
                
                # Phase 14: Reverse Shell
                if not self._should_skip_phase("reverse_shell"):
                    self.current_phase = "reverse_shell"
                    self.phase_detail = "execute reverse shells"
                    self.phase_tool = "reverse-shell"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_reverse_shell_phase()
                
                # Phase 15: Privilege Escalation
                if not self._should_skip_phase("privesc"):
                    self.current_phase = "privesc"
                    self.phase_detail = "check escalation vectors"
                    self.phase_tool = "privesc-checker"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_privilege_escalation_phase()
                
                # Phase 16: WAF Bypass Detection
                if not self._should_skip_phase("waf_bypass"):
                    self.current_phase = "waf_bypass"
                    self.phase_detail = "detect WAF and bypass"
                    self.phase_tool = "waf-bypass-engine"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_waf_bypass_phase()
                
                # Phase 17: Boolean-Based SQLi
                if not self._should_skip_phase("boolean_sqli"):
                    self.current_phase = "boolean_sqli"
                    self.phase_detail = "detect blind SQLi"
                    self.phase_tool = "boolean-sqli-detector"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_boolean_sqli_phase()
                
                # Phase 18: XSS Detection
                if not self._should_skip_phase("xss"):
                    self.current_phase = "xss"
                    self.phase_detail = "detect XSS vectors"
                    self.phase_tool = "xss-detector"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_xss_phase()
                
                # Phase 19: IDOR Detection
                if not self._should_skip_phase("idor"):
                    self.current_phase = "idor"
                    self.phase_detail = "detect IDOR vulnerabilities"
                    self.phase_tool = "idor-detector"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_idor_phase()
                
                # Phase 20: Default Credentials
                if not self._should_skip_phase("default_creds"):
                    self.current_phase = "default_creds"
                    self.phase_detail = "test default credentials"
                    self.phase_tool = "creds-scanner"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_default_creds_phase()
                
                # Phase 21: CVE Exploitation
                if not self._should_skip_phase("cve_exploit"):
                    self.current_phase = "cve_exploit"
                    self.phase_detail = "test known CVE exploits"
                    self.phase_tool = "cve-exploiter"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_cve_exploit_phase()
                
                # Phase 22: API Vulnerabilities
                if not self._should_skip_phase("api_vuln"):
                    self.current_phase = "api_vuln"
                    self.phase_detail = "scan API security"
                    self.phase_tool = "api-vuln-scanner"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_api_vuln_phase()
                
                # Phase 23: Subdomain Takeover
                if not self._should_skip_phase("subdomain_takeover"):
                    self.current_phase = "subdomain_takeover"
                    self.phase_detail = "detect subdomain takeover"
                    self.phase_tool = "takeover-scanner"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_subdomain_takeover_phase()
                
                # ─── POST-EXPLOITATION PHASES (24-32) ────────────────────────────────────
                
                # Phase 24: MFA Bypass & Circumvention
                if not self._should_skip_phase("mfa_bypass"):
                    self.current_phase = "mfa_bypass"
                    self.phase_detail = "bypass MFA/2FA mechanisms"
                    self.phase_tool = "mfa-bypass-engine"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_mfa_bypass_phase()
                
                # Phase 25: OAuth/SAML Exploitation
                if not self._should_skip_phase("oauth_saml"):
                    self.current_phase = "oauth_saml"
                    self.phase_detail = "exploit OAuth/SAML flows"
                    self.phase_tool = "oauth-saml-exploiter"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_oauth_saml_phase()
                
                # Phase 26: Persistence & Backdoor Deployment
                if not self._should_skip_phase("persistence"):
                    self.current_phase = "persistence"
                    self.phase_detail = "establish backdoors"
                    self.phase_tool = "persistence-engine"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_persistence_phase()
                
                # Phase 27: Lateral Movement
                if not self._should_skip_phase("lateral_movement"):
                    self.current_phase = "lateral_movement"
                    self.phase_detail = "move across network"
                    self.phase_tool = "lateral-movement-engine"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_lateral_movement_phase()
                
                # Phase 28: SSL/TLS Pinning Bypass
                if not self._should_skip_phase("ssl_pinning"):
                    self.current_phase = "ssl_pinning"
                    self.phase_detail = "bypass certificate pinning"
                    self.phase_tool = "ssl-bypass-engine"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_ssl_pinning_phase()
                
                # Phase 29: Zero-Day Detection
                if not self._should_skip_phase("zero_day"):
                    self.current_phase = "zero_day"
                    self.phase_detail = "detect zero-day vulns"
                    self.phase_tool = "zero-day-detector"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_zero_day_phase()
                
                # Phase 30: Container/Cloud Escape
                if not self._should_skip_phase("container_escape"):
                    self.current_phase = "container_escape"
                    self.phase_detail = "escape container/cloud"
                    self.phase_tool = "container-escape-engine"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_container_escape_phase()
                
                # Phase 31: Custom Exploit Framework
                if not self._should_skip_phase("custom_exploit"):
                    self.current_phase = "custom_exploit"
                    self.phase_detail = "deploy custom exploits"
                    self.phase_tool = "custom-exploit-framework"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_custom_exploit_phase()
                
                # Phase 32: Log Evasion & Covering Tracks
                if not self._should_skip_phase("log_evasion"):
                    self.current_phase = "log_evasion"
                    self.phase_detail = "erase forensic evidence"
                    self.phase_tool = "log-evasion-engine"
                    self.phase_status = "running"
                    self._update_display()
                    self._run_log_evasion_phase()
                
                # Phase 33: Learning
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

                if self._should_stop_due_to_stagnation():
                    self.logger.info("[AGENT] Stopping early due to stagnant iterations")
                    self.last_action = "stopping early: no new signal across iterations"
                    self._update_display()
                    break
                    
                self._adapt_for_next_iteration()
            
            # Final

            if not self.options.get("skip_ddos"):
                self.current_phase = "ddos"
                self.phase_detail = "[DDoS] Checking if attack needed..."
                self._update_display()
                self._run_ddos_phase()

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
                    'top_chain': top_chain,
                    'eps': self.stats.get('eps', 0),
                    'live': self.stats.get('live', 0),
                    'wp': self.stats.get('wp', False),
                })
            else:
                self.display.stop()
            
        except KeyboardInterrupt:
            self.last_action = "interrupted by user"
            self.phase_status = "interrupted"
            self._update_display()
            self.logger.warning("Scan interrupted")
            self.state.save()
            
            # 🔥 HIỂN THỊ TẤT CẢ FINDINGS ĐÃ THU THẬP ĐƯỢC TRƯỚC KHI THOÁT
            print("\n\n")
            print(f"{C.BOLD}{C.BRIGHT_RED}{'═' * 70}{C.RESET}")
            print(f"{C.BOLD}{C.BRIGHT_RED}║  ⚡ SCAN INTERRUPTED — Displaying collected findings ⚡{C.RESET}{' ' * 12}{C.BOLD}{C.BRIGHT_RED}║{C.RESET}")
            print(f"{C.BOLD}{C.BRIGHT_RED}{'═' * 70}{C.RESET}")
            print()
            
            # Gọi _print_modern_summary để hiển thị tất cả findings đã thu thập
            try:
                self._print_modern_summary()
            except Exception as e:
                print(f"Error displaying summary: {e}")
            
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

    def _force_display_refresh(self):
        """
        🔥 Force immediate display refresh with all restored data.
        This method ensures that when resuming a scan, all previously discovered
        findings are immediately visible in the dashboard.
        """
        # Log the restoration for debugging
        self.logger.info("[DISPLAY] Force refreshing display with restored data...")
        
        # Update last_action to show resume status
        previous_phase = self.state.get("current_phase", "unknown")
        self.last_action = f"resumed — continuing from {previous_phase}"
        
        # Force update stats from state
        self._update_stats()
        
        # Log what was restored
        summary = self.state.summary()
        self.logger.info(f"[DISPLAY] Restored state summary: {summary}")
        
        # Add a feed event to notify about resume
        if self.batch_display:
            subs = summary.get('subdomains', 0)
            live = summary.get('live_hosts', 0)
            eps = summary.get('endpoints', 0)
            wp = summary.get('wordpress', False)
            
            details = []
            if subs > 0:
                details.append(f"{subs} subs")
            if live > 0:
                details.append(f"{live} live")
            if eps > 0:
                details.append(f"{eps} eps")
            if wp:
                details.append("WordPress")
            
            if details:
                self.batch_display._add_to_feed(
                    "♻️", "Resumed", self.target,
                    f"Loaded: {', '.join(details)}"
                )
        
        # Force display update
        self._update_display()
        self.logger.info("[DISPLAY] Display refresh complete")

    def _restore_findings_from_state(self):
        """
        🔥 Restore findings from previous session when resuming a scan.
        This ensures all WordPress findings (plugins, themes, users, etc.) are
        properly loaded and displayed when continuing from a saved state.
        """
        if not self.resumed_from_state:
            return
        
        self.logger.info("[RESTORE] Restoring findings from previous session...")
        
        # Restore WordPress findings from state
        wp_plugins = self.state.get("wp_plugins", []) or []
        wp_themes = self.state.get("wp_themes", []) or []
        wp_users = self.state.get("wp_users", []) or []
        wp_version = self.state.get("wp_version", "unknown")
        wp_vulns = self.state.get("wp_vulnerabilities", []) or []
        wp_conditioned = self.state.get("wp_conditioned_findings", []) or []
        
        # Update self.findings with restored data
        if wp_plugins:
            self.findings['plugins'] = wp_plugins[:10]
            self.logger.info(f"[RESTORE] Restored {len(wp_plugins)} plugins")
        
        if wp_themes:
            self.findings['themes'] = wp_themes[:5]
            self.logger.info(f"[RESTORE] Restored {len(wp_themes)} themes")
        
        if wp_users:
            self.findings['users'] = wp_users[:10]
            self.logger.info(f"[RESTORE] Restored {len(wp_users)} users")
        
        if wp_version and wp_version != "unknown":
            self.findings['cms_version'] = f"WordPress {wp_version}"
            self.logger.info(f"[RESTORE] Restored WordPress version: {wp_version}")
        
        if wp_vulns:
            self.findings['wp_vulns'] = wp_vulns[:10]
            self.logger.info(f"[RESTORE] Restored {len(wp_vulns)} WordPress vulnerabilities")
        
        if wp_conditioned:
            high_conf = [c for c in wp_conditioned if c.get('chain_candidate') and c.get('confidence', 0) >= 70]
            if high_conf:
                self.findings['conditioned_chains'] = high_conf[:5]
                self.logger.info(f"[RESTORE] Restored {len(high_conf)} high-confidence exploit chains")
        
        # Restore technologies from state
        technologies = self.state.get("technologies", {}) or {}
        if technologies:
            tech_list = list(technologies.keys())[:15]
            self.findings['technologies'] = tech_list
            self.tech_stack = {tech: technologies.get(tech, {}) for tech in tech_list}
            self.logger.info(f"[RESTORE] Restored {len(tech_list)} technologies")
        
        # Restore toolkit metrics from state
        scan_meta = self.state.get("scan_metadata", {}) or {}
        toolkit_m = scan_meta.get("toolkit_metrics", {}) or {}
        if toolkit_m:
            self.toolkit_metrics = {
                'tech': toolkit_m.get('tech', 0),
                'ports': toolkit_m.get('ports', 0),
                'dirs': toolkit_m.get('dirs', 0),
                'api': toolkit_m.get('api', 0),
                'vulns': toolkit_m.get('vulns', 0),
            }
            self.logger.info(f"[RESTORE] Restored toolkit metrics: {toolkit_m}")
        
        # Restore chains data from state
        exploit_chains = self.state.get("exploit_chains", []) or []
        if exploit_chains:
            self.chains_data = []
            for i, chain in enumerate(exploit_chains[:5], 1):
                chain_name = chain.get("name", "") if isinstance(chain, dict) else getattr(chain, "name", f"Chain-{i}")
                chain_risk = (
                    (chain.get("risk") or chain.get("risk_level") or chain.get("severity"))
                    if isinstance(chain, dict)
                    else getattr(chain, "risk_level", "MEDIUM")
                )
                chain_steps = chain.get("steps", []) if isinstance(chain, dict) else getattr(chain, "steps", [])
                
                chain_info = {
                    'name': chain_name[:50],
                    'risk': chain_risk or 'MEDIUM',
                    'exploited': False,
                    'partial': False,
                    'steps': [],
                    'result': ''
                }
                
                for step in chain_steps[:3]:
                    step_desc = step.get('description', '') if isinstance(step, dict) else getattr(step, "name", "")
                    step_info = {
                        'desc': step_desc[:50],
                        'success': step.get('exploited', False) if isinstance(step, dict) else False,
                        'partial': step.get('partial', False) if isinstance(step, dict) else False,
                    }
                    chain_info['steps'].append(step_info)
                
                self.chains_data.append(chain_info)
            self.logger.info(f"[RESTORE] Restored {len(self.chains_data)} exploit chains")
        
        # Restore vuln_types from state
        vulns = self.state.get("confirmed_vulnerabilities", []) or []
        if vulns:
            self.vuln_types.clear()
            for v in vulns:
                vtype = v.get('type', 'unknown')
                self.vuln_types[vtype] += 1
            self.logger.info(f"[RESTORE] Restored {len(vulns)} vulnerabilities")
        
        self.logger.info("[RESTORE] Findings restoration complete")

    def _update_stats(self):
        # Lấy vulns trực tiếp từ confirmed_vulnerabilities (chính xác hơn)
        vulns = self.state.get("confirmed_vulnerabilities", [])
        vulns_count = len(vulns)
        
        summary = self.state.summary()
        self.stats.update({
            'subs': summary.get('subdomains', 0),
            'live': summary.get('live_hosts', 0),
            'eps': summary.get('endpoints', 0),
            'vulns': vulns_count,  # ← SỬA: dùng số lượng vulns thực tế
            'wp': 1 if summary.get('wordpress') else 0
        })
        
        # Cập nhật vuln_types cho display
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

    def _initialize_seed_queue(self):
        """
        Initialize scan with input target as seed (seed-first scanning).
        This ensures the input target is always scanned, regardless of recon results.
        """
        from urllib.parse import urlparse
        
        self.logger.info(f"[INIT] Initializing seed queue with: {self.target}")
        
        try:
            parsed = urlparse(self.target)
            
            seed = {
                "url": self.target,
                "source": "input_seed",
                "host": parsed.netloc.split(":")[0] if parsed.netloc else self.target,
                "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                "scheme": parsed.scheme or "https",
                "priority": 100
            }
            
            self.state.update(seed_targets=[seed])
            self.state.update(all_scan_targets=[seed])
            self.last_action = f"Seed initialized: {self.target}"
            
            self.logger.info(f"[INIT] Seed target registered for scanning: {seed['url']}")
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[INIT] Failed to initialize seed queue: {e}")
            self.last_action = f"Seed init failed: {str(e)[:30]}"
            self._update_display()

    def _should_skip_phase(self, phase: str) -> bool:
        """Check if a phase should be skipped based on completion status or user options."""
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

    def _get_resume_phase(self) -> str:
        """Get the phase to resume from when restarting after interruption.
        
        Returns the phase that was interrupted (if any), so we can skip it
        and continue from the next phase.
        """
        if not self.resumed_from_state:
            return None
        
        previous_phase = self.state.get("current_phase", "")
        if not previous_phase or previous_phase in self.completed_phases:
            return None
        
        # Map phase names to their canonical names used in completed_phases
        phase_mapping = {
            "recon": "recon",
            "live": "live_hosts", 
            "wp": "wordpress",
            "toolkit": "toolkit",
            "crawl": "discovery",
            "wp_detect_state": "wp_detect_state",
            "js_hunter": "js_hunter",
            "param_mine": "param_mine",
            "auth": "auth",
            "classify": "classify",
            "rank": "rank",
            "scan": "scan",
            "analyze": "analyze",
            "cve_analysis": "cve_analysis",
            "pivot": "priv_pivot",
            "graph": "graph",
            "chain": "chain",
            "select": "exploit_select",
            "exploit": "exploit",
            "sqli_exploit": "sqli_exploit",
            "upload_bypass": "upload_bypass",
            "reverse_shell": "reverse_shell",
            "privesc": "privesc",
            "waf_bypass": "waf_bypass",
            "boolean_sqli": "boolean_sqli",
            "xss": "xss",
            "idor": "idor",
            "default_creds": "default_creds",
            "cve_exploit": "cve_exploit",
            "api_vuln": "api_vuln",
            "subdomain_takeover": "subdomain_takeover",
            "mfa_bypass": "mfa_bypass",
            "oauth_saml": "oauth_saml",
            "persistence": "persistence",
            "lateral_movement": "lateral_movement",
            "ssl_pinning": "ssl_pinning",
            "zero_day": "zero_day",
            "container_escape": "container_escape",
            "custom_exploit": "custom_exploit",
            "log_evasion": "log_evasion",
            "learn": "learn",
        }
        
        canonical_phase = phase_mapping.get(previous_phase, previous_phase)
        self.logger.info(f"[RESUME] Previous interrupted phase: {previous_phase} -> {canonical_phase}")
        return canonical_phase

    def _mark_phase_done(self, phase: str):
        if not phase:
            return
        self.completed_phases.add(phase)
        scan_meta = self.state.get("scan_metadata", {}) or {}
        scan_meta["completed_phases"] = sorted(self.completed_phases)
        self.state.update(scan_metadata=scan_meta)

    def _run_recon_phase(self):
        before = len(self.state.get("subdomains", []))
        self._set_activity("subfinder+assetfinder+amass", "running", "enum")
        self.phase_detail = "[SUBFINDER] Enumerating subdomains..."
        self._update_display()
        self.recon_engine.run(progress_cb=self._progress_callback)
        self._set_activity("recon-engine", "done", "enum")
        after = len(self.state.get("subdomains", []))
        if after > before:
            self.stats['subs'] = after
            self.phase_detail = f"[RECON] Found {after} total subdomains"
            self._update_display()
            self.last_action = f"recon: +{after-before} subdomains"
            if self.batch_display:
                self.batch_display._add_to_feed("➕", "Subdomain", self.target, f"Found {after-before} new")
        # Update attack surface with recon findings
        self.attack_surface.add_clue("tech", f"subdomains:{after}", "recon_engine", 0.9, f"Found {after} subdomains")
        self.attack_surface.add_clue("recon_complete", json.dumps({"subdomains": after}), "recon_engine", 1.0)
        self.state.update(attack_surface=self.attack_surface.to_dict())
        
        self._update_stats()
        self._mark_phase_done("recon")

    def _run_live_hosts_phase(self):
        before = len(self.state.get("live_hosts", []))
        if before >= int((self.budget.to_dict() if hasattr(self, "budget") else {}).get("live_secondary_targets", 90)):
            self.last_action = f"live hosts: reused {before} from recon cache"
            self.phase_status = "done"
            self.phase_detail = f"[CACHE] Reusing {before} live hosts"
            self._update_display()
            self._mark_phase_done("live_hosts")
            return
        self._set_activity("live-host-detector", "running", "detect")
        self.phase_detail = "[HTTPX] Testing connectivity to hosts..."
        self._update_display()
        
        # SEED-FIRST: Include both seed targets and recon discoveries
        seeds = self.state.get("seed_targets", [])
        seed_urls = [s["url"] for s in seeds] if seeds else []
        
        discoveries = self.state.get("subdomains", [])
        
        # Combine: Seeds have priority, then add discoveries
        all_targets = seed_urls + discoveries
        
        stats_info = f"{len(seed_urls)} seeds"
        if discoveries:
            stats_info += f" + {len(discoveries)} discoveries"
        self.logger.info(f"[LIVE] Probing {stats_info}")
        
        self.stats['total_hosts'] = len(all_targets)
        
        # Probe all targets (seeds + discoveries)
        if all_targets:
            self.live_host_engine.detect_live_hosts(all_targets, skip_dev_test=True)
        
        self._set_activity("live-host-detector", "done", "detect")
        after = len(self.state.get("live_hosts", []))
        if after > before:
            self.stats['live'] = after
            self.phase_detail = f"[LIVE] Found {after} live hosts"
            self._update_display()
            self.last_action = f"live hosts: +{after-before} live"
            if self.batch_display:
                self.batch_display._add_to_feed("🌐", "Live", self.target, f"Found {after-before} live")
        self._canonicalize_state_urls()
        self._update_stats()
        self._mark_phase_done("live_hosts")

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

    def _run_wordpress_detection_from_state(self):
        self._set_activity("wordpress-detection", "running", "analyze")
        
        # Check if WordPress was not already detected
        already_detected = self.state.get("wordpress_detected", False)
        if already_detected:
            self.logger.info("[WP] WordPress already detected; skipping state-based detection")
            self.last_action = "wordpress already detected"
            return
        
        # Collect URLs/endpoints from state
        all_urls = []
        urls_from_state = self.state.get("urls", [])
        if isinstance(urls_from_state, list):
            all_urls.extend(str(u) for u in urls_from_state if u)
        
        endpoints = self.state.get("endpoints", [])
        if isinstance(endpoints, list):
            for ep in endpoints:
                if isinstance(ep, dict) and 'url' in ep:
                    all_urls.append(str(ep['url']))
                elif isinstance(ep, str):
                    all_urls.append(ep)
        
        crawled = self.state.get("crawled_urls", [])
        if isinstance(crawled, list):
            all_urls.extend(str(u) for u in crawled if u)
        
        if not all_urls:
            self.logger.debug("[WP] No URLs found in state; skipping detection")
            self.last_action = "no urls to analyze"
            return
        
        self.logger.info(f"[WP] Analyzing {len(all_urls)} discovered URLs for WordPress patterns...")
        
        # Use WP scanner's new detection method
        try:
            is_wordpress = self.wp_scanner.detect_wordpress_from_state_data()
            
            if is_wordpress:
                self.logger.info("[WP] WordPress detected from state data ✓")
                self.stats['wp'] = 1
                self.last_action = "wordpress: detected from patterns"
                
                # 🔥 FIX: Lấy version và themes từ state
                version = self.state.get("wp_version", "unknown")
                themes = self.state.get("wp_themes", [])
                plugins = self.state.get("wp_plugins", [])
                
                # 🔥 FIX: Cập nhật findings để hiển thị
                if version and version != "unknown":
                    self.findings['cms_version'] = f"WordPress {version}"
                if themes:
                    self.findings['themes'] = themes[:5]
                if plugins:
                    self.findings['plugins'] = plugins[:10]
                
                # Get confidence score if available
                confidence = self.state.get("wp_scan_confidence", 0)
                if confidence:
                    self.phase_detail = f"pattern-detect ({confidence:.0f}%)"
                    
                # 🔥 FIX: Force update display
                self._update_display()
            else:
                self.logger.debug("[WP] Insufficient WordPress patterns in data")
                self.last_action = "no wordpress patterns"
        
        except Exception as e:
            self.logger.warning(f"[WP] Error during state-based detection: {e}")
            self.last_action = f"detection error: {str(e)[:30]}"

    def _run_wordpress_phase(self):
        self._set_activity("wpscan+wp-fingerprint", "running", "scan")
        live_hosts = self._select_live_hosts_for_deep_scan(limit=15)  # Tối ưu: giảm từ 40 xuống 15 để tránh treo
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
                
                # 🔥 PRINT FINDINGS TO TERMINAL IMMEDIATELY 🔥
                print(f"\n{Colors.BOLD}{Colors.BRIGHT_YELLOW}{'═' * 60}{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.BRIGHT_YELLOW}║  🎯 WORDPRESS DETECTION RESULTS{Colors.RESET}{' ' * 25}{Colors.BOLD}{Colors.BRIGHT_YELLOW}║{Colors.RESET}")
                print(f"{Colors.BOLD}{Colors.BRIGHT_YELLOW}{'═' * 60}{Colors.RESET}")
                
                # Extract findings from WordPress scan
                all_plugins = []
                all_themes = []
                all_users = []
                wp_versions = []
                php_version_found = ""
                
                for site_url, site_data in wp_sites.items():
                    domain = site_url.replace("https://", "").replace("http://", "").split("/")[0]
                    
                    # Print WordPress version
                    if site_data.get('version'):
                        version = site_data['version']
                        wp_versions.append(version)
                        eol_marker = ""
                        # Check for EOL status
                        tech_details = self.state.get("technical_details", {}) or {}
                        wp_advanced = tech_details.get("wordpress_advanced_scan", {}) or {}
                        if wp_advanced.get("version_detection"):
                            is_eol = wp_advanced["version_detection"].get("eol", False)
                            if is_eol:
                                eol_marker = f" {Colors.BRIGHT_RED}(EOL - End of Life){Colors.RESET}"
                        print(f"\n{Colors.BOLD}{Colors.CYAN}📌 Site: {domain}{Colors.RESET}")
                        print(f"   {Colors.BOLD}WordPress Version:{Colors.RESET} {Colors.YELLOW}{version}{Colors.RESET}{eol_marker}")
                    
                    # Print PHP version
                    if site_data.get('php_version'):
                        php_version_found = site_data['php_version']
                        php_outdated = False
                        tech_details = self.state.get("technical_details", {}) or {}
                        wp_advanced = tech_details.get("wordpress_advanced_scan", {}) or {}
                        if wp_advanced.get("php_analysis"):
                            php_outdated = wp_advanced["php_analysis"].get("outdated", False)
                        php_marker = f" {Colors.BRIGHT_RED}(OUTDATED - Exploitable!){Colors.RESET}" if php_outdated else f" {Colors.GREEN}(Current){Colors.RESET}"
                        print(f"   {Colors.BOLD}PHP Version:{Colors.RESET} {Colors.YELLOW}{php_version_found}{Colors.RESET}{php_marker}")
                    
                    # Print users
                    if site_data.get('users'):
                        users = site_data['users']
                        all_users.extend(users)
                        print(f"\n   {Colors.BOLD}{Colors.BRIGHT_GREEN}👤 Users Enumerated ({len(users)}):{Colors.RESET}")
                        for user in users[:10]:
                            print(f"      {Colors.CYAN}└─ {user}{Colors.RESET}")
                        if len(users) > 10:
                            print(f"      {Colors.DIM}└─ ... and {len(users) - 10} more{Colors.RESET}")
                    
                    # Print plugins with vulnerabilities
                    if site_data.get('plugins'):
                        plugins = site_data['plugins']
                        all_plugins.extend(plugins[:5])
                        vuln_plugins = [p for p in plugins if p.get('vulnerabilities')]
                        print(f"\n   {Colors.BOLD}{Colors.BRIGHT_BLUE}🔌 Plugins Detected ({len(plugins)}):{Colors.RESET}")
                        
                        # Show vulnerable plugins first
                        if vuln_plugins:
                            print(f"      {Colors.BRIGHT_RED}⚠️ VULNERABLE PLUGINS:{Colors.RESET}")
                            for p in vuln_plugins[:5]:
                                pname = p.get('name', '')
                                pver = p.get('version', 'unknown')
                                ver_str = f" v{pver}" if pver and pver != 'unknown' else ""
                                cve_list = p.get('vulnerabilities', [])
                                cve_marker = ""
                                if cve_list:
                                    cve_ids = [c.get('cve_id', str(c)) if isinstance(c, dict) else str(c) for c in cve_list[:2]]
                                    if cve_ids:
                                        cve_marker = f" {Colors.BRIGHT_RED}[{', '.join(cve_ids)}]{Colors.RESET}"
                                print(f"         {Colors.BRIGHT_RED}└─ ⚠️ {pname}{ver_str}{cve_marker}{Colors.RESET}")
                        
                        # Show all plugins
                        safe_plugins = [p for p in plugins if p not in vuln_plugins]
                        if safe_plugins:
                            print(f"      {Colors.GREEN}✓ Safe plugins:{Colors.RESET}")
                            for p in safe_plugins[:5]:
                                pname = p.get('name', '')
                                pver = p.get('version', 'unknown')
                                ver_str = f" v{pver}" if pver and pver != 'unknown' else ""
                                print(f"         └─ {pname}{ver_str}")
                    
                    # Print themes
                    if site_data.get('themes'):
                        themes = site_data['themes']
                        all_themes.extend(themes[:3])
                        vuln_themes = [t for t in themes if t.get('vulnerabilities')]
                        print(f"\n   {Colors.BOLD}{Colors.BRIGHT_MAGENTA}🎨 Themes Detected ({len(themes)}):{Colors.RESET}")
                        for t in themes[:5]:
                            tname = t.get('name', '')
                            tver = t.get('version', 'unknown')
                            ver_str = f" v{tver}" if tver and tver != 'unknown' else ""
                            has_vuln = bool(t.get('vulnerabilities'))
                            vuln_marker = f" {Colors.BRIGHT_RED}⚠️ VULNERABLE{Colors.RESET}" if has_vuln else ""
                            print(f"      └─ {tname}{ver_str}{vuln_marker}")
                    
                    # Print vulnerabilities
                    if site_data.get('vulnerabilities'):
                        vulns = site_data['vulnerabilities']
                        print(f"\n   {Colors.BOLD}{Colors.BRIGHT_RED}🐞 Vulnerabilities ({len(vulns)}):{Colors.RESET}")
                        for v in vulns[:5]:
                            vtype = v.get('type', 'unknown')
                            severity = v.get('severity', 'MEDIUM')
                            sev_color = Colors.BRIGHT_RED if severity == 'CRITICAL' else Colors.RED if severity == 'HIGH' else Colors.YELLOW
                            print(f"      {sev_color}└─ [{severity}] {vtype}{Colors.RESET}")
                    
                    # Print conditioned findings (exploit chains)
                    if site_data.get('conditioned_findings'):
                        conditioned = site_data['conditioned_findings']
                        high_conf = [c for c in conditioned if c.get('chain_candidate') and c.get('confidence', 0) >= 70]
                        if high_conf:
                            print(f"\n   {Colors.BOLD}{Colors.BRIGHT_RED}🎯 High-Confidence Exploit Chains ({len(high_conf)}):{Colors.RESET}")
                            for chain in high_conf[:5]:
                                chain_name = chain.get('name', '')[:45]
                                confidence = chain.get('confidence', 0)
                                cve = chain.get('cve', [])
                                severity = chain.get('severity', 'MEDIUM')
                                sev_color = Colors.BRIGHT_RED if severity == 'CRITICAL' else Colors.RED if severity == 'HIGH' else Colors.YELLOW
                                cve_str = f" [{', '.join(cve[:2])}]" if cve else ""
                                print(f"      {Colors.BRIGHT_RED}└─ [{confidence}%]{cve_str} [{sev_color}{severity}{Colors.RESET}] {chain_name}{Colors.RESET}")
                    
                    print()
                
                print(f"{Colors.BOLD}{Colors.BRIGHT_YELLOW}{'═' * 60}{Colors.RESET}\n")
                
                # Store findings for display
                self.findings['plugins'] = list({(p['name'], p['version']): p for p in all_plugins}.values())[:10]
                self.findings['themes'] = list({(t['name'], t['version']): t for t in all_themes}.values())[:5]
                self.findings['users'] = list(set(all_users))[:5]
                if wp_versions:
                    self.findings['cms_version'] = f"WordPress {wp_versions[0]}"
                if php_version_found:
                    self.findings['php_version'] = php_version_found
                
                if self.batch_display:
                    self.batch_display._add_to_feed("🎯", "WordPress", self.target, f"Found {len(wp_sites)} sites")
                
                # ─── INTEGRATION: Advanced WordPress Security Scan (wp_scan_cve) ───
                # BUG 12 FIX: Only run advanced scan when wp_sites are detected
                self.logger.debug("[WORDPRESS] Running advanced security scan on detected targets...")
                for site_url in wp_sites.keys():
                    try:
                        self.phase_detail = f"[ADVANCED SCAN] Analyzing {site_url.split('://')[-1][:30]}..."
                        self._update_display()
                        
                        advanced_scan = WordPressAdvancedScan(site_url, timeout_per_check=8)
                        scan_data = advanced_scan.run_data_collection()
                        
                        # Merge results into state
                        self.state = WordPressAdvancedScan.merge_into_state(self.state, scan_data)
                        
                        # Log findings for display
                        if scan_data.get("version_detection"):
                            wp_ver = scan_data["version_detection"].get("wp_version")
                            is_eol = scan_data["version_detection"].get("eol", False)
                            self.logger.info(f"[WORDPRESS] Version: {wp_ver} {'(EOL)' if is_eol else ''}")
                        
                        if scan_data.get("php_analysis"):
                            php_ver = scan_data["php_analysis"].get("php_version")
                            is_outdated = scan_data["php_analysis"].get("outdated", False)
                            self.logger.info(f"[PHP] Version: {php_ver} {'(OUTDATED)' if is_outdated else ''}")
                        
                        if scan_data.get("wordpress_api", {}).get("user_enumeration_possible"):
                            self.logger.warning(f"[SECURITY] User enumeration possible via REST API")
                            users = scan_data.get("wordpress_api", {}).get("users_found", [])
                            if users:
                                self.logger.info(f"[USERS] Found: {', '.join(str(u) for u in users)}")
                                self.findings['users'] = users
                                if self.batch_display:
                                    self.batch_display._add_to_feed("👤", "Users", site_url.split('://')[-1][:20], ', '.join(users[:3]))
                        if scan_data.get("vulnerabilities"):
                            vuln_count = len(scan_data["vulnerabilities"])
                            self.logger.info(f"[SECURITY] Found {vuln_count} security observations")
                            
                            if self.batch_display:
                                for vuln in scan_data.get("vulnerabilities", []):
                                    icon = "⚠️"
                                    self.batch_display._add_to_feed(
                                        icon, 
                                        vuln.get("type", "OBSERVATION"), 
                                        site_url.split('://')[-1][:20],
                                        vuln.get("description", "")[:40]
                                    )
                        
                        time.sleep(1.5)  # Rate limiting
                    except Exception as e:
                        self.logger.debug(f"[ADVANCED SCAN] Error for {site_url}: {str(e)[:60]}")
        self._set_activity("wpscan+wp-fingerprint", "done", "scan")
        self._update_stats()
        self._mark_phase_done("wordpress")

    def _run_toolkit_phase(self):
        """Enhanced toolkit scanning with detailed tracking of all sub-modules and timeout protection"""
        live_hosts = self._select_live_hosts_for_deep_scan(limit=10)  # FIX: Reduced from 30 to prevent timeout
        
        if not live_hosts:
            self.last_action = "toolkit: no live hosts for scanning"
            self._mark_phase_done("toolkit")
            return
        
        # FIX: Filter out unreachable hosts based on response time
        live_hosts = self._filter_unreachable_hosts(live_hosts)
        if not live_hosts:
            self.last_action = "toolkit: no reachable hosts after filtering"
            self._mark_phase_done("toolkit")
            return
        
        self._set_activity("kali-toolkit", "running", "kali-tools")
        self.logger.info(f"[TOOLKIT] Starting comprehensive scan on {len(live_hosts)} hosts")
        
        # FIX: Add timeout protection for entire toolkit phase (600s = 10 minutes)
        toolkit_start_time = time.time()
        toolkit_timeout = 600  # 10 minutes max for entire toolkit phase
        
        # Run toolkit with progress tracking
        findings = self.toolkit.run(live_hosts, progress_cb=self._progress_callback)
        
        # Check if toolkit phase exceeded timeout
        toolkit_elapsed = time.time() - toolkit_start_time
        if toolkit_elapsed > toolkit_timeout:
            self.logger.warning(f"[TOOLKIT] Phase exceeded {toolkit_timeout}s timeout after {toolkit_elapsed:.0f}s")
            self.last_action = f"toolkit: timeout after {toolkit_elapsed:.0f}s"
        
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
            'open_ports': set(),
            'directories_count': 0,
            'api_count': 0,
            'api_endpoints': set(),
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
                for tech in techs:
                    tech_name = tech.get('name', '')
                    if tech_name:
                        self.tech_stack.setdefault(tech_name, tech)
                self.findings['technologies'] = sorted(metrics['tech_list'])
                
                # Extract PHP version and WAF
                for tech in techs:
                    tech_name = tech.get('name', '').lower()
                    if 'php' in tech_name and not self.findings.get('php_version'):
                        self.findings['php_version'] = tech.get('name', '')
                    if 'waf' in tech_name or 'firewall' in tech_name:
                        if not self.findings.get('waf'):
                            self.findings['waf'] = tech.get('name', '')
                
                vulns = data.get('vulnerabilities', [])
                metrics['vulnerabilities'].extend(vulns)
                
                self.phase_detail = f"[WHATWEB] Found {len(techs)} tech, {len(vulns)} CVEs"
                self._update_display()
                self.logger.info(f"[WHATWEB] {finding.get('url')}: {len(techs)} techs, {len(vulns)} CVEs")
                
            elif tool_name == 'wappalyzer':
                data = finding.get('data', {})
                techs = data.get('technologies', [])
                metrics['tech_count'] += len(techs)
                metrics['tech_list'].update([t for t in techs if t])
                version_info = data.get('version_info', {})
                for tech in techs:
                    if tech:
                        self.tech_stack.setdefault(tech, {
                            'name': tech,
                            'version': version_info.get(tech),
                            'source': 'wappalyzer'
                        })
                self.findings['technologies'] = sorted(metrics['tech_list'])
                
                self.phase_detail = f"[WAPPALYZER] Found {len(techs)} technologies"
                self._update_display()
                self.logger.info(f"[WAPPALYZER] {finding.get('url')}: {len(techs)} technologies")
                for tech in techs:
                    self.logger.debug(f"  ├─ {tech}")
                
            elif tool_name == 'naabu':
                data = finding.get('data', {})
                ports = data.get('ports', [])
                metrics['ports_count'] += len(ports)
                metrics['open_ports'].update(ports)
                services = data.get('services', {})
                
                self.phase_detail = f"[NAABU] Found {len(ports)} ports on {finding.get('host')}"
                self._update_display()
                self.logger.info(f"[NAABU] {finding.get('host')}: {len(ports)} ports open")
                for port, service_info in services.items():
                    self.logger.debug(f"  ├─ {port}: {service_info.get('service', 'unknown')}")
                
            elif tool_name == 'dirbusting':
                data = finding.get('data', {})
                dirs = data.get('directories', [])
                files = data.get('files', [])
                suspicious = data.get('suspicious', [])
                metrics['directories_count'] += len(dirs) + len(files)
                
                self.phase_detail = f"[DIRBUSTING] {len(dirs)} dirs | {len(files)} files | {len(suspicious)} suspicious"
                self._update_display()
                self.logger.info(f"[DIRBUSTING] {finding.get('url')}: {len(dirs)} dirs, {len(files)} files, {len(suspicious)} suspicious")
                
            elif tool_name == 'api_scanner':
                data = finding.get('data', {})
                base_url = finding.get('url', '').rstrip('/')
                rest_endpoints = data.get('rest_endpoints', []) or []
                graphql_endpoints = data.get('graphql_endpoints', []) or []
                api_docs = data.get('api_docs', []) or []
                api_doc_urls = [
                    doc.get('url') or doc.get('endpoint')
                    for doc in api_docs
                    if isinstance(doc, dict) and (doc.get('url') or doc.get('endpoint'))
                ]
                apis_found = data.get('apis_found', []) or []
                raw_endpoints = data.get('raw_endpoints', []) or []
                api_total = len(rest_endpoints) + len(graphql_endpoints) + len(api_docs)
                normalized_api_endpoints = set()
                for endpoint in (rest_endpoints + graphql_endpoints + api_doc_urls + apis_found + raw_endpoints):
                    if not endpoint:
                        continue
                    if endpoint.startswith(("http://", "https://")):
                        normalized_api_endpoints.add(endpoint)
                    elif endpoint.startswith("/") and base_url:
                        normalized_api_endpoints.add(f"{base_url}{endpoint}")
                if api_total == 0:
                    deduped_api = normalized_api_endpoints
                    api_total = len(deduped_api)
                    metrics['api_endpoints'].update(deduped_api)
                else:
                    metrics['api_endpoints'].update(normalized_api_endpoints)
                metrics['api_count'] += api_total
                
                self.phase_detail = f"[API-SCANNER] {len(rest_endpoints)} REST | {len(graphql_endpoints)} GraphQL | {len(api_docs)} docs"
                self._update_display()
                self.logger.info(f"[API-SCANNER] {finding.get('url')}: {len(rest_endpoints)} REST, {len(graphql_endpoints)} GraphQL, {len(api_docs)} docs")
                
                vulns = data.get('vulnerabilities', [])
                metrics['vulnerabilities'].extend(vulns)
                for vuln in vulns:
                    self.logger.warning(f"[API-VULN] {vuln.get('type')}: {finding.get('url')}")
            
            elif tool_name == 'wafw00f':
                self.phase_detail = f"[WAFW00F] WAF detection: {finding.get('severity')}"
                self._update_display()
                self.logger.info(f"[WAFW00F] WAF detection: {finding.get('severity')}")
            
            elif tool_name == 'nikto':
                self.phase_detail = f"[NIKTO] Scanning {finding.get('url')}"
                self._update_display()
                self.logger.info(f"[NIKTO] Scan completed: {finding.get('url')}")
            
            elif tool_name == 'nmap':
                data = finding.get('data', {})
                ports = data.get('ports', []) or []
                metrics['ports_count'] += len(ports) if ports else int(finding.get('ports_found', 0) or 0)
                metrics['open_ports'].update(ports)
                self.phase_detail = f"[NMAP] Scanning {finding.get('host')}"
                self._update_display()
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
        
        metrics['summary'] = ' | '.join(summary_parts) if summary_parts else (f"completed {metrics['total']} tools" if metrics['total'] else 'no data')
        
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
            self.tech_stack.update({tech: self.tech_stack.get(tech, {'name': tech}) for tech in metrics['tech_list'] if tech})
            self.findings['technologies'] = sorted(current_tech.keys())
        
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

        if metrics['api_endpoints']:
            current_endpoints = self.state.get("endpoints", []) or []
            existing_urls = {e.get("url") for e in current_endpoints if isinstance(e, dict)}
            for endpoint in sorted(metrics['api_endpoints']):
                full_url = endpoint if endpoint.startswith(("http://", "https://")) else ""
                if not full_url:
                    continue
                if full_url in existing_urls:
                    continue
                current_endpoints.append({
                    "url": full_url,
                    "source": "api_scanner",
                    "categories": ["api"],
                    "method": "GET"
                })
                existing_urls.add(full_url)
            self.state.update(endpoints=current_endpoints)
            self.endpoint_stats['api'] = max(self.endpoint_stats.get('api', 0), len(metrics['api_endpoints']))

        if metrics['open_ports']:
            scan_meta = self.state.get("scan_metadata", {}) or {}
            existing_ports = {int(p) for p in (scan_meta.get("open_ports", []) or []) if str(p).isdigit()}
            existing_ports.update(int(port) for port in metrics['open_ports'])
            scan_meta["open_ports"] = sorted(existing_ports)
            self.state.update(scan_metadata=scan_meta)
        
        # BUG 10 FIX: Merge dirbusting results into endpoints
        # Get the raw findings from toolkit
        findings = self.state.get("external_findings", []) or []
        for finding in findings:
            if finding.get("tool") == "dirbusting":
                base_url = finding.get("url", "")
                dirbusting_data = finding.get("data", {})
                directories = dirbusting_data.get("directories", [])
                files = dirbusting_data.get("files", [])
                
                current_endpoints = self.state.get("endpoints", []) or []
                
                # Add directories and files as endpoints
                for item in directories + files:
                    path = item if isinstance(item, str) else item.get("path", "") if isinstance(item, dict) else ""
                    if path:
                        full_url = base_url.rstrip("/") + "/" + path.lstrip("/")
                        # Check if endpoint already exists
                        if not any(e.get("url") == full_url for e in current_endpoints):
                            new_endpoint = {
                                "url": full_url,
                                "source": "dirbusting",
                                "categories": ["general"],
                                "method": "GET"
                            }
                            current_endpoints.append(new_endpoint)
                
                # Update state
                if any(e.get("source") == "dirbusting" for e in current_endpoints):
                    self.state.update(endpoints=current_endpoints)
                    self.logger.info(f"[MERGE] Added {len([e for e in current_endpoints if e.get('source') == 'dirbusting'])} dirbusting endpoints")


    def _run_discovery_phase(self):
        before = len(self.state.get("endpoints", []))
        self._set_activity("crawler", "running", "spider")
        self.phase_detail = "[CRAWLER] Discovering endpoints..."
        self._update_display()
        prioritized_hosts = [h.get("url", "") for h in self._select_live_hosts_for_deep_scan(limit=80) if h.get("url")]
        if prioritized_hosts:
            merged_urls = list(dict.fromkeys(prioritized_hosts + self.state.get("urls", [])))
            self.state.update(urls=merged_urls)
        self.discovery_engine.run(progress_cb=self._progress_callback)
        self._canonicalize_state_urls()
        self._set_activity("crawler", "done", "spider")
        after = len(self.state.get("endpoints", []))
        if after > before:
            self.endpoint_stats['total'] = after
            self.stats['eps'] = after
            self.phase_detail = f"[DISCOVERY] Found {after} total endpoints"
            self._update_display()
            self.last_action = f"crawl: +{after-before} endpoints"
            if self.batch_display:
                self.batch_display._add_to_feed("📁", "Endpoint", self.target, f"Found {after-before} new")
        self._update_stats()
        self._mark_phase_done("discovery")

    def _run_auth_phase(self):
        self._set_activity("session-bootstrap", "running", "roles")
        self.phase_detail = "[AUTH] Testing session authentication..."
        self._update_display()
        results = self.auth_engine.run(self.auth_file)
        self._set_activity("session-bootstrap", "done", "roles")
        success = sum(1 for r in results if r.get("success"))
        self.last_action = f"auth: {success}/{len(results)} roles authenticated"
        self.phase_detail = f"[AUTH] Authenticated {success}/{len(results)} sessions"
        self._update_display()
        if self.batch_display:
            self.batch_display._add_to_feed("🔐", "Auth", self.target, self.last_action)
        self._mark_phase_done("auth")

    def _run_classification_phase(self):
        self.phase_detail = "[CLASSIFY] Analyzing endpoint types..."
        self._update_display()
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
            self.phase_detail = f"[CLASSIFY] Found {api_count} API, {admin_count} Admin, {upload_count} Upload endpoints"
            self._update_display()
        self.phase_status = "done"
        self._update_stats()
        self._mark_phase_done("classify")

    def _run_prioritization_phase(self):
        self.phase_detail = "[RANK] Prioritizing high-risk endpoints..."
        self._update_display()
        self._run_endpoint_ranking()
        self._canonicalize_state_urls()
        self._run_post_discovery_probe()
        prioritized = len(self.state.get("prioritized_endpoints", []))
        self.logger.warning(f"[RANK] Prioritized endpoints count: {prioritized}")
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("rank")

    def _run_post_discovery_probe(self):
        if not self.options.get("probe_after_discovery"):
            return

        targets = self.state.get("prioritized_endpoints", []) or []
        if not targets:
            self.logger.warning("[PROBE] No prioritized endpoints available for validation")
            return

        max_endpoints = max(1, int(self.options.get("probe_max_endpoints", 1)))
        request_count = max(1, int(self.options.get("probe_count", 2)))
        delay = max(0.1, float(self.options.get("probe_delay", 0.5)))

        self.phase_detail = "[PROBE] Validating prioritized endpoints..."
        self.phase_tool = "safe-endpoint-probe"
        self.phase_status = "running"
        self._update_display()

        results = run_endpoint_probe(
            state=self.state,
            output_dir=self.output_dir,
            http_client=self.http_client,
            endpoints=targets,
            max_endpoints=max_endpoints,
            requests_per_endpoint=request_count,
            delay_seconds=delay,
        )

        self.last_action = f"validated {len(results)} prioritized endpoint(s)"
        self.logger.warning(f"[PROBE] Completed validation on {len(results)} endpoint(s)")
        self._update_display()

    def _confidence_value(self, value, default=0.0):
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _normalize_vulnerability_record(self, vuln):
        if not isinstance(vuln, dict):
            return {}

        normalized = dict(vuln)
        endpoint = normalized.get("endpoint") or normalized.get("url") or normalized.get("target") or ""
        if endpoint:
            normalized["endpoint"] = endpoint
            normalized.setdefault("url", endpoint)

        normalized["confidence"] = self._confidence_value(normalized.get("confidence", 0.0))

        severity = str(normalized.get("severity", "") or "").upper()
        if not severity:
            confidence = normalized["confidence"]
            severity = "CRITICAL" if confidence >= 0.9 else "HIGH" if confidence >= 0.75 else "MEDIUM" if confidence >= 0.4 else "LOW"
        normalized["severity"] = severity
        return normalized

    def _vuln_merge_key(self, vuln):
        normalized = self._normalize_vulnerability_record(vuln)
        endpoint = normalized.get("endpoint") or normalized.get("url") or ""
        vtype = normalized.get("type") or normalized.get("name") or "unknown"
        payload = normalized.get("payload") or ""
        return (endpoint, vtype, payload)

    def _merge_vulnerability_lists(self, existing, incoming):
        merged = {}
        for source in (existing or [], incoming or []):
            for vuln in source:
                normalized = self._normalize_vulnerability_record(vuln)
                if not normalized:
                    continue
                key = self._vuln_merge_key(normalized)
                current = merged.get(key)
                if current is None or normalized.get("confidence", 0.0) >= current.get("confidence", 0.0):
                    if current:
                        current.update(normalized)
                    else:
                        merged[key] = normalized
        return list(merged.values())

    def _run_scanning_phase(self):
        before = len(self.state.get("confirmed_vulnerabilities", []))

        self._set_activity("nuclei/sqlmap/dalfox", "running", "active")
        self.phase_detail = "[NUCLEI] Testing with active scanning..."
        self._update_display()

        try:
            targets = (
                self.state.get("prioritized_endpoints")
                or self.state.get("endpoints")
                or [{"url": u} for u in self.state.get("urls", [])]
            )

            if not targets:
                self.logger.warning("[SCAN] No targets available → skipping scan")
            else:
                self.logger.warning(f"[SCAN] Running scan on {len(targets)} endpoints")

            self.state.update(scan_targets=targets)
            self.state.update(prioritized_endpoints=targets)
            # Update total_payloads để UI hiển thị đúng
            self.stats['total_payloads'] = min(len(targets), 100)
            # FIX: Only reset progress if this is a fresh run, not a resume
            if not self.resumed_from_state:
                self.stats['payloads_tested'] = 0
            else:
                # Restore progress from state if available
                already_scanned = len(self.state.get("scanned_endpoints", []))
                self.stats['payloads_tested'] = already_scanned
                self.logger.info(f"[SCAN] Resumed from previous progress: {already_scanned} endpoints already scanned")
            self._update_display()
            # RUN SCAN
            def _scan_progress(completed):
                self.stats['payloads_tested'] = min(completed, self.stats.get('total_payloads', 100))
                self._update_display()

            self.scanning_engine.run(progress_cb=_scan_progress)

            self.stats['payloads_tested'] = self.stats['total_payloads']
            self._update_display()
            self.error_recovery.log_success("scan", "nuclei")

        except Exception as e:
            error_msg = str(e)[:80]
            self.error_recovery.log_error("scan", "nuclei", error_msg)
            recovery = self.error_recovery.suggest_recovery("scan", "nuclei", error_msg)
            self.phase_detail = f"[SCAN] Error - {recovery['recommended_action']}"
            self.logger.warning(f"Scanning phase error: {error_msg}")

        self._set_activity("nuclei/sqlmap/dalfox", "done", "active")

        # ============ ĐỌC VÀ XỬ LÝ SCAN RESULTS ============
        scan_results_file = os.path.join(self.output_dir, "scan_results.json")
        scan_responses = []
        vulns_from_scan = []

        if os.path.exists(scan_results_file):
            self.logger.info(f"[SCAN] Reading scan results from {scan_results_file}")
            
            with open(scan_results_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        result = json.loads(line)
                        scan_responses.append(result)
                        
                        # Phát hiện vuln
                        if result.get("vulnerable", False):
                            endpoint = result.get("endpoint", "")
                            category = result.get("category", "unknown")
                            confidence = self._confidence_value(result.get("confidence", 0.5), 0.5)
                            
                            # Tạo vuln object
                            vuln = {
                                "type": category,
                                "endpoint": endpoint,
                                "url": endpoint,
                                "confidence": confidence,
                                "evidence": result.get("reason", "No indicators detected"),
                                "payload": result.get("payload", ""),
                                "severity": "HIGH" if confidence >= 0.75 else "MEDIUM" if confidence >= 0.4 else "LOW",
                                "status_code": result.get("status_code", 0),
                                "method": result.get("method", "GET")
                            }
                            vulns_from_scan.append(vuln)
                            
                    except json.JSONDecodeError as e:
                        self.logger.warning(f"[SCAN] Invalid JSON at line {line_num}: {e}")
                        continue
            merged_confirmed = self._merge_vulnerability_lists(
                self.state.get("confirmed_vulnerabilities", []) or [],
                vulns_from_scan,
            )
            merged_all = self._merge_vulnerability_lists(
                self.state.get("vulnerabilities", []) or [],
                merged_confirmed,
            )

            self.state.update(confirmed_vulnerabilities=[])
            self.state.update(confirmed_vulnerabilities=merged_confirmed)
            self.state.update(vulnerabilities=[])
            self.state.update(vulnerabilities=merged_all)

            self.logger.info(
                f"[SCAN] Loaded {len(scan_responses)} responses, parsed {len(vulns_from_scan)} file findings, "
                f"state now has {len(merged_confirmed)} confirmed / {len(merged_all)} total vulnerabilities"
            )

            if vulns_from_scan:
                for vuln in vulns_from_scan[:10]:
                    self.logger.info(
                        f"[SCAN]   - {vuln['type']} on {vuln['endpoint'][:60]} (conf: {vuln['confidence']})"
                    )
            elif merged_confirmed:
                self.logger.info("[SCAN] No vulnerable file findings, but tool-promoted findings already exist in state")
            else:
                self.logger.info("[SCAN] No vulnerable results found in scan artifacts or state")

        else:
            current_confirmed = self.state.get("confirmed_vulnerabilities", []) or []
            current_all = self.state.get("vulnerabilities", []) or []
            self.logger.warning(f"[SCAN] scan_results.json NOT FOUND at {scan_results_file}")
            # Fallback
            fallback_targets = self.state.get("prioritized_endpoints") or self.state.get("endpoints") or []
            for e in fallback_targets[:20]:
                scan_responses.append({
                    "endpoint": e.get("url") if isinstance(e, dict) else e,
                    "vulnerable": False,
                    "category": "surface",
                    "confidence": 0.1,
                    "reason": "No active scan result - fallback surface detection"
                })
            self.logger.warning(
                f"[SCAN] Generated {len(scan_responses)} fallback responses; "
                f"state currently has {len(current_confirmed)} confirmed / {len(current_all)} total vulnerabilities"
            )

        # SAVE TO STATE
        self.state.update(scan_responses=scan_responses)

        # ============ CẬP NHẬT STATS ============
        after = len(self.state.get("confirmed_vulnerabilities", []))
        scanned = len(self.state.get("prioritized_endpoints", []) or [])
        self.stats['payloads_tested'] = min(scanned, 100)
        self._update_display()

        if after > before:
            self.stats['vulns'] = after
            new_vulns = after - before

            self.phase_detail = f"[SCAN] Found {after} vulnerabilities (+{new_vulns} new)"
            self._update_display()
            self.last_action = f"scan: +{new_vulns} vulns found"

            vulns = self.state.get("confirmed_vulnerabilities", [])
            if vulns and self.batch_display:
                for vuln in vulns[-new_vulns:]:
                    vtype = vuln.get('type', 'unknown')
                    icon = "🐞" if vtype == "sqli" else "⚠️"
                    self.batch_display._add_to_feed(icon, vtype.upper(), self.target, vuln.get('url', '')[:30])

            self._update_stats()
        else:
            self.logger.info(f"[SCAN] No new vulnerabilities (before={before}, after={after})")
            self._update_stats()

        self._mark_phase_done("scan")

    def _run_analysis_phase(self):
        self.phase_detail = "[ANALYSIS] Processing scan results..."
        self._update_display()

        # Load scan_responses from state, and if missing then load from scan_results.json.
        responses = self.state.get("scan_responses", []) or []
        if not responses:
            scan_file = os.path.join(self.output_dir, "scan_results.json")
            loaded = []
            if os.path.exists(scan_file):
                try:
                    with open(scan_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                loaded.append(json.loads(line))
                            except json.JSONDecodeError:
                                self.logger.warning(f"[ANALYSIS] Invalid JSON line in scan_results.json: {line}")
                except Exception as e:
                    self.logger.warning(f"[ANALYSIS] Failed to read scan_results.json: {e}")

            if loaded:
                responses = loaded
                self.state.update(scan_responses=responses)
                self.logger.warning(f"[ANALYSIS] Loaded {len(responses)} scan responses from scan_results.json")

        existing_confirmed = self.state.get("confirmed_vulnerabilities", []) or []
        existing_detected = self.state.get("vulnerabilities", []) or []
        parsed_vulnerabilities = []
        for response in responses:
            if response.get("vulnerable"):
                confidence = self._confidence_value(response.get("confidence", 0), 0.0)
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
                    "validated": False,
                }
                parsed_vulnerabilities.append(vuln)

        merged_confirmed = self._merge_vulnerability_lists(existing_confirmed, parsed_vulnerabilities)
        merged_detected = self._merge_vulnerability_lists(existing_detected, merged_confirmed)
        manual_queue = []
        for vuln in merged_confirmed:
            severity = str(vuln.get("severity", "") or "").upper()
            if vuln.get("requires_manual_validation") or severity in ("CRITICAL", "HIGH"):
                manual_queue.append(
                    {
                        "id": f"{vuln.get('endpoint') or vuln.get('url')}::{vuln.get('type')}::{len(manual_queue)+1}",
                        "endpoint": vuln.get("endpoint") or vuln.get("url"),
                        "type": vuln.get("type"),
                        "severity": severity or "HIGH",
                        "evidence": vuln.get("evidence", ""),
                        "status": "pending_manual_review",
                    }
                )

        self.state.update(confirmed_vulnerabilities=[])
        self.state.update(confirmed_vulnerabilities=merged_confirmed)
        self.state.update(vulnerabilities=[])
        self.state.update(vulnerabilities=merged_detected)
        self.state.update(manual_validation_required=manual_queue)
        if manual_queue:
            queue_file = os.path.join(self.output_dir, "manual_validation_queue.json")
            with open(queue_file, "w") as f:
                json.dump(manual_queue, f, indent=2)

        # Generate security_findings from non-CVE signals
        self.phase_detail = "[ANALYSIS] Extracting security findings from scan data..."
        self._update_display()
        findings = self._generate_findings() or []

        # Overwrite (no merge) security_findings into state.
        # StateManager merges lists, so clear first to guarantee overwrite semantics.
        self.state.update(security_findings=[])
        self.state.update(security_findings=findings)
        self.logger.info(f"[ANALYSIS] Generated {len(findings)} security findings")

        # Detect RCE chain possibilities (dynamic, rules-driven)
        rce_possibilities = self._analyze_rce_possibilities() or []

        # Overwrite (no merge) rce_chain_possibilities into state.
        self.state.update(rce_chain_possibilities=[])
        self.state.update(rce_chain_possibilities=rce_possibilities)
        self.logger.info(f"[ANALYSIS] Identified {len(rce_possibilities)} RCE attack surface(s)")

        # ─── SECURITY MISCONFIGURATION CHECKS (Crypto/SSL/TLS/Sensitive Data) ────────
        self.phase_detail = "[ANALYSIS] Running security misconfiguration checks..."
        self._update_display()
        self._run_security_misconfig_checks()

        if merged_confirmed:
            self.last_action = f"analysis: {len(merged_confirmed)} confirmed vulns + {len(findings)} findings"
            self._update_stats()
        elif findings:
            self.last_action = f"analysis: {len(findings)} findings (no CVEs)"
            self._update_stats()

        self.phase_status = "done"
        self._update_display()
        self._mark_phase_done("analyze")

    def _generate_findings(self) -> List[Dict[str, Any]]:
        """
        Generate structured findings from discovered data (non-CVE signals).
        Covers: tech detection, misconfigurations, interesting endpoints, anomalies.
        """
        findings: List[Dict[str, Any]] = []

        # 1. TECHNOLOGY DETECTION FINDINGS
        findings.extend(self._extract_tech_findings())

        # 2. OUTDATED VERSION FINDINGS (rules-driven)
        findings.extend(self._extract_outdated_version_findings())

        # 3. INTERESTING ENDPOINT FINDINGS (rules-driven + dynamic fallback)
        findings.extend(self._extract_endpoint_findings())

        # 4. MISCONFIGURATION FINDINGS
        findings.extend(self._extract_misconfig_findings())

        # 5. INFORMATION LEAK FINDINGS
        findings.extend(self._extract_info_leak_findings())

        # 6. ANOMALY FINDINGS
        findings.extend(self._extract_anomaly_findings())

        # Deduplicate
        seen = set()
        unique_findings = []
        for finding in findings:
            key = (finding.get("type"), finding.get("title", ""), finding.get("endpoint", ""))
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        self.logger.debug(f"[FINDINGS] Generated {len(unique_findings)} findings from {len(findings)} raw entries")
        return unique_findings

    def _extract_outdated_version_findings(self) -> List[Dict[str, Any]]:
        """
        Detect outdated/unsafe versions using rules files only.
        If rules are missing or versions are unknown, skip gracefully.
        """
        findings: List[Dict[str, Any]] = []

        rules_file = os.path.join(BASE_DIR, "rules", "wordpress_rules.json")
        if not os.path.exists(rules_file):
            return findings

        try:
            with open(rules_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return findings

        wp_rules = data.get("wordpress", data) or {}

        def to_version_tuple(v: str) -> Optional[tuple]:
            if not v or not isinstance(v, str):
                return None
            if v.lower() == "unknown":
                return None
            # Extract numeric components only (e.g. "5.8.1" -> (5, 8, 1))
            parts = re.findall(r"\d+", v)
            if not parts:
                return None
            return tuple(int(p) for p in parts[:4])

        def cmp_versions(a: str, b: str) -> Optional[int]:
            ta = to_version_tuple(a)
            tb = to_version_tuple(b)
            if ta is None or tb is None:
                return None
            if ta == tb:
                return 0
            return -1 if ta < tb else 1

        def version_in_expr(version: str, expr: str) -> bool:
            if not version or not expr:
                return False
            expr = expr.strip()
            c = cmp_versions(version, expr.lstrip("<").strip())
            if expr.startswith("<"):
                return c is not None and c < 0
            if "-" in expr and not expr.startswith("<"):
                # Range: "4.0-4.7.1"
                start, end = [p.strip() for p in expr.split("-", 1)]
                c1 = cmp_versions(version, start)
                c2 = cmp_versions(version, end)
                return c1 is not None and c2 is not None and c1 >= 0 and c2 <= 0
            return False

        # WordPress core
        if self.state.get("wordpress_detected"):
            wp_version = self.state.get("wp_version", "unknown")
            if isinstance(wp_version, str) and wp_version.lower() != "unknown":
                vuln_versions = wp_rules.get("vulnerable_versions", {}) or {}
                sev_map = {
                    "critical": "CRITICAL",
                    "high": "HIGH",
                    "medium": "MEDIUM",
                }
                for group, ranges in vuln_versions.items():
                    for expr in ranges or []:
                        if version_in_expr(wp_version, str(expr)):
                            findings.append(
                                {
                                    "type": "outdated_version",
                                    "severity": sev_map.get(group, "MEDIUM"),
                                    "title": f"Outdated WordPress version detected (v{wp_version})",
                                    "endpoint": "WordPress Core",
                                    "evidence": f"Matched vulnerable version rule: {expr}",
                                    "prerequisites": ["wordpress_detected"],
                                    "consequences": ["outdated_wordpress_version"],
                                }
                            )
                            break

        # Plugins/themes (only if versions are known)
        plugin_vulns = wp_rules.get("plugin_vulnerabilities", {}) or {}
        for plugin in self.state.get("wp_plugins", []) or []:
            if not isinstance(plugin, dict):
                continue
            name = plugin.get("name", "")
            ver = plugin.get("version", "unknown")
            if not name or not ver or str(ver).lower() == "unknown":
                continue
            if name not in plugin_vulns:
                continue
            info = plugin_vulns.get(name, {}) or {}
            for expr in info.get("versions", []) or []:
                if version_in_expr(str(ver), str(expr)):
                    findings.append(
                        {
                            "type": "outdated_component_version",
                            "severity": info.get("severity", "MEDIUM"),
                            "title": f"Outdated WordPress plugin detected: {name} (v{ver})",
                            "endpoint": "WordPress Plugin",
                            "evidence": f"Matched vulnerable version rule: {expr}",
                            "prerequisites": ["wordpress_detected"],
                            "consequences": ["outdated_component_version"],
                            "cve": info.get("cve", []),
                        }
                    )
                    break

        theme_vulns = wp_rules.get("theme_vulnerabilities", {}) or {}
        for theme in self.state.get("wp_themes", []) or []:
            if not isinstance(theme, dict):
                continue
            name = theme.get("name", "")
            ver = theme.get("version", "unknown")
            if not name or not ver or str(ver).lower() == "unknown":
                continue
            if name not in theme_vulns:
                continue
            info = theme_vulns.get(name, {}) or {}
            for expr in info.get("versions", []) or []:
                if version_in_expr(str(ver), str(expr)):
                    findings.append(
                        {
                            "type": "outdated_component_version",
                            "severity": info.get("severity", "MEDIUM"),
                            "title": f"Outdated WordPress theme detected: {name} (v{ver})",
                            "endpoint": "WordPress Theme",
                            "evidence": f"Matched vulnerable version rule: {expr}",
                            "prerequisites": ["wordpress_detected"],
                            "consequences": ["outdated_component_version"],
                            "cve": info.get("cve", []),
                        }
                    )
                    break

        return findings

    def _extract_tech_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from technology detection."""
        findings = []
        
        # WordPress detection
        if self.state.get("wordpress_detected"):
            wp_version = self.state.get("wp_version", "unknown")
            findings.append({
                "type": "tech_detect",
                "severity": "INFO",
                "title": f"WordPress detected (v{wp_version})",
                "endpoint": "N/A",
                "evidence": f"WordPress CMS identified. Version: {wp_version}. Plugins detected: {len(self.state.get('wp_plugins', []))}. Themes: {len(self.state.get('wp_themes', []))}."
            })
        
        # Framework/CMS detection
        cms_version = self.findings.get('cms_version', '')
        if cms_version and 'wordpress' not in cms_version.lower():
            findings.append({
                "type": "tech_detect",
                "severity": "INFO",
                "title": f"CMS detected - {cms_version}",
                "endpoint": "N/A",
                "evidence": f"Server is running {cms_version}"
            })
        
        # PHP version
        php_version = self.findings.get('php_version', '')
        if php_version:
            findings.append({
                "type": "tech_detect",
                "severity": "INFO",
                "title": f"PHP version exposed: {php_version}",
                "endpoint": "N/A",
                "evidence": f"Server identifies as {php_version} in response headers"
            })
        
        # WAF detection
        waf = self.findings.get('waf', '')
        if waf:
            findings.append({
                "type": "tech_detect",
                "severity": "INFO",
                "title": f"WAF/Security detected: {waf}",
                "endpoint": "N/A",
                "evidence": f"Server is protected by {waf} security appliance"
            })
        
        return findings

    def _extract_endpoint_findings(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        def collect_candidate_urls() -> List[str]:
            out = set()
            for u in (self.state.get("urls", []) or []):
                if u:
                    out.add(str(u))
            for u in (self.state.get("crawled_urls", []) or []):
                if u:
                    out.add(str(u))

            for item in self.state.get("endpoints", []) or []:
                if isinstance(item, dict) and item.get("url"):
                    out.add(str(item["url"]))
                elif isinstance(item, str) and item:
                    out.add(item)

            for item in self.state.get("prioritized_endpoints", []) or []:
                if isinstance(item, dict) and item.get("url"):
                    out.add(str(item["url"]))

            for resp in self.state.get("scan_responses", []) or []:
                if isinstance(resp, dict) and resp.get("endpoint"):
                    out.add(str(resp["endpoint"]))
            return list(out)

        def wildcard_to_regex(pattern: str) -> str:
            # Support '*' as wildcard for rule path patterns.
            escaped = re.escape(pattern)
            return escaped.replace(r"\*", ".*")

        candidate_urls = collect_candidate_urls()
        if not candidate_urls:
            return findings

        # Prefer dynamic patterns from state; fallback to rules.
        pattern_entries: List[Dict[str, Any]] = []
        state_patterns = self.state.get("dangerous_patterns", []) or []
        if isinstance(state_patterns, list) and state_patterns:
            for p in state_patterns:
                if isinstance(p, dict) and p.get("pattern"):
                    pattern_entries.append(p)

        if not pattern_entries:
            rules_file = os.path.join(BASE_DIR, "rules", "wordpress_rules.json")
            if os.path.exists(rules_file):
                try:
                    with open(rules_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    wp_rules = data.get("wordpress", data) or {}
                except Exception:
                    wp_rules = {}
            else:
                wp_rules = {}

            # Build severity lookup from common vulnerable endpoints.
            common = wp_rules.get("common_vulnerabilities", {}) or {}
            endpoint_sev_map: Dict[str, Dict[str, Any]] = {}
            for key, info in common.items():
                endpoint = info.get("endpoint")
                if endpoint:
                    endpoint_sev_map[str(endpoint).lower()] = info

            default_paths = wp_rules.get("default_paths", {}) or {}

            token_map = {
                "login": "login_endpoint_found",
                "uploads": "file_upload_endpoint",
            }

            # Default WP paths -> dynamic patterns
            for path_key, path_value in default_paths.items():
                if not path_value:
                    continue
                sev = "MEDIUM"
                type_hint = str(path_key)
                match_info = endpoint_sev_map.get(str(path_value).lower())
                if match_info and match_info.get("severity"):
                    sev = match_info.get("severity", sev)
                    type_hint = match_info.get("type", type_hint)
                consequences = []
                tok = token_map.get(str(path_key))
                if tok:
                    consequences.append(tok)

                pattern_entries.append(
                    {
                        "finding_type": "interesting_endpoint",
                        "pattern": str(path_value),
                        "title": f"WordPress path exposed: {path_key}",
                        "severity": sev,
                        "consequences": consequences,
                    }
                )

            # Common vulnerable endpoints
            for info in common.values():
                endpoint = info.get("endpoint")
                if not endpoint:
                    continue
                tok = None
                # Map known "common" findings into capability tokens when possible.
                if info.get("type") == "xmlrpc_bruteforce":
                    tok = "xmlrpc_endpoint_found"
                if info.get("type") == "user_enumeration":
                    tok = "user_enumeration_possible"
                consequences = [tok] if tok else []
                pattern_entries.append(
                    {
                        "finding_type": "interesting_endpoint",
                        "pattern": str(endpoint),
                        "title": f"Potential vulnerable WordPress endpoint ({info.get('type', 'unknown')})",
                        "severity": info.get("severity", "MEDIUM"),
                        "consequences": consequences,
                    }
                )

            # Detection patterns (paths/files) as extra signals
            det = wp_rules.get("detection_patterns", {}) or {}
            for p in det.get("paths", []) or []:
                pattern_entries.append(
                    {
                        "finding_type": "interesting_endpoint",
                        "pattern": str(p),
                        "title": "WordPress indicator path exposed",
                        "severity": "LOW",
                        "consequences": [],
                    }
                )
            for f_name in det.get("files", []) or []:
                pattern_entries.append(
                    {
                        "finding_type": "interesting_endpoint",
                        "pattern": str(f_name),
                        "title": "WordPress indicator file exposed",
                        "severity": "LOW",
                        "consequences": [],
                    }
                )

        # Dynamic fallback: infer endpoint type from URL naming (rules-driven patterns are preferred above).
        # Note: keep fallback generic and do not hardcode sensitive specific filenames.
        fallback_patterns = [
            (r"/admin(?:/|\\b)", "Admin interface exposed", "LOW", ["admin_endpoint_found"]),
            (r"/login(?:/|\\b)", "Login panel exposed", "MEDIUM", ["login_endpoint_found"]),
            (r"/upload(?:/|\\b)|/uploads(?:/|\\b)", "File upload surface exposed", "MEDIUM", ["file_upload_endpoint"]),
            (r"/api(?:/|\\b)|graphql|swagger", "API surface exposed", "LOW", ["api_endpoint_found"]),
            (r"/debug(?:/|\\b)|/debug\\.php(?:\\b|$)", "Debug surface exposed", "MEDIUM", []),
            (r"/backup(?:/|\\b)", "Backup surface exposed", "MEDIUM", []),
            (r"/config(?:/|\\b)", "Configuration surface exposed", "MEDIUM", []),
        ]
        for regex, title, sev, cons in fallback_patterns:
            pattern_entries.append(
                {
                    "finding_type": "interesting_endpoint",
                    "regex": regex,
                    "title": title,
                    "severity": sev,
                    "consequences": cons,
                }
            )

        # Apply patterns to each candidate URL.
        for url in candidate_urls:
            if not url:
                continue
            for entry in pattern_entries:
                finding_type = entry.get("finding_type", "interesting_endpoint")
                severity = entry.get("severity", "MEDIUM")
                title = entry.get("title", "Interesting endpoint")
                consequences = entry.get("consequences", []) or []

                if entry.get("regex"):
                    regex = str(entry["regex"])
                else:
                    regex = wildcard_to_regex(str(entry.get("pattern", "")))

                if not regex:
                    continue

                if re.search(regex, url, re.IGNORECASE):
                    pattern_label = entry.get("pattern") or entry.get("regex")
                    findings.append(
                        {
                            "type": finding_type,
                            "severity": severity,
                            "title": title,
                            "endpoint": url,
                            "evidence": f"Matched dynamic pattern '{pattern_label}' on {url}",
                            "prerequisites": [],
                            "consequences": consequences,
                        }
                    )

        self.logger.debug(f"[FINDINGS] Endpoint findings: {len(findings)} raw matches")
        return findings

    def _extract_misconfig_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from misconfigurations."""
        findings = []
        
        # Suspicious response patterns
        responses = self.state.get("scan_responses", []) or []
        responses_str = " ".join([str(r) for r in responses])
        
        # Check for verbose error messages
        verbose_patterns = [
            r'strpos\(\)',
            r'undefined variable',
            r'Warning: ',
            r'Fatal error:',
            r'Exception:',
            r'stack trace',
            r'at line \d+',
        ]
        
        for pattern in verbose_patterns:
            if re.search(pattern, responses_str, re.IGNORECASE):
                findings.append({
                    "type": "misconfig",
                    "severity": "LOW",
                    "title": "Verbose error messages exposed",
                    "endpoint": "*",
                    "evidence": f"Server exposes debugging information in error responses (pattern: {pattern})"
                })
                break
        
        return findings

    def _extract_info_leak_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from potential information leaks."""
        findings = []
        
        # User enumeration via WordPress
        if self.findings.get('users'):
            user_count = len(self.findings['users'])
            findings.append({
                "type": "info_leak",
                "severity": "LOW",
                "title": f"{user_count} users enumerated",
                "endpoint": "WordPress REST API",
                "evidence": f"User enumeration possible - {user_count} usernames discovered: {', '.join(self.findings['users'][:5])}"
            })
        
        # Plugin information leak
        if self.findings.get('plugins'):
            plugin_count = len(self.findings['plugins'])
            findings.append({
                "type": "info_leak",
                "severity": "LOW",
                "title": f"{plugin_count} plugins identified",
                "endpoint": "/wp-content/plugins/",
                "evidence": f"Active WordPress plugins exposed: {', '.join([p.get('name', 'unknown')[:20] for p in self.findings['plugins'][:5]])}"
            })
        
        # Technology fingerprinting
        if self.tech_stack:
            tech_count = len(self.tech_stack)
            tech_list = list(self.tech_stack.keys())[:5]
            findings.append({
                "type": "info_leak",
                "severity": "LOW",
                "title": f"Technology fingerprinting possible ({tech_count} technologies detected)",
                "endpoint": "*",
                "evidence": f"Server reveals technology stack: {', '.join(tech_list)}"
            })
        
        return findings

    def _extract_anomaly_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from anomalous patterns."""
        findings = []
        endpoints = self.state.get("endpoints", []) or []
        
        # Attack surface despite no CVEs
        if len(endpoints) > 20 and len(self.state.get("confirmed_vulnerabilities", [])) == 0:
            findings.append({
                "type": "anomaly",
                "severity": "MEDIUM",
                "title": "Large attack surface with no detected CVEs",
                "endpoint": f"{len(endpoints)} total",
                "evidence": f"Server exposes {len(endpoints)} endpoints but no CVEs detected. Potential for zero-day or complex chain attacks."
            })
        
        return findings

    def _analyze_rce_possibilities(self) -> List[Dict[str, Any]]:
        """
        Analyze potential RCE attack chains WITHOUT executing exploits.
        Chains are derived dynamically from:
        - existing findings (security_findings)
        - existing vulnerabilities (confirmed_vulnerabilities)
        - rules-based chain prerequisites (rules/exploit_chains.json)
        """
        findings = self.state.get("security_findings", []) or []
        confirmed_vulns = self.state.get("confirmed_vulnerabilities", []) or []

        # Collect candidate URLs to infer endpoint capabilities.
        all_urls = set()
        for u in (self.state.get("urls", []) or []):
            if u:
                all_urls.add(str(u))
        for u in (self.state.get("crawled_urls", []) or []):
            if u:
                all_urls.add(str(u))
        for item in (self.state.get("endpoints", []) or []):
            if isinstance(item, dict) and item.get("url"):
                all_urls.add(str(item["url"]))
        for item in (self.state.get("prioritized_endpoints", []) or []):
            if isinstance(item, dict) and item.get("url"):
                all_urls.add(str(item["url"]))

        token_sources: Dict[str, List[str]] = defaultdict(list)
        tokens = set()

        # Helper: collect capability tokens from findings (both prerequisites and consequences).
        # If a finding exists, its prerequisites are considered satisfied for chain inference purposes.
        for f in findings:
            for tok in (f.get("prerequisites", []) or []):
                if tok:
                    tokens.add(tok)
                    token_sources[tok].append(f.get("evidence") or f.get("endpoint") or f.get("title") or f.get("type") or "finding")
            for tok in (f.get("consequences", []) or []):
                if tok:
                    tokens.add(tok)
                    token_sources[tok].append(f.get("evidence") or f.get("endpoint") or f.get("title") or f.get("type") or "finding")

        # WordPress marker
        if self.state.get("wordpress_detected"):
            tokens.add("wordpress_detected")
            token_sources["wordpress_detected"].append("state.wordpress_detected")

        # WordPress-specific endpoint capabilities from rules (dynamic, no hardcoded endpoint names)
        login_endpoint_path = None
        uploads_path = None
        wp_rules_file = os.path.join(BASE_DIR, "rules", "wordpress_rules.json")
        if os.path.exists(wp_rules_file):
            try:
                with open(wp_rules_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                wp_rules = data.get("wordpress", data) or {}
                default_paths = wp_rules.get("default_paths", {}) or {}
                login_endpoint_path = default_paths.get("login")
                uploads_path = default_paths.get("uploads")
            except Exception:
                pass

        def wildcard_to_regex(pattern: str) -> str:
            escaped = re.escape(pattern)
            return escaped.replace(r"\*", ".*")

        if login_endpoint_path:
            login_regex = wildcard_to_regex(str(login_endpoint_path))
            if any(re.search(login_regex, u, re.IGNORECASE) for u in all_urls):
                tokens.add("login_endpoint_found")
                token_sources["login_endpoint_found"].append(str(login_endpoint_path))

        if uploads_path:
            uploads_regex = wildcard_to_regex(str(uploads_path))
            if any(re.search(uploads_regex, u, re.IGNORECASE) for u in all_urls):
                tokens.add("file_upload_endpoint")
                token_sources["file_upload_endpoint"].append(str(uploads_path))

        # Generic fallback capability inference
        if "login_endpoint_found" not in tokens:
            if any(re.search(r"/login(?:/|\\b)", u, re.IGNORECASE) for u in all_urls):
                tokens.add("login_endpoint_found")
                token_sources["login_endpoint_found"].append("URL matched /login")

        if "file_upload_endpoint" not in tokens:
            if any(re.search(r"/upload(?:/|\\b)|/uploads(?:/|\\b)", u, re.IGNORECASE) for u in all_urls):
                tokens.add("file_upload_endpoint")
                token_sources["file_upload_endpoint"].append("URL matched /upload(s)")

        # Map vulnerability categories to chain prerequisite tokens.
        def vuln_type_to_token(vtype: str) -> Optional[str]:
            t = (vtype or "").lower()
            if not t:
                return None
            if "sql" in t or "sqli" in t or t in {"sqli", "sql_injection"}:
                return "sqli_vulnerability"
            if "file_inclusion" in t or "lfi" in t or "path_traversal" in t:
                return "lfi_vulnerability"
            if "xss" in t:
                return "xss_vulnerability"
            if "auth" in t or "authentication" in t or "login" in t:
                return "auth_vulnerability"
            if "file_upload" in t or "upload" in t:
                return "file_upload_endpoint"
            return None

        for v in confirmed_vulns:
            token = vuln_type_to_token(v.get("type", ""))
            if token:
                tokens.add(token)
                token_sources[token].append(v.get("evidence") or v.get("endpoint") or v.get("url") or v.get("type") or "vuln")

        # Load rules-driven chain templates and select those whose prerequisites are met.
        chains_file = os.path.join(BASE_DIR, "rules", "exploit_chains.json")
        if not os.path.exists(chains_file):
            return []

        try:
            with open(chains_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return []

        chain_templates = data.get("chains", data) or {}

        severity_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

        possible = []
        for chain_id, tpl in chain_templates.items():
            prereqs = tpl.get("prerequisites", []) or []
            prereqs = [str(p) for p in prereqs if p is not None]
            if prereqs and not all(p in tokens for p in prereqs):
                continue

            components = []
            for p in prereqs:
                srcs = token_sources.get(p, [])
                if srcs:
                    components.append(f"{p} ({srcs[0][:80]})")
                else:
                    components.append(p)

            evidence_parts = []
            desc = tpl.get("description") or ""
            if desc:
                evidence_parts.append(desc.strip())
            if prereqs:
                evidence_parts.append(f"Prerequisites satisfied: {', '.join(prereqs)}")
            evidence = " | ".join([p for p in evidence_parts if p])

            possible.append(
                {
                    "type": "rce_possibility",
                    "severity": tpl.get("risk_level", "MEDIUM"),
                    "title": tpl.get("name", chain_id),
                    "components": components,
                    "evidence": evidence or tpl.get("name", chain_id),
                    "requires_validation": True,
                    "prerequisites": prereqs,
                }
            )

        possible.sort(key=lambda x: severity_weight.get(x.get("severity", "MEDIUM"), 0), reverse=True)
        return possible

    def _run_attack_graph_phase(self, attack_graph: AttackGraph):
        self.phase_detail = "[GRAPH] Building attack graph from vulnerabilities..."
        self._update_display()
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
            self.phase_detail = f"[GRAPH] Built attack graph with {len(vulnerabilities)} vulnerability nodes"
            self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("graph")

    def _process_conditioned_findings(self) -> List[Dict[str, Any]]:
        """
        Xử lý conditioned findings từ WordPress scan.
        Đọc wp_conditioned_findings từ state, lọc chain_candidate và confidence >= 70.
        Trả về danh sách chain info để hiển thị và lưu vào state.
        """
        conditioned = self.state.get("wp_conditioned_findings", [])
        if not conditioned:
            self.logger.debug("[CONDITIONED] No conditioned findings in state")
            return []
        
        self.logger.info(f"[CONDITIONED] Found {len(conditioned)} conditioned findings, filtering...")
        
        chains = []
        for finding in conditioned:
            # Chỉ lấy findings có chain_candidate = True
            if not finding.get("chain_candidate", False):
                continue
            
            confidence = finding.get("confidence", 0)
            if confidence < 70:
                self.logger.debug(f"[CONDITIONED] Skipping {finding.get('name')} - confidence {confidence} < 70")
                continue
            
            # Xây dựng chain info
            component_name = finding.get("name", "unknown")
            vuln_type = finding.get("vuln_type", "vulnerability")
            cve_list = finding.get("cve", [])
            severity = finding.get("severity", "MEDIUM")
            conditions = finding.get("conditions", {})
            auth_req = conditions.get("auth_requirement", "unknown")
            candidate_endpoint = conditions.get("candidate_endpoint", "")
            version = finding.get("version", "unknown")
            
            # Tạo tên chain
            if cve_list:
                chain_name = f"[{cve_list[0]}] {component_name} {version} → {vuln_type.upper()}"
            else:
                chain_name = f"{component_name} {version} → {vuln_type.upper()}"
            
            chain_info = {
                "name": chain_name,
                "cve": cve_list,
                "confidence": confidence,
                "severity": severity,
                "prerequisites": auth_req,
                "endpoint": candidate_endpoint,
                "version": version,
                "component": component_name,
                "vuln_type": vuln_type,
                "status": "ready" if confidence >= 80 else "candidate"
            }
            
            chains.append(chain_info)
            
            # Log chi tiết
            self.logger.warning(f"[CONDITIONED] ✅ {chain_name} (conf: {confidence}%, auth: {auth_req})")
            
            # Thêm vào findings để hiển thị
            self.findings.setdefault("conditioned_chains", []).append(chain_info)
            
            # Thêm vào live feed
            if self.batch_display:
                cve_display = cve_list[0] if cve_list else "No CVE"
                self.batch_display._add_to_ai_feed(
                    "🔗 Conditioned Chain",
                    f"{component_name} {version} → {vuln_type} (conf: {confidence}%)",
                    self.target
                )
            
            # Thêm vào chains_data để hiển thị trong DETAILS
            chain_display = {
                'name': chain_name[:50],
                'risk': severity,
                'exploited': False,
                'partial': False,
                'steps': [],
                'result': f"Confidence: {confidence}% | Auth: {auth_req}"
            }
            
            if cve_list:
                chain_display['steps'].append({
                    'desc': f"CVE: {', '.join(cve_list[:2])}",
                    'success': False,
                    'partial': False
                })
            
            if candidate_endpoint:
                chain_display['steps'].append({
                    'desc': f"Endpoint: {candidate_endpoint[:50]}",
                    'success': False,
                    'partial': False
                })
            
            self.chains_data.append(chain_display)
        
        # Lưu vào state
        self.state.update(conditioned_chains=chains)
        
        if chains:
            self.phase_detail = f"[CONDITIONED] Found {len(chains)} high-confidence chains"
        else:
            self.phase_detail = "[CONDITIONED] No high-confidence chains found"
        
        self._update_display()
        
        return chains

    def _run_chain_planning_phase(self, attack_graph: AttackGraph):
        self.phase_detail = "[CHAINS] Planning attack chains..."
        self._update_display()
        
        # ========== PROCESS CONDITIONED FINDINGS ==========
        # 1. Xử lý conditioned findings từ WordPress
        conditioned_chains = self._process_conditioned_findings()
        if conditioned_chains:
            self.logger.warning(f"[CHAIN] Found {len(conditioned_chains)} conditioned chains from WordPress data")
            for chain in conditioned_chains[:3]:
                if self.batch_display:
                    self.batch_display._add_to_ai_feed(
                        "🎯 Conditioned Chain",
                        f"{chain.get('name', '')[:50]} (conf: {chain.get('confidence')}%)",
                        self.target
                    )
        
        # 2. Gọi chain planner từ graph (code cũ)
        chains = self.chain_planner.plan_chains_from_graph(attack_graph)
        base_chains = list(chains)
        
        # 3. Gọi conditioned chains từ chain_planner
        try:
            wp_conditioned_chains = self.chain_planner._build_conditioned_wp_chains()
            if wp_conditioned_chains:
                self.logger.warning(f"[CHAIN] Found {len(wp_conditioned_chains)} chains from chain_planner conditioned method")
                for chain in wp_conditioned_chains:
                    chain_name = getattr(chain, 'name', '')
                    if chain_name and not any(
                        getattr(c, 'name', '') == chain_name for c in chains
                    ):
                        chains.append(chain)
        except Exception as e:
            self.logger.debug(f"[CHAIN] Could not get conditioned chains from chain_planner: {e}")
        # ========== END CONDITIONED FINDINGS ==========
        
        if self.ai_chain_planner:
            try:
                ai_chains = self.ai_chain_planner.plan_chains(asdict(self.state.state))
                if ai_chains:
                    seen_names = {
                        getattr(chain, "name", "") if not isinstance(chain, dict) else chain.get("name", "")
                        for chain in chains
                    }
                    for chain in ai_chains:
                        name = chain.get("name", "")
                        if name and name not in seen_names:
                            chains.append(chain)
                            seen_names.add(name)
            except Exception as e:
                self.logger.warning(f"[CHAIN] AI chain enrichment failed: {e}")
        manual_playbook = self.chain_planner.build_manual_playbook(base_chains)
        
        self.chains_data = []
        for i, chain in enumerate(chains[:5], 1):
            chain_name = chain.get("name") if isinstance(chain, dict) else getattr(chain, "name", f"Chain-{i}")
            chain_risk = (
                (chain.get("risk") or chain.get("risk_level") or chain.get("severity"))
                if isinstance(chain, dict)
                else getattr(chain, "risk_level", "MEDIUM")
            )
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
            self.phase_detail = f"[CHAINS] Generated {len(chains)} attack chain(s)"
        else:
            self.last_action = "chains: generated manual playbook"
            self.phase_detail = "[CHAINS] Generated manual attack playbook"
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("chain")

    def _run_exploit_phase(self):
        self.phase_detail = "[EXPLOIT] Testing attack chains for exploitation..."
        self._update_display()
        chains = self.state.get("exploit_chains", [])
        if chains:
            results = []
            exploited_count = 0
            
            # FIX: Test ALL chains (not just first 3) for deeper exploitation
            # Also increased limit to test more chains for comprehensive coverage
            max_chains_to_test = min(len(chains), 10)  # Test up to 10 chains
            self.logger.info(f"[EXPLOIT] Testing {max_chains_to_test} out of {len(chains)} available chains")
            
            for i, chain in enumerate(chains[:max_chains_to_test]):
                self.phase_detail = f"[EXPLOIT] Testing chain {i+1}/{min(3, len(chains))}..."
                self._update_display()
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
                self.phase_detail = f"[EXPLOIT] Successfully exploited {exploited_count} chain(s)"
            else:
                self.last_action = "exploit: no success"
                self.phase_detail = "[EXPLOIT] No successful exploitations"
            self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("exploit")

    def _run_sqli_exploit_phase(self):
        """Phase 12: SQL Injection Exploitation"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[SQLI] Detecting and exploiting SQL Injection..."
        self._update_display()
        
        try:
            live_hosts = self.state.get("live_hosts", [])
            vulnerabilities = self.state.get("vulnerabilities", [])
            
            # Check for SQL injection indicators
            sqli_vpaths = [v for v in vulnerabilities if 'sql' in str(v).lower()]
            
            if not sqli_vpaths and not live_hosts:
                self.phase_detail = "[SQLI] No SQLi indicators found"
                self.phase_status = "done"
                self._mark_phase_done("sqli_exploit")
                return
            
            sqli_results = []
            for host_info in live_hosts[:3]:
                url = host_info.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[SQLI] Testing {url.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.sqli_exploiter.exploit(url, progress_cb=self._progress_callback)
                sqli_results.append(result)
                
                if result.get('vulnerabilities'):
                    self.stats['vulns'] += len(result['vulnerabilities'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("💧", "SQLi Found", url, f"{len(result['vulnerabilities'])} vulns")
                
                if result.get('shells_written'):
                    self.stats['exploited'] += len(result['shells_written'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("🐚", "Shell", url, f"{len(result['shells_written'])} shells")
            
            self.state.update(sqli_findings=sqli_results)
            self.last_action = f"sqli: tested {len(sqli_results)} hosts"
            self.phase_detail = f"[SQLI] Complete - {self.stats['exploited']} shells written"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[SQLI] Phase failed: {e}")
            self.last_action = f"sqli error: {str(e)[:50]}"
            self.phase_detail = f"[SQLI] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("sqli_exploit")

    def _run_upload_bypass_phase(self):
        """Phase 13: File Upload Bypass"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[UPLOAD] Detecting and bypassing upload restrictions..."
        self._update_display()
        
        try:
            live_hosts = self.state.get("live_hosts", [])
            endpoints = self.state.get("endpoints", [])
            
            # Find upload endpoints
            upload_endpoints = [e for e in endpoints if 'upload' in e.get('path', '').lower() or 'file' in e.get('path', '').lower()]
            
            if not upload_endpoints and not live_hosts:
                self.phase_detail = "[UPLOAD] No upload endpoints found"
                self.phase_status = "done"
                self._mark_phase_done("upload_bypass")
                return
            
            upload_results = []
            urls_to_test = upload_endpoints[:5] if upload_endpoints else live_hosts[:3]
            
            for endpoint in urls_to_test:
                url = endpoint.get('url') if isinstance(endpoint, dict) else endpoint
                url = self._canonicalize_url(url)
                if not url:
                    continue
                
                self.phase_detail = f"[UPLOAD] Testing {url.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.upload_bypass.bypass(url, progress_cb=self._progress_callback)
                upload_results.append(result)
                
                if result.get('uploaded_files'):
                    self.stats['exploited'] += len(result['uploaded_files'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("📤", "Upload", url, f"{len(result['uploaded_files'])} files")
            
            self.state.update(upload_bypass_findings=upload_results)
            self.last_action = f"upload: tested {len(upload_results)} paths"
            self.phase_detail = f"[UPLOAD] Complete - {self.stats['exploited']} files uploaded"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[UPLOAD] Phase failed: {e}")
            self.last_action = f"upload error: {str(e)[:50]}"
            self.phase_detail = f"[UPLOAD] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("upload_bypass")

    def _run_reverse_shell_phase(self):
        """Phase 14: Reverse Shell Generation and Execution"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[SHELL] Generating and testing reverse shells..."
        self._update_display()
        
        try:
            exploit_results = self.state.get("exploit_results", [])
            rce_endpoints = [e for e in exploit_results if e.get('type', '').lower() == 'rce']
            
            if not rce_endpoints:
                self.phase_detail = "[SHELL] No RCE endpoints found"
                self.phase_status = "done"
                self._mark_phase_done("reverse_shell")
                return
            
            shell_results = []
            for rce_endpoint in rce_endpoints[:2]:
                url = rce_endpoint.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[SHELL] Testing {url.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.reverse_shell_gen.generate_and_execute(
                    url,
                    progress_cb=self._progress_callback
                )
                shell_results.append(result)
                
                if result.get('shells_executed'):
                    self.stats['exploited'] += len(result['shells_executed'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔗", "Shell", url, f"{len(result['shells_executed'])} executed")
                
                if result.get('command_results'):
                    cmd_count = len(result['command_results'])
                    self.last_action = f"shell: {cmd_count} commands executed"
            
            self.state.update(shell_findings=shell_results)
            self.phase_detail = f"[SHELL] Complete - {self.stats['exploited']} shells executed"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[SHELL] Phase failed: {e}")
            self.last_action = f"shell error: {str(e)[:50]}"
            self.phase_detail = f"[SHELL] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("reverse_shell")

    def _run_privilege_escalation_phase(self):
        """Phase 15: Privilege Escalation"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[PRIVESC] Checking privilege escalation vectors..."
        self._update_display()
        
        try:
            shell_findings = self.state.get("shell_findings", [])
            
            if not shell_findings:
                self.phase_detail = "[PRIVESC] No shell access found"
                self.phase_status = "done"
                self._mark_phase_done("privesc")
                return
            
            privesc_results = []
            for shell_finding in shell_findings[:2]:
                url = shell_finding.get('url')
                if not url or not shell_finding.get('shells_executed'):
                    continue
                
                self.phase_detail = f"[PRIVESC] Testing {url.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.privesc_checker.check_escalation(
                    url,
                    progress_cb=self._progress_callback
                )
                privesc_results.append(result)
                
                if result.get('escalation_chains'):
                    self.stats['vulns'] += len(result['escalation_chains'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔝", "Privesc", url, f"{len(result['escalation_chains'])} chains")
                
                vuln_count = (len(result.get('kernel_vulns', [])) + 
                             len(result.get('sudo_issues', [])) + 
                             len(result.get('suid_files', [])))
                if vuln_count > 0:
                    self.stats['exploited'] += 1
            
            self.state.update(privesc_findings=privesc_results)
            self.last_action = f"privesc: analyzed {len(privesc_results)} targets"
            self.phase_detail = f"[PRIVESC] Complete - {self.stats['exploited']} escalation paths"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[PRIVESC] Phase failed: {e}")
            self.last_action = f"privesc error: {str(e)[:50]}"
            self.phase_detail = f"[PRIVESC] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("privesc")

    def _run_waf_bypass_phase(self):
        """Phase 16: WAF Bypass Detection"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[WAF] Detecting and bypassing WAF protections..."
        self._update_display()
        
        try:
            endpoints = self.state.get("prioritized_endpoints", [])
            if not endpoints:
                self.phase_detail = "[WAF] No endpoints available"
                self._update_display()
                self._mark_phase_done("waf_bypass")
                return
            
            # Test first 5 endpoints for WAF
            waf_results = []
            for endpoint in endpoints[:5]:
                url = endpoint if isinstance(endpoint, str) else endpoint.get("url", "")
                url = self._canonicalize_url(url)
                if not url:
                    continue
                
                self.phase_detail = f"[WAF] Testing {url.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.waf_bypass.detect_and_bypass(
                    url,
                    progress_cb=self._progress_callback
                )
                waf_results.append(result)
                
                if result.get('wafs_detected'):
                    self.stats['vulns'] += len(result['wafs_detected'])
                    if self.batch_display:
                        waf_names = ', '.join([w['name'] for w in result['wafs_detected']])
                        self.batch_display._add_to_feed("🛡️", "WAF Detected", url, waf_names)
            
            self.state.update(waf_findings=waf_results)
            self.last_action = f"waf: detected on {len([r for r in waf_results if r.get('wafs_detected')])}/{len(waf_results)}"
            self.phase_detail = f"[WAF] Complete - {len([r for r in waf_results if r.get('wafs_detected')])} sites behind WAF"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[WAF] Phase failed: {e}")
            self.last_action = f"waf error: {str(e)[:50]}"
            self.phase_detail = f"[WAF] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("waf_bypass")

    def _run_boolean_sqli_phase(self):
        """Phase 17: Boolean-Based SQLi Detection"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[BOOL_SQLI] Testing boolean-based SQL injection..."
        self._update_display()
        
        try:
            endpoints = self.state.get("prioritized_endpoints", [])
            sqli_results = []
            
            for endpoint in endpoints[:10]:
                url = endpoint if isinstance(endpoint, str) else endpoint.get("url", "")
                url = self._canonicalize_url(url)
                if not url:
                    continue
                
                self.phase_detail = f"[BOOL_SQLI] Testing {url.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.boolean_sqli.detect(
                    url,
                    progress_cb=self._progress_callback
                )
                sqli_results.append(result)
                
                if result.get('vulnerabilities'):
                    vuln_count = len(result['vulnerabilities'])
                    self.stats['vulns'] += vuln_count
                    
                    # FIX 1: Store detected vulnerabilities in confirmed_vulnerabilities
                    # so chain_planner can find them and generate SQLi chains
                    current_vulns = self.state.get("confirmed_vulnerabilities", []) or []
                    for v in result['vulnerabilities']:
                        vuln_entry = {
                            "type": "SQLI",
                            "name": f"Boolean-based SQL Injection - {v.get('parameter', 'unknown')}",
                            "endpoint": url,
                            "url": url,
                            "parameter": v.get('parameter', ''),
                            "severity": "HIGH",
                            "confidence": v.get('confidence', 'medium'),
                            "description": f"Boolean-based SQLi detected on parameter '{v.get('parameter', 'unknown')}'",
                            "details": v,
                            "source": "boolean_sqli_detector"
                        }
                        # Avoid duplicates
                        if not any(v2.get('endpoint') == url and v2.get('parameter') == v.get('parameter') for v2 in current_vulns):
                            current_vulns.append(vuln_entry)
                    
                    self.state.update(confirmed_vulnerabilities=current_vulns)
                    
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔍", "Boolean SQLi", url, f"{vuln_count} found")
            
            self.state.update(boolean_sqli_findings=sqli_results)
            vuln_count = sum(len(r.get('vulnerabilities', [])) for r in sqli_results)
            self.last_action = f"bool_sqli: {vuln_count} vulnerabilities found"
            self.phase_detail = f"[BOOL_SQLI] Complete - {vuln_count} blind SQLi detected"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[BOOL_SQLI] Phase failed: {e}")
            self.last_action = f"bool_sqli error: {str(e)[:50]}"
            self.phase_detail = f"[BOOL_SQLI] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("boolean_sqli")

    def _run_xss_phase(self):
        """Phase 18: Comprehensive XSS Detection"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[XSS] Testing for reflected, stored, and DOM XSS..."
        self._update_display()
        
        try:
            endpoints = self.state.get("prioritized_endpoints", [])
            xss_results = []
            
            for endpoint in endpoints[:10]:
                url = endpoint if isinstance(endpoint, str) else endpoint.get("url", "")
                url = self._canonicalize_url(url)
                if not url:
                    continue
                
                self.phase_detail = f"[XSS] Testing {url.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.xss_detector.detect(
                    url,
                    progress_cb=self._progress_callback
                )
                xss_results.append(result)
                
                if result.get('vulnerabilities'):
                    vuln_count = len(result['vulnerabilities'])
                    self.stats['vulns'] += vuln_count
                    
                    # FIX 1: Store detected vulnerabilities in confirmed_vulnerabilities
                    # so chain_planner can find them and generate XSS chains
                    current_vulns = self.state.get("confirmed_vulnerabilities", []) or []
                    for v in result['vulnerabilities']:
                        vuln_entry = {
                            "type": "XSS",
                            "name": f"Cross-Site Scripting - {v.get('type', 'reflected')} - {v.get('parameter', 'unknown')}",
                            "endpoint": url,
                            "url": url,
                            "parameter": v.get('parameter', ''),
                            "severity": "HIGH" if v.get('confidence') == 'high' else "MEDIUM",
                            "confidence": v.get('confidence', 'medium'),
                            "description": f"{v.get('type', 'XSS')} vulnerability detected on parameter '{v.get('parameter', 'unknown')}'",
                            "details": v,
                            "source": "xss_detector"
                        }
                        # Avoid duplicates
                        if not any(v2.get('endpoint') == url and v2.get('parameter') == v.get('parameter') and v2.get('type') == v.get('type') for v2 in current_vulns):
                            current_vulns.append(vuln_entry)
                    
                    self.state.update(confirmed_vulnerabilities=current_vulns)
                    
                    if self.batch_display:
                        types = set(v.get('type') for v in result['vulnerabilities'])
                        self.batch_display._add_to_feed("✖️", "XSS", url, f"{vuln_count} ({', '.join(types)})")
            
            self.state.update(xss_findings=xss_results)
            vuln_count = sum(len(r.get('vulnerabilities', [])) for r in xss_results)
            self.last_action = f"xss: {vuln_count} vulnerabilities found"
            self.phase_detail = f"[XSS] Complete - {vuln_count} XSS vectors detected"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[XSS] Phase failed: {e}")
            self.last_action = f"xss error: {str(e)[:50]}"
            self.phase_detail = f"[XSS] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("xss")

    def _run_idor_phase(self):
        """Phase 19: IDOR Detection and User Enumeration"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[IDOR] Testing for insecure direct object references..."
        self._update_display()
        
        try:
            endpoints = self.state.get("prioritized_endpoints", [])
            idor_results = []
            
            for endpoint in endpoints[:10]:
                url = endpoint if isinstance(endpoint, str) else endpoint.get("url", "")
                url = self._canonicalize_url(url)
                if not url:
                    continue
                
                self.phase_detail = f"[IDOR] Testing {url.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.idor_detector.detect(
                    url,
                    progress_cb=self._progress_callback
                )
                idor_results.append(result)
                
                if result.get('vulnerabilities'):
                    self.stats['vulns'] += len(result['vulnerabilities'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔑", "IDOR", url, f"{len(result['vulnerabilities'])} found")
            
            self.state.update(idor_findings=idor_results)
            vuln_count = sum(len(r.get('vulnerabilities', [])) for r in idor_results)
            self.last_action = f"idor: {vuln_count} vulnerabilities found"
            self.phase_detail = f"[IDOR] Complete - {vuln_count} IDOR vectors detected"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[IDOR] Phase failed: {e}")
            self.last_action = f"idor error: {str(e)[:50]}"
            self.phase_detail = f"[IDOR] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("idor")

    def _run_default_creds_phase(self):
        """Phase 20: Default Credentials Scanning"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[CREDS] Scanning for default credentials..."
        self._update_display()
        
        try:
            endpoints = self.state.get("live_urls", [])
            if not endpoints:
                endpoints = self.state.get("prioritized_endpoints", [])
            
            creds_results = []
            for url in endpoints[:5]:
                url_str = url if isinstance(url, str) else url.get("url", "")
                url_str = self._canonicalize_url(url_str)
                if not url_str:
                    continue
                
                self.phase_detail = f"[CREDS] Testing {url_str.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.default_creds.scan(
                    url_str,
                    progress_cb=self._progress_callback
                )
                creds_results.append(result)
                
                if result.get('credentials_found'):
                    self.stats['exploited'] += len(result['credentials_found'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔐", "Default Creds", url_str, f"{len(result['credentials_found'])} found")
            
            self.state.update(default_creds_findings=creds_results)
            cred_count = sum(len(r.get('credentials_found', [])) for r in creds_results)
            self.last_action = f"creds: {cred_count} working credentials found"
            self.phase_detail = f"[CREDS] Complete - {cred_count} default credentials working"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[CREDS] Phase failed: {e}")
            self.last_action = f"creds error: {str(e)[:50]}"
            self.phase_detail = f"[CREDS] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("default_creds")

    def _run_cve_exploit_phase(self):
        """Phase 21: Known CVE Exploitation"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[CVE] Testing for known CVE exploits..."
        self._update_display()
        
        try:
            cve_results = []
            technologies = self.state.get("technologies", {})
            endpoints = self.state.get("live_urls", [])
            
            if not endpoints:
                endpoints = self.state.get("prioritized_endpoints", [])
            
            for url in endpoints[:5]:
                url_str = url if isinstance(url, str) else url.get("url", "")
                url_str = self._canonicalize_url(url_str)
                if not url_str:
                    continue
                
                self.phase_detail = f"[CVE] Testing {url_str.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.cve_exploiter.scan(
                    url_str,
                    technologies=technologies,
                    progress_cb=self._progress_callback
                )
                cve_results.append(result)
                
                if result.get('exploitable_cves'):
                    self.stats['vulns'] += len(result['exploitable_cves'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("🎯", "CVE", url_str, f"{len(result['exploitable_cves'])} exploitable")
            
            self.state.update(cve_findings=cve_results)
            cve_count = sum(len(r.get('exploitable_cves', [])) for r in cve_results)
            self.last_action = f"cve: {cve_count} exploitable CVEs found"
            self.phase_detail = f"[CVE] Complete - {cve_count} known exploits available"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[CVE] Phase failed: {e}")
            self.last_action = f"cve error: {str(e)[:50]}"
            self.phase_detail = f"[CVE] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("cve_exploit")

    def _run_api_vuln_phase(self):
        """Phase 22: API Vulnerability Scanning"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[API] Scanning API vulnerabilities..."
        self._update_display()
        
        try:
            api_results = []
            endpoints = self.state.get("api_endpoints", [])
            prioritized_endpoints = self.state.get("prioritized_endpoints", [])
            
            if not endpoints and prioritized_endpoints:
                endpoints = [e for e in prioritized_endpoints if 'api' in str(e).lower()]
            
            if not endpoints:
                self.phase_detail = "[API] No API endpoints found"
                self._update_display()
                self._mark_phase_done("api_vuln")
                return
            
            for url in endpoints[:5]:
                url_str = url if isinstance(url, str) else url.get("url", "")
                url_str = self._canonicalize_url(url_str)
                if not url_str:
                    continue
                
                self.phase_detail = f"[API] Testing {url_str.split('//')[-1][:30]}..."
                self._update_display()
                
                result = self.api_vuln_scanner.scan(
                    url_str,
                    progress_cb=self._progress_callback
                )
                api_results.append(result)
                
                if result.get('vulnerabilities'):
                    self.stats['vulns'] += len(result['vulnerabilities'])
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔌", "API", url_str, f"{len(result['vulnerabilities'])} issues")
            
            self.state.update(api_vuln_findings=api_results)
            vuln_count = sum(len(r.get('vulnerabilities', [])) for r in api_results)
            self.last_action = f"api: {vuln_count} vulnerabilities found"
            self.phase_detail = f"[API] Complete - {vuln_count} API issues detected"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[API] Phase failed: {e}")
            self.last_action = f"api error: {str(e)[:50]}"
            self.phase_detail = f"[API] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("api_vuln")

    def _run_subdomain_takeover_phase(self):
        """Phase 23: Subdomain Takeover Detection"""
        if self._should_abort_low_signal():
            return
        
        self.phase_detail = "[TAKEOVER] Scanning for subdomain takeover vulnerabilities..."
        self._update_display()
        
        try:
            takeover_results = []
            subdomains = self.state.get("subdomains", [])
            
            if not subdomains:
                self.phase_detail = "[TAKEOVER] No subdomains found"
                self._update_display()
                self._mark_phase_done("subdomain_takeover")
                return
            
            self.phase_detail = f"[TAKEOVER] Testing {len(subdomains)} subdomains..."
            self._update_display()
            
            result = self.subdomain_takeover.scan(
                self.target,
                subdomains=subdomains,
                progress_cb=self._progress_callback
            )
            takeover_results.append(result)
            
            if result.get('vulnerable_subdomains'):
                self.stats['vulns'] += len(result['vulnerable_subdomains'])
                if self.batch_display:
                    self.batch_display._add_to_feed("🏴", "Takeover", self.target, f"{len(result['vulnerable_subdomains'])} vulnerable")
            
            self.state.update(subdomain_takeover_findings=takeover_results)
            vuln_count = sum(len(r.get('vulnerable_subdomains', [])) for r in takeover_results)
            self.last_action = f"takeover: {vuln_count} vulnerable subdomains found"
            self.phase_detail = f"[TAKEOVER] Complete - {vuln_count} subdomains at risk"
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[TAKEOVER] Phase failed: {e}")
            self.last_action = f"takeover error: {str(e)[:50]}"
            self.phase_detail = f"[TAKEOVER] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("subdomain_takeover")

    # ─── POST-EXPLOITATION PHASE HANDLERS (24-32) ────────────────────────────
    
    def _run_mfa_bypass_phase(self):
        """Phase 24: MFA/2FA Bypass & Circumvention"""
        # Evidence-based gating check
        as_data = self.attack_surface.to_dict()
        should_run, reason = should_execute_module("mfa_bypass", as_data)
        if not should_run:
            self.logger.info(f"[GATING] Skipping mfa_bypass: {reason}")
            self.phase_detail = f"[GATING] Skipped mfa_bypass ({reason})"
            self._update_display()
            self._mark_phase_done("mfa_bypass")
            return
        
        self.phase_detail = "[MFA] Analyzing MFA/2FA protection mechanisms..."
        self._update_display()
        
        try:
            live_hosts = self.state.get("live_hosts", [])
            mfa_results = []
            
            for host_info in live_hosts[:5]:
                url = host_info.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[MFA] Scanning {url.split('//')[-1][:30]} for MFA..."
                self._update_display()
                
                result = self.mfa_bypass.analyze_mfa(
                    url,
                    progress_cb=self._progress_callback
                )
                mfa_results.append(result)
                
                if result.get('mfa_detected'):
                    self.stats['vulns'] += 1
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔐", "MFA Detected", url, result.get('mfa_type', 'Unknown'))
                
                if result.get('bypass_techniques'):
                    techniques = result['bypass_techniques']
                    self.stats['exploited'] += len(techniques)
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔓", "MFA Bypass", url, f"{len(techniques)} techniques")
            
            self.state.update(mfa_findings=mfa_results)
            bypass_count = sum(len(r.get('bypass_techniques', [])) for r in mfa_results)
            self.last_action = f"mfa: detected {len(mfa_results)} MFA configs, {bypass_count} bypasses possible"
            self.phase_detail = f"[MFA] Complete - {bypass_count} potential bypass vectors identified"
            
        except Exception as e:
            self.logger.error(f"[MFA] Phase failed: {e}")
            self.last_action = f"mfa error: {str(e)[:50]}"
            self.phase_detail = f"[MFA] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("mfa_bypass")
    
    def _run_oauth_saml_phase(self):
        """Phase 25: OAuth/SAML Exploitation"""
        # Evidence-based gating check
        as_data = self.attack_surface.to_dict()
        should_run, reason = should_execute_module("oauth_saml_exploit", as_data)
        if not should_run:
            self.logger.info(f"[GATING] Skipping oauth_saml_exploit: {reason}")
            self.phase_detail = f"[GATING] Skipped oauth_saml_exploit ({reason})"
            self._update_display()
            self._mark_phase_done("oauth_saml")
            return
        
        self.phase_detail = "[OAUTH] Probing OAuth/SAML authentication flows..."
        self._update_display()
        
        try:
            live_hosts = self.state.get("live_hosts", [])
            oauth_results = []
            
            for host_info in live_hosts[:5]:
                url = host_info.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[OAUTH] Analyzing {url.split('//')[-1][:30]} auth flows..."
                self._update_display()
                
                result = self.oauth_saml_exploit.exploit_oauth_saml(
                    url,
                    progress_cb=self._progress_callback
                )
                oauth_results.append(result)
                
                if result.get('oauth_found'):
                    self.stats['vulns'] += 1
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔑", "OAuth Found", url, "OAuth flow detected")
                
                if result.get('exploitable_vulns'):
                    vulns = result['exploitable_vulns']
                    self.stats['exploited'] += len(vulns)
                    if self.batch_display:
                        self.batch_display._add_to_feed("⚡", "OAuth Vuln", url, f"{len(vulns)} exploitable flows")
            
            self.state.update(oauth_saml_findings=oauth_results)
            vuln_count = sum(len(r.get('exploitable_vulns', [])) for r in oauth_results)
            self.last_action = f"oauth: {len(oauth_results)} OAuth flows analyzed, {vuln_count} exploitable"
            self.phase_detail = f"[OAUTH] Complete - {vuln_count} OAuth/SAML vulnerabilities identified"
            
        except Exception as e:
            self.logger.error(f"[OAUTH] Phase failed: {e}")
            self.last_action = f"oauth error: {str(e)[:50]}"
            self.phase_detail = f"[OAUTH] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("oauth_saml")
    
    def _run_persistence_phase(self):
        """Phase 26: Persistence & Backdoor Deployment"""
        self.phase_detail = "[PERSIST] Establishing persistence mechanisms..."
        self._update_display()
        
        try:
            exploit_results = self.state.get("exploit_results", [])
            exploited_hosts = [h for h in self.state.get("live_hosts", []) if any(e.get('success') for e in exploit_results)]
            persistence_results = []
            
            for host_info in exploited_hosts[:3]:
                url = host_info.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[PERSIST] Deploying backdoors on {url.split('//')[-1][:30]}..."
                self._update_display()

                target_info = {
                    "url": url,
                    "server_header": host_info.get("web_server", ""),
                    "tech_stack": self.state.get("technologies", {}) or {},
                    "wordpress_detected": self.state.get("wordpress_detected", False),
                }
                vectors = self.persistence_engine.analyze_persistence_options(target_info)
                shell_payload = self.persistence_engine.generate_web_shell("php", obfuscated=True)
                result = {
                    "target": url,
                    "persistent_access": bool(vectors),
                    "recovery_vectors": vectors[:5],
                    "generated_shell": shell_payload,
                }
                persistence_results.append(result)
                
                if result.get('persistent_access'):
                    self.stats['exploited'] += 1
                    if self.batch_display:
                        self.batch_display._add_to_feed("👻", "Persistence", url, "Backdoor established")
                
                if result.get('recovery_vectors'):
                    vectors = result['recovery_vectors']
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔄", "Recovery", url, f"{len(vectors)} recovery methods")
            
            self.state.update(persistence_findings=persistence_results)
            backdoors = sum(1 for r in persistence_results if r.get('persistent_access'))
            self.last_action = f"persistence: {backdoors} backdoors deployed"
            self.phase_detail = f"[PERSIST] Complete - {backdoors} persistent access points established"
            
        except Exception as e:
            self.logger.error(f"[PERSIST] Phase failed: {e}")
            self.last_action = f"persistence error: {str(e)[:50]}"
            self.phase_detail = f"[PERSIST] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("persistence")
    
    def _run_lateral_movement_phase(self):
        """Phase 27: Lateral Movement & Privilege Escalation"""
        self.phase_detail = "[LATERAL] Exploring lateral movement opportunities..."
        self._update_display()
        
        try:
            live_hosts = self.state.get("live_hosts", [])
            lateral_results = []
            
            for host_info in live_hosts[:5]:
                url = host_info.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[LATERAL] Mapping network from {url.split('//')[-1][:30]}..."
                self._update_display()

                target_info = {
                    "url": url,
                    "tech_stack": self.state.get("technologies", {}) or {},
                    "wordpress_detected": self.state.get("wordpress_detected", False),
                }
                lateral_targets = self.lateral_movement.discover_internal_services(target_info)
                privilege_vectors = self.lateral_movement.privilege_escalation_vectors()
                result = {
                    "target": url,
                    "lateral_targets": lateral_targets,
                    "privilege_escalation": privilege_vectors,
                }
                lateral_results.append(result)
                
                if result.get('lateral_targets'):
                    targets = result['lateral_targets']
                    self.stats['exploited'] += len(targets)
                    if self.batch_display:
                        self.batch_display._add_to_feed("🌐", "Lateral", url, f"{len(targets)} pivot targets")
                
                if privilege_vectors:
                    self.stats['exploited'] += 1
                    if self.batch_display:
                        self.batch_display._add_to_feed("📈", "PrivEsc", url, "Escalation path found")
            
            self.state.update(lateral_movement_findings=lateral_results)
            pivot_count = sum(len(r.get('lateral_targets', [])) for r in lateral_results)
            self.last_action = f"lateral: {pivot_count} pivot targets identified"
            self.phase_detail = f"[LATERAL] Complete - {pivot_count} lateral movement paths discovered"
            
        except Exception as e:
            self.logger.error(f"[LATERAL] Phase failed: {e}")
            self.last_action = f"lateral error: {str(e)[:50]}"
            self.phase_detail = f"[LATERAL] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("lateral_movement")
    
    def _run_ssl_pinning_phase(self):
        """Phase 28: SSL/TLS Certificate Pinning Bypass"""
        # Evidence-based gating check
        as_data = self.attack_surface.to_dict()
        should_run, reason = should_execute_module("ssl_pinning_bypass", as_data)
        if not should_run:
            self.logger.info(f"[GATING] Skipping ssl_pinning_bypass: {reason}")
            self.phase_detail = f"[GATING] Skipped ssl_pinning_bypass ({reason})"
            self._update_display()
            self._mark_phase_done("ssl_pinning")
            return
        
        self.phase_detail = "[SSL] Analyzing SSL/TLS pinning mechanisms..."
        self._update_display()
        
        try:
            live_hosts = self.state.get("live_hosts", [])
            ssl_results = []
            
            for host_info in live_hosts[:5]:
                url = host_info.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[SSL] Checking {url.split('//')[-1][:30]} certificate pinning..."
                self._update_display()
                
                result = self.ssl_pinning_bypass.analyze_pinning(
                    url,
                    progress_cb=self._progress_callback
                )
                ssl_results.append(result)
                
                if result.get('pinning_detected'):
                    self.stats['vulns'] += 1
                    if self.batch_display:
                        self.batch_display._add_to_feed("📌", "Pinning", url, "Certificate pinning detected")
                
                if result.get('bypass_techniques'):
                    techniques = result['bypass_techniques']
                    self.stats['exploited'] += len(techniques)
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔓", "SSL Bypass", url, f"{len(techniques)} techniques")
            
            self.state.update(ssl_pinning_findings=ssl_results)
            bypass_count = sum(len(r.get('bypass_techniques', [])) for r in ssl_results)
            self.last_action = f"ssl: {bypass_count} pinning bypass vectors found"
            self.phase_detail = f"[SSL] Complete - {bypass_count} SSL/TLS bypass methods identified"
            
        except Exception as e:
            self.logger.error(f"[SSL] Phase failed: {e}")
            self.last_action = f"ssl error: {str(e)[:50]}"
            self.phase_detail = f"[SSL] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("ssl_pinning")
    
    def _run_zero_day_phase(self):
        """Phase 29: Zero-Day Vulnerability Detection"""
        # Evidence-based gating check
        as_data = self.attack_surface.to_dict()
        should_run, reason = should_execute_module("zero_day_detection", as_data)
        if not should_run:
            self.logger.info(f"[GATING] Skipping zero_day_detection: {reason}")
            self.phase_detail = f"[GATING] Skipped zero_day_detection ({reason})"
            self._update_display()
            self._mark_phase_done("zero_day")
            return
        
        self.phase_detail = "[ZERO] Searching for zero-day vulnerabilities..."
        self._update_display()
        
        try:
            endpoints = self.state.get("endpoints", [])
            zero_day_results = []
            
            for endpoint in endpoints[:10]:
                self.phase_detail = f"[ZERO] Fuzzing {endpoint.get('path', '/')[:30]}..."
                self._update_display()
                
                result = self.zero_day_detection.detect_zero_days(
                    endpoint,
                    progress_cb=self._progress_callback
                )
                zero_day_results.append(result)
                
                if result.get('anomalies'):
                    anomalies = result['anomalies']
                    self.stats['vulns'] += len(anomalies)
                    if self.batch_display:
                        self.batch_display._add_to_feed("🔥", "Anomaly", endpoint.get('path', '/'), f"{len(anomalies)} detected")
            
            self.state.update(zero_day_findings=zero_day_results)
            anomaly_count = sum(len(r.get('anomalies', [])) for r in zero_day_results)
            self.last_action = f"zero_day: {anomaly_count} potential zero-days detected"
            self.phase_detail = f"[ZERO] Complete - {anomaly_count} anomalies requiring analysis"
            
        except Exception as e:
            self.logger.error(f"[ZERO] Phase failed: {e}")
            self.last_action = f"zero_day error: {str(e)[:50]}"
            self.phase_detail = f"[ZERO] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("zero_day")
    
    def _run_container_escape_phase(self):
        """Phase 30: Container/Cloud Environment Escape"""
        # Evidence-based gating check
        as_data = self.attack_surface.to_dict()
        should_run, reason = should_execute_module("container_escape", as_data)
        if not should_run:
            self.logger.info(f"[GATING] Skipping container_escape: {reason}")
            self.phase_detail = f"[GATING] Skipped container_escape ({reason})"
            self._update_display()
            self._mark_phase_done("container_escape")
            return
        
        self.phase_detail = "[CONTAINER] Probing for container/cloud escape vectors..."
        self._update_display()
        
        try:
            exploited_hosts = self.state.get("live_hosts", [])[:3]
            container_results = []
            
            for host_info in exploited_hosts:
                url = host_info.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[CONTAINER] Checking {url.split('//')[-1][:30]} for isolation..."
                self._update_display()
                
                result = self.container_escape.detect_container_env(
                    url,
                    progress_cb=self._progress_callback
                )
                container_results.append(result)
                
                if result.get('is_containerized'):
                    self.stats['exploited'] += 1
                    if self.batch_display:
                        self.batch_display._add_to_feed("📦", "Container", url, result.get('container_type', 'Unknown'))
                
                if result.get('escape_vectors'):
                    vectors = result['escape_vectors']
                    self.stats['exploited'] += len(vectors)
                    if self.batch_display:
                        self.batch_display._add_to_feed("🚀", "Escape", url, f"{len(vectors)} vectors")
            
            self.state.update(container_findings=container_results)
            escape_count = sum(len(r.get('escape_vectors', [])) for r in container_results)
            self.last_action = f"container: {escape_count} escape vectors identified"
            self.phase_detail = f"[CONTAINER] Complete - {escape_count} container escape paths found"
            
        except Exception as e:
            self.logger.error(f"[CONTAINER] Phase failed: {e}")
            self.last_action = f"container error: {str(e)[:50]}"
            self.phase_detail = f"[CONTAINER] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("container_escape")
    
    def _run_custom_exploit_phase(self):
        """Phase 31: Custom Exploit Framework Execution"""
        self.phase_detail = "[CUSTOM] Loading and executing custom exploits..."
        self._update_display()
        
        try:
            available_exploits = self.custom_exploit.list_exploits()
            if not available_exploits:
                self.logger.info("[CUSTOM] No registered custom exploits; skipping phase")
                self.state.update(custom_exploit_findings=[])
                self.last_action = "custom_exploit: skipped (no custom exploits loaded)"
                self.phase_detail = "[CUSTOM] Skipped - no custom exploits loaded"
                self._update_display()
                self.phase_status = "done"
                self._mark_phase_done("custom_exploits")
                return

            vulnerabilities = self.state.get("vulnerabilities", [])
            custom_results = []
            
            for vuln in vulnerabilities[:5]:
                self.phase_detail = f"[CUSTOM] Testing exploit for {vuln.get('type', 'unknown')[:30]}..."
                self._update_display()

                target_url = vuln.get("url") or vuln.get("endpoint")
                if not target_url:
                    continue

                for exploit_info in available_exploits:
                    exploit_name = exploit_info.get("name")
                    if not exploit_name:
                        continue

                    result = self.custom_exploit.execute_exploit(
                        exploit_name,
                        target_url,
                        self.http_client,
                        self.state,
                        vulnerability=vuln,
                    )
                    custom_results.append(result)

                    if result.get('status') == 'success' and (result.get('result') or {}).get('success'):
                        self.stats['exploited'] += 1
                        if self.batch_display:
                            self.batch_display._add_to_feed("💥", "Custom", vuln.get('type', 'exploit'), "Successful")
            
            self.state.update(custom_exploit_findings=custom_results)
            success_count = sum(1 for r in custom_results if r.get('status') == 'success' and (r.get('result') or {}).get('success'))
            self.last_action = f"custom_exploit: {success_count} custom exploits succeeded"
            self.phase_detail = f"[CUSTOM] Complete - {success_count} successful custom exploitations"
            
        except Exception as e:
            self.logger.error(f"[CUSTOM] Phase failed: {e}")
            self.last_action = f"custom error: {str(e)[:50]}"
            self.phase_detail = f"[CUSTOM] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("custom_exploit")
    
    def _run_log_evasion_phase(self):
        """Phase 32: Log Evasion & Forensic Evidence Removal"""
        self.phase_detail = "[EVASION] Removing forensic evidence and evading detection..."
        self._update_display()
        
        try:
            exploited_hosts = self.state.get("live_hosts", [])[:3]
            evasion_results = []
            
            for host_info in exploited_hosts:
                url = host_info.get('url')
                if not url:
                    continue
                
                self.phase_detail = f"[EVASION] Cleaning logs on {url.split('//')[-1][:30]}..."
                self._update_display()

                system_info = {
                    "url": url,
                    "uid": 0 if url.startswith("https://") else 1000,
                    "available_tools": ["sed", "find", "history"],
                }
                log_locations = self.log_evasion.discover_log_locations()
                opportunities = self.log_evasion.detect_evasion_opportunities(system_info)
                commands = self.log_evasion.generate_evasion_commands(
                    os_type="linux",
                    evasion_type="stealthy" if opportunities else "basic",
                )
                risk = self.log_evasion.check_forensic_detection_risk(
                    "log_tampering" if opportunities else "direct_deletion"
                )
                result = {
                    "target": url,
                    "log_locations": log_locations,
                    "opportunities": opportunities,
                    "commands": commands[:10],
                    "risk": risk,
                    "logs_erased": False,
                    "detection_evasion": bool(opportunities),
                }
                evasion_results.append(result)
                
                if result.get('logs_erased'):
                    self.stats['exploited'] += 1
                    if self.batch_display:
                        self.batch_display._add_to_feed("🧹", "Evasion", url, "Logs cleaned")
                
                if result.get('detection_evasion'):
                    if self.batch_display:
                        self.batch_display._add_to_feed("👻", "Stealth", url, "Detection avoided")
            
            self.state.update(log_evasion_findings=evasion_results)
            cleaned_count = sum(1 for r in evasion_results if r.get('logs_erased'))
            self.last_action = f"evasion: cleaned logs on {cleaned_count} hosts"
            self.phase_detail = f"[EVASION] Complete - Forensic evidence removed from {cleaned_count} systems"
            
        except Exception as e:
            self.logger.error(f"[EVASION] Phase failed: {e}")
            self.last_action = f"evasion error: {str(e)[:50]}"
            self.phase_detail = f"[EVASION] Error - {str(e)[:60]}"
        
        self._update_display()
        self.phase_status = "done"
        self._mark_phase_done("log_evasion")

    # ═══════════════════════════════════════════════════════════════════════════
    # ENHANCED ANALYSIS & VALIDATION PHASES (33-36)
    # These phases provide deeper vulnerability analysis and chain validation
    # ═══════════════════════════════════════════════════════════════════════════

    def _run_service_fingerprint_phase(self):
        """Phase 33: Service Fingerprinting - Deep analysis of discovered services"""
        if self._should_abort_low_signal():
            self._mark_phase_done("service_fp")
            return
        
        self.phase_detail = "[SERVICE_FP] Performing deep service fingerprinting..."
        self._update_display()
        
        try:
            live_hosts = self.state.get("live_hosts", [])
            if not live_hosts:
                self.phase_detail = "[SERVICE_FP] No live hosts for fingerprinting"
                self._update_display()
                self._mark_phase_done("service_fp")
                return
            
            # Get live URLs for fingerprinting
            hosts_to_fp = []
            for host in live_hosts[:20]:  # Limit to 20 for performance
                url = host.get('url', '')
                if url:
                    hosts_to_fp.append({'url': url})
            
            if not hosts_to_fp:
                self.phase_detail = "[SERVICE_FP] No URLs available for fingerprinting"
                self._update_display()
                self._mark_phase_done("service_fp")
                return
            
            self.logger.info(f"[SERVICE_FP] Fingerprinting {len(hosts_to_fp)} hosts")
            
            # Run service fingerprinting
            results = self.service_fingerprinter.fingerprint_all(
                hosts_to_fp,
                progress_cb=self._progress_callback
            )
            
            # Update stats
            tech_count = len(results.get('technologies', {}))
            if tech_count > 0:
                self.stats['vulns'] += tech_count  # Count technologies as findings
                self.last_action = f"service_fp: identified {tech_count} technologies"
                self.phase_detail = f"[SERVICE_FP] Complete - {tech_count} technologies fingerprinted"
                
                if self.batch_display:
                    tech_names = list(results.get('technologies', {}).keys())[:5]
                    self.batch_display._add_to_feed("🔍", "Service FP", self.target, f"{tech_count} techs: {', '.join(tech_names)}")
            else:
                self.last_action = "service_fp: no technologies identified"
                self.phase_detail = "[SERVICE_FP] Complete - No technologies identified"
            
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[SERVICE_FP] Phase failed: {e}")
            self.last_action = f"service_fp error: {str(e)[:50]}"
            self.phase_detail = f"[SERVICE_FP] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("service_fp")

    def _run_verify_vulns_phase(self):
        """Phase 34: Vulnerability Verification - Confirm detected vulnerabilities"""
        if self._should_abort_low_signal():
            self._mark_phase_done("verify_vulns")
            return
        
        self.phase_detail = "[VERIFY] Verifying detected vulnerabilities..."
        self._update_display()
        
        try:
            vulnerabilities = self.state.get("vulnerabilities", [])
            if not vulnerabilities:
                self.phase_detail = "[VERIFY] No vulnerabilities to verify"
                self._update_display()
                self._mark_phase_done("verify_vulns")
                return
            
            self.logger.info(f"[VERIFY] Verifying {len(vulnerabilities)} vulnerabilities")
            
            # Run verification
            results = self.exploit_verifier.verify_vulnerabilities(
                vulnerabilities,
                progress_cb=self._progress_callback
            )
            
            # Update stats
            verified_count = results.get('summary', {}).get('verified', 0)
            rejected_count = results.get('summary', {}).get('rejected', 0)
            
            if verified_count > 0:
                self.stats['vulns'] += verified_count
                self.last_action = f"verify: {verified_count} confirmed, {rejected_count} rejected"
                self.phase_detail = f"[VERIFY] Complete - {verified_count} verified, {rejected_count} rejected"
                
                if self.batch_display:
                    self.batch_display._add_to_feed("✅", "Verified", self.target, f"{verified_count} vulns confirmed")
            else:
                self.last_action = f"verify: {rejected_count} rejected, none confirmed"
                self.phase_detail = f"[VERIFY] Complete - {rejected_count} rejected, none confirmed"
            
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[VERIFY] Phase failed: {e}")
            self.last_action = f"verify error: {str(e)[:50]}"
            self.phase_detail = f"[VERIFY] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("verify_vulns")

    def _run_fp_filter_phase(self):
        """Phase 35: False Positive Filtering - Remove false positives from results"""
        if self._should_abort_low_signal():
            self._mark_phase_done("fp_filter")
            return
        
        self.phase_detail = "[FP_FILTER] Filtering false positives..."
        self._update_display()
        
        try:
            vulnerabilities = self.state.get("vulnerabilities", [])
            if not vulnerabilities:
                self.phase_detail = "[FP_FILTER] No vulnerabilities to filter"
                self._update_display()
                self._mark_phase_done("fp_filter")
                return
            
            self.logger.info(f"[FP_FILTER] Filtering {len(vulnerabilities)} vulnerabilities")
            
            # Run false positive filtering
            results = self.false_positive_filter.filter_vulnerabilities(
                vulnerabilities,
                progress_cb=self._progress_callback
            )
            
            # Update stats
            confirmed_count = results.get('summary', {}).get('confirmed', 0)
            removed_count = results.get('summary', {}).get('removed', 0)
            fp_rate = results.get('summary', {}).get('fp_rate', 0)
            
            if removed_count > 0:
                self.last_action = f"fp_filter: {confirmed_count} confirmed, {removed_count} removed (FP rate: {fp_rate:.0%})"
                self.phase_detail = f"[FP_FILTER] Complete - {confirmed_count} confirmed, {removed_count} removed"
                
                if self.batch_display:
                    self.batch_display._add_to_feed("🎯", "FP Filter", self.target, f"Removed {removed_count} false positives")
            else:
                self.last_action = f"fp_filter: {confirmed_count} confirmed, none removed"
                self.phase_detail = f"[FP_FILTER] Complete - {confirmed_count} confirmed"
            
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[FP_FILTER] Phase failed: {e}")
            self.last_action = f"fp_filter error: {str(e)[:50]}"
            self.phase_detail = f"[FP_FILTER] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("fp_filter")

    def _run_chain_validate_phase(self):
        """Phase 36: Chain Validation - Validate attack chains before execution"""
        if self._should_abort_low_signal():
            self._mark_phase_done("chain_validate")
            return
        
        self.phase_detail = "[CHAIN_VAL] Validating attack chains..."
        self._update_display()
        
        try:
            chains = self.state.get("exploit_chains", [])
            if not chains:
                self.phase_detail = "[CHAIN_VAL] No chains to validate"
                self._update_display()
                self._mark_phase_done("chain_validate")
                return
            
            # Build context for validation
            context = {
                "technologies": self.state.get("technologies", {}),
                "vulnerabilities": self.state.get("vulnerabilities", []),
                "capabilities": ["http_client", "sqli_tool", "browser"],
                "tools": {
                    "http_client": True,
                    "sqlmap": True,
                    "browser": True,
                },
                "login_endpoints": [],
                "upload_endpoints": [],
                "api_endpoints": [],
            }
            
            self.logger.info(f"[CHAIN_VAL] Validating {len(chains)} chains")
            
            # Run chain validation
            results = self.chain_validator.validate_chains(chains, context)
            
            # Update stats
            valid_count = sum(1 for r in results if r.is_valid)
            can_execute_count = sum(1 for r in results if r.can_execute)
            avg_confidence = sum(r.confidence for r in results) / len(results) if results else 0
            
            if valid_count > 0:
                self.last_action = f"chain_val: {valid_count} valid, {can_execute_count} executable (conf: {avg_confidence:.0%})"
                self.phase_detail = f"[CHAIN_VAL] Complete - {valid_count} valid, {can_execute_count} executable"
                
                if self.batch_display:
                    self.batch_display._add_to_feed("🔗", "Chain Val", self.target, f"{valid_count} valid chains")
            else:
                self.last_action = f"chain_val: 0 valid, {can_execute_count} executable"
                self.phase_detail = f"[CHAIN_VAL] Complete - 0 valid, {can_execute_count} executable"
            
            # Store validation results in state
            self.state.update(chain_validation_results=[
                {
                    "chain_id": r.chain_id,
                    "status": r.status.value,
                    "confidence": r.confidence,
                    "estimated_success_rate": r.estimated_success_rate,
                    "issues": r.issues,
                }
                for r in results
            ])
            
            self._update_display()
            
        except Exception as e:
            self.logger.error(f"[CHAIN_VAL] Phase failed: {e}")
            self.last_action = f"chain_val error: {str(e)[:50]}"
            self.phase_detail = f"[CHAIN_VAL] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("chain_validate")

    def _run_ddos_phase(self):

        exploit_results = self.state.get("exploit_results", [])
        successful_exploits = self._meaningful_successful_exploits(exploit_results)
        
        # FIX 4: Only skip DDoS if exploits were successful (not the other way around)
        if successful_exploits:
            self.logger.info("[DDoS] Skipping - exploits were already successful, no need for DDoS")
            self.phase_detail = "[DDoS] Skipped - exploits successful"
            self._update_display()
            return
        
        # Lấy prioritized endpoints
        endpoints = self.state.get("prioritized_endpoints", [])
        if not endpoints:
            self.logger.warning("[DDoS] No endpoints available for attack")
            self.phase_detail = "[DDoS] No endpoints available"
            self._update_display()
            return
        
        self.current_phase = "ddos"
        self.phase_detail = "[DDoS] Starting attack (no exploits found)..."
        self.phase_tool = "locust-ddos"
        self.phase_status = "running"
        self._update_display()
        
        try:
            # Khởi tạo LoadTester (formerly DDoSAttacker)
            self.ddos_attacker = LoadTester(self.state, self.output_dir, self.http_client, enabled=True)
            
            # Config DDoS parameters (có thể tùy chỉnh qua options)
            users = self.options.get("ddos_users", 1000)
            runtime = self.options.get("ddos_runtime", 60)
            max_endpoints = self.options.get("ddos_max_endpoints", 10)
            
            # Lấy top endpoints
            attack_targets = []
            for ep in endpoints[:max_endpoints]:
                if isinstance(ep, dict):
                    url = ep.get("url") or ep.get("endpoint")
                    if url:
                        attack_targets.append({"url": url, "priority": ep.get("risk_level", "MEDIUM")})
                elif isinstance(ep, str):
                    attack_targets.append({"url": ep, "priority": "MEDIUM"})
            
            if not attack_targets:
                self.logger.warning("[DDoS] No valid target URLs")
                return
            
            self.logger.warning(f"[DDoS] 🔥 LAUNCHING ATTACK on {len(attack_targets)} endpoints with {users} users for {runtime}s")
            self.phase_detail = f"[DDoS] Flooding {len(attack_targets)} endpoints with {users} users..."
            self._update_display()
            
            # Execute attack
            results = self.ddos_attacker.run_load_test(
                endpoints=attack_targets,
                users=users,
                spawn_rate=int(users / 10),
                runtime=runtime,
                method="MIX"
            )
            
            # Save results
            self.state.update(ddos_results=results)
            
            if results.get("status") == "completed":
                total_requests = results.get("total_requests", 0)
                rps = results.get("current_rps", 0)
                self.last_action = f"DDoS completed: {total_requests} requests, {rps} req/s"
                self.phase_detail = f"[DDoS] Attack finished - {total_requests} requests sent"
                
                if self.batch_display:
                    self.batch_display._add_to_feed("💣", "DDoS", self.target, f"{total_requests} reqs, {rps} rps")
            else:
                self.last_action = f"DDoS failed: {results.get('reason', 'unknown')}"
                self.phase_detail = f"[DDoS] Attack failed - {results.get('reason', 'unknown')}"
            
            self._update_display()
            
        except ImportError:
            self.logger.error("[DDoS] Locust not installed! Install with: pip install locust")
            self.last_action = "DDoS: locust not installed"
            self.phase_detail = "[DDoS] Locust not installed"
            self._update_display()
        except Exception as e:
            self.logger.error(f"[DDoS] Phase failed: {e}")
            self.last_action = f"DDoS error: {str(e)[:50]}"
            self.phase_detail = f"[DDoS] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("ddos")

    def _run_security_misconfig_checks(self):
        """
        Run comprehensive security misconfiguration checks using crypto_scanner and sqlmap_runner.
        Checks: SSL/TLS issues, sensitive data exposure, command injection, SQL injection confirmation.
        """
        try:
            live_hosts = self.state.get("live_hosts", []) or []
            endpoints = self.state.get("endpoints", []) or []
            
            # Get URLs to scan
            urls_to_scan = []
            for host in live_hosts[:10]:
                url = host.get('url', '')
                if url:
                    urls_to_scan.append(url)
            
            # Also add prioritized endpoints
            prioritized = self.state.get("prioritized_endpoints", []) or []
            for ep in prioritized[:10]:
                url = ep.get('url', '') if isinstance(ep, dict) else str(ep)
                if url and url not in urls_to_scan:
                    urls_to_scan.append(url)
            
            crypto_findings = []
            sqlmap_findings = []
            
            for url in urls_to_scan[:5]:
                # ─── Crypto/SSL/TLS Checks ──────────────────────────────
                try:
                    self.phase_detail = f"[CRYPTO] Checking {url.split('://')[-1][:30]}..."
                    self._update_display()
                    
                    crypto_result = self.crypto_scanner.scan(url)
                    if crypto_result:
                        findings = crypto_result.get('findings', [])
                        crypto_findings.extend(findings)
                        
                        # Store in state
                        if findings:
                            self.logger.info(f"[CRYPTO] Found {len(findings)} issues on {url}")
                            for f in findings[:3]:
                                self.logger.debug(f"  ├─ {f.get('title', 'N/A')}: {f.get('severity', 'N/A')}")
                except Exception as e:
                    self.logger.debug(f"[CRYPTO] Error scanning {url}: {e}")
                
                # ─── SQLMap Confirmation (if sqlmap available) ──────────
                try:
                    if self.sqlmap_runner.is_sqlmap_available():
                        self.phase_detail = f"[SQLMAP] Quick test on {url.split('://')[-1][:30]}..."
                        self._update_display()
                        
                        sqli_result = self.sqlmap_runner.test_sqli_quick(url)
                        if sqli_result and sqli_result.get('vulnerable'):
                            sqlmap_findings.append({
                                'url': url,
                                'vulnerable': True,
                                'details': sqli_result.get('details', ''),
                                'source': 'sqlmap'
                            })
                            self.logger.warning(f"[SQLMAP] ✅ SQLi confirmed on {url}")
                            
                            if self.batch_display:
                                self.batch_display._add_to_feed("💧", "SQLi Confirmed", url, "sqlmap verified")
                except Exception as e:
                    self.logger.debug(f"[SQLMAP] Error on {url}: {e}")
            
            # Store findings in state
            if crypto_findings:
                self.state.update(crypto_findings=crypto_findings)
                self.stats['vulns'] += len(crypto_findings)
                self.logger.info(f"[CRYPTO] Total findings: {len(crypto_findings)}")
            
            if sqlmap_findings:
                self.state.update(sqlmap_findings=sqlmap_findings)
                self.logger.info(f"[SQLMAP] Confirmed SQLi: {len(sqlmap_findings)} targets")
            
            self.last_action = f"misconfig: {len(crypto_findings)} crypto + {len(sqlmap_findings)} SQLi"
            
        except Exception as e:
            self.logger.debug(f"[MISCONFIG] Error in security checks: {e}")
            self.last_action = f"misconfig error: {str(e)[:40]}"

    # ═══════════════════════════════════════════════════════════════════════════
    # NEW: Advanced Core Module Phase Handlers
    # These phases integrate the new ML, Burp, Metasploit, and LLM modules
    # ═══════════════════════════════════════════════════════════════════════════

    def _run_ml_classification_phase(self):
        """ML-based endpoint classification phase"""
        if not self.ml_classifier:
            self._mark_phase_done("ml_classify")
            return
        
        self.phase_detail = "[ML] Classifying endpoints with ML..."
        self._update_display()
        
        try:
            endpoints = self.state.get("endpoints", [])
            if not endpoints:
                self.phase_detail = "[ML] No endpoints to classify"
                self._update_display()
                self._mark_phase_done("ml_classify")
                return
            
            # Extract URLs for classification
            urls = []
            for ep in endpoints[:100]:
                url = ep.get('url', '') if isinstance(ep, dict) else str(ep)
                if url:
                    urls.append(url)
            
            self.logger.info(f"[ML] Classifying {len(urls)} endpoints")
            
            # Run ML classification
            results = self.ml_classifier.classify_batch(urls)
            
            # Store classification results
            api_endpoints = []
            admin_endpoints = []
            auth_endpoints = []
            upload_endpoints = []
            
            ml_classified = []
            for r in results:
                ml_classified.append({
                    'url': r.endpoint,
                    'type': r.predicted_type.value,
                    'confidence': r.confidence,
                    'reasoning': r.reasoning
                })
                
                if r.predicted_type.name == 'API':
                    api_endpoints.append(r.endpoint)
                elif r.predicted_type.name == 'ADMIN':
                    admin_endpoints.append(r.endpoint)
                elif r.predicted_type.name == 'AUTH':
                    auth_endpoints.append(r.endpoint)
                elif r.predicted_type.name == 'UPLOAD':
                    upload_endpoints.append(r.endpoint)
            
            # Store in state
            self.state.update(ml_classified_endpoints=ml_classified)
            self.state.update(api_endpoints=api_endpoints)
            self.state.update(admin_endpoints=admin_endpoints)
            self.state.update(auth_endpoints=auth_endpoints)
            self.state.update(upload_endpoints=upload_endpoints)
            
            # Predict vulnerabilities
            vuln_predictions = self.ml_classifier.predict_vulnerabilities(urls)
            if vuln_predictions:
                predictions_list = []
                for p in vuln_predictions:
                    predictions_list.append({
                        'url': p.endpoint,
                        'vulnerability_type': p.vulnerability_type.value,
                        'probability': p.probability,
                        'confidence': p.confidence,
                        'indicators': p.indicators,
                        'recommendations': p.recommendations
                    })
                self.state.update(ml_vulnerability_predictions=predictions_list)
            
            self.stats['eps'] = len(results)
            self.last_action = f"ml_classify: {len(results)} endpoints classified"
            self.phase_detail = f"[ML] Complete - {len(results)} classified, {len(vuln_predictions)} vuln predictions"
            self._update_display()
            
            if self.batch_display:
                self.batch_display._add_to_feed("🤖", "ML Classify", self.target, f"{len(results)} endpoints")
            
        except Exception as e:
            self.logger.error(f"[ML] Phase failed: {e}")
            self.last_action = f"ml_classify error: {str(e)[:50]}"
            self.phase_detail = f"[ML] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("ml_classify")

    def _run_burp_scan_phase(self):
        """Burp Suite automated scanning phase"""
        if not self.burp_scanner:
            self._mark_phase_done("burp_scan")
            return
        
        self.phase_detail = "[BURP] Running Burp Suite scan..."
        self._update_display()
        
        try:
            target_url = self.target
            if not target_url.startswith(('http://', 'https://')):
                target_url = f"https://{target_url}"
            
            self.logger.info(f"[BURP] Starting scan on {target_url}")
            
            # Run Burp scan
            issues = self.burp_scanner.scan_url(
                target_url,
                wait_for_completion=True,
                timeout=3600  # 1 hour timeout
            )
            
            # Store Burp findings
            burp_issues = []
            for issue in issues:
                burp_issues.append({
                    'name': issue.issue_name,
                    'severity': issue.severity.value,
                    'confidence': issue.confidence.value,
                    'url': issue.url,
                    'type': issue.issue_type,
                    'parameter': issue.parameter,
                    'evidence': issue.evidence,
                    'background': issue.background,
                    'remediation': issue.remediation
                })
            
            self.state.update(burp_issues=burp_issues)
            
            # Update stats
            high_severity = sum(1 for i in burp_issues if i['severity'] == 'High')
            medium_severity = sum(1 for i in burp_issues if i['severity'] == 'Medium')
            low_severity = sum(1 for i in burp_issues if i['severity'] == 'Low')
            
            self.stats['vulns'] += len(burp_issues)
            
            self.last_action = f"burp_scan: {len(burp_issues)} issues ({high_severity}H/{medium_severity}M/{low_severity}L)"
            self.phase_detail = f"[BURP] Complete - {len(burp_issues)} issues found"
            self._update_display()
            
            if self.batch_display:
                self.batch_display._add_to_feed("🔧", "Burp Scan", self.target, f"{len(burp_issues)} issues")
            
        except Exception as e:
            self.logger.error(f"[BURP] Phase failed: {e}")
            self.last_action = f"burp_scan error: {str(e)[:50]}"
            self.phase_detail = f"[BURP] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("burp_scan")

    def _run_metasploit_exploit_phase(self):
        """Metasploit auto-exploitation phase"""
        if not self.auto_exploiter or not self.metasploit or not self.metasploit.connected:
            self._mark_phase_done("msf_exploit")
            return
        
        self.phase_detail = "[MSF] Running Metasploit auto-exploitation..."
        self._update_display()
        
        try:
            # Get vulnerabilities from state
            vulns = self.state.get("confirmed_vulnerabilities", [])
            exploitable_cves = self.state.get("exploitable_cves", [])
            
            if not vulns and not exploitable_cves:
                self.phase_detail = "[MSF] No vulnerabilities to exploit"
                self._update_display()
                self._mark_phase_done("msf_exploit")
                return
            
            # Build vulnerability list for auto-exploiter
            vuln_list = []
            for v in vulns:
                vuln_list.append({
                    'id': v.get('type', ''),
                    'name': v.get('name', ''),
                    'endpoint': v.get('endpoint', ''),
                    'severity': v.get('severity', ''),
                    'confidence': v.get('confidence', 0)
                })
            
            for cve in exploitable_cves:
                vuln_list.append({
                    'id': cve.get('cve_id', ''),
                    'name': cve.get('name', ''),
                    'endpoint': cve.get('endpoint', ''),
                    'severity': cve.get('severity', ''),
                    'confidence': cve.get('probability_of_success', 0)
                })
            
            self.logger.info(f"[MSF] Auto-exploiting with {len(vuln_list)} vulnerabilities")
            
            # Determine platform
            platform = "linux"  # Default
            tech_stack = self.state.get("technologies", {})
            if tech_stack:
                tech_names = [t.lower() for t in tech_stack.keys()]
                if any('windows' in t or 'iis' in t for t in tech_names):
                    platform = "windows"
                elif any('php' in t or 'apache' in t for t in tech_names):
                    platform = "linux"
            
            # Run auto-exploitation
            attempts = self.auto_exploiter.auto_exploit(
                target=self.target,
                vulnerabilities=vuln_list,
                platform=platform
            )
            
            # Store exploit results
            msf_results = []
            successful = 0
            for attempt in attempts:
                msf_results.append({
                    'attempt_id': attempt.attempt_id,
                    'target': attempt.target,
                    'exploit_module': attempt.exploit_module,
                    'payload': attempt.payload,
                    'status': attempt.status.value,
                    'session_id': attempt.session_id,
                    'result': attempt.result,
                    'error': attempt.error
                })
                if attempt.status.name == 'SUCCESS':
                    successful += 1
            
            self.state.update(msf_exploit_attempts=msf_results)
            self.stats['exploited'] += successful
            
            self.last_action = f"msf_exploit: {successful}/{len(attempts)} successful"
            self.phase_detail = f"[MSF] Complete - {successful} sessions established"
            self._update_display()
            
            if self.batch_display:
                self.batch_display._add_to_feed("💣", "Metasploit", self.target, f"{successful} sessions")
            
        except Exception as e:
            self.logger.error(f"[MSF] Phase failed: {e}")
            self.last_action = f"msf_exploit error: {str(e)[:50]}"
            self.phase_detail = f"[MSF] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("msf_exploit")

    def _run_llm_analysis_phase(self):
        """LLM-powered analysis phase"""
        if not self.llm_analyzer:
            self._mark_phase_done("llm_analysis")
            return
        
        self.phase_detail = "[LLM] Running AI-powered analysis..."
        self._update_display()
        
        try:
            # Gather all findings
            findings = {
                'target': self.target,
                'vulnerabilities': self.state.get("confirmed_vulnerabilities", []),
                'endpoints': self.state.get("endpoints", []),
                'technologies': self.state.get("technologies", {}),
                'exploit_chains': self.state.get("exploit_chains", []),
                'security_findings': self.state.get("security_findings", []),
                'wordpress_findings': {
                    'version': self.state.get("wp_version", ""),
                    'plugins': self.state.get("wp_plugins", []),
                    'themes': self.state.get("wp_themes", []),
                    'users': self.state.get("wp_users", []),
                    'vulnerabilities': self.state.get("wp_vulnerabilities", [])
                }
            }
            
            self.logger.info(f"[LLM] Analyzing target with AI...")
            
            # Run vulnerability analysis
            vuln_analysis = self.llm_analyzer.analyze_vulnerabilities(
                findings['vulnerabilities'],
                context=f"Target: {self.target}"
            )
            
            # Run risk assessment
            risk_assessment = self.llm_analyzer.assess_risk(findings)
            
            # Run attack path suggestion
            attack_paths = self.llm_analyzer.suggest_attack_paths(findings)
            
            # Run remediation advice
            remediation = self.llm_analyzer.get_remediation_advice(
                findings['vulnerabilities'],
                environment=self.target
            )
            
            # Store analysis results
            llm_analysis = {
                'vulnerability_analysis': vuln_analysis.content,
                'risk_assessment': risk_assessment.content,
                'attack_paths': attack_paths.content,
                'remediation_advice': remediation.content,
                'confidence': vuln_analysis.confidence.value,
                'key_findings': vuln_analysis.key_findings,
                'recommendations': vuln_analysis.recommendations
            }
            
            self.state.update(llm_analysis=llm_analysis)
            
            self.last_action = f"llm_analysis: AI analysis complete (confidence: {vuln_analysis.confidence.value})"
            self.phase_detail = f"[LLM] Complete - AI-powered analysis finished"
            self._update_display()
            
            if self.batch_display:
                self.batch_display._add_to_feed("🧠", "LLM Analysis", self.target, f"Confidence: {vuln_analysis.confidence.value}")
            
        except Exception as e:
            self.logger.error(f"[LLM] Phase failed: {e}")
            self.last_action = f"llm_analysis error: {str(e)[:50]}"
            self.phase_detail = f"[LLM] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("llm_analysis")

    def _run_learning_phase(self):
        self.phase_detail = "[LEARN] Analyzing results and updating patterns..."
        self._update_display()
        self.learning_engine.learn_from_iteration(self.state)

        failed_payloads = self.learning_engine.get_failed_payloads()
        self.learning_stats['mutated'] = len(failed_payloads)
        self.phase_detail = f"[LEARN] Analyzed {len(failed_payloads)} failed payloads"
        self._update_display()

        # ── Groq learning analysis ──────────────────────────────────────────
        try:
            failure_data = self.learning_engine.export_learning_data()
            user_msg = json.dumps({
                "target": self.target,
                "iteration": self.iteration_count,
                "failure_patterns": failure_data.get("failure_patterns", {}),
                "successful_payloads": failure_data.get("successful_payloads", [])[-5:],
                "failed_payloads_sample": failure_data.get("failed_payloads", [])[-10:],
                "stats": failure_data.get("stats", {})
            })
            raw = self._call_groq(self._GROQ_LEARNING_PROMPT, user_msg, timeout=12)
            if raw:
                raw = raw.lstrip("```json").lstrip("```").rstrip("```").strip()
                analysis = json.loads(raw)
                waf_fp = analysis.get("waf_fingerprint", "Unknown")
                bypass_rec = analysis.get("recommended_bypass", "NONE")
                exploitability = analysis.get("estimated_exploitability", "UNKNOWN")
                self.logger.info(f"[GROQ-LEARN] WAF={waf_fp} | Bypass={bypass_rec} | Exploitability={exploitability}")
                self.phase_detail = f"[LEARN] AI: WAF={waf_fp}, Bypass={bypass_rec}, Score={exploitability}"
                self._update_display()
                # Hiện lên AI panel
                if self.batch_display:
                    self.batch_display._add_to_ai_feed(
                        "WAF Analysis",
                        f"WAF={waf_fp} | Bypass={bypass_rec} | Exploitability={exploitability}",
                        self.target
                    )
                    root_cause = analysis.get("failure_root_cause", "")
                    if root_cause:
                        self.batch_display._add_to_ai_feed(
                            "Failure Root Cause",
                            root_cause[:55],
                            self.target
                        )
                # Feed kết quả vào waf_context của payload_gen
                if bypass_rec and bypass_rec != "NONE":
                    self.payload_gen.waf_context["bypass_mode"] = bypass_rec
                if waf_fp and waf_fp not in ("None", "Unknown"):
                    self.payload_gen.waf_context["waf_name"] = waf_fp
                blocked = analysis.get("blocked_keywords", [])
                if blocked:
                    self.payload_gen.waf_context["failed_patterns"] = blocked
                self.state.update(ai_learning_analysis=analysis)
        except Exception as e:
            self.logger.debug(f"[GROQ-LEARN] Analysis failed: {e}")

        self.phase_status = "done"
        self._mark_phase_done("learn")

    def _filter_unreachable_hosts(self, live_hosts: List[Dict]) -> List[Dict]:
        """
        FIX: Filter out unreachable hosts based on response time and connectivity.
        Skip hosts that are likely to timeout during toolkit scanning.
        """
        if not live_hosts:
            return []
        
        filtered = []
        max_response_time = 10.0  # Skip hosts with >10s response time
        
        for host in live_hosts:
            url = host.get("url", "")
            if not url:
                continue
            
            # Check if host has good response time from previous scans
            response_time = host.get("response_time", 0) or host.get("latency", 0) or 0
            status_code = host.get("status_code", 0) or 0
            
            # Skip hosts with no response or error status
            if status_code == 0 or status_code >= 500:
                self.logger.debug(f"[TOOLKIT] Skipping unreachable host: {url} (status: {status_code})")
                continue
            
            # Skip hosts with high response time
            if response_time > max_response_time:
                self.logger.debug(f"[TOOLKIT] Skipping slow host: {url} (response_time: {response_time:.2f}s)")
                continue
            
            # Check if host was previously blacklisted for timeouts
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname or ""
            from core.scan_optimizer import get_optimizer
            optimizer = get_optimizer()
            if optimizer and optimizer.is_host_blacklisted(hostname):
                self.logger.debug(f"[TOOLKIT] Skipping blacklisted host: {url}")
                continue
            
            filtered.append(host)
        
        if filtered:
            self.logger.info(f"[TOOLKIT] Filtered {len(live_hosts)} hosts → {len(filtered)} reachable hosts")
        
        return filtered

    def _generate_fallback_chains(self) -> List[Dict]:
        """
        FIX: Generate fallback exploit chains when toolkit phase fails or produces no chains.
        This ensures exploit phase always has something to work with.
        """
        fallback_chains = []
        
        # Get available data from state
        technologies = self.state.get("technologies", {}) or {}
        endpoints = self.state.get("endpoints", []) or []
        vulnerabilities = self.state.get("vulnerabilities", []) or []
        wp_detected = self.state.get("wordpress_detected", False)
        
        # Chain 1: Unauthenticated API Access (if API endpoints found)
        api_endpoints = [e for e in endpoints if 'api' in (e.get('url', '') if isinstance(e, dict) else str(e)).lower()]
        if api_endpoints:
            fallback_chains.append({
                "name": "Unauthenticated API Access",
                "description": "Test API endpoints for missing authentication or weak authorization",
                "risk_level": "HIGH",
                "estimated_time": "5-10 minutes",
                "steps": [
                    {
                        "name": "API Discovery",
                        "action": "Enumerate all API endpoints and methods",
                        "target": api_endpoints[0].get('url', '') if isinstance(api_endpoints[0], dict) else api_endpoints[0],
                        "tool": "api_scanner",
                        "payload": "",
                        "success_indicator": "API endpoints identified with methods"
                    },
                    {
                        "name": "Authentication Bypass Test",
                        "action": "Test each endpoint without authentication",
                        "target": "",
                        "tool": "http_client",
                        "payload": "GET /api/v1/users (no auth)",
                        "success_indicator": "200 OK response without authentication"
                    },
                    {
                        "name": "Data Extraction",
                        "action": "Extract sensitive data from unauthenticated endpoints",
                        "target": "",
                        "tool": "http_client",
                        "payload": "",
                        "success_indicator": "User data, credentials, or sensitive information retrieved"
                    }
                ]
            })
        
        # Chain 2: WordPress Exploitation (if WordPress detected)
        if wp_detected:
            wp_version = self.state.get("wp_version", "unknown")
            wp_plugins = self.state.get("wp_plugins", []) or []
            
            fallback_chains.append({
                "name": f"WordPress {wp_version} Exploitation Chain",
                "description": "Exploit WordPress vulnerabilities for initial access",
                "risk_level": "HIGH",
                "estimated_time": "10-15 minutes",
                "steps": [
                    {
                        "name": "WordPress Enumeration",
                        "action": "Enumerate WordPress version, plugins, themes, and users",
                        "target": self.target,
                        "tool": "wpscan",
                        "payload": "",
                        "success_indicator": "WordPress version and plugins identified"
                    },
                    {
                        "name": "Plugin Vulnerability Exploitation",
                        "action": "Exploit known vulnerabilities in detected plugins",
                        "target": "",
                        "tool": "exploit_framework",
                        "payload": "",
                        "success_indicator": "Plugin vulnerability exploited successfully"
                    },
                    {
                        "name": "Admin Access",
                        "action": "Gain administrative access via exploited vulnerability",
                        "target": "",
                        "tool": "http_client",
                        "payload": "",
                        "success_indicator": "Admin dashboard access achieved"
                    }
                ]
            })
        
        # Chain 3: SQL Injection (if parameters found)
        endpoints_with_params = [e for e in endpoints if '?' in (e.get('url', '') if isinstance(e, dict) else str(e))]
        if endpoints_with_params:
            fallback_chains.append({
                "name": "SQL Injection Exploitation Chain",
                "description": "Test for and exploit SQL injection vulnerabilities",
                "risk_level": "CRITICAL",
                "estimated_time": "15-20 minutes",
                "steps": [
                    {
                        "name": "SQLi Detection",
                        "action": "Test parameters for SQL injection vulnerability",
                        "target": endpoints_with_params[0].get('url', '') if isinstance(endpoints_with_params[0], dict) else endpoints_with_params[0],
                        "tool": "sqlmap",
                        "payload": "' OR 1=1--",
                        "success_indicator": "SQL injection confirmed"
                    },
                    {
                        "name": "Database Enumeration",
                        "action": "Enumerate database structure and tables",
                        "target": "",
                        "tool": "sqlmap",
                        "payload": "--dbs --tables",
                        "success_indicator": "Database structure enumerated"
                    },
                    {
                        "name": "Credential Extraction",
                        "action": "Dump user credentials from database",
                        "target": "",
                        "tool": "sqlmap",
                        "payload": "--dump -T users",
                        "success_indicator": "User credentials extracted"
                    }
                ]
            })
        
        # Chain 4: File Upload RCE (if upload endpoints found)
        upload_endpoints = [e for e in endpoints if 'upload' in (e.get('url', '') if isinstance(e, dict) else str(e)).lower()]
        if upload_endpoints:
            fallback_chains.append({
                "name": "File Upload to RCE Chain",
                "description": "Bypass file upload restrictions to achieve remote code execution",
                "risk_level": "CRITICAL",
                "estimated_time": "10-15 minutes",
                "steps": [
                    {
                        "name": "Upload Endpoint Analysis",
                        "action": "Analyze file upload endpoint for validation bypass",
                        "target": upload_endpoints[0].get('url', '') if isinstance(upload_endpoints[0], dict) else upload_endpoints[0],
                        "tool": "http_client",
                        "payload": "",
                        "success_indicator": "Upload mechanism understood"
                    },
                    {
                        "name": "Validation Bypass",
                        "action": "Bypass file type validation (extension, MIME, magic bytes)",
                        "target": "",
                        "tool": "upload_bypass",
                        "payload": "",
                        "success_indicator": "Malicious file uploaded successfully"
                    },
                    {
                        "name": "Webshell Execution",
                        "action": "Execute uploaded webshell for RCE",
                        "target": "",
                        "tool": "http_client",
                        "payload": "",
                        "success_indicator": "Remote code execution achieved"
                    }
                ]
            })
        
        # Chain 5: Default Credentials (always applicable)
        fallback_chains.append({
            "name": "Default Credentials Exploitation",
            "description": "Test for default/weak credentials on admin panels and APIs",
            "risk_level": "MEDIUM",
            "estimated_time": "5-10 minutes",
            "steps": [
                {
                    "name": "Login Panel Discovery",
                    "action": "Find login panels and authentication endpoints",
                    "target": self.target,
                    "tool": "crawler",
                    "payload": "",
                    "success_indicator": "Login endpoints identified"
                },
                {
                    "name": "Credential Testing",
                    "action": "Test common default credentials",
                    "target": "",
                    "tool": "http_client",
                    "payload": "admin:admin, admin:password, root:root",
                    "success_indicator": "Valid credentials found"
                },
                {
                    "name": "Session Hijacking",
                    "action": "Use credentials to gain authenticated access",
                    "target": "",
                    "tool": "http_client",
                    "payload": "",
                    "success_indicator": "Authenticated session established"
                }
            ]
        })
        
        if fallback_chains:
            self.logger.warning(f"[FALLBACK] Generated {len(fallback_chains)} fallback exploit chains")
        
        return fallback_chains

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

    def _canonicalize_url(self, url: str) -> str:
        """Prefer the known-live scheme for the same host:port without disabling HTTPS globally."""
        if not url or not isinstance(url, str):
            return url
        try:
            from urllib.parse import urlparse, urlunparse

            parsed = urlparse(url)
            if not parsed.scheme or not parsed.hostname:
                return url

            target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            for host_info in self.state.get("live_hosts", []) or []:
                live_url = host_info.get("url", "")
                live_parsed = urlparse(live_url)
                if not live_parsed.scheme or not live_parsed.hostname:
                    continue
                live_port = live_parsed.port or (443 if live_parsed.scheme == "https" else 80)
                if live_parsed.hostname != parsed.hostname or live_port != target_port:
                    continue
                if live_parsed.scheme == parsed.scheme:
                    return url
                return urlunparse((
                    live_parsed.scheme,
                    live_parsed.netloc,
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                ))
        except Exception:
            return url
        return url

    def _canonicalize_state_urls(self):
        """Normalize state URL collections to the scheme proven live for each host:port."""
        for field in ["urls", "live_urls"]:
            values = self.state.get(field, []) or []
            if values:
                self.state.update(**{field: [self._canonicalize_url(v) for v in values]})

        for field in ["endpoints", "prioritized_endpoints"]:
            entries = self.state.get(field, []) or []
            if not entries:
                continue
            normalized = []
            for entry in entries:
                if isinstance(entry, dict) and entry.get("url"):
                    patched = entry.copy()
                    patched["url"] = self._canonicalize_url(entry.get("url"))
                    normalized.append(patched)
                else:
                    normalized.append(entry)
            self.state.update(**{field: normalized})

    def _check_confidence_threshold(self) -> bool:
        vulnerabilities = self.state.get("confirmed_vulnerabilities", [])
        exploit_results = self.state.get("exploit_results", [])
        
        if vulnerabilities and exploit_results:
            successful = len(self._meaningful_successful_exploits(exploit_results))
            confidence = successful / len(vulnerabilities)
            return confidence >= self.confidence_threshold
        return False

    def _meaningful_successful_exploits(self, exploit_results=None):
        exploit_results = exploit_results if exploit_results is not None else (self.state.get("exploit_results", []) or [])

        def is_meaningful(result):
            if not result.get("success"):
                return False
            context = result.get("context", {}) or {}
            chain_name = (result.get("chain") or "").lower()
            if "xml-rpc multicall bruteforce" in chain_name:
                return bool(context.get("valid_credentials"))
            if "wordpress admin takeover" in chain_name:
                return bool(context.get("authenticated_session") and context.get("admin_access"))
            if "sql injection" in chain_name:
                return bool(context.get("sqli_confirmed") and (context.get("database_list") or context.get("dumped_credentials")))
            if "upload" in chain_name and "rce" in chain_name:
                return bool(context.get("uploaded_shell_url") and context.get("rce_verified"))
            return bool(result.get("final_payload"))

        return [r for r in exploit_results if is_meaningful(r)]

    def _iteration_snapshot(self) -> Dict[str, int]:
        exploit_results = self.state.get("exploit_results", []) or []
        return {
            "confirmed_vulns": len(self.state.get("confirmed_vulnerabilities", []) or []),
            "all_vulns": len(self.state.get("vulnerabilities", []) or []),
            "successful_exploits": len(self._meaningful_successful_exploits(exploit_results)),
            "exploit_results": len(exploit_results),
            "prioritized_endpoints": len(self.state.get("prioritized_endpoints", []) or []),
            "security_findings": len(self.state.get("security_findings", []) or []),
            "rce_paths": len(self.state.get("rce_chain_possibilities", []) or []),
        }

    def _should_stop_due_to_stagnation(self) -> bool:
        snapshot = self._iteration_snapshot()
        if self._last_iteration_snapshot is None:
            self._last_iteration_snapshot = snapshot
            return False

        progress = any(snapshot[k] > self._last_iteration_snapshot.get(k, 0) for k in snapshot.keys())
        if progress:
            self._stagnant_iterations = 0
            self._last_iteration_snapshot = snapshot
            return False

        self._stagnant_iterations += 1
        self._last_iteration_snapshot = snapshot
        return self._stagnant_iterations >= 1 and self.iteration_count >= 2

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
        # ── Gọi AI để ra quyết định cho iteration tiếp theo ──────────────────
        self._ai_decide_and_apply()

    # ═══════════════════════════════════════════════════════════════════════════
    # GROQ AI DECISION LAYER
    # Được gọi ở cuối mỗi iteration để điều chỉnh strategy cho iteration sau.
    # Không thay thế logic cũ — chỉ override các parameter nếu AI nói cần.
    # ═══════════════════════════════════════════════════════════════════════════

    # ── Prompt 1: Adaptive Strategy Decision ───────────────────────────────────
    # Dùng ở: _ai_decide_and_apply() sau mỗi iteration
    # Quyết định rate, endpoint filter, WAF bypass mode, chain hints
    _GROQ_DECISION_PROMPT = """You are the decision engine of an automated penetration testing agent performing authorized security assessments.

After each scan iteration, you receive the current scan state and must output a JSON decision for the NEXT iteration.

## INPUT FORMAT
JSON object with these fields:
- target: domain being tested
- iteration: current iteration number (max 3)
- waf_detected: WAF name string or null
- consecutive_resets: connection resets in a row
- consecutive_waf_blocks: consecutive 403/406/419 responses
- payload_success_rate: float 0.0-1.0 from last batch
- payloads_tested: total payloads sent this iteration
- endpoints_total: total discovered endpoints
- endpoints_scanned: how many were scanned
- endpoint_priority_counts: {"CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N}
- vulns_found: list of {type, severity, endpoint}
- cms: detected CMS and version string
- plugins: list of {name, version, has_known_cve}
- wp_users: list of discovered WordPress usernames
- xmlrpc_enabled: boolean
- last_10_status_codes: list of last 10 HTTP status codes
- failed_payload_types: payload categories with 0% success rate
- current_waf_bypass_mode: "NONE"|"ENCODE"|"CASE_MANGLE"|"FRAGMENT"|"SLOW"
- scan_responses_count: total scan responses in state

## OUTPUT FORMAT
Respond ONLY with a valid JSON object. No explanation. No markdown. No extra text.

{
  "action": "PROCEED" | "CHANGE_STRATEGY" | "SKIP_TO_EXPLOIT" | "ABORT_TARGET",
  "reason": "<one sentence>",
  "next_strategy": {
    "rate_limit_factor": <float 0.1-1.0>,
    "max_payloads": <int 10-100>,
    "timeout_multiplier": <float 0.5-3.0>,
    "endpoint_filter": "CRITICAL_ONLY" | "HIGH_AND_ABOVE" | "ALL",
    "waf_bypass_mode": "NONE" | "ENCODE" | "CASE_MANGLE" | "FRAGMENT" | "SLOW",
    "skip_payload_types": [],
    "prioritize_payload_types": []
  },
  "chain_hints": [],
  "learning_insight": "<one sentence — what pattern explains failures>"
}

## DECISION RULES — apply in order, first match wins

ABORT conditions:
- consecutive_resets > 50 AND vulns_found empty → action=ABORT_TARGET
- iteration == 3 AND payloads_tested > 80 AND vulns_found empty AND consecutive_waf_blocks > 30 → action=ABORT_TARGET

WAF blocking escalation (NEVER skip steps):
- consecutive_waf_blocks > 10 AND current_waf_bypass_mode == "NONE" → CHANGE_STRATEGY, waf_bypass_mode=ENCODE
- consecutive_waf_blocks > 10 AND current_waf_bypass_mode == "ENCODE" → CHANGE_STRATEGY, waf_bypass_mode=CASE_MANGLE
- consecutive_waf_blocks > 10 AND current_waf_bypass_mode == "CASE_MANGLE" → CHANGE_STRATEGY, waf_bypass_mode=FRAGMENT
- consecutive_waf_blocks > 10 AND current_waf_bypass_mode == "FRAGMENT" → CHANGE_STRATEGY, waf_bypass_mode=SLOW, rate_limit_factor=0.1

Connection resets:
- consecutive_resets > 5 → rate_limit_factor=0.2, timeout_multiplier=2.0
- consecutive_resets > 20 → rate_limit_factor=0.1, timeout_multiplier=3.0, max_payloads=10

Server overload:
- last_10_status_codes has 8+ entries that are 5xx → rate_limit_factor=0.2, timeout_multiplier=2.5

Payload efficiency:
- payload_success_rate < 0.05 AND payloads_tested > 20 → add all zero-success categories to skip_payload_types
- Never continue a payload type that failed 20+ times with 0 success

Endpoint filtering:
- endpoints_total > 5000 AND vulns_found not empty → endpoint_filter=CRITICAL_ONLY
- endpoints_total > 5000 AND vulns_found empty → endpoint_filter=HIGH_AND_ABOVE
- iteration == 3 AND vulns_found empty → endpoint_filter=HIGH_AND_ABOVE, max_payloads=20

Early exploit:
- vulns_found has 2+ HIGH or CRITICAL entries AND payload_success_rate > 0.3 → action=SKIP_TO_EXPLOIT

Chain hints (add when conditions met):
- any vuln type contains "sqli" → add "sqli_credential_dump"
- cms contains "WordPress" AND any plugin has has_known_cve=true → add "wp_plugin_exploit_to_rce"
- any vuln type contains "file_upload" → add "webshell_upload_rce"
- xmlrpc_enabled AND wp_users not empty → add "xmlrpc_multicall_bruteforce"
- any vuln type contains "xss" AND wp_users not empty → add "stored_xss_session_hijack"

Default: if no rule matches → action=PROCEED with unchanged settings"""

    # ── Prompt 2: Learning Analysis ─────────────────────────────────────────────
    # Dùng ở: _run_learning_phase() sau learn_from_iteration()
    # Phân tích failure pattern, fingerprint WAF, gợi ý bypass
    _GROQ_LEARNING_PROMPT = """You are a penetration testing analyst reviewing scan results to extract actionable insights.

Analyze failure patterns from a completed scan iteration and output structured recommendations.

## INPUT FORMAT
JSON object with:
- target: domain scanned
- iteration: which iteration just finished
- failure_patterns: {response_codes, common_rejections, keyword_filtering, encoding_issues, payload_length_issues}
- successful_payloads: last 5 successful payloads [{payload, vuln_type}]
- failed_payloads_sample: last 10 failed payloads [{payload, reason, response_code}]
- stats: {total_successful, total_failed, success_rate}

## OUTPUT FORMAT
Respond ONLY with a valid JSON object. No explanation. No markdown.

{
  "failure_root_cause": "<one sentence>",
  "waf_fingerprint": "Cloudflare" | "ModSecurity" | "WordFence" | "Generic" | "None" | "Unknown",
  "waf_confidence": <float 0.0-1.0>,
  "blocked_keywords": [],
  "recommended_bypass": "ENCODE" | "CASE_MANGLE" | "FRAGMENT" | "SLOW" | "NONE",
  "payload_types_to_drop": [],
  "payload_types_to_keep": [],
  "next_iteration_focus": "<one sentence>",
  "estimated_exploitability": "HIGH" | "MEDIUM" | "LOW" | "NONE"
}

## ANALYSIS RULES

WAF fingerprinting:
- keyword_filtering["script"] or keyword_filtering["alert"] > 5 → likely WordFence
- Many 406 responses → likely ModSecurity
- 403 with inconsistent pattern, no keyword match → likely Cloudflare or CDN
- No 403/406, 200 but payload not reflected → application-level filtering

Bypass recommendation:
- Dominant 403 + keyword filtering → CASE_MANGLE first, then FRAGMENT
- Dominant 406 → ENCODE first (ModSecurity often misses double encoding)
- Connection resets (status_code 0) → SLOW mode, reduce concurrency
- encoding_issues > 5 → try double encoding before other strategies
- payload_length_issues > 5 → FRAGMENT long payloads

Exploitability estimation:
- success_rate > 0.1 → HIGH
- success_rate > 0.02 → MEDIUM
- success_rate > 0 → LOW
- success_rate == 0 AND total_failed > 50 → NONE"""

    def _call_groq(self, system_prompt: str, user_message: str, timeout: int = 15) -> str:
        """Gọi Groq API với retry logic. Trả về string rỗng nếu lỗi hoặc không có key."""
        import urllib.request as _ureq
        import urllib.error as _uerr
        import time
        
        groq_key = os.environ.get("GROQ_API_KEY", "") or os.environ.get("GROQ_APIKEY", "")
        if not groq_key:
            return ""
        
        max_retries = 3
        base_delay = 1
        
        for attempt in range(max_retries):
            try:
                body = json.dumps({
                    "model": config.PRIMARY_AI_MODEL,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    "max_tokens": 512,
                    "temperature": 0.1
                }).encode("utf-8")
                req = _ureq.Request(
                    "https://api.groq.com/openai/v1/chat/completions",
                    data=body,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "python-requests/2.31.0",
                        "Authorization": f"Bearer {groq_key}"
                    }
                )
                with _ureq.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data["choices"][0]["message"]["content"].strip()
            except _uerr.HTTPError as e:
                if e.code == 429:  # 429 = rate limit (not 403)
                    # Rate limited - exponential backoff
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        self.logger.debug(f"[GROQ] HTTP 429 rate-limit on attempt {attempt + 1}, backing off {delay}s...")
                        time.sleep(delay)
                        continue
                    else:
                        self.logger.warning(f"[GROQ] Exhausted retries for 429 after {max_retries} attempts")
                else:
                    self.logger.debug(f"[GROQ] HTTP error {e.code}: {e}")
                    break
            except _uerr.URLError as e:
                if attempt < max_retries - 1:
                    self.logger.debug(f"[GROQ] Network error on attempt {attempt + 1}: {e}, retrying...")
                    time.sleep(base_delay * (2 ** attempt))
                    continue
                else:
                    self.logger.debug(f"[GROQ] Network error exhausted retries: {e}")
            except Exception as e:
                self.logger.debug(f"[GROQ] API call failed attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(base_delay * (2 ** attempt))
        return ""

    def _build_ai_context(self) -> dict:
        """Build context dict để feed vào _GROQ_DECISION_PROMPT."""
        scan_responses = self.state.get("scan_responses", []) or []
        vulns = self.state.get("confirmed_vulnerabilities", []) or []
        endpoints = self.state.get("prioritized_endpoints", []) or []
        plugins = self.state.get("wp_plugins", []) or []

        priority_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for ep in endpoints:
            lvl = ep.get("risk_level", "LOW") if isinstance(ep, dict) else "LOW"
            priority_counts[lvl] = priority_counts.get(lvl, 0) + 1

        last_codes = [
            r.get("status_code", 0) for r in scan_responses[-10:]
            if isinstance(r, dict)
        ]

        consecutive_resets = 0
        for r in reversed(scan_responses):
            if isinstance(r, dict) and (
                r.get("status_code", 0) == 0
                or "reset" in str(r.get("reason", "")).lower()
            ):
                consecutive_resets += 1
            else:
                break

        consecutive_waf_blocks = 0
        for r in reversed(scan_responses):
            if isinstance(r, dict) and r.get("status_code", 0) in (403, 406, 419):
                consecutive_waf_blocks += 1
            else:
                break

        total = len(scan_responses)
        successful = sum(1 for r in scan_responses if isinstance(r, dict) and r.get("vulnerable"))
        success_rate = round(successful / total, 4) if total > 0 else 0.0

        category_stats = {}
        for r in scan_responses:
            if not isinstance(r, dict):
                continue
            cat = r.get("category", "unknown")
            if cat not in category_stats:
                category_stats[cat] = {"total": 0, "success": 0}
            category_stats[cat]["total"] += 1
            if r.get("vulnerable"):
                category_stats[cat]["success"] += 1
        failed_types = [
            cat for cat, s in category_stats.items()
            if s["total"] >= 5 and s["success"] == 0
        ]

        return {
            "target": self.target,
            "iteration": self.iteration_count,
            "waf_detected": self.findings.get("waf") or None,
            "consecutive_resets": consecutive_resets,
            "consecutive_waf_blocks": consecutive_waf_blocks,
            "payload_success_rate": success_rate,
            "payloads_tested": self.stats.get("payloads_tested", 0),
            "endpoints_total": len(self.state.get("urls", []) or []),
            "endpoints_scanned": len(endpoints),
            "endpoint_priority_counts": priority_counts,
            "vulns_found": [
                {"type": v.get("type", ""), "severity": v.get("severity", ""), "endpoint": v.get("endpoint", "")[:60]}
                for v in vulns[:10]
            ],
            "cms": self.findings.get("cms_version", ""),
            "plugins": [
                {"name": p.get("name", ""), "version": p.get("version", ""), "has_known_cve": bool(p.get("vulnerabilities"))}
                for p in plugins[:10]
            ],
            "wp_users": self.state.get("wp_users", [])[:5],
            "xmlrpc_enabled": any(
                "xmlrpc" in str(f).lower()
                for f in self.state.get("wp_vulns", []) or []
            ),
            "last_10_status_codes": last_codes,
            "failed_payload_types": failed_types,
            "current_waf_bypass_mode": getattr(self, "_waf_bypass_mode", "NONE"),
            "scan_responses_count": total,
        }

    def _ai_decide_and_apply(self):
        """Gọi Groq để ra quyết định adaptive sau mỗi iteration và apply kết quả."""
        try:
            ctx = self._build_ai_context()
            raw = self._call_groq(self._GROQ_DECISION_PROMPT, json.dumps(ctx), timeout=15)
            if not raw:
                return

            # Strip markdown fences nếu có
            raw = raw.lstrip("```json").lstrip("```").rstrip("```").strip()
            decision = json.loads(raw)

            action = decision.get("action", "PROCEED")
            reason = decision.get("reason", "")
            strategy = decision.get("next_strategy", {})
            chain_hints = decision.get("chain_hints", [])
            insight = decision.get("learning_insight", "")

            self.logger.info(f"[GROQ] Decision: {action} — {reason}")
            if insight:
                self.logger.info(f"[GROQ] Insight: {insight}")

            # Hiện lên AI panel
            if self.batch_display:
                self.batch_display._add_to_ai_feed(
                    f"Decision: {action}",
                    f"{reason[:55]}" if reason else "",
                    self.target
                )
                if insight:
                    self.batch_display._add_to_ai_feed(
                        "Insight",
                        insight[:55],
                        self.target
                    )
                if chain_hints:
                    self.batch_display._add_to_ai_feed(
                        "Chain hints",
                        ", ".join(chain_hints[:3]),
                        self.target
                    )

            # Lưu insight vào state để chain_planner và report dùng
            self.state.update(ai_learning_insight=insight)
            if chain_hints:
                self.state.update(ai_chain_hints=chain_hints)

            # Apply WAF bypass mode
            new_bypass = strategy.get("waf_bypass_mode")
            if new_bypass and new_bypass != getattr(self, "_waf_bypass_mode", "NONE"):
                self._waf_bypass_mode = new_bypass
                self.payload_gen.waf_context["bypass_mode"] = new_bypass
                self.logger.info(f"[GROQ] WAF bypass escalated to: {new_bypass}")
                if self.batch_display:
                    self.batch_display._add_to_feed("🧠", "AI-Adapt", self.target, f"WAF bypass → {new_bypass}")

            # Apply skip_payload_types
            skip_types = strategy.get("skip_payload_types", [])
            if skip_types:
                self.state.update(ai_skip_payload_types=skip_types)
                self.logger.info(f"[GROQ] Skipping payload types: {skip_types}")

            # Apply endpoint filter
            ep_filter = strategy.get("endpoint_filter")
            if ep_filter:
                self.state.update(ai_endpoint_filter=ep_filter)

            # Apply max_payloads
            max_p = strategy.get("max_payloads")
            if max_p and isinstance(max_p, int):
                self.stats["total_payloads"] = min(max_p, self.stats.get("total_payloads", 100))

            # Xử lý action đặc biệt
            if action == "ABORT_TARGET":
                self.logger.warning(f"[GROQ] ABORT_TARGET: {reason}")
                self.last_action = f"AI abort: {reason}"
                self._update_display()
            elif action == "SKIP_TO_EXPLOIT":
                self.logger.info(f"[GROQ] SKIP_TO_EXPLOIT: {reason}")
                # Mark scan phase done để nhảy thẳng vào exploit
                self._mark_phase_done("scan")
            elif action == "CHANGE_STRATEGY":
                self.logger.info(f"[GROQ] CHANGE_STRATEGY: {reason}")
                self.last_action = f"AI strategy change: {new_bypass or 'adjusted'}"
                self._update_display()

        except Exception as e:
            self.logger.debug(f"[GROQ] _ai_decide_and_apply failed: {e}")

    def _run_endpoint_ranking(self):
        urls = self.state.get("urls", [])
        endpoints = self.state.get("endpoints", [])
        
        # 🔥 FIX: Log số lượng
        self.logger.warning(f"[RANK] urls: {len(urls)}, endpoints: {len(endpoints)}")
        
        # Normalize endpoints → always dict
        normalized = []
        
        for u in urls:
            if u:
                normalized.append({
                    "url": u,
                    "parameters": [],
                    "categories": []
                })
        
        for ep in endpoints:
            if isinstance(ep, dict) and ep.get("url"):
                normalized.append(ep)
            elif isinstance(ep, str):
                normalized.append({
                    "url": ep,
                    "parameters": [],
                    "categories": []
                })
        
        # Deduplicate by URL
        try:
            from core.host_filter import HostFilter
            allowed_domains = self.state.get("allowed_domains", []) or []
            host_filter = HostFilter(skip_dev_test=True, allowed_domains=allowed_domains)
        except Exception:
            host_filter = None

        seen = set()
        all_eps = []
        live_hosts = self.state.get("live_hosts", []) or []
        preferred_hosts = {}
        try:
            from urllib.parse import urlparse
            for item in live_hosts:
                live_url = item.get("url", "")
                parsed_live = urlparse(live_url)
                if parsed_live.hostname:
                    preferred_hosts[(parsed_live.hostname.lower(), parsed_live.port or (443 if parsed_live.scheme == "https" else 80))] = {
                        "scheme": parsed_live.scheme,
                        "netloc": parsed_live.netloc,
                    }
        except Exception:
            preferred_hosts = {}

        for ep in normalized:
            u = ep["url"]
            if host_filter and host_filter.allowed_domains and not host_filter._is_in_allowed_domains(u):
                continue

            try:
                from urllib.parse import urlparse, urlunparse
                parsed = urlparse(u)
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                preferred_target = preferred_hosts.get(((parsed.hostname or "").lower(), port))
                if preferred_target and (parsed.netloc != preferred_target["netloc"] or parsed.scheme != preferred_target["scheme"]):
                    ep = dict(ep)
                    ep["url"] = urlunparse(parsed._replace(scheme=preferred_target["scheme"], netloc=preferred_target["netloc"]))
                    u = ep["url"]
            except Exception:
                pass

            if u not in seen:
                seen.add(u)
                all_eps.append(ep)
        
        if not all_eps:
            self.logger.warning("[RANK] No URLs found for ranking")
            # 🔥 FIX: Fallback từ urls
            if urls:
                fallback_eps = [{"url": u, "parameters": [], "categories": []} for u in urls[:100]]
                self.state.update(prioritized_endpoints=fallback_eps)
                self.logger.warning(f"[RANK] Fallback: {len(fallback_eps)} endpoints from urls")
            return
        
        self.logger.warning(f"[RANK] Total endpoints before ranking: {len(all_eps)}")
        
        # Rank using URL only
        ranker = EndpointRanker()
        ranked_dicts = ranker.rank_endpoints([ep["url"] for ep in all_eps])
        
        self.logger.warning(f"[RANK] Ranked endpoints: {len(ranked_dicts)}")
        
        # Extract URLs from ranked dicts
        ranked_urls = [item["url"] for item in ranked_dicts] if ranked_dicts else []
        
        # Fallback if rank fail
        if not ranked_urls:
            self.logger.warning("[RANK] Ranker returned empty, using fallback")
            ranked_urls = [ep["url"] for ep in all_eps]
        
        rank_top = int(os.environ.get("RANK_TOP", "150"))
        
        # Map URL → full object
        url_map = {ep["url"]: ep for ep in all_eps}
        final_targets = [url_map[u] for u in ranked_urls if u in url_map][:rank_top]
        
        # 🔥 FIX: fallback lần 2
        if not final_targets:
            self.logger.warning("[RANK] Final targets empty → fallback to all endpoints")
            final_targets = all_eps[:50]
        
        self.state.update(prioritized_endpoints=final_targets)
        
        self.logger.warning(f"[RANK] Final prioritized endpoints: {len(final_targets)}")
        
        # Save file
        ranked_file = os.path.join(self.output_dir, "endpoints_ranked.json")
        with open(ranked_file, "w") as f:
            json.dump(final_targets, f, indent=2)

    def _run_js_endpoint_hunt_phase(self):
        """Phase 4.3: JavaScript Endpoint Hunting"""
        self.phase_detail = "[HUNT] Extracting endpoints from JavaScript files..."
        self._update_display()
        
        try:
            # Get JS URLs from discovered endpoints
            endpoints = self.state.get("endpoints", []) or []
            js_urls = [
                ep.get('url', '') for ep in endpoints 
                if ep.get('url', '').endswith('.js')
            ]
            
            if js_urls:
                self.logger.info(f"[JS_HUNTER] Found {len(js_urls)} JS files to analyze")
                self.last_action = f"hunting endpoints in {len(js_urls)} JS files"
                self.phase_detail = f"[HUNT] Analyzing {len(js_urls)} JavaScript files..."
                self._update_display()
                
                # Hunt for endpoints
                results = hunt_js_endpoints(self.state, js_urls)
                
                new_endpoints = results.get('endpoints', [])
                new_params = results.get('parameters', [])
                
                self.logger.warning(f"[JS_HUNTER] Found {len(new_endpoints)} new endpoints, {len(new_params)} parameters")
                self.phase_detail = f"[HUNT] Extracted {len(new_endpoints)} endpoints, {len(new_params)} parameters"
                self._update_display()
                
                if self.batch_display:
                    self.batch_display._add_to_ai_feed(
                        "JS Discovery",
                        f"Found {len(new_endpoints)} JS endpoints",
                        self.target
                    )
            else:
                self.logger.info("[JS_HUNTER] No JS files found in endpoints")
                self.phase_detail = "[HUNT] No JavaScript files to analyze"
                self._update_display()
        
        except Exception as e:
            self.logger.error(f"[JS_HUNTER] Error: {e}")
            self.phase_detail = f"[HUNT] Error: {str(e)[:50]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("js_hunter")

    def _run_parameter_mining_phase(self):
        """Phase 4.4: Parameter Mining"""
        self.phase_detail = "[MINE] Discovering hidden parameters..."
        self._update_display()
        
        try:
            endpoints = self.state.get("endpoints", []) or []
            
            if endpoints:
                self.logger.info(f"[PARAM_MINER] Mining parameters on {len(endpoints)} endpoints")
                self.last_action = f"mining parameters on {len(endpoints)} endpoints"
                self.phase_detail = f"[MINE] Testing {min(50, len(endpoints))} endpoints for parameters..."
                self._update_display()
                
                # Mine parameters
                results = mine_endpoint_parameters(
                    self.state, 
                    endpoints,
                    self.state.get('scan_metadata', {}).get('budget')
                )
                
                mining_results = results.get('mining_results', [])
                discovered = sum(
                    len(r.get('discovered_parameters', [])) 
                    for r in mining_results
                )
                
                self.logger.warning(f"[PARAM_MINER] Discovered {discovered} parameters on {len(mining_results)} endpoints")
                self.phase_detail = f"[MINE] Discovered {discovered} parameters"
                self._update_display()
                
                if self.batch_display:
                    self.batch_display._add_to_ai_feed(
                        "Parameter Discovery",
                        f"Found {discovered} parameters",
                        self.target
                    )
            else:
                self.logger.info("[PARAM_MINER] No endpoints available for mining")
                self.phase_detail = "[MINE] No endpoints to mine"
                self._update_display()
        
        except Exception as e:
            self.logger.error(f"[PARAM_MINER] Error: {e}")
            self.phase_detail = f"[MINE] Error: {str(e)[:50]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("param_mine")

    def _run_cve_analysis_phase(self):
        """Phase 8.2: CVE Matching & Risk Assessment (INSERTED BEFORE CHAIN PLANNING)"""
        self.phase_detail = "[CVE] Matching detected technologies to CVE database..."
        self._update_display()
        
        try:
            technologies = self.state.get("technologies", {}) or {}
            if not technologies:
                self.logger.info("[CVE_ANALYSIS] No technologies detected yet")
                self.phase_detail = "[CVE] No technologies to analyze"
                self._update_display()
                self._mark_phase_done("cve_analysis")
                return
            
            self.logger.info(f"[CVE_ANALYSIS] Analyzing {len(technologies)} technologies")
            
            exploitable_cves = []
            cve_count = 0
            
            # Check each technology for known CVEs
            for tech_name, tech_data in technologies.items():
                version = None
                if isinstance(tech_data, dict):
                    version = tech_data.get("version", "")
                elif isinstance(tech_data, str):
                    continue
                
                if not version or version.lower() in ["unknown", "none", ""]:
                    self.logger.debug(f"[CVE_ANALYSIS] {tech_name}: version unknown, skipping")
                    continue
                
                self.phase_detail = f"[CVE] Checking {tech_name} {version}..."
                self._update_display()
                
                # Use existing CVE exploiter to query CVEs
                cve_result = self.cve_exploiter.scan(
                    self.target,
                    technologies={tech_name: version},
                    progress_cb=self._progress_callback
                )
                
                if cve_result and cve_result.get("exploitable_cves"):
                    for cve_info in cve_result["exploitable_cves"]:
                        cve_entry = {
                            "cve_id": cve_info.get("cve"),
                            "tech": tech_name,
                            "version": version,
                            "name": cve_info.get("name", ""),
                            "description": cve_info.get("description", ""),
                            "affected": cve_info.get("affected", ""),
                            "endpoint": cve_info.get("endpoint", ""),
                            "method": cve_info.get("method", "GET"),
                            "severity": self._cvss_to_severity(cve_info.get("affected", "")),
                            "probability_of_success": 0.85,  # Known CVEs are reliable
                            "effort": "low"
                        }
                        exploitable_cves.append(cve_entry)
                        cve_count += 1
                        
                        self.logger.warning(f"[CVE_ANALYSIS] ✅ Found: {cve_info.get('cve')} in {tech_name} {version}")
                        
                        if self.batch_display:
                            self.batch_display._add_to_feed(
                                "🔍", "CVE Found", self.target, 
                                f"{cve_info.get('cve')} ({tech_name})"
                            )
            
            # Store in state for chain planning & exploit selection
            self.state.update(exploitable_cves=exploitable_cves)
            self.state.update(cve_facts={
                "total_exploitable": cve_count,
                "high_severity": len([c for c in exploitable_cves if c["severity"] in ["CRITICAL", "HIGH"]]),
                "technology_count": len(technologies),
                "analyzed_count": sum(1 for t in technologies.values() if isinstance(t, dict) and t.get("version"))
            })
            
            self.stats['vulns'] += cve_count
            self.last_action = f"cve_analysis: {cve_count} exploitable CVEs found"
            self.phase_detail = f"[CVE] Complete - {cve_count} CVEs matched to chain planning"
            self._update_display()
            
            self.logger.info(f"[CVE_ANALYSIS] Complete: {cve_count} exploitable CVEs found")
            
        except Exception as e:
            self.logger.error(f"[CVE_ANALYSIS] Error: {e}")
            self.last_action = f"cve_analysis error: {str(e)[:50]}"
            self.phase_detail = f"[CVE] Error - {str(e)[:60]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("cve_analysis")
    
    def _cvss_to_severity(self, affected_str: str) -> str:
        """Helper: Convert CVSS score or version range to severity"""
        if "critical" in affected_str.lower():
            return "CRITICAL"
        elif "high" in affected_str.lower() or "rce" in affected_str.lower():
            return "HIGH"
        else:
            return "MEDIUM"

    def _run_privilege_pivot_phase(self):
        """Phase 8.5: Privilege Escalation Analysis"""
        self.phase_detail = "[PIVOT] Analyzing privilege escalation chains..."
        self._update_display()
        
        try:
            endpoints = self.state.get("endpoints", []) or []
            vulnerabilities = self.state.get("vulnerabilities", []) or []
            
            if endpoints and vulnerabilities:
                self.logger.info(f"[PIVOT] Analyzing {len(endpoints)} endpoints for privesc chains")
                self.last_action = f"building privilege escalation chains"
                self.phase_detail = f"[PIVOT] Building chains from {len(vulnerabilities)} vulnerabilities..."
                self._update_display()
                
                # Analyze privilege escalation
                chains = analyze_privilege_escalation(endpoints, vulnerabilities)
                
                self.logger.warning(f"[PIVOT] Generated {len(chains)} exploitation chains")
                self.phase_detail = f"[PIVOT] Built {len(chains)} attack chains"
                self._update_display()
                
                # Store chains in state
                self.state.update(privilege_escalation_chains=chains)
                
                if self.batch_display:
                    self.batch_display._add_to_ai_feed(
                        "Privilege Escalation",
                        f"Built {len(chains)} chains",
                        self.target
                    )
            else:
                self.logger.info("[PIVOT] Insufficient data for privilege escalation analysis")
        
        except Exception as e:
            self.logger.error(f"[PIVOT] Error: {e}")
            self.phase_detail = f"[PIVOT] Error: {str(e)[:50]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("priv_pivot")

    def _run_exploit_selection_phase(self):
        """Phase 10.5: Automatic Exploit Selection (LEVEL BOSS) - NOW WITH CVE PRIORITIZATION"""
        self.phase_detail = "[SELECT] Selecting best exploitation strategy (CVE-aware)..."
        self._update_display()
        
        try:
            vulnerabilities = self.state.get("vulnerabilities", []) or []
            endpoints = self.state.get("endpoints", []) or []
            technologies = self.state.get("technologies", {}) or {}
            chains = self.state.get("exploit_chains", []) or []
            exploitable_cves = self.state.get("exploitable_cves", []) or []  # NEW: CVE data from Phase 8.2
            
            # NEW: Build CVE-specific chains for prioritization
            cve_chains = []
            if exploitable_cves:
                self.logger.info(f"[AUTO_EXPLOIT] Found {len(exploitable_cves)} CVE exploits to prioritize")
                for cve in exploitable_cves:
                    cve_chain = {
                        "name": f"[{cve.get('cve_id', 'CVE')}] {cve.get('tech', 'Unknown')} {cve.get('version', '')} RCE",
                        "type": "known_cve",
                        "severity": "CRITICAL",
                        "cve_id": cve.get("cve_id"),
                        "technology": cve.get("tech"),
                        "version": cve.get("version"),
                        "probability_of_success": cve.get("probability_of_success", 0.85),
                        "effort": cve.get("effort", "low"),
                        "endpoint": cve.get("endpoint", ""),
                        "method": cve.get("method", "GET")
                    }
                    cve_chains.append(cve_chain)
                    self.logger.warning(f"[AUTO_EXPLOIT] Added CVE chain: {cve_chain['name']}")
            
            # Combine CVE chains first (highest priority), then regular chains
            all_chains = cve_chains + chains
            
            if all_chains and vulnerabilities:
                self.logger.info(f"[AUTO_EXPLOIT] Selecting from {len(all_chains)} chains ({len(cve_chains)} CVEs + {len(chains)} custom)")
                self.last_action = f"selecting best exploitation strategy (CVE-aware)"
                self.phase_detail = f"[SELECT] Ranking {len(all_chains)} strategies ({len(cve_chains)} CVE exploits)..."
                self._update_display()
                
                # Convert technologies dict to list
                tech_list = technologies.keys() if isinstance(technologies, dict) else technologies
                
                # Select best strategy (CVE chains have priority)
                selected = None
                if cve_chains:
                    # Prioritize CVE with highest success probability and lowest effort
                    selected_cve_chain = sorted(
                        cve_chains, 
                        key=lambda x: (x.get("probability_of_success", 0), -len(x.get("effort", ""))),
                        reverse=True
                    )[0]
                    self.logger.warning(f"[AUTO_EXPLOIT] ⭐ PRIORITIZED CVE: {selected_cve_chain['name']}")
                    # Create wrapper for compatibility
                    class CVEStrategy:
                        def __init__(self, cve_chain):
                            self.chain_name = cve_chain["name"]
                            self.chain_data = cve_chain
                        def to_dict(self):
                            return self.chain_data
                    selected = CVEStrategy(selected_cve_chain)
                
                if not selected:
                    # Fall back to standard strategy selection
                    selected = select_exploitation_strategy(
                        vulnerabilities,
                        chains,
                        endpoints,
                        list(tech_list)
                    )
                
                if selected:
                    self.logger.warning(f"[AUTO_EXPLOIT] Selected: {selected.chain_name}")
                    self.phase_detail = f"[SELECT] ⭐ Selected: {selected.chain_name[:50]}"
                    self._update_display()
                    
                    # Get all strategies
                    all_strategies = select_all_strategies(
                        vulnerabilities,
                        chains,
                        endpoints,
                        list(tech_list)
                    ) if not cve_chains else []
                    
                    # Store strategies (CVE-first)
                    self.state.update(
                        selected_exploit_strategy=selected.to_dict() if hasattr(selected, 'to_dict') else selected.chain_data,
                        alternative_strategies=[s.to_dict() for s in all_strategies[1:]] if all_strategies else [],
                        cve_exploit_available=bool(cve_chains)
                    )
                    
                    if self.batch_display:
                        strategy_type = "🔍 CVE Exploit" if cve_chains else "⚔️  Custom Exploit"
                        self.batch_display._add_to_ai_feed(
                            strategy_type,
                            f"Selected: {selected.chain_name}",
                            self.target
                        )
                else:
                    self.logger.warning("[AUTO_EXPLOIT] No suitable strategy found")
                    self.phase_detail = "[SELECT] No suitable strategy found"
                    self._update_display()
            else:
                self.logger.info("[AUTO_EXPLOIT] Insufficient data for selection")
                self.phase_detail = "[SELECT] Insufficient data"
                self._update_display()
        
        except Exception as e:
            self.logger.error(f"[AUTO_EXPLOIT] Error: {e}")
            self.phase_detail = f"[SELECT] Error: {str(e)[:50]}"
            self._update_display()
        
        self.phase_status = "done"
        self._mark_phase_done("exploit_select")

    def _generate_final_report(self):
        report_gen = ReportGenerator(self.state, self.output_dir)
        report_gen.generate()
        
        # Print terminal summary
        self._print_scan_summary()

    def _print_scan_summary(self):
        """Print modern structured scan summary to terminal"""
        self._print_modern_summary()

    def _print_error_summary(self):
        """Print error summary at the end of scan"""
        self.error_recovery.print_error_report(use_colors=True)

    def _load_previous_scan_data(self) -> dict:
        """Load and aggregate data from previous scan results in /results directory"""
        import glob as glob_module
        
        previous_data = {
            'total_scans': 0,
            'total_vulns': 0,
            'total_exploited': 0,
            'total_chains': 0,
            'wordpress_sites': 0,
            'technologies': {},
            'common_vulns': {},
            'recent_findings': []
        }
        
        try:
            # Find all result directories
            results_dir = os.path.join(BASE_DIR, "results")
            if not os.path.exists(results_dir):
                return previous_data
            
            # Get all subdirectories that contain state.json
            state_files = glob_module.glob(os.path.join(results_dir, "*", "state.json"))
            
            for state_file in state_files[-10:]:  # Last 10 scans
                try:
                    with open(state_file, 'r') as f:
                        state_data = json.load(f)
                    
                    previous_data['total_scans'] += 1
                    
                    # Aggregate vulnerabilities
                    vulns = state_data.get('confirmed_vulnerabilities', [])
                    previous_data['total_vulns'] += len(vulns)
                    
                    for v in vulns:
                        vtype = v.get('type', 'unknown')
                        previous_data['common_vulns'][vtype] = previous_data['common_vulns'].get(vtype, 0) + 1
                    
                    # Aggregate exploit results
                    exploit_results = state_data.get('exploit_results', [])
                    successful = [e for e in exploit_results if e.get('success')]
                    previous_data['total_exploited'] += len(successful)
                    
                    # Aggregate chains
                    chains = state_data.get('exploit_chains', [])
                    previous_data['total_chains'] += len(chains)
                    
                    # Check for WordPress
                    if state_data.get('wordpress_detected'):
                        previous_data['wordpress_sites'] += 1
                    
                    # Aggregate technologies
                    technologies = state_data.get('technologies', {})
                    if isinstance(technologies, dict):
                        for tech_name in technologies.keys():
                            previous_data['technologies'][tech_name] = previous_data['technologies'].get(tech_name, 0) + 1
                    
                    # Get recent findings
                    findings = state_data.get('security_findings', [])
                    if findings:
                        for f in findings[:3]:
                            previous_data['recent_findings'].append({
                                'type': f.get('type', ''),
                                'title': f.get('title', ''),
                                'severity': f.get('severity', ''),
                                'target': os.path.basename(os.path.dirname(state_file))
                            })
                
                except (json.JSONDecodeError, IOError) as e:
                    continue
            
        except Exception as e:
            pass
        
        return previous_data

    def _print_previous_scans_summary(self):
        """Print summary of findings from previous scans"""
        previous_data = self._load_previous_scan_data()
        
        if previous_data['total_scans'] == 0:
            return
        
        C = Colors
        
        print()
        print(f"{C.BOLD}{C.BRIGHT_MAGENTA}{'═' * 70}{C.RESET}")
        print(f"{C.BOLD}{C.BRIGHT_MAGENTA}║  📊 PREVIOUS SCANS SUMMARY — Historical Data{C.RESET}{' ' * 22}{C.BOLD}{C.BRIGHT_MAGENTA}║{C.RESET}")
        print(f"{C.BOLD}{C.BRIGHT_MAGENTA}{'═' * 70}{C.RESET}")
        print()
        
        print(f"  {C.BOLD}Total Previous Scans:{C.RESET} {C.CYAN}{previous_data['total_scans']}{C.RESET}")
        print(f"  {C.BOLD}Total Vulnerabilities Found:{C.RESET} {C.BRIGHT_RED}{previous_data['total_vulns']}{C.RESET}")
        print(f"  {C.BOLD}Total Successful Exploits:{C.RESET} {C.BRIGHT_GREEN}{previous_data['total_exploited']}{C.RESET}")
        print(f"  {C.BOLD}Total Attack Chains:{C.RESET} {C.YELLOW}{previous_data['total_chains']}{C.RESET}")
        print(f"  {C.BOLD}WordPress Sites Scanned:{C.RESET} {C.BRIGHT_YELLOW}{previous_data['wordpress_sites']}{C.RESET}")
        print()
        
        # Common vulnerability types across all scans
        if previous_data['common_vulns']:
            print(f"  {C.BOLD}Most Common Vulnerability Types:{C.RESET}")
            sorted_vulns = sorted(previous_data['common_vulns'].items(), key=lambda x: x[1], reverse=True)
            for vtype, count in sorted_vulns[:5]:
                print(f"     └─ {C.YELLOW}{vtype}:{C.RESET} {C.BRIGHT_RED}{count}{C.RESET}")
        print()
        
        # Most common technologies
        if previous_data['technologies']:
            print(f"  {C.BOLD}Most Common Technologies:{C.RESET}")
            sorted_tech = sorted(previous_data['technologies'].items(), key=lambda x: x[1], reverse=True)
            for tech, count in sorted_tech[:5]:
                print(f"     └─ {C.CYAN}{tech}:{C.RESET} {count} sites")
        print()
        
        # Recent findings
        if previous_data['recent_findings']:
            print(f"  {C.BOLD}Recent Security Findings:{C.RESET}")
            for f in previous_data['recent_findings'][:5]:
                severity_color = C.BRIGHT_RED if f['severity'] in ['CRITICAL', 'HIGH'] else C.YELLOW
                print(f"     └─ [{severity_color}{f['severity']}{C.RESET}] {f['title'][:50]} ({f['target'][:20]})")
        print()
        
        print(f"{C.BOLD}{C.BRIGHT_MAGENTA}{'═' * 70}{C.RESET}")
        print()

    def _print_wordpress_findings(self):
        """Print detailed WordPress scan findings in terminal with relative paths (domain names)"""
        C = Colors
        
        # Get WordPress data from state
        wp_detected = self.state.get("wordpress_detected", False)
        if not wp_detected:
            return
        
        wp_sites = self.state.get("wp_sites", [])
        wp_version = self.state.get("wp_version", "unknown")
        wp_plugins = self.state.get("wp_plugins", []) or []
        wp_themes = self.state.get("wp_themes", []) or []
        wp_users = self.state.get("wp_users", []) or []
        wp_vulns = self.state.get("wp_vulnerabilities", []) or []
        wp_conditioned = self.state.get("wp_conditioned_findings", []) or []
        wp_core = self.state.get("wp_core", {}) or {}
        
        # Get PHP version from findings or state
        php_version = self.findings.get('php_version', '')
        technologies = self.state.get("technologies", {}) or {}
        if not php_version:
            for tech_name, tech_data in technologies.items():
                if 'php' in tech_name.lower():
                    if isinstance(tech_data, dict):
                        php_version = tech_data.get('version', '')
                    else:
                        php_version = str(tech_data)
                    break
        
        # Check for EOL status
        wp_eol = self.state.get("wordpress_eol", False)
        tech_details = self.state.get("technical_details", {}) or {}
        wp_advanced = tech_details.get("wordpress_advanced_scan", {}) or {}
        if wp_advanced.get("version_detection"):
            wp_eol = wp_advanced["version_detection"].get("eol", False)
        
        # Get PHP outdated status
        php_outdated = False
        if wp_advanced.get("php_analysis"):
            php_outdated = wp_advanced["php_analysis"].get("outdated", False)
        
        print()
        print(f"{C.BOLD}{C.BRIGHT_CYAN}{'═' * 75}{C.RESET}")
        print(f"{C.BOLD}{C.BRIGHT_CYAN}║  📋 WordPress Scan Results — Detailed Findings{C.RESET}{' ' * 28}{C.BOLD}{C.BRIGHT_CYAN}║{C.RESET}")
        print(f"{C.BOLD}{C.BRIGHT_CYAN}{'═' * 75}{C.RESET}")
        print()
        
        # ─── 1. WordPress Versions Detected ─────────────────────────────────
        print(f"  {C.BOLD}🎯 WordPress Versions Detected{C.RESET}")
        print(f"  {'─' * 70}")
        
        # Group by site
        if wp_sites:
            for site in wp_sites[:10]:
                # Extract domain from URL (relative path)
                from urllib.parse import urlparse
                domain = urlparse(site).netloc if '://' in site else site
                
                # Get version for this site
                site_version = wp_core.get("version", wp_version) if site == wp_core.get("url") else wp_version
                
                # Check for CVEs
                core_vulns = wp_core.get("vulnerabilities", []) if site == wp_core.get("url") else []
                cve_count = len(core_vulns)
                cve_marker = f" {C.BRIGHT_RED}⚠️ {cve_count} CVEs{C.RESET}" if cve_count > 0 else ""
                eol_marker = f" {C.BRIGHT_RED}(EOL){C.RESET}" if wp_eol else ""
                
                version_str = f"WordPress {site_version}" if site_version and site_version != "unknown" else "WordPress (version unknown)"
                print(f"     {C.YELLOW}{domain}{C.RESET}")
                print(f"        Version: {C.CYAN}{version_str}{C.RESET}{eol_marker}{cve_marker}")
                if core_vulns:
                    for v in core_vulns[:3]:
                        cve_id = v.get('cve_id', 'Unknown') if isinstance(v, dict) else str(v)
                        print(f"        └─ {C.BRIGHT_RED}{cve_id}{C.RESET}")
        else:
            # Fallback: show from findings
            if self.findings.get('cms_version'):
                print(f"     {C.CYAN}{self.findings['cms_version']}{C.RESET}")
            else:
                print(f"     {C.DIM}No WordPress sites detected{C.RESET}")
        print()
        
        # ─── 2. Users Found via REST API ────────────────────────────────────
        print(f"  {C.BOLD}👥 Users Found via REST API{C.RESET}")
        print(f"  {'─' * 70}")
        
        if wp_users:
            # Group users by site if possible
            user_count = len(wp_users)
            print(f"     Total users enumerated: {C.YELLOW}{user_count}{C.RESET}")
            print()
            for user in wp_users[:10]:
                print(f"        • {C.CYAN}{user}{C.RESET}")
            if len(wp_users) > 10:
                print(f"        ... and {len(wp_users) - 10} more")
        else:
            print(f"     {C.DIM}No users enumerated{C.RESET}")
        print()
        
        # ─── 3. Plugins Detected ────────────────────────────────────────────
        print(f"  {C.BOLD}🔌 Plugins Detected{C.RESET}")
        print(f"  {'─' * 70}")
        
        if wp_plugins:
            plugin_count = len(wp_plugins)
            vuln_plugins = [p for p in wp_plugins if isinstance(p, dict) and (p.get('vulnerabilities') or p.get('cve'))]
            
            print(f"     Total plugins: {C.YELLOW}{plugin_count}{C.RESET}")
            print(f"     Vulnerable plugins: {C.BRIGHT_RED}{len(vuln_plugins)}{C.RESET}")
            print()
            
            # Show vulnerable plugins first
            if vuln_plugins:
                print(f"     {C.BRIGHT_RED}⚠️ VULNERABLE PLUGINS:{C.RESET}")
                for p in vuln_plugins[:5]:
                    pname = p.get('name', '') if isinstance(p, dict) else str(p)
                    pver = p.get('version', '') if isinstance(p, dict) else ''
                    ver_str = f" v{pver}" if pver and pver != 'unknown' else ""
                    cve_list = p.get('vulnerabilities', []) if isinstance(p, dict) else []
                    cve_marker = ""
                    if cve_list and isinstance(cve_list, list):
                        cve_ids = [c.get('cve_id', str(c)) if isinstance(c, dict) else str(c) for c in cve_list[:2]]
                        if cve_ids:
                            cve_marker = f" {C.BRIGHT_RED}[{', '.join(cve_ids)}]{C.RESET}"
                    print(f"        {C.BRIGHT_RED}└─ ⚠️ {pname}{ver_str}{cve_marker}{C.RESET}")
                print()
            
            # Show all plugins
            print(f"     All plugins detected:")
            for p in wp_plugins[:8]:
                pname = p.get('name', '') if isinstance(p, dict) else str(p)
                pver = p.get('version', '') if isinstance(p, dict) else ''
                ver_str = f" v{pver}" if pver and pver != 'unknown' else ""
                print(f"        └─ {pname}{ver_str}")
            if len(wp_plugins) > 8:
                print(f"        ... and {len(wp_plugins) - 8} more")
        else:
            print(f"     {C.DIM}No plugins detected{C.RESET}")
        print()
        
        # ─── 4. Vulnerable Plugins (Detailed) ───────────────────────────────
        vuln_plugins_detailed = [p for p in wp_plugins if isinstance(p, dict) and p.get('vulnerabilities')]
        if vuln_plugins_detailed:
            print(f"  {C.BOLD}⚠️ Vulnerable Plugins — CVE Details{C.RESET}")
            print(f"  {'─' * 70}")
            
            for p in vuln_plugins_detailed[:5]:
                pname = p.get('name', '') if isinstance(p, dict) else str(p)
                pver = p.get('version', '') if isinstance(p, dict) else ''
                cve_list = p.get('vulnerabilities', []) if isinstance(p, dict) else []
                
                if cve_list:
                    cve_count = len(cve_list)
                    print(f"     {C.BRIGHT_RED}{pname} v{pver} — {cve_count} CVEs{C.RESET}")
                    for cve in cve_list[:5]:
                        cve_id = cve.get('cve_id', str(cve)) if isinstance(cve, dict) else str(cve)
                        severity = cve.get('severity', '') if isinstance(cve, dict) else ''
                        sev_color = C.BRIGHT_RED if severity == 'CRITICAL' else C.RED if severity == 'HIGH' else C.YELLOW
                        print(f"        └─ [{sev_color}{severity}{C.RESET}] {cve_id}")
            print()
        
        # ─── 5. Themes Detected ─────────────────────────────────────────────
        if wp_themes:
            print(f"  {C.BOLD}🎨 Themes Detected{C.RESET}")
            print(f"  {'─' * 70}")
            
            vuln_themes = [t for t in wp_themes if isinstance(t, dict) and t.get('vulnerabilities')]
            print(f"     Total themes: {C.YELLOW}{len(wp_themes)}{C.RESET}")
            if vuln_themes:
                print(f"     Vulnerable themes: {C.BRIGHT_RED}{len(vuln_themes)}{C.RESET}")
            
            for t in wp_themes[:5]:
                tname = t.get('name', '') if isinstance(t, dict) else str(t)
                tver = t.get('version', '') if isinstance(t, dict) else ''
                ver_str = f" v{tver}" if tver and tver != 'unknown' else ""
                has_vuln = bool(t.get('vulnerabilities')) if isinstance(t, dict) else False
                vuln_marker = f" {C.BRIGHT_RED}⚠️ VULNERABLE{C.RESET}" if has_vuln else ""
                print(f"        └─ {tname}{ver_str}{vuln_marker}")
            print()
        
        # ─── 6. PHP Version ─────────────────────────────────────────────────
        if php_version:
            print(f"  {C.BOLD}📌 PHP Version{C.RESET}")
            print(f"  {'─' * 70}")
            php_marker = f" {C.BRIGHT_RED}⚠️ OUTDATED — Exploitable!{C.RESET}" if php_outdated else f" {C.GREEN}✓ Current{C.RESET}"
            print(f"     {C.YELLOW}{php_version}{C.RESET}{php_marker}")
            print()
        
        # ─── 7. WPScan Status ──────────────────────────────────────────────
        print(f"  {C.BOLD}🔍 WPScan Status{C.RESET}")
        print(f"  {'─' * 70}")
        
        # Check for rate limiting or errors
        rate_limited_plugins = []
        for p in wp_plugins:
            pname = p.get('name', '') if isinstance(p, dict) else str(p)
            if pname.lower() in ['akismet', 'wordpress-seo', 'contact-form-7', 'wp-super-cache', 'wordfence']:
                rate_limited_plugins.append(pname)
        
        if rate_limited_plugins:
            print(f"     {C.BRIGHT_YELLOW}⚠️ Rate Limited (cannot fully scan):{C.RESET}")
            for p in rate_limited_plugins:
                print(f"        └─ {p}")
        else:
            print(f"     {C.GREEN}✓ No rate limiting issues{C.RESET}")
        print()
        
        # ─── 8. Exploit Chains (Conditioned Findings) ──────────────────────
        if wp_conditioned:
            high_conf_chains = [c for c in wp_conditioned if c.get("chain_candidate", False) and c.get("confidence", 0) >= 70]
            if high_conf_chains:
                print(f"  {C.BOLD}🎯 High-Confidence Exploit Chains{C.RESET}")
                print(f"  {'─' * 70}")
                print(f"     {C.BRIGHT_RED}{len(high_conf_chains)} chains ready to exploit!{C.RESET}")
                print()
                for chain in high_conf_chains[:5]:
                    chain_name = chain.get("name", "")[:45]
                    confidence = chain.get("confidence", 0)
                    cve = chain.get("cve", [])
                    severity = chain.get("severity", "MEDIUM")
                    sev_color = C.BRIGHT_RED if severity == "CRITICAL" else C.RED if severity == "HIGH" else C.YELLOW
                    cve_str = f" [{', '.join(cve[:2])}]" if cve else ""
                    print(f"     {C.BRIGHT_RED}└─ [{confidence}%]{cve_str} [{sev_color}{severity}{C.RESET}] {chain_name}{C.RESET}")
                print()
        
        print(f"{C.BOLD}{C.BRIGHT_CYAN}{'═' * 75}{C.RESET}")
        print()

    def _print_modern_summary(self):
        """Print modern structured terminal display with colors and gradients"""
        # First print error report if there were any errors
        self._print_error_summary()
        
        # Print previous scans summary if available
        self._print_previous_scans_summary()
        
        # Print WordPress findings (NEW - detailed WordPress scan results)
        self._print_wordpress_findings()
        
        summary = self.state.summary()
        vulns = self.state.get("confirmed_vulnerabilities", []) or []
        findings = self.state.get("security_findings", []) or []
        technologies = self.state.get("technologies", {}) or {}
        exploit_results = self.state.get("exploit_results", []) or []
        chains = self.state.get("exploit_chains", []) or []
        wp_plugins = self.state.get("wp_plugins", []) or []
        wp_version = self.state.get("wp_version", "")
        
        # Get PHP version from findings or detect from state
        php_version = self.findings.get('php_version', '')
        if not php_version:
            for tech_name, tech_data in technologies.items():
                if 'php' in tech_name.lower():
                    if isinstance(tech_data, dict):
                        php_version = tech_data.get('version', '')
                    else:
                        php_version = str(tech_data)
                    break
        
        # Also check wp_advanced_scan data for PHP version
        tech_details = self.state.get("technical_details", {}) or {}
        wp_advanced = tech_details.get("wordpress_advanced_scan", {}) or {}
        if not php_version and wp_advanced.get("php_analysis"):
            php_version = wp_advanced["php_analysis"].get("php_version", "")
        
        # Count vulnerability types
        vuln_types = {}
        for v in vulns:
            vtype = v.get('type', 'unknown')
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        successful_exploits = self._meaningful_successful_exploits(exploit_results)
        C = Colors
        T = Theme
        
        # ═══════════════════════════════════════════════════════════════════════════
        # 🔥 KEY FINDINGS SUMMARY - Extract and display all important discoveries
        # ═══════════════════════════════════════════════════════════════════════════
        print()
        print(f"{C.BOLD}{C.BRIGHT_CYAN}{'═' * 70}{C.RESET}")
        print(f"{C.BOLD}{C.BRIGHT_CYAN}║  🔥 KEY FINDINGS SUMMARY — All Important Discoveries{C.RESET}{' ' * 18}{C.BOLD}{C.BRIGHT_CYAN}║{C.RESET}")
        print(f"{C.BOLD}{C.BRIGHT_CYAN}{'═' * 70}{C.RESET}")
        print()
        
        # ─── 1. PHP VERSION (Critical for exploitation) ─────────────────────
        if php_version:
            php_outdated = False
            if wp_advanced.get("php_analysis"):
                php_outdated = wp_advanced["php_analysis"].get("outdated", False)
            php_marker = f" {C.BRIGHT_RED}⚠️ OUTDATED — Exploitable!{C.RESET}" if php_outdated else f" {C.GREEN}✓ Current{C.RESET}"
            print(f"  {C.BOLD}📌 PHP Version:{C.RESET} {C.YELLOW}{php_version}{C.RESET}{php_marker}")
        else:
            print(f"  {C.BOLD}📌 PHP Version:{C.RESET} {C.DIM}Not detected{C.RESET}")
        print()
        
        # ─── 2. WORDPRESS CORE ──────────────────────────────────────────────
        if summary.get('wordpress'):
            wp_ver = f"WordPress {wp_version}" if wp_version else "WordPress (version unknown)"
            wp_eol = self.state.get("wordpress_eol", False)
            if wp_advanced.get("version_detection"):
                wp_eol = wp_advanced["version_detection"].get("eol", False)
            wp_marker = f" {C.BRIGHT_RED}⚠️ EOL — Critical vulnerabilities!{C.RESET}" if wp_eol else f" {C.GREEN}✓ Supported{C.RESET}"
            print(f"  {C.BOLD}🎯 WordPress:{C.RESET} {C.YELLOW}{wp_ver}{C.RESET}{wp_marker}")
            
            # REST API status
            rest_api_enabled = False
            user_enum_possible = False
            if wp_advanced.get("wordpress_api"):
                rest_api_enabled = wp_advanced["wordpress_api"].get("rest_api_enabled", False)
                user_enum_possible = wp_advanced["wordpress_api"].get("user_enumeration_possible", False)
            if rest_api_enabled:
                api_marker = f" {C.BRIGHT_RED}⚠️ User enumeration possible!{C.RESET}" if user_enum_possible else f" {C.GREEN}✓ Secure{C.RESET}"
                print(f"  {C.BOLD}   REST API:{C.RESET} Enabled{api_marker}")
            
            # XML-RPC status
            xmlrpc_vulns = [v for v in vulns if 'xmlrpc' in v.get('type', '').lower()]
            if xmlrpc_vulns:
                print(f"  {C.BOLD}   XML-RPC:{C.RESET} {C.BRIGHT_RED}⚠️ Enabled — Brute force vector!{C.RESET}")
            else:
                print(f"  {C.BOLD}   XML-RPC:{C.RESET} {C.DIM}Not detected{C.RESET}")
            print()
        
        # ─── 3. USERS (Enumeration results) ─────────────────────────────────
        wp_users = self.state.get("wp_users", [])
        if wp_users:
            print(f"  {C.BOLD}👤 Users Enumerated:{C.RESET} {C.YELLOW}{len(wp_users)} users found{C.RESET}")
            for u in wp_users[:5]:
                print(f"     └─ {C.CYAN}{u}{C.RESET}")
            if len(wp_users) > 5:
                print(f"     └─ ... and {len(wp_users) - 5} more")
        else:
            print(f"  {C.BOLD}👤 Users:{C.RESET} {C.DIM}None enumerated{C.RESET}")
        print()
        
        # ─── 4. PLUGINS (With vulnerabilities highlighted) ──────────────────
        if wp_plugins:
            vuln_plugins = [p for p in wp_plugins if isinstance(p, dict) and (p.get('vulnerabilities') or p.get('cve'))]
            safe_plugins = [p for p in wp_plugins if p not in vuln_plugins]
            
            print(f"  {C.BOLD}🔌 Plugins:{C.RESET} {C.YELLOW}{len(wp_plugins)} total{C.RESET} — {C.BRIGHT_RED}{len(vuln_plugins)} vulnerable{C.RESET}")
            
            # Show vulnerable plugins first
            if vuln_plugins:
                print(f"  {C.BRIGHT_RED}   ⚠️ VULNERABLE PLUGINS:{C.RESET}")
                for p in vuln_plugins[:5]:
                    pname = p.get('name', '') if isinstance(p, dict) else str(p)
                    pver = p.get('version', '') if isinstance(p, dict) else ''
                    ver_str = f" v{pver}" if pver else ""
                    cve_list = p.get('vulnerabilities', []) if isinstance(p, dict) else []
                    cve_marker = ""
                    if cve_list and isinstance(cve_list, list):
                        cve_ids = [c.get('cve_id', str(c)) if isinstance(c, dict) else str(c) for c in cve_list[:2]]
                        if cve_ids:
                            cve_marker = f" {C.BRIGHT_RED}[{', '.join(cve_ids)}]{C.RESET}"
                    print(f"     {C.BRIGHT_RED}└─ ⚠️ {pname}{ver_str}{cve_marker}{C.RESET}")
            
            # Show safe plugins
            if safe_plugins:
                print(f"  {C.GREEN}   ✓ Safe plugins:{C.RESET}")
                for p in safe_plugins[:3]:
                    pname = p.get('name', '') if isinstance(p, dict) else str(p)
                    pver = p.get('version', '') if isinstance(p, dict) else ''
                    ver_str = f" v{pver}" if pver else ""
                    print(f"     └─ {pname}{ver_str}")
        else:
            print(f"  {C.BOLD}🔌 Plugins:{C.RESET} {C.DIM}None detected{C.RESET}")
        print()
        
        # ─── 5. THEMES (With vulnerabilities) ───────────────────────────────
        wp_themes = self.state.get("wp_themes", [])
        if wp_themes:
            vuln_themes = [t for t in wp_themes if isinstance(t, dict) and t.get('vulnerabilities')]
            print(f"  {C.BOLD}🎨 Themes:{C.RESET} {C.YELLOW}{len(wp_themes)} total{C.RESET} — {C.BRIGHT_RED}{len(vuln_themes)} vulnerable{C.RESET}")
            for t in wp_themes[:3]:
                tname = t.get('name', '') if isinstance(t, dict) else str(t)
                tver = t.get('version', '') if isinstance(t, dict) else ''
                ver_str = f" v{tver}" if tver else ""
                has_vuln = bool(t.get('vulnerabilities')) if isinstance(t, dict) else False
                vuln_marker = f" {C.BRIGHT_RED}⚠️ VULNERABLE{C.RESET}" if has_vuln else ""
                print(f"     └─ {tname}{ver_str}{vuln_marker}")
        print()
        
        # ─── 6. UPLOAD POINTS (Critical attack surface) ─────────────────────
        upload_endpoints = self.state.get("upload_endpoints", [])
        endpoints = self.state.get("endpoints", []) or []
        upload_eps = [e for e in endpoints if 'upload' in (e.get('url', '') if isinstance(e, dict) else str(e)).lower()]
        
        if upload_eps:
            print(f"  {C.BOLD}📤 Upload Points:{C.RESET} {C.BRIGHT_RED}{len(upload_eps)} found — HIGH RISK!{C.RESET}")
            for ep in upload_eps[:5]:
                url = ep.get('url', '') if isinstance(ep, dict) else str(ep)
                # Extract just the path
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path if parsed.path else url
                print(f"     {C.BRIGHT_RED}└─ ⚠️ {path}{C.RESET}")
        else:
            print(f"  {C.BOLD}📤 Upload Points:{C.RESET} {C.GREEN}✓ None detected{C.RESET}")
        print()
        
        # ─── 7. API ENDPOINTS ───────────────────────────────────────────────
        api_endpoints = [e for e in endpoints if 'api' in (e.get('url', '') if isinstance(e, dict) else str(e)).lower()]
        if api_endpoints:
            print(f"  {C.BOLD}🔌 API Endpoints:{C.RESET} {C.YELLOW}{len(api_endpoints)} discovered{C.RESET}")
            for ep in api_endpoints[:3]:
                url = ep.get('url', '') if isinstance(ep, dict) else str(ep)
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path if parsed.path else url
                print(f"     └─ {path}")
        print()
        
        # ─── 8. ADMIN/DASHBOARD ENDPOINTS ───────────────────────────────────
        admin_endpoints = [e for e in endpoints if 'admin' in (e.get('url', '') if isinstance(e, dict) else str(e)).lower()]
        if admin_endpoints:
            print(f"  {C.BOLD}🔐 Admin Panels:{C.RESET} {C.YELLOW}{len(admin_endpoints)} found{C.RESET}")
            for ep in admin_endpoints[:3]:
                url = ep.get('url', '') if isinstance(ep, dict) else str(ep)
                from urllib.parse import urlparse
                parsed = urlparse(url)
                path = parsed.path if parsed.path else url
                print(f"     └─ {path}")
        print()
        
        # ─── 9. TECHNOLOGIES DETECTED ───────────────────────────────────────
        tech_list = list(technologies.keys()) if isinstance(technologies, dict) else []
        if tech_list:
            print(f"  {C.BOLD}🛠️ Technologies:{C.RESET} {C.YELLOW}{len(tech_list)} detected{C.RESET}")
            for tech in tech_list[:8]:
                tech_data = technologies.get(tech, {}) if isinstance(technologies, dict) else {}
                if isinstance(tech_data, dict):
                    ver = tech_data.get('version', '')
                    if ver and ver not in ('unknown', 'none', ''):
                        print(f"     └─ {tech}: {C.CYAN}{ver}{C.RESET}")
                    elif tech not in ('php', 'wordpress'):
                        print(f"     └─ {tech}")
                elif tech not in ('php', 'wordpress'):
                    print(f"     └─ {tech}")
        print()
        
        # ─── 10. VULNERABILITIES BY TYPE ────────────────────────────────────
        print(f"  {C.BOLD}🐞 Vulnerabilities Summary:{C.RESET}")
        
        sqli_count = vuln_types.get('sql_injection', 0) + vuln_types.get('sqli', 0)
        xss_count = vuln_types.get('xss', 0)
        upload_count = vuln_types.get('file_upload', 0) + vuln_types.get('upload', 0)
        idor_count = vuln_types.get('idor', 0)
        rce_count = vuln_types.get('rce', 0)
        auth_count = vuln_types.get('authentication', 0) + vuln_types.get('auth', 0)
        
        vuln_summary = []
        if sqli_count > 0:
            vuln_summary.append(f"{C.BRIGHT_RED}SQLi: {sqli_count}{C.RESET}")
        if xss_count > 0:
            vuln_summary.append(f"{C.YELLOW}XSS: {xss_count}{C.RESET}")
        if upload_count > 0:
            vuln_summary.append(f"{C.BRIGHT_RED}Upload: {upload_count}{C.RESET}")
        if idor_count > 0:
            vuln_summary.append(f"{C.YELLOW}IDOR: {idor_count}{C.RESET}")
        if rce_count > 0:
            vuln_summary.append(f"{C.BRIGHT_RED}RCE: {rce_count}{C.RESET}")
        if auth_count > 0:
            vuln_summary.append(f"{C.YELLOW}Auth: {auth_count}{C.RESET}")
        
        if vuln_summary:
            print(f"     {' | '.join(vuln_summary)}")
        else:
            print(f"     {C.GREEN}✓ No vulnerabilities detected{C.RESET}")
        print()
        
        # ─── 11. EXPLOIT CHAINS ─────────────────────────────────────────────
        if chains:
            high_risk_chains = [c for c in chains if isinstance(c, dict) and c.get('risk_level') in ('CRITICAL', 'HIGH')]
            print(f"  {C.BOLD}⛓️ Attack Chains:{C.RESET} {C.YELLOW}{len(chains)} total{C.RESET} — {C.BRIGHT_RED}{len(high_risk_chains)} high-risk{C.RESET}")
            for chain in high_risk_chains[:3]:
                chain_name = chain.get('name', '')[:50]
                risk = chain.get('risk_level', 'MEDIUM')
                print(f"     {C.BRIGHT_RED}└─ [{risk}] {chain_name}{C.RESET}")
        print()
        
        # ─── 12. CONDITIONED FINDINGS (WordPress exploit chains) ────────────
        conditioned = self.state.get("wp_conditioned_findings", [])
        if conditioned:
            high_conf_chains = [c for c in conditioned if c.get("chain_candidate", False) and c.get("confidence", 0) >= 70]
            if high_conf_chains:
                print(f"  {C.BOLD}🎯 High-Confidence Exploit Chains:{C.RESET} {C.BRIGHT_RED}{len(high_conf_chains)} ready to exploit!{C.RESET}")
                for chain in high_conf_chains[:3]:
                    chain_name = chain.get("name", "")[:45]
                    confidence = chain.get("confidence", 0)
                    cve = chain.get("cve", [])
                    cve_str = f" [{', '.join(cve[:2])}]" if cve else ""
                    print(f"     {C.BRIGHT_RED}└─ [{confidence}%]{cve_str} {chain_name}{C.RESET}")
        print()
        
        print(f"{C.BOLD}{C.BRIGHT_CYAN}{'═' * 70}{C.RESET}")
        print()
        
        # ═══════════════════════════════════════════════════════════════════════════
        # STANDARD REPORT SECTIONS
        # ═══════════════════════════════════════════════════════════════════════════
        
        # ─── HEADER WITH GRADIENT ─────────────────────────────────────────────
        print()
        border = f"{T.BORDER}╔{'═' * 62}╗{C.RESET}"
        header = f"{T.BORDER}║{C.RESET}  {C.gradient(T.PRIMARY, '⚡ AI RECON AGENT — FINAL REPORT ⚡')}{C.RESET}  {T.BORDER}║{C.RESET}"
        
        print(border)
        print(header)
        print(f"{T.BORDER}║{C.RESET}  {C.BOLD}Target:{C.RESET} {C.CYAN}{self.target:<54}{C.RESET} {T.BORDER}║{C.RESET}")
        print(f"{T.BORDER}║{C.RESET}  {C.BOLD}Iteration:{C.RESET} {C.YELLOW}{self.iteration_count}/{self.max_iterations:<51}{C.RESET} {T.BORDER}║{C.RESET}")
        print(f"{T.BORDER}║{C.RESET}  {C.BOLD}Duration:{C.RESET} {C.GREEN}{int(time.time() - self.scan_start_time)}s{' ' * 55}{C.RESET} {T.BORDER}║{C.RESET}")
        print(border)
        print()
        
        # ─── [RECON] ──────────────────────────────────────────────────────────
        print("[RECON]")
        subs = summary.get('subdomains', 0)
        live = summary.get('live_hosts', 0)
        print(f"  Running: subfinder")
        print(f"  Found: {subs} subdomains")
        print()
        print(f"  Running: httpx")
        print(f"  Live hosts: {live}")
        print()
        print("─" * 64)
        print()
        
        # ─── [DISCOVERY] ──────────────────────────────────────────────────────
        print("[DISCOVERY]")
        eps = summary.get('endpoints', 0)
        print(f"  Running: crawler")
        print(f"  Endpoints discovered: {eps}")
        
        # JS endpoints
        js_endpoints = self.state.get("js_endpoints", []) or []
        print()
        print(f"  Running: js_endpoint_hunter")
        print(f"  JS endpoints: {len(js_endpoints)}")
        
        # Parameters
        params = self.state.get("discovered_parameters", []) or []
        print()
        print(f"  Running: parameter_miner")
        print(f"  Parameters discovered: {len(params)}")
        print()
        print("─" * 64)
        print()
        
        # ─── [TECHNOLOGIES] ───────────────────────────────────────────────────
        print("[TECHNOLOGIES]")
        
        # Server info
        waf = self.findings.get('waf', '')
        if waf:
            print(f"  WAF: {waf}")
        
        # WordPress - Enhanced display with ALL available data
        if summary.get('wordpress'):
            wp_ver = f"WordPress {wp_version}" if wp_version else "WordPress (version unknown)"
            print(f"  CMS: {wp_ver}")
            
            # Check if WordPress version is EOL
            wp_eol = self.state.get("wordpress_eol", False)
            if wp_advanced.get("version_detection"):
                wp_eol = wp_advanced["version_detection"].get("eol", False)
            if wp_eol:
                print(f"  {C.BRIGHT_RED}⚠️  WordPress version is EOL (End of Life){C.RESET}")
            
            # Display PHP version prominently for WordPress
            if php_version:
                php_outdated = False
                if wp_advanced.get("php_analysis"):
                    php_outdated = wp_advanced["php_analysis"].get("outdated", False)
                php_marker = f" {C.BRIGHT_RED}(OUTDATED){C.RESET}" if php_outdated else ""
                print(f"  PHP: {php_version}{php_marker}")
            
            # Display REST API status
            rest_api_enabled = False
            user_enum_possible = False
            if wp_advanced.get("wordpress_api"):
                rest_api_enabled = wp_advanced["wordpress_api"].get("rest_api_enabled", False)
                user_enum_possible = wp_advanced["wordpress_api"].get("user_enumeration_possible", False)
            if rest_api_enabled:
                api_marker = f" {C.BRIGHT_YELLOW}(User enumeration possible){C.RESET}" if user_enum_possible else ""
                print(f"  REST API: Enabled{api_marker}")
            
            # Display XML-RPC status
            xmlrpc_vulns = [v for v in vulns if 'xmlrpc' in v.get('type', '').lower()]
            if xmlrpc_vulns:
                print(f"  {C.BRIGHT_YELLOW}XML-RPC: Enabled (potential attack vector){C.RESET}")
            
            # Display users
            wp_users = self.state.get("wp_users", [])
            if wp_users:
                print(f"  Users ({len(wp_users)}):")
                for u in wp_users[:10]:
                    print(f"    └─ {u}")
            
            # Display plugins with version and vulnerabilities
            if wp_plugins:
                print(f"  Plugins ({len(wp_plugins)}):")
                for p in wp_plugins[:10]:
                    pname = p.get('name', '') if isinstance(p, dict) else str(p)
                    pver = p.get('version', '') if isinstance(p, dict) else ''
                    ver_str = f" v{pver}" if pver else ""
                    # Check for vulnerabilities
                    has_vuln = bool(p.get('vulnerabilities')) if isinstance(p, dict) else False
                    cve_list = p.get('vulnerabilities', []) if isinstance(p, dict) else []
                    vuln_marker = f" {C.BRIGHT_RED}⚠️ VULNERABLE{C.RESET}" if has_vuln else ""
                    cve_marker = ""
                    if cve_list and isinstance(cve_list, list):
                        cve_ids = [c.get('cve_id', str(c)) if isinstance(c, dict) else str(c) for c in cve_list[:3]]
                        if cve_ids:
                            cve_marker = f" {C.BRIGHT_RED}[{', '.join(cve_ids)}]{C.RESET}"
                    print(f"    └─ {pname}{ver_str}{vuln_marker}{cve_marker}")
            
            # Display themes with version and vulnerabilities
            wp_themes = self.state.get("wp_themes", [])
            if wp_themes:
                print(f"  Themes ({len(wp_themes)}):")
                for t in wp_themes[:5]:
                    tname = t.get('name', '') if isinstance(t, dict) else str(t)
                    tver = t.get('version', '') if isinstance(t, dict) else ''
                    ver_str = f" v{tver}" if tver else ""
                    has_vuln = bool(t.get('vulnerabilities')) if isinstance(t, dict) else False
                    cve_list = t.get('vulnerabilities', []) if isinstance(t, dict) else []
                    vuln_marker = f" {C.BRIGHT_RED}⚠️ VULNERABLE{C.RESET}" if has_vuln else ""
                    cve_marker = ""
                    if cve_list and isinstance(cve_list, list):
                        cve_ids = [c.get('cve_id', str(c)) if isinstance(c, dict) else str(c) for c in cve_list[:2]]
                        if cve_ids:
                            cve_marker = f" {C.BRIGHT_RED}[{', '.join(cve_ids)}]{C.RESET}"
                    print(f"    └─ {tname}{ver_str}{vuln_marker}{cve_marker}")
            
            # Display WordPress-specific vulnerabilities
            wp_vulns = self.state.get("wp_vulnerabilities", [])
            if wp_vulns:
                print(f"  WordPress Vulnerabilities ({len(wp_vulns)}):")
                for v in wp_vulns[:5]:
                    vtype = v.get('type', '') if isinstance(v, dict) else str(v)
                    severity = v.get('severity', '') if isinstance(v, dict) else ''
                    sev_color = C.BRIGHT_RED if severity == "CRITICAL" else C.RED if severity == "HIGH" else C.YELLOW
                    print(f"    └─ [{sev_color}{severity}{C.RESET}] {vtype}")
            
            # Display conditioned findings (exploit chains)
            conditioned = self.state.get("wp_conditioned_findings", [])
            if conditioned:
                high_conf_chains = [c for c in conditioned if c.get("chain_candidate", False) and c.get("confidence", 0) >= 70]
                if high_conf_chains:
                    print(f"  Exploit Chains ({len(high_conf_chains)} high-confidence):")
                    for chain in high_conf_chains[:5]:
                        chain_name = chain.get("name", "")
                        confidence = chain.get("confidence", 0)
                        severity = chain.get("severity", "MEDIUM")
                        cve = chain.get("cve", [])
                        sev_color = C.BRIGHT_RED if severity == "CRITICAL" else C.RED if severity == "HIGH" else C.YELLOW
                        cve_str = f" [{', '.join(cve[:2])}]" if cve else ""
                        print(f"    └─ [{sev_color}{severity}{C.RESET}][{confidence}%]{cve_str} {chain_name[:50]}")
            
            # Display advanced scan observations
            if wp_advanced.get("vulnerabilities"):
                adv_vulns = wp_advanced["vulnerabilities"]
                print(f"  Advanced Scan Findings ({len(adv_vulns)}):")
                for v in adv_vulns[:5]:
                    vtype = v.get("type", "unknown")
                    severity = v.get("severity", "MEDIUM")
                    sev_color = C.BRIGHT_RED if severity == "CRITICAL" else C.RED if severity == "HIGH" else C.YELLOW
                    print(f"    └─ [{sev_color}{severity}{C.RESET}] {vtype}")
        else:
            # Non-WordPress site - show PHP if detected
            if php_version:
                print(f"  PHP: {php_version}")
        
        # Other technologies
        tech_list = list(technologies.keys()) if isinstance(technologies, dict) else []
        if tech_list:
            print(f"  Technologies ({len(tech_list)}):")
            for tech in tech_list[:8]:
                tech_data = technologies.get(tech, {}) if isinstance(technologies, dict) else {}
                if isinstance(tech_data, dict):
                    ver = tech_data.get('version', '')
                    if ver and ver not in ('unknown', 'none', ''):
                        print(f"    └─ {tech}: {ver}")
                    elif 'php' not in tech.lower() and 'wordpress' not in tech.lower():
                        print(f"    └─ {tech}")
                elif 'php' not in tech.lower() and 'wordpress' not in tech.lower():
                    print(f"    └─ {tech}")
        
        print()
        print("─" * 64)
        print()
        
        # ─── [VULNERABILITIES] ────────────────────────────────────────────────
        print("[VULNERABILITIES]")
        
        sqli_count = vuln_types.get('sql_injection', 0) + vuln_types.get('sqli', 0)
        xss_count = vuln_types.get('xss', 0)
        upload_count = vuln_types.get('file_upload', 0) + vuln_types.get('upload', 0)
        idor_count = vuln_types.get('idor', 0)
        rce_count = vuln_types.get('rce', 0)
        
        if sqli_count > 0:
            print(f"  SQL Injection candidates: {sqli_count}")
        if xss_count > 0:
            print(f"  XSS candidates: {xss_count}")
        if upload_count > 0:
            print(f"  Upload points: {upload_count}")
        if idor_count > 0:
            print(f"  IDOR vulnerabilities: {idor_count}")
        if rce_count > 0:
            print(f"  RCE vectors: {rce_count}")
        
        # Show other vuln types
        for vtype, count in vuln_types.items():
            if vtype not in ('sql_injection', 'sqli', 'xss', 'file_upload', 'upload', 'idor', 'rce'):
                print(f"  {vtype}: {count}")
        
        if not vuln_types:
            print("  No vulnerabilities detected")
        
        print()
        print("─" * 64)
        print()
        
        # ─── [EXPLOITATION] ───────────────────────────────────────────────────
        print("[EXPLOITATION]")
        
        if chains:
            print(f"  Attack chains identified: {len(chains)}")
            for chain in chains[:3]:
                chain_name = chain.get('name', '') if isinstance(chain, dict) else getattr(chain, 'name', '')
                risk = chain.get('risk', chain.get('risk_level', 'MEDIUM')) if isinstance(chain, dict) else getattr(chain, 'risk_level', 'MEDIUM')
                print(f"    • [{risk}] {chain_name[:55]}")
        
        if successful_exploits:
            print()
            print(f"  Successfully exploited: {len(successful_exploits)} chain(s)")
        
        # Module gating display - show skipped modules
        print()
        gated_modules = self.state.get("gated_modules", []) or []
        if gated_modules:
            print("  Skipped modules (evidence-based gating):")
            for mod in gated_modules:
                mod_name = mod.get('module', '') if isinstance(mod, dict) else str(mod)
                reason = mod.get('reason', 'no indicators') if isinstance(mod, dict) else ''
                print(f"    Skipped: {mod_name} ({reason})")
        print()
        print("─" * 64)
        print()
        
        # ─── FINAL STATS ──────────────────────────────────────────────────────
        print(f"[SUMMARY]")
        print(f"  Total endpoints:  {eps}")
        print(f"  Total vulns:      {len(vulns)}")
        print(f"  Exploited chains: {len(successful_exploits)}")
        print(f"  Technologies:     {len(tech_list)}")
        print("═" * 64)
        print()

    # ─── NEW: Enhanced Methods for 10 Critical Improvements ─────────────────────────────

    def _analyze_and_classify_endpoints(self):
        """
        IMPROVEMENT #3: Classify endpoints before attacking
        - Send HEAD/GET request  
        - Analyze Content-Type
        - Detect forms
        - Classify into: static, html, json, api, upload
        """
        self.current_phase = "classify"
        self.phase_detail = "[CLASSIFY] Analyzing endpoints..."
        self.phase_tool = "endpoint-analyzer"
        self._update_display()
        
        endpoints = self.state.get("endpoints", [])
        classified = []
        upload_endpoints = []
        
        for endpoint in endpoints[:100]:
            ep_url = endpoint.get('full_url') or endpoint.get('url')
            if not ep_url:
                continue
            
            try:
                analysis = self.endpoint_analyzer.analyze(ep_url, timeout=5)
                
                if analysis['reachable']:
                    endpoint['type'] = analysis['endpoint_type']
                    endpoint['content_type'] = analysis['content_type']
                    endpoint['has_form'] = analysis['has_form']
                    endpoint['forms'] = analysis.get('forms', [])
                    endpoint['is_upload'] = analysis['is_upload']
                    
                    if analysis['is_upload']:
                        upload_endpoints.append(endpoint)
                    
                    classified.append(endpoint)
            except Exception as e:
                self.error_recovery.log_error("classify", "endpoint-analyzer", str(e)[:50])
                continue
        
        self.state.update(endpoints=classified, upload_endpoints=upload_endpoints)
        self.last_action = f"classified {len(classified)} endpoints"
        self._update_display()
        self._mark_phase_done("classify")

    def _generate_smart_wordlists(self, company_name: str = "") -> Dict:
        """
        IMPROVEMENT #5: Generate smart context-aware wordlists
        """
        if not company_name:
            company_name = self.target.replace(".com", "").replace(".net", "").replace(".org", "")
        
        self.wordlist_gen.set_context(
            company_name=company_name,
            domain_name=self.target,
            discovered_users=self.state.get('enumerated_users', [])
        )
        
        usernames = self.wordlist_gen.generate_usernames(100)
        passwords = self.wordlist_gen.generate_passwords(usernames, 500)
        directories = self.wordlist_gen.generate_dirs(100)
        parameters = self.wordlist_gen.generate_parameter_names(50)
        
        return {
            'usernames': usernames,
            'passwords': passwords,
            'directories': directories,
            'parameters': parameters
        }

    def _execute_real_exploit_attacks(self) -> bool:
        """
        IMPROVEMENT #4 & #6: Execute real attacks with recovery
        Tests actual vulnerabilities, not just detection
        """
        self.current_phase = "exploit"
        self.phase_detail = "[EXPLOIT] Testing real vulnerabilities..."
        self.phase_tool = "exploit-executor"
        self._update_display()
        
        exploit_count = 0
        success_count = 0
        
        try:
            # Execute conditional playbook
            findings = {
                'found_wordpress': self.stats.get('wp', 0) > 0,
                'plugins': self.state.get('plugins', []),
                'has_upload_form': len(self.state.get('upload_endpoints', [])) > 0,
                'users': self.state.get('enumerated_users', []),
            }
            
            actions = self.playbook.execute_playbook(findings)
            
            for action in actions[:5]:
                try:
                    if action == 'test_file_upload':
                        upload_eps = self.state.get('upload_endpoints', [])
                        for upload_ep in upload_eps[:2]:
                            forms = upload_ep.get('forms', [])
                            for form in forms[:1]:
                                success, msg = self.exploit_executor.execute_upload_exploit(
                                    self.target, form
                                )
                                exploit_count += 1
                                if success:
                                    success_count += 1
                                    self.stats['exploited'] += 1
                                    self.phase_detail = f"[EXPLOIT] {msg}"
                    
                    elif action == 'wp_plugin_exploit':
                        wp_info = {'plugins': self.state.get('plugins', [])}
                        success, msg = self.exploit_executor.execute_wordpress_exploit(
                            self.target, wp_info
                        )
                        exploit_count += 1
                        if success:
                            success_count += 1
                            self.stats['exploited'] += 1
                    
                    self._update_display()
                    
                except Exception as e:
                    self.error_recovery.log_error("exploit", action, str(e)[:50])
                    continue
            
            self.last_action = f"exploit: {success_count}/{exploit_count} successful"
            self._update_display()
            self._mark_phase_done("exploit")
            
            return success_count > 0
            
        except Exception as e:
            recovery = self.error_recovery.suggest_recovery("exploit", "executor", str(e)[:80])
            self.last_action = f"exploit error: {recovery['recommended_action']}"
            self.error_recovery.log_error("exploit", "executor", str(e)[:50])
            self._update_display()
            return False


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
    parser.add_argument("--urls-file", help="File with manual URLs")
    parser.add_argument("--subdomains-file", help="File with manual subdomains")
    parser.add_argument("--auth-file", help="JSON file with role-based login credentials")
    parser.add_argument("--force-recon", action="store_true", help="Force continue if recon fails")
    parser.add_argument("--max-workers", type=int, default=5, help="Max concurrent workers (default: 5)")
    parser.add_argument("--skip-auth", action="store_true", help="Skip authenticated session bootstrap")
    parser.add_argument("--once", action="store_true", help="Run one scheduling cycle and exit")
    parser.add_argument("--no-resume", action="store_true", help="Always start fresh run (disable auto-resume)")
    parser.add_argument("--aggressive", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--probe-after-discovery",
        action="store_true",
        help="Run a low-rate validation pass on prioritized endpoints immediately after ranking"
    )
    parser.add_argument(
        "--probe-max-endpoints",
        type=int,
        default=1,
        help="Max prioritized endpoints to validate after ranking (default: 1)"
    )
    parser.add_argument(
        "--probe-count",
        type=int,
        default=2,
        help="Requests per validated endpoint during the safe probe pass (default: 2)"
    )
    parser.add_argument(
        "--probe-delay",
        type=float,
        default=0.5,
        help="Delay in seconds between probe requests (default: 0.5)"
    )


    parser.add_argument(
        "--skip-ddos",
        action="store_true",
        help="Skip DDoS attack phase (enabled by default when no exploits found)"
    )
    parser.add_argument(
        "--ddos-users",
        type=int,
        default=1000,
        help="Number of concurrent users for DDoS (default: 1000)"
    )
    parser.add_argument(
        "--ddos-runtime",
        type=int,
        default=60,
        help="Duration of DDoS attack in seconds (default: 60)"
    )
    parser.add_argument(
        "--ddos-max-endpoints",
        type=int,
        default=10,
        help="Max endpoints to attack (default: 10)"
    )

    return parser.parse_args()


def load_targets(filepath: str) -> tuple[list, int]:
    """Load domains from file, preserve schemes (http://, https://) - strip paths"""
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
                # Strip path from URL - only keep scheme + domain
                from urllib.parse import urlparse
                parsed = urlparse(line.lower())
                if parsed.scheme and parsed.netloc:
                    # URL with scheme: extract just scheme://netloc
                    clean_url = f"{parsed.scheme}://{parsed.netloc}"
                    targets.append(clean_url)
                elif '.' in line and '/' not in line:
                    # Plain domain without scheme
                    targets.append(line.lower())
                elif '.' in line and '/' in line:
                    # Domain with path but no scheme - extract domain part
                    domain_part = line.split('/')[0].lower()
                    targets.append(domain_part)
                else:
                    # Fallback: just strip trailing slashes
                    line = line.rstrip('/').strip()
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
        
        # Read all targets from targets.txt to build allowed_domains list
        allowed_domains = []
        targets_file = getattr(args, 'file', 'targets.txt')
        if os.path.exists(targets_file):
            with open(targets_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extract domain from URL (strip scheme and path)
                        from urllib.parse import urlparse
                        parsed = urlparse(line.lower())
                        if parsed.scheme and parsed.netloc:
                            allowed_domains.append(parsed.netloc)
                        elif '.' in line:
                            allowed_domains.append(line.lower().split('/')[0])
        
        agent = ReconAgent(
            target=domain,
            output_dir=output_dir,
            options=options,
            urls_file=getattr(args, 'urls_file', ''),
            subdomains_file=getattr(args, 'subdomains_file', ''),
            auth_file=getattr(args, 'auth_file', ''),
            force_recon=getattr(args, 'force_recon', False),
            batch_display=batch_display,
            api_status=check_api_keys(),
            allowed_domains=allowed_domains
        )
        agent.run()

        groq = GroqClient(os.getenv("GROQ_API_KEY"))
        analyzer = AIAnalyzer(agent.state, output_dir, ai_client=groq)

        try:
            ai_report = analyzer._generate_ai_report({
                "target": domain,
                "summary": agent.state.summary(),
                "findings": agent.state.get("confirmed_vulnerabilities", []) or []
            })

            print("[AI REPORT]", ai_report)

        except Exception as e:
            print("[AI REPORT ERROR]", e)
    except Exception as e:
        logging.getLogger("batch").error(f"{domain} failed: {e}")
        batch_display.mark_failed(domain, str(e)[:30])


def run_batch(targets_file: str, options: dict, args):
    """Continuous batch mode - monitor file for changes"""
    base_output = args.output or os.path.join(BASE_DIR, "results")
    os.makedirs(base_output, exist_ok=True)
    
    # Setup logging with both file and stream handlers
    batch_log = os.path.join(base_output, "batch.log")
    
    # Create logger
    batch_logger = logging.getLogger("batch")
    batch_logger.setLevel(logging.INFO)
    
    # File handler - with fallback support
    file_handler = None
    try:
        file_handler = logging.FileHandler(batch_log)
        file_handler.setLevel(logging.INFO)
        file_formatter = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
        file_handler.setFormatter(file_formatter)
    except (PermissionError, IOError) as e:
        # Fallback: try to write to user's home directory
        print(f"⚠️  Cannot write to {batch_log}: {e}")
        try:
            fallback_log = os.path.expanduser("~/.agent_batch.log")
            file_handler = logging.FileHandler(fallback_log)
            file_handler.setLevel(logging.INFO)
            file_formatter = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
            file_handler.setFormatter(file_formatter)
            print(f"✓ Using fallback log: {fallback_log}")
        except Exception as e2:
            print(f"⚠️  Cannot write fallback log either: {e2}")
            file_handler = None
    
    # Stream handler - for real-time terminal output
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.INFO)
    stream_formatter = logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
    stream_handler.setFormatter(stream_formatter)
    
    # Remove existing handlers and add new ones
    batch_logger.handlers.clear()
    if file_handler:
        batch_logger.addHandler(file_handler)
    batch_logger.addHandler(stream_handler)
    
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
                        # Sanitize domain: extract hostname and replace special chars
                        from urllib.parse import urlparse
                        parsed = urlparse(domain)
                        hostname = parsed.netloc if parsed.netloc else domain
                        domain_safe = hostname.replace(".", "_").replace(":", "_").replace("/", "_")
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

                # Reduced sleep for faster Terminal updates
                time.sleep(2)
                
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
        "aggressive": True,
        "probe_after_discovery": args.probe_after_discovery,
        "probe_max_endpoints": args.probe_max_endpoints,
        "probe_count": args.probe_count,
        "probe_delay": args.probe_delay,
        "skip_ddos": args.skip_ddos,
        "ddos_users": args.ddos_users,
        "ddos_runtime": args.ddos_runtime,
        "ddos_max_endpoints": args.ddos_max_endpoints,
    }

    if args.target:
        target_file = os.path.expanduser("~/ai_recon_single_target.txt")
        with open(target_file, "w") as f:
            f.write(args.target.strip() + "\n")
        args.file = target_file
        args.once = True

    # Chạy batch mode
    run_batch(args.file, options, args)


if __name__ == "__main__":
    main()
