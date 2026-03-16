"""
agent.py - AI Recon Agent Main Orchestrator
Autonomous Security Testing Agent with Knowledge-Driven Architecture
NO HARDCODED LOGIC - Rules + AI + Graph Driven
"""

import argparse
import logging
import os
import sys
import json
import time
import signal
from datetime import datetime
from typing import Dict, List, Any

# ─── Setup paths ─────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ─── Core Components ─────────────────────────────────────────────────────────
from core.state_manager import StateManager
from core.endpoint_ranker import EndpointRanker
from core.url_normalizer import URLNormalizer
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

from modules.wp_scanner import WordPressScannerEngine

# ─── Learning & Rules ────────────────────────────────────────────────────────
from learning.learning_engine import LearningEngine

# ─── Integrations ────────────────────────────────────────────────────────────
from integrations.gau_runner import GAURunner
from integrations.wayback_runner import WaybackRunner
from integrations.subfinder_runner import SubfinderRunner

# ─── Reports ─────────────────────────────────────────────────────────────────
from reports.report_generator import ReportGenerator


# ─── Logging Setup ────────────────────────────────────────────────────────────
def setup_logging(output_dir: str, verbose: bool = False) -> logging.Logger:
    os.makedirs(output_dir, exist_ok=True)
    log_file = os.path.join(output_dir, "agent.log")

    level = logging.DEBUG if verbose else logging.INFO

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(formatter)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(fh)
    root.addHandler(ch)

    return logging.getLogger("recon.agent")


# ─── Banner ───────────────────────────────────────────────────────────────────
BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║          █████╗ ██╗    ██████╗ ███████╗ ██████╗ ███╗   ██╗  ║
║         ██╔══██╗██║    ██╔══██╗██╔════╝██╔════╝ ████╗  ██║  ║
║         ███████║██║    ██████╔╝█████╗  ██║      ██╔██╗ ██║  ║
║         ██╔══██║██║    ██╔══██╗██╔══╝  ██║      ██║╚██╗██║  ║
║         ██║  ██║██║    ██║  ██║███████╗╚██████╔╝██║ ╚████║  ║
║         ╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝  ║
║                                                              ║
║              AI-POWERED WEB RECONNAISSANCE AGENT            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


# ─── Main Agent ───────────────────────────────────────────────────────────────
class ReconAgent:
    def __init__(self, target: str, output_dir: str, options: dict,
                 wps_token: str = "", nvd_key: str = ""):
        self.target = target.lower().strip()
        self.output_dir = output_dir
        self.options = options
        self.wps_token = wps_token
        self.nvd_key = nvd_key
        
        # Initialize core components
        self.state = StateManager(self.target, output_dir)
        self.session = SessionManager()
        self.http_client = HTTPClient(self.session)
        self.learning_engine = LearningEngine(output_dir)
        
        # Initialize AI components with Groq
        groq_key = os.environ.get("GROQ_API_KEY", "")
        self.endpoint_classifier = EndpointClassifier(groq_key)
        self.payload_gen = PayloadGenerator(groq_key)
        self.payload_mutator = PayloadMutator()
        self.vuln_analyzer = AIAnalyzer(self.state, output_dir, groq_key)
        self.chain_planner = ChainPlanner(self.state)
        
        # Initialize engines
        self.recon_engine = ReconEngine(self.state, output_dir)
        self.live_host_engine = LiveHostEngine(self.state, output_dir)
        self.discovery_engine = DiscoveryEngine(self.state, output_dir)
        self.scanning_engine = ScanningEngine(self.state, output_dir, self.payload_gen, self.payload_mutator)
        self.exploit_engine = ExploitTestEngine(self.state, output_dir)
        self.wp_scanner = WordPressScannerEngine(self.state, output_dir)
        
        self.logger = logging.getLogger("recon.agent")
        self.start_time = time.time()
        self.iteration_count = 0
        self.max_iterations = 5  # Prevent infinite loops
        self.confidence_threshold = 0.8

    def run(self):
        """Execute the autonomous security testing loop"""
        self.logger.info(f"🎯 Target: {self.target}")
        self.logger.info(f"📁 Output: {self.output_dir}")
        self.logger.info(f"⚙️  Options: {self.options}")

        try:
            # Initialize attack graph
            attack_graph = AttackGraph()
            
            # Main autonomous loop
            while self.iteration_count < self.max_iterations:
                self.iteration_count += 1
                self.logger.info(f"\n{'='*60}")
                self.logger.info(f"  ITERATION {self.iteration_count}/{self.max_iterations}")
                self.logger.info(f"{'='*60}")
                
                # Phase 2: Live Host Detection
                if not self._should_skip_phase("live_hosts"):
                    self._run_live_hosts_phase()
                
                # Phase 3: WordPress Detection & Scanning
                if not self._should_skip_phase("wordpress"):
                    self._run_wordpress_phase()
                
                # Phase 4: Endpoint Discovery
                if not self._should_skip_phase("discovery"):
                    self._run_discovery_phase()
                
                # Phase 5: Endpoint Classification
                self._run_classification_phase()
                
                # Phase 6: Endpoint Prioritization
                self._run_prioritization_phase()
                
                # Phase 7: Scanning & Testing
                if not self._should_skip_phase("scan"):
                    self._run_scanning_phase()
                
                # Phase 8: Response Analysis
                self._run_analysis_phase()
                
                # Phase 9: Attack Graph Construction
                self._run_attack_graph_phase(attack_graph)
                
                # Phase 10: Chain Planning
                self._run_chain_planning_phase(attack_graph)
                
                # Phase 11: Exploit Testing
                if not self._should_skip_phase("exploit"):
                    self._run_exploit_phase()
                
                # Phase 12: Learning & Adaptation
                self._run_learning_phase()
                
                # Check confidence and decide to continue
                if self._check_confidence_threshold():
                    self.logger.info("[AGENT] Confidence threshold reached, stopping iterations")
                    break
                    
                # Learn from failures and mutate payloads
                self._adapt_for_next_iteration()
                
            # Final Report Generation
            self._generate_final_report()
            self._print_final_summary()
            
        except KeyboardInterrupt:
            self.logger.warning("\n[AGENT] Scan interrupted by user. Saving state...")
            self.state.save()
            self._generate_final_report()
        except Exception as e:
            self.logger.error(f"[AGENT] Fatal error: {e}", exc_info=True)
            self.state.add_error(str(e))
            self.state.save()
            raise

    def _should_skip_phase(self, phase: str) -> bool:
        """Check if a phase should be skipped based on options"""
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
        """Phase 1: Reconnaissance - Discover surface area"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 1: RECONNAISSANCE")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("recon")
        
        self.recon_engine.run()
        
        # Validate live hosts
        self.live_host_engine.detect_live_hosts(self.state.get("subdomains", []))

    def _run_live_hosts_phase(self):
        """Phase 2: Live Host Detection"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 2: LIVE HOST DETECTION")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("live_hosts")
        
        # Already done in recon phase, but can be run separately if needed
        pass

    def _run_wordpress_phase(self):
        """Phase 3: WordPress Detection & Scanning"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 3: WORDPRESS SCANNING")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("wordpress")
        
        live_hosts = self.state.get("live_hosts", [])
        target_urls = [host.get("url", "") for host in live_hosts if host.get("url")]
        
        if target_urls:
            self.wp_scanner.scan_wordpress_sites(target_urls)

    def _run_discovery_phase(self):
        """Phase 2: Endpoint Discovery - Extract endpoints from sources"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 2: ENDPOINT DISCOVERY")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("discovery")
        
        self.discovery_engine.run()

    def _run_classification_phase(self):
        """Phase 3: AI Endpoint Classification"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 3: ENDPOINT CLASSIFICATION")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("classification")
        
        endpoints = self.state.get("endpoints", [])
        classified = []
        
        for endpoint in endpoints:
            classification = self.endpoint_classifier.classify(endpoint)
            endpoint.update(classification)
            classified.append(endpoint)
            
        self.state.update(classified_endpoints=classified)

    def _run_prioritization_phase(self):
        """Phase 4: Endpoint Risk Ranking"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 4: ENDPOINT PRIORITIZATION")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("prioritization")
        
        self._run_endpoint_ranking()

    def _run_scanning_phase(self):
        """Phase 5: Vulnerability Scanning with AI-generated payloads"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 5: VULNERABILITY SCANNING")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("scanning")
        
        self.scanning_engine.run()

    def _run_analysis_phase(self):
        """Phase 6: Response Analysis & Vulnerability Reasoning"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 6: RESPONSE ANALYSIS")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("analysis")
        
        responses = self.state.get("scan_responses", [])
        vulnerabilities = []
        
        for response in responses:
            analysis = self.vuln_analyzer.analyze_response(response)
            if analysis.get("is_vulnerable"):
                vulnerabilities.append(analysis)
                
        self.state.update(confirmed_vulnerabilities=vulnerabilities)

    def _run_attack_graph_phase(self, attack_graph: AttackGraph):
        """Phase 7: Attack Graph Construction"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 7: ATTACK GRAPH CONSTRUCTION")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("attack_graph")
        
        vulnerabilities = self.state.get("confirmed_vulnerabilities", [])
        attack_graph.build_from_vulnerabilities(vulnerabilities)
        
        # Save graph
        graph_file = os.path.join(self.output_dir, "attack_graph.json")
        attack_graph.save_to_file(graph_file)

    def _run_chain_planning_phase(self, attack_graph: AttackGraph):
        """Phase 8: Exploit Chain Planning"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 8: CHAIN PLANNING")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("chain_planning")
        
        chains = self.chain_planner.plan_chains_from_graph(attack_graph)
        self.state.update(exploit_chains=chains)

    def _run_exploit_phase(self):
        """Phase 9: Exploit Testing"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 9: EXPLOIT TESTING")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("exploitation")
        
        chains = self.state.get("exploit_chains", [])
        results = []
        
        for chain in chains[:3]:  # Test top 3 chains
            result = self.exploit_engine.test_chain(chain)
            results.append(result)
            
        self.state.update(exploit_results=results)

    def _run_learning_phase(self):
        """Phase 10: Learning from Results"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info("  PHASE 10: LEARNING & ADAPTATION")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("learning")
        
        self.learning_engine.learn_from_iteration(self.state)

    def _check_confidence_threshold(self) -> bool:
        """Check if we've reached sufficient confidence to stop iterating"""
        vulnerabilities = self.state.get("confirmed_vulnerabilities", [])
        exploit_results = self.state.get("exploit_results", [])
        
        if not vulnerabilities:
            return False
            
        successful_exploits = [r for r in exploit_results if r.get("success")]
        confidence = len(successful_exploits) / len(vulnerabilities) if vulnerabilities else 0
        
        self.logger.info(f"[AGENT] Current confidence: {confidence:.2f} (threshold: {self.confidence_threshold})")
        return confidence >= self.confidence_threshold

    def _adapt_for_next_iteration(self):
        """Adapt payloads and strategies for next iteration based on learning"""
        failed_payloads = self.learning_engine.get_failed_payloads()
        if failed_payloads:
            self.logger.info(f"[AGENT] Mutating {len(failed_payloads)} failed payloads for next iteration")
            mutated = self.payload_mutator.mutate_payloads(failed_payloads)
            self.payload_gen.add_mutated_payloads(mutated)

    def _run_endpoint_ranking(self):
        """Phase 4: Score and rank all discovered endpoints"""
        urls = self.state.get("urls", [])
        endpoints = self.state.get("endpoints", [])

        # Combine all URLs for ranking
        all_urls = list(set(urls + [ep.get("url", "") for ep in endpoints if ep.get("url")]))

        if not all_urls:
            self.logger.warning("[RANK] No URLs to rank")
            return

        ranker = EndpointRanker()
        ranked = ranker.rank_endpoints(all_urls)

        # Show top risky
        ranker.print_top(ranked, n=20)

        # Số endpoint ưu tiên lưu (env RANK_TOP=150 để tăng)
        rank_top = int(os.environ.get("RANK_TOP", "150"))
        self.state.update(prioritized_endpoints=ranked[:rank_top])

        # Save to file
        ranked_file = os.path.join(self.output_dir, "endpoints_ranked.json")
        with open(ranked_file, "w") as f:
            json.dump(ranked[:rank_top], f, indent=2)

        self.logger.info(f"[RANK] Saved ranked endpoints → {ranked_file}")

    def _generate_final_report(self):
        """Generate comprehensive final report"""
        report_gen = ReportGenerator(self.state, self.output_dir)
        report_gen.generate()

    def _print_final_summary(self):
        elapsed = time.time() - self.start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        summary = self.state.summary()
        exploit_results = self.state.get("exploit_results", [])
        successful = [r for r in exploit_results if r.get("success")]

        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE - {mins}m {secs}s - {self.iteration_count} iterations")
        """Phase 4: Score and rank all discovered endpoints"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"  PHASE 4: ENDPOINT PRIORITIZATION")
        self.logger.info(f"{'='*60}")
        self.state.set_phase("endpoint_ranking")

        urls = self.state.get("urls", [])
        endpoints = self.state.get("endpoints", [])

        # Combine all URLs for ranking
        all_urls = list(set(urls + [ep.get("url", "") for ep in endpoints if ep.get("url")]))

        if not all_urls:
            self.logger.warning("[RANK] No URLs to rank")
            return

        ranker = EndpointRanker()
        ranked = ranker.rank_endpoints(all_urls)

        # Show top risky
        ranker.print_top(ranked, n=20)

        # Số endpoint ưu tiên lưu (env RANK_TOP=150 để tăng)
        rank_top = int(os.environ.get("RANK_TOP", "150"))
        self.state.update(prioritized_endpoints=ranked[:rank_top])

        # Save to file
        ranked_file = os.path.join(self.output_dir, "endpoints_ranked.json")
        with open(ranked_file, "w") as f:
            json.dump(ranked[:rank_top], f, indent=2)

        self.logger.info(f"[RANK] Saved ranked endpoints → {ranked_file}")

    def _generate_final_report(self):
        """Generate comprehensive final report"""
        report_gen = ReportGenerator(self.state, self.output_dir)
        report_gen.generate()

    def _print_final_summary(self):
        elapsed = time.time() - self.start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        summary = self.state.summary()
        exploit_results = self.state.get("exploit_results", [])
        successful = [r for r in exploit_results if r.get("success")]

        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE - {mins}m {secs}s - {self.iteration_count} iterations")
        print(f"{'='*60}")
        print(f"  Target        : {self.target}")
        print(f"  Subdomains    : {summary['subdomains']}")
        print(f"  Live Hosts    : {summary['live_hosts']}")
        print(f"  URLs          : {summary['urls']}")
        print(f"  Endpoints     : {summary['endpoints']}")
        print(f"  Vulnerabilities: {summary['vulnerabilities']}")
        print(f"  Exploit Chains: {len(self.state.get('exploit_chains', []))}")
        print(f"  Successful Exploits: {len(successful)}")
        print(f"  Iterations    : {self.iteration_count}")
        print(f"{'='*60}")
        print(f"  Output Dir    : {self.output_dir}")
        print(f"{'='*60}\n")

        self.logger.info("[AGENT] Done!")
        print(f"{'='*60}")
        print(f"  Target        : {self.target}")
        print(f"  Subdomains    : {summary['subdomains']}")
        print(f"  Live Hosts    : {summary['live_hosts']}")
        print(f"  URLs          : {summary['urls']}")
        print(f"  Endpoints     : {summary['endpoints']}")
        print(f"  Vulnerabilities: {summary['vulnerabilities']}")
        print(f"  Exploits      : {len(exploit_results)} attempted, {len(successful)} successful")
        print(f"  WordPress     : {'YES' if summary['wordpress'] else 'NO'}")
        print(f"{'='*60}")
        print(f"  Output Dir    : {self.output_dir}")
        print(f"{'='*60}\n")

        self.logger.info("[AGENT] Done!")


# ─── CLI Entry Point ──────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="AI Recon Agent - Automated Web Security Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # Single target
  python agent.py -t example.com
  python agent.py -t example.com --no-exploit

  # Batch mode (file.txt, one domain per line)
  python agent.py -f targets.txt
  python agent.py -f targets.txt --no-exploit --skip-recon
  python agent.py -f targets.txt --delay 30 --workers 1
        """
    )

    # Target: single hoặc file
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "-t", "--target",
        help="Single target domain (e.g. example.com)"
    )
    target_group.add_argument(
        "-f", "--file",
        help="File chứa danh sách domain, mỗi dòng một domain"
    )

    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Custom output base dir (default: results/)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--no-exploit",
        action="store_true",
        help="Disable exploitation phase (recon only)"
    )
    parser.add_argument(
        "--auto-exploit",
        action="store_true",
        help="Automatically execute planned exploit chains (dangerous!)"
    )
    parser.add_argument(
        "--skip-recon",
        action="store_true",
        help="Skip subdomain enumeration"
    )
    parser.add_argument(
        "--skip-live",
        action="store_true",
        help="Skip live host detection"
    )
    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help="Skip crawling"
    )
    parser.add_argument(
        "--skip-scan",
        action="store_true",
        help="Skip vulnerability scanning"
    )
    parser.add_argument(
        "--skip-wp",
        action="store_true",
        help="Skip WordPress scanning"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume: bỏ qua domain đã scan xong (chỉ dùng với -f)"
    )
    parser.add_argument(
        "--delay",
        type=int,
        default=5,
        help="Delay (giây) giữa các domain khi batch mode (default: 5)"
    )

    parser.add_argument(
        "--wps-token",
        default="",
        help="WPScan API token (hoac set env WPSCAN_API_TOKEN)"
    )
    parser.add_argument(
        "--nvd-key",
        default="",
        help="NVD API key (hoac set env NVD_API_KEY)"
    )

    return parser.parse_args()


# ─── Batch State Tracker ──────────────────────────────────────────────────────

class BatchTracker:
    """
    Theo dõi tiến trình batch scan.
    Lưu vào batch_progress.json để có thể resume.
    """
    def __init__(self, base_dir: str):
        self.progress_file = os.path.join(base_dir, "batch_progress.json")
        self.data = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.progress_file):
            try:
                with open(self.progress_file) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"done": [], "failed": [], "skipped": [], "started": datetime.now().isoformat()}

    def save(self):
        os.makedirs(os.path.dirname(self.progress_file), exist_ok=True)
        with open(self.progress_file, "w") as f:
            json.dump(self.data, f, indent=2)

    def is_done(self, domain: str) -> bool:
        return domain in self.data["done"] or domain in self.data["skipped"]

    def mark_done(self, domain: str):
        if domain not in self.data["done"]:
            self.data["done"].append(domain)
        self.save()

    def mark_failed(self, domain: str, reason: str):
        self.data["failed"].append({"domain": domain, "reason": reason, "time": datetime.now().isoformat()})
        self.save()

    def stats(self) -> dict:
        return {
            "done": len(self.data["done"]),
            "failed": len(self.data["failed"]),
            "skipped": len(self.data["skipped"]),
        }


def load_targets(filepath: str) -> list:
    """Đọc file txt, lọc domain hợp lệ, bỏ comment và dòng trống"""
    if not os.path.exists(filepath):
        print(f"[ERROR] File không tồn tại: {filepath}")
        sys.exit(1)

    targets = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            # Bỏ qua dòng trống và comment
            if not line or line.startswith("#"):
                continue
            # Bỏ http:// https:// nếu có
            line = line.replace("https://", "").replace("http://", "").split("/")[0].strip()
            if line:
                targets.append(line.lower())

    # Deduplicate giữ thứ tự
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)

    return unique


def print_batch_header(targets: list, options: dict):
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    BATCH SCAN MODE                           ║
╠══════════════════════════════════════════════════════════════╣
║  Targets     : {str(len(targets)):5s}                                        ║
║  Exploit     : {"OFF" if options.get("skip_exploit") else "ON ":3s}                                         ║
║  Recon       : {"OFF" if options.get("skip_recon") else "ON ":3s}                                         ║
║  WP Scan     : {"OFF" if options.get("skip_wp") else "ON ":3s}                                         ║
╚══════════════════════════════════════════════════════════════╝
""")


def run_batch(targets: list, options: dict, args):
    """Chạy scan tuần tự toàn bộ danh sách domain"""
    base_output = args.output or os.path.join(BASE_DIR, "results")
    os.makedirs(base_output, exist_ok=True)

    # Setup batch logger
    batch_log = os.path.join(base_output, "batch.log")
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.FileHandler(batch_log),
            logging.StreamHandler(sys.stdout),
        ]
    )
    batch_logger = logging.getLogger("batch")

    tracker = BatchTracker(base_output)
    total = len(targets)

    print_batch_header(targets, options)

    # Handle Ctrl+C gracefully
    interrupted = [False]
    def _sigint(sig, frame):
        interrupted[0] = True
        print("\n\n[BATCH] Ctrl+C — finishing current target then stopping...")
    signal.signal(signal.SIGINT, _sigint)

    batch_start = time.time()

    for idx, domain in enumerate(targets, 1):
        if interrupted[0]:
            batch_logger.info(f"[BATCH] Interrupted by user at {domain}")
            break

        # Resume: bỏ qua domain đã xong
        if args.resume and tracker.is_done(domain):
            batch_logger.info(f"[BATCH] [{idx}/{total}] SKIP (already done): {domain}")
            continue

        # Progress bar
        pct = int((idx - 1) / total * 40)
        bar = "█" * pct + "░" * (40 - pct)
        print(f"\n[{bar}] {idx}/{total}")
        print(f"{'='*60}")
        print(f"  TARGET [{idx}/{total}] : {domain}")
        print(f"{'='*60}")

        # Output dir per domain
        domain_safe = domain.replace(".", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain_output = os.path.join(base_output, f"{domain_safe}_{timestamp}")

        try:
            # Setup per-domain logging (append to main batch log too)
            setup_logging(domain_output, options.get("verbose", False))

            agent = ReconAgent(
                target=domain,
                output_dir=domain_output,
                options=options,
                wps_token=args.wps_token,
                nvd_key=args.nvd_key,
            )
            agent.run()
            tracker.mark_done(domain)

            elapsed = int(time.time() - batch_start)
            batch_logger.info(
                f"[BATCH] [{idx}/{total}] DONE: {domain} "
                f"(elapsed total: {elapsed//60}m{elapsed%60}s)"
            )

        except KeyboardInterrupt:
            interrupted[0] = True
            tracker.mark_failed(domain, "interrupted")
            batch_logger.warning(f"[BATCH] [{idx}/{total}] INTERRUPTED: {domain}")
            break

        except Exception as e:
            tracker.mark_failed(domain, str(e))
            batch_logger.error(f"[BATCH] [{idx}/{total}] FAILED: {domain} — {e}")
            print(f"[BATCH] ERROR on {domain}: {e} — continuing to next target...")

        # Delay giữa các domain
        if idx < total and not interrupted[0]:
            remaining = total - idx
            batch_logger.info(
                f"[BATCH] Waiting {args.delay}s before next target... "
                f"({remaining} remaining)"
            )
            for i in range(args.delay, 0, -1):
                print(f"\r  Next target in {i}s...  ", end="", flush=True)
                time.sleep(1)
            print()

    # Final batch summary
    stats = tracker.stats()
    elapsed_total = int(time.time() - batch_start)
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   BATCH SCAN COMPLETE                        ║
╠══════════════════════════════════════════════════════════════╣
║  Total       : {str(total):5s}                                        ║
║  Done        : {str(stats['done']):5s}                                        ║
║  Failed      : {str(stats['failed']):5s}                                        ║
║  Time        : {str(elapsed_total//60) + 'm' + str(elapsed_total%60) + 's':8s}                                     ║
║  Output      : {str(base_output)[:45]:45s} ║
╚══════════════════════════════════════════════════════════════╝
""")
    batch_logger.info(f"[BATCH] Complete. {stats}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)
    args = parse_args()

    options = {
        "skip_recon": args.skip_recon,
        "skip_live": args.skip_live,
        "skip_crawl": args.skip_crawl,
        "skip_scan": args.skip_scan,
        "skip_wp": args.skip_wp,
        "skip_exploit": args.no_exploit,
        "verbose": args.verbose,
    }

    # ── BATCH MODE ────────────────────────────────────────────
    if args.file:
        targets = load_targets(args.file)
        if not targets:
            print(f"[ERROR] Không có domain nào hợp lệ trong {args.file}")
            sys.exit(1)
        print(f"[BATCH] Loaded {len(targets)} targets từ {args.file}")
        run_batch(targets, options, args)
        return

    # ── SINGLE TARGET MODE ────────────────────────────────────
    if args.output:
        output_dir = args.output
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(BASE_DIR, "results", timestamp)

    logger = setup_logging(output_dir, args.verbose)
    logger.info(f"Target: {args.target}")

    agent = ReconAgent(
        target=args.target,
        output_dir=output_dir,
        options=options,
        wps_token=args.wps_token,
        nvd_key=args.nvd_key,
    )

    if args.resume:
        loaded = agent.state.load()
        if loaded:
            logger.info("[AGENT] Resumed from existing state")
        else:
            logger.warning("[AGENT] No existing state found, starting fresh")

    agent.run()


if __name__ == "__main__":
    main()