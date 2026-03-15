"""
agent.py - AI Recon Agent Main Orchestrator
Pipeline: recon → live-host detection → crawling → endpoint ranking
         → vulnerability scan → exploit engine → response analysis → report
"""

import argparse
import logging
import os
import sys
import json
import time
import signal
from datetime import datetime

# ─── Setup paths ─────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# ─── Modules ──────────────────────────────────────────────────────────────────
from core.state_manager import StateManager
from core.endpoint_ranker import EndpointRanker
from modules.recon import ReconModule
from modules.live_hosts import LiveHostsModule
from modules.crawler import CrawlerModule
from modules.scanner import ScannerModule
from modules.wp_scanner import WPScannerModule
from modules.exploiter import ExploiterModule
from ai.chain_planner import ChainPlanner
from ai.analyzer import AIAnalyzer


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
        self.state = StateManager(self.target, output_dir)
        self.logger = logging.getLogger("recon.agent")
        self.start_time = time.time()
        # AI client cho báo cáo: ưu tiên Groq (miễn phí), sau đó Anthropic
        self._ai_client = None
        groq_key = os.environ.get("GROQ_API_KEY")
        if groq_key:
            try:
                class _GroqReportClient:
                    def __init__(self, key):
                        self._key = key
                        self._url = "https://api.groq.com/openai/v1/chat/completions"
                    def generate(self, prompt: str) -> str:
                        import urllib.request
                        body = json.dumps({
                            "model": "llama-3.3-70b-versatile",
                            "messages": [{"role": "user", "content": prompt}],
                            "max_tokens": 8192,
                            "temperature": 0.3,
                        }).encode()
                        req = urllib.request.Request(
                            self._url,
                            data=body,
                            headers={
                                "Authorization": f"Bearer {self._key}",
                                "Content-Type": "application/json",
                            },
                            method="POST",
                        )
                        with urllib.request.urlopen(req, timeout=120) as resp:
                            out = json.loads(resp.read().decode())
                        return (out.get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
                self._ai_client = _GroqReportClient(groq_key)
                self.logger.info("[AGENT] AI report enabled (Groq, free tier)")
            except Exception as e:
                self.logger.debug(f"[AGENT] Groq init failed: {e}")
        if self._ai_client is None:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
            if api_key:
                try:
                    import anthropic
                    class _AIReportClient:
                        def __init__(self, key):
                            self._client = anthropic.Anthropic(api_key=key)
                        def generate(self, prompt: str) -> str:
                            r = self._client.messages.create(
                                model="claude-3-5-sonnet-20241022",
                                max_tokens=8192,
                                messages=[{"role": "user", "content": prompt}]
                            )
                            return r.content[0].text if r.content else ""
                    self._ai_client = _AIReportClient(api_key)
                    self.logger.info("[AGENT] AI report enabled (Anthropic)")
                except Exception as e:
                    self.logger.debug(f"[AGENT] Anthropic init failed: {e}")

    def run(self):
        """Execute the full recon pipeline"""
        self.logger.info(f"🎯 Target: {self.target}")
        self.logger.info(f"📁 Output: {self.output_dir}")
        self.logger.info(f"⚙️  Options: {self.options}")

        try:
            # ── Phase 1: Subdomain Recon ──────────────────────────────────
            if not self.options.get("skip_recon"):
                recon = ReconModule(self.state, self.output_dir)
                recon.run()
            else:
                self.logger.info("[AGENT] Skipping recon phase")

            # ── Phase 2: Live Host Detection ──────────────────────────────
            if not self.options.get("skip_live"):
                live = LiveHostsModule(self.state, self.output_dir)
                live.run()

            # ── Phase 3: Crawling ─────────────────────────────────────────
            if not self.options.get("skip_crawl"):
                crawler = CrawlerModule(self.state, self.output_dir)
                crawler.run()

            # ── Phase 4: Endpoint Prioritization ─────────────────────────
            self._run_endpoint_ranking()

            # ── Phase 5: Vulnerability Scan ───────────────────────────────
            if not self.options.get("skip_scan"):
                scanner = ScannerModule(self.state, self.output_dir)
                scanner.run()

            # ── Phase 6: WordPress Scan ───────────────────────────────────
            if not self.options.get("skip_wp"):
                wp_scanner = WPScannerModule(self.state, self.output_dir,
                                             wpscan_token=self.wps_token,
                                             nvd_key=self.nvd_key)
                wp_scanner.run()

            # ── Exploit Chain Planning ────────────────────────────────────
            chains = self._plan_exploit_chains()

            # ── Phase 7: Exploitation ─────────────────────────────────────
            if not self.options.get("skip_exploit"):
                exploiter = ExploiterModule(self.state, self.output_dir)
                exploiter.run()
            else:
                self.logger.info("[AGENT] Exploitation disabled (--no-exploit)")

            # ── Final Report ──────────────────────────────────────────────
            self._generate_report()

            # ── Summary ───────────────────────────────────────────────────
            self._print_final_summary()

        except KeyboardInterrupt:
            self.logger.warning("\n[AGENT] Scan interrupted by user. Saving state...")
            self.state.save()
            self._generate_report()
        except Exception as e:
            self.logger.error(f"[AGENT] Fatal error: {e}", exc_info=True)
            self.state.add_error(str(e))
            self.state.save()
            raise

    def _run_endpoint_ranking(self):
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

    def _plan_exploit_chains(self) -> list:
        """Plan exploit chains based on current findings"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"  EXPLOIT CHAIN PLANNING")
        self.logger.info(f"{'='*60}")

        planner = ChainPlanner(self.state)
        chains = planner.plan_chains()

        if chains:
            chain_report = planner.format_chain_report(chains)
            self.logger.info(f"\n{chain_report}")

            # Save chain plan
            chain_file = os.path.join(self.output_dir, "exploit_chains.txt")
            with open(chain_file, "w") as f:
                f.write(chain_report)

        return chains

    def _generate_report(self):
        """Generate final AI report"""
        analyzer = AIAnalyzer(self.state, self.output_dir, ai_client=getattr(self, "_ai_client", None))
        report = analyzer.generate_report()

        # Print first part of report to console
        lines = report.splitlines()
        for line in lines[:50]:
            print(line)
        if len(lines) > 50:
            print(f"... (full report in {analyzer.report_file})")

    def _print_final_summary(self):
        elapsed = time.time() - self.start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        summary = self.state.summary()
        exploit_results = self.state.get("exploit_results", [])
        successful = [r for r in exploit_results if r.get("success")]

        print(f"\n{'='*60}")
        print(f"  SCAN COMPLETE - {mins}m {secs}s")
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