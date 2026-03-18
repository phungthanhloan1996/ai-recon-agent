"""
core/state_manager.py - Global State Management
Lưu toàn bộ dữ liệu trong quá trình scan
"""

import json
import os
import logging
from datetime import datetime
from typing import Any, Dict, List
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("recon.state")


@dataclass
class ScanState:
    target: str = ""
    scan_id: str = ""
    start_time: str = ""
    
    # Phase 1 - Recon
    subdomains: List[str] = field(default_factory=list)
    
    # Phase 2 - Live hosts
    live_hosts: List[Dict] = field(default_factory=list)
    technologies: Dict[str, List[str]] = field(default_factory=dict)
    
    # Phase 3 - Crawling
    urls: List[str] = field(default_factory=list)
    archived_urls: List[str] = field(default_factory=list)
    endpoints: List[Dict] = field(default_factory=list)

    # Phase 4 - Prioritized endpoints
    prioritized_endpoints: List[Dict] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)

    # Phase 5 - Vulnerabilities
    vulnerabilities: List[Dict] = field(default_factory=list)
    confirmed_vulnerabilities: List[Dict] = field(default_factory=list)
    scan_responses: List[Dict] = field(default_factory=list)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)

    # Phase 6 - WordPress
    wordpress_detected: bool = False
    wp_sites: List[str] = field(default_factory=list)
    wp_plugins: List[Dict] = field(default_factory=list)
    wp_themes: List[Dict] = field(default_factory=list)
    wp_users: List[str] = field(default_factory=list)
    wp_vulns: List[Dict] = field(default_factory=list)
    wp_vulnerabilities: List[Dict] = field(default_factory=list)
    wp_conditioned_findings: List[Dict] = field(default_factory=list)

    # Phase 7 - Exploit results
    exploit_chains: List[Dict] = field(default_factory=list)
    exploit_results: List[Dict] = field(default_factory=list)
    external_findings: List[Dict] = field(default_factory=list)
    mutated_payloads: List[Any] = field(default_factory=list)
    authenticated_sessions: List[Dict] = field(default_factory=list)
    manual_validation_required: List[Dict] = field(default_factory=list)
    manual_validation_completed: List[Dict] = field(default_factory=list)
    manual_attack_playbook: List[Dict] = field(default_factory=list)
    
    # Meta
    current_phase: str = "init"
    errors: List[str] = field(default_factory=list)


class StateManager:
    def __init__(self, target: str, output_dir: str):
        self.output_dir = output_dir
        self.state_file = os.path.join(output_dir, "state.json")
        self.state = ScanState(
            target=target,
            scan_id=os.path.basename(output_dir),
            start_time=datetime.now().isoformat()
        )
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"[STATE] Initialized state for target: {target}")

    def update(self, **kwargs):
        """Update state fields"""
        for key, value in kwargs.items():
            if hasattr(self.state, key):
                current = getattr(self.state, key)
                if isinstance(current, list) and isinstance(value, list):
                    # Deduplicate
                    if value and isinstance(value[0], str):
                        merged = list(set(current + value))
                    else:
                        merged = current + [v for v in value if v not in current]
                    setattr(self.state, key, merged)
                else:
                    setattr(self.state, key, value)
        self.save()

    def add_subdomain(self, subdomain: str):
        if subdomain not in self.state.subdomains:
            self.state.subdomains.append(subdomain)

    def add_live_host(self, host_info: Dict):
        urls = [h["url"] for h in self.state.live_hosts]
        if host_info.get("url") not in urls:
            self.state.live_hosts.append(host_info)

    def add_url(self, url: str):
        if url not in self.state.urls:
            self.state.urls.append(url)

    def add_endpoint(self, endpoint: Dict):
        paths = [e["path"] for e in self.state.endpoints]
        if endpoint.get("path") not in paths:
            self.state.endpoints.append(endpoint)

    def add_vulnerability(self, vuln: Dict):
        self.state.vulnerabilities.append(vuln)

    def add_exploit_result(self, result: Dict):
        self.state.exploit_results.append(result)

    def add_error(self, error: str):
        self.state.errors.append(error)
        logger.error(f"[STATE] Error recorded: {error}")

    def set_phase(self, phase: str):
        self.state.current_phase = phase
        logger.info(f"[STATE] Phase → {phase}")
        self.save()

    def get(self, key: str, default=None) -> Any:
        return getattr(self.state, key, default)

    def save(self):
        try:
            with open(self.state_file, "w") as f:
                json.dump(asdict(self.state), f, indent=2, default=str)
        except Exception as e:
            logger.error(f"[STATE] Failed to save state: {e}")

    def load(self) -> bool:
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
                self.state = ScanState(**data)
                logger.info("[STATE] Loaded existing state")
                return True
            except Exception as e:
                logger.error(f"[STATE] Failed to load state: {e}")
        return False

    def summary(self) -> Dict:
        s = self.state
        return {
            "target": s.target,
            "subdomains": len(s.subdomains),
            "live_hosts": len(s.live_hosts),
            "urls": len(s.urls),
            "endpoints": len(s.endpoints),
            "vulnerabilities": len(s.confirmed_vulnerabilities or s.vulnerabilities),
            "exploit_results": len(s.exploit_results),
            "wordpress": s.wordpress_detected,
            "wp_plugins": len(s.wp_plugins),
        }
