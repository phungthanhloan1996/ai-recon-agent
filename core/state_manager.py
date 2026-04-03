"""
core/state_manager.py - Global State Management
Lưu toàn bộ dữ liệu trong quá trình scan
"""

import json
import os
import logging
import tempfile
import shutil
import time
from datetime import datetime
from typing import Any, Dict, List
from dataclasses import dataclass, field, asdict

logger = logging.getLogger("recon.state")


@dataclass
class ScanState:
    target: str = ""
    scan_id: str = ""
    start_time: str = ""
    
    # Seed-first scanning: Track input target and discovered targets separately
    seed_targets: List[Dict] = field(default_factory=list)
    discovered_targets: List[Dict] = field(default_factory=list)
    all_scan_targets: List[Dict] = field(default_factory=list)
    
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
    endpoint_probe_results: List[Dict] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)

    # Phase 5 - Vulnerabilities & Findings
    vulnerabilities: List[Dict] = field(default_factory=list)
    confirmed_vulnerabilities: List[Dict] = field(default_factory=list)
    scan_responses: List[Dict] = field(default_factory=list)
    scan_metadata: Dict[str, Any] = field(default_factory=dict)
    
    # NEW: Structured findings layer (non-CVE security signals)
    security_findings: List[Dict] = field(default_factory=list)  # General security findings
    rce_chain_possibilities: List[Dict] = field(default_factory=list)  # Potential RCE vectors

    # Phase 6 - WordPress
    wordpress_detected: bool = False
    wp_sites: List[str] = field(default_factory=list)
    wp_plugins: List[Dict] = field(default_factory=list)
    wp_themes: List[Dict] = field(default_factory=list)
    wp_users: List[str] = field(default_factory=list)
    wp_vulns: List[Dict] = field(default_factory=list)
    wp_vulnerabilities: List[Dict] = field(default_factory=list)
    wp_core: Dict[str, Any] = field(default_factory=dict)
    core_vulnerabilities: List[Dict] = field(default_factory=list)
    wp_conditioned_findings: List[Dict] = field(default_factory=list)
    wp_version: str = "unknown"
    wp_scan_confidence: float = 0.0
    wp_pattern_matches: Dict[str, Any] = field(default_factory=dict)

    # Phase 7 - Exploit results
    exploit_chains: List[Dict] = field(default_factory=list)
    exploit_results: List[Dict] = field(default_factory=list)
    external_findings: List[Dict] = field(default_factory=list)
    mutated_payloads: List[Any] = field(default_factory=list)
    authenticated_sessions: List[Dict] = field(default_factory=list)
    manual_validation_required: List[Dict] = field(default_factory=list)
    manual_validation_completed: List[Dict] = field(default_factory=list)
    manual_attack_playbook: List[Dict] = field(default_factory=list)
    
    # Phase 8 - Authentication Attacks (NEW)
    auth_endpoints: List[Dict] = field(default_factory=list)
    mfa_findings: List[Dict] = field(default_factory=list)  # MFA mechanisms detected
    oauth_endpoints: List[Dict] = field(default_factory=list)  # OAuth/SAML auth points
    oauth_saml_findings: List[Dict] = field(default_factory=list)  # OAuth/SAML exploitation results
    token_theft_vectors: List[Dict] = field(default_factory=list)  # Token stealing methods
    
    # Phase 9 - Persistence & Post-Exploitation (NEW)
    persistence_vectors: List[Dict] = field(default_factory=list)  # Backdoor placement options
    persistence_findings: List[Dict] = field(default_factory=list)  # Persistence deployment results
    backdoors_deployed: List[Dict] = field(default_factory=list)  # Deployed backdoors
    web_shells: List[Dict] = field(default_factory=list)  # Web shell info (path, type, creds)
    reverse_shells: List[Dict] = field(default_factory=list)  # Reverse shell callbacks
    cron_jobs: List[Dict] = field(default_factory=list)  # Scheduled tasks deployed
    startup_persistence: List[Dict] = field(default_factory=list)  # Boot-time persistence
    
    # Phase 10 - Lateral Movement & Privilege Escalation (NEW)
    adjacent_services: List[Dict] = field(default_factory=list)  # Internal services found
    internal_network_map: List[Dict] = field(default_factory=list)  # Network topology
    lateral_movement_chains: List[Dict] = field(default_factory=list)  # Inter-service exploitation paths
    lateral_movement_findings: List[Dict] = field(default_factory=list)  # Lateral movement results
    privilege_escalation_methods: List[Dict] = field(default_factory=list)  # Privilege escalation vectors
    kernel_exploits_applicable: List[Dict] = field(default_factory=list)  # Kernel CVEs matching version
    
    # Phase 11 - SSL/TLS Attacks (NEW)
    ssl_findings: List[Dict] = field(default_factory=list)  # SSL/TLS weaknesses (pinning, weak ciphers)
    ssl_pinning_findings: List[Dict] = field(default_factory=list)  # SSL pinning bypass results
    pinning_bypass_methods: List[Dict] = field(default_factory=list)  # Ways to bypass cert pinning
    
    # Phase 12 - Zero-Day & Fuzzing (NEW)
    fuzzing_results: List[Dict] = field(default_factory=list)  # Anomalies found via fuzzing
    zero_day_findings: List[Dict] = field(default_factory=list)  # Zero-day detection results
    potential_zero_days: List[Dict] = field(default_factory=list)  # Unknown/unpatched vulnerabilities
    anomaly_detections: List[Dict] = field(default_factory=list)  # Behavioral anomalies
    
    # Phase 13 - Container & Cloud Escape (NEW)
    container_detected: bool = False
    container_type: str = ""  # docker, kubernetes, lxc, etc.
    container_escape_vectors: List[Dict] = field(default_factory=list)  # Container escape methods
    container_findings: List[Dict] = field(default_factory=list)  # Container escape results
    cloud_metadata_accessible: bool = False  # AWS/GCP metadata server reachable
    cloud_credentials: List[Dict] = field(default_factory=list)  # Cloud creds found
    
    # Phase 14 - Custom Exploit Framework (NEW)
    custom_exploits: List[Dict] = field(default_factory=list)  # Custom exploit definitions
    custom_exploit_results: List[Dict] = field(default_factory=list)  # Results from custom exploits
    custom_exploit_findings: List[Dict] = field(default_factory=list)  # Custom exploit execution results
    
    # Phase 15 - Log Evasion & Coverage Tracks (NEW)
    log_locations: List[Dict] = field(default_factory=list)  # Log file locations found
    log_evasion_techniques: List[Dict] = field(default_factory=list)  # Methods to evade logs
    log_evasion_findings: List[Dict] = field(default_factory=list)  # Log evasion execution results
    logs_cleared: List[Dict] = field(default_factory=list)  # Logs cleared during engagement
    
    # API & Vulnerability Management
    default_creds_findings: List[Dict] = field(default_factory=list)
    cve_exploit_findings: List[Dict] = field(default_factory=list)
    api_vuln_findings: List[Dict] = field(default_factory=list)
    subdomain_takeover_findings: List[Dict] = field(default_factory=list)
    
    # Phase 16 - Advanced Post-Exploitation (NEW)
    living_off_land_techniques: List[Dict] = field(default_factory=list)  # LOLBin techniques used
    data_exfiltration_methods: List[Dict] = field(default_factory=list)  # Ways to exfil data
    command_execution_history: List[Dict] = field(default_factory=list)  # Commands executed on target
    
    # WAF Blocking
    waf_blocked: bool = False
    waf_block_count: int = 0

    # Meta
    current_phase: str = "init"
    errors: List[str] = field(default_factory=list)


class StateManager:
    def __init__(self, target: str, output_dir: str):
        self.output_dir = output_dir
        self.state_file = os.path.join(output_dir, "state.json")
        self._last_save_ts = 0.0
        self._dirty = False
        self._save_interval = float(os.getenv("STATE_SAVE_INTERVAL_SECONDS", "2"))
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
        self._dirty = True
        self.save(force=False)

    def add_subdomain(self, subdomain: str):
        if subdomain not in self.state.subdomains:
            self.state.subdomains.append(subdomain)

    def add_live_host(self, host_info: Dict):
        urls = [h.get("url") for h in self.state.live_hosts if "url" in h]
        if host_info.get("url") not in urls:
            self.state.live_hosts.append(host_info)

    def add_url(self, url: str):
        if url not in self.state.urls:
            self.state.urls.append(url)

    def add_endpoint(self, endpoint: Dict):
        paths = [e.get("path") for e in self.state.endpoints if "path" in e]
        if endpoint.get("path") not in paths:
            self.state.endpoints.append(endpoint)

    def update_technologies(self, host: str, tech_data: Dict[str, Any]):
        technologies = self.state.technologies or {}
        current = technologies.get(host, {})
        if not isinstance(current, dict):
            current = {"value": current}
        current.update(tech_data)
        technologies[host] = current
        self.state.technologies = technologies
        self._dirty = True
        self.save(force=False)

    def upsert_endpoint(self, endpoint: Dict[str, Any]):
        if not isinstance(endpoint, dict):
            return
        url = endpoint.get("url")
        if not url:
            return
        for existing in self.state.endpoints:
            if isinstance(existing, dict) and existing.get("url") == url:
                existing.update(endpoint)
                self._dirty = True
                self.save(force=False)
                return
        self.state.endpoints.append(endpoint)
        self._dirty = True
        self.save(force=False)

    def update_scan_metadata(self, **kwargs):
        metadata = self.state.scan_metadata or {}
        metadata.update(kwargs)
        self.state.scan_metadata = metadata
        self._dirty = True
        self.save(force=False)

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
        self._dirty = True
        self.save(force=True)

    def get(self, key: str, default=None) -> Any:
        return getattr(self.state, key, default)

    def save(self, force: bool = True):
        """Save state atomically (write to temp, then rename) to prevent corruption"""
        now = time.time()
        if not force and not self._dirty:
            return
        if not force and (now - self._last_save_ts) < self._save_interval:
            return
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            
            # Write to temporary file first
            fd, temp_path = tempfile.mkstemp(dir=self.output_dir, suffix=".tmp")
            try:
                with os.fdopen(fd, 'w') as f:
                    json.dump(asdict(self.state), f, indent=2, default=str)
                
                # Atomic rename
                shutil.move(temp_path, self.state_file)
                self._last_save_ts = now
                self._dirty = False
                logger.debug(f"[STATE] State saved atomically to {self.state_file}")
            except Exception as e:
                # Clean up temp file if something went wrong
                if os.path.exists(temp_path):
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
                raise e
        except Exception as e:
            logger.error(f"[STATE] Failed to save state atomically: {e}")
            # Fallback to direct write
            try:
                with open(self.state_file, "w") as f:
                    json.dump(asdict(self.state), f, indent=2, default=str)
                self._last_save_ts = now
                self._dirty = False
                logger.warning("[STATE] Saved state using fallback method")
            except Exception as e2:
                logger.error(f"[STATE] Fallback save also failed: {e2}")

    def _recover_from_corruption(self) -> bool:
        """Try to recover from corrupted JSON file"""
        if not os.path.exists(self.state_file):
            return False
        
        backup_path = self.state_file + ".corrupted"
        
        try:
            # Move corrupted file to backup
            shutil.move(self.state_file, backup_path)
            logger.warning(f"[STATE] Moved corrupted state file to {backup_path}")
            
            # Check if there's a previous backup we can restore
            for i in range(1, 5):  # Look for state.json.backup1-4
                backup_num = self.state_file + f".backup{i}"
                if os.path.exists(backup_num):
                    try:
                        logger.info(f"[STATE] Attempting recovery from {backup_num}")
                        with open(backup_num) as f:
                            data = json.load(f)
                        self.state = ScanState(**data)
                        self.save()
                        logger.info("[STATE] Successfully recovered from backup")
                        return True
                    except:
                        continue
            
            logger.warning("[STATE] No valid backups found, starting with fresh state")
            return False
        except Exception as e:
            logger.error(f"[STATE] Error during corruption recovery: {e}")
            return False

    def load(self) -> bool:
        """Load state from file, with corruption detection and recovery"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file) as f:
                    data = json.load(f)
                self.state = ScanState(**data)
                logger.info("[STATE] Loaded existing state successfully")
                return True
            except json.JSONDecodeError as e:
                logger.error(f"[STATE] JSON corruption detected: {e}")
                # Try to recover from backup
                if self._recover_from_corruption():
                    return True
                logger.warning("[STATE] Starting with fresh state after corruption")
                return False
            except TypeError as e:
                # Missing required fields - try with defaults
                logger.warning(f"[STATE] State has missing/incompatible fields: {e}")
                try:
                    with open(self.state_file) as f:
                        data = json.load(f)
                    # Fill in missing fields with defaults
                    for key in asdict(ScanState()).keys():
                        if key not in data:
                            data[key] = getattr(ScanState(), key)
                    self.state = ScanState(**data)
                    logger.info("[STATE] Loaded state with default values for missing fields")
                    return True
                except Exception as e2:
                    logger.error(f"[STATE] Failed to load state even with defaults: {e2}")
                    return False
            except Exception as e:
                logger.error(f"[STATE] Unexpected error loading state: {e}")
                return False
        return False



    def __getitem__(self, key: str):
        """Cho phép đọc: state['some_key']"""
        return getattr(self.state, key, None)

    def __setitem__(self, key: str, value: Any):
        """Cho phép gán: state['some_key'] = value   ← Đây là fix chính"""
        # Allow setting both existing and new keys
        setattr(self.state, key, value)
        self.save()

    def __contains__(self, key: str) -> bool:
        """Cho phép kiểm tra: if 'key' in state"""
        return hasattr(self.state, key)


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

