"""
WordPress Advanced Scan Integration
- Thin wrapper over wp_scan_cve.py
- Extracts ONLY data collection, NO reporting
- Returns structured findings for pipeline merge
"""

import sys
import os
import json
import time
from urllib.parse import urljoin

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from wp_scan_cve module (located in parent directory or accessible)
try:
    # Try to find and import from WP-NEXUS if available
    wp_scan_path = os.path.expanduser("~/Desktop/WP-NEXUS")
    if os.path.exists(wp_scan_path):
        sys.path.insert(0, wp_scan_path)
    
    from wp_scan_cve import ServerBehaviorObserver, ProfessionalWPAudit
    WP_SCAN_CVE_AVAILABLE = True
except ImportError as e:
    WP_SCAN_CVE_AVAILABLE = False
    print(f"[WARNING] wp_scan_cve module not found: {e}")


class WordPressAdvancedScan:
    """
    Data-only wrapper around wp_scan_cve.ProfessionalWPAudit
    Runs all data collection without generating reports
    """
    
    def __init__(self, target_url: str, timeout_per_check: int = 10):
        """
        Initialize advanced scan for a WordPress target
        
        Args:
            target_url: Target domain/URL
            timeout_per_check: Timeout for individual HTTP requests
        """
        self.target_url = target_url
        self.timeout = timeout_per_check
        self.data = {
            "target": target_url,
            "timestamp": time.time(),
            "version_detection": {},
            "php_analysis": {},
            "wordpress_api": {},
            "plugin_versions": {},
            "server_behaviors": {},
            "vulnerabilities": [],
            "observations": {
                "posture_indicators": [],
                "behavioral_patterns": [],
                "reality_context": []
            }
        }
    
    def run_data_collection(self) -> dict:
        """
        Run all data collection without report generation
        Returns structured findings for integration into main pipeline
        """
        if not WP_SCAN_CVE_AVAILABLE:
            return self._fallback_data()
        
        try:
            # Initialize audit without triggering report generation
            audit = ProfessionalWPAudit(self.target_url)
            
            # Call ONLY data collection methods, no printing
            self._collect_static_indicators(audit)
            self._collect_server_behaviors(audit)
            self._collect_observational_context(audit)
            
            # Extract and structure findings
            self._extract_findings(audit)
            
            return self.data
            
        except Exception as e:
            print(f"[ERROR] Advanced WordPress scan failed: {str(e)[:100]}")
            return self._fallback_data()
    
    def _collect_static_indicators(self, audit):
        """Collect static posture indicators without printing"""
        try:
            # Call the data collection method
            audit.assess_static_indicators()
            
            # Store raw data
            self.data["static_indicators"] = audit.static_indicators
            self.data["behavioral_data"] = audit.behavioral_data
            
        except Exception as e:
            print(f"[DEBUG] Static indicators error: {str(e)[:80]}")
    
    def _collect_server_behaviors(self, audit):
        """Observe server behaviors without printing"""
        try:
            # This includes fingerprinting, rate handling, error patterns, auth boundaries
            audit.observe_server_behaviors()
            
            # Update behavioral data
            self.data["behavioral_data"].update(audit.behavioral_data)
            
        except Exception as e:
            print(f"[DEBUG] Server behaviors error: {str(e)[:80]}")
    
    def _collect_observational_context(self, audit):
        """Analyze observational context"""
        try:
            audit.analyze_observational_context()
            
            # Store observations
            self.data["observations"] = {
                "posture_indicators": audit.observations.get("posture_indicators", []),
                "behavioral_patterns": audit.observations.get("behavioral_patterns", []),
                "reality_context": audit.reality_context
            }
            
        except Exception as e:
            print(f"[DEBUG] Observational context error: {str(e)[:80]}")
    
    def _extract_findings(self, audit):
        """Extract and structure findings from audit data"""
        static = audit.static_indicators or {}
        behavioral = audit.behavioral_data or {}
        
        # WordPress Version
        if static.get("wordpress_version"):
            self.data["version_detection"] = {
                "wp_version": static.get("wordpress_version"),
                "confidence": static.get("version_confidence", "unknown"),
                "methods": static.get("version_detection_methods", []),
                "eol": self._check_eol_version(static.get("wordpress_version"))
            }
        
        # PHP Version  
        if static.get("php_version"):
            self.data["php_analysis"] = {
                "php_version": static.get("php_version"),
                "php_versions_found": static.get("php_versions_found", []),
                "consistent_across_endpoints": static.get("php_headers_consistent", False),
                "outdated": self._check_outdated_php(static.get("php_version"))
            }
        
        # WordPress REST API
        if static.get("wp_rest_api_enabled"):
            self.data["wordpress_api"] = {
                "rest_api_enabled": True,
                "api_version": static.get("wp_api_version"),
                "user_enumeration_possible": static.get("user_enumeration_possible", False),
                "users_endpoint_accessible": static.get("wp_api_users_accessible", False)
            }
        
        # Plugin Versions
        fingerprint = behavioral.get("fingerprint", {})
        if fingerprint.get("plugins"):
            self.data["plugin_versions"] = {
                "detected_plugins": fingerprint.get("plugins", []),
                "count": len(fingerprint.get("plugins", []))
            }
        
        # Server Behaviors
        if behavioral.get("rate_handling"):
            self.data["server_behaviors"]["rate_handling"] = behavioral["rate_handling"]["pattern_analysis"]
        if behavioral.get("error_responses"):
            self.data["server_behaviors"]["error_patterns"] = behavioral["error_responses"]["summary"]
        if behavioral.get("auth_boundaries"):
            self.data["server_behaviors"]["auth_boundaries"] = behavioral["auth_boundaries"]["boundary_analysis"]
        
        # Build vulnerabilities list from observations
        vulnerabilities = []
        
        # EOL WordPress version
        if self.data["version_detection"].get("eol"):
            vulnerabilities.append({
                "type": "EOL_WORDPRESS_VERSION",
                "severity": "HIGH",
                "version": static.get("wordpress_version"),
                "description": "WordPress version is end-of-life, no longer receiving security updates",
                "evidence": f"WordPress {static.get('wordpress_version')} detected"
            })
        
        # Outdated PHP
        if self.data["php_analysis"].get("outdated"):
            vulnerabilities.append({
                "type": "OUTDATED_PHP_VERSION",
                "severity": "HIGH",
                "version": static.get("php_version"),
                "description": "PHP version is outdated and no longer maintained",
                "evidence": f"PHP {static.get('php_version')} detected"
            })
        
        # User enumeration via REST API
        if self.data["wordpress_api"].get("user_enumeration_possible"):
            vulnerabilities.append({
                "type": "USER_ENUMERATION_REST_API",
                "severity": "MEDIUM",
                "description": "User enumeration possible via WordPress REST API",
                "evidence": "WordPress REST API /users endpoint accessible without authentication"
            })
        
        # Directory listing
        if static.get("directory_listing_enabled"):
            vulnerabilities.append({
                "type": "DIRECTORY_LISTING",
                "severity": "MEDIUM",
                "description": "Directory listing enabled on web server",
                "evidence": "wp-content/uploads directory accessible with directory listing"
            })
        
        self.data["vulnerabilities"] = vulnerabilities
    
    def _check_eol_version(self, version: str) -> bool:
        """Check if WordPress version is EOL"""
        try:
            parts = version.split('.')
            major = int(parts[0]) if parts else 0
            
            # WordPress versions before 6.0 are EOL as of 2026
            return major < 6
        except:
            return False
    
    def _check_outdated_php(self, version: str) -> bool:
        """Check if PHP version is outdated"""
        outdated_versions = ['5.', '7.0', '7.1', '7.2', '7.3', '7.4']
        return any(version.startswith(v) for v in outdated_versions)
    
    def _fallback_data(self) -> dict:
        """Return minimal data when wp_scan_cve is not available"""
        return self.data
    
    def get_structured_findings(self) -> dict:
        """
        Return findings structured for pipeline integration
        """
        return self.data
    
    @staticmethod
    def merge_into_state(state: dict, advanced_scan_data: dict) -> dict:
        """
        Merge advanced scan findings into agent state
        
        Args:
            state: Current agent state
            advanced_scan_data: Data from advanced scan
            
        Returns:
            Updated state with merged data
        """
        # Ensure required keys exist
        if "technical_details" not in state:
            state["technical_details"] = {}
        
        # Add advanced WordPress scan results
        state["technical_details"]["wordpress_advanced_scan"] = advanced_scan_data
        
        # Update/enrich WordPress findings
        if advanced_scan_data.get("version_detection"):
            state["cms_version"] = f"WordPress {advanced_scan_data['version_detection'].get('wp_version')}"
            state["wordpress_eol"] = advanced_scan_data["version_detection"].get("eol", False)
        
        if advanced_scan_data.get("php_analysis"):
            state["server_php_version"] = advanced_scan_data["php_analysis"].get("php_version")
            state["php_outdated"] = advanced_scan_data["php_analysis"].get("outdated", False)
        
        if advanced_scan_data.get("wordpress_api"):
            state["wordpress_rest_api_enabled"] = advanced_scan_data["wordpress_api"].get("rest_api_enabled", False)
            state["user_enumeration_via_api"] = advanced_scan_data["wordpress_api"].get("user_enumeration_possible", False)
        
        if advanced_scan_data.get("plugin_versions"):
            if "plugins" not in state:
                state["plugins"] = []
            # Merge plugins, avoiding duplicates
            existing_plugins = {p.get("name"): p for p in state.get("plugins", [])}
            for plugin in advanced_scan_data["plugin_versions"].get("detected_plugins", []):
                if plugin.get("name") not in existing_plugins:
                    state["plugins"].append(plugin)
        
        # Add vulnerabilities from advanced scan
        if advanced_scan_data.get("vulnerabilities"):
            if "confirmed_vulnerabilities" not in state:
                state["confirmed_vulnerabilities"] = []
            
            for vuln in advanced_scan_data["vulnerabilities"]:
                # Check if already exists
                exists = any(
                    v.get("type") == vuln.get("type")
                    for v in state.get("confirmed_vulnerabilities", [])
                )
                if not exists:
                    state["confirmed_vulnerabilities"].append(vuln)
        
        # Add observations for context
        if advanced_scan_data.get("observations"):
            state["scan_observations"] = advanced_scan_data["observations"]
        
        return state


def scan_all_wordpress_targets(targets: list, max_workers: int = 1) -> dict:
    """
    Scan multiple WordPress targets for advanced findings
    
    Args:
        targets: List of target URLs
        max_workers: Parallel workers (recommended: 1 to avoid rate limiting)
        
    Returns:
        Dictionary with results keyed by target
    """
    results = {}
    
    for target in targets:
        try:
            scanner = WordPressAdvancedScan(target)
            data = scanner.run_data_collection()
            results[target] = data
            time.sleep(2)  # Rate limiting between targets
        except Exception as e:
            print(f"[ERROR] Scan failed for {target}: {str(e)[:80]}")
            results[target] = {"error": str(e)[:100]}
    
    return results
