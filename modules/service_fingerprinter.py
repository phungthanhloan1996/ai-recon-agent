"""
modules/service_fingerprinter.py - Service Fingerprinting Engine

Performs deep fingerprinting of discovered services to identify:
- Service versions and configurations
- Technology stack details
- Potential attack vectors based on service characteristics
- Service-specific vulnerabilities

This module enhances the attack surface analysis by providing detailed
service intelligence that feeds into exploit selection and chain planning.
"""

import json
import os
import logging
import re
import time
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

from core.http_engine import HTTPClient
from core.state_manager import StateManager

logger = logging.getLogger("recon.service_fingerprinter")


class ServiceFingerprinter:
    """
    Deep service fingerprinting engine.
    Analyzes services to extract version info, configurations, and attack vectors.
    """
    
    def __init__(self, state: StateManager, output_dir: str):
        self.state = state
        self.output_dir = output_dir
        self.http_client = HTTPClient()
        self.findings_file = os.path.join(output_dir, "service_fingerprints.json")
        
        # Service-specific fingerprinting patterns
        self.service_patterns = {
            "web_servers": {
                "apache": {
                    "headers": ["Apache"],
                    "patterns": [r"Apache/([\d.]+)"],
                    "version_header": "Server"
                },
                "nginx": {
                    "headers": ["nginx"],
                    "patterns": [r"nginx/([\d.]+)"],
                    "version_header": "Server"
                },
                "iis": {
                    "headers": ["IIS", "Microsoft-IIS"],
                    "patterns": [r"Microsoft-IIS/([\d.]+)"],
                    "version_header": "Server"
                },
                "cloudflare": {
                    "headers": ["cloudflare", "cf-ray"],
                    "patterns": [],
                    "version_header": None
                }
            },
            "frameworks": {
                "django": {
                    "patterns": [r"Django/([\d.]+)", r"csrftoken"],
                    "headers": []
                },
                "laravel": {
                    "patterns": [r"laravel_session", r"XSRF-TOKEN"],
                    "headers": ["X-Laravel"]
                },
                "express": {
                    "patterns": [r"Express"],
                    "headers": ["X-Powered-By: Express"]
                },
                "rails": {
                    "patterns": [r"Rails/([\d.]+)"],
                    "headers": ["X-Powered-By: Phusion Passenger"]
                },
                "spring": {
                    "patterns": [r"Spring"],
                    "headers": ["X-Application-Context"]
                }
            },
            "databases": {
                "mysql": {
                    "patterns": [r"mysql", r"MariaDB"],
                    "ports": [3306]
                },
                "postgresql": {
                    "patterns": [r"postgresql", r"postgres"],
                    "ports": [5432]
                },
                "mongodb": {
                    "patterns": [r"mongodb", r"MongoDB"],
                    "ports": [27017]
                },
                "redis": {
                    "patterns": [r"redis", r"Redis"],
                    "ports": [6379]
                }
            },
            "cms": {
                "wordpress": {
                    "patterns": [r"wp-content", r"wp-includes", r"WordPress"],
                    "paths": ["/wp-admin/", "/wp-login.php", "/wp-content/"]
                },
                "drupal": {
                    "patterns": [r"Drupal", r"sites/default"],
                    "paths": ["/user/login", "/admin/"]
                },
                "joomla": {
                    "patterns": [r"Joomla", r"media/jui"],
                    "paths": ["/administrator/", "/index.php"]
                }
            }
        }
    
    def fingerprint_all(self, hosts: List[Dict[str, Any]], progress_cb=None) -> Dict[str, Any]:
        """
        Fingerprint all discovered hosts and services.
        
        Args:
            hosts: List of host info dicts with 'url' key
            progress_cb: Optional progress callback
            
        Returns:
            Dictionary of fingerprinting results
        """
        results = {
            "status": "completed",
            "findings": [],
            "services": {},
            "technologies": {}
        }
        
        if not hosts:
            logger.warning("[SERVICE_FP] No hosts provided for fingerprinting")
            return results
        
        logger.info(f"[SERVICE_FP] Starting deep fingerprinting on {len(hosts)} hosts")
        
        for idx, host_info in enumerate(hosts[:50]):  # Limit to 50 for performance
            url = host_info.get("url", "")
            if not url:
                continue
            
            try:
                if progress_cb:
                    progress_cb(f"Fingerprinting {url.split('//')[-1][:30]}...")
                
                fp_result = self.fingerprint_host(url)
                results["findings"].append(fp_result)
                
                # Aggregate technologies
                for tech_name, tech_info in fp_result.get("technologies", {}).items():
                    if tech_name not in results["technologies"]:
                        results["technologies"][tech_name] = []
                    results["technologies"][tech_name].append(tech_info)
                
                # Aggregate services
                for svc_name, svc_info in fp_result.get("services", {}).items():
                    if svc_name not in results["services"]:
                        results["services"][svc_name] = []
                    results["services"][svc_name].append(svc_info)
                
                time.sleep(0.2)  # Rate limiting
                
            except Exception as e:
                logger.error(f"[SERVICE_FP] Error fingerprinting {url}: {e}")
                continue
        
        # Save findings
        self._save_findings(results)
        
        # Update state
        self._update_state(results)
        
        logger.info(f"[SERVICE_FP] Completed - Found {len(results['technologies'])} technologies")
        return results
    
    def fingerprint_host(self, url: str) -> Dict[str, Any]:
        """
        Perform deep fingerprinting on a single host.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary with fingerprinting results
        """
        result = {
            "url": url,
            "technologies": {},
            "services": {},
            "attack_vectors": [],
            "confidence": 0.0
        }
        
        try:
            # Get response headers and body
            response = self.http_client.get(url, timeout=15)
            headers = dict(response.headers)
            body = response.text
            
            # Parse headers for technology detection
            header_technologies = self._analyze_headers(headers)
            result["technologies"].update(header_technologies)
            
            # Parse body for technology detection
            body_technologies = self._analyze_body(body)
            result["technologies"].update(body_technologies)
            
            # Detect service versions
            service_versions = self._extract_versions(headers, body)
            result["services"].update(service_versions)
            
            # Identify attack vectors based on detected technologies
            attack_vectors = self._identify_attack_vectors(result["technologies"], result["services"])
            result["attack_vectors"] = attack_vectors
            
            # Calculate overall confidence
            if result["technologies"] or result["services"]:
                result["confidence"] = min(1.0, 0.3 + 0.1 * len(result["technologies"]) + 0.15 * len(result["services"]))
            
        except Exception as e:
            logger.debug(f"[SERVICE_FP] Failed to fingerprint {url}: {e}")
            result["error"] = str(e)
        
        return result
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Analyze HTTP headers for technology detection."""
        technologies = {}
        
        # Server header analysis
        server = headers.get("Server", "").lower()
        for svc_name, svc_info in self.service_patterns["web_servers"].items():
            if any(h.lower() in server for h in svc_info["headers"]):
                version = self._extract_version_from_header(server, svc_info["patterns"])
                technologies[svc_name] = {
                    "name": svc_name,
                    "type": "web_server",
                    "version": version,
                    "source": "Server header",
                    "confidence": 0.9 if version else 0.7
                }
        
        # X-Powered-By header
        powered_by = headers.get("X-Powered-By", "").lower()
        for fw_name, fw_info in self.service_patterns["frameworks"].items():
            if any(h.lower() in powered_by for h in fw_info["headers"]):
                technologies[fw_name] = {
                    "name": fw_name,
                    "type": "framework",
                    "version": None,
                    "source": "X-Powered-By header",
                    "confidence": 0.85
                }
        
        # Set-Cookie analysis
        set_cookie = headers.get("Set-Cookie", "").lower()
        if "csrftoken" in set_cookie:
            technologies["django"] = {
                "name": "django",
                "type": "framework",
                "version": None,
                "source": "Cookie pattern",
                "confidence": 0.8
            }
        elif "laravel_session" in set_cookie:
            technologies["laravel"] = {
                "name": "laravel",
                "type": "framework",
                "version": None,
                "source": "Cookie pattern",
                "confidence": 0.85
            }
        
        # ASP.NET detection
        if headers.get("X-AspNet-Version") or headers.get("X-AspNetMvc-Version"):
            technologies["asp.net"] = {
                "name": "asp.net",
                "type": "framework",
                "version": headers.get("X-AspNet-Version", ""),
                "source": "ASP.NET headers",
                "confidence": 0.9
            }
        
        return technologies
    
    def _analyze_body(self, body: str) -> Dict[str, Dict[str, Any]]:
        """Analyze response body for technology detection."""
        technologies = {}
        body_lower = body.lower()
        
        # CMS detection
        for cms_name, cms_info in self.service_patterns["cms"].items():
            matches = sum(1 for p in cms_info["patterns"] if re.search(p, body, re.IGNORECASE))
            if matches >= 2:  # Require at least 2 pattern matches
                technologies[cms_name] = {
                    "name": cms_name,
                    "type": "cms",
                    "version": None,
                    "source": "Body patterns",
                    "confidence": 0.8 + 0.1 * matches
                }
        
        # Framework detection from body
        for fw_name, fw_info in self.service_patterns["frameworks"].items():
            matches = sum(1 for p in fw_info["patterns"] if re.search(p, body, re.IGNORECASE))
            if matches >= 1 and fw_name not in technologies:
                technologies[fw_name] = {
                    "name": fw_name,
                    "type": "framework",
                    "version": None,
                    "source": "Body patterns",
                    "confidence": 0.6 + 0.1 * matches
                }
        
        # JavaScript framework detection
        js_frameworks = {
            "react": [r"react", r"react-dom"],
            "vue": [r"vue", r"Vue\.js"],
            "angular": [r"angular", r"ng-version"],
            "jquery": [r"jquery", r"jQuery"],
            "bootstrap": [r"bootstrap", r"bs-"],
            "tailwind": [r"tailwind"]
        }
        
        for js_name, patterns in js_frameworks.items():
            if any(re.search(p, body, re.IGNORECASE) for p in patterns):
                technologies[js_name] = {
                    "name": js_name,
                    "type": "javascript_framework",
                    "version": None,
                    "source": "JS framework detection",
                    "confidence": 0.7
                }
        
        # Analytics/tracking detection
        if re.search(r"googletagmanager|google-analytics|ga\.js", body_lower):
            technologies["google-analytics"] = {
                "name": "google-analytics",
                "type": "analytics",
                "version": None,
                "source": "Analytics script",
                "confidence": 0.9
            }
        
        return technologies
    
    def _extract_versions(self, headers: Dict[str, str], body: str) -> Dict[str, Dict[str, Any]]:
        """Extract specific version information."""
        services = {}
        server_header = headers.get("Server", "")
        
        # Extract web server version
        version_patterns = [
            (r"Apache/([\d.]+)", "apache"),
            (r"nginx/([\d.]+)", "nginx"),
            (r"Microsoft-IIS/([\d.]+)", "iis"),
            (r"PHP/([\d.]+)", "php"),
            (r"Python/([\d.]+)", "python"),
            (r"Node\.js/([\d.]+)", "nodejs"),
        ]
        
        combined = f"{server_header}\n{body[:5000]}"
        for pattern, service_name in version_patterns:
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                version = match.group(1)
                services[service_name] = {
                    "name": service_name,
                    "version": version,
                    "source": "Version extraction",
                    "confidence": 0.95
                }
        
        return services
    
    def _identify_attack_vectors(self, technologies: Dict, services: Dict) -> List[Dict[str, Any]]:
        """Identify potential attack vectors based on detected technologies."""
        vectors = []
        
        tech_names = set(technologies.keys()) | set(services.keys())
        
        # Check for outdated/known vulnerable versions
        for svc_name, svc_info in services.items():
            version = svc_info.get("version")
            if version:
                vuln_check = self._check_version_vulnerabilities(svc_name, version)
                if vuln_check:
                    vectors.append(vuln_check)
        
        # CMS-specific vectors
        if "wordpress" in tech_names:
            vectors.append({
                "type": "wp_plugin_exploit",
                "description": "WordPress plugin vulnerability exploitation",
                "priority": "high",
                "requirements": ["wordpress_detected"]
            })
            vectors.append({
                "type": "wp_xmlrpc_attack",
                "description": "XML-RPC multicall exploitation",
                "priority": "medium",
                "requirements": ["wordpress_detected", "xmlrpc_enabled"]
            })
        
        # Framework-specific vectors
        if "django" in tech_names:
            vectors.append({
                "type": "django_debug_exploit",
                "description": "Django debug mode information disclosure",
                "priority": "medium",
                "requirements": ["django_detected"]
            })
        
        if "laravel" in tech_names:
            vectors.append({
                "type": "laravel_rce",
                "description": "Laravel framework RCE via deserialization",
                "priority": "high",
                "requirements": ["laravel_detected", "vulnerable_version"]
            })
        
        if "asp.net" in tech_names:
            vectors.append({
                "type": "viewstate_exploit",
                "description": "ASP.NET ViewState exploitation",
                "priority": "medium",
                "requirements": ["asp.net_detected"]
            })
        
        # Web server vectors
        if "apache" in tech_names:
            vectors.append({
                "type": "apache_rce",
                "description": "Apache HTTP Server exploitation",
                "priority": "high",
                "requirements": ["apache_detected", "vulnerable_version"]
            })
        
        if "iis" in tech_names:
            vectors.append({
                "type": "iis_shortname_scan",
                "description": "IIS short filename disclosure",
                "priority": "low",
                "requirements": ["iis_detected"]
            })
        
        return vectors
    
    def _check_version_vulnerabilities(self, service: str, version: str) -> Optional[Dict[str, Any]]:
        """Check if a specific version has known vulnerabilities."""
        # Simplified version checking - in production, this would query CVE databases
        vulnerable_versions = {
            "apache": {
                "ranges": [
                    ("2.4.0", "2.4.49", "CVE-2021-41773 - Path Traversal"),
                    ("2.4.49", "2.4.50", "CVE-2021-42013 - RCE"),
                ]
            },
            "nginx": {
                "ranges": [
                    ("1.0.0", "1.17.0", "CVE-2019-9511 - HTTP/2 DoS"),
                ]
            },
            "php": {
                "ranges": [
                    ("5.0.0", "5.6.40", "Multiple RCE vulnerabilities"),
                    ("7.0.0", "7.1.33", "Multiple security fixes"),
                ]
            }
        }
        
        if service in vulnerable_versions:
            for low, high, cve_info in vulnerable_versions[service]["ranges"]:
                if self._version_in_range(version, low, high):
                    return {
                        "type": "version_vulnerability",
                        "service": service,
                        "version": version,
                        "description": cve_info,
                        "priority": "critical",
                        "requirements": [f"{service}_version_{version}"]
                    }
        
        return None
    
    def _version_in_range(self, version: str, low: str, high: str) -> bool:
        """Check if version is within vulnerable range."""
        try:
            def parse_ver(v):
                return tuple(int(x) for x in v.split(".")[:3])
            
            ver_tuple = parse_ver(version)
            low_tuple = parse_ver(low)
            high_tuple = parse_ver(high)
            
            return low_tuple <= ver_tuple <= high_tuple
        except (ValueError, IndexError):
            return False
    
    def _extract_version_from_header(self, header: str, patterns: List[str]) -> Optional[str]:
        """Extract version from header using patterns."""
        for pattern in patterns:
            match = re.search(pattern, header, re.IGNORECASE)
            if match:
                return match.group(1) if match.groups() else None
        return None
    
    def _save_findings(self, results: Dict[str, Any]):
        """Save fingerprinting findings to file."""
        try:
            with open(self.findings_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.debug(f"[SERVICE_FP] Findings saved to {self.findings_file}")
        except Exception as e:
            logger.error(f"[SERVICE_FP] Failed to save findings: {e}")
    
    def _update_state(self, results: Dict[str, Any]):
        """Update state manager with fingerprinting results."""
        # Update technologies
        current_tech = self.state.get("technologies", {}) or {}
        for tech_name, tech_list in results.get("technologies", {}).items():
            if tech_list:
                latest = tech_list[-1]
                current_tech[tech_name] = {
                    "version": latest.get("version"),
                    "type": latest.get("type"),
                    "confidence": latest.get("confidence", 0.7),
                    "source": latest.get("source", "service_fingerprinter")
                }
        self.state.update(technologies=current_tech)
        
        # Update attack vectors
        current_vectors = self.state.get("attack_vectors", []) or []
        for finding in results.get("findings", []):
            for vector in finding.get("attack_vectors", []):
                if vector not in current_vectors:
                    current_vectors.append(vector)
        self.state.update(attack_vectors=current_vectors)
        
        # Update attack surface
        attack_surface = self.state.get("attack_surface", {}) or {}
        for tech_name, tech_info in results.get("technologies", {}).items():
            if tech_info:
                latest = tech_info[-1] if isinstance(tech_info, list) else tech_info
                attack_surface.setdefault("technologies", {})[tech_name] = latest
        self.state.update(attack_surface=attack_surface)
        
        logger.debug(f"[SERVICE_FP] State updated with {len(results.get('technologies', {}))} technologies")