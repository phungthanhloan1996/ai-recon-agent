"""
integrations/whatweb_runner.py - Advanced Whatweb Technology Fingerprinting
Extracts technologies, versions, and plugins from web servers
Integrates with CVE matcher for vulnerability identification
"""

import subprocess
import json
import logging
import re
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.cve_matcher import match_any_range

logger = logging.getLogger("recon.whatweb")


class WhatwebRunner:
    """Run whatweb for comprehensive web technology fingerprinting"""

    def __init__(self, output_dir: str, verbose: bool = False):
        self.output_dir = output_dir
        self.verbose = verbose
        self.cve_db = self._load_cve_patterns()

    def _load_cve_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load CVE patterns from rules"""
        cve_patterns = {}
        try:
            rules_dir = Path(__file__).parent.parent / "rules"
            for rule_file in ["vulnerability_patterns.json", "exploit_chains.json"]:
                rule_path = rules_dir / rule_file
                if rule_path.exists():
                    with open(rule_path, "r") as f:
                        patterns = json.load(f)
                        if isinstance(patterns, dict):
                            cve_patterns.update(patterns)
        except Exception as e:
            logger.warning(f"Failed to load CVE patterns: {e}")
        return cve_patterns

    def run(self, url: str, timeout: int = 60, max_retries: int = 2) -> Dict[str, Any]:
        """Run whatweb on URL with retry logic and comprehensive parsing"""
        result = {
            "url": url,
            "success": False,
            "technologies": [],
            "plugins": [],
            "headers": {},
            "cookies": [],
            "forms": [],
            "vulnerabilities": [],
            "raw_output": "",
            "error": None
        }

        for attempt in range(max_retries):
            try:
                output = self._execute_whatweb(url, timeout)
                if output:
                    result["success"] = True
                    result["raw_output"] = output
                    self._parse_whatweb_output(output, result)
                    self._match_cves(result)
                    return result
            except subprocess.TimeoutExpired:
                result["error"] = f"Timeout on attempt {attempt+1}/{max_retries}"
                logger.warning(f"Whatweb timeout for {url}: {result['error']}")
            except Exception as e:
                result["error"] = str(e)
                logger.warning(f"Whatweb error for {url} (attempt {attempt+1}): {e}")

        return result

    def _execute_whatweb(self, url: str, timeout: int) -> str:
        """Execute whatweb command and capture output - improved reliability"""
        try:
            cmd = [
                "whatweb",
                "--no-errors",
                "--follow-redirect=same-host",
                "--max-redirect=5",
                "--log-json=/tmp/whatweb.json",
                "--user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                url
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Try to read JSON output first
            try:
                json_file = Path("/tmp/whatweb.json")
                if json_file.exists():
                    with open(json_file, "r") as f:
                        data = f.read()
                        json_file.unlink()  # Clean up
                        return data
            except Exception:
                pass
            
            # Return stdout if successful, otherwise try stderr
            output = result.stdout if result.returncode == 0 else result.stderr
            
            # If no output, try to read the JSON file anyway
            if not output:
                try:
                    json_file = Path("/tmp/whatweb.json")
                    if json_file.exists():
                        with open(json_file, "r") as f:
                            output = f.read()
                except Exception:
                    pass
            
            return output
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            logger.error(f"Failed to execute whatweb: {e}")
            raise

    def _parse_whatweb_output(self, output: str, result: Dict[str, Any]):
        """Parse whatweb JSON output and extract technologies"""
        try:
            # Try parsing as JSON array
            data = json.loads(output)
            if not isinstance(data, list):
                data = [data]
            
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                
                # Extract plugins (technologies)
                plugins = entry.get("plugins", {})
                if isinstance(plugins, dict):
                    for tech_name, details in plugins.items():
                        tech_info = self._parse_technology(tech_name, details)
                        if tech_info:
                            result["technologies"].append(tech_info)
                            if details and isinstance(details, (list, dict)):
                                result["plugins"].append({
                                    "name": tech_name,
                                    "details": str(details)[:500]
                                })
                
                # Extract headers
                if "http_response" in entry and isinstance(entry["http_response"], dict):
                    headers = entry["http_response"].get("headers", {})
                    if isinstance(headers, dict):
                        result["headers"] = {k: v[:200] for k, v in headers.items()}
                
                # Extract cookies
                if "cookies" in entry and isinstance(entry["cookies"], list):
                    result["cookies"] = entry["cookies"]
                
                # Extract forms
                if "forms" in entry and isinstance(entry["forms"], list):
                    result["forms"] = entry["forms"][:5]  # Limit to 5 forms
        except json.JSONDecodeError:
            # Fall back to text parsing
            self._parse_text_output(output, result)

    def _parse_text_output(self, output: str, result: Dict[str, Any]):
        """Fallback parser for text output"""
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Extract technology patterns
            # Example: "WordPress 5.8.3"
            wordpress_match = re.search(r"WordPress[:\s]+([0-9.]+)", line, re.IGNORECASE)
            if wordpress_match:
                result["technologies"].append({
                    "name": "WordPress",
                    "version": wordpress_match.group(1),
                    "category": "CMS"
                })
            
            # Apache version
            apache_match = re.search(r"Apache[:\s]+([0-9.]+)", line, re.IGNORECASE)
            if apache_match:
                result["technologies"].append({
                    "name": "Apache",
                    "version": apache_match.group(1),
                    "category": "Web Server"
                })
            
            # Nginx version
            nginx_match = re.search(r"Nginx[:\s]+([0-9.]+)", line, re.IGNORECASE)
            if nginx_match:
                result["technologies"].append({
                    "name": "Nginx",
                    "version": nginx_match.group(1),
                    "category": "Web Server"
                })
            
            # PHP version
            php_match = re.search(r"PHP[:\s]+([0-9.]+)", line, re.IGNORECASE)
            if php_match:
                result["technologies"].append({
                    "name": "PHP",
                    "version": php_match.group(1),
                    "category": "Language"
                })
            
            # Extract any version numbers
            version_match = re.search(r"([Vv]ersion[:\s]+)?([0-9]+\.[0-9.]+)", line)
            if version_match and not any(t.get("version") == version_match.group(2) for t in result["technologies"]):
                # Generic technology with version
                if "Title:" not in line and "Status" not in line:
                    result["technologies"].append({
                        "name": line[:50],
                        "version": version_match.group(2),
                        "category": "Unknown"
                    })

    def _parse_technology(self, tech_name: str, details: Any) -> Optional[Dict[str, Any]]:
        """Parse individual technology entry"""
        try:
            tech_info = {
                "name": tech_name,
                "category": self._categorize_tech(tech_name),
                "version": None,
                "metadata": {}
            }
            
            if isinstance(details, list):
                for item in details:
                    if isinstance(item, dict):
                        if "version" in item:
                            tech_info["version"] = str(item["version"])
                        tech_info["metadata"].update(item)
                    elif isinstance(item, str):
                        # Try to extract version from string
                        version_match = re.search(r"(?:v|version)[:\s]*([0-9.]+)", item, re.IGNORECASE)
                        if version_match:
                            tech_info["version"] = version_match.group(1)
            elif isinstance(details, dict):
                if "version" in details:
                    tech_info["version"] = str(details["version"])
                tech_info["metadata"] = details
            elif isinstance(details, str):
                version_match = re.search(r"(?:v|version)[:\s]*([0-9.]+)", details, re.IGNORECASE)
                if version_match:
                    tech_info["version"] = version_match.group(1)
            
            return tech_info
        except Exception as e:
            logger.debug(f"Error parsing technology {tech_name}: {e}")
            return None

    def _categorize_tech(self, tech_name: str) -> str:
        """Categorize technology by type"""
        tech_lower = tech_name.lower()
        
        if any(x in tech_lower for x in ["wordpress", "drupal", "joomla", "magento", "shopify"]):
            return "CMS"
        elif any(x in tech_lower for x in ["apache", "nginx", "iis", "caddy", "lighttpd"]):
            return "Web Server"
        elif any(x in tech_lower for x in ["php", "python", "nodejs", "ruby", "java", "golang"]):
            return "Language"
        elif any(x in tech_lower for x in ["mysql", "postgresql", "mongodb", "redis"]):
            return "Database"
        elif any(x in tech_lower for x in ["jquery", "react", "vue", "angular", "bootstrap"]):
            return "JavaScript"
        elif any(x in tech_lower for x in ["openssl", "ssl", "tls"]):
            return "Security"
        else:
            return "Unknown"

    def _match_cves(self, result: Dict[str, Any]):
        """Match detected technologies against known CVE patterns"""
        for tech in result["technologies"]:
            tech_name = tech.get("name", "").lower()
            version = tech.get("version")
            
            if not version:
                continue
            
            # Check against loaded CVE patterns
            for pattern_name, pattern_data in self.cve_db.items():
                if isinstance(pattern_data, dict):
                    # Match against product name
                    if pattern_data.get("product", "").lower() in tech_name:
                        affected_versions = pattern_data.get("affected_versions", [])
                        if match_any_range(version, affected_versions):
                            result["vulnerabilities"].append({
                                "cve": pattern_data.get("cve_id", pattern_name),
                                "technology": tech_name,
                                "version": version,
                                "severity": pattern_data.get("severity", "MEDIUM"),
                                "description": pattern_data.get("description", "")[:200]
                            })

    def parse_results(self, multiple_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate multiple whatweb results"""
        aggregated = {
            "total_hosts": len(multiple_results),
            "technologies_found": {},
            "vulnerabilities": [],
            "high_risk_hosts": [],
            "plugin_summary": {}
        }
        
        for result in multiple_results:
            if not result.get("success"):
                continue
            
            # Aggregate technologies
            for tech in result.get("technologies", []):
                tech_key = tech.get("name", "Unknown")
                if tech_key not in aggregated["technologies_found"]:
                    aggregated["technologies_found"][tech_key] = {
                        "count": 0,
                        "versions": set(),
                        "category": tech.get("category", "Unknown")
                    }
                aggregated["technologies_found"][tech_key]["count"] += 1
                if tech.get("version"):
                    aggregated["technologies_found"][tech_key]["versions"].add(tech["version"])
            
            # Aggregate vulnerabilities
            for vuln in result.get("vulnerabilities", []):
                aggregated["vulnerabilities"].append({
                    **vuln,
                    "url": result.get("url")
                })
            
            # Track high-risk hosts
            if result.get("vulnerabilities"):
                aggregated["high_risk_hosts"].append({
                    "url": result.get("url"),
                    "vulnerability_count": len(result.get("vulnerabilities", []))
                })
            
            # Plugin summary
            for plugin in result.get("plugins", []):
                plugin_name = plugin.get("name", "Unknown")
                if plugin_name not in aggregated["plugin_summary"]:
                    aggregated["plugin_summary"][plugin_name] = {"count": 0, "affected": []}
                aggregated["plugin_summary"][plugin_name]["count"] += 1
                if any(v["technology"] == plugin_name for v in result.get("vulnerabilities", [])):
                    aggregated["plugin_summary"][plugin_name]["affected"].append(result.get("url"))
        
        # Convert sets to lists for JSON serialization
        for tech in aggregated["technologies_found"].values():
            tech["versions"] = list(tech.get("versions", set()))
        
        # Sort high-risk hosts
        aggregated["high_risk_hosts"].sort(
            key=lambda x: x.get("vulnerability_count", 0),
            reverse=True
        )
        
        return aggregated
