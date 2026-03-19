"""
integrations/wappalyzer_runner.py - Advanced Technology Detection
Uses Wappalyzer patterns for accurate web technology identification
"""

import subprocess
import json
import logging
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger("recon.wappalyzer")


class WappalyzerRunner:
    """Run Wappalyzer for advanced web technology fingerprinting"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.tool = self._detect_tool()

    def _detect_tool(self) -> Optional[str]:
        """Detect available Wappalyzer tool"""
        tools = ["wappalyzer", "wapalyzer-cli"]
        for tool in tools:
            try:
                result = subprocess.run([tool, "-h"], capture_output=True, timeout=5)
                if result.returncode == 0 or "usage" in result.stderr.lower():
                    logger.info(f"Detected {tool}")
                    return tool
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        # Check if wappalyzer npm package is available
        try:
            result = subprocess.run(["npm", "list", "-g", "wappalyzer"], capture_output=True, timeout=5)
            if result.returncode == 0:
                logger.info("Detected wappalyzer via npm")
                return "wappalyzer"
        except Exception:
            pass
        
        logger.warning("Wappalyzer not found, will use fallback pattern matching")
        return None

    def run(self, url: str, timeout: int = 60, max_retries: int = 2) -> Dict[str, Any]:
        """Run Wappalyzer on URL"""
        result = {
            "url": url,
            "success": False,
            "technologies": [],
            "categories": {},
            "confidence_scores": {},
            "version_info": {},
            "raw_output": "",
            "error": None
        }

        for attempt in range(max_retries):
            try:
                if self.tool:
                    output = self._execute_wappalyzer(url, timeout)
                else:
                    output = None
                
                if output:
                    result["success"] = True
                    result["raw_output"] = output
                    self._parse_wappalyzer_output(output, result)
                else:
                    logger.info(f"Wappalyzer tool not available, using fallback patterns")
                    result["success"] = True
                    self._parse_with_fallback(url, result)
                
                return result
            except subprocess.TimeoutExpired:
                result["error"] = f"Timeout on attempt {attempt+1}/{max_retries}"
                logger.warning(f"Wappalyzer timeout for {url}: {result['error']}")
            except Exception as e:
                result["error"] = str(e)
                logger.warning(f"Wappalyzer error for {url} (attempt {attempt+1}): {e}")

        return result

    def _execute_wappalyzer(self, url: str, timeout: int) -> str:
        """Execute Wappalyzer tool"""
        try:
            if self.tool == "wappalyzer":
                cmd = ["wappalyzer", url, "--format", "json"]
            else:
                cmd = [self.tool, url, "--json"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return result.stdout if result.returncode == 0 else ""
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            logger.debug(f"Failed to execute wappalyzer: {e}")
            return ""

    def _parse_wappalyzer_output(self, output: str, result: Dict[str, Any]):
        """Parse Wappalyzer JSON output"""
        try:
            data = json.loads(output)
            
            if isinstance(data, dict):
                # Parse applications/technologies
                for tech_name, tech_data in data.items():
                    if isinstance(tech_data, dict):
                        version = tech_data.get("version", "")
                        confidence = tech_data.get("confidence", "0")
                        category = tech_data.get("category", "Unknown")
                        
                        result["technologies"].append(tech_name)
                        if category:
                            if category not in result["categories"]:
                                result["categories"][category] = []
                            result["categories"][category].append(tech_name)
                        
                        if version:
                            result["version_info"][tech_name] = version
                        
                        if confidence:
                            confidence_val = int(confidence) if isinstance(confidence, (int, str)) else 100
                            result["confidence_scores"][tech_name] = confidence_val
        except json.JSONDecodeError:
            # Fallback to text parsing
            self._parse_text_wappalyzer_output(output, result)

    def _parse_text_wappalyzer_output(self, output: str, result: Dict[str, Any]):
        """Fallback text parsing of Wappalyzer output"""
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Parse lines like "WordPress 5.8.3 (84% confidence)"
            match = re.search(r"(.+?)\s+([\d.]+)?\s*\((\d+)%\s+confidence\)", line)
            if match:
                tech_name = match.group(1).strip()
                version = match.group(2) or ""
                confidence = int(match.group(3))
                
                result["technologies"].append(tech_name)
                if version:
                    result["version_info"][tech_name] = version
                result["confidence_scores"][tech_name] = confidence

    def _parse_with_fallback(self, url: str, result: Dict[str, Any]):
        """Fallback pattern-based technology detection"""
        try:
            import urllib.request
            import socket
            
            socket.setdefaulttimeout(3)
            with urllib.request.urlopen(url, timeout=3) as response:
                headers = response.headers
                content = response.read().decode('utf-8', errors='ignore')[:50000]
            
            # Detect from headers
            self._detect_from_headers(headers, result)
            
            # Detect from content
            self._detect_from_content(content, result)
        except Exception as e:
            logger.debug(f"Fallback detection error: {e}")
        finally:
            socket.setdefaulttimeout(None)

    def _detect_from_headers(self, headers: Dict[str, str], result: Dict[str, Any]):
        """Detect technologies from HTTP headers"""
        patterns = {
            "Server": {
                r"Apache(?:/(\d+\.\d+))?": ("Apache", "Web Server"),
                r"nginx(?:/(\d+\.\d+))?": ("Nginx", "Web Server"),
                r"IIS/(\d+\.\d+)": ("IIS", "Web Server"),
                r"Microsoft-IIS": ("IIS", "Web Server"),
                r"Caddy": ("Caddy", "Web Server"),
            },
            "X-Powered-By": {
                r"PHP(?:[\s/-]?([\d.]+))?": ("PHP", "Language"),
                r"Express": ("Node.js/Express", "Language"),
                r"ASP\.NET": ("ASP.NET", "Language"),
                r"JSP": ("Java", "Language"),
            },
            "X-AspNet-Version": {
                r"(\d+\.\d+)": ("ASP.NET", "Language"),
            },
            "X-Frame-Options": {
                r".+": ("Security Headers", "Security"),
            }
        }
        
        for header_name, header_patterns in patterns.items():
            header_value = headers.get(header_name, "")
            for pattern, (tech_name, category) in header_patterns.items():
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    result["technologies"].append(tech_name)
                    if category:
                        if category not in result["categories"]:
                            result["categories"][category] = []
                        result["categories"][category].append(tech_name)
                    
                    if match.groups():
                        result["version_info"][tech_name] = match.group(1)

    def _detect_from_content(self, content: str, result: Dict[str, Any]):
        """Detect technologies from HTML content"""
        patterns = {
            r"wp-content|wp-includes|Wordpress": ("WordPress", "CMS"),
            r"wp-json/wp/v2/users": ("WordPress", "CMS"),
            r"jQuery(?:[\s/-]?([\d.]+))?": ("jQuery", "JavaScript Library"),
            r"React(?:[\s/-]?([\d.]+))?": ("React", "JavaScript Framework"),
            r"Vue(?:[\s/-]?([\d.]+))?": ("Vue.js", "JavaScript Framework"),
            r"Angular(?:[\s/-]?([\d.]+))?": ("Angular", "JavaScript Framework"),
            r"bootstrap(?:[\s/-]?v?([\d.]+))?": ("Bootstrap", "CSS Framework"),
            r"Foundation(?:[\s/-]?([\d.]+))?": ("Foundation", "CSS Framework"),
            r"Drupal(?:[\s/-]?([\d.]+))?": ("Drupal", "CMS"),
            r"Joomla(?:[\s/-]?([\d.]+))?": ("Joomla", "CMS"),
            r"Magento": ("Magento", "E-commerce"),
            r"Shopify": ("Shopify", "E-commerce"),
            r"WooCommerce": ("WooCommerce", "E-commerce Plugin"),
            r"Struts": ("Apache Struts", "Framework"),
            r"Spring": ("Spring Framework", "Framework"),
            r"Laravel": ("Laravel", "Framework"),
            r"Django": ("Django", "Framework"),
            r"Flask": ("Flask", "Framework"),
            r"FastAPI": ("FastAPI", "Framework"),
            r"GraphQL": ("GraphQL", "API"),
            r"swagger|swagger-ui": ("Swagger/OpenAPI", "API Documentation"),
            r"Kubernetes": ("Kubernetes", "Orchestration"),
            r"Docker": ("Docker", "Containerization"),
        }
        
        for pattern, (tech_name, category) in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                if tech_name not in result["technologies"]:
                    result["technologies"].append(tech_name)
                
                if category:
                    if category not in result["categories"]:
                        result["categories"][category] = []
                    if tech_name not in result["categories"][category]:
                        result["categories"][category].append(tech_name)
                
                # Try to extract version
                for match in matches:
                    if isinstance(match, tuple) and match[1]:
                        result["version_info"][tech_name] = match[1]
                        break

    def run_batch(self, urls: List[str], timeout: int = 60) -> List[Dict[str, Any]]:
        """Run on multiple URLs"""
        results = []
        for url in urls:
            results.append(self.run(url, timeout))
        return results
