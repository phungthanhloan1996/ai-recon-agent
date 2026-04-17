import urllib.parse
"""
integrations/dirbusting_runner.py - Directory and File Brute-forcing
Uses dirsearch or gobuster to discover hidden files and directories.
Integrated with GlobalConcurrencyManager for resource control.
"""

import subprocess
import json
import logging
import re
from typing import Dict, List, Any, Optional
from pathlib import Path
from urllib.parse import urlparse

from core.scan_optimizer import get_optimizer
from core.resource_manager import get_concurrency_manager

logger = logging.getLogger("recon.dirbusting")


class DirBustingRunner:
    """Run directory/file brute-forcing using available tools"""

    def __init__(self, output_dir: str, wordlist: Optional[str] = None):
        self.output_dir = output_dir
        self.wordlist = wordlist or self._get_default_wordlist()
        self.tool = self._detect_tool()
        self.extensions = ["php", "txt", "html", "js", "json", "xml", "asp", "aspx", "jsp", "py", "cfg", "conf", "config", "bak", "backup"]

    def _detect_tool(self) -> Optional[str]:
        """Detect available tool (dirsearch preferred, fallback to gobuster)"""
        for tool in ["dirsearch", "gobuster"]:
            try:
                subprocess.run([tool, "-h"], capture_output=True, timeout=5)
                logger.info(f"Detected {tool} for directory brute-forcing")
                return tool
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        logger.warning("No directory brute-forcing tool found (dirsearch or gobuster)")
        return None

    def _get_default_wordlist(self) -> str:
        """Get default wordlist path"""
        candidates = [
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-small.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/opt/wordlists/common.txt"
        ]
        
        for path in candidates:
            if Path(path).exists():
                logger.info(f"Using wordlist: {path}")
                return path
        
        # Fallback: create basic wordlist
        return self._create_basic_wordlist()

    def _create_basic_wordlist(self) -> str:
        """Create basic wordlist if none found"""
        wordlist_path = Path(self.output_dir) / "common_wordlist.txt"
        basic_words = [
            "admin", "wp-admin", "api", "api-docs", "swagger", "graphql",
            "login", "logout", "signin", "signup", "register", "user", "users",
            "profile", "settings", "config", "configuration", "test",
            "debug", "dev", "development", "staging", "backup", "backup.zip",
            "wp-json", "wp-content", "wp-includes", "plugins", "themes",
            "uploads", "download", "upload", "file", "files", "documents",
            "images", "images/uploads", "media", "css", "js", "javascript",
            "scripts", "vendor", "lib", "libs", "node_modules", "public",
            "private", "public_html", "httpdocs", "root", "home",
            ".git", ".gitignore", ".htaccess", "web.config", "robots.txt",
            "sitemap.xml", "sitemap.xml.gz", "feed.xml", "rss.xml",
            "index.php", "index.html", "index.htm", "default.php",
            "admin.php", "user.php", "config.php", "database.php",
            ".env", ".env.example", ".env.local", ".env.backup",
            "composer.json", "package.json", "requirements.txt",
            "aws-config", "azure-config", "gcp-config",
            "README", "README.md", "CHANGELOG", "TODO", "NOTES",
            "version.txt", "VERSION", "license.txt", "LICENSE",
            ".tar", ".tar.gz", ".zip", ".rar", ".7z",
            "sql", "sql.gz", "database.sql", "backup.sql",
            "test.php", "phpinfo.php", "shell.php", "cmd.php",
            "api/v1", "api/v2", "api/v3", "api/users", "api/products",
            "graphql", "graphql/", "graphql/api", "graphql/query",
            "rest", "rest/api", "restful", "json/api",
            "webhook", "webhooks", "callback", "callbackurl"
        ]
        
        try:
            with open(wordlist_path, "w") as f:
                f.write("\n".join(basic_words))
            logger.info(f"Created basic wordlist: {wordlist_path}")
            return str(wordlist_path)
        except Exception as e:
            logger.error(f"Failed to create wordlist: {e}")
            return ""

    def run(self, url: str, timeout: int = 300, max_retries: int = 1) -> Dict[str, Any]:
        """Run directory brute-forcing on URL.
        
        FIXED: Increased timeout from 180s to 300s to handle slow hosts.
        FIXED: Increased max_retries from 2 to 3 for better resilience.
        FIXED: Added retry logic with exponential backoff for timeouts.
        FIXED: Adaptive timeout based on host history.
        FIX #3: Implement adaptive timeout REDUCTION on retry (not increase).
                After timeout, reduce timeout by 25% to fail faster on problematic hosts.
        """
        optimizer = get_optimizer()
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        
        # Check if host is blacklisted
        if optimizer.is_host_blacklisted(hostname):
            return {
                "url": url,
                "success": False,
                "tool": self.tool,
                "directories": [],
                "files": [],
                "endpoints": [],
                "suspicious": [],
                "raw_output": "",
                "error": f"Host {hostname} is blacklisted"
            }
        
        result = {
            "url": url,
            "success": False,
            "tool": self.tool,
            "directories": [],
            "files": [],
            "endpoints": [],
            "suspicious": [],
            "raw_output": "",
            "error": None
        }

        if not self.tool:
            result["error"] = "No directory brute-forcing tool available"
            return result

        if not self.wordlist:
            result["error"] = "No wordlist available"
            return result

        # FIX #3: Adaptive timeout - REDUCE on retry to fail faster
        base_timeout = timeout  # Default 180s
        current_timeout = base_timeout
        
        # Track timeout history for this host
        timeout_count = 0
        
        for attempt in range(max_retries):
            try:
                # FIX #3: On retry after timeout, use adaptive timeout
                if attempt > 0 and timeout_count > 0:
                    # First retry: reduce by 25%
                    # Second retry: reduce by 50% (but not below 60s)
                    reduction = 0.25 if attempt == 1 else 0.50
                    current_timeout = int(current_timeout * (1 - reduction))
                    current_timeout = max(60, current_timeout)  # Minimum 60s for dirbusting
                    logger.info(f"[DIRBUST] Retry attempt {attempt+1} for {url} with timeout {current_timeout}s (was {timeout}s)")
                
                output = self._execute_scan(url, current_timeout)
                if output:
                    result["success"] = True
                    result["raw_output"] = output
                    self._parse_output(output, result)
                    return result
            except subprocess.TimeoutExpired:
                timeout_count += 1
                result["error"] = f"Timeout on attempt {attempt+1} ({current_timeout}s)"
                logger.warning(f"[DIRBUST] Timeout for {url}: {result['error']}")
                
                # FIX #3: Check optimizer for adaptive timeout suggestion
                host_status = optimizer.get_host_status(hostname) if optimizer else None
                if host_status and hasattr(host_status, 'adaptive_timeout_enabled') and host_status.adaptive_timeout_enabled:
                    logger.warning(f"[DIRBUST] Host {hostname} has adaptive timeout enabled, reducing timeout for next attempt")
                
                # Only record timeout after all retries exhausted
                if attempt >= max_retries - 1:
                    optimizer.record_dirbust_timeout(url)
                    logger.warning(f"[DIRBUST] All retries exhausted for {url}, skipping future attempts")
                continue  # Try next retry
            except Exception as e:
                result["error"] = str(e)
                logger.warning(f"[DIRBUST] Error for {url} (attempt {attempt+1}): {e}")
                break  # Non-timeout errors should not retry

        return result

    def _execute_scan(self, url: str, timeout: int) -> str:
        """Execute directory brute-forcing command"""
        try:
            if self.tool == "dirsearch":
                cmd = [
                    "dirsearch",
                    "-u", url,
                    "-w", self.wordlist,
                    "-e", ",".join(self.extensions),
                    "--format", "json",
                    "-q",
                    "--timeout", "10",
                    "-r"
                ]
            else:  # gobuster
                cmd = [
                    "gobuster",
                    "dir",
                    "-u", url,
                    "-w", self.wordlist,
                    "-q",
                    "-t", "20",
                    "--timeout", "10s",
                    "-a", "Mozilla/5.0",
                    "--no-error"
                ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return result.stdout if result.returncode == 0 else result.stderr
        except subprocess.TimeoutExpired:
            raise
        except Exception as e:
            logger.error(f"Failed to execute {self.tool}: {e}")
            raise

    def _parse_output(self, output: str, result: Dict[str, Any]):
        """Parse directory brute-forcing output"""
        try:
            # Try JSON parsing first
            for line in output.strip().split("\n"):
                if not line.strip():
                    continue
                
                try:
                    entry = json.loads(line)
                    if "path" in entry:
                        self._classify_entry(entry["path"], entry.get("status"), result)
                except json.JSONDecodeError:
                    # Try text parsing
                    if "200" in line or "301" in line or "302" in line:
                        match = re.search(r"(https?://[^\s]+?)(?:\s|$)", line)
                        if match:
                            path = match.group(1)
                            status = re.search(r"(\d{3})", line)
                            status_code = int(status.group(1)) if status else 0
                            self._classify_entry(path, status_code, result)
        except Exception as e:
            logger.debug(f"Error parsing output: {e}")
            # Fallback to text parsing
            self._parse_text_output(output, result)

    def _parse_text_output(self, output: str, result: Dict[str, Any]):
        """Fallback text parsing"""
        status_pattern = r"(?:Status|Code)[:\s]+(\d+)"
        path_pattern = r"(https?://[^\s]+?)(?:\s|Status|Code|$)"
        
        for line in output.split("\n"):
            if not line.strip():
                continue
            
            status_match = re.search(status_pattern, line)
            path_match = re.search(path_pattern, line)
            
            if path_match:
                path = path_match.group(1).rstrip("\\/")
                status = int(status_match.group(1)) if status_match else 200
                self._classify_entry(path, status, result)

    def _classify_entry(self, path: str, status: int, result: Dict[str, Any]):
        """Classify found entry"""
        if not isinstance(status, int):
            try:
                status = int(status)
            except (ValueError, TypeError):
                status = 200
        
        # Only process successful responses
        if status not in [200, 204, 301, 302, 307, 401, 403]:
            return
        
        path_lower = path.lower()
        
        # Classify by type
        if any(ext in path_lower for ext in [".php", ".asp", ".aspx", ".jsp", ".py", ".pl"]):
            result["files"].append({"path": path, "status": status})
        elif path_lower.endswith("/"):
            result["directories"].append({"path": path, "status": status})
        else:
            result["endpoints"].append({"path": path, "status": status})
        
        # Flag suspicious findings
        if any(susp in path_lower for susp in [
            "admin", "backup", ".git", ".env", ".htaccess", "config", "database",
            "shell", "webshell", "cmd", "exec", "eval", "test", "dev", "debug",
            "private", "secret", "key", "password", "sql", "upload"
        ]):
            result["suspicious"].append(path)

    def run_batch(self, urls: List[str], timeout: int = 180) -> List[Dict[str, Any]]:
        """Run on multiple URLs"""
        results = []
        for url in urls:
            results.append(self.run(url, timeout))
        return results
