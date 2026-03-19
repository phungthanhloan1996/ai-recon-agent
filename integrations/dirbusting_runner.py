"""
integrations/dirbusting_runner.py - Directory and File Brute-forcing
Uses dirsearch or gobuster to discover hidden files and directories
"""

import subprocess
import json
import logging
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

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

    def run(self, url: str, timeout: int = 180, max_retries: int = 2) -> Dict[str, Any]:
        """Run directory brute-forcing on URL"""
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

        for attempt in range(max_retries):
            try:
                output = self._execute_scan(url, timeout)
                if output:
                    result["success"] = True
                    result["raw_output"] = output
                    self._parse_output(output, result)
                    return result
            except subprocess.TimeoutExpired:
                result["error"] = f"Timeout on attempt {attempt+1}/{max_retries}"
                logger.warning(f"Dir busting timeout for {url}: {result['error']}")
            except Exception as e:
                result["error"] = str(e)
                logger.warning(f"Dir busting error for {url} (attempt {attempt+1}): {e}")

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
                    "-t", "30",
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
