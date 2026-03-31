"""
integrations/sqlmap_runner.py - SQLMap Integration
Wrapper for SQLMap SQL injection detection and exploitation tool.
"""

import json
import os
import re
import logging
import subprocess
import shutil
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

logger = logging.getLogger("recon.sqlmap_runner")


class SQLMapRunner:
    """
    Wrapper for SQLMap - automated SQL injection tool.
    Provides methods to run SQLMap and parse its output.
    """
    
    def __init__(self, output_dir: str = None, sqlmap_path: str = None):
        """
        Initialize SQLMap runner.
        
        Args:
            output_dir: Directory for saving results
            sqlmap_path: Path to sqlmap executable (if not in PATH)
        """
        self.output_dir = output_dir
        self.sqlmap_path = sqlmap_path or self._find_sqlmap()
        self.results_dir = os.path.join(output_dir, "sqlmap_results") if output_dir else None
    
    def _find_sqlmap(self) -> Optional[str]:
        """Find SQLMap in system PATH or common locations"""
        # Check if sqlmap is in PATH
        sqlmap_in_path = shutil.which("sqlmap")
        if sqlmap_in_path:
            return sqlmap_in_path
        
        # Check common installation locations
        common_paths = [
            "/usr/bin/sqlmap",
            "/usr/local/bin/sqlmap",
            "/opt/sqlmap/sqlmap.py",
            os.path.expanduser("~/.local/bin/sqlmap"),
            os.path.expanduser("~/sqlmap/sqlmap.py"),
            "/usr/share/sqlmap/sqlmap.py",
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                return path
        
        # Check if sqlmap is installed via apt/kali
        if os.path.exists("/usr/share/sqlmap"):
            return "/usr/share/sqlmap/sqlmap.py"
        
        return None
    
    def is_sqlmap_available(self) -> bool:
        """Check if SQLMap is available on the system"""
        if self.sqlmap_path:
            return os.path.exists(self.sqlmap_path)
        return False
    
    def run_sqlmap(
        self,
        url: str,
        data: str = None,
        cookies: str = None,
        headers: Dict[str, str] = None,
        level: int = 1,
        risk: int = 1,
        timeout: int = 300,
        tamper: str = None,
        techniques: str = "BEUSTQ",
        batch: bool = True,
        additional_args: List[str] = None
    ) -> Dict[str, Any]:
        """
        Run SQLMap against a target URL.
        
        Args:
            url: Target URL
            data: POST data (if any)
            cookies: Cookie string
            headers: Additional headers dict
            level: Test level (1-5, default 1)
            risk: Risk level (1-3, default 1)
            timeout: Timeout in seconds
            tamper: Tamper script name(s)
            techniques: Injection techniques to test (B=Boolean, E=Error, U=Union, S=Stacked, T=Time, Q=Inline query)
            batch: Use batch mode (no prompts)
            additional_args: Additional command line arguments
            
        Returns:
            Dictionary with SQLMap results
        """
        result = {
            "url": url,
            "success": False,
            "vulnerable": False,
            "findings": [],
            "output": "",
            "error": "",
            "dbms": None,
            "databases": [],
            "tables": [],
            "columns": [],
            "users": [],
            "password_hashes": [],
        }
        
        if not self.is_sqlmap_available():
            result["error"] = "SQLMap not found on system"
            logger.warning("[SQLMAP] SQLMap not available")
            return result
        
        try:
            # Build command
            cmd = [self.sqlmap_path]
            
            # Basic options
            cmd.extend(["-u", url])
            cmd.extend(["--level", str(level)])
            cmd.extend(["--risk", str(risk)])
            cmd.extend(["--technique", techniques])
            cmd.extend(["--timeout", str(min(timeout, 60))])  # SQLMap timeout per request
            
            # Batch mode
            if batch:
                cmd.append("--batch")
            
            # Don't follow redirects by default
            cmd.append("--skip-urlencode")
            
            # POST data
            if data:
                cmd.extend(["--data", data])
            
            # Cookies
            if cookies:
                cmd.extend(["--cookie", cookies])
            
            # Headers
            if headers:
                for key, value in headers.items():
                    cmd.extend(["--header", f"{key}: {value}"])
            
            # Tamper script
            if tamper:
                cmd.extend(["--tamper", tamper])
            
            # Output directory
            if self.results_dir:
                os.makedirs(self.results_dir, exist_ok=True)
                cmd.extend(["--output-dir", self.results_dir])
            
            # Additional arguments
            if additional_args:
                cmd.extend(additional_args)
            
            # Add safe options
            cmd.extend(["--answers", "N"])  # Default to No for prompts
            cmd.extend(["--crawl", "1"])  # Crawl 1 level deep
            
            # Run SQLMap
            logger.info(f"[SQLMAP] Running: {' '.join(cmd[:10])}...")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            
            stdout = ""
            stderr = ""
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                result["error"] = "SQLMap timed out"
            
            result["output"] = stdout
            result["error"] = stderr or result["error"]
            
            # Parse output
            parsed = self._parse_sqlmap_output(stdout)
            result.update(parsed)
            
            if result["vulnerable"]:
                logger.warning(f"[SQLMAP] SQL Injection found on {url}")
                if result["dbms"]:
                    logger.info(f"[SQLMAP] DBMS: {result['dbms']}")
            else:
                logger.info(f"[SQLMAP] No SQL injection found on {url}")
            
        except Exception as e:
            result["error"] = str(e)
            logger.error(f"[SQLMAP] Error running SQLMap: {e}")
        
        return result
    
    def _parse_sqlmap_output(self, output: str) -> Dict[str, Any]:
        """
        Parse SQLMap console output to extract findings.
        
        Args:
            output: Raw SQLMap output string
            
        Returns:
            Parsed results dictionary
        """
        result = {
            "vulnerable": False,
            "findings": [],
            "dbms": None,
            "databases": [],
            "tables": [],
            "columns": [],
            "users": [],
            "password_hashes": [],
        }
        
        if not output:
            return result
        
        lines = output.split('\n')
        
        # Check for vulnerability indicators
        vulnerability_patterns = [
            r"Parameter '.+?' appears to be '.+?' injectable",
            r"SQL injection detected",
            r"is vulnerable to",
            r"back-end DBMS: ",
        ]
        
        for line in lines:
            line = line.strip()
            
            # Check for vulnerability
            for pattern in vulnerability_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "sql_injection",
                        "evidence": line[:200],
                        "severity": "CRITICAL"
                    })
                    break
            
            # Extract DBMS
            if "back-end DBMS:" in line:
                match = re.search(r"back-end DBMS:\s*(.+)", line)
                if match:
                    result["dbms"] = match.group(1).strip()
            
            # Extract database names
            if "available databases" in line.lower():
                match = re.search(r'\[(\d+)\]', line)
                if match:
                    result["databases"].append(line.strip())
            
            # Extract table names
            if re.search(r'Database: .+?\n\s+\[.+\] table', output, re.IGNORECASE):
                if 'table' in line.lower() and '[' in line:
                    result["tables"].append(line.strip())
            
            # Extract users
            if "Database:" in line and "users" in line.lower():
                result["users"].append(line.strip())
            
            # Extract password hashes
            if "password hash" in line.lower() or "password:" in line.lower():
                result["password_hashes"].append(line.strip())
        
        return result
    
    def run_sqlmap_json(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        Run SQLMap and try to get JSON output.
        
        Args:
            url: Target URL
            **kwargs: Additional arguments for run_sqlmap
            
        Returns:
            Parsed JSON results if available
        """
        # First run to detect vulnerability
        basic_result = self.run_sqlmap(url, **kwargs)
        
        if not basic_result["vulnerable"]:
            return basic_result
        
        # Try to get more detailed results from JSON output
        try:
            # SQLMap stores results in ~/.local/share/sqlmap/output/
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname or "unknown"
            
            # Common output locations
            output_dirs = [
                os.path.expanduser(f"~/.local/share/sqlmap/output/{hostname}"),
                os.path.expanduser(f"~/.sqlmap/output/{hostname}"),
                f"/tmp/sqlmap/output/{hostname}",
            ]
            
            for output_dir in output_dirs:
                json_file = os.path.join(output_dir, "log")
                if os.path.exists(json_file):
                    try:
                        with open(json_file, 'r') as f:
                            for line in f:
                                try:
                                    json_data = json.loads(line)
                                    if json_data.get("type") == "payload":
                                        basic_result["findings"].append({
                                            "type": "sql_injection",
                                            "payload": json_data.get("value", ""),
                                            "place": json_data.get("place", ""),
                                            "parameter": json_data.get("parameter", ""),
                                        })
                                except json.JSONDecodeError:
                                    continue
                    except Exception:
                        continue
            
            # Also check for JSON file in our output dir
            if self.results_dir:
                for f in os.listdir(self.results_dir):
                    if f.endswith('.json'):
                        json_path = os.path.join(self.results_dir, f)
                        try:
                            with open(json_path, 'r') as file:
                                json_data = json.load(file)
                                if isinstance(json_data, list):
                                    for entry in json_data:
                                        if entry.get("vulnerable"):
                                            basic_result["findings"].append(entry)
                        except Exception:
                            continue
            
        except Exception as e:
            logger.debug(f"[SQLMAP] Failed to parse JSON output: {e}")
        
        return basic_result
    
    def test_sqli_quick(
        self,
        url: str,
        params: List[str] = None,
        timeout: int = 60
    ) -> List[Dict[str, Any]]:
        """
        Quick SQLi test for specific parameters.
        
        Args:
            url: Target URL
            params: List of parameter names to test
            timeout: Timeout in seconds
            
        Returns:
            List of findings
        """
        findings = []
        
        if not self.is_sqlmap_available():
            return findings
        
        if not params:
            # Try to detect parameters from URL
            params = []
            if '?' in url:
                query_string = url.split('?')[1]
                params = [p.split('=')[0] for p in query_string.split('&') if '=' in p]
        
        for param in params[:5]:  # Limit to 5 parameters
            try:
                result = self.run_sqlmap(
                    url=url,
                    level=2,
                    risk=1,
                    timeout=timeout,
                    additional_args=["--param", param]
                )
                
                if result["vulnerable"]:
                    findings.extend(result["findings"])
                    
            except Exception as e:
                logger.debug(f"[SQLMAP] Error testing param {param}: {e}")
        
        return findings
    
    def dump_database(
        self,
        url: str,
        database: str,
        data: str = None,
        tables: List[str] = None,
        timeout: int = 600
    ) -> Dict[str, Any]:
        """
        Dump database contents using SQLMap.
        
        Args:
            url: Target URL
            database: Database name to dump
            data: POST data if needed
            tables: Specific tables to dump (None for all)
            timeout: Timeout in seconds
            
        Returns:
            Dump results
        """
        result = {
            "database": database,
            "tables": {},
            "success": False,
            "error": ""
        }
        
        if not self.is_sqlmap_available():
            result["error"] = "SQLMap not available"
            return result
        
        try:
            cmd = [self.sqlmap_path]
            cmd.extend(["-u", url])
            cmd.extend(["-D", database])
            cmd.extend(["--dump"])
            cmd.extend(["--batch"])
            cmd.extend(["--timeout", "30"])
            
            if data:
                cmd.extend(["--data", data])
            
            if tables:
                for table in tables:
                    cmd.extend(["-T", table])
            
            if self.results_dir:
                cmd.extend(["--output-dir", self.results_dir])
            
            logger.info(f"[SQLMAP] Dumping database {database}...")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            # Parse dump output
            result["success"] = "Dumped" in stdout or "rows" in stdout.lower()
            result["output"] = stdout
            result["error"] = stderr
            
        except subprocess.TimeoutExpired:
            result["error"] = "Dump operation timed out"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def get_version(self) -> str:
        """Get SQLMap version"""
        if not self.is_sqlmap_available():
            return "Not installed"
        
        try:
            result = subprocess.run(
                [self.sqlmap_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip() or result.stderr.strip()
        except Exception:
            return "Unknown"