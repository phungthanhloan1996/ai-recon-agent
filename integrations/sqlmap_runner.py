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

    def _safe_target_name(self, url: str) -> str:
        return re.sub(r"[^A-Za-z0-9._-]", "_", url)[:180]

    def _get_runtime_artifact_paths(self, url: str) -> Dict[str, str]:
        base_dir = self.results_dir or self.output_dir or "."
        os.makedirs(base_dir, exist_ok=True)
        safe_name = self._safe_target_name(url)
        return {
            "stdout": os.path.join(base_dir, f"{safe_name}.stdout.log"),
            "stderr": os.path.join(base_dir, f"{safe_name}.stderr.log"),
            "summary": os.path.join(base_dir, f"{safe_name}.summary.json"),
        }

    def _write_text_file(self, path: str, content: str):
        try:
            with open(path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(content or "")
        except Exception as e:
            logger.error(f"[SQLMAP] Failed to write artifact {path}: {e}")

    def _write_summary_file(self, path: str, data: Dict[str, Any]):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"[SQLMAP] Failed to write summary artifact {path}: {e}")
    
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
        level: int = 3,
        risk: int = 2,
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
            artifact_paths = self._get_runtime_artifact_paths(url)
            # Build command
            cmd = [self.sqlmap_path]
            
            # Basic options
            cmd.extend(["-u", url])
            cmd.extend(["--level", str(level)])
            cmd.extend(["--risk", str(risk)])
            cmd.extend(["--technique", techniques])
            cmd.extend(["--timeout", str(min(timeout, 600))])# SQLMap timeout per request
            
            # Batch mode
            if batch:
                cmd.append("--batch")
            
            # Don't follow redirects by default
            #md.append("--skip-urlencode")
            
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
            #md.extend(["--crawl", "1"])  # Crawl 1 level deep
            
            # Run SQLMap
            logger.info(f"[SQLMAP] Running: {' '.join(cmd[:10])}...")
            # Debug: log full command
            logger.debug(f"[SQLMAP] Full command: {' '.join(cmd)}")
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
            result["artifact_path"] = artifact_paths["summary"]
            result["raw_output_path"] = artifact_paths["stdout"]
            result["stderr_path"] = artifact_paths["stderr"]
            self._write_text_file(artifact_paths["stdout"], stdout)
            self._write_text_file(artifact_paths["stderr"], stderr)
            
            # Parse output
            parsed = self._parse_sqlmap_output(stdout)
            result.update(parsed)
            self._write_summary_file(artifact_paths["summary"], result)
            
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
        """
        # First run to detect vulnerability
        basic_result = self.run_sqlmap(url, **kwargs)
        parsed_artifact_paths: List[str] = []
        
        # ALWAYS try to parse JSON output, even if not vulnerable
        # (sqlmap might have found something but parser missed it)
        
        # Try to get more detailed results from JSON output
        try:
            # SQLMap stores results in ~/.local/share/sqlmap/output/
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname or "unknown"
            
            # FIXED: Correct output directories
            output_dirs = [
                os.path.expanduser(f"~/.local/share/sqlmap/output/{hostname}"),
                os.path.expanduser(f"~/.sqlmap/output/{hostname}"),
                f"/tmp/sqlmap/output/{hostname}",
            ]
            
            # Also check our results dir
            if self.results_dir:
                output_dirs.append(self.results_dir)
            
            for output_dir in output_dirs:
                if not os.path.exists(output_dir):
                    continue
                    
                # FIXED: Look for all possible SQLMap output files
                for root, dirs, files in os.walk(output_dir):
                    for file in files:
                        if file in ['log', 'output', 'target.json'] or file.endswith('.txt'):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    parsed_artifact_paths.append(file_path)
                                    
                                    # FIXED: Check for vulnerability indicators in raw output
                                    if not basic_result["vulnerable"]:
                                        if any(indicator in content.lower() for indicator in [
                                            'injectable', 'vulnerable', 'parameter.*appears to be'
                                        ]):
                                            basic_result["vulnerable"] = True
                                            logger.info(f"[SQLMAP] Found vulnerability in output file: {file_path}")
                                    
                                    # Try to parse as JSON
                                    if file.endswith('.json'):
                                        try:
                                            json_data = json.loads(content)
                                            if isinstance(json_data, dict):
                                                if json_data.get("vulnerable"):
                                                    basic_result["vulnerable"] = True
                                                    basic_result["findings"].append(json_data)
                                            elif isinstance(json_data, list):
                                                for entry in json_data:
                                                    if entry.get("vulnerable"):
                                                        basic_result["vulnerable"] = True
                                                        basic_result["findings"].append(entry)
                                        except json.JSONDecodeError:
                                            pass
                                    
                                    # Parse line by line for payloads
                                    for line in content.split('\n'):
                                        if 'payload' in line.lower() or 'parameter' in line.lower():
                                            if 'injectable' in line.lower():
                                                basic_result["vulnerable"] = True
                                                basic_result["findings"].append({
                                                    "type": "sql_injection",
                                                    "evidence": line[:500],
                                                    "severity": "CRITICAL"
                                                })
                                                
                            except Exception as e:
                                logger.debug(f"[SQLMAP] Failed to read {file_path}: {e}")
                                continue
                
                # FIXED: Check for session directory (sqlmap stores detailed results here)
                session_dir = os.path.join(output_dir, "session")
                if os.path.exists(session_dir):
                    for file in os.listdir(session_dir):
                        if file.endswith('.txt'):
                            file_path = os.path.join(session_dir, file)
                            try:
                                with open(file_path, 'r') as f:
                                    content = f.read()
                                    parsed_artifact_paths.append(file_path)
                                    if 'injectable' in content.lower():
                                        basic_result["vulnerable"] = True
                                        logger.info(f"[SQLMAP] Found injection evidence in session: {file_path}")
                            except Exception:
                                pass
                                
        except Exception as e:
            logger.debug(f"[SQLMAP] Failed to parse JSON output: {e}")
        
        # FIXED: Log final result for debugging
        if basic_result["vulnerable"]:
            logger.warning(f"[SQLMAP] ✅ SQL Injection CONFIRMED on {url}")
            logger.warning(f"[SQLMAP] Findings: {len(basic_result['findings'])}")
        else:
            # Log a sample of output for debugging
            output_sample = basic_result.get("output", "")[:500]
            if output_sample:
                logger.debug(f"[SQLMAP] Output sample: {output_sample}")

        basic_result["parsed_artifact_paths"] = parsed_artifact_paths
        if basic_result.get("artifact_path"):
            self._write_summary_file(basic_result["artifact_path"], basic_result)
        
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
