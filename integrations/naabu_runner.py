"""
integrations/naabu_runner.py - Fast Port Scanning with Naabu
Efficient port discovery using Naabu (Go-based, faster than Nmap)
"""

import subprocess
import json
import logging
import re
from typing import Dict, List, Any, Optional
from pathlib import Path

logger = logging.getLogger("recon.naabu")


class NaabuRunner:
    """Run naabu for fast port discovery - AGGRESSIVELY OPTIMIZED"""

    def __init__(self, output_dir: str, fast: bool = True):
        self.output_dir = output_dir
        self.fast = fast
        # AGGRESSIVE OPTIMIZATION: Only essential web ports
        self.web_ports = [80, 443, 8080, 8443]
        # Minimal common ports for quick scanning
        self.common_ports = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080, 8443]
        # Maximum ports to scan (limit to avoid timeouts)
        self.max_ports = 13

    def run(self, target: str, timeout: int = 120, max_retries: int = 2) -> Dict[str, Any]:
        """Run naabu on target host"""
        result = {
            "target": target,
            "success": False,
            "ports": [],
            "services": {},
            "raw_output": "",
            "error": None
        }

        for attempt in range(max_retries):
            try:
                output = self._execute_naabu(target, timeout)
                if output:
                    result["success"] = True
                    result["raw_output"] = output
                    self._parse_output(output, result)
                    return result
            except subprocess.TimeoutExpired:
                result["error"] = f"Timeout on attempt {attempt+1}/{max_retries}"
                logger.warning(f"Naabu timeout for {target}: {result['error']}")
            except Exception as e:
                result["error"] = str(e)
                logger.warning(f"Naabu error for {target} (attempt {attempt+1}): {e}")

        return result

    def _execute_naabu(self, target: str, timeout: int) -> str:
        """Execute naabu command - AGGRESSIVELY OPTIMIZED"""
        try:
            if self.fast:
                # AGGRESSIVE OPTIMIZATION: Only top 100 ports (was 1000)
                cmd = [
                    "naabu",
                    "-host", target,
                    "-top-ports", "100",
                    "-rate", "3000",  # Reduced rate for stability
                    "-json",
                    "-verbose",
                    "-timeout", "3",  # Fast per-port timeout
                    "-retries", "1"   # Only 1 retry
                ]
            else:
                # Full scan (slower)
                cmd = [
                    "naabu",
                    "-host", target,
                    "-p", "-",  # All ports
                    "-rate", "1000",
                    "-json",
                    "-verbose",
                    "-timeout", "3",
                    "-retries", "1"
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
            logger.error(f"Failed to execute naabu: {e}")
            raise

    def _parse_output(self, output: str, result: Dict[str, Any]):
        """Parse naabu JSON output"""
        try:
            for line in output.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if "port" in entry:
                        port = entry["port"]
                        result["ports"].append(port)
                        
                        # Try to identify service
                        service_info = {
                            "port": port,
                            "protocol": entry.get("protocol", "tcp"),
                            "service": self._identify_service(port)
                        }
                        result["services"][port] = service_info
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            logger.debug(f"Error parsing naabu output: {e}")
            # Fallback to text parsing
            self._parse_text_output(output, result)

    def _parse_text_output(self, output: str, result: Dict[str, Any]):
        """Fallback text parsing"""
        # Match port patterns like "target:port" or "port/tcp"
        port_pattern = r"(?:^|\s)(\d+)(?:/tcp|/udp)?(?:\s|$)"
        
        for line in output.split("\n"):
            matches = re.findall(port_pattern, line)
            for match in matches:
                try:
                    port = int(match)
                    if port not in result["ports"]:
                        result["ports"].append(port)
                        result["services"][port] = {
                            "port": port,
                            "protocol": "tcp",
                            "service": self._identify_service(port)
                        }
                except ValueError:
                    continue

    def _identify_service(self, port: int) -> str:
        """Identify common services by port"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            5000: "HTTP-Alt",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8000: "HTTP-Alt",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            8888: "HTTP-Alt",
            9000: "HTTP-Alt",
            9443: "HTTPS-Alt",
            27017: "MongoDB",
            27018: "MongoDB-Alt",
            27019: "MongoDB-Alt",
        }
        return services.get(port, f"Unknown-{port}")

    def run_batch(self, targets: List[str], timeout: int = 120) -> List[Dict[str, Any]]:
        """Run naabu on multiple targets"""
        results = []
        for target in targets:
            results.append(self.run(target, timeout))
        return results
