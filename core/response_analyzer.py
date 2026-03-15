"""
core/response_analyzer.py - HTTP Response Analyzer
Phân tích response để xác định exploit success
"""

import re
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("recon.response_analyzer")


# Signatures for detecting successful exploits
SIGNATURES = {
    "sql_injection": {
        "success": [
            r"you have an error in your sql syntax",
            r"warning.*mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"syntax error.*near",
            r"pg_query\(\): query failed",
            r"supplied argument is not a valid postgresql",
            r"ora-\d{5}",  # Oracle errors
            r"microsoft.*odbc.*driver",
            r"mysql_fetch_array\(\)",
            r"sqlite_step\(\)",
            r"division by zero",
            r"sql syntax.*near",
        ],
        "data_leak": [
            r"root:.*:/bin/",
            r"\d+:\d+:\d+:\d+",  # potential data rows
        ]
    },
    "xss": {
        "success": [
            r"<script>alert\(",
            r"<svg.*onload=",
            r"javascript:alert",
            r"onerror=alert",
        ]
    },
    "lfi": {
        "success": [
            r"root:x:0:0",
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"for 16-bit app support",
            r"daemon:x:",
            r"/bin/bash",
            r"etc/passwd",
        ]
    },
    "rce": {
        "success": [
            r"uid=\d+\(\w+\) gid=\d+",
            r"total \d+\ndrwx",
            r"linux \d+\.\d+",
            r"Microsoft Windows \[Version",
            r"command not found",
        ]
    },
    "upload": {
        "success": [
            r"file uploaded successfully",
            r"upload successful",
            r"file has been uploaded",
            r"successfully uploaded",
        ],
        "webshell": [
            r"uid=",
            r"whoami",
            r"system\(",
            r"shell_exec\(",
        ]
    },
    "auth_bypass": {
        "success": [
            r"welcome.*admin",
            r"logged in as",
            r"dashboard",
            r"logout",
        ]
    },
    "xmlrpc": {
        "success": [
            r"<methodResponse>",
            r"<value>",
            r"faultCode",
        ],
        "bruteforce_success": [
            r"isAdmin.*1",
            r"<string>.*</string>",
        ]
    },
    "info_disclosure": {
        "sensitive": [
            r"api[_\s-]?key\s*[=:]\s*['\"]?[\w\-]{16,}",
            r"secret[_\s-]?key\s*[=:]\s*['\"]?[\w\-]{16,}",
            r"password\s*[=:]\s*['\"]?[\w\-@#$%]{6,}",
            r"db_pass(word)?\s*[=:]\s*",
            r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
            r"AWS_SECRET_ACCESS_KEY",
            r"authorization:\s*bearer\s+[\w\-\.]+",
        ]
    }
}

HTTP_STATUS_RISK = {
    200: "OK - Potential success",
    201: "Created - Possible successful upload/creation",
    301: "Redirect - Note destination",
    302: "Redirect - Note destination",
    401: "Unauthorized - Auth required (try bypass)",
    403: "Forbidden - Access control (try bypass)",
    500: "Server Error - Possible injection point",
    502: "Bad Gateway - Backend error",
    503: "Service Unavailable",
}


class ResponseAnalyzer:
    def __init__(self):
        self.findings = []

    def analyze(
        self,
        response_text: str,
        status_code: int,
        url: str,
        exploit_type: str,
        payload: Optional[str] = None
    ) -> Dict:
        """
        Analyze HTTP response for exploit success indicators.
        Returns a result dict with success status and details.
        """
        result = {
            "url": url,
            "exploit_type": exploit_type,
            "payload": payload,
            "status_code": status_code,
            "success": False,
            "confidence": 0.0,
            "indicators": [],
            "severity": "INFO",
            "notes": [],
        }

        text_lower = response_text.lower() if response_text else ""

        # Check exploit-specific signatures
        if exploit_type in SIGNATURES:
            sigs = SIGNATURES[exploit_type]
            for sig_type, patterns in sigs.items():
                for pattern in patterns:
                    if re.search(pattern, text_lower, re.IGNORECASE | re.MULTILINE):
                        result["indicators"].append(f"{sig_type}: {pattern[:50]}")
                        result["success"] = True
                        result["confidence"] = min(1.0, result["confidence"] + 0.3)
                        if sig_type in ("success", "webshell", "bruteforce_success", "data_leak"):
                            result["severity"] = "CRITICAL"

        # Always check for info disclosure
        info_patterns = SIGNATURES.get("info_disclosure", {}).get("sensitive", [])
        for pattern in info_patterns:
            match = re.search(pattern, response_text or "", re.IGNORECASE)
            if match:
                result["indicators"].append(f"sensitive_data: {match.group(0)[:60]}")
                result["success"] = True
                result["confidence"] = max(result["confidence"], 0.7)
                result["severity"] = "HIGH"

        # Status code analysis
        status_note = HTTP_STATUS_RISK.get(status_code, "")
        if status_note:
            result["notes"].append(f"HTTP {status_code}: {status_note}")

        # Size-based heuristics
        if response_text:
            size = len(response_text)
            if size > 100000:
                result["notes"].append(f"Large response ({size} bytes) - possible data dump")
            elif size < 10 and status_code == 200:
                result["notes"].append("Empty 200 response - suspicious")

        # Confidence normalization
        result["confidence"] = round(min(1.0, result["confidence"]), 2)

        if result["success"]:
            logger.warning(
                f"[ANALYZER] ✓ EXPLOIT SUCCESS [{exploit_type}] "
                f"confidence={result['confidence']} url={url}"
            )
            self.findings.append(result)
        else:
            logger.debug(f"[ANALYZER] ✗ No success indicator for {exploit_type} @ {url}")

        return result

    def analyze_shell_response(self, response_text: str) -> Tuple[bool, str]:
        """Check if webshell executed successfully"""
        patterns = SIGNATURES["rce"]["success"]
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE | re.MULTILINE):
                # Extract command output
                lines = response_text.strip().splitlines()
                output = "\n".join(lines[:10])
                return True, output
        return False, ""

    def check_sql_data_exfil(self, response_text: str) -> Optional[str]:
        """Check if SQLi leaked actual data"""
        # Look for tabular data patterns
        patterns = [
            r"(\w+@[\w.]+)",  # emails
            r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",  # phone numbers
            r"admin|administrator|root|superuser",  # admin users
        ]
        found = []
        for pattern in patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            found.extend(matches[:3])
        
        if found:
            return ", ".join(set(found))
        return None

    def get_findings(self) -> List[Dict]:
        return self.findings

    def severity_summary(self) -> Dict:
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            sev = finding.get("severity", "INFO")
            summary[sev] = summary.get(sev, 0) + 1
        return summary