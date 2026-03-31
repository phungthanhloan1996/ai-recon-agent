"""
modules/crypto_scanner.py - Cryptographic Security Scanner
Checks for SSL/TLS vulnerabilities, sensitive data exposure, and mixed content issues.
OWASP A04:2021 - Cryptographic Failures
"""

import ssl
import socket
import re
import json
import os
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("recon.crypto_scanner")


class CryptographicScanner:
    """
    Scanner for cryptographic security issues including:
    - SSL/TLS certificate validation
    - Weak cipher suites
    - HSTS configuration
    - Sensitive data exposure in responses
    - Mixed content (HTTP resources on HTTPS pages)
    """
    
    # Patterns for sensitive data detection
    SENSITIVE_DATA_PATTERNS = {
        "password": [
            r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']?([^\s"\']{4,})',
            r'(?i)["\']password["\']\s*:\s*["\']?([^\s"\']{4,})',
            r'(?i)password\s*=\s*["\']([^"\']+)["\']',
        ],
        "api_key": [
            r'(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{16,})',
            r'(?i)["\']api[_-]?key["\']\s*:\s*["\']?([a-zA-Z0-9_\-]{16,})',
            r'(?i)sk_live_[a-zA-Z0-9]{24,}',  # Stripe live key
            r'(?i)sk_test_[a-zA-Z0-9]{24,}',  # Stripe test key
        ],
        "token": [
            r'(?i)(?:access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})',
            r'(?i)["\']token["\']\s*:\s*["\']?([a-zA-Z0-9_\-\.]{20,})',
            r'(?i)eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',  # JWT
        ],
        "credit_card": [
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            r'\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b',
        ],
        "ssn": [
            r'\b[0-9]{3}[\s-]?[0-9]{2}[\s-]?[0-9]{4}\b',
        ],
        "private_key": [
            r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
            r'-----BEGIN OPENSSH PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        ],
        "aws_credentials": [
            r'(?i)AKIA[0-9A-Z]{16}',  # AWS Access Key ID
            r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})',
        ],
        "database_connection": [
            r'(?i)(?:mysql|postgres|mongodb|redis)://[^\s"\'<>]+',
            r'(?i)Server=(.+?);.*Database=(.+?);',
        ],
        "email": [
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        ],
    }
    
    # Weak cipher patterns
    WEAK_CIPHERS = [
        "RC4",
        "DES",
        "3DES",
        "MD5",
        "NULL",
        "EXPORT",
        "anon",
    ]
    
    # Mixed content patterns
    MIXED_CONTENT_PATTERNS = [
        r'<script\s+src=["\']http://',
        r'<link\s+[^>]*href=["\']http://',
        r'<img\s+[^>]*src=["\']http://',
        r'<iframe\s+[^>]*src=["\']http://',
        r'<form\s+[^>]*action=["\']http://',
        r'url\(["\']?http://',
        r'<source\s+[^>]*src=["\']http://',
        r'<video\s+[^>]*src=["\']http://',
        r'<audio\s+[^>]*src=["\']http://',
    ]
    
    def __init__(self, http_client=None, output_dir: str = None):
        """
        Initialize the cryptographic scanner.
        
        Args:
            http_client: HTTPClient instance for making requests
            output_dir: Directory for saving results
        """
        self.http_client = http_client
        self.output_dir = output_dir
        self.findings = []
    
    def check_ssl_tls(self, url: str) -> Dict[str, Any]:
        """
        Check SSL/TLS certificate and configuration.
        
        Args:
            url: Target URL to check
            
        Returns:
            Dictionary containing SSL/TLS analysis results
        """
        result = {
            "url": url,
            "check_type": "ssl_tls",
            "timestamp": datetime.now().isoformat(),
            "findings": [],
            "grade": "A",
            "certificate": {},
            "protocol_support": {},
            "cipher_suites": [],
            "vulnerabilities": []
        }
        
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            
            if not hostname:
                result["findings"].append({
                    "type": "error",
                    "severity": "HIGH",
                    "title": "Invalid URL",
                    "description": f"Could not extract hostname from {url}"
                })
                return result
            
            # Check certificate
            cert_info = self._get_certificate_info(hostname, port)
            if cert_info:
                result["certificate"] = cert_info
                
                # Check for certificate issues
                cert_findings = self._check_certificate_issues(cert_info, hostname)
                result["findings"].extend(cert_findings)
            
            # Check protocol support
            protocol_info = self._check_protocol_support(hostname, port)
            result["protocol_support"] = protocol_info
            
            # Check for weak protocols
            if protocol_info.get("ssl_v2", False):
                result["vulnerabilities"].append("SSLv2 enabled")
                result["findings"].append({
                    "type": "weak_protocol",
                    "severity": "CRITICAL",
                    "title": "SSLv2 Enabled",
                    "description": "Server supports deprecated SSLv2 protocol"
                })
            
            if protocol_info.get("ssl_v3", False):
                result["vulnerabilities"].append("SSLv3 enabled")
                result["findings"].append({
                    "type": "weak_protocol",
                    "severity": "HIGH",
                    "title": "SSLv3 Enabled",
                    "description": "Server supports deprecated SSLv3 protocol (POODLE)"
                })
            
            if protocol_info.get("tls_1_0", False):
                result["findings"].append({
                    "type": "weak_protocol",
                    "severity": "MEDIUM",
                    "title": "TLS 1.0 Enabled",
                    "description": "Server supports deprecated TLS 1.0 protocol"
                })
            
            if protocol_info.get("tls_1_1", False):
                result["findings"].append({
                    "type": "weak_protocol",
                    "severity": "LOW",
                    "title": "TLS 1.1 Enabled",
                    "description": "Server supports deprecated TLS 1.1 protocol"
                })
            
            # Calculate grade
            result["grade"] = self._calculate_ssl_grade(result)
            
            self.findings.append(result)
            logger.info(f"[CRYPTO] SSL/TLS check for {hostname}:{port} - Grade: {result['grade']}")
            
        except Exception as e:
            logger.error(f"[CRYPTO] SSL/TLS check failed for {url}: {e}")
            result["findings"].append({
                "type": "error",
                "severity": "INFO",
                "title": "SSL/TLS Check Failed",
                "description": str(e)
            })
        
        return result
    
    def _get_certificate_info(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return None
                    
                    # Parse certificate
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    
                    # Get validity dates
                    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    
                    # Get SANs
                    sans = []
                    for ext in cert.get("subjectAltName", []):
                        if ext[0] == "DNS":
                            sans.append(ext[1])
                    
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "serial_number": cert.get("serialNumber", ""),
                        "version": cert.get("version"),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "validity_days": (not_after - datetime.now()).days,
                        "sans": sans,
                        "signature_algorithm": cert.get("signatureAlgorithm", ""),
                    }
                    
        except Exception as e:
            logger.debug(f"[CRYPTO] Failed to get certificate info: {e}")
            return None
    
    def _check_certificate_issues(self, cert_info: Dict, hostname: str) -> List[Dict]:
        """Check for certificate-related issues"""
        findings = []
        
        # Check expiration
        validity_days = cert_info.get("validity_days", 0)
        if validity_days < 0:
            findings.append({
                "type": "expired_certificate",
                "severity": "CRITICAL",
                "title": "Expired SSL Certificate",
                "description": f"Certificate expired {abs(validity_days)} days ago"
            })
        elif validity_days < 30:
            findings.append({
                "type": "expiring_certificate",
                "severity": "MEDIUM",
                "title": "Certificate Expiring Soon",
                "description": f"Certificate expires in {validity_days} days"
            })
        elif validity_days < 90:
            findings.append({
                "type": "certificate_renewal",
                "severity": "LOW",
                "title": "Certificate Renewal Recommended",
                "description": f"Certificate expires in {validity_days} days"
            })
        
        # Check if hostname matches certificate
        sans = cert_info.get("sans", [])
        cn = cert_info.get("subject", {}).get("commonName", "")
        
        hostname_matches = hostname in sans or hostname == cn or f"*.{hostname.split('.', 1)[-1]}" in sans
        
        if not hostname_matches:
            findings.append({
                "type": "hostname_mismatch",
                "severity": "HIGH",
                "title": "Hostname Mismatch",
                "description": f"Certificate does not cover hostname {hostname}"
            })
        
        # Check signature algorithm
        sig_algo = cert_info.get("signature_algorithm", "").lower()
        if "md5" in sig_algo or "sha1" in sig_algo:
            findings.append({
                "type": "weak_signature",
                "severity": "MEDIUM",
                "title": "Weak Signature Algorithm",
                "description": f"Certificate uses {sig_algo} which is considered weak"
            })
        
        # Check key size (if available)
        # Note: Getting key size requires more detailed cert parsing
        
        return findings
    
    def _check_protocol_support(self, hostname: str, port: int) -> Dict[str, bool]:
        """Check which SSL/TLS protocols are supported"""
        protocols = {
            "ssl_v2": False,
            "ssl_v3": False,
            "tls_1_0": False,
            "tls_1_1": False,
            "tls_1_2": False,
            "tls_1_3": False,
        }
        
        protocol_map = {
            "tls_1_3": ssl.TLSVersion.TLSv1_3 if hasattr(ssl.TLSVersion, 'TLSv1_3') else None,
            "tls_1_2": ssl.TLSVersion.TLSv1_2,
            "tls_1_1": ssl.TLSVersion.TLSv1_1,
            "tls_1_0": ssl.TLSVersion.TLSv1,
            "ssl_v3": ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, 'SSLv3') else None,
        }
        
        for proto_name, proto_version in protocol_map.items():
            if proto_version is None:
                continue
            
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.maximum_version = proto_version
                context.minimum_version = proto_version
                
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols[proto_name] = True
            except Exception:
                protocols[proto_name] = False
        
        return protocols
    
    def _calculate_ssl_grade(self, result: Dict) -> str:
        """Calculate SSL/TLS security grade (A-F)"""
        grade = "A"
        
        # Check for critical issues
        critical_findings = [f for f in result["findings"] if f.get("severity") == "CRITICAL"]
        high_findings = [f for f in result["findings"] if f.get("severity") == "HIGH"]
        medium_findings = [f for f in result["findings"] if f.get("severity") == "MEDIUM"]
        low_findings = [f for f in result["findings"] if f.get("severity") == "LOW"]
        
        if critical_findings:
            grade = "F"
        elif len(high_findings) >= 2:
            grade = "D"
        elif high_findings:
            grade = "C"
        elif len(medium_findings) >= 2:
            grade = "B"
        elif medium_findings:
            grade = "B"
        elif low_findings:
            grade = "A-"
        
        # Check for TLS 1.3 support (bonus)
        if result["protocol_support"].get("tls_1_3") and grade in ["A", "A-"]:
            grade = "A+"
        
        return grade
    
    def check_sensitive_data(self, response_text: str, url: str = "") -> List[Dict[str, Any]]:
        """
        Scan response body for sensitive data exposure.
        
        Args:
            response_text: Response body content
            url: Optional URL for context
            
        Returns:
            List of findings for detected sensitive data
        """
        findings = []
        
        if not response_text:
            return findings
        
        for data_type, patterns in self.SENSITIVE_DATA_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_text)
                if matches:
                    # Mask sensitive values for safety
                    masked_matches = []
                    for match in matches[:3]:  # Limit to first 3 matches
                        if isinstance(match, tuple):
                            masked = match[0][:4] + "***" if match[0] else ""
                        else:
                            masked = str(match)[:4] + "***"
                        masked_matches.append(masked)
                    
                    severity = self._get_data_severity(data_type)
                    
                    finding = {
                        "type": "sensitive_data_exposure",
                        "data_type": data_type,
                        "severity": severity,
                        "url": url,
                        "title": f"{data_type.replace('_', ' ').title()} Detected",
                        "description": f"Potential {data_type.replace('_', ' ')} exposure detected in response",
                        "evidence": f"Found {len(matches)} occurrence(s): {', '.join(masked_matches)}",
                        "count": len(matches),
                        "timestamp": datetime.now().isoformat()
                    }
                    findings.append(finding)
                    
                    logger.warning(f"[CRYPTO] {data_type} detected in {url or 'response'}: {len(matches)} matches")
        
        return findings
    
    def _get_data_severity(self, data_type: str) -> str:
        """Get severity level for data type"""
        severity_map = {
            "private_key": "CRITICAL",
            "aws_credentials": "CRITICAL",
            "database_connection": "CRITICAL",
            "credit_card": "CRITICAL",
            "ssn": "CRITICAL",
            "password": "HIGH",
            "api_key": "HIGH",
            "token": "HIGH",
            "email": "MEDIUM",
        }
        return severity_map.get(data_type, "MEDIUM")
    
    def check_mixed_content(self, html: str, page_url: str = "") -> List[Dict[str, Any]]:
        """
        Detect HTTP resources served over HTTPS page (mixed content).
        
        Args:
            html: HTML content of the page
            page_url: URL of the page being checked
            
        Returns:
            List of mixed content findings
        """
        findings = []
        
        if not html:
            return findings
        
        # Check if page is loaded over HTTPS
        is_https = page_url.startswith("https://") if page_url else False
        
        if not is_https:
            # Mixed content only applies to HTTPS pages
            return findings
        
        for pattern in self.MIXED_CONTENT_PATTERNS:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                # Extract the resource type from pattern
                resource_type = "resource"
                if "script" in pattern:
                    resource_type = "script"
                elif "link" in pattern:
                    resource_type = "stylesheet"
                elif "img" in pattern:
                    resource_type = "image"
                elif "iframe" in pattern:
                    resource_type = "iframe"
                elif "form" in pattern:
                    resource_type = "form"
                elif "video" in pattern:
                    resource_type = "video"
                elif "audio" in pattern:
                    resource_type = "audio"
                
                severity = "HIGH" if resource_type in ["script", "iframe", "form"] else "MEDIUM"
                
                finding = {
                    "type": "mixed_content",
                    "severity": severity,
                    "url": page_url,
                    "resource_type": resource_type,
                    "title": f"Mixed Content: Insecure {resource_type} on HTTPS Page",
                    "description": f"Page loaded over HTTPS includes {resource_type} resources over HTTP",
                    "evidence": f"Found {len(matches)} insecure {resource_type} reference(s)",
                    "count": len(matches),
                    "timestamp": datetime.now().isoformat()
                }
                findings.append(finding)
                
                logger.warning(f"[CRYPTO] Mixed content ({resource_type}) detected on {page_url}: {len(matches)} instances")
        
        return findings
    
    def check_hsts(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """
        Check for HSTS (HTTP Strict Transport Security) header.
        
        Args:
            headers: Response headers dictionary
            
        Returns:
            List of HSTS-related findings
        """
        findings = []
        
        if not headers:
            return findings
        
        # Find HSTS header (case-insensitive)
        hsts_value = None
        for key, value in headers.items():
            if key.lower() == "strict-transport-security":
                hsts_value = value
                break
        
        if not hsts_value:
            findings.append({
                "type": "missing_hsts",
                "severity": "MEDIUM",
                "title": "Missing HSTS Header",
                "description": "Server does not send Strict-Transport-Security header",
                "recommendation": "Add HSTS header with max-age of at least 31536000 seconds (1 year)"
            })
        else:
            # Parse HSTS value
            max_age_match = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    findings.append({
                        "type": "weak_hsts",
                        "severity": "LOW",
                        "title": "Short HSTS Max-Age",
                        "description": f"HSTS max-age is {max_age} seconds ({max_age // 86400} days), recommended: 31536000 (365 days)",
                        "recommendation": "Increase HSTS max-age to at least 31536000 seconds"
                    })
            
            if "includesubdomains" not in hsts_value.lower():
                findings.append({
                    "type": "hsts_no_subdomains",
                    "severity": "LOW",
                    "title": "HSTS Not Applied to Subdomains",
                    "description": "HSTS header does not include 'includeSubDomains' directive",
                    "recommendation": "Add 'includeSubDomains' to HSTS header"
                })
            
            if "preload" not in hsts_value.lower():
                findings.append({
                    "type": "hsts_no_preload",
                    "severity": "INFO",
                    "title": "HSTS Preload Not Enabled",
                    "description": "HSTS header does not include 'preload' directive",
                    "recommendation": "Consider adding 'preload' and submitting to HSTS preload list"
                })
        
        return findings
    
    def scan(self, url: str, response_text: str = "", headers: Dict = None, html: str = "") -> Dict[str, Any]:
        """
        Run comprehensive cryptographic security scan.
        
        Args:
            url: Target URL
            response_text: Optional response body for sensitive data scanning
            headers: Optional response headers for HSTS check
            html: Optional HTML content for mixed content check
            
        Returns:
            Comprehensive scan results
        """
        results = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "ssl_tls": None,
            "sensitive_data": [],
            "mixed_content": [],
            "hsts": [],
            "summary": {
                "total_findings": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "grade": "N/A"
            }
        }
        
        # SSL/TLS check
        if url.startswith("https://"):
            results["ssl_tls"] = self.check_ssl_tls(url)
            if results["ssl_tls"]:
                results["summary"]["grade"] = results["ssl_tls"].get("grade", "N/A")
        
        # Sensitive data check
        if response_text:
            results["sensitive_data"] = self.check_sensitive_data(response_text, url)
        
        # Mixed content check
        if html and url.startswith("https://"):
            results["mixed_content"] = self.check_mixed_content(html, url)
        
        # HSTS check
        if headers:
            results["hsts"] = self.check_hsts(headers)
        
        # Aggregate findings
        all_findings = []
        if results["ssl_tls"] and results["ssl_tls"].get("findings"):
            all_findings.extend(results["ssl_tls"]["findings"])
        all_findings.extend(results["sensitive_data"])
        all_findings.extend(results["mixed_content"])
        all_findings.extend(results["hsts"])
        
        # Count by severity
        for finding in all_findings:
            severity = finding.get("severity", "INFO").lower()
            results["summary"][severity] = results["summary"].get(severity, 0) + 1
            results["summary"]["total_findings"] += 1
        
        results["all_findings"] = all_findings
        
        return results
    
    def save_results(self, results: Dict, filename: str = None):
        """Save scan results to file"""
        if not self.output_dir:
            return
        
        if not filename:
            filename = f"crypto_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"[CRYPTO] Results saved to {filepath}")
        except Exception as e:
            logger.error(f"[CRYPTO] Failed to save results: {e}")
    
    def get_findings(self) -> List[Dict]:
        """Get all findings from scans"""
        return self.findings