"""
integrations/burp_api.py - Burp Suite Professional API Integration

Provides integration with Burp Suite Professional via REST API for:
- Automated scanning with Burp Scanner
- Project management and control
- Issue retrieval and analysis
- Report generation
"""

import json
import time
import logging
import hashlib
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Status of Burp scans"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    FAILED = "failed"


class IssueSeverity(Enum):
    """Burp issue severity levels"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATION = "Information"


class IssueConfidence(Enum):
    """Burp issue confidence levels"""
    CERTAIN = "Certain"
    FIRM = "Firm"
    TENTATIVE = "Tentative"


@dataclass
class BurpIssue:
    """Represents a Burp Suite security issue"""
    issue_id: str
    issue_type: str
    issue_name: str
    severity: IssueSeverity
    confidence: IssueConfidence
    url: str
    method: str = "GET"
    parameter: Optional[str] = None
    evidence: Optional[str] = None
    background: Optional[str] = None
    remediation: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    host: str = ""
    port: int = 0
    protocol: str = "https"
    discovered_at: float = field(default_factory=time.time)


@dataclass
class BurpScan:
    """Represents a Burp Suite scan"""
    scan_id: str
    url: str
    status: ScanStatus = ScanStatus.QUEUED
    progress: int = 0
    issues_found: int = 0
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    errors: List[str] = field(default_factory=list)


class BurpAPI:
    """
    Integration with Burp Suite Professional via REST API.
    
    Features:
    - Start and manage scans
    - Retrieve scan results and issues
    - Manage Burp projects
    - Generate reports
    - Control proxy and scanner
    """
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 1337,
        api_key: str = "",
        ssl: bool = False,
        timeout: int = 30,
    ):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.timeout = timeout
        self.ssl = ssl
        
        # Session
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        })
        
        # Active scans
        self.active_scans: Dict[str, BurpScan] = {}
        self.issues: Dict[str, BurpIssue] = {}
        
        # Statistics
        self.stats = {
            'scans_started': 0,
            'scans_completed': 0,
            'scans_failed': 0,
            'issues_found': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'info_severity': 0,
        }
        
        # Connection state
        self.connected = False
    
    @property
    def base_url(self) -> str:
        """Get base URL for API"""
        protocol = "https" if self.ssl else "http"
        return f"{protocol}://{self.host}:{self.port}/v0.1"
    
    def test_connection(self) -> bool:
        """Test connection to Burp Suite"""
        try:
            response = self.session.get(f"{self.base_url}/version", timeout=self.timeout)
            if response.status_code == 200:
                self.connected = True
                logger.info(f"Connected to Burp Suite at {self.base_url}")
                return True
            else:
                logger.error(f"Failed to connect to Burp Suite: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Failed to connect to Burp Suite: {e}")
            return False
    
    # Project Management
    def create_project(self, project_name: str, project_folder: str = None) -> Dict:
        """Create a new Burp project"""
        data = {
            'project_name': project_name,
        }
        if project_folder:
            data['project_folder'] = project_folder
        
        response = self.session.post(f"{self.base_url}/project", json=data)
        return response.json()
    
    def open_project(self, project_path: str) -> Dict:
        """Open an existing Burp project"""
        data = {'project_path': project_path}
        response = self.session.post(f"{self.base_url}/project/open", json=data)
        return response.json()
    
    def close_project(self) -> Dict:
        """Close current Burp project"""
        response = self.session.delete(f"{self.base_url}/project")
        return response.json()
    
    # Scanning
    def start_scan(
        self,
        url: str,
        scan_configuration: Dict = None,
        scan_name: str = None,
    ) -> BurpScan:
        """
        Start a new scan.
        
        Args:
            url: Target URL to scan
            scan_configuration: Scan configuration options
            scan_name: Optional name for the scan
            
        Returns:
            BurpScan object
        """
        scan_id = hashlib.md5(f"{url}:{time.time()}".encode()).hexdigest()[:12]
        
        scan = BurpScan(
            scan_id=scan_id,
            url=url,
        )
        
        self.active_scans[scan_id] = scan
        self.stats['scans_started'] += 1
        
        try:
            data = {
                'url': url,
                'name': scan_name or f"Scan-{scan_id}",
            }
            
            if scan_configuration:
                data['configuration'] = scan_configuration
            
            response = self.session.post(
                f"{self.base_url}/scan",
                json=data,
                timeout=self.timeout,
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                scan.scan_id = result.get('scan_id', scan_id)
                scan.status = ScanStatus.RUNNING
                scan.started_at = time.time()
                
                # Re-register with actual scan ID
                if scan.scan_id != scan_id:
                    del self.active_scans[scan_id]
                    self.active_scans[scan.scan_id] = scan
                
                logger.info(f"Started Burp scan: {scan.scan_id} for {url}")
            else:
                scan.status = ScanStatus.FAILED
                scan.errors.append(f"HTTP {response.status_code}: {response.text}")
                self.stats['scans_failed'] += 1
                logger.error(f"Failed to start Burp scan: {response.text}")
                
        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.errors.append(str(e))
            self.stats['scans_failed'] += 1
            logger.error(f"Exception starting Burp scan: {e}")
        
        return scan
    
    def get_scan_status(self, scan_id: str) -> Dict:
        """Get status of a scan"""
        response = self.session.get(f"{self.base_url}/scan/{scan_id}")
        return response.json()
    
    def check_scan_status(self, scan_id: str) -> ScanStatus:
        """Check and update scan status"""
        if scan_id not in self.active_scans:
            return ScanStatus.FAILED
        
        try:
            status_data = self.get_scan_status(scan_id)
            scan = self.active_scans[scan_id]
            
            status_str = status_data.get('status', '').lower()
            if 'complete' in status_str:
                scan.status = ScanStatus.COMPLETE
                scan.completed_at = time.time()
                scan.progress = 100
                self.stats['scans_completed'] += 1
            elif 'running' in status_str or 'active' in status_str:
                scan.status = ScanStatus.RUNNING
                scan.progress = status_data.get('progress', 0)
            elif 'cancelled' in status_str:
                scan.status = ScanStatus.CANCELLED
            elif 'failed' in status_str or 'error' in status_str:
                scan.status = ScanStatus.FAILED
                self.stats['scans_failed'] += 1
            
            return scan.status
            
        except Exception as e:
            logger.error(f"Error checking scan status: {e}")
            return ScanStatus.FAILED
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        try:
            response = self.session.delete(f"{self.base_url}/scan/{scan_id}")
            return response.status_code in [200, 204]
        except Exception as e:
            logger.error(f"Error cancelling scan: {e}")
            return False
    
    # Issues
    def get_scan_issues(self, scan_id: str) -> List[BurpIssue]:
        """Get issues found by a scan"""
        try:
            response = self.session.get(f"{self.base_url}/scan/{scan_id}/results")
            if response.status_code != 200:
                return []
            
            issues_data = response.json().get('issues', [])
            issues = []
            
            for issue_data in issues_data:
                issue = self._parse_issue(issue_data)
                issues.append(issue)
                self.issues[issue.issue_id] = issue
                
                # Update stats
                self.stats['issues_found'] += 1
                severity = issue.severity.value.lower()
                if severity == 'high':
                    self.stats['high_severity'] += 1
                elif severity == 'medium':
                    self.stats['medium_severity'] += 1
                elif severity == 'low':
                    self.stats['low_severity'] += 1
                else:
                    self.stats['info_severity'] += 1
            
            if scan_id in self.active_scans:
                self.active_scans[scan_id].issues_found = len(issues)
            
            return issues
            
        except Exception as e:
            logger.error(f"Error getting scan issues: {e}")
            return []
    
    def _parse_issue(self, issue_data: Dict) -> BurpIssue:
        """Parse issue data into BurpIssue object"""
        issue_id = issue_data.get('issue_id', hashlib.md5(str(issue_data).encode()).hexdigest()[:12])
        
        severity_str = issue_data.get('severity', 'Information')
        try:
            severity = IssueSeverity(severity_str)
        except ValueError:
            severity = IssueSeverity.INFORMATION
        
        confidence_str = issue_data.get('confidence', 'Tentative')
        try:
            confidence = IssueConfidence(confidence_str)
        except ValueError:
            confidence = IssueConfidence.TENTATIVE
        
        return BurpIssue(
            issue_id=issue_id,
            issue_type=issue_data.get('issue_type', 'Unknown'),
            issue_name=issue_data.get('issue_name', 'Unknown Issue'),
            severity=severity,
            confidence=confidence,
            url=issue_data.get('url', ''),
            method=issue_data.get('method', 'GET'),
            parameter=issue_data.get('parameter'),
            evidence=issue_data.get('evidence'),
            background=issue_data.get('background'),
            remediation=issue_data.get('remediation'),
            request=issue_data.get('request'),
            response=issue_data.get('response'),
            host=issue_data.get('host', ''),
            port=issue_data.get('port', 0),
            protocol=issue_data.get('protocol', 'https'),
        )
    
    def get_all_issues(self) -> List[BurpIssue]:
        """Get all issues from all scans"""
        return list(self.issues.values())
    
    def get_issues_by_severity(self, severity: IssueSeverity) -> List[BurpIssue]:
        """Get issues filtered by severity"""
        return [i for i in self.issues.values() if i.severity == severity]
    
    # Reports
    def generate_report(
        self,
        scan_ids: List[str] = None,
        report_type: str = "html",
        report_path: str = None,
    ) -> Optional[str]:
        """
        Generate a report for scans.
        
        Args:
            scan_ids: List of scan IDs to include (None for all)
            report_type: Report format (html, xml, json)
            report_path: Path to save report (if None, returns content)
            
        Returns:
            Report content or path if saved
        """
        try:
            data = {
                'scan_ids': scan_ids or list(self.active_scans.keys()),
                'report_type': report_type,
            }
            
            if report_path:
                data['file_path'] = report_path
            
            response = self.session.post(
                f"{self.base_url}/report",
                json=data,
                timeout=60,
            )
            
            if response.status_code == 200:
                if report_path:
                    with open(report_path, 'wb') as f:
                        f.write(response.content)
                    logger.info(f"Report saved to {report_path}")
                    return report_path
                else:
                    return response.text
            else:
                logger.error(f"Failed to generate report: {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return None
    
    # Proxy
    def set_proxy_scope(self, include_patterns: List[str], exclude_patterns: List[str] = None) -> Dict:
        """Set proxy scope"""
        data = {
            'include_patterns': include_patterns,
        }
        if exclude_patterns:
            data['exclude_patterns'] = exclude_patterns
        
        response = self.session.put(f"{self.base_url}/target/scope", json=data)
        return response.json()
    
    def clear_proxy_history(self) -> Dict:
        """Clear proxy history"""
        response = self.session.delete(f"{self.base_url}/proxy/history")
        return response.json()
    
    def get_proxy_history(self, limit: int = 100) -> List[Dict]:
        """Get proxy history"""
        response = self.session.get(f"{self.base_url}/proxy/history", params={'limit': limit})
        return response.json().get('items', [])
    
    # Spider
    def start_spider(
        self,
        url: str,
        max_depth: int = 5,
        max_crawl_time: int = 600,
    ) -> Dict:
        """Start spidering a target"""
        data = {
            'url': url,
            'max_depth': max_depth,
            'max_crawl_time': max_crawl_time,
        }
        
        response = self.session.post(f"{self.base_url}/spider", json=data)
        return response.json()
    
    def get_spider_status(self) -> Dict:
        """Get spider status"""
        response = self.session.get(f"{self.base_url}/spider/status")
        return response.json()
    
    # Utilities
    def send_to_repeater(self, request_data: Dict) -> Dict:
        """Send a request to Repeater"""
        response = self.session.post(f"{self.base_url}/repeater", json=request_data)
        return response.json()
    
    def send_to_intruder(self, request_data: Dict, payload_positions: List[int]) -> Dict:
        """Send a request to Intruder"""
        data = {
            'request': request_data,
            'payload_positions': payload_positions,
        }
        response = self.session.post(f"{self.base_url}/intruder", json=data)
        return response.json()
    
    def get_target_summary(self) -> Dict:
        """Get summary of all targets"""
        response = self.session.get(f"{self.base_url}/target")
        return response.json()
    
    # Statistics
    def get_stats(self) -> Dict:
        """Get statistics"""
        return {
            **self.stats,
            'active_scans': len([s for s in self.active_scans.values() if s.status == ScanStatus.RUNNING]),
            'total_issues': len(self.issues),
        }
    
    def export_results(self, output_path: str):
        """Export results to JSON"""
        data = {
            'scans': [
                {
                    'scan_id': s.scan_id,
                    'url': s.url,
                    'status': s.status.value,
                    'progress': s.progress,
                    'issues_found': s.issues_found,
                    'started_at': s.started_at,
                    'completed_at': s.completed_at,
                    'errors': s.errors,
                }
                for s in self.active_scans.values()
            ],
            'issues': [
                {
                    'issue_id': i.issue_id,
                    'issue_type': i.issue_type,
                    'issue_name': i.issue_name,
                    'severity': i.severity.value,
                    'confidence': i.confidence.value,
                    'url': i.url,
                    'method': i.method,
                    'parameter': i.parameter,
                    'evidence': i.evidence,
                    'host': i.host,
                    'port': i.port,
                }
                for i in self.issues.values()
            ],
            'stats': self.get_stats(),
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        logger.info(f"Exported Burp results to {output_path}")


class BurpScanner:
    """
    High-level scanner using Burp API.
    
    Provides simplified interface for automated scanning with Burp Suite.
    """
    
    def __init__(self, api: BurpAPI):
        self.api = api
    
    def scan_url(
        self,
        url: str,
        wait_for_completion: bool = True,
        poll_interval: float = 5.0,
        timeout: float = 3600.0,
    ) -> List[BurpIssue]:
        """
        Scan a URL and optionally wait for results.
        
        Args:
            url: Target URL
            wait_for_completion: Wait for scan to complete
            poll_interval: How often to check status
            timeout: Maximum wait time
            
        Returns:
            List of BurpIssue objects
        """
        # Start scan
        scan = self.api.start_scan(url)
        
        if not wait_for_completion:
            return []
        
        # Wait for completion
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.api.check_scan_status(scan.scan_id)
            
            if status == ScanStatus.COMPLETE:
                break
            elif status in [ScanStatus.FAILED, ScanStatus.CANCELLED]:
                logger.warning(f"Scan {scan.scan_id} ended with status {status.value}")
                break
            
            time.sleep(poll_interval)
        
        # Get issues
        return self.api.get_scan_issues(scan.scan_id)
    
    def scan_multiple(
        self,
        urls: List[str],
        parallel: bool = False,
        wait_for_all: bool = True,
    ) -> Dict[str, List[BurpIssue]]:
        """
        Scan multiple URLs.
        
        Args:
            urls: List of URLs to scan
            parallel: Start all scans in parallel
            wait_for_all: Wait for all scans to complete
            
        Returns:
            Dict mapping URLs to their issues
        """
        results = {}
        scans = []
        
        if parallel:
            # Start all scans
            for url in urls:
                scan = self.api.start_scan(url)
                scans.append((url, scan))
        else:
            # Sequential scanning
            for url in urls:
                scan = self.api.start_scan(url)
                scans.append((url, scan))
                
                if wait_for_all:
                    # Wait for this scan before starting next
                    start_time = time.time()
                    while time.time() - start_time < 3600:
                        status = self.api.check_scan_status(scan.scan_id)
                        if status in [ScanStatus.COMPLETE, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                            break
                        time.sleep(5)
        
        # Wait for all if parallel
        if parallel and wait_for_all:
            for url, scan in scans:
                start_time = time.time()
                while time.time() - start_time < 3600:
                    status = self.api.check_scan_status(scan.scan_id)
                    if status in [ScanStatus.COMPLETE, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                        break
                    time.sleep(5)
        
        # Collect results
        for url, scan in scans:
            results[url] = self.api.get_scan_issues(scan.scan_id)
        
        return results


# Convenience function
def connect_burp(
    host: str = "127.0.0.1",
    port: int = 1337,
    api_key: str = "",
) -> Optional[BurpAPI]:
    """
    Connect to Burp Suite.
    
    Returns:
        BurpAPI instance or None if connection failed
    """
    api = BurpAPI(host=host, port=port, api_key=api_key)
    if api.test_connection():
        return api
    return None