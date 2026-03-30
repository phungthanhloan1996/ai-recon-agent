"""
reports/dashboard_enhanced.py - Enhanced Dashboard Display
"""
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger("dashboard")


@dataclass
class DashboardMetrics:
    """Dashboard metrics"""
    total_endpoints: int = 0
    vulnerabilities_found: int = 0
    critical_issues: int = 0
    high_issues: int = 0
    medium_issues: int = 0
    low_issues: int = 0
    exploits_attempted: int = 0
    exploits_successful: int = 0
    scan_duration: float = 0.0


class EnhancedDashboard:
    """Enhanced dashboard for displaying scan results"""
    
    def __init__(self, title: str = "AI Recon Agent Dashboard"):
        self.title = title
        self.metrics = DashboardMetrics()
        self.findings = []
        self.alerts = []
    
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to dashboard"""
        self.findings.append({
            'timestamp': datetime.now().isoformat(),
            'finding': finding
        })
    
    def add_alert(self, alert: str, severity: str = 'info') -> None:
        """Add an alert"""
        self.alerts.append({
            'timestamp': datetime.now().isoformat(),
            'alert': alert,
            'severity': severity
        })
    
    def update_metrics(self, metrics: DashboardMetrics) -> None:
        """Update dashboard metrics"""
        self.metrics = metrics
    
    def render(self) -> str:
        """Render dashboard as string"""
        output = []
        output.append("\n" + "="*80)
        output.append(f"  {self.title}")
        output.append("="*80)
        
        # Metrics section
        output.append("\n[METRICS]")
        output.append(f"  Total Endpoints: {self.metrics.total_endpoints}")
        output.append(f"  Vulnerabilities: {self.metrics.vulnerabilities_found}")
        output.append(f"    - Critical: {self.metrics.critical_issues}")
        output.append(f"    - High: {self.metrics.high_issues}")
        output.append(f"    - Medium: {self.metrics.medium_issues}")
        output.append(f"    - Low: {self.metrics.low_issues}")
        output.append(f"  Exploits Successful: {self.metrics.exploits_successful}/{self.metrics.exploits_attempted}")
        output.append(f"  Scan Duration: {self.metrics.scan_duration:.2f}s")
        
        # Findings section
        if self.findings:
            output.append("\n[FINDINGS]")
            for finding in self.findings[-10:]:  # Last 10
                output.append(f"  - {finding['finding'].get('type', 'Unknown')}: {finding['finding'].get('description', '')}")
        
        # Alerts section
        if self.alerts:
            output.append("\n[ALERTS]")
            for alert in self.alerts[-5:]:  # Last 5
                output.append(f"  [{alert['severity'].upper()}] {alert['alert']}")
        
        output.append("\n" + "="*80 + "\n")
        return "\n".join(output)
    
    def display(self) -> None:
        """Display dashboard in console"""
        print(self.render())


def format_state_for_display(state: Dict[str, Any]) -> str:
    """Format state for display"""
    output = []
    output.append("\n[APPLICATION STATE]")
    
    for key, value in state.items():
        if isinstance(value, (dict, list)):
            output.append(f"  {key}: {len(value)} items")
        else:
            output.append(f"  {key}: {value}")
    
    return "\n".join(output)
