"""
core/structured_logger.py - Structured Logging for Stealthy Scanning
Implements CONSTRAINT 4: [MODULE] [ACTION] [REASONING] logging format.
"""

import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict


@dataclass
class ScanEvent:
    """Structured scan event for logging."""
    module: str  # e.g., "SCANNER", "WAF", "BEHAVIOR", "RESOURCE"
    action: str  # e.g., "TEST_PAYLOAD", "DETECT_BLOCKING", "CLASSIFY_PARAM"
    reasoning: str  # Why this action was taken
    target: Optional[str] = None
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    status: str = "info"  # info, success, warning, error, critical
    result: Optional[Dict[str, Any]] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class StructuredFormatter(logging.Formatter):
    """Custom formatter for [MODULE] [ACTION] [REASONING] format."""

    def format(self, record):
        # Check if this is a structured event
        if hasattr(record, 'event'):
            event: ScanEvent = record.event
            
            # Format: [MODULE] [ACTION] [REASONING] | Target: X | Endpoint: Y | Result: Z
            msg_parts = [
                f"[{event.module}]",
                f"[{event.action}]",
                f"[{event.reasoning}]"
            ]
            
            if event.target:
                msg_parts.append(f"Target: {event.target}")
            if event.endpoint:
                msg_parts.append(f"Endpoint: {event.endpoint[:100]}")
            if event.parameter:
                msg_parts.append(f"Param: {event.parameter}")
            if event.payload:
                msg_parts.append(f"Payload: {event.payload[:50]}")
            
            msg = " | ".join(msg_parts)
            
            if event.result:
                msg += f" | Result: {json.dumps(event.result, default=str)[:200]}"
            
            record.msg = msg
            record.args = ()
        
        # Standard formatting
        levelname = record.levelname
        if levelname == "WARNING":
            levelname = "WARN"
        elif levelname == "CRITICAL":
            levelname = "CRIT"
        
        return f"[{record.created:.0f}] [{levelname:5s}] {record.msg}"


class StealthLogger:
    """
    Logger for stealthy scanning with structured output.
    """

    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.events = []  # Keep event history
    
    def log_event(self, event: ScanEvent):
        """Log a structured event."""
        self.events.append(event)
        
        # Select log level based on status
        level_map = {
            'info': logging.INFO,
            'success': logging.INFO,
            'warning': logging.WARNING,
            'error': logging.ERROR,
            'critical': logging.CRITICAL,
        }
        
        log_level = level_map.get(event.status, logging.INFO)
        
        # Create log record with event attached
        record = self.logger.makeRecord(
            self.logger.name,
            log_level,
            "()", 0,
            event.reasoning,
            (),
            None
        )
        record.event = event
        
        self.logger.handle(record)
    
    def test_payload(
        self,
        endpoint: str,
        parameter: str,
        payload: str,
        vulnerability_type: str,
        reasoning: str
    ):
        """Log payload test."""
        self.log_event(ScanEvent(
            module="SCANNER",
            action="TEST_PAYLOAD",
            reasoning=reasoning,
            endpoint=endpoint,
            parameter=parameter,
            payload=payload,
            result={'vulnerability_type': vulnerability_type}
        ))
    
    def detect_waf_blocking(
        self,
        endpoint: str,
        status_code: int,
        waf_type: str,
        reasoning: str
    ):
        """Log WAF blocking detection."""
        self.log_event(ScanEvent(
            module="WAF",
            action="DETECT_BLOCKING",
            reasoning=reasoning,
            endpoint=endpoint,
            status="warning",
            result={'status_code': status_code, 'waf_type': waf_type}
        ))
    
    def apply_waf_bypass(
        self,
        endpoint: str,
        bypass_mode: str,
        original_payload: str,
        mutated_payload: str,
        reasoning: str
    ):
        """Log WAF bypass attempt."""
        self.log_event(ScanEvent(
            module="WAF-BYPASS",
            action="APPLY_BYPASS",
            reasoning=reasoning,
            endpoint=endpoint,
            payload=mutated_payload,
            result={
                'bypass_mode': bypass_mode,
                'original_length': len(original_payload),
                'mutated_length': len(mutated_payload)
            }
        ))
    
    def classify_parameter(
        self,
        parameter: str,
        param_type: str,
        recommended_vulns: list,
        reasoning: str
    ):
        """Log parameter classification."""
        self.log_event(ScanEvent(
            module="BEHAVIOR",
            action="CLASSIFY_PARAMETER",
            reasoning=reasoning,
            parameter=parameter,
            result={
                'param_type': param_type,
                'recommended_vulns': recommended_vulns
            }
        ))
    
    def resource_alert(
        self,
        metric: str,
        current_value: float,
        threshold: float,
        reasoning: str
    ):
        """Log resource constraint."""
        status = "warning" if current_value > threshold * 0.9 else "info"
        self.log_event(ScanEvent(
            module="RESOURCE",
            action="MONITOR",
            reasoning=reasoning,
            status=status,
            result={
                'metric': metric,
                'current': current_value,
                'threshold': threshold
            }
        ))
    
    def vulnerability_found(
        self,
        endpoint: str,
        vulnerability_type: str,
        confidence: float,
        payload: str,
        reasoning: str
    ):
        """Log vulnerability discovery."""
        status = "critical" if confidence >= 0.9 else "warning"
        self.log_event(ScanEvent(
            module="VULN",
            action="FOUND",
            reasoning=reasoning,
            endpoint=endpoint,
            payload=payload,
            status=status,
            result={
                'type': vulnerability_type,
                'confidence': confidence
            }
        ))
    
    def get_event_summary(self) -> Dict[str, Any]:
        """Get summary of logged events."""
        summary = {
            'total_events': len(self.events),
            'by_module': {},
            'by_action': {},
            'by_status': {},
        }
        
        for event in self.events:
            # Count by module
            if event.module not in summary['by_module']:
                summary['by_module'][event.module] = 0
            summary['by_module'][event.module] += 1
            
            # Count by action
            if event.action not in summary['by_action']:
                summary['by_action'][event.action] = 0
            summary['by_action'][event.action] += 1
            
            # Count by status
            if event.status not in summary['by_status']:
                summary['by_status'][event.status] = 0
            summary['by_status'][event.status] += 1
        
        return summary
    
    def export_events_json(self) -> str:
        """Export all events as JSON."""
        return json.dumps([asdict(event) for event in self.events], indent=2, default=str)


def setup_structured_logging(log_file: Optional[str] = None):
    """
    Setup structured logging for the entire recon pipeline.
    
    Sets up console and file handlers with custom formatter.
    """
    # Get root logger
    root_logger = logging.getLogger("recon")
    root_logger.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(StructuredFormatter())
    root_logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(StructuredFormatter())
        root_logger.addHandler(file_handler)
    
    return root_logger
