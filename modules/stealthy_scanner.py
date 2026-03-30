"""
modules/stealthy_scanner.py - Integrated Stealthy & High-Efficiency Vulnerability Scanner
Implements all 4 constraints in a unified scanning pipeline.

PIPELINE:
1. BEHAVIORAL ANALYSIS: Match payloads to parameter types
2. WAF BYPASS: Polymorphic payloads when 403/406 detected
3. RESOURCE CONSERVATION: Limit to 50 concurrent tasks, handle timeouts
4. STRUCTURED LOGGING: [MODULE] [ACTION] [REASONING] format
"""

import logging
import random
import time
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
import json

from core.behavioral_analyzer import (
    BehavioralAnalyzer,
    ParameterType,
    VulnerabilityType
)
from core.waf_bypass_engine import (
    WAFBypassEngine,
    BypassMode,
    WAFType
)
from core.resource_manager import (
    ResourceManager,
    ConcurrencyController
)
from core.structured_logger import StealthLogger, ScanEvent
from core.http_engine import HTTPClient
from core.response_analyzer import VulnerabilityScorer
from ai.payload_gen import PayloadGenerator

logger = logging.getLogger("recon.stealthy_scanner")
stealth_logger = StealthLogger("recon.stealthy_scanner")


@dataclass
class ScanResult:
    """Result of scanning a single endpoint."""
    endpoint: str
    vulnerable: bool = False
    vulnerabilities: List[Dict] = None  # List of found vulns
    payloads_tested: int = 0
    waf_detected: Optional[str] = None
    bypass_modes_tried: List[str] = None
    duration_seconds: float = 0.0
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.bypass_modes_tried is None:
            self.bypass_modes_tried = []


class StealthyScanner:
    """
    Unified stealthy scanning pipeline with all constraints implemented.
    
    CONSTRAINT 1: BEHAVIORAL ANALYSIS
    - Analyze each parameter before testing
    - Only test relevant vulnerability types
    - Match payload type to parameter logic
    
    CONSTRAINT 2: WAF BYPASS STRATEGY
    - Detect 403/406 responses
    - Apply polymorphic payloads
    - Rotate encoding techniques
    - Add evasion headers
    
    CONSTRAINT 3: RESOURCE CONSERVATION
    - Max 50 concurrent tasks
    - Handle timeouts → increase delay, reduce concurrency
    - Monitor memory/CPU
    
    CONSTRAINT 4: STRUCTURED LOGGING
    - [MODULE] [ACTION] [REASONING] format
    - Detailed reasoning for each decision
    """

    def __init__(
        self,
        http_client: HTTPClient = None,
        max_payloads_per_param: int = 10,
        timeout_seconds: int = 30
    ):
        # Core components
        self.http_client = http_client or HTTPClient()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.waf_bypass_engine = WAFBypassEngine()
        self.resource_manager = ResourceManager(max_concurrent_tasks=50)
        self.concurrency_controller = ConcurrencyController(self.resource_manager)
        self.payload_generator = PayloadGenerator()
        self.vulnerability_scorer = VulnerabilityScorer()
        
        # Configuration
        self.max_payloads_per_param = max_payloads_per_param
        self.timeout_seconds = timeout_seconds
        
        # Statistics
        self.scan_stats = {
            'endpoints_scanned': 0,
            'vulnerabilities_found': 0,
            'payloads_tested': 0,
            'waf_blocks_detected': 0,
            'waf_bypasses_successful': 0,
            'timeouts': 0,
        }

    # ─── Unified Scanning Pipeline ────────────────────────────────────────────

    def scan_endpoint(
        self,
        endpoint_url: str,
        parameters: Dict[str, str],
        target: str = "unknown"
    ) -> ScanResult:
        """
        Comprehensive stealthy scan of a single endpoint.
        
        Pipeline:
        1. Analyze parameters and classify
        2. Generate targeted payloads
        3. Test with WAF bypass on blocked
        4. Score and report findings
        """
        start_time = time.time()
        result = ScanResult(endpoint=endpoint_url)
        
        stealth_logger.log_event(ScanEvent(
            module="SCANNER",
            action="START_ENDPOINT_SCAN",
            reasoning="Beginning comprehensive endpoint analysis",
            target=target,
            endpoint=endpoint_url,
        ))
        
        try:
            # STEP 1: BEHAVIORAL ANALYSIS - Classify parameters
            analysis = self.behavioral_analyzer.analyze_endpoint(
                endpoint_url,
                parameters
            )
            
            stealth_logger.log_event(ScanEvent(
                module="BEHAVIOR",
                action="ENDPOINT_ANALYSIS",
                reasoning=f"Classified {len(analysis['parameter_analysis'])} parameters, "
                         f"{analysis['total_recommended_payloads']} total payloads recommended",
                endpoint=endpoint_url,
                result=analysis
            ))
            
            # STEP 2: Test each parameter with targeted payloads
            for param_analysis in analysis['parameter_analysis']:
                param_name = param_analysis['name']
                param_type = param_analysis['type']
                
                stealth_logger.classify_parameter(
                    parameter=param_name,
                    param_type=param_type,
                    recommended_vulns=param_analysis['recommended_vulns'],
                    reasoning=f"Parameter '{param_name}' will be tested for "
                             f"{', '.join(v[0] for v in param_analysis['recommended_vulns'][:2])}"
                )
                
                # Test each recommended vulnerability type
                for vuln_type, priority in param_analysis['recommended_vulns']:
                    # Skip low-priority vulns if we're resource-constrained
                    if priority < 0.3 and self.resource_manager.last_metrics and \
                       self.resource_manager.last_metrics.is_high():
                        logger.debug(f"[SCANNER] Skipping low-priority {vuln_type} due to resource constraints")
                        continue
                    
                    # Get payload budget for this vuln type
                    payload_count = param_analysis['payload_budget'].get(vuln_type, 0)
                    if payload_count == 0:
                        continue
                    
                    # Generate payloads
                    payloads = self.payload_generator.generate_for_category(
                        vuln_type,
                        parameters=[param_name],
                        include_ai=True
                    )[:payload_count]
                    
                    # Test payloads
                    for payload in payloads:
                        vuln = self._test_payload_with_bypass(
                            endpoint_url,
                            param_name,
                            payload,
                            vuln_type,
                            target=target
                        )
                        
                        if vuln:
                            result.vulnerabilities.append(vuln)
                            self.behavioral_analyzer.record_effectiveness(
                                param_name, vuln_type, True
                            )
                            self.scan_stats['vulnerabilities_found'] += 1
                            stealth_logger.vulnerability_found(
                                endpoint=endpoint_url,
                                vulnerability_type=vuln_type,
                                confidence=vuln.get('confidence', 0),
                                payload=payload[:50],
                                reasoning=f"Vulnerability confirmed with confidence {vuln.get('confidence', 0):.2f}"
                            )
                        else:
                            self.behavioral_analyzer.record_effectiveness(
                                param_name, vuln_type, False
                            )
                        
                        result.payloads_tested += 1
                        self.scan_stats['payloads_tested'] += 1
        
        except Exception as e:
            logger.error(f"[SCANNER] Error scanning endpoint: {e}")
            stealth_logger.log_event(ScanEvent(
                module="SCANNER",
                action="ERROR",
                reasoning=f"Exception during scan: {str(e)[:100]}",
                endpoint=endpoint_url,
                status="error"
            ))
        
        finally:
            result.duration_seconds = time.time() - start_time
            self.scan_stats['endpoints_scanned'] += 1
            result.vulnerable = len(result.vulnerabilities) > 0
            
            stealth_logger.log_event(ScanEvent(
                module="SCANNER",
                action="END_ENDPOINT_SCAN",
                reasoning=f"Completed scan: {len(result.vulnerabilities)} vulns found, "
                         f"{result.payloads_tested} payloads tested in {result.duration_seconds:.1f}s",
                endpoint=endpoint_url,
                result={
                    'vulnerable': result.vulnerable,
                    'vuln_count': len(result.vulnerabilities),
                    'payloads_tested': result.payloads_tested,
                    'duration_s': result.duration_seconds
                }
            ))
        
        return result

    # ─── Payload Testing with WAF Bypass ──────────────────────────────────────

    def _test_payload_with_bypass(
        self,
        endpoint_url: str,
        parameter: str,
        payload: str,
        vuln_type: str,
        target: str = "unknown",
        max_bypass_attempts: int = 3
    ) -> Optional[Dict]:
        """
        Test a payload with automatic WAF bypass escalation.
        
        FIX #8: Skip WAF bypass for URLs without parameters (noise filtering)
        
        Returns: Vulnerability dict if found, None otherwise
        """
        # FIX #8: Filter URLs with no injection parameters - they don't need WAF bypass
        from urllib.parse import urlparse
        parsed = urlparse(endpoint_url)
        
        if config.WAF_BYPASS_FILTER_NO_PARAMS and not parsed.query:
            # URL has no parameters - skip WAF bypass logic, just do normal test
            logger.debug(f"[SCANNER] Skipping WAF bypass for parameter-less URL: {endpoint_url}")
            response = self._execute_test(
                endpoint_url,
                parameter,
                payload,
                target=target
            )
            if response and not self.waf_bypass_engine.detect_waf_blocking(
                response.get('status_code', 0),
                response.get('headers', {}),
                response.get('body', '')
            )[0]:
                return self._analyze_response(response, vuln_type, endpoint_url, parameter, payload)
            return None
        
        current_bypass_mode = BypassMode.NONE
        
        for attempt in range(max_bypass_attempts):
            # CONSTRAINT 2: WAF BYPASS STRATEGY
            if attempt > 0:
                current_bypass_mode = self.waf_bypass_engine.recommend_bypass_mode()
                stealth_logger.log_event(ScanEvent(
                    module="WAF-BYPASS",
                    action="ESCALATE",
                    reasoning=f"Escalating to {current_bypass_mode.value} after {attempt} failed attempts",
                    endpoint=endpoint_url,
                    parameter=parameter,
                    result={'attempt': attempt, 'mode': current_bypass_mode.value}
                ))
            
            # Generate polymorphic variants
            payload_variants = self.waf_bypass_engine.generate_polymorphic_payloads(
                payload,
                current_bypass_mode,
                count=2
            )
            
            # Test each variant
            for variant in payload_variants:
                response = self._execute_test(
                    endpoint_url,
                    parameter,
                    variant,
                    target=target
                )
                
                if response is None:
                    continue
                
                # Check for WAF blocking
                is_blocked, block_reason = self.waf_bypass_engine.detect_waf_blocking(
                    response.get('status_code', 0),
                    response.get('headers', {}),
                    response.get('body', '')
                )
                
                if is_blocked:
                    self.scan_stats['waf_blocks_detected'] += 1
                    stealth_logger.detect_waf_blocking(
                        endpoint=endpoint_url,
                        status_code=response.get('status_code', 0),
                        waf_type=self.waf_bypass_engine.waf_type.value,
                        reasoning=f"Detected blocking: {block_reason}"
                    )
                    
                    # Try next bypass mode
                    continue
                
                # No WAF blocking - analyze response
                vuln = self._analyze_response_for_vulnerability(
                    response,
                    variant,
                    vuln_type
                )
                
                if vuln:
                    self.scan_stats['waf_bypasses_successful'] += 1
                    stealth_logger.apply_waf_bypass(
                        endpoint=endpoint_url,
                        bypass_mode=current_bypass_mode.value,
                        original_payload=payload,
                        mutated_payload=variant,
                        reasoning=f"WAF bypass successful with {current_bypass_mode.value}"
                    )
                    return vuln
        
        return None

    def _execute_test(
        self,
        endpoint_url: str,
        parameter: str,
        payload: str,
        target: str = "unknown"
    ) -> Optional[Dict]:
        """
        Execute a single payload test with resource management.
        
        Returns: Response dict {status_code, headers, body, response_time}
        """
        try:
            # CONSTRAINT 3: RESOURCE CONSERVATION
            # Check if we can start task
            if not self.resource_manager.can_start_task():
                if not self.resource_manager.wait_for_slot(timeout_seconds=30):
                    logger.warning(f"[SCANNER] Resource timeout for {endpoint_url}")
                    self.resource_manager.on_timeout(target)
                    return None
            
            # Register task
            task_id = f"scan_{target}_{hash(endpoint_url) % 10000}"
            self.resource_manager.register_task(task_id)
            
            try:
                # Get evasion headers
                headers = self.waf_bypass_engine.generate_evasion_headers()
                
                # Apply delay
                delay = self.resource_manager.get_delay()
                time.sleep(delay)
                
                stealth_logger.test_payload(
                    endpoint=endpoint_url,
                    parameter=parameter,
                    payload=payload[:50],
                    vulnerability_type="unknown",
                    reasoning=f"Injecting payload in {parameter} with {len(headers)} evasion headers"
                )
                
                # Prepare test URL
                test_url = f"{endpoint_url}?{parameter}={payload}" if "?" not in endpoint_url else \
                          f"{endpoint_url}&{parameter}={payload}"
                
                start_time = time.time()
                response = self.http_client.get(
                    test_url,
                    headers=headers,
                    timeout=self.timeout_seconds,
                    allow_redirects=True
                )
                elapsed = time.time() - start_time
                
                # Record successful request
                self.resource_manager.on_successful_request(target)
                
                return {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'body': response.text,
                    'response_time': elapsed,
                    'length': len(response.text),
                }
            
            finally:
                self.resource_manager.unregister_task(task_id, status="completed")
        
        except Exception as e:
            logger.error(f"[SCANNER] Test execution failed: {e}")
            self.resource_manager.on_timeout(target)
            self.scan_stats['timeouts'] += 1
            return None

    def _analyze_response_for_vulnerability(
        self,
        response: Dict,
        payload: str,
        vuln_type: str
    ) -> Optional[Dict]:
        """
        Analyze response to detect vulnerability.
        
        Returns: Vulnerability dict if found, None otherwise
        """
        try:
            score_result = self.vulnerability_scorer.score_vulnerability(
                exploit_type=vuln_type,
                response_text=response.get('body', ''),
                baseline_response=None,  # TODO: add baseline
                payload=payload,
                payload_count=1,
                status_code=response.get('status_code', 200),
                baseline_status=200
            )
            
            if score_result['score'] >= 0.5:
                return {
                    'type': vuln_type,
                    'confidence': score_result['score'],
                    'severity': score_result['severity'],
                    'evidence': score_result['evidence'],
                    'payload': payload[:100],
                }
        
        except Exception as e:
            logger.debug(f"[SCANNER] Response analysis failed: {e}")
        
        return None

    # ─── Batch Scanning ──────────────────────────────────────────────────────

    def scan_endpoints_batch(
        self,
        endpoints: List[Tuple[str, Dict[str, str]]],
        target: str = "unknown",
        max_workers: int = None
    ) -> List[ScanResult]:
        """
        Scan multiple endpoints in parallel with resource limits.
        
        Args:
            endpoints: List of (url, parameters_dict) tuples
            target: Target name
            max_workers: Max parallel workers (uses resource manager if None)
        
        Returns: List of ScanResult objects
        """
        max_workers = max_workers or self.resource_manager.current_concurrency
        results = []
        
        stealth_logger.log_event(ScanEvent(
            module="SCANNER",
            action="START_BATCH",
            reasoning=f"Starting batch scan of {len(endpoints)} endpoints with max {max_workers} workers",
            target=target,
        ))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            
            for url, params in endpoints:
                future = executor.submit(
                    self.scan_endpoint,
                    url,
                    params,
                    target
                )
                futures[future] = url
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"[SCANNER] Batch scan error: {e}")
        
        stealth_logger.log_event(ScanEvent(
            module="SCANNER",
            action="END_BATCH",
            reasoning=f"Completed batch scan: {len(results)} endpoints, "
                     f"{self.scan_stats['vulnerabilities_found']} vulns total",
            target=target,
            result=self.scan_stats
        ))
        
        return results

    def get_scan_summary(self) -> Dict:
        """Get summary of all scanning activity."""
        return {
            'statistics': self.scan_stats,
            'resource_status': self.resource_manager.get_status(),
            'waf_info': {
                'last_detected_type': self.waf_bypass_engine.waf_type.value,
                'consecutive_blocks': self.waf_bypass_engine.consecutive_blocks,
                'bypass_attempts': len(self.waf_bypass_engine.bypass_attempts),
            },
            'behavioral_analyst': {
                'parameters_analyzed': len(self.behavioral_analyzer.effectiveness_scores),
                'effectiveness_scores': dict(self.behavioral_analyzer.effectiveness_scores),
            }
        }
