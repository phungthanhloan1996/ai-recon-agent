"""
test_stealthy_scanner.py - Stealthy Scanner Integration Test
Demonstrates all 4 constraints in action:
1. Behavioral analysis matching payloads to parameters
2. WAF bypass with polymorphic payloads
3. Resource conservation with concurrency limits
4. Structured [MODULE] [ACTION] [REASONING] logging
"""

import sys
import logging
import json
from pathlib import Path

# Add repo to path
repo_root = Path(__file__).parent
sys.path.insert(0, str(repo_root))

from modules.stealthy_scanner import StealthyScanner
from core.http_engine import HTTPClient
from core.structured_logger import setup_structured_logging, StealthLogger
from core.behavioral_analyzer import BehavioralAnalyzer

# Setup structured logging
setup_structured_logging(log_file="/tmp/stealthy_scan.log")
logger = logging.getLogger("test_stealthy_scanner")


def test_behavioral_analyzer():
    """Test CONSTRAINT 1: Behavioral Analysis"""
    logger.info("\n" + "="*80)
    logger.info("CONSTRAINT 1: BEHAVIORAL ANALYSIS")
    logger.info("="*80)
    
    analyzer = BehavioralAnalyzer()
    
    test_cases = [
        ("id", "123"),
        ("search", "test query"),
        ("redirect_uri", "https://evil.com"),
        ("file", "../../etc/passwd"),
        ("cmd", "ls -la"),
        ("email", "attacker@evil.com"),
    ]
    
    for param_name, param_value in test_cases:
        param_type = analyzer.classify_parameter(param_name, param_value)
        recommendations = analyzer.recommend_vulnerabilities(param_type)
        budget = analyzer.get_priority_payloads(param_type)
        
        logger.info(f"\nParameter: {param_name}={param_value}")
        logger.info(f"  Type: {param_type.value}")
        logger.info(f"  Recommended: {[(v.value, f'{p:.1f}') for v, p in recommendations[:3]]}")
        logger.info(f"  Payload Budget: {json.dumps({k.value: v for k, v in budget.items()})}")


def test_waf_bypass_engine():
    """Test CONSTRAINT 2: WAF Bypass with Polymorphic Payloads"""
    logger.info("\n" + "="*80)
    logger.info("CONSTRAINT 2: WAF BYPASS STRATEGY")
    logger.info("="*80)
    
    from core.waf_bypass_engine import WAFBypassEngine, BypassMode
    
    engine = WAFBypassEngine()
    
    # Test payload
    base_payload = "' OR '1'='1"
    
    bypass_modes = [
        BypassMode.NONE,
        BypassMode.ENCODE,
        BypassMode.CASE_MANGLE,
        BypassMode.FRAGMENT,
    ]
    
    for mode in bypass_modes:
        variants = engine.generate_polymorphic_payloads(base_payload, mode, count=3)
        logger.info(f"\nBypass Mode: {mode.value}")
        logger.info(f"  Base: {base_payload}")
        for i, variant in enumerate(variants[:2], 1):
            logger.info(f"  Variant {i}: {variant[:60]}...")
    
    # Test evasion headers
    headers = engine.generate_evasion_headers()
    logger.info(f"\nEvasion Headers Generated:")
    for key, value in list(headers.items())[:5]:
        logger.info(f"  {key}: {value[:40]}...")


def test_resource_manager():
    """Test CONSTRAINT 3: Resource Conservation"""
    logger.info("\n" + "="*80)
    logger.info("CONSTRAINT 3: RESOURCE CONSERVATION")
    logger.info("="*80)
    
    from core.resource_manager import ResourceManager
    
    manager = ResourceManager(max_concurrent_tasks=50)
    
    # Get metrics
    metrics = manager.get_metrics()
    logger.info(f"\nCurrent Resource Metrics:")
    logger.info(f"  Memory: {metrics.memory_percent:.1f}% ({metrics.memory_mb:.1f} MB)")
    logger.info(f"  CPU: {metrics.cpu_percent:.1f}%")
    logger.info(f"  Max Concurrent Tasks: {manager.max_concurrent_tasks}")
    logger.info(f"  Current Concurrency Setting: {manager.current_concurrency}")
    
    # Test timeout handling
    logger.info(f"\nSimulating timeouts on target...")
    for i in range(5):
        manager.on_timeout("example.com")
        logger.info(f"  Timeout #{i+1}: delay={manager.current_delay:.1f}s, concurrency={manager.current_concurrency}")


def test_structured_logging():
    """Test CONSTRAINT 4: Structured Logging"""
    logger.info("\n" + "="*80)
    logger.info("CONSTRAINT 4: STRUCTURED LOGGING [MODULE] [ACTION] [REASONING]")
    logger.info("="*80)
    
    from core.structured_logger import StealthLogger, ScanEvent
    
    stealth_logger = StealthLogger("test_logger")
    
    # Test various event types
    stealth_logger.classify_parameter(
        parameter="id",
        param_type="id",
        recommended_vulns=[("sqli", 1.0), ("idor", 0.9)],
        reasoning="Parameter 'id' is numeric ID typically vulnerable to SQLi and IDOR"
    )
    
    stealth_logger.detect_waf_blocking(
        endpoint="https://example.com/api/user?id=123",
        status_code=403,
        waf_type="modsecurity",
        reasoning="Detected 403 response with ModSecurity signature in headers"
    )
    
    stealth_logger.apply_waf_bypass(
        endpoint="https://example.com/api/user?id=123",
        bypass_mode="ENCODE",
        original_payload="' OR '1'='1",
        mutated_payload="%27%20OR%20%271%27%3D%271",
        reasoning="Applied URL encoding to bypass keyword filtering"
    )
    
    stealth_logger.vulnerability_found(
        endpoint="https://example.com/api/user?id=123",
        vulnerability_type="sqli",
        confidence=0.85,
        payload="' OR '1'='1",
        reasoning="Payload reflected in response with database error pattern detected"
    )
    
    stealth_logger.resource_alert(
        metric="memory_percent",
        current_value=78.5,
        threshold=80.0,
        reasoning="Memory usage approaching threshold - may need to reduce concurrency"
    )
    
    # Get summary
    summary = stealth_logger.get_event_summary()
    logger.info(f"\nLogging Summary:")
    logger.info(f"  Total Events: {summary['total_events']}")
    logger.info(f"  By Module: {json.dumps(summary['by_module'], indent=4)}")
    logger.info(f"  By Status: {json.dumps(summary['by_status'])}")


def test_integrated_scanner():
    """Test CONSTRAINT 1-4: Integrated Stealthy Scanner"""
    logger.info("\n" + "="*80)
    logger.info("INTEGRATED TEST: All 4 Constraints Together")
    logger.info("="*80)
    
    scanner = StealthyScanner(
        http_client=HTTPClient(),
        max_payloads_per_param=5,
        timeout_seconds=10
    )
    
    # Sample endpoints
    test_endpoints = [
        ("https://httpbin.org/get?id=1&search=test", {"id": "1", "search": "test"}),
    ]
    
    logger.info(f"\nScanning {len(test_endpoints)} endpoint(s)...")
    logger.info("Watch the [MODULE] [ACTION] [REASONING] logs below:\n")
    
    results = []
    for url, params in test_endpoints:
        try:
            result = scanner.scan_endpoint(url, params, target="test_target")
            results.append(result)
            
            logger.info(f"\nScan Result for {url}:")
            logger.info(f"  Vulnerable: {result.vulnerable}")
            logger.info(f"  Vulnerabilities Found: {len(result.vulnerabilities)}")
            logger.info(f"  Payloads Tested: {result.payloads_tested}")
            logger.info(f"  Duration: {result.duration_seconds:.1f}s")
        
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
    
    # Print summary
    summary = scanner.get_scan_summary()
    logger.info(f"\nScan Summary:")
    logger.info(f"  Statistics: {json.dumps(summary['statistics'], indent=2)}")
    logger.info(f"  Resource Status: {json.dumps(summary['resource_status'], indent=2)}")


def main():
    """Run all tests."""
    logger.info("╔" + "="*78 + "╗")
    logger.info("║ STEALTHY VULNERABILITY SCANNER - CONSTRAINT VALIDATION TEST           ║")
    logger.info("║ OBJECTIVE: Execute scans while bypassing WAF/IDS                       ║")
    logger.info("╚" + "="*78 + "╝")
    
    try:
        # Test each constraint
        test_behavioral_analyzer()
        test_waf_bypass_engine()
        test_resource_manager()
        test_structured_logging()
        test_integrated_scanner()
        
        logger.info("\n" + "="*80)
        logger.info("✓ ALL TESTS COMPLETED SUCCESSFULLY")
        logger.info("="*80)
        logger.info("\nNEXT STEPS:")
        logger.info("1. Check /tmp/stealthy_scan.log for detailed structured logs")
        logger.info("2. Integrate StealthyScanner into agent.py")
        logger.info("3. For production usage, ensure targets are in scope")
        logger.info("4. Monitor resource usage and WAF bypass effectiveness")
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
