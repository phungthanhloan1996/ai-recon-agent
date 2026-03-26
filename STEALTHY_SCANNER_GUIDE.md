# STEALTHY HIGH-EFFICIENCY VULNERABILITY SCANNING PIPELINE

## OBJECTIVE
Execute a stealthy, high-efficiency vulnerability scan while bypassing WAF/IDS systems with a 4GB RAM constraint.

## ARCHITECTURE OVERVIEW

The system is built on 4 integrated constraint modules:

```
┌─────────────────────────────────────────────────────────────────┐
│  BEHAVIORAL ANALYSIS (Constraint 1)                             │
│  • Classify parameters by name/value patterns                   │
│  • Recommend targeted vulnerability types                       │
│  • Match payload type to parameter logic                        │
└────────────────┬────────────────────────────────────────────────┘
                 │
┌────────────────┴────────────────────────────────────────────────┐
│  STEALTHY SCANNER                                               │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │ Generate targeted payloads                              │   │
│  │ Test payload on endpoint                                │   │
│  │ ▼                                                        │   │
└──┼────────────────────────────────────────────────────────┬─┘   │
   │                                                        │     
   └────┬──────────────────────────────────────────────────┘     
        │                                                        
        ▼                                                        
┌─────────────────────────────────────────────────────────────────┐│
│  WAF BYPASS ENGINE (Constraint 2)                               ││
│                                                                  ││
│  403/406 Detected?  YES ──→ Detect WAF Type                    ││
│                      ├─→ Apply Polymorphic Payloads            ││
│                      ├─→ URL Double Encoding                   ││
│                      ├─→ Case Mangling (ScRiPt)               ││
│                      ├─→ Fragment Keywords (un/**/ion)        ││
│                      ├─→ Hex Encoding                         ││
│                      └─→ Rotate through modes                 ││
│                                                                  ││
│  NO ──────────────────→ Continue with normal payload            ││
│                                                                  ││
│  + Evasion Headers on EVERY request:                            ││
│    • X-Forwarded-For: [Random IP]                              ││
│    • X-Real-IP: [Random IP]                                    ││
│    • User-Agent: [Real Browser String]                         ││
└──┬────────────────────────────────────────────────────────────┬┘│
   │                                                              │ │
   └──────┬───────────────────────────────────────────────────┬──┘ │
          │                                                   │    │
          ▼                                                   ▼    │
┌──────────────────────────────┐  ┌──────────────────────────────┐│
│  ANALYZE RESPONSE            │  │ RESOURCE MANAGER             ││
│  • Score vulnerability       │  │ (Constraint 3)               ││
│  • Check for WAF indicators  │  │                              ││
│  • Extract evidence          │  │ • Max 50 concurrent tasks    ││
│  • Calculate confidence      │  │ • Monitor CPU/Memory         ││
└──────────────┬───────────────┘  │ • Timeout handling:          ││
               │                   │   >3 timeouts →              ││
               │                   │   +2s delay                  ││
               │                   │   -10 concurrency            ││
               │                   │ • Adaptive sleep             ││
               │                   │ • Resource alerts            ││
               │                   └──────────────────────────────┘│
               │                                                   │
               └──────────────────────────────────────────────────┘│
                                                                  │
┌──────────────────────────────────────────────────────────────┐ │
│  STRUCTURED LOGGER (Constraint 4)                            │ │
│  Format: [MODULE] [ACTION] [REASONING]                       │ │
│  Example: [WAF] [DETECT_BLOCKING] [403 Forbidden - ModSec]  │ │
│           [SCANNER] [TEST_PAYLOAD] [Testing SQLi in 'id']   │ │
│           [BEHAVIOR] [CLASSIFY_PARAMETER] [...payload budget]│ │
│           [RESOURCE] [MONITOR] [Memory 78% - high usage]    │ │
└──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## CONSTRAINT 1: BEHAVIORAL ANALYSIS

**Goal:** Do NOT spray all payloads on all endpoints. Match payload type to parameter logic.

### Implementation Details

The `BehavioralAnalyzer` classifies parameters into types:

- **ID Parameters** (`id`, `uid`, `pid`, `*_id`): SQLi, IDOR
- **Search Parameters** (`search`, `q`, `query`, `keyword`): SQLi, XSS
- **Redirect Parameters** (`redirect`, `redirect_uri`, `return`, `goto`): Open Redirect, SSRF
- **File Parameters** (`file`, `path`, `filepath`): LFI, RFI
- **Upload Parameters** (`upload`, `media`, `avatar`): File Upload Bypass, RCE
- **Command Parameters** (`cmd`, `exec`, `command`): RCE
- **Email Parameters** (`email`, `mail`, `recipient`): SQLI, Email Injection
- **Name Fields** (`name`, `username`, `title`): XSS, SQLi

### Recommendation System

For each parameter, the analyzer recommends vulnerability types with priority scores:

```python
analyzer = BehavioralAnalyzer()
param_type = analyzer.classify_parameter("id", "123")
# Returns: ParameterType.ID

recommendations = analyzer.recommend_vulnerabilities(param_type)
# Returns: [(VulnerabilityType.SQLI, 1.0), (VulnerabilityType.IDOR, 0.9), ...]

payload_budget = analyzer.get_priority_payloads(param_type, max_payloads=10)
# Returns: {VulnerabilityType.SQLI: 10, VulnerabilityType.IDOR: 5}
```

### Resource Conservation

- **Max 3 parameters per endpoint** (prevent explosion)
- **Payload budget based on priority** (high=10, medium=5, low=2)
- **Skip unknown parameters** (unless specifically focused)

---

## CONSTRAINT 2: WAF BYPASS STRATEGY (CRITICAL)

**Goal:** If 403/406 detected, IMMEDIATELY switch to polymorphic payloads.

### WAF Detection

The system detects WAF blocking by:
1. **HTTP Status Codes**: 403 (Forbidden), 406 (Not Acceptable)
2. **Response Headers**: CloudFlare, ModSecurity, WAF signatures
3. **Response Body**: "Forbidden", "Access Denied", "Blocked"
4. **Connection Resets**: Status 0 or 5xx errors

Detected WAF types:
- CloudFlare (CF-RAY header)
- ModSecurity (Access denied pattern)
- WordFence (Forbidden pattern)
- AWS WAF
- F5, Imperva, Akamai

### Bypass Escalation

Consecutive blocking → escalate bypass mode:

```
Blocks 0-3:   NONE (original payload)
Blocks 4-10:  ENCODE (URL encode, double encode)
Blocks 11-20: CASE_MANGLE (Mixed case for keywords)
Blocks 21-40: FRAGMENT (Break keywords with comments)
Blocks 41+:   SLOW (Minimal payloads, slow rate)
```

### Polymorphic Payload Techniques

#### 1. URL Encoding
```
Original: ' OR '1'='1
Encoded:  %27%20OR%20%271%27%3D%271
Double:   %2527%2520OR%2520%25271%2527%253D%25271
```

#### 2. Hex Encoding
```
Original: UNION SELECT
Hex:      0x55 0x4E 0x49 0x4F 0x4E (for SQL)
```

#### 3. Case Mangling
```
Original: UNION SELECT alert(1)
Mangled:  UnIoN sElEcT aLeRt(1)
          UNioN SELect ALert(1)
```

#### 4. Fragment Keywords
```
Original: UNION SELECT
Fragment: UN/*comment*/ION SEL/*filter*/ECT
```

#### 5. Unicode Escaping
```
Original: alert(1)
Unicode:  \u0061lert(1)
```

### Evasion Headers

EVERY request includes:
```
X-Forwarded-For: [Random IP]
X-Real-IP: [Random IP]
X-Originating-IP: [Random IP]
User-Agent: [Real Browser String]
CF-Connecting-IP: [Random IP]
True-Client-IP: [Random IP]
```

### Bypass Statistics

Track effectiveness:
```python
engine = WAFBypassEngine()
# ... perform tests ...
stats = engine.get_bypass_statistics()
# {
#   'attempts': 45,
#   'success_rate': 0.73,
#   'by_mode': {
#     'NONE': {'total': 10, 'blocked': 8, 'success_rate': 0.2},
#     'ENCODE': {'total': 20, 'blocked': 5, 'success_rate': 0.75},
#     'CASE_MANGLE': {'total': 15, 'blocked': 2, 'success_rate': 0.87},
#   }
# }
```

---

## CONSTRAINT 3: RESOURCE CONSERVATION

**Goal:** Handle 4GB RAM with max 50 concurrent tasks. Handle timeouts gracefully.

### Resource Monitoring

Tracks in real-time:
- CPU usage (% of process)
- Memory usage (% of system RAM and MB)
- Active tasks (currently running)
- Pending tasks (waiting for slots)
- Task queue size

### Concurrency Control

- **Maximum concurrent tasks**: 50 (hard limit)
- **High resource usage** (>70% memory, >75% CPU) → scale back
- **Critical resource usage** (>85% memory, >90% CPU) → block new tasks

### Adaptive Response

When resource usage is high:
1. Reduce concurrency (e.g., 50 → 40)
2. Increase delay between requests
3. Drop low-priority payloads
4. Abort low-value targets

### Timeout Escalation

**CONSTRAINT**: If timeout > 3 times on a target:
1. Increase delay by 2 seconds
2. Reduce concurrency by 10
3. Track per-target timeout counts
4. Abort after 10+ timeouts

Example:
```
Target: example.com
Timeout 1: delay=0.1s, concurrency=50 ✓
Timeout 2: delay=0.1s, concurrency=50 ✓
Timeout 3: delay=0.1s, concurrency=50 ✓
Timeout 4: ESCALATE! → delay=2.1s, concurrency=40
Timeout 5: delay=2.1s, concurrency=40
Timeout 6: ESCALATE! → delay=4.1s, concurrency=30
...
Timeout 11: ABORT target
```

### Task Management

```python
manager = ResourceManager(max_concurrent_tasks=50)

# Check if can start new task
if manager.can_start_task():
    manager.register_task("task_id_123")
    # ... execute task ...
    manager.unregister_task("task_id_123", status="completed")
else:
    # Wait for slot
    if manager.wait_for_slot(timeout_seconds=300):
        manager.register_task("task_id_123")

# Handle timeout
manager.on_timeout("example.com")  # Escalates as needed

# Get status
status = manager.get_status()
# {
#   'memory_percent': 62.3,
#   'cpu_percent': 45.2,
#   'active_tasks': 25,
#   'max_concurrent': 50,
#   'current_delay': 0.5,
#   'timeout_count': 3
# }
```

---

## CONSTRAINT 4: STRUCTURED LOGGING

**Goal:** Every action logged in format: `[MODULE] [ACTION] [REASONING]`

### Log Format

```
[MODULE] [ACTION] [REASONING] | Target: X | Endpoint: Y | Result: Z
```

### Log Levels

- **INFO**: Normal operations
- **WARNING**: Issues (high resource, WAF detected)
- **ERROR**: Failures
- **CRITICAL**: System critical issues

### Event Types

#### Behavioral Analysis
```
[BEHAVIOR] [CLASSIFY_PARAMETER] [Parameter 'id' classified as database ID - test SQLi/IDOR]
[BEHAVIOR] [ENDPOINT_ANALYSIS] [Endpoint /api/users analyzed - 3 params, 15 payloads recommended]
```

#### WAF Bypass
```
[WAF] [DETECT_BLOCKING] [403 Forbidden detected - ModSecurity signature in headers]
[WAF-BYPASS] [ESCALATE] [Escal to ENCODE after 5 consecutive blocks]
[WAF-BYPASS] [APPLY_BYPASS] [Applied URL double encoding - mutated 34 chars]
```

#### Vulnerability Discovery
```
[VULN] [FOUND] [SQLi confirmed with confidence 0.87 - payload reflected in error message]
[SCANNER] [TEST_PAYLOAD] [Injecting payload in 'search' parameter with 10 evasion headers]
```

#### Resource Management
```
[RESOURCE] [MONITOR] [Memory 78.5% - high usage, reducing concurrency 50→40]
[RESOURCE] [TIMEOUT_ESCALATION] [4 timeouts on example.com - delay 0.1→2.1s]
```

### Example Log Output

```
[SCANNER] [START_ENDPOINT_SCAN] [Beginning comprehensive endpoint analysis] | Target: test.com | Endpoint: https://test.com/api/user?id=123

[BEHAVIOR] [ENDPOINT_ANALYSIS] [Classified 2 parameters, 12 total payloads recommended] | Endpoint: https://test.com/api/user?id=123 | Result: {'parameter_analysis': {...}}

[BEHAVIOR] [CLASSIFY_PARAMETER] [Parameter 'id' will be tested for sqli, idor] | Param: id

[SCANNER] [TEST_PAYLOAD] [Injecting payload in id with 10 evasion headers] | Endpoint: https://test.com/api/user?id=123 | Payload: ' OR '1'='1

[WAF] [DETECT_BLOCKING] [Detected blocking: 403 - Unknown WAF] | Endpoint: https://test.com/api/user?id=123 | Result: {'status_code': 403, 'waf_type': 'unknown'}

[WAF-BYPASS] [ESCALATE] [Escalating to ENCODE after 1 failed attempts] | Endpoint: https://test.com/api/user?id=123

[WAF-BYPASS] [APPLY_BYPASS] [WAF bypass successful with ENCODE] | Endpoint: https://test.com/api/user?id=123 | Payload: %27%20OR%20%271%27%3D%271

[VULN] [FOUND] [Vulnerability confirmed with confidence 0.85] | Endpoint: https://test.com/api/user?id=123 | Payload: ' OR '1'='1 | Result: {'type': 'sqli', 'confidence': 0.85}

[RESOURCE] [MONITOR] [Memory 72.3%, CPU 42.1%, 23 active tasks] | Result: {'metric': 'memory_percent', 'current': 72.3, 'threshold': 80.0}

[SCANNER] [END_ENDPOINT_SCAN] [Completed scan: 1 vulns found, 8 payloads tested in 12.3s] | Endpoint: https://test.com/api/user?id=123
```

---

## USAGE

### 1. Basic Scanning

```python
from modules.stealthy_scanner import StealthyScanner
from core.http_engine import HTTPClient

# Create scanner instance
scanner = StealthyScanner(
    http_client=HTTPClient(),
    max_payloads_per_param=10,
    timeout_seconds=30
)

# Scan single endpoint
result = scanner.scan_endpoint(
    endpoint_url="https://example.com/api/user?id=1&search=test",
    parameters={"id": "1", "search": "test"},
    target="example.com"
)

print(f"Vulnerable: {result.vulnerable}")
print(f"Vulnerabilities: {result.vulnerabilities}")
print(f"Payloads tested: {result.payloads_tested}")
```

### 2. Batch Scanning

```python
endpoints = [
    ("https://example.com/api/user?id=1", {"id": "1"}),
    ("https://example.com/search?q=test", {"q": "test"}),
    ("https://example.com/download?file=doc.pdf", {"file": "doc.pdf"}),
]

results = scanner.scan_endpoints_batch(
    endpoints,
    target="example.com",
    max_workers=20  # Use resource manager default if None
)

for result in results:
    if result.vulnerable:
        print(f"✓ {result.endpoint}: {len(result.vulnerabilities)} vulns found")
```

### 3. View Summary

```python
summary = scanner.get_scan_summary()

print(f"Endpoints scanned: {summary['statistics']['endpoints_scanned']}")
print(f"Vulnerabilities found: {summary['statistics']['vulnerabilities_found']}")
print(f"WAF blocks detected: {summary['statistics']['waf_blocks_detected']}")
print(f"WAF bypasses successful: {summary['statistics']['waf_bypasses_successful']}")
print(f"Resource status: {summary['resource_status']}")
```

### 4. Run Integration Test

```bash
python test_stealthy_scanner.py
```

Outputs:
- Console logs with [MODULE] [ACTION] [REASONING] format
- Detailed log file: `/tmp/stealthy_scan.log`

---

## INTEGRATION WITH AGENT

To integrate StealthyScanner into your ReconAgent:

```python
from modules.stealthy_scanner import StealthyScanner
from core.http_engine import HTTPClient

class ReconAgent:
    def __init__(self, *args, **kwargs):
        # ... existing code ...
        
        # Initialize stealthy scanner
        self.stealthy_scanner = StealthyScanner(
            http_client=self.http_client,
            max_payloads_per_param=10,
            timeout_seconds=config.HTTP_TIMEOUT
        )
    
    def scan_endpoints(self, endpoints: List[Tuple[str, Dict]]) -> List:
        """Scan endpoints using stealthy high-efficiency pipeline."""
        
        logger.info("[AGENT] Starting stealthy vulnerability scanning")
        
        results = self.stealthy_scanner.scan_endpoints_batch(
            endpoints,
            target=self.state.target,
            max_workers=self.state.concurrency
        )
        
        # Process results
        for result in results:
            if result.vulnerable:
                for vuln in result.vulnerabilities:
                    self.state.add_vulnerability(
                        endpoint=result.endpoint,
                        type=vuln['type'],
                        confidence=vuln['confidence'],
                        evidence=vuln['evidence']
                    )
        
        # Get summary
        summary = self.stealthy_scanner.get_scan_summary()
        logger.info(f"[AGENT] Scan complete: {json.dumps(summary['statistics'])}")
        
        return results
```

---

## PERFORMANCE EXPECTATIONS

On a 4GB RAM system:

- **Endpoints per second**: 2-5 (depending on target response time)
- **Payloads per endpoint**: 10-30 (behavioral analysis limits this)
- **WAF bypass success**: 50-90% (depending on WAF type)
- **Peak memory usage**: ~60-70% RAM
- **Peak CPU usage**: 40-60%

### Bottlenecks

- **Network latency**: Wait for HTTP responses (unavoidable)
- **WAF delays**: Some WAFs add delays to responses (mitigated by bypass)
- **Timeout recovery**: 3+ timeouts per target escalate to slow mode

---

## SECURITY & LEGAL

⚠️ **IMPORTANT:**

1. **ONLY use this tool on systems you own or have explicit permission to test**
2. **Unauthorized access is illegal** - ensure proper authorization
3. **Test responsibly** - avoid disrupting target services
4. **Local testing recommended**: Test on httpbin.org, local test environments first
5. **Customizable payloads**: Adjust for your specific testing needs

---

## TROUBLESHOOTING

### Issue: Slow Scanning
**Solution**: Check resource usage. If memory >80%, scanner auto-reduces concurrency.
Use `get_scan_summary()` to check bottleneck.

### Issue: All Payloads Blocked
**Solution**: Increase bypass mode aggressiveness:
- Check: `waf_bypass_engine.current_bypass_mode`
- Manually escalate: `waf_bypass_engine.recommend_bypass_mode()`

### Issue: High Memory Usage
**Solution**: Reduce `max_payloads_per_param` or use fewer concurrent workers.

### Issue: Many Timeouts
**Solution**: Automatically handled with increased delays and reduced concurrency.
Check: `resource_manager.timeout_by_target`

---

## Future Enhancements

1. **Machine Learning**: Learn which payloads work for specific target patterns
2. **Distributed Scanning**: Coordinate multiple scanners across systems
3. **Advanced WAF Fingerprinting**: Identify specific WAF version for targeted bypasses
4. **Payload Timing**: Use timing analysis for blind SQLi detection
5. **OOB Detection**: Out-of-band channels for RCE validation
6. **Custom Payload Rules**: User-defined payload generation templates

---

## Authors & Credits

Built for high-efficiency, stealthy reconnaissance within hardware constraints.

Implements industry-best-practices from:
- OWASP Testing Guide
- Burp Suite Techniques
- PortSwigger Web Security Academy
- CWE/CVE Databases

---

## License

For educational and authorized security testing purposes only.
