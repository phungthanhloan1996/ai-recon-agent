"""
QUICK_START.md - Get Started with Stealthy High-Efficiency Scanning

Complete beginner's guide to using the new vulnerability scanning pipeline.
"""

# QUICK START GUIDE

## What's Included

This package contains a complete vulnerability scanning system designed for:
- **Stealth**: Bypasses WAF/IDS detection
- **Efficiency**: Max 50 concurrent tasks on 4GB RAM
- **Intelligence**: Behavioral analysis matches payloads to parameters
- **Transparency**: Every action logged with reasoning

## Installation

```bash
# No additional dependencies needed!
# Uses existing requirements:
# - requests
# - urllib3
# - psutil (for resource monitoring)
```

If `psutil` is missing:
```bash
pip install psutil
```

## 5-Minute Demo

### 1. Run the Integration Test

```bash
cd /home/root17/Desktop/ai-recon-agent
python test_stealthy_scanner.py
```

This demonstrates all 4 constraints in action:
- Behavioral analysis of parameters
- WAF bypass with 4 different encoding techniques
- Resource management with 50 concurrent limit
- Structured logging format

### 2. Scan a Single Endpoint

```python
from modules.stealthy_scanner import StealthyScanner
from core.http_engine import HTTPClient

# Create scanner
scanner = StealthyScanner()

# Scan endpoint
result = scanner.scan_endpoint(
    endpoint_url="https://httpbin.org/get?id=1&search=test",
    parameters={"id": "1", "search": "test"},
    target="httpbin.org"
)

# View results
print(f"Vulnerable: {result.vulnerable}")
print(f"Vulnerabilities: {result.vulnerabilities}")
print(f"Payloads tested: {result.payloads_tested}")
print(f"Duration: {result.duration_seconds:.1f}s")
```

### 3. Scan Multiple Endpoints

```python
endpoints = [
    ("https://httpbin.org/get?id=1", {"id": "1"}),
    ("https://httpbin.org/get?search=test", {"search": "test"}),
]

results = scanner.scan_endpoints_batch(
    endpoints,
    target="httpbin.org",
    max_workers=10
)

# Analyze results
for result in results:
    if result.vulnerable:
        print(f"✓ {result.endpoint}")
        for vuln in result.vulnerabilities:
            print(f"  - {vuln['type']} (confidence: {vuln['confidence']:.0%})")
```

### 4. Monitor Resource Usage

```python
status = scanner.resource_manager.get_status()
print(f"Memory: {status['memory_percent']:.1f}%")
print(f"CPU: {status['cpu_percent']:.1f}%")
print(f"Active tasks: {status['active_tasks']}/{status['max_concurrent']}")
print(f"Timeouts: {status['timeout_count']}")
```

## Understanding the Pipeline

### Step 1: Parameter Classification

The system analyzes each parameter:

```
Parameter: "id=123"
  ↓
Classification: Numeric ID (likely database)
  ↓
Recommendation: Test SQLi (priority 1.0), IDOR (0.9)
  ↓
Payload budget: 10 SQLi payloads, 5 IDOR payloads
```

### Step 2: Test Payload

```
[SCANNER] [TEST_PAYLOAD] [Testing SQLi in 'id' with 10 headers]
  ↓
Send: GET /api?id=' OR '1'='1
With: X-Forwarded-For: 192.168.1.1
      X-Real-IP: 10.0.0.1
      User-Agent: Chrome/120
  ↓
Response: 200 OK
```

### Step 3: Detect WAF Blocking

```
Response status: 403
  ↓
[WAF] [DETECT_BLOCKING] [403 Forbidden - likely WAF]
  ↓
Consecutive blocks: 5
```

### Step 4: Apply Bypass

```
[WAF-BYPASS] [ESCALATE] [Escalating to ENCODE mode]
  ↓
Original: ' OR '1'='1
Encoded:  %27%20OR%20%271%27%3D%271
  ↓
Send: GET /api?id=%27%20OR%20%271%27%3D%271
  ↓
Response: 200 OK → Bypass successful!
```

### Step 5: Analyze & Score

```
Response contains: Database error message
Payload reflected: YES
Score: 0.85 (HIGH confidence)
  ↓
[VULN] [FOUND] [SQLi confirmed - database error visible]
```

## Configuration

All settings in one place. Key parameters:

```python
from modules.stealthy_scanner import StealthyScanner

scanner = StealthyScanner(
    http_client=None,                    # None = default HTTPClient
    max_payloads_per_param=10,           # Payloads to test per parameter
    timeout_seconds=30,                  # Request timeout
)

# Resource limits
scanner.resource_manager.max_concurrent_tasks = 50      # Hard limit
scanner.resource_manager.max_memory_percent = 80.0      # Trigger warning
scanner.resource_manager.max_cpu_percent = 85.0         # Trigger warning

# Bypass settings
scanner.waf_bypass_engine.consecutive_blocks = 0        # Reset tracker
```

## Expected Output

### Console Logs

```
[SCANNER] [START_ENDPOINT_SCAN] [Beginning comprehensive endpoint analysis]
[BEHAVIOR] [CLASSIFY_PARAMETER] [Parameter 'id' will be tested for sqli, idor]
[SCANNER] [TEST_PAYLOAD] [Injecting payload in id with 10 evasion headers]
[WAF] [DETECT_BLOCKING] [403 Forbidden detected - Unknown WAF]
[WAF-BYPASS] [APPLY_BYPASS] [WAF bypass successful with ENCODE]
[VULN] [FOUND] [Vulnerability confirmed with confidence 0.85]
[RESOURCE] [MONITOR] [Memory 65.2%, CPU 42.1%, 15 active tasks]
[SCANNER] [END_ENDPOINT_SCAN] [Completed scan: 1 vulns found in 8.3s]
```

### Scan Result

```python
result.endpoint              # URL scanned
result.vulnerable           # True if vulns found
result.vulnerabilities      # List of found vulnerabilities
  [{'type': 'sqli',
    'confidence': 0.85,
    'evidence': ['Payload reflected', 'Database error'],
    'payload': "' OR '1'='1"}]
result.payloads_tested      # Total payloads attempted
result.waf_detected         # 'modsecurity', 'cloudflare', etc.
result.bypass_modes_tried   # ['NONE', 'ENCODE', 'CASE_MANGLE']
result.duration_seconds     # Scan duration
```

## Common Tasks

### Task: Scan WordPress Site

```python
scanner = StealthyScanner()

wp_endpoints = [
    ("https://example.com/wp-admin/", {"user": "admin"}),
    ("https://example.com/wp-login.php", {"log": "test", "pwd": "test"}),
    ("https://example.com/?s=test", {"s": "test"}),
]

results = scanner.scan_endpoints_batch(wp_endpoints, target="example.com")

for result in results:
    if result.vulnerable:
        print(f"VULNERABLE: {result.endpoint}")
        for vuln in result.vulnerabilities:
            print(f"  {vuln['type']}: {', '.join(vuln['evidence'][:2])}")
```

### Task: Scan with Custom Payloads

```python
# Override payload generator
scanner.payload_generator.waf_context = {
    "waf_name": "modsecurity",
    "bypass_mode": "ENCODE",
    "failed_patterns": ["script", "alert"]
}

# Then scan normally
result = scanner.scan_endpoint(url, params)
```

### Task: Monitor Resource Usage

```python
# Get real-time metrics
metrics = scanner.resource_manager.get_metrics()
print(f"Memory: {metrics.memory_percent:.1f}%")
print(f"Active tasks: {metrics.active_tasks}/{metrics.memory_percent}")

# Check if critical
if metrics.is_critical():
    print("WARNING: Critical resource usage!")
    print(f"Reducing concurrency to {scanner.resource_manager.current_concurrency}")
```

## Understanding Constraints

### Constraint 1: Behavioral Analysis

**Why it matters:** Reduces payload explosion
- Without analysis: 100 payloads × 10 endpoints = 1000 tests
- With analysis: 5-10 payloads × 10 endpoints = 50-100 tests (90% reduction!)

**In practice:**
```
id=1         → Test SQLi (10 payloads) + IDOR (5 payloads)
file=pdf     → Test LFI (10 payloads) only
redirect=y   → Test Open Redirect (10 payloads) + SSRF (5 payloads)
```

### Constraint 2: WAF Bypass

**Why it matters:** Avoids complete blocking
- Without bypass: 403 Forbidden → no results
- With bypass: Try 4 encoding techniques → 60-90% success rate

**In practice:**
```
Test 1: 403 Forbidden
Test 2 (ENCODE): 403 Forbidden
Test 3 (CASE_MANGLE): 200 OK ✓ Bypass successful!
Pay attention to logs for insights
```

### Constraint 3: Resource Conservation

**Why it matters:** Prevents system crash
- 4GB RAM + 50 concurrent tasks = balanced load
- Handles timeouts gracefully (don't keep retrying forever)

**In practice:**
```
Memory 65%: Normal operation
Memory 80%: Automatic concurrency reduction (50 → 40)
Memory 85%+: Wait for slot before starting new task
3+ timeouts: Increase delay from 0.1s to 2.1s
```

### Constraint 4: Structured Logging

**Why it matters:** Understand what's happening
- Every decision logged with reasoning
- Easy to debug: search logs for specific module/action

**In practice:**
```
[BEHAVIOR] - Shows parameter analysis
[SCANNER] - Shows payload testing
[WAF] - Shows WAF detection
[WAF-BYPASS] - Shows bypass attempts  
[VULN] - Shows findings
[RESOURCE] - Shows resource status
```

## Troubleshooting

### Q: My scan is slow

A: Check logs for [RESOURCE] entries. If memory >75%, scanner auto-reduces.
Solution: Reduce `max_payloads_per_param` or use fewer workers.

### Q: All my payloads are blocked

A: Check [WAF] logs. Bypass mode may not match WAF type.
Solution: Let system escalate through modes or set manually.

### Q: Getting timeouts

A: Check [RESOURCE] logs. Solution: Already handled!
Timeout count automatically increases delay and reduces concurrency.

### Q: No vulnerabilities found

A: Check [Scanner] logs for why payloads weren't effective.
Solution: Ensure you're testing public-facing endpoints, not internal APIs.

## Next Steps

1. **Run the test**: `python test_stealthy_scanner.py`
2. **Read the guide**: See `STEALTHY_SCANNER_GUIDE.md`
3. **Integrate into agent**: Add to your ReconAgent class
4. **Customize payloads**: Adjust for your specific targets
5. **Monitor results**: Check logs for insights

## Support

For issues or questions:
1. Check logs in `/tmp/stealthy_scan.log`
2. Review `STEALTHY_SCANNER_GUIDE.md` for details
3. Check constraint explanations above
4. Review test file for example usage

## Legal

⚠️ This tool is for authorized security testing ONLY
- Get explicit permission before testing any system
- Test on systems you own or have permission for
- Unauthorized access is illegal

---

Happy secure testing! 🎯
