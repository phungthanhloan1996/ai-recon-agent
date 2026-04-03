# HTTPX Integration for Live Host Validation

## Problem Statement

The reconnaissance pipeline was not using httpx (ProjectDiscovery) effectively for live host validation. Instead, it was using Python's HTTPClient with ThreadPoolExecutor, which is significantly slower and less efficient for HTTP probing.

### Issues with the Previous Approach:
1. **Slow DNS resolution**: Python's socket.gethostbyname() was used for DNS verification, which doesn't handle timeouts well
2. **Sequential-like probing**: Even with ThreadPoolExecutor, Python's HTTP client is slower than Go-based tools
3. **Wasted time on dead hosts**: The pipeline would continue scanning URLs from dead subdomains
4. **No early filtering**: httpx was available but not integrated into the live host validation phase

## Solution

### 1. Installed ProjectDiscovery httpx
```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### 2. Created `integrations/httpx_runner.py`
A new integration module that wraps ProjectDiscovery httpx for fast HTTP probing:

- **`HttpxRunner` class**: Main interface for httpx operations
- **`probe_hosts()`**: Flexible probing with configurable options
- **`quick_probe()`**: Optimized for speed (100 threads, 300 req/s)
- **`validate_live_hosts()`**: Primary method for recon pipeline
- **Auto-detection**: Finds httpx binary in common Go installation paths

### 3. Updated `modules/recon.py`
Modified the `ReconEngine` class to use httpx for live host validation:

- Added import for `HttpxRunner`
- Initialized `self.httpx = HttpxRunner(output_dir)` in `__init__`
- Updated `validate_live_hosts()` to:
  - **Primary**: Use httpx for fast HTTP probing (Go-based, 100+ threads)
  - **Fallback**: Use Python HTTPClient if httpx is unavailable

## Performance Benefits

| Metric | Python HTTPClient | ProjectDiscovery httpx |
|--------|-------------------|------------------------|
| Concurrency | 16 threads | 100+ threads |
| Rate limit | N/A | 300 req/s (configurable) |
| DNS handling | socket.gethostbyname() | Built-in async resolver |
| Timeout handling | Per-request | Global + per-request |
| Memory usage | Higher (Python overhead) | Lower (Go efficiency) |

### Expected Speed Improvement:
- **5-10x faster** for live host validation
- **Better timeout handling** - no more waiting for DNS timeouts on dead hosts
- **More accurate results** - httpx handles redirects, SSL, and edge cases better

## Usage

The httpx integration is automatic. When `ReconEngine.validate_live_hosts()` is called:

1. It first checks if httpx is available
2. If available, uses httpx for fast probing
3. If not available, falls back to Python HTTPClient

### Example Output:
```
[RECON] Validating live hosts
[RECON] Using httpx for live host validation (150 URLs, timeout=8s)
[HTTPX] Validating 150 hosts with httpx...
[HTTPX] Probed 150 targets, found 45 live hosts
[HTTPX] Live hosts by status: {200: 35, 301: 8, 302: 2}
[RECON] httpx validated 45 live hosts out of 150 checked
```

## Files Modified

1. **`integrations/httpx_runner.py`** (NEW)
   - New httpx integration module

2. **`modules/recon.py`** (MODIFIED)
   - Added httpx import
   - Added httpx initialization in `__init__`
   - Updated `validate_live_hosts()` to use httpx

## Configuration

The httpx behavior can be tuned via budget settings in `config.py` or state:

```yaml
# Budget settings
recon_validate_urls: 200      # Max URLs to validate
live_timeout: 8               # Timeout per probe (seconds)
```

The httpx runner uses these defaults:
- Threads: 100
- Rate limit: 300 req/s
- Follow redirects: Yes (max 2)
- Status codes considered "live": 2xx, 3xx

## Verification

To verify the integration is working:

```bash
cd /home/root17/Desktop/ai-recon-agent
python3 -c "
from integrations.httpx_runner import HttpxRunner
runner = HttpxRunner('/tmp')
print(f'httpx available: {runner.is_available()}')
print(f'httpx path: {runner.httpx_path}')
results = runner.quick_probe(['https://example.com'], timeout=5)
print(f'Results: {len(results)} live hosts')
"
```

Expected output:
```
httpx available: True
httpx path: /home/root17/go/bin/httpx
Results: 1 live hosts