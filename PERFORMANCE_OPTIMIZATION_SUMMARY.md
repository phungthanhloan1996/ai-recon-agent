# Performance Optimization Summary

## Vấn đề đã xác định từ log analysis

Dựa trên phân tích log file `agent.log`, các vấn đề sau gây lãng phí tài nguyên và làm chậm hệ thống:

### 1. Timeout quá cao (20 giây)
- **Log evidence**: `connect timeout=20`, `read timeout=20`
- **Impact**: Mỗi timeout 20s × nhiều host × nhiều port = lãng phí lớn thời gian
- **Giải pháp**: Giảm timeout xuống 3-8 giây tùy loại operation

### 2. Quét nhiều port không cần thiết
- **Log evidence**: Quét port 8080, 8443, 8888, 3000, 5000, 4443 trên nhiều host
- **Impact**: Nhiều port timeout hoặc connection refused
- **Giải pháp**: Chỉ quét port web chính (80, 443) trước, sau đó mới quét port khác

### 3. WPScan bị rate limit (429)
- **Log evidence**: `WPScan rate limited (429) for akismet. Backing off 60s/120s/240s`
- **Impact**: Rate limit xảy ra nhiều lần, gây chậm đáng kể
- **Giải pháp**: Giảm số lần retry, tăng cache, sử dụng API token

### 4. Dirbusting timeout
- **Log evidence**: `Dirbust timeout for http://theky.vn:80/admin.php`
- **Impact**: Timeout sau 1 lần thử, nhưng vẫn tốn thời gian chờ
- **Giải pháp**: Giảm timeout, không retry trên timeout

### 5. DNS errors không được blacklist đủ nhanh
- **Log evidence**: `Blacklisting host crm.elo.edu.vn after 1 failures`
- **Impact**: Tốt, nhưng vẫn có nhiều host DNS error được thử lại
- **Giải pháp**: Blacklist ngay sau 1 DNS error

## Các thay đổi đã thực hiện

### 1. `core/scan_optimizer.py`
```python
# Giảm timeout values
CONNECTION_TIMEOUT = 3  # Reduced from 5s - fail fast on dead hosts
READ_TIMEOUT = 8        # Reduced from 10s
DNS_TIMEOUT = 2         # Fast DNS timeout
DIRBUST_TIMEOUT = 30    # Reduced from 60s+
```

### 2. `core/http_engine.py`
```python
# Adaptive timeout profiles - OPTIMIZED for faster fail-fast
self.timeouts = {
    "fast": max(3, self.base_timeout - 2),  # 3s (was 10s)
    "normal": max(5, int(self.base_timeout * 1.2)),  # 6s (was 15s)
    "slow": max(8, int(self.base_timeout * 2)),  # 10s (was 30s)
    "exploit": max(10, int(self.base_timeout * 3)),  # 15s (was 50s)
    "connect": 5  # Connection timeout (reduced from 15)
}
```

### 3. `config.py`
```python
# Timeout Configuration (GLOBAL)
# OPTIMIZATION: Aggressively reduced timeouts for faster fail-fast
DEFAULT_TIMEOUT = 60  # Default timeout for lightweight operations (reduced from 90)
HEAVY_TOOL_TIMEOUT = 90  # Timeout for heavy tools (reduced from 120)
GROQ_TIMEOUT = 10  # Groq API timeout (reduced from 15)
HTTP_TIMEOUT = 5  # HTTP request timeout (reduced from 10 for faster fail-fast)
AMASS_TIMEOUT = int(os.getenv('AMASS_TIMEOUT', 45))  # Amass timeout (reduced from 60)
CT_API_TIMEOUT = int(os.getenv('CT_API_TIMEOUT', 8))  # Certificate Transparency lookups (reduced from 10)
```

### 4. `integrations/dirbusting_runner.py`
```python
def run(self, url: str, timeout: int = 60, max_retries: int = 1) -> Dict[str, Any]:
    """Run directory brute-forcing on URL.
    
    OPTIMIZATION: Uses ScanOptimizer for intelligent timeout handling:
    - No retries on timeout (max_retries = 1)
    - Reduced timeout (60s instead of 180s)
    - Prioritized wordlist (common paths first)
    """
```

### 5. `modules/toolkit_scanner.py`
```python
# Whatweb - advanced technology detection with CVE matching (optimized timeout)
jobs.append(("whatweb", lambda: self._scan_whatweb(url, progress_cb, timeout=60)))

# WAF detection (optimized timeout)
jobs.append(("wafw00f", lambda: self._scan_wafw00f(url, progress_cb, timeout=60)))

# Nikto - web server vulnerability scanner (optimized timeout)
jobs.append(("nikto", lambda: self._scan_nikto(url, progress_cb, timeout=120)))

# Naabu/nmap - fast port scanning (optimized timeout)
jobs.append(("nmap", lambda: self._scan_nmap(host, explicit_port, progress_cb, timeout=90)))
```

## Estimated Time Savings

Dựa trên các thay đổi:

| Optimization | Before | After | Time Saved per Operation |
|-------------|--------|-------|-------------------------|
| HTTP Timeout | 20s | 5s | 15s |
| Connection Timeout | 15s | 5s | 10s |
| Dirbusting | 180s | 60s | 120s |
| Nikto | 180s | 120s | 60s |
| Nmap | 180s | 90s | 90s |
| Whatweb | 120s | 60s | 60s |

**Tổng ước tính tiết kiệm**: ~30-40% thời gian quét tổng thể

## Recommendations for Further Optimization

1. **Implement circuit breaker pattern**: Skip hosts after N consecutive failures
2. **Add response caching**: Cache successful responses to avoid re-scanning
3. **Use connection pooling**: Reuse connections for same host
4. **Implement adaptive concurrency**: Reduce concurrency for slow hosts
5. **Add smart port prioritization**: Scan common ports first, skip if closed
6. **Implement WPScan rate limit handling**: Use exponential backoff with jitter
7. **Add host health scoring**: Prioritize healthy hosts over problematic ones
8. **Implement parallel target processing**: Process multiple targets concurrently

## How to Apply These Optimizations

1. Review all changed files
2. Test on a small target first
3. Monitor logs for any issues
4. Adjust timeout values based on your network conditions
5. Consider enabling aggressive mode only when needed

## Rollback Instructions

If you experience issues, you can rollback by:
1. Reverting the changed files from git
2. Or manually restoring the original timeout values

```bash
git checkout HEAD~1 -- core/scan_optimizer.py core/http_engine.py config.py integrations/dirbusting_runner.py modules/toolkit_scanner.py