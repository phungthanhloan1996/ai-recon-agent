# Performance Optimization Guide - AGGRESSIVE MODE

## Overview

This document describes the aggressive performance optimizations implemented to address:
- Network timeouts on unresponsive targets
- WPScan API rate limiting (429 errors)
- Port scanning timeouts
- DNS resolution failures
- Targets that don't respond (e.g., vepg.vn)

## Changes Summary

### 1. Configuration Changes (`config/optimizer_config.yaml`)

#### Timeout Settings (Ultra-Aggressive)
| Setting | Before | After | Impact |
|---------|--------|-------|--------|
| connection | 5s | 3s | 40% faster fail on dead hosts |
| read | 10s | 8s | 20% faster read operations |
| dns | 3s | 2s | 33% faster DNS failures |
| dirbust | 30s | 20s | 33% faster directory scanning |
| wpscan | 10s | 8s | 20% faster WPScan |
| port_scan | 120s | 60s | 50% faster port scanning |

#### Blacklist Settings (Aggressive)
| Setting | Before | After | Impact |
|---------|--------|-------|--------|
| threshold | 3 | 2 | Blacklist after 2 failures |
| timeout_threshold | 2 | 1 | Blacklist after 1 timeout |
| expiration | 1800s | 900s | 15min blacklist (was 30min) |
| skip_target_after_failures | N/A | 3 | Skip target entirely after 3 failures |

#### Port Scanning (Reduced)
| Setting | Before | After | Impact |
|---------|--------|-------|--------|
| web_ports | [80, 443, 8080, 8443] | [80, 443] | 50% fewer ports |
| common_ports | 17 ports | 13 ports | 24% fewer ports |
| max_ports_per_host | N/A | 13 | Hard limit |
| fast_mode | top 1000 | top 100 | 90% reduction |

#### WPScan Settings (Local Database Mode)
| Setting | Before | After | Impact |
|---------|--------|-------|--------|
| max_retries | 2 | 1 | 50% fewer retries |
| backoff_times | [30, 60] | [15] | 75% less wait time |
| skip_after_failures | 2 | 1 | Skip immediately on rate limit |
| use_local_database | false | true | **Avoids API rate limiting** |
| max_plugins | N/A | 20 | Limit plugin enumeration |
| max_themes | N/A | 10 | Limit theme enumeration |

#### Concurrency Settings (Optimized)
| Setting | Before | After | Impact |
|---------|--------|-------|--------|
| max_concurrent_hosts | 5 | 3 | 40% less load |
| host_scan_delay | 0.5s | 0.2s | 60% faster between hosts |
| max_concurrent_requests | 10 | 5 | 50% less per-host load |

### 2. Core Engine Changes

#### `core/scan_optimizer.py`
- **Aggressive HostStatus tracking**: Blacklist after 1 DNS error or 1 timeout
- **Consecutive failure tracking**: Skip target after 3 consecutive failures
- **Success rate monitoring**: Skip if >70% failure rate after 5 requests
- **New methods**: `should_skip_target()`, `get_skip_reason()`

#### `core/http_engine.py`
- **Ultra-aggressive timeouts**: 3s connection, 8s normal mode
- **Reduced retries**: Only 1 retry (was 3)
- **Enhanced blacklist integration**: Immediate skip for blacklisted hosts
- **Dead host caching**: Cache unreachable ports to avoid repeat attempts

#### `modules/wp_scanner.py`
- **Local database mode**: Uses `--no-update` and local cache
- **No API dependency**: Works without api.wpscan.org token
- **Fast timeout**: 8 seconds max
- **Immediate skip on rate limit**: No retry on 429

#### `integrations/naabu_runner.py`
- **Top 100 ports**: Reduced from 1000 (90% reduction)
- **Fast per-port timeout**: 3 seconds
- **Single retry**: Only 1 retry attempt
- **Reduced rate**: 3000 packets/sec (was 5000)

### 3. New Target Skip Mechanism

The system now implements a 3-level skip mechanism:

1. **Level 1 - Blacklist**: Host fails 2 times → blacklisted for 15 minutes
2. **Level 2 - Skip Target**: Host fails 3 consecutive times → skipped entirely
3. **Level 3 - Domain Skip**: Root domain is dead → all subdomains skipped

```python
# Example usage in code:
optimizer = get_optimizer()
if optimizer.should_skip_target(hostname):
    reason = optimizer.get_skip_reason(hostname)
    logger.warning(f"Skipping {hostname}: {reason}")
    continue
```

## Expected Performance Improvements

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Dead host detection | ~40s | ~6s | 85% faster |
| WPScan rate limit hits | Frequent | Rare | Uses local DB |
| Port scan time | ~120s | ~30s | 75% faster |
| Timeout waste | High | Minimal | Aggressive fail-fast |
| Memory usage | High | Lower | Fewer concurrent operations |

## Usage

The optimizations are automatically applied when running the agent. No configuration changes are needed.

### For Development/Testing

If you need to revert to slower but more thorough scanning:

```yaml
# In config/optimizer_config.yaml
timeouts:
  connection: 10       # Slower but more reliable
  read: 15
  dns: 5
  
blacklist:
  threshold: 5         # More lenient
  
port_scanning:
  fast_mode: false     # Full port scan
  max_ports_per_host: 1000
```

## Monitoring

The optimizer provides statistics:

```python
optimizer = get_optimizer()
stats = optimizer.calculate_time_saved()
print(f"Time saved: {stats['estimated_time_saved_minutes']:.1f} minutes")
print(f"Hosts skipped: {stats['hosts_skipped']}")
print(f"Retries avoided: {stats['retries_avoided']}")
```

## Troubleshooting

### Too Aggressive - Missing Valid Hosts

If valid hosts are being skipped:
1. Increase `blacklist.threshold` to 3-5
2. Increase `timeout_threshold` to 2-3
3. Increase connection timeout to 5-10s

### WPScan Not Finding Vulnerabilities

If WPScan local database mode is missing vulnerabilities:
1. Update WPScan database: `wpscan --update`
2. Or provide API token: Set `WPSCAN_API_TOKEN` environment variable

### Port Scans Missing Services

If important ports are being missed:
1. Set `port_scanning.fast_mode: false`
2. Increase `max_ports_per_host` to 100-500
3. Add specific ports to `web_ports` list

## Technical Details

### Blacklist Algorithm

```
if DNS_error and failures >= 1:
    blacklist immediately
elif timeout and failures >= 1:
    blacklist immediately  
elif failures >= 2:
    blacklist
elif consecutive_failures >= 3:
    skip target entirely
elif total_requests >= 5 and failure_rate > 70%:
    skip target entirely
```

### Timeout Cascade

```
1. Check if host is blacklisted → skip immediately
2. Get optimized timeout based on host history
3. Use minimum of (optimized_timeout, mode_timeout)
4. If timeout occurs → record failure → check blacklist
5. If DNS error → blacklist immediately
```

### WPScan Local Database Mode

```bash
# Command used (no API token required):
wpscan --url TARGET \
  --format json \
  --cache-dir /path/to/cache \
  --disable-tls-checks \
  -e vp,u \
  --no-update \
  --stealthy
```

This uses the locally cached vulnerability database instead of querying api.wpscan.org.