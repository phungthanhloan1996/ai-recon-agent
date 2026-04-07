# All 12 Issues - Complete Implementation Plan

## Summary of Changes Made

### ✅ Issue #1: GROQ Failover Logic (PARTIALLY FIXED)
**Status:** Circuit breaker already implemented in `ai/groq_client.py`
- Already has circuit breaker with CLOSED/OPEN/HALF_OPEN states
- Already handles 403 Forbidden with fallback to static payloads
- Already has exponential backoff and rate limiting

**Remaining work:**
- Add hard stop flag (`groq_circuit_open`) to agent.py - ✅ DONE
- Add explicit check in main loop to break when circuit is open for too long

### ✅ Issue #2: Loop Termination Condition (PARTIALLY FIXED)
**Status:** Variables added to agent.py
- Added `max_wall_clock_seconds = 8 * 3600` (8 hours hard limit)
- Added `max_iterations_hard_limit = 5`
- Added `_report_generated` flag

**Remaining work:**
- Add time check at start of each iteration
- Add explicit break after report generation
- Check `_report_generated` before spawning new iteration

### ✅ Issue #3: Scope Leak Prevention (PARTIALLY FIXED)
**Status:** Variables added to agent.py
- Added `external_domains_blacklist` set
- Added `allowed_domains_set` from allowed_domains list

**Remaining work:**
- Modify `modules/api_scanner.py` to filter URLs against allowed_domains
- Modify `modules/crawler.py` to enforce domain filtering
- Add domain validation before passing to any scanner

### 🔄 Issue #4: LIVE Probe Phase Optimization
**Required changes:**
- Use httpx results as input instead of probing all subdomains
- Implement async/concurrent probing with aiohttp
- Reduce timeout to 5-8s
- Skip hosts that already timed out

### 🔄 Issue #5: Katana Demotion
**Required changes in `modules/crawler.py`:**
- Make hakrawler the PRIMARY crawler
- Make katana optional/secondary
- Limit katana input to confirmed live hosts only
- Reduce katana timeout to 45s max

### 🔄 Issue #6: Nuclei Concurrency Reduction
**Required changes in `integrations/nuclei_runner.py`:**
- Reduce concurrent tasks from 150 to 20-30
- Add per-host rate limiting
- Add shorter timeout with retry logic

### 🔄 Issue #7: Param Miner False Positive
**Required changes in `modules/parameter_miner.py`:**
- Add baseline check comparing response with random param
- Detect soft-404 behavior before mining
- Filter endpoints returning same pattern response

### 🔄 Issue #8: Dalfox Timeout Caching
**Required changes in `integrations/dalfox_runner.py`:**
- Cache timeout/failure results per endpoint
- Share cache between iterations
- Skip endpoints that failed in previous iterations

### 🔄 Issue #9: Exploit Localhost Validation
**Required changes in `ai/chain_planner.py` and `core/exploit_executor.py`:**
- Validate target URL before starting exploit chain
- Abort if target resolves to localhost/127.0.0.1
- Add proper error handling for Unknown Step

### 🔄 Issue #10: Gobuster Parallel Execution
**Required changes in `modules/toolkit_scanner.py`:**
- Run gobuster in parallel for multiple hosts
- Use smaller wordlist for initial pass (top 500)

### 🔄 Issue #11: Wappalyzer Availability
**Required changes in `integrations/wappalyzer_runner.py`:**
- Install wappalyzer CLI or use API
- Or improve fallback pattern matching

### 🔄 Issue #12: Nikto Incomplete Scan
**Required changes in `modules/toolkit_scanner.py`:**
- Check nikto configuration
- Fix output format parsing
- Add proper timeout handling

## Files to Modify

1. **agent.py** - ✅ Done (added variables and flags)
2. **modules/api_scanner.py** - Add domain filtering
3. **modules/crawler.py** - Demote katana, enforce domain filtering
4. **integrations/nuclei_runner.py** - Reduce concurrency
5. **modules/parameter_miner.py** - Add soft-404 detection
6. **integrations/dalfox_runner.py** - Add failure caching
7. **ai/chain_planner.py** - Add localhost validation
8. **core/exploit_executor.py** - Add target validation
9. **modules/toolkit_scanner.py** - Parallel gobuster, fix nikto
10. **integrations/wappalyzer_runner.py** - Fix availability

## Priority Order

1. 🔴 **Issue #3** - Scope leak (security risk)
2. 🔴 **Issue #2** - Loop termination (resource waste)
3. 🟠 **Issue #6** - Nuclei concurrency (performance)
4. 🟠 **Issue #4** - LIVE probe optimization (performance)
5. 🟠 **Issue #5** - Katana demotion (performance)
6. 🟡 **Issue #8** - Dalfox caching (performance)
7. 🟡 **Issue #7** - Param miner false positives (quality)
8. 🟡 **Issue #9** - Localhost validation (correctness)
9. 🟡 **Issue #10** - Gobuster parallel (performance)
10. 🔵 **Issue #11** - Wappalyzer (quality)
11. 🔵 **Issue #12** - Nikto fix (quality)