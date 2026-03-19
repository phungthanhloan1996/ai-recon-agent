# WordPress Advanced Scan Integration Guide

## Overview

**wp_scan_cve.py** (Professional WordPress Security Audit tool) được nhúng vào **ai-recon-agent** pipeline với mục đích thu thập dữ liệu bổ sung về WordPress targets.

### Dữ liệu Thu thập:

1. **WordPress Version Detection** (7 methods)
   - Generator meta tag
   - RDF feed
   - CSS/JS file versions
   - WordPress feed
   - wp-links-opml.php
   - Login page version
   - Version confidence scoring

2. **PHP Version Analysis**
   - X-Powered-By headers từ 6 endpoints
   - Server header introspection
   - Consistency checks

3. **WordPress REST API Analysis**
   - API availability
   - User enumeration possibility
   - Endpoint accessibility

4. **Plugin Version Detection**
   - Specific plugins: contact-form-7, elementor, woocommerce, wp-file-manager
   - Passive detection từ HTML
   - Security implications

5. **Server Behavior Observation**
   - Rate limiting patterns
   - Error response behaviors
   - Authentication boundary analysis

## Architecture

### File Structure

```
ai-recon-agent/
├── integrations/
│   └── wp_advanced_scan.py          # Wrapper (NEW)
├── agent.py                          # Main agent (MODIFIED)
├── reports/
│   └── report_generator.py           # Report gen (MODIFIED)
└── [other files]
```

### Integration Points

```
agent.py :: _run_wordpress_phase()
  ├── 1. Run standard wpscan
  ├── 2. [NEW] Run advanced WordPress scan
  │   ├── WordPressAdvancedScan.run_data_collection()
  │   ├── Merge results via WordPressAdvancedScan.merge_into_state()
  │   └── Update display with findings
  └── 3. Continue with toolkit phase
```

## Workflow

### Phase: WordPress Detection (Modified)

```python
# In _run_wordpress_phase():

1. wp_sites = self.wp_scanner.scan_wordpress_sites(target_urls)
   # Standard WPScan + fingerprinting

2. for site_url in target_urls:
     advanced_scan = WordPressAdvancedScan(site_url)
     scan_data = advanced_scan.run_data_collection()
     
     # Data collection methods called:
     # - assess_static_indicators()     → PHP version, directory listing
     # - observe_server_behaviors()      → Rate handling, error patterns, auth
     # - analyze_observational_context() → Version security implications
     
     self.state = WordPressAdvancedScan.merge_into_state(
         self.state, 
         scan_data
     )

3. Report generation includes wordpress_advanced_scan data
```

## Data Field Mappings

### state.json After Merge

```json
{
  "cms_version": "WordPress 5.6.1",
  "wordpress_eol": true,
  "server_php_version": "7.3.0",
  "php_outdated": true,
  "wordpress_rest_api_enabled": true,
  "user_enumeration_via_api": true,
  "plugins": [...merged with advanced scan detection...],
  "confirmed_vulnerabilities": [
    ...existing vulns...
    {
      "type": "EOL_WORDPRESS_VERSION",
      "severity": "HIGH",
      "version": "5.6.1",
      "description": "WordPress version is end-of-life..."
    },
    {
      "type": "OUTDATED_PHP_VERSION",
      "severity": "HIGH",
      "version": "7.3.0",
      "description": "PHP version is outdated..."
    },
    {
      "type": "USER_ENUMERATION_REST_API",
      "severity": "MEDIUM",
      "description": "User enumeration possible via REST API..."
    }
  ],
  "scan_observations": {
    "posture_indicators": [...],
    "behavioral_patterns": [...],
    "reality_context": [...]
  },
  "technical_details": {
    "wordpress_advanced_scan": {
      "target": "https://example.com",
      "timestamp": 1234567890.123,
      "version_detection": {
        "wp_version": "5.6.1",
        "confidence": "high",
        "methods": ["generator_meta", "css_versions"],
        "eol": true
      },
      "php_analysis": {
        "php_version": "7.3.0",
        "php_versions_found": ["7.3.0"],
        "consistent_across_endpoints": true,
        "outdated": true
      },
      "wordpress_api": {
        "rest_api_enabled": true,
        "api_version": "v2_available",
        "user_enumeration_possible": true,
        "users_endpoint_accessible": true
      },
      "plugin_versions": {
        "detected_plugins": [...],
        "count": 5
      },
      "server_behaviors": {
        "rate_handling": {...},
        "error_patterns": {...},
        "auth_boundaries": {...}
      },
      "observations": {
        "posture_indicators": [...],
        "behavioral_patterns": [...],
        "reality_context": [...]
      }
    }
  }
}
```

### final_report.json Integration

```json
{
  "assessment_info": {...},
  "summary": {...},
  "findings": {...},
  "attack_surface": {...},
  "technical_details": {
    "scan_responses": ...,
    "iterations_performed": ...,
    "learning_data": ...,
    "manual_validation": {...},
    "manual_attack_playbook": [...],
    "wordpress_advanced_scan": {
      // All advanced scan data included directly
    }
  }
}
```

## Vulnerability Detection

### Automatic Vulnerabilities Added

Based on advanced scan findings:

1. **EOL WordPress Version**
   - Detected: WordPress version < 6.0
   - Severity: HIGH
   - Reason: No longer receiving security updates
   - Implication: Likely contains known vulnerabilities

2. **Outdated PHP Version**
   - Detected: PHP 5.x, 7.0-7.4
   - Severity: HIGH
   - Reason: End-of-life, no active maintenance
   - Implication: Missing critical security patches

3. **User Enumeration via REST API**
   - Detected: /wp-json/wp/v2/users endpoint accessible
   - Severity: MEDIUM
   - Reason: User discovery without authentication
   - Implication: Information disclosure for targeted attacks

4. **Directory Listing**
   - Detected: /wp-content/uploads directory browsable
   - Severity: MEDIUM
   - Reason: Unintended file exposure
   - Implication: Potential for malicious file discovery/upload

## Attack Chain Enrichment

Advanced scan data enhances attack chains with new preconditions:

### Preconditions (Enhanced)

```json
{
  "preconditions": {
    "wordpress_version_known": true,
    "wordpress_eol": true,
    "php_version_known": true,
    "php_outdated": true,
    "user_enumeration_possible": true,
    "plugins_detected": 5,
    "vulnerable_plugins": [
      {
        "name": "contact-form-7",
        "version": "5.1.0",
        "vulnerability": "known_cve"
      }
    ]
  }
}
```

### New Attack Vectors

1. **Version-Specific Exploits**
   - WP 5.6.1 has specific CVEs
   - PHP 7.3 has specific CVEs
   - Chain can target exact versions

2. **Plugin-Based Attacks**
   - Advanced scan identifies plugin versions
   - Known exploits matched to exact versions
   - Probability of success increases

3. **User Enumeration → Brute Force**
   - REST API user enum identifies valid users
   - Wordlist generation targets those users
   - Brute force has higher success rate

## Performance Characteristics

### Timing

- Per target: ~8-15 seconds (7 WordPress detection methods + 6 PHP checks + 3 plugins)
- Rate limiting: 1.5s between checks to avoid triggering WAF
- Parallel execution: NOT recommended (use sequential to avoid rate limits)

### Requests per Target

- WordPress version detection: ~8 HTTP requests
- PHP header checks: ~6 HTTP requests
- REST API checks: ~2 HTTP requests
- Plugin checks: ~12 HTTP requests (4 plugins × 3 files)
- Behavior observation: ~15 HTTP requests
- **Total: ~45 HTTP requests per target**

### Output Artifacts

- state.json: Updated with all advanced scan data
- final_report.json: Includes technical_details.wordpress_advanced_scan
- scan_observations: Stored in state for exploitation phase

## Configuration

### Timeouts

```python
# In _run_wordpress_phase():
advanced_scan = WordPressAdvancedScan(site_url, timeout_per_check=8)
```

- Default: 8 seconds per HTTP request
- Adjust based on target network speed
- Lower timeout (5-6s) for faster targets
- Higher timeout (10-12s) for slow targets

### Rate Limiting

```python
time.sleep(1.5)  # Between targets
```

- Built-in 1.5s delay between target scans
- Prevents rate limiting from target WAF
- Reduces false "timeout" errors

## Logging & Display

### Console Output

```
[ADVANCED SCAN] Analyzing dolphin-vc.com...
[WORDPRESS] Version: 5.6.1 (EOL)
[PHP] Version: 7.3.0 (OUTDATED)
[SECURITY] User enumeration possible via REST API
[SECURITY] Found 3 security observations
⚠️ EOL_WORDPRESS_VERSION dolphin-vc | WordPress version is end-of-life...
⚠️ OUTDATED_PHP_VERSION dolphin-vc | PHP version is outdated...
⚠️ USER_ENUMERATION_REST_API dolphin-vc | User enumeration possible via...
```

### Debug Logging

```python
# Only in DEBUG mode:
self.logger.debug("[WORDPRESS] Running advanced security scan on detected targets...")
self.logger.debug("[ADVANCED SCAN] Error for {site_url}: {error}")
```

## Error Handling

### Graceful Degradation

If wp_scan_cve module not available:
```python
WP_SCAN_CVE_AVAILABLE = False
# Wrapper returns empty/fallback data
# scan continues without advanced findings
```

### Per-Target Error Handling

```python
try:
    scan_data = advanced_scan.run_data_collection()
    # Merge and continue
except Exception as e:
    self.logger.debug(f"Advanced scan error: {str(e)[:60]}")
    # Continue with next target
```

## Verification Checklist

- [x] Wrapper module imports correctly
- [x] No report generation (data-only)
- [x] Results merge into state.json
- [x] final_report.json includes advanced_scan
- [x] Vulnerabilities auto-detected from version/PHP
- [x] Attack chains get new preconditions
- [x] Timeout and rate limiting configured
- [x] Error handling graceful
- [x] Display shows findings in real-time

## Example Output

### state.json snippet

```json
{
  "wordpress_advanced_scan": {
    "target": "https://dolphin-vc.com",
    "version_detection": {
      "wp_version": "5.6.1",
      "confidence": "high",
      "methods": ["generator_meta", "css_versions", "feed"],
      "eol": true
    },
    "php_analysis": {
      "php_version": "7.3.0",
      "consistent_across_endpoints": true,
      "outdated": true
    },
    "wordpress_api": {
      "rest_api_enabled": true,
      "user_enumeration_possible": true
    },
    "vulnerabilities": [
      {
        "type": "EOL_WORDPRESS_VERSION",
        "severity": "HIGH"
      },
      {
        "type": "OUTDATED_PHP_VERSION", 
        "severity": "HIGH"
      },
      {
        "type": "USER_ENUMERATION_REST_API",
        "severity": "MEDIUM"
      }
    ]
  }
}
```

## Testing

### Manual Test

```bash
cd /home/root17/Desktop/ai-recon-agent

# Test wrapper alone
python3 -c "
from integrations.wp_advanced_scan import WordPressAdvancedScan

scanner = WordPressAdvancedScan('http://dolphin-vc.com')
data = scanner.run_data_collection()  # Fallback if wp_scan_cve unavailable
print('Version Detection:', data['version_detection'])
print('PHP Analysis:', data['php_analysis'])
print('Vulnerabilities:', len(data['vulnerabilities']))
"

# Test integration in pipeline
python3 agent.py -t dolphin-vc.com
```

### Expected Behavior

1. Agent runs standard WPScan phase
2. After wpscan, advanced scan runs on same targets
3. Results merge into state.json automatically
4. final_report.json includes technical_details.wordpress_advanced_scan
5. Console shows security observations for each target

## Future Enhancements

1. **Parallel Target Scanning**: Handle multiple targets with worker pool
2. **Credential Testing**: Use discovered credentials from auth phase
3. **Exploit Targeting**: Auto-select exploits based on detected versions
4. **Historical Tracking**: Compare versions across scan iterations
5. **Custom Rules**: Add organization-specific vulnerability matching

---

## Summary

✅ **Integration Complete**

- wp_scan_cve.py embedded as data-only component
- Runs immediately after WordPress detection
- Results automatically merge into state + reports  
- New vulnerabilities auto-detected from versions
- Attack chains enriched with new preconditions
- No report generation or console spam
- Ready for production use

