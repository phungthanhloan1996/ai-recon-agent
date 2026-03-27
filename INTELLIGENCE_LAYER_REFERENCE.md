# Intelligence Layer Quick Reference

## How the Enhanced AI Components Work Together

### Phase 1: Endpoint Classification
**Module**: `ai/endpoint_classifier.py`  
**Input**: URL, path, parameters, response context  
**Output**: Endpoint type, interest level, exploitation hints, chain potential

**Enhanced Behavior**:
- 🎯 **Prioritizes**: File upload, plugin management, authentication, APIs
- 🔍 **Analyzes**: high_impact_indicators, exploit_chains
- ⚡ **Confidence**: HIGH for upload endpoints (direct RCE), MEDIUM for data endpoints

**Example**:
```
Input: /admin/upload.php
Output: {
  endpoint_type: "admin_file_upload",
  interest_level: "CRITICAL" (0.98),
  exploitation_hints: ["file_upload_bypass", "rce_via_upload"],
  chain_potential: "UPLOAD → BYPASS → EXECUTE → RCE"
}
```

---

### Phase 2: Response Analysis
**Module**: `ai/analyzer.py`  
**Input**: Endpoint responses, endpoint data, vulnerability detection  
**Output**: Exploitation chains, business impact, vulnerability assessment

**Key Methods**:

#### `_score_endpoint_risk()` - Risk Scoring
Takes any endpoint and scores it 0.0-1.0 based on exploitation potential:

| Endpoint Type | Score | Reasoning |
|--------------|-------|-----------|
| File upload | 0.95-0.98 | Direct RCE path |
| Plugin mgmt | 0.92 | Code execution |
| Unauth admin | 0.95 | Instant compromise |
| Unauth auth | 0.85 | Access bypass |
| Protected admin | 0.70 | Escalation target |
| APIs | 0.75-0.88 | Data/control manipulation |
| Webhooks | 0.78 | SSRF potential |

**How It Works**:
1. Evaluates endpoint type (upload/admin/api/etc)
2. Checks vulnerability hints (RCE, auth bypass, IDOR)
3. Counts dangerous parameters (cmd, exec, id, path, file)
4. Analyzes URL patterns for high-value targets
5. Returns score reflecting real exploitation potential

#### `_detect_misconfigurations()` - High-Impact Issues
Identifies security issues that lead to compromise:

**CRITICAL**:
- Unauthenticated admin panels
- Unprotected file upload
- Unauthenticated sensitive APIs

**HIGH**:
- Backup files exposed
- Debug endpoints active
- Configuration files leaked
- Source code accessible

#### `build_attack_context()` - Chain Aggregation
Builds comprehensive attack intelligence:
- Identifies file upload + execution chains
- Maps IDOR patterns and data access
- Finds authentication bypass opportunities
- Highlights plugin vulnerabilities
- Structures data for chain planning

**Enhanced Behavior**:
- 🔗 **Chains vulnerabilities**: Upload + exec, auth + escalate
- 💼 **Business impact**: RCE = CRITICAL, data theft = HIGH
- 📊 **Prioritization**: Sorts by real-world exploitation likelihood

---

### Phase 3: Chain Planning
**Module**: `ai/chain_planner.py`  
**Input**: Vulnerabilities, endpoints, attack context  
**Output**: Multi-step exploitation chains with prerequisites

**Chain Categories**:

#### 1️⃣ File Upload → RCE (4-5 steps)
```
1. Discover upload endpoint
2. Test bypass techniques (extension, MIME, polyglot)
3. Upload webshell to accessible directory
4. Access shell at predictable path
5. Execute -> WHOAMI -> RCE
```
**Risk**: 0.95+ | **Impact**: CRITICAL

#### 2️⃣ Auth Bypass → Escalation (4-5 steps)
```
1. Enumerate users/auth endpoints
2. Test bypass (IDOR, weak tokens, JWT)
3. Access as other user
4. Check for admin functionality
5. Escalate -> admin access
```
**Risk**: 0.85+ | **Impact**: CRITICAL

#### 3️⃣ API Abuse → Compromise (4-5 steps)
```
1. Enumerate API endpoints
2. Identify missing/weak auth
3. Manipulate IDs or roles
4. Access privileged operations
5. Extract data or modify system
```
**Risk**: 0.75+ | **Impact**: HIGH

#### 4️⃣ LFI → Code Execution (3-4 steps)
```
1. Find LFI endpoint (file, path, page param)
2. Read sensitive files (config, .env, source)
3. Extract credentials or write location
4. Achieve code execution/data theft
```
**Risk**: 0.72+ | **Impact**: HIGH-CRITICAL

#### 5️⃣ Command Injection → Shell (3-4 steps)
```
1. Identify parameters reaching system commands
2. Test command separators (;, |, &, etc)
3. Inject reverse shell payload
4. Full server compromise
```
**Risk**: 0.80+ | **Impact**: CRITICAL

#### 6️⃣ SSRF Chain (4 steps)
```
1. Find URL parameter (webhook, callback, fetch)
2. Direct to internal services (127.0.0.1, metadata)
3. Extract credentials/tokens
4. Use for further compromise
```
**Risk**: 0.78+ | **Impact**: HIGH

#### 7️⃣ Plugin Exploitation (4 steps)
```
1. Enumerate plugins
2. Identify vulnerable versions
3. Exploit known vulnerability
4. RCE or admin access
```
**Risk**: 0.70+ | **Impact**: CRITICAL

---

## Intelligence Flow Diagram

```
ENDPOINTS DISCOVERED
        ↓
┌──────────────────────────────────────────┐
│ ENDPOINT CLASSIFIER                      │
│ - Identifies critical attack vectors     │
│ - Scores interest level                  │
│ → Upload? Plugin? Auth? API?             │
└──────────────────┬───────────────────────┘
                   ↓ (HIGH-PRIORITY ENDPOINTS)
┌──────────────────────────────────────────┐
│ RESPONSE ANALYZER                        │
│ - _score_endpoint_risk() [0.0-1.0]       │
│ - _detect_misconfigurations()            │
│ - build_attack_context()                 │
│ → Chains vulnerabilities together        │
│ → Identifies exploitation prerequisites  │
└──────────────────┬───────────────────────┘
                   ↓ (VULNERABILITY CHAINS)
┌──────────────────────────────────────────┐
│ CHAIN PLANNER                            │
│ - Designs multi-step exploitation        │
│ - Validates prerequisites                │
│ - Prioritizes by impact                  │
│ → RCE > Admin > Data                     │
└──────────────────┬───────────────────────┘
                   ↓ (RANKED EXPLOIT CHAINS)
┌──────────────────────────────────────────┐
│ EXPLOIT EXECUTOR                         │
│ - Tests chains in priority order         │
│ - Validates each step                    │
│ - Confirms successful compromise         │
└──────────────────────────────────────────┘
```

---

## Scoring Reference

### Endpoint Risk Scores (0.0 - 1.0)

| Score | Type | Exploitation Path | Priority |
|-------|------|-------------------|----------|
| 0.98+ | Upload endpoint | Direct RCE | 🔴 CRITICAL |
| 0.95+ | Unauthenticated admin | Full compromise | 🔴 CRITICAL |
| 0.92+ | Plugin management | Code execution | 🔴 CRITICAL |
| 0.88+ | API with file operations | RCE or data theft | 🔴 CRITICAL |
| 0.85+ | Unprotected auth endpoint | Access bypass | 🔴 CRITICAL |
| 0.78+ | Webhook/callback | SSRF chain | 🟠 HIGH |
| 0.75+ | General API | Data manipulation | 🟠 HIGH |
| 0.72+ | File download | LFI/traversal | 🟠 HIGH |
| 0.65+ | Data endpoint | IDOR potential | 🟠 HIGH |
| 0.50-0.65 | Form/auth | Investigation needed | 🟡 MEDIUM |
| 0.30-0.50 | General endpoint | Low priority | 🟡 MEDIUM |
| <0.30 | Static/info only | Reconnaissance | 🟢 LOW |

---

## Key Scoring Multipliers

### Amplification Factors in `_score_endpoint_risk()`:
```python
File upload endpoint:           +0.95 (base)
Plugin management:              +0.92
Unauth admin:                   +0.95
Protected admin:                +0.70 + param analysis

RCE hint detected:              +0.25 bonus
Auth bypass hint:               +0.20 bonus
IDOR/privilege hint:            +0.20 bonus
SSRF/LFI hint:                  +0.15 bonus

Each dangerous parameter:       +0.08 (cmd, exec, id, path, url)
Active endpoint (200):          +0.12
Protected endpoint (401):       +0.05

High-value URL pattern:         +0.10
Debug/test endpoint:            +0.08
```

**Example Calculation**:
```
Base: File upload endpoint          = 0.95
+ Status 200 (active)              = +0.12
+ Parameter 'file'                 = +0.08
+ Parameter 'type'                 = +0.08
+ RCE hint detected               = +0.25
TOTAL SCORE                        = 1.0 (capped)
→ CRITICAL: Execute immediately
```

---

## Real-World Exploitation Examples

### Example 1: E-commerce Upload Vulnerability
```
DISCOVERED: POST /api/product/upload
CLASSIFICATION:
  - endpoint_type: "api_file_upload"
  - interest_level: "CRITICAL" (0.96)
  - hints: ["file_upload", "rce_potential"]

ANALYSIS:
  - File upload without extension validation
  - Accessible at /uploads/products/
  - Test bypass with shell.php.jpg

CHAIN:
  1. Enumerate endpoint via OPTIONS
  2. Test PHP double extension bypass
  3. Upload webshell as product image
  4. Access /uploads/products/shell.php
  5. Execute arbitrary commands
  6. Establish persistence
  
IMPACT: CRITICAL - Full application compromise
```

### Example 2: WordPress Vulnerability
```
DISCOVERED: GET /wp-admin/plugin-editor.php (unprotected)
CLASSIFICATION:
  - endpoint_type: "plugin_management"
  - interest_level: "CRITICAL" (0.92)
  - hints: ["admin_access", "code_execution"]

ANALYSIS:
  - Unprotected admin endpoint
  - Direct plugin code editor access
  - No authentication required

CHAIN:
  1. Access /wp-admin/plugin-editor.php
  2. Select any plugin file
  3. Insert PHP webshell code
  4. Access plugin file at /wp-content/plugins/
  5. RCE confirmation

IMPACT: CRITICAL - Full site compromise, database access
```

### Example 3: API Parameter Injection
```
DISCOVERED: POST /api/users/export
CLASSIFICATION:
  - endpoint_type: "api_export"
  - interest_level: "HIGH" (0.72)
  - hints: ["file_operation", "injection_point"]
  - parameter: "format" (dangerous)

ANALYSIS:
  - Format parameter not sanitized
  - Could allow command injection
  - Test CSV injection or command execution

CHAIN:
  1. Enumerate export formats (csv, pdf, xml)
  2. Test command injection: format=`whoami`
  3. Achieve RCE via command execution
  4. Extract all user data

IMPACT: HIGH - Data breach, server access
```

---

## How to Improve the Intelligence Layer

### 1. **Add New Chain Patterns**
Update `ai/chain_planner.py` system prompt with new exploitation scenarios:
```python
_CHAIN_PLANNER_SYSTEM += """
NEW PATTERN: Deserialization gadget chains
- Identify serialized data (base64, binary)
- Test with known gadget chains (ysoserial)
- Trigger RCE via deserialization
"""
```

### 2. **Enhance Risk Scoring**
Adjust multipliers in `_score_endpoint_risk()` based on observed patterns:
```python
# If certain patterns consistently successful, increase weight
if 'dangerous_pattern' in url and status == 200:
    score += 0.30  # Increased from 0.20
```

### 3. **Add Technology-Specific Detection**
Enhance `_detect_misconfigurations()` for WordPress, Node.js, etc:
```python
if 'wordpress' in technologies:
    # Check for WP-specific vulnerabilities
    if wp_version and known_vulnerable(wp_version):
        score += 0.25
```

### 4. **Learn from Successful Chains**
Track working exploitation patterns and increase confidence:
```python
if exploit_succeeded:
    learning_engine.record_successful_chain(chain, target_tech)
    # Future similar targets → increased confidence
```

---

## Debugging Intelligence Layer

### Check Endpoint Classification
```python
from ai.endpoint_classifier import EndpointClassifier
classifier = EndpointClassifier()
result = classifier.classify({
    'url': 'http://target.com/admin/upload.php',
    'parameters': ['file', 'name']
})
print(result['interest_level'])  # Should be CRITICAL
```

### Verify Risk Scoring
```python
from ai.analyzer import AIAnalyzer
analyzer = AIAnalyzer(state, output_dir)
score = analyzer._score_endpoint_risk({
    'url': 'http://target.com/upload',
    'endpoint_type': 'file_upload',
    'status_code': 200
})
print(score)  # Should be 0.95+
```

### Test Chain Generation
```python
from ai.chain_planner import ChainPlanner
planner = ChainPlanner(state)
chains = planner.plan_chains(vulnerabilities, endpoints)
for chain in chains:
    print(f"{chain.name}: {chain.steps}")  # Should include all exploitation steps
```

---

## Performance Notes

- 📊 **Scoring**: ~1-5ms per endpoint
- 🔗 **Chain generation**: 100-500ms for vulnerability set
- 💾 **Memory**: Proportional to endpoint count (linear)
- ⚡ **Optimization**: Batches misconfigurations by severity

---

## Documents Reference

- **Framework**: `/memories/session/penetration_tester_framework.md`
- **Enhancement Guide**: `INTELLIGENCE_LAYER_ENHANCEMENT.md`
- **Integration Status**: `/memories/session/integration_complete.md`
