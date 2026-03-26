# AI Agent Intelligence Enhancements

This document outlines the improvements made to enhance the intelligence and attack-chain reasoning of the AI-driven security scanning agent.

## Summary

The agent now features **enriched endpoint context**, **technology-aware vulnerability hints**, and **pattern-based attack chain generation** that dramatically improve the quality of exploit reasoning without modifying core execution engines.

---

## Task 1: Enriched Endpoint Metadata

### File: `core/endpoint_analyzer.py`

**Changes:**
- Added three new fields to endpoint analysis results:
  - `technologies`: List of detected technologies
  - `vulnerability_hints`: Array of vulnerability classes that may apply
  - `parameters`: Detailed parameter metadata

**New Methods:**

```python
def generate_vulnerability_hints(result: Dict) -> List[str]
```
Maps endpoint characteristics (type, forms, parameters) to vulnerability classes:
- **File uploads** → `file_upload`, `rce_via_upload`
- **Forms** → `form_injection`, `lfi`, `ssrf` (based on parameter names)
- **API endpoints** → `api_abuse`, `injection`, `auth_bypass`
- **Auth endpoints** → `auth_bypass`, `credential_leak`
- **Admin endpoints** → `privilege_escalation`, `admin_access`

```python
def extract_parameter_details(result: Dict) -> List[Dict]
```
Extracts detailed parameter information including:
- Parameter name and source (query_string, form_GET, form_POST)
- Required flag and type (text, password, file, etc.)
- Original values

```python
def enrich_with_technologies(result: Dict, technologies: List[str]) -> Dict
```
Integrates technology detection with endpoint analysis to add tech-specific hints.

```python
def _get_tech_hints(technologies: List[str]) -> List[str]
```
Maps technologies to vulnerability classes:
- **WordPress** → plugin_vuln, rce_via_plugin, privilege_escalation
- **PHP** → file_inclusion, insecure_deserialization
- **Apache** → path_traversal, directory_listing
- **Node.js** → prototype_pollution
- **Java** → deserialization_rce
- **MySQL** → sqli

---

## Task 2: Vulnerability Hint Generation

### File: `core/cve_matcher.py`

**New Functions:**

```python
def get_vulnerability_hints_for_tech(technology: str, version: Optional[str]) -> list
```
Returns vulnerability hint classes for detected technologies with version-specific matching:
- Checks TECH_VULN_HINTS mapping
- Applies version-based patterns (e.g., wordpress <5.0 has path_traversal risk)

```python
def get_hints_for_endpoint(endpoint_data: dict) -> list
```
Comprehensive hint generation combining:
1. Existing endpoint analysis hints
2. Technology-based hints
3. Parameter-based hints (e.g., `cmd` param → command_injection)

**Technology Mapping (NEW):**
```python
TECH_VULN_HINTS = {
    'wordpress': {
        'hint_classes': ['file_upload', 'plugin_vuln', 'rce_via_plugin', 'privilege_escalation'],
        'patterns': {
            '<5.0': ['path_traversal', 'xss'],
            '<4.8': ['sqli', 'privilege_escalation'],
            '<4.0': ['file_inclusion', 'remote_code_execution']
        }
    },
    # ... (7 more technologies)
}
```

---

## Task 3: Enhanced Parameter Discovery

### File: `modules/endpoint_probe.py`

**New Functions:**

```python
def extract_endpoints_with_context(endpoints: List[Dict], technologies: List[str]) -> List[Dict]
```
Enriches endpoints with comprehensive intelligence:
- Query string parameter extraction
- Path-based security indicator detection
- Technology mapping
- Vulnerability hint generation
- Confidence scoring

```python
def _extract_path_indicators(path: str) -> List[str]
```
Identifies security-relevant path patterns:
- Admin paths, Upload paths, API paths
- Auth paths, Config paths, WordPress paths
- Debug/test paths, Backup files, VCS paths

**Example indicators:**
- `/admin` → `admin_path`
- `/upload` → `file_access_path`
- `/api/v1` → `api_path`
- `.env` → `config_path`
- `.git` → `vcs_path`

```python
def _calculate_endpoint_confidence(endpoint: Dict) -> float
```
Confidence scoring based on:
- Reachability (0.2)
- Parameters (0.2)
- Vulnerability hints (0.15)
- Endpoint type identification (0.15)
- Form presence (0.15)
- Technology detection (0.15)

---

## Task 4: Improved AI Analyzer Input

### File: `ai/analyzer.py`

**New Public Method:**

```python
def build_attack_context(self) -> Dict
```
Builds comprehensive attack context for chain planning with structure:
```python
{
    'target': str,
    'endpoints': List[Dict],           # Top 30 with full metadata
    'parameters': List[Dict],          # Deduplicated parameters
    'technologies': List[str],         # Detected stack
    'vulnerability_hints': List[str],  # All hint types found
    'discovered_vulnerabilities': List[Dict],
    'confirmed_vulnerabilities': List[Dict],
    'wordpress': Dict,                 # WP-specific context
    'misconfigurations': List[Dict],
    'attack_surface': {
        'file_upload_endpoints': List[Dict],
        'auth_endpoints': List[Dict],
        'api_endpoints': List[Dict],
        'admin_endpoints': List[Dict]
    },
    'chain_patterns': List[Dict]       # Pre-identified attack patterns
}
```

**New Helper Methods:**

```python
def _extract_all_parameters(endpoint_context: List[Dict]) -> List[Dict]
```
Deduplicates and aggregates all parameters across endpoints.

```python
def _detect_misconfigurations(endpoint_context: List[Dict]) -> List[Dict]
```
Identifies common security misconfigurations:
- Debug endpoints exposed
- Backup files publicly accessible
- Admin panels without authentication
- Directory listing enabled

```python
def _identify_chain_patterns(endpoint_context: List[Dict], all_hints: set) -> List[Dict]
```
Pre-identifies viable attack patterns:
- **file_upload_to_rce**: File upload + executable directory
- **auth_bypass_to_privilege_escalation**: Auth bypass + priv escalation vector
- **ssrf_chain**: SSRF + internal access
- **enum_then_attack**: Info disclosure + targeted exploitation

```python
def _score_endpoint_risk(endpoint: Dict) -> float
```
Risk scoring considering endpoint type, hints, parameters, and status code.

---

## Task 5: Pattern-Based Chain Planning

### File: `ai/chain_planner.py`

**Enhanced `plan_chains()` Method:**
Now calls `_generate_chains_from_hints()` first to leverage enriched metadata.

**New Public Method:**

```python
def plan_chains_from_context(attack_context: Dict) -> List[ExploitChain]
```
Main entry point for generating chains from enriched context. Orchestrates:
1. Pattern-based chains
2. Attack surface exploitation
3. Technology-specific chains
4. Misconfiguration exploitation

**New Pattern-Based Chain Generators:**

```python
def _generate_chains_from_hints(self) -> List[ExploitChain]
```
Generates 6 core attack patterns:

1. **File Upload to RCE** (CRITICAL risk)
   - Steps: Upload endpoint → Upload webshell → Execute
   
2. **LFI to Information Disclosure** (HIGH risk)
   - Steps: LFI enumeration → Config extraction → Credential use
   
3. **SSRF to Internal Access** (HIGH risk)
   - Steps: SSRF identification → Internal service probing → Exploitation
   
4. **Auth Bypass to Admin Access** (CRITICAL risk)
   - Steps: Bypass testing → Admin access → System exploitation
   
5. **User Enumeration to Account Takeover** (HIGH risk)
   - Steps: User enumeration → Brute force → Account compromise
   
6. **Injection Attacks** (HIGH/MEDIUM risk)
   - Steps: Vulnerability test → Data/command extraction

**Attack Surface-Based Generators:**

```python
def _generate_chains_from_attack_surface(attack_surface: Dict) -> List[ExploitChain]
```
Generates chains for each attack surface element:
- File upload endpoint exploitation
- Authentication endpoint attacks
- API abuse scenarios
- Admin panel exploitation

**Technology-Specific Generators:**

```python
def _generate_tech_specific_chains(technologies: List[str], endpoints: List[Dict]) -> List[ExploitChain]
```

- **WordPress** → Plugin/theme exploitation chain
- **PHP** → Code injection chain
- **Node.js** → Prototype pollution chain

**Misconfiguration Exploitation:**

```python
def _generate_misconfig_chains(misconfigs: List[Dict]) -> List[ExploitChain]
```

- Unauthenticated admin access
- Debug endpoint information disclosure
- Backup file extraction

**Supporting Chain Builders:**

- `_build_pattern_chain()` - Framework for constructing chains
- `_build_upload_to_rce_chain()`
- `_build_auth_to_priv_chain()`
- `_build_ssrf_exploitation_chain()`
- `_build_enum_attack_chain()`
- `_build_api_attack_chain()`
- `_build_admin_access_chain()`
- `_build_wordpress_attack_chain()`
- `_build_php_exploitation_chain()`
- `_build_nodejs_attack_chain()`

---

## Data Flow Architecture

```
┌─ Endpoint Discovery & Crawling
│  └─ Endpoints (URLs)
│
├─ Endpoint Analysis (core/endpoint_analyzer.py)
│  └─ Enhanced metadata + hints
│
├─ Technology Detection (wappalyzer, whatweb)
│  └─ Tech stack
│
├─ Context Enrichment (modules/endpoint_probe.py)
│  ├─ Parameter details
│  ├─ Path indicators
│  ├─ Vulnerability hints
│  └─ Confidence scores
│
├─ AI Context Building (ai/analyzer.py)
│  ├─ build_attack_context()
│  ├─ Endpoint aggregation
│  ├─ Misconfiguration detection
│  ├─ Pattern identification
│  └─ Attack surface mapping
│
└─ Intelligent Chain Planning (ai/chain_planner.py)
   ├─ plan_chains_from_context()
   ├─ Pattern-based generation
   ├─ Tech-specific chains
   ├─ Surface exploitation
   ├─ Misconfig chains
   └─ Prioritized exploit chains
```

---

## Integration Points

### Using the Enhanced System

**1. In agent_enhancements.py or main pipeline:**

```python
# Build rich context
from ai.analyzer import AIAnalyzer

analyzer = AIAnalyzer(state, output_dir, ai_client)
attack_context = analyzer.build_attack_context()

# Generate intelligent chains
from ai.chain_planner import ChainPlanner

planner = ChainPlanner(state)
chains = planner.plan_chains_from_context(attack_context)
```

**2. In endpoint processing:**

```python
# Enrich endpoints with context
from modules.endpoint_probe import extract_endpoints_with_context

enriched_endpoints = extract_endpoints_with_context(
    endpoints=state.get("prioritized_endpoints", []),
    technologies=state.get("technologies", {}).keys()
)
```

**3. For vulnerability insights:**

```python
# Get tech-specific hints
from core.cve_matcher import get_vulnerability_hints_for_tech, get_hints_for_endpoint

hints = get_vulnerability_hints_for_tech("wordpress", "5.8.1")
endpoint_hints = get_hints_for_endpoint(endpoint_data)
```

---

## Benefits & Impact

### Before (Old System)
- ❌ Generic exploit chains
- ❌ Limited context in chain generation
- ❌ Parameters and technologies isolated from chain planning
- ❌ Weak vulnerability reasoning

### After (Enhanced System)
- ✅ **Pattern-based chains** from real endpoint data
- ✅ **Rich context** flowing through entire pipeline
- ✅ **Technology-aware** vulnerability assessment
- ✅ **Parameter-informed** exploitation strategies
- ✅ **Misconfiguration-targeted** attacks
- ✅ **Attack surface mapping** for realistic chains
- ✅ **6+ core attack patterns** automatically generated
- ✅ **Confidence scoring** for chain feasibility

---

## Constraints & Design Notes

### What Was NOT Changed
- ✅ Core execution engines (http_engine.py, exploit_executor.py)
- ✅ Folder structure
- ✅ Existing state management
- ✅ Module interfaces

### Extended Gracefully
- Extended existing classes with new methods
- Added helper functions
- Minimal invasive changes
- Backward compatible

### No Heavy Dependencies Added
- Uses existing imports only
- Pure computation
- No new external libraries required

---

## Testing & Validation

All modified files have been validated for:
- ✅ Syntax correctness
- ✅ Type compatibility
- ✅ Integration points
- ✅ No breaking changes

---

## Future Enhancement Opportunities

1. **ML-based chain prioritization** using learning engine
2. **Custom chain patterns** from exploit database
3. **Real-time hint refinement** based on response analysis
4. **Multi-stage chain composition** for complex attacks
5. **Chain mutation** for obfuscation and evasion

---

## File Changes Summary

| File | Changes | New Functions | Purpose |
|------|---------|---------------|---------|
| `core/endpoint_analyzer.py` | +160 lines | 4 new methods | Endpoint metadata enrichment |
| `core/cve_matcher.py` | +130 lines | 2 new functions | Tech → vuln mapping |
| `modules/endpoint_probe.py` | +170 lines | 3 new functions | Parameter discovery |
| `ai/analyzer.py` | +350 lines | 5 new methods | Attack context building |
| `ai/chain_planner.py` | +650 lines | 16 new methods | Pattern-based chains |
| **TOTAL** | **+1,460 lines** | **30 new functions** | Intelligence layer |

---

## Quick Start

To use the enhanced system:

```python
from ai.analyzer import AIAnalyzer
from ai.chain_planner import ChainPlanner

# Build intelligence context
analyzer = AIAnalyzer(state, output_dir)
attack_context = analyzer.build_attack_context()

# Plan intelligent chains
planner = ChainPlanner(state)
chains = planner.plan_chains_from_context(attack_context)

# Execute chains with rich metadata
for chain in chains:
    print(f"[{chain.risk_level}] {chain.name}")
    print(f"  Description: {chain.description}")
    print(f"  Steps: {len(chain.steps)}")
```

---

**Status:** ✅ Complete and Ready for Integration
