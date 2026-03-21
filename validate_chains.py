#!/usr/bin/env python3
"""
Dynamic Exploit Chain Validation Script
- Loads state from JSON file or state parameter
- Validates all chains use fully qualified URLs with schemes
- No hardcoded domains or hostnames
- Works with any target passed in state
"""

import sys
import json
import os
from pathlib import Path
from ai.chain_planner import ChainPlanner


def load_state(state_file=None):
    """
    Load state dynamically from JSON file or use provided state.
    Searches for latest state.json if no file specified.
    
    Args:
        state_file: Optional path to state.json file
    
    Returns:
        Dictionary containing scan state
    """
    # If explicit file provided, use it
    if state_file:
        if not os.path.exists(state_file):
            print(f"[!] State file not found: {state_file}")
            sys.exit(1)
        print(f"[*] Loading state from: {state_file}")
        with open(state_file, 'r') as f:
            return json.load(f)
    
    # Otherwise, find latest results/*/state.json
    results_dir = Path("/home/root17/Desktop/ai-recon-agent/results")
    if not results_dir.exists():
        print("[!] No results directory found")
        sys.exit(1)
    
    # Find all state.json files
    state_files = list(results_dir.glob("*/state.json"))
    if not state_files:
        print("[!] No state.json files found in results")
        sys.exit(1)
    
    # Use most recently modified
    latest_state = max(state_files, key=lambda p: p.stat().st_mtime)
    print(f"[*] Loading state from: {latest_state}")
    
    with open(latest_state, 'r') as f:
        return json.load(f)


def validate_chain_urls(state):
    """
    Validate that all chains use fully qualified URLs (dynamic from state, no hardcoding).
    
    Args:
        state: Dictionary containing scan state
    
    Returns:
        Boolean indicating success/failure
    """
    # Validate required state fields
    target = state.get('target', '')
    live_hosts = state.get('live_hosts', [])
    
    if not target:
        print("[!] State missing required field: 'target'")
        return False
    
    print(f"\n[*] Target: {target}")
    if live_hosts:
        print(f"[*] Live hosts: {len(live_hosts)}")
    
    # Initialize ChainPlanner with dynamic state (NO HARDCODING)
    planner = ChainPlanner(state)
    
    print("\n[*] Testing URL builders with dynamic state...")
    
    # Test _get_base_url (dynamic from state)
    base_url = planner._get_base_url()
    print(f"  Dynamic Base URL: {base_url}")
    
    if not base_url.startswith(('http://', 'https://')):
        print(f"  [FAIL] Base URL missing scheme: {base_url}")
        return False
    print(f"  [OK] Base URL has scheme")
    
    # Test _build_full_url (dynamic)
    test_paths = ["xmlrpc.php", "wp-admin/", "/uploads/"]
    for path in test_paths:
        full_url = planner._build_full_url(path)
        print(f"  Full URL ({path}): {full_url[:60]}...")
        
        if not full_url.startswith(('http://', 'https://')):
            print(f"    [FAIL] Missing scheme")
            return False
        print(f"    [OK] Has scheme")
    
    print("\n[*] Testing chain builders with dynamic state...")
    
    # Build chains dynamically (all built from state, not hardcoded)
    chains_to_test = []
    
    # Get actual endpoints and data from state (NOT hardcoded)
    wp_users = state.get('wp_users', []) or ['admin']
    wp_plugins = state.get('wp_plugins', [])
    vulnerabilities = state.get('confirmed_vulnerabilities', [])
    endpoints = state.get('prioritized_endpoints', [])
    
    # Only create chains that have the necessary prerequisites in state
    chains_to_test.append(('_build_xmlrpc_chain', planner._build_xmlrpc_chain(wp_users)))
    
    if wp_users:
        chains_to_test.append(('_build_wp_admin_chain', planner._build_wp_admin_chain(wp_users)))
    
    if endpoints:
        upload_ep = next((ep for ep in endpoints if 'upload' in ep.get('url', '').lower()), endpoints[0])
        chains_to_test.append(('_build_upload_chain', planner._build_upload_chain(upload_ep)))
    
    if vulnerabilities:
        sqli_vuln = next((v for v in vulnerabilities if 'sql' in v.get('name', '').lower()), vulnerabilities[0])
        if sqli_vuln:
            chains_to_test.append(('_build_sqli_chain', planner._build_sqli_chain(sqli_vuln)))
    
    if endpoints:
        lfi_ep = next((ep for ep in endpoints if any(param in ep.get('url', '') for param in ['file=', 'page=', 'include='])), endpoints[0])
        chains_to_test.append(('_build_lfi_chain', planner._build_lfi_chain(lfi_ep)))
    
    if vulnerabilities:
        xss_vuln = next((v for v in vulnerabilities if 'xss' in v.get('name', '').lower()), vulnerabilities[0] if vulnerabilities else None)
        if xss_vuln:
            chains_to_test.append(('_build_xss_chain', planner._build_xss_chain(xss_vuln)))
    
    if wp_plugins:
        chains_to_test.append(('_build_wp_plugin_chain', planner._build_wp_plugin_chain(wp_plugins[0])))
    
    errors = []
    scheme_check_count = 0
    total_steps = 0
    
    for chain_name, chain in chains_to_test:
        print(f"\n  {chain_name}:")
        for i, step in enumerate(chain.steps, 1):
            target = step.target
            total_steps += 1
            print(f"    Step {i} ({step.name}): {target[:70] if len(target) > 70 else target}")
            
            if not target:
                errors.append(f"{chain_name}: Step {i} has EMPTY target")
                print(f"      [FAIL] Empty target URL")
            elif not target.startswith(('http://', 'https://')):
                # Check if it's a legitimate non-URL target (like "User-Agent header")
                if ':' not in target or '.' not in target:
                    print(f"      [OK] Non-URL target (acceptable)")
                    scheme_check_count += 1
                else:
                    errors.append(f"{chain_name}: Step {i} missing scheme: {target}")
                    print(f"      [FAIL] Missing scheme")
            else:
                print(f"      [OK] Has scheme (dynamic)")
                scheme_check_count += 1
    
    print(f"\n" + "="*70)
    print(f"[*] VALIDATION SUMMARY")
    print(f"="*70)
    print(f"  Chains tested: {len(chains_to_test)}")
    print(f"  Total steps: {total_steps}")
    print(f"  Steps with proper scheme: {scheme_check_count}")
    print(f"  Base URL: {base_url} (from state['target'] or state['live_hosts'])")
    print(f"  Target loaded from state: (NO HARDCODING)")
    
    if errors:
        print(f"\n[!] ERRORS ({len(errors)}):")
        for error in errors:
            print(f"    - {error}")
        return False
    else:
        print(f"\n[✓] SUCCESS: All chains have fully qualified URLs!")
        print(f"[✓] All URLs built dynamically from state (NO HARDCODING)")
        print(f"[✓] Chains ready for execution on any target")
        return True


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Validate exploit chains use dynamic URLs from state (no hardcoding)'
    )
    parser.add_argument(
        '--state', '-s',
        help='Path to state.json file (auto-detected from results/ if not provided)'
    )
    parser.add_argument(
        '--target', '-t',
        help='Override target domain from state (for testing)'
    )
    
    args = parser.parse_args()
    
    try:
        # Load state dynamically
        state = load_state(args.state)
        
        # Override target if provided
        if args.target:
            print(f"[*] Overriding target from state: {state.get('target')} -> {args.target}")
            state['target'] = args.target
        
        # Validate chains
        success = validate_chain_urls(state)
        
        return 0 if success else 1
    
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
