#!/usr/bin/env python3
"""
Demonstration: Exploit chains work with ANY target (no hardcoding)
"""

import json
from ai.chain_planner import ChainPlanner


def demo_target(target_name, state_override):
    """Demonstrate chains work with different targets"""
    print(f"\n{'='*70}")
    print(f"DEMO: {target_name}")
    print(f"{'='*70}")
    
    # Create a minimal state for demonstration
    state = {
        'target': state_override['target'],
        'live_hosts': state_override.get('live_hosts', [
            {'url': f"https://{state_override['target']}", 'status': 'live'}
        ]),
        'wp_users': ['admin', 'test'],
        'wp_plugins': [{'name': 'vulnerable-plugin', 'vulnerabilities': [{'type': 'RCE'}]}],
        'confirmed_vulnerabilities': [{'url': '/?id=1', 'type': 'sqli'}],
        'prioritized_endpoints': [
            {'url': '/uploads/', 'score': 9},
            {'url': '/?page=1', 'score': 7}
        ],
    }
    
    planner = ChainPlanner(state)
    base = planner._get_base_url()
    
    print(f"Target (from state): {state['target']}")
    print(f"Base URL (dynamic): {base}")
    print(f"\nDynamic URLs generated:")
    print(f"  XML-RPC:     {planner._build_full_url('xmlrpc.php')}")
    print(f"  WP Admin:    {planner._build_full_url('wp-admin/')}")
    print(f"  Uploads:     {planner._build_full_url('/uploads/')}")
    print(f"  Login:       {planner._build_full_url('wp-login.php')}")
    
    # Build a sample chain
    chain = planner._build_xmlrpc_chain(state.get('wp_users', []))
    print(f"\nXML-RPC Chain ({chain.name}):")
    for i, step in enumerate(chain.steps, 1):
        print(f"  Step {i}: {step.name}")
        print(f"    Target: {step.target}")
        assert step.target.startswith(('http://', 'https://')), "Missing scheme!"
    
    print(f"\n✓ All URLs are fully qualified (have http:// or https://)")
    print(f"✓ No hardcoding - all DYNAMIC from state")


if __name__ == '__main__':
    print("\n" + "="*70)
    print("DEMONSTRATION: Dynamic Chains (No Hardcoding)")
    print("="*70)
    print("\nShowing same chain code works with DIFFERENT TARGETS:")
    
    # Demo 1: WordPress site with standard port
    demo_target("WordPress Site (HTTPS)", {
        'target': 'wordpress-blog.com',
        'live_hosts': [
            {'url': 'https://wordpress-blog.com', 'status': 'live'}
        ]
    })
    
    # Demo 2: Legacy system with non-standard port
    demo_target("Legacy App (Custom Port)", {
        'target': 'legacy-system.internal:8080',
        'live_hosts': [
            {'url': 'http://legacy-system.internal:8080', 'status': 'live'}
        ]
    })
    
    # Demo 3: Subdomain with HTTPS
    demo_target("Subdomain API", {
        'target': 'api.startup.io',
        'live_hosts': [
            {'url': 'https://api.startup.io', 'status': 'live'}
        ]
    })
    
    # Demo 4: Internal IP address
    demo_target("Internal Network", {
        'target': '192.168.1.100',
        'live_hosts': [
            {'url': 'http://192.168.1.100', 'status': 'live'}
        ]
    })
    
    # Demo 5: Localhost development
    demo_target("Local Development", {
        'target': 'localhost:3000',
        'live_hosts': [
            {'url': 'http://localhost:3000', 'status': 'live'}
        ]
    })
    
    print("\n" + "="*70)
    print("✓ SUCCESS: Same chain code works for ALL targets!")
    print("✓ No hardcoding required")
    print("✓ All URLs built dynamically from state")
    print("="*70)
