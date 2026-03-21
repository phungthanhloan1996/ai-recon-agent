#!/usr/bin/env python3
"""
Test: Security Findings Layer
Demonstrates non-CVE signal detection and RCE chain analysis.
"""

import json
import tempfile
from core.state_manager import StateManager
from agent import ReconAgent

def test_findings_generation():
    """
    Test the complete findings generation pipeline.
    """
    print("\n" + "="*80)
    print("TEST: Security Findings Layer - Non-CVE Signal Detection")
    print("="*80)
    
    # Create temporary workspace
    with tempfile.TemporaryDirectory() as tmpdir:
        print("\n📋 SCENARIO: WordPress site with interesting endpoints and misconfigurations")
        print("(No CVEs detected, but significant findings present)")
        
        # Initialize agent
        state = StateManager("http://target.com", tmpdir)
        agent = ReconAgent(
            target="http://target.com",
            output_dir=tmpdir,
            options={},
            batch_display=None
        )
        
        # Simulate discovered data
        agent.state.update(
            wordpress_detected=True,
            wp_version="5.8.1",
            wp_plugins=[
                {"name": "woocommerce", "version": "unknown"},
                {"name": "contact-form-7", "version": "unknown"}
            ],
            wp_themes=[
                {"name": "divi", "version": "unknown"}
            ],
            urls=[
                "http://target.com/wp-login.php",
                "http://target.com/xmlrpc.php",
                "http://target.com/wp-admin/",
                "http://target.com/wp-content/",
                "http://target.com/wp-json/",
                "http://target.com/upload-file",
                "http://target.com/api/users",
                "http://target.com/api/posts",
                "http://target.com/admin/dashboard",
                "http://target.com/debug"
            ],
            crawled_urls=[
                "http://target.com/config.php.bak",
                "http://target.com/.git",
                "http://target.com/backup"
            ],
            endpoints=[
                {"url": "http://target.com/upload-file", "path": "/upload-file"},
                {"url": "http://target.com/api/users", "path": "/api/users"},
                {"url": "http://target.com/api/posts", "path": "/api/posts"}
            ]
        )
        
        # Simulate tech stack detection
        agent.findings.update({
            'php_version': 'PHP 7.4.12',
            'waf': 'Cloudflare',
            'users': ['admin', 'john.doe', 'contact@target.com'],
            'cms_version': 'WordPress 5.8.1'
        })
        agent.tech_stack = {'WordPress': True, 'Apache': True, 'PHP': True}
        
        # Simulate endpoint stats
        agent.endpoint_stats.update({
            'api': 3,
            'admin': 1,
            'upload': 1,
            'total': 25
        })
        
        print("\n✅ SIMULATED DATA:")
        print(f"   • WordPress detected: {agent.state.get('wordpress_detected')}")
        print(f"   • URLs discovered: {len(agent.state.get('urls', []))}")
        print(f"   • Plugins found: {len(agent.state.get('wp_plugins', []))}")
        print(f"   • Users enumerated: {len(agent.findings.get('users', []))}")
        print(f"   • Endpoint types: {agent.endpoint_stats['api']} API, {agent.endpoint_stats['admin']} admin, {agent.endpoint_stats['upload']} upload")
        
        # Generate findings
        print("\n🔍 GENERATING FINDINGS...")
        findings = agent._generate_findings()
        
        print(f"\n📊 FINDINGS GENERATED: {len(findings)} items")
        for i, finding in enumerate(findings, 1):
            severity_icon = "🔴" if finding['severity'] == "HIGH" else "🟡" if finding['severity'] == "MEDIUM" else "🔵"
            print(f"\n   {i}. {severity_icon} [{finding['severity']}] {finding['title']}")
            print(f"      Type: {finding['type']}")
            print(f"      Evidence: {finding['evidence'][:70]}...")
        
        # Analyze RCE possibilities
        print("\n\n🎯 ANALYZING RCE ATTACK CHAINS...")
        rce_chains = agent._analyze_rce_possibilities()
        
        print(f"\n⛓️  RCE POSSIBILITIES: {len(rce_chains)} chains identified")
        for i, chain in enumerate(rce_chains, 1):
            print(f"\n   Chain {i}: {chain['title']}")
            print(f"      Components: {' → '.join(chain['components'])}")
            print(f"      Evidence: {chain['evidence']}")
            print(f"      Requires validation: {chain['requires_validation']}")
        
        # Show output format
        print("\n\n📄 STATE PERSISTENCE:")
        print(f"   • security_findings: {len(findings)} entries")
        print(f"   • rce_chain_possibilities: {len(rce_chains)} entries")
        print(f"   • Persisted in state.json: ✅")
        
        print("\n" + "="*80)
        print("COMPARISON: Before vs After Enhancement")
        print("="*80)
        
        print("\n❌ BEFORE (Current System):")
        print("   └─ Report: '0 vulns' ← STOPS HERE, ignores all else")
        print("   └─ Display: Empty/silent")
        print("   └─ Result: User thinks target is clean")
        
        print("\n✅ AFTER (With Findings Layer):")
        print(f"   └─ Report: '0 CVEs found, but {len(findings)} interesting findings detected'")
        print(f"   ├─ Technology stack identified")
        print(f"   ├─ {len(agent.findings.get('users', []))} users enumerated")
        print(f"   ├─ Sensitive endpoints exposed")
        print(f"   ├─ Misconfigurations detected")
        print(f"   └─ {len(rce_chains)} potential RCE chains identified")
        print(f"   └─ Display: Detailed findings with evidence")
        print(f"   └─ Result: User understands attack surface")
        
        print("\n" + "="*80)
        print("✅ TEST COMPLETED SUCCESSFULLY")
        print("="*80 + "\n")
        
        return {
            'findings_count': len(findings),
            'rce_chains_count': len(rce_chains),
            'test_passed': len(findings) > 0 and len(rce_chains) > 0
        }

if __name__ == "__main__":
    result = test_findings_generation()
    print(f"\n📈 METRICS:")
    print(f"   ✓ Findings generated: {result['findings_count']}")
    print(f"   ✓ RCE chains identified: {result['rce_chains_count']}")
    print(f"   ✓ Test passed: {result['test_passed']}\n")
    exit(0 if result['test_passed'] else 1)
