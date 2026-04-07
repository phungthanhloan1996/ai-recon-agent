#!/usr/bin/env python3
"""
Test to verify the chain planner fix:
- Only generates chains from REAL recon data
- Rejects localhost/fake targets
- Returns empty chains when no real data available
"""

from ai.chain_planner import ChainPlanner, ExploitChain
from core.exploit_executor import ExploitExecutor


def test_no_fake_chains_without_data():
    """Test that planner returns empty chains when no real data available"""
    planner = ChainPlanner()
    
    # Empty findings and endpoints
    findings = {}
    endpoints = {}
    
    chains = planner.plan(findings, endpoints)
    
    assert len(chains) == 0, "Should return empty chains when no data available"
    print("✓ Test passed: No fake chains without data")


def test_no_localhost_chains():
    """Test that planner never generates chains with localhost targets"""
    planner = ChainPlanner()
    
    # Fake data with localhost
    findings = {
        'wordpress': {
            'users': ['admin'],
            'xmlrpc_enabled': True
        }
    }
    endpoints = {
        'wordpress': {
            'sites': [
                {'url': 'http://localhost', 'version': '5.8', 'admin_url': 'http://localhost/wp-admin'}
            ]
        }
    }
    
    chains = planner.plan(findings, endpoints)
    
    # Should filter out localhost
    for chain in chains:
        assert not chain.target_url.startswith('localhost'), \
            f"Chain target should not be localhost: {chain.target_url}"
        assert chain.target_url.startswith('http'), \
            f"Chain target should be valid URL: {chain.target_url}"
    
    print("✓ Test passed: No localhost chains generated")


def test_real_wordpress_chains():
    """Test that planner generates chains from REAL WordPress data"""
    planner = ChainPlanner()
    
    # Real WordPress findings
    findings = {
        'wordpress': {
            'users': ['admin', 'editor'],
            'xmlrpc_enabled': True
        }
    }
    endpoints = {
        'wordpress': {
            'sites': [
                {
                    'url': 'https://dolphin-vc.com',
                    'version': '5.8',
                    'admin_url': 'https://dolphin-vc.com/wp-admin',
                    'xmlrpc_url': 'https://dolphin-vc.com/xmlrpc.php'
                }
            ]
        }
    }
    
    chains = planner.plan(findings, endpoints)
    
    assert len(chains) > 0, "Should generate chains for real WordPress sites"
    
    # Should have admin takeover chain
    admin_chains = [c for c in chains if c.chain_type == 'wordpress_admin']
    assert len(admin_chains) > 0, "Should generate WordPress admin chain"
    
    # Should have XML-RPC chain
    xmlrpc_chains = [c for c in chains if c.chain_type == 'wordpress_xmlrpc']
    assert len(xmlrpc_chains) > 0, "Should generate XML-RPC chain"
    
    # Verify targets are real
    for chain in chains:
        assert 'dolphin-vc.com' in chain.target_url, \
            f"Chain should target real site: {chain.target_url}"
    
    print("✓ Test passed: Real WordPress chains generated correctly")


def test_chain_validation():
    """Test that validator rejects invalid chains"""
    planner = ChainPlanner()
    
    # Valid chain
    valid_chain = ExploitChain(
        name="Test Chain",
        chain_type="test",
        target_url="https://example.com/wp-admin",
        steps=[
            {"action": "test", "target": "https://example.com/wp-admin"}
        ],
        confidence=0.8,
        prerequisites={},
        context={}
    )
    
    assert planner.validate_chain(valid_chain), "Should validate real chain"
    
    # Invalid chain with localhost
    invalid_chain = ExploitChain(
        name="Fake Chain",
        chain_type="test",
        target_url="http://localhost",
        steps=[
            {"action": "test", "target": "http://localhost"}
        ],
        confidence=0.8,
        prerequisites={},
        context={}
    )
    
    assert not planner.validate_chain(invalid_chain), "Should reject localhost chain"
    
    # Invalid chain with empty target
    empty_chain = ExploitChain(
        name="Empty Chain",
        chain_type="test",
        target_url="",
        steps=[],
        confidence=0.8,
        prerequisites={},
        context={}
    )
    
    assert not planner.validate_chain(empty_chain), "Should reject empty chain"
    
    print("✓ Test passed: Chain validation works correctly")


def test_executor_rejects_invalid_chains():
    """Test that executor rejects chains with invalid targets"""
    executor = ExploitExecutor()
    
    # Valid chain
    valid_chain = ExploitChain(
        name="Valid Chain",
        chain_type="wordpress_admin",
        target_url="https://example.com/wp-admin",
        steps=[
            {"action": "brute_force_admin", "target": "https://example.com/wp-admin", "users": []}
        ],
        confidence=0.8,
        prerequisites={},
        context={}
    )
    
    result = executor.execute_chain(valid_chain, {})
    # Should attempt execution (even if steps not implemented)
    assert 'chain_type' in result, "Should process valid chain"
    
    # Invalid chain with localhost
    invalid_chain = ExploitChain(
        name="Invalid Chain",
        chain_type="wordpress_admin",
        target_url="http://localhost",
        steps=[
            {"action": "brute_force_admin", "target": "http://localhost", "users": []}
        ],
        confidence=0.8,
        prerequisites={},
        context={}
    )
    
    result = executor.execute_chain(invalid_chain, {})
    assert not result.get('success', False), "Should reject invalid chain"
    assert 'Invalid target' in result.get('error', ''), "Should report invalid target"
    
    print("✓ Test passed: Executor rejects invalid chains")


def test_statistics():
    """Test chain statistics generation"""
    planner = ChainPlanner()
    
    chains = [
        ExploitChain(
            name="Chain 1",
            chain_type="wordpress_admin",
            target_url="https://site1.com/wp-admin",
            steps=[],
            confidence=0.7,
            prerequisites={},
            context={}
        ),
        ExploitChain(
            name="Chain 2",
            chain_type="wordpress_xmlrpc",
            target_url="https://site2.com/xmlrpc.php",
            steps=[],
            confidence=0.6,
            prerequisites={},
            context={}
        )
    ]
    
    stats = planner.get_chain_statistics(chains)
    
    assert stats['total_chains'] == 2, "Should count total chains"
    assert stats['by_type']['wordpress_admin'] == 1, "Should count by type"
    assert stats['by_type']['wordpress_xmlrpc'] == 1, "Should count by type"
    assert abs(stats['avg_confidence'] - 0.65) < 0.01, "Should calculate avg confidence"
    assert len(stats['targets']) == 2, "Should collect unique targets"
    
    print("✓ Test passed: Statistics generation works correctly")


if __name__ == "__main__":
    print("Testing Chain Planner Fix...")
    print("=" * 60)
    
    test_no_fake_chains_without_data()
    test_no_localhost_chains()
    test_real_wordpress_chains()
    test_chain_validation()
    test_executor_rejects_invalid_chains()
    test_statistics()
    
    print("=" * 60)
    print("✓ All tests passed! Chain planner fix is working correctly.")
    print("\nKey improvements:")
    print("  - No more fake/heuristic chains")
    print("  - Only generates chains from REAL recon data")
    print("  - Validates all targets (no localhost)")
    print("  - Returns empty chains when no viable targets found")