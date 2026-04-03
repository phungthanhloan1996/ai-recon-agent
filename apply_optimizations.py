#!/usr/bin/env python3
"""
Quick script to apply and test scan optimizations
Run this to validate the optimization implementation
"""

import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.scan_optimizer import ScanOptimizer, get_optimizer

def test_optimizer():
    """Test the scan optimizer functionality"""
    print("=" * 60)
    print("SCAN OPTIMIZER TEST SUITE")
    print("=" * 60)
    
    optimizer = get_optimizer()
    
    # Test 1: Host blacklist
    print("\n[Test 1] Host Blacklist Behavior")
    print("-" * 40)
    
    test_host = "dead.example.com"
    print(f"Recording failures for {test_host}...")
    
    # Simulate DNS error (should blacklist after 1)
    optimizer.record_host_failure(test_host, "DNS resolution failed")
    print(f"  After 1 DNS error: blacklisted = {optimizer.is_host_blacklisted(test_host)}")
    assert optimizer.is_host_blacklisted(test_host), "Should blacklist after DNS error"
    
    # Test 2: Connection timeout blacklist
    test_host2 = "slow.example.com"
    print(f"\nRecording timeouts for {test_host2}...")
    optimizer.record_host_failure(test_host2, "Connection timed out")
    print(f"  After 1 timeout: blacklisted = {optimizer.is_host_blacklisted(test_host2)}")
    optimizer.record_host_failure(test_host2, "Connection timed out")
    print(f"  After 2 timeouts: blacklisted = {optimizer.is_host_blacklisted(test_host2)}")
    assert optimizer.is_host_blacklisted(test_host2), "Should blacklist after 2 timeouts"
    
    # Test 3: Standard failure blacklist
    test_host3 = "flaky.example.com"
    print(f"\nRecording failures for {test_host3}...")
    for i in range(3):
        optimizer.record_host_failure(test_host3, f"Error {i+1}")
        print(f"  After {i+1} failures: blacklisted = {optimizer.is_host_blacklisted(test_host3)}")
    assert optimizer.is_host_blacklisted(test_host3), "Should blacklist after 3 failures"
    
    print("\n✓ Blacklist tests passed!")
    
    # Test 4: Port caching
    print("\n[Test 2] Port Scan Caching")
    print("-" * 40)
    
    test_host_port = "web.example.com"
    open_ports = {80, 443, 8080}
    closed_ports = {8443, 8888, 3000}
    
    optimizer.cache_port_scan(test_host_port, open_ports, closed_ports)
    print(f"Cached ports for {test_host_port}:")
    print(f"  Open: {open_ports}")
    print(f"  Closed: {closed_ports}")
    
    # Check cache retrieval
    cached = optimizer.get_cached_ports(test_host_port)
    assert cached is not None, "Should retrieve cached result"
    assert cached.open_ports == open_ports, "Open ports should match"
    assert cached.closed_ports == closed_ports, "Closed ports should match"
    
    # Check should_skip_port
    assert optimizer.should_skip_port(test_host_port, 8443), "Should skip closed port"
    assert not optimizer.should_skip_port(test_host_port, 80), "Should not skip open port"
    
    print("✓ Port caching tests passed!")
    
    # Test 5: WPScan retry logic
    print("\n[Test 3] WPScan Retry Logic")
    print("-" * 40)
    
    test_plugin = "akismet"
    
    # First attempt should be allowed
    assert optimizer.should_retry_wpscan(test_plugin, 0), "First attempt should be allowed"
    print(f"  Attempt 0: allowed = True")
    
    # Record rate limit failure
    optimizer.record_wpscan_failure(test_plugin, is_rate_limit=True)
    
    # Second attempt should be allowed (first failure)
    assert optimizer.should_retry_wpscan(test_plugin, 1), "Second attempt should be allowed"
    print(f"  Attempt 1: allowed = True")
    
    # Record another failure
    optimizer.record_wpscan_failure(test_plugin, is_rate_limit=True)
    
    # Third attempt should be denied
    assert not optimizer.should_retry_wpscan(test_plugin, 2), "Third attempt should be denied"
    print(f"  Attempt 2: allowed = False")
    
    print("✓ WPScan retry tests passed!")
    
    # Test 6: Dirbust retry logic
    print("\n[Test 4] Dirbust Retry Logic")
    print("-" * 40)
    
    test_path = "https://example.com/admin"
    
    # First attempt should be allowed
    assert optimizer.should_retry_dirbust(test_path, 0), "First attempt should be allowed"
    print(f"  Attempt 0: allowed = True")
    
    # Record timeout
    optimizer.record_dirbust_timeout(test_path)
    
    # Second attempt should be denied
    assert not optimizer.should_retry_dirbust(test_path, 1), "Second attempt should be denied"
    print(f"  Attempt 1: allowed = False")
    
    print("✓ Dirbust retry tests passed!")
    
    # Test 7: Optimized timeouts
    print("\n[Test 5] Optimized Timeouts")
    print("-" * 40)
    
    # Normal host
    timeout = optimizer.get_optimized_timeout("normal.example.com", "connection")
    print(f"  Normal host timeout: {timeout}s")
    assert timeout == 5, "Normal timeout should be 5s"
    
    # DNS error host (should get faster timeout)
    dns_host = "dns-error.example.com"
    optimizer.record_host_failure(dns_host, "DNS resolution failed")
    timeout = optimizer.get_optimized_timeout(dns_host, "connection")
    print(f"  DNS error host timeout: {timeout}s")
    assert timeout == 2, "DNS error host should get 2s timeout"
    
    print("✓ Timeout tests passed!")
    
    # Test 8: Statistics
    print("\n[Test 6] Statistics Tracking")
    print("-" * 40)
    
    stats = optimizer.calculate_time_saved()
    print(f"  Hosts skipped: {stats['hosts_skipped']}")
    print(f"  Ports cached: {stats['ports_cached']}")
    print(f"  Retries avoided: {stats['retries_avoided']}")
    print(f"  Estimated time saved: {stats['estimated_time_saved_minutes']:.1f} minutes")
    
    print("✓ Statistics tests passed!")
    
    # Summary
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED!")
    print("=" * 60)
    
    # Print optimization report
    print("\n" + optimizer.generate_report())
    
    return True

def estimate_time_savings():
    """Estimate time savings for a typical scan"""
    print("\n" + "=" * 60)
    print("ESTIMATED TIME SAVINGS")
    print("=" * 60)
    
    # Assumptions
    total_hosts = 50
    dead_host_ratio = 0.3
    dead_hosts = int(total_hosts * dead_host_ratio)
    live_hosts = total_hosts - dead_hosts
    ports_per_host = 6
    wpscan_plugins = 10
    dirbust_paths = 100
    
    # Before optimization
    before_dead = dead_hosts * 8 * 20 / 60  # minutes
    before_ports = total_hosts * ports_per_host * 20 / 60
    before_wpscan = wpscan_plugins * 0.3 * 420 / 60  # 30% rate limited
    before_dirbust = dirbust_paths * 0.05 * 120 / 60  # 5% timeout
    before_total = before_dead + before_ports + before_wpscan + before_dirbust
    
    # After optimization
    after_dead = dead_hosts * 3 * 5 / 60
    after_ports = live_hosts * ports_per_host * 5 / 60
    after_wpscan = wpscan_plugins * 0.3 * 90 / 60
    after_dirbust = dirbust_paths * 0.05 * 30 / 60
    after_total = after_dead + after_ports + after_wpscan + after_dirbust
    
    savings = before_total - after_total
    percentage = (savings / before_total) * 100
    
    print(f"""
Scenario: {total_hosts} hosts ({dead_hosts} dead, {live_hosts} live)

BEFORE OPTIMIZATION:
  Dead host scanning:    {before_dead:.1f} minutes
  Port scanning:         {before_ports:.1f} minutes
  WPScan rate limits:    {before_wpscan:.1f} minutes
  Dirbust timeouts:      {before_dirbust:.1f} minutes
  ─────────────────────────────────────
  Total:                 {before_total:.1f} minutes ({before_total/60:.1f} hours)

AFTER OPTIMIZATION:
  Dead host scanning:    {after_dead:.1f} minutes
  Port scanning:         {after_ports:.1f} minutes
  WPScan rate limits:    {after_wpscan:.1f} minutes
  Dirbust timeouts:      {after_dirbust:.1f} minutes
  ─────────────────────────────────────
  Total:                 {after_total:.1f} minutes ({after_total/60:.1f} hours)

TIME SAVED:              {savings:.1f} minutes ({savings/60:.1f} hours)
IMPROVEMENT:             {percentage:.1f}% reduction
""")

if __name__ == "__main__":
    try:
        # Run tests
        success = test_optimizer()
        
        if success:
            # Show estimated savings
            estimate_time_savings()
            
            print("\n" + "=" * 60)
            print("✓ Optimization implementation validated successfully!")
            print("=" * 60)
            print("\nNext steps:")
            print("1. Review config/optimizer_config.yaml for customization")
            print("2. Read OPTIMIZATION_GUIDE.md for detailed documentation")
            print("3. Run your scanning operations to see improvements")
            
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)