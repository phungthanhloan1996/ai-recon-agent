#!/usr/bin/env python3
"""
Test script for WordPress detection from state data.
Demonstrates the new pattern-based detection method.
"""

import json
import tempfile
import os
from core.state_manager import StateManager
from modules.wp_scanner import WordPressScannerEngine

def test_wordpress_detection_from_state():
    """Test WordPress detection using URL patterns from state data"""
    
    print("\n" + "="*70)
    print("TEST: WordPress Detection from State Data")
    print("="*70)
    
    # Create temporary directory for test
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize state manager
        state = StateManager("http://target.com", tmpdir)
        
        # Simulate discovered URLs with WordPress indicators
        test_urls = [
            "http://target.com/wp-login.php",
            "http://target.com/wp-admin/",
            "http://target.com/wp-content/",
            "http://target.com/wp-includes/",
            "http://target.com/wp-json/",
            "http://target.com/wp-content/plugins/woocommerce/",
            "http://target.com/wp-content/plugins/contact-form-7/",
            "http://target.com/wp-content/themes/twentytwentyone/",
            "http://target.com/wp-content/themes/astra/",
            "http://target.com/wp-content/uploads/2024/01/image.jpg?ver=5.8.1",
            "http://target.com/xmlrpc.php",
            "http://target.com/readme.html"
        ]
        
        # Store URLs in state as endpoints
        endpoints = [{"url": url} for url in test_urls]
        state.update(
            urls=test_urls,
            endpoints=endpoints,
            crawled_urls=test_urls
        )
        
        print(f"\n📍 Simulation Setup:")
        print(f"   • URLs in state: {len(test_urls)}")
        print(f"   • WordPress indicators present:")
        print(f"     - wp-login.php ✓")
        print(f"     - xmlrpc.php ✓")
        print(f"     - wp-admin/ ✓")
        print(f"     - wp-content/ ✓")
        print(f"     - wp-includes/ ✓")
        print(f"     - wp-json/ ✓")
        print(f"     - 2 plugins detected ✓")
        print(f"     - 2 themes detected ✓")
        print(f"     - Version from URL: 5.8.1 ✓")
        
        # Initialize WordPress scanner
        wp_scanner = WordPressScannerEngine(state, tmpdir)
        
        print(f"\n🔍 Running WordPress Detection...")
        
        # Run the detection
        result = wp_scanner.detect_wordpress_from_state_data()
        
        print(f"\n✅ Detection Result: {'DETECTED' if result else 'NOT DETECTED'}")
        
        # Show what was detected
        print(f"\n📊 State Update:")
        print(f"   • wordpress_detected: {state.get('wordpress_detected', False)}")
        print(f"   • wp_scan_confidence: {state.get('wp_scan_confidence', 'N/A')}%")
        print(f"   • wp_version: {state.get('wp_version', 'unknown')}")
        
        plugins = state.get('wp_plugins', [])
        themes = state.get('wp_themes', [])
        
        print(f"\n🔌 Plugins Found ({len(plugins)}):")
        for plugin in plugins[:5]:
            print(f"   • {plugin.get('name', 'unknown')} @ {plugin.get('path', '?')}")
        
        print(f"\n🎨 Themes Found ({len(themes)}):")
        for theme in themes[:5]:
            print(f"   • {theme.get('name', 'unknown')} @ {theme.get('path', '?')}")
        
        print(f"\n📈 Pattern Matches:")
        matches = state.get('wp_pattern_matches', {})
        for pattern_name, urls in matches.items():
            print(f"   • {pattern_name}: {len(urls)} match(es)")
        
        print("\n" + "="*70)
        print("TEST SUMMARY")
        print("="*70)
        
        # Verify all expected findings
        checks = [
            ("WordPress detected", result == True),
            ("Confidence > 70%", state.get('wp_scan_confidence', 0) > 70),
            ("Version extracted", state.get('wp_version') != 'unknown'),
            ("Plugins found", len(plugins) > 0),
            ("Themes found", len(themes) > 0),
        ]
        
        all_passed = True
        for check_name, passed in checks:
            status = "✓ PASS" if passed else "✗ FAIL"
            print(f"{status}: {check_name}")
            if not passed:
                all_passed = False
        
        print("\n" + "="*70)
        if all_passed:
            print("✅ ALL TESTS PASSED")
        else:
            print("❌ SOME TESTS FAILED")
        print("="*70 + "\n")
        
        return all_passed

if __name__ == "__main__":
    success = test_wordpress_detection_from_state()
    exit(0 if success else 1)
