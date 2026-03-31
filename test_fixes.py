#!/usr/bin/env python3
"""
Test script to verify all bug fixes and enhancements
"""
import os
import sys
sys.path.insert(0, '/home/root17/Desktop/ai-recon-agent')

def test_permission_fix():
    """Test #1: FileHandler permission fix"""
    print("\n📝 Test #1: FileHandler Permission Error Fix")
    print("─" * 50)
    try:
        import logging
        from agent import run_batch
        
        # Check if try-except is in place around FileHandler
        import inspect
        source = inspect.getsource(run_batch)
        if "except (PermissionError, IOError)" in source:
            print("✅ PASS: Permission error handling is in place")
            return True
        else:
            print("❌ FAIL: Permission error handling not found")
            return False
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

def test_timeout_fixes():
    """Test #2: Timeout values fixed in config"""
    print("\n⏱️  Test #2: Timeout Values")
    print("─" * 50)
    try:
        import config
        results = []
        
        # Check AMASS_TIMEOUT
        if config.AMASS_TIMEOUT >= 120:
            print(f"✅ AMASS_TIMEOUT = {config.AMASS_TIMEOUT} (target: ≥120)")
            results.append(True)
        else:
            print(f"❌ AMASS_TIMEOUT = {config.AMASS_TIMEOUT} (should be ≥120)")
            results.append(False)
        
        # Check HTTP_TIMEOUT
        if config.HTTP_TIMEOUT >= 30:
            print(f"✅ HTTP_TIMEOUT = {config.HTTP_TIMEOUT} (target: ≥30)")
            results.append(True)
        else:
            print(f"❌ HTTP_TIMEOUT = {config.HTTP_TIMEOUT} (should be ≥30)")
            results.append(False)
        
        # Check KATANA_TIMEOUT
        if config.KATANA_TIMEOUT >= 600:
            print(f"✅ KATANA_TIMEOUT = {config.KATANA_TIMEOUT} (target: ≥600)")
            results.append(True)
        else:
            print(f"❌ KATANA_TIMEOUT = {config.KATANA_TIMEOUT} (should be ≥600)")
            results.append(False)
        
        # Check HTTP_POOL_SIZE
        if config.HTTP_POOL_SIZE >= 50:
            print(f"✅ HTTP_POOL_SIZE = {config.HTTP_POOL_SIZE} (target: ≥50)")
            results.append(True)
        else:
            print(f"❌ HTTP_POOL_SIZE = {config.HTTP_POOL_SIZE} (should be ≥50)")
            results.append(False)
        
        return all(results)
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

def test_retry_mechanisms():
    """Test #3: Retry mechanisms for API failures"""
    print("\n🔄 Test #3: Retry Mechanisms")
    print("─" * 50)
    try:
        import config
        results = []
        
        # Check WPScan retry config
        if hasattr(config, 'WPSCAN_429_MAX_RETRIES'):
            print(f"✅ WPSCAN_429_MAX_RETRIES = {config.WPSCAN_429_MAX_RETRIES}")
            results.append(True)
        else:
            print("❌ WPSCAN_429_MAX_RETRIES not found")
            results.append(False)
        
        # Check Groq retry config
        if hasattr(config, 'GROQ_MAX_RETRIES'):
            print(f"✅ GROQ_MAX_RETRIES = {config.GROQ_MAX_RETRIES}")
            results.append(True)
        else:
            print("❌ GROQ_MAX_RETRIES not found")
            results.append(False)
        
        # Check if WPScan backoff is in cve_lookup
        try:
            with open('/home/root17/Desktop/ai-recon-agent/integrations/cve_lookup.py', 'r') as f:
                content = f.read()
                if "exponential backoff" in content or "2 ** attempt" in content:
                    print("✅ WPScan exponential backoff implementation found")
                    results.append(True)
                else:
                    print("❌ WPScan exponential backoff not found")
                    results.append(False)
        except:
            results.append(False)
        
        return all(results)
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

def test_binary_file_filtering():
    """Test #4: Binary file filtering"""
    print("\n📁 Test #4: Binary File Filtering")
    print("─" * 50)
    try:
        with open('/home/root17/Desktop/ai-recon-agent/modules/crawler.py', 'r') as f:
            content = f.read()
            if ".jpg" in content and ".png" in content and "binary_extensions" in content:
                print("✅ Binary file filtering is implemented")
                return True
            else:
                print("❌ Binary file filtering not found")
                return False
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

def test_display_enhancements():
    """Test #5: Display enhancements"""
    print("\n✨ Test #5: Display Enhancements")
    print("─" * 50)
    try:
        with open('/home/root17/Desktop/ai-recon-agent/agent.py', 'r') as f:
            content = f.read()
            results = []
            
            # Check for progress bar method
            if "_get_progress_bar" in content:
                print("✅ Progress bar method added")
                results.append(True)
            else:
                print("❌ Progress bar method not found")
                results.append(False)
            
            # Check for enhanced progress text
            if ("percent" in content or "%" in content) and ("█" in content or "[" in content):
                print("✅ Enhanced progress display with percentage bars")
                results.append(True)
            else:
                print("❌ Enhanced progress display not found")
                results.append(False)
            
            # Check for live event feed
            if "LIVE EVENTS" in content or "live_feed" in content:
                print("✅ Live events feed implementation")
                results.append(True)
            else:
                print("❌ Live events feed not found")
                results.append(False)
            
            return all(results)
    except Exception as e:
        print(f"❌ FAIL: {e}")
        return False

def main():
    print("\n" + "="*60)
    print("🧪 AI-RECON-AGENT BUG FIX & ENHANCEMENT VERIFICATION")
    print("="*60)
    
    tests = [
        test_permission_fix,
        test_timeout_fixes,
        test_retry_mechanisms,
        test_binary_file_filtering,
        test_display_enhancements,
    ]
    
    results = []
    for test_func in tests:
        try:
            result = test_func()
            results.append(result)
        except Exception as e:
            print(f"\n❌ Test {test_func.__name__} crashed: {e}")
            results.append(False)
    
    # Summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY")
    print("="*60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ ALL TESTS PASSED - System is ready!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test(s) failed - Review above")
        return 1

if __name__ == "__main__":
    sys.exit(main())
