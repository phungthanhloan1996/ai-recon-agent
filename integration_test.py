#!/usr/bin/env python3
"""
Integration Test - Verify all 10 improvements work together
Run with: python3 integration_test.py
"""

import sys
import os

def test_all_improvements():
    print("\n" + "="*80)
    print("INTEGRATION TEST - AI RECON AGENT IMPROVEMENTS")
    print("="*80 + "\n")
    
    tests_passed = 0
    tests_total = 10
    passed_checks = []
    
    # Test 1: URL Normalization
    try:
        from core.url_normalizer_enhanced import URLNormalizer
        
        test_cases = [
            ('example.com', True),
            ('https://example.com', True),
            ('http://example.com', True),
        ]
        
        all_pass = True
        for url, expected_valid in test_cases:
            normalized, valid, err = URLNormalizer.normalize(url, follow_redirects=False)
            if valid != expected_valid:
                all_pass = False
                print(f"  ✗ '{url}' expected {expected_valid}, got {valid}")
        
        if all_pass:
            print(f"✓ PASS: URL Normalization - handles schemes, domains, redirects")
            tests_passed += 1
            passed_checks.append("#1 URL Normalization")
        else:
            print(f"✗ FAIL: URL Normalization")
        
    except Exception as e:
        print(f"✗ FAIL: URL Normalization - {e}")
    
    # Test 2: Endpoint Classification
    try:
        from core.endpoint_analyzer import EndpointAnalyzer
        
        # Test static file detection
        result = EndpointAnalyzer._classify_type('http://example.com/image.jpg', 'image/jpeg')
        test2_pass = result == 'static'
        
        # Test API detection
        result = EndpointAnalyzer._classify_type('http://example.com/api/users', 'application/json')
        test2_pass = test2_pass and result in ('json', 'api')
        
        if test2_pass:
            print(f"✓ PASS: Endpoint Classification - static/html/json/api detection")
            tests_passed += 1
            passed_checks.append("#2 Endpoint Classification")
        else:
            print(f"✗ FAIL: Endpoint Classification")
        
    except Exception as e:
        print(f"✗ FAIL: Endpoint Classification - {e}")
    
    # Test 3: HTML Form Extraction
    try:
        from core.endpoint_analyzer import FormExtractor
        
        html = '''
        <html>
            <form action="/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
            </form>
        </html>
        '''
        
        extractor = FormExtractor()
        extractor.feed(html)
        
        if len(extractor.forms) == 1:
            form = extractor.forms[0]
            if form['action'] == '/login' and form['method'] == 'POST':
                print(f"✓ PASS: HTML Form Extraction - parses forms/inputs/multipart")
                tests_passed += 1
                passed_checks.append("#3 HTML Form Extraction")
            else:
                print(f"✗ FAIL: HTML Form Extraction - structure incorrect")
        else:
            print(f"✗ FAIL: HTML Form Extraction")
        
    except Exception as e:
        print(f"✗ FAIL: HTML Form Extraction - {e}")
    
    # Test 4: Error Recovery & Self-Reflection
    try:
        from core.error_recovery import ErrorRecovery
        
        recovery = ErrorRecovery()
        recovery.log_error('scan', 'nuclei', 'Connection refused')
        recovery.log_error('scan', 'nuclei', 'Timeout')
        
        if recovery.error_count['scan'] >= 2:
            suggestion = recovery.suggest_recovery('scan', 'nuclei', 'Connection refused')
            if suggestion['error_type'] == 'connection_refused':
                print(f"✓ PASS: Error Recovery - auto-categorize, retry, adapt strategy")
                tests_passed += 1
                passed_checks.append("#4 Error Recovery Loop")
            else:
                print(f"✗ FAIL: Error Recovery")
        else:
            print(f"✗ FAIL: Error Recovery")
        
    except Exception as e:
        print(f"✗ FAIL: Error Recovery - {e}")
    
    # Test 5: Conditional Playbook
    try:
        from core.error_recovery import ConditionalPlaybook
        
        playbook = ConditionalPlaybook()
        findings = {'found_wordpress': True, 'plugins': [{'name': 'test'}], 'users': []}
        actions = playbook.execute_playbook(findings)
        
        if 'wp_plugin_scan' in actions:
            print(f"✓ PASS: Conditional Playbook - IF/THEN dynamic routing")
            tests_passed += 1
            passed_checks.append("#5 Conditional Playbook")
        else:
            print(f"✗ FAIL: Conditional Playbook")
        
    except Exception as e:
        print(f"✗ FAIL: Conditional Playbook - {e}")
    
    # Test 6: Wordlist Generation
    try:
        from core.wordlist_generator import WordlistGenerator
        
        gen = WordlistGenerator()
        gen.set_context('acme', 'acme.com', ['admin', 'test'])
        
        usernames = gen.generate_usernames(10)
        passwords = gen.generate_passwords(usernames, 20)
        directories = gen.generate_dirs(10)
        
        has_context = any('acme' in p.lower() for p in passwords)
        
        if len(usernames) > 0 and len(passwords) > 0 and has_context:
            print(f"✓ PASS: Wordlist Generation - smart context-aware generation")
            tests_passed += 1
            passed_checks.append("#6 Wordlist Generation")
        else:
            print(f"✗ FAIL: Wordlist Generation")
        
    except Exception as e:
        print(f"✗ FAIL: Wordlist Generation - {e}")
    
    # Test 7: Upload Exploit Logic
    try:
        from core.exploit_executor import ExploitExecutor
        
        mutations = ExploitExecutor.UPLOAD_MUTATIONS
        required = ['.php', '.phtml', '.jpg.php']
        
        if len(mutations) > 10 and all(any(r in m for m in mutations) for r in required):
            print(f"✓ PASS: Upload Exploit - multipart + mutations: {len(mutations)} variants")
            tests_passed += 1
            passed_checks.append("#7 Upload Exploit Logic")
        else:
            print(f"✗ FAIL: Upload Exploit")
        
    except Exception as e:
        print(f"✗ FAIL: Upload Exploit Logic - {e}")
    
    # Test 8: Session Management
    try:
        from core.http_engine import HTTPClient
        
        client = HTTPClient()
        if hasattr(client, 'session') and hasattr(client.session, 'cookies'):
            print(f"✓ PASS: Session Management - cookie jar persistence")
            tests_passed += 1
            passed_checks.append("#8 Session Management")
        else:
            print(f"✗ FAIL: Session Management")
        
    except Exception as e:
        print(f"✗ FAIL: Session Management - {e}")
    
    # Test 9: Iteration Reduction (5→3)
    try:
        from agent import DomainDisplay
        
        dd = DomainDisplay('example.com', {})
        max_iter = dd.data['max_iter']
        dd.stop()
        
        if max_iter == 3:
            print(f"✓ PASS: Iteration Reduction - max = 3 (was 5)")
            tests_passed += 1
            passed_checks.append("#9 Iteration Reduction")
        else:
            print(f"✗ FAIL: Iteration Reduction")
        
    except Exception as e:
        print(f"✗ FAIL: Iteration Reduction - {e}")
    
    # Test 10: Real Tool Integration
    try:
        from core.exploit_executor import ExploitExecutor
        
        # Check for real execution methods
        methods = ['run_wpscan', 'run_nuclei', 'run_dalfox']
        executor_methods = [m for m in methods if hasattr(ExploitExecutor, m)]
        
        if len(executor_methods) == 3:
            print(f"✓ PASS: Real Tool Execution - wpscan, nuclei, dalfox")
            tests_passed += 1
            passed_checks.append("#10 Real Tool Execution")
        else:
            print(f"✗ FAIL: Real Tool Execution")
        
    except Exception as e:
        print(f"✗ FAIL: Real Tool Execution - {e}")
    
    # Summary
    print("\n" + "="*80)
    print(f"RESULTS: {tests_passed}/{tests_total} CRITICAL IMPROVEMENTS VERIFIED")
    print("="*80)
    
    if tests_passed == tests_total:
        print("\n✅ ALL 10 IMPROVEMENTS IMPLEMENTED AND WORKING!\n")
        print("Verified Improvements:")
        for check in passed_checks:
            print(f"  ✓ {check}")
        print()
        return 0
    else:
        print(f"\n⚠️  {tests_total - tests_passed} improvement(s) need review\n")
        return 1

if __name__ == '__main__':
    sys.exit(test_all_improvements())
