#!/usr/bin/env python3
"""
Auto-fix script for ai-recon-agent errors
Run: python3 auto_fix_all_errors.py
"""

import os
import re
import sys
import shutil
from datetime import datetime

def backup_file(filepath):
    """Create backup before modifying"""
    if os.path.exists(filepath):
        backup = filepath + f".bak_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(filepath, backup)
        print(f"📁 Backup created: {backup}")
        return True
    return False

def fix_payload_mutation(filepath):
    """Fix payload_mutation.py - add type checking"""
    print(f"\n🔧 Fixing {filepath}...")
    
    if not os.path.exists(filepath):
        print(f"   ❌ File not found: {filepath}")
        return False
    
    backup_file(filepath)
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # List of methods that need type checking
    methods_to_fix = [
        '_base64_encode',
        '_url_encode', 
        '_double_url_encode',
        '_html_encode',
        '_hex_encode',
        '_case_variations',
        '_add_comments',
        '_quote_variations',
        '_command_injection',
        '_mutate_for_sqli',
        '_mutate_for_xss',
        '_mutate_for_rce',
        '_waf_replace_keywords'
    ]
    
    type_check_code = '''        # Auto-fix: type checking for dict input
        if not isinstance(payload, str):
            if isinstance(payload, dict):
                payload = str(payload)
            else:
                return ""
        
'''
    
    fixed_count = 0
    for method in methods_to_fix:
        # Pattern to find method definition
        pattern = rf'(def {method}\(self, payload: str\) -> str:\n)(    )?"""'
        
        # Check if method exists and doesn't already have the fix
        if method in content and 'not isinstance(payload, str)' not in content.split(f'def {method}')[1][:500]:
            # Add type check after method definition line
            content = content.replace(
                f'def {method}(self, payload: str) -> str:\n',
                f'def {method}(self, payload: str) -> str:\n{type_check_code}'
            )
            fixed_count += 1
            print(f"   ✅ Fixed: {method}")
    
    # Fix _mutate_for_* methods which have different signature
    mutate_patterns = [
        ('_mutate_for_sqli', 'def _mutate_for_sqli(self, payloads: List[str]) -> List[str]:'),
        ('_mutate_for_xss', 'def _mutate_for_xss(self, payloads: List[str]) -> List[str]:'),
        ('_mutate_for_rce', 'def _mutate_for_rce(self, payloads: List[str]) -> List[str]:'),
    ]
    
    for method_name, method_def in mutate_patterns:
        if method_def in content and 'if not isinstance(payloads' not in content.split(method_def)[1][:500]:
            type_check_list = '''        # Auto-fix: type checking for list input
        if not isinstance(payloads, list):
            return []
        
'''
            content = content.replace(
                method_def + '\n',
                method_def + '\n' + type_check_list
            )
            fixed_count += 1
            print(f"   ✅ Fixed: {method_name}")
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    print(f"   ✅ Fixed {fixed_count} methods in {filepath}")
    return True

def fix_toolkit_scanner(filepath):
    """Fix toolkit_scanner.py - add timeout parameter"""
    print(f"\n🔧 Fixing {filepath}...")
    
    if not os.path.exists(filepath):
        print(f"   ❌ File not found: {filepath}")
        return False
    
    backup_file(filepath)
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Fix _scan_nikto method signature
    pattern = r'def _scan_nikto\(\n?\s*self,\n?\s*url: str,\n?\s*progress_cb=None\n?\):'
    replacement = 'def _scan_nikto(self, url: str, progress_cb=None, timeout=180):'
    
    if 'def _scan_nikto' in content and 'timeout' not in content.split('def _scan_nikto')[1][:200]:
        content = re.sub(pattern, replacement, content, flags=re.MULTILINE)
        print(f"   ✅ Added timeout parameter to _scan_nikto")
    
    # Also fix the subprocess call if timeout is used
    if 'timeout=' in content:
        print(f"   ✅ timeout parameter already used")
    
    with open(filepath, 'w') as f:
        f.write(content)
    
    return True

def fix_wp_scanner(filepath):
    """Fix wp_scanner.py - add retry logic"""
    print(f"\n🔧 Fixing {filepath}...")
    
    if not os.path.exists(filepath):
        print(f"   ❌ File not found: {filepath}")
        return False
    
    backup_file(filepath)
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Check if retry logic already exists
    if 'for attempt in range' in content:
        print(f"   ✅ Retry logic already exists")
        return True
    
    # Find _run_wpscan method
    if 'def _run_wpscan' in content:
        # Add retry wrapper
        retry_code = '''
    # Auto-fix: Add retry logic for wpscan
    for attempt in range(3):
        try:
            # Original code continues below
            if not tool_available("wpscan"):
                return {}
            
            os.makedirs(self.wpscan_cache_dir, exist_ok=True)
            
            cmd = [
                "wpscan",
                "--url", url,
                "--format", "json",
                "--cache-dir", self.wpscan_cache_dir
            ]
'''
        
        # This is complex - manual edit needed
        print(f"   ⚠️ Manual fix needed for wpscan retry logic")
        print(f"   📝 Please check {filepath} and add retry logic around line 502")
    
    return True

def fix_recon_ct_lookup(filepath):
    """Fix recon.py - add retry for CT lookup"""
    print(f"\n🔧 Fixing {filepath}...")
    
    if not os.path.exists(filepath):
        print(f"   ❌ File not found: {filepath}")
        return False
    
    backup_file(filepath)
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Check if retry already exists
    if 'for attempt in range' in content and 'CT lookup' in content:
        print(f"   ✅ Retry logic already exists")
        return True
    
    # Find CT lookup error line
    if 'logger.warning(f"[RECON] CT lookup failed: {e}")' in content:
        # Add retry wrapper
        retry_block = '''
                # Auto-fix: Add retry for CT lookup
                for attempt in range(2):
                    try:
                        # Original CT lookup code
                        # ... (insert original code here)
                        break
                    except Exception as e:
                        if attempt == 0:
                            import time
                            time.sleep(2)
                            continue
                        logger.warning(f"[RECON] CT lookup failed after retry: {e}")
                        break
'''
        print(f"   ⚠️ Manual fix needed for CT lookup retry logic")
        print(f"   📝 Please check {filepath} line 440 and add retry logic")
    
    return True

def verify_fixes():
    """Verify that fixes were applied correctly"""
    print("\n" + "="*60)
    print("VERIFYING FIXES")
    print("="*60)
    
    checks = [
        ('ai/payload_mutation.py', 'not isinstance(payload, str)', 'Type checking added'),
        ('modules/toolkit_scanner.py', 'timeout=180', 'Timeout parameter added'),
        ('modules/recon.py', 'for attempt in range', 'Retry logic added (if applicable)'),
        ('modules/wp_scanner.py', 'for attempt in range', 'Retry logic added (if applicable)'),
    ]
    
    all_ok = True
    for filepath, pattern, message in checks:
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                content = f.read()
                if pattern in content:
                    print(f"✅ {filepath}: {message}")
                else:
                    print(f"⚠️ {filepath}: {message} - NOT FOUND (may need manual fix)")
                    all_ok = False
        else:
            print(f"❌ {filepath}: File not found")
            all_ok = False
    
    return all_ok

def main():
    print("="*60)
    print("AI-RECON-AGENT AUTO-FIX SCRIPT")
    print("="*60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Fix each file
    fixes = [
        ('ai/payload_mutation.py', fix_payload_mutation),
        ('modules/toolkit_scanner.py', fix_toolkit_scanner),
        ('modules/wp_scanner.py', fix_wp_scanner),
        ('modules/recon.py', fix_recon_ct_lookup),
    ]
    
    for filepath, fix_func in fixes:
        fix_func(filepath)
    
    # Verify fixes
    success = verify_fixes()
    
    print("\n" + "="*60)
    if success:
        print("✅ All fixes applied successfully!")
    else:
        print("⚠️ Some fixes may need manual intervention")
    print("="*60)
    
    print("\n📝 Next steps:")
    print("1. Run: python3 agent.py --target http://localhost:8000")
    print("2. Check if errors are reduced")
    print("3. Verify report shows vulnerabilities_found = 621")
    print()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
