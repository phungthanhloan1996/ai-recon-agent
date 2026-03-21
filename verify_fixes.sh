#!/bin/bash
echo "=========================================="
echo "VERIFYING FIXES AFTER AUTO-PATCH"
echo "=========================================="

# 1. Kiểm tra report generator
echo -e "\n1. CHECKING REPORT GENERATOR..."
if grep -q "confirmed_vulnerabilities.*vulnerabilities" reports/report_generator.py; then
    echo "   ✅ Report generator fixed"
else
    echo "   ❌ Report generator NOT fixed"
fi

# 2. Kiểm tra payload_mutation type checking
echo -e "\n2. CHECKING PAYLOAD_MUTATION..."
if grep -q "not isinstance(payload, str)" ai/payload_mutation.py; then
    echo "   ✅ Type checking added"
else
    echo "   ❌ Type checking NOT added"
fi

# 3. Kiểm tra toolkit_scanner timeout
echo -e "\n3. CHECKING TOOLKIT_SCANNER..."
if grep -q "timeout=180" modules/toolkit_scanner.py; then
    echo "   ✅ Timeout parameter added"
else
    echo "   ❌ Timeout parameter NOT added"
fi

# 4. Kiểm tra state.json hiện tại
echo -e "\n4. CHECKING STATE.JSON..."
if [ -f "results/http:/localhost:8000_20260320_230125/state.json" ]; then
    confirmed=$(python3 -c "import json; s=json.load(open('results/http:/localhost:8000_20260320_230125/state.json')); print(len(s.get('confirmed_vulnerabilities', [])))" 2>/dev/null || echo "0")
    vulns=$(python3 -c "import json; s=json.load(open('results/http:/localhost:8000_20260320_230125/state.json')); print(len(s.get('vulnerabilities', [])))" 2>/dev/null || echo "0")
    echo "   Confirmed vulnerabilities: $confirmed"
    echo "   Vulnerabilities: $vulns"
    echo "   Total should be: $((confirmed + vulns))"
fi

echo -e "\n=========================================="
echo "RECOMMENDATION:"
echo "1. If all checks pass, run: python3 agent.py --target http://localhost:8000"
echo "2. Check logs for remaining errors"
echo "3. Verify final report"
echo "=========================================="
