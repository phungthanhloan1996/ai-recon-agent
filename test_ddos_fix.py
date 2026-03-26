#!/usr/bin/env python3
"""
Test script để kiểm tra DDoS attack functionality
"""

import os
import sys
import tempfile
import json
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
)
logger = logging.getLogger("test_ddos")

# Add repo to path
repo_root = Path(__file__).parent
sys.path.insert(0, str(repo_root))

from core.state_manager import StateManager, ScanState
from modules.ddos_attacker import DDoSAttacker


def test_ddos_attack():
    """Test DDoS attack with sample endpoints"""
    
    logger.info("=" * 80)
    logger.info("DDoS ATTACK FUNCTIONALITY TEST")
    logger.info("=" * 80)
    
    # Create temporary output directory
    output_dir = tempfile.mkdtemp(prefix="ddos_test_")
    logger.info(f"[TEST] Output directory: {output_dir}")
    
    # Initialize state with required parameters
    state = StateManager(target="test.example.com", output_dir=output_dir)
    
    # Create sample endpoints
    test_endpoints = [
        {"url": "http://httpbin.org/get", "priority": "HIGH"},
        {"url": "http://httpbin.org/delay/1", "priority": "MEDIUM"},
        {"url": "http://httpbin.org/status/200", "priority": "LOW"},
    ]
    
    logger.info(f"[TEST] Created {len(test_endpoints)} test endpoints")
    for ep in test_endpoints:
        logger.info(f"  - {ep['url']}")
    
    # Initialize DDoS attacker
    try:
        logger.info("[TEST] Initializing DDoSAttacker...")
        ddos = DDoSAttacker(state, output_dir)
        logger.info("[TEST] ✅ DDoSAttacker initialized successfully")
    except Exception as e:
        logger.error(f"[TEST] ❌ Failed to initialize DDoSAttacker: {e}", exc_info=True)
        return False
    
    # Test parameter configurations
    test_configs = [
        {"users": 10, "spawn_rate": 5, "runtime": 5, "name": "Light test (10 users, 5s)"},
        {"users": 50, "spawn_rate": 10, "runtime": 10, "name": "Medium test (50 users, 10s)"},
    ]
    
    for config in test_configs:
        name = config.pop("name")
        logger.info(f"\n[TEST] Running: {name}")
        logger.info(f"[TEST] Config: {config}")
        
        try:
            logger.info("[TEST] Launching DDoS attack...")
            results = ddos.run_ddos_attack(
                endpoints=test_endpoints,
                **config
            )
            
            logger.info(f"[TEST] Attack results: {json.dumps(results, indent=2)}")
            
            if results.get("status") == "completed":
                logger.info(f"[TEST] ✅ Attack completed successfully!")
                logger.info(f"  - Total requests: {results.get('total_requests')}")
                logger.info(f"  - RPS: {results.get('current_rps')}")
                logger.info(f"  - Failures: {results.get('failures')}")
            else:
                logger.warning(f"[TEST] ⚠️  Attack did not complete: {results.get('reason')}")
                
        except Exception as e:
            logger.error(f"[TEST] ❌ Attack failed: {e}", exc_info=True)
            return False
    
    # Check output files
    logger.info("\n[TEST] Checking output files...")
    output_files = os.listdir(output_dir)
    logger.info(f"[TEST] Generated files ({len(output_files)}):")
    for file in output_files:
        fpath = os.path.join(output_dir, file)
        size = os.path.getsize(fpath)
        logger.info(f"  - {file} ({size} bytes)")
    
    # Check for DDoS report files
    has_report = any("ddos" in f.lower() or "report" in f.lower() for f in output_files)
    if has_report:
        logger.info("[TEST] ✅ DDoS report files generated")
    else:
        logger.warning("[TEST] ⚠️  DDoS report files not found")
    
    logger.info("\n" + "=" * 80)
    logger.info("TEST COMPLETED")
    logger.info("=" * 80)
    
    return True


if __name__ == "__main__":
    success = test_ddos_attack()
    sys.exit(0 if success else 1)
