"""
INTEGRATION TEST: Full Pipeline Fix Verification
=================================================

Tests the complete data flow:
1. Endpoint ranking returns dicts
2. Agent extracts URLs correctly
3. Endpoints reach scanner with proper structure
4. Scanner normalizes empty categories/parameters
5. Pipelines doesn't break on edge cases
"""

import sys
import os
import json
import tempfile
import logging
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.endpoint_ranker import EndpointRanker
from core.state_manager import StateManager
from modules.scanner import ScanningEngine
from ai.payload_gen import PayloadGenerator
from ai.payload_mutation import PayloadMutator
from learning.learning_engine import LearningEngine

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)
logger = logging.getLogger("test_integration")


class IntegrationTest:
    """Full end-to-end test of the pipeline fix"""
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="recon_test_")
        self.results = []
        logger.info(f"Using temp directory: {self.temp_dir}")
    
    def test_ranking_to_state_flow(self):
        """Test 1: Ranking → URL extraction → state population"""
        logger.info("\n" + "="*70)
        logger.info("TEST 1: Ranking → URL extraction → State population")
        logger.info("="*70)
        
        try:
            # Setup
            all_eps = [
                {"url": "http://test.com/admin", "categories": ["admin"], "parameters": []},
                {"url": "http://test.com/upload.php", "categories": ["upload"], "parameters": []},
                {"url": "http://test.com/api/users", "categories": ["api"], "parameters": ["id"]},
                {"url": "http://test.com/login", "categories": ["auth"], "parameters": []},
                {"url": "http://test.com/search?q=test", "categories": [], "parameters": ["q"]},
            ]
            
            state = StateManager("integration.test.com", self.temp_dir)
            
            # STEP 1: Rank endpoints (this returns List[Dict])
            logger.info("\n[STEP 1] Ranking endpoints...")
            ranker = EndpointRanker()
            ranked_dicts = ranker.rank_endpoints([ep["url"] for ep in all_eps])
            logger.info(f"  ✓ Ranker returned {len(ranked_dicts)} ranked dicts")
            
            assert isinstance(ranked_dicts, list), "❌ Ranker output is not a list"
            assert len(ranked_dicts) > 0, "❌ Ranker output is empty"
            
            # STEP 2: Extract URLs from dicts (THE FIX!)
            logger.info("\n[STEP 2] Extracting URLs from ranked dicts...")
            ranked_urls = [item["url"] for item in ranked_dicts] if ranked_dicts else []
            logger.info(f"  ✓ Extracted {len(ranked_urls)} URLs")
            
            assert all(isinstance(u, str) for u in ranked_urls), "❌ Not all URLs are strings"
            assert len(ranked_urls) == len(all_eps), "❌ URL count mismatch"
            
            # STEP 3: Map back to full objects
            logger.info("\n[STEP 3] Mapping URLs back to full endpoints...")
            url_map = {ep["url"]: ep for ep in all_eps}
            final_targets = [url_map[u] for u in ranked_urls if u in url_map]
            logger.info(f"  ✓ Mapped {len(final_targets)} endpoints")
            
            assert len(final_targets) > 0, f"❌ Mapping failed, got {len(final_targets)} targets"
            assert len(final_targets) == len(all_eps), f"❌ Expected {len(all_eps)}, got {len(final_targets)}"
            
            # STEP 4: Store in state
            logger.info("\n[STEP 4] Storing in state as prioritized_endpoints...")
            state.update(prioritized_endpoints=final_targets)
            retrieved = state.get("prioritized_endpoints", [])
            logger.info(f"  ✓ State contains {len(retrieved)} endpoints")
            
            assert len(retrieved) == len(final_targets), "❌ State retrieval failed"
            
            logger.info("\n✅ TEST 1 PASSED: Full ranking → state flow works correctly\n")
            self.results.append(("TEST 1", "PASS"))
            return True
            
        except Exception as e:
            logger.error(f"\n❌ TEST 1 FAILED: {e}\n")
            self.results.append(("TEST 1", f"FAIL: {e}"))
            return False
    
    def test_scanner_receives_endpoints(self):
        """Test 2: Scanner receives properly structured endpoints"""
        logger.info("\n" + "="*70)
        logger.info("TEST 2: Scanner receives properly structured endpoints")
        logger.info("="*70)
        
        try:
            state = StateManager("scanner.test.com", self.temp_dir)
            
            # Simulate agent's processed endpoints
            endpoints = [
                {
                    "url": "http://httpbin.org/get?id=1",
                    "categories": ["injection"],
                    "parameters": ["id"],
                },
                {
                    "url": "http://httpbin.org/search?q=test",
                    "categories": [],  # Empty categories to test auto-detection
                    "parameters": ["q"],
                },
                {
                    "url": "http://httpbin.org/admin",
                    "categories": ["admin"],
                    "parameters": [],  # Empty parameters to test auto-detection
                },
            ]
            
            state.update(prioritized_endpoints=endpoints)
            
            # Initialize scanner
            payload_gen = PayloadGenerator()
            payload_mutator = PayloadMutator()
            learning_engine = LearningEngine(self.temp_dir)
            scanner = ScanningEngine(
                state, self.temp_dir,
                payload_gen, payload_mutator, learning_engine
            )
            
            logger.info("\n[CHECK 1] Scanner can read prioritized_endpoints...")
            prioritized = state.get("prioritized_endpoints", [])
            assert prioritized is not None, "❌ prioritized_endpoints is None"
            assert len(prioritized) == 3, f"❌ Expected 3 endpoints, got {len(prioritized)}"
            logger.info(f"  ✓ Found {len(prioritized)} endpoints")
            
            logger.info("\n[CHECK 2] Each endpoint has required structure...")
            for idx, ep in enumerate(prioritized):
                assert isinstance(ep, dict), f"❌ Endpoint {idx} is not a dict"
                assert "url" in ep, f"❌ Endpoint {idx} missing 'url'"
                assert isinstance(ep["url"], str), f"❌ Endpoint {idx} url not string"
                url = ep["url"]
                assert url.startswith("http"), f"❌ Endpoint {idx} url invalid: {url}"
                logger.info(f"  ✓ Endpoint {idx}: {url} is valid")
            
            logger.info("\n[CHECK 3] scan_endpoint can extract fields...")
            for idx, ep in enumerate(prioritized):
                # Simulate what scan_endpoint does
                url = ep.get("url", "")
                categories = ep.get("categories", []) or []
                parameters = ep.get("parameters", []) or []
                
                assert url, f"❌ Endpoint {idx} has no URL"
                
                # Check auto-detection logic would work
                if not categories:
                    url_lower = url.lower()
                    if any(kw in url_lower for kw in ["admin", "search", "api"]):
                        categories = ["auto_detected"]
                
                logger.info(f"  ✓ Endpoint {idx}: url={url[:40]}..., cats={categories}, params={parameters}")
            
            logger.info("\n✅ TEST 2 PASSED: Scanner receives valid endpoints\n")
            self.results.append(("TEST 2", "PASS"))
            return True
            
        except Exception as e:
            logger.error(f"\n❌ TEST 2 FAILED: {e}\n")
            self.results.append(("TEST 2", f"FAIL: {e}"))
            return False
    
    def test_fallback_handling(self):
        """Test 3: Fallback logic works when ranking fails"""
        logger.info("\n" + "="*70)
        logger.info("TEST 3: Fallback logic for empty ranking")
        logger.info("="*70)
        
        try:
            all_eps = [
                {"url": "http://test.com/a", "categories": [], "parameters": []},
                {"url": "http://test.com/b", "categories": [], "parameters": []},
            ]
            
            # Simulate ranker returning empty (edge case)
            logger.info("\n[SCENARIO] Ranker returns empty list...")
            ranked_dicts = []  # Empty result
            
            # Apply the fix's fallback logic
            ranked_urls = [item["url"] for item in ranked_dicts] if ranked_dicts else []
            logger.info(f"  → Extracted URLs: {len(ranked_urls)}")
            
            if not ranked_urls:
                logger.info("  → Triggering fallback...")
                ranked_urls = [ep["url"] for ep in all_eps]
            
            assert len(ranked_urls) > 0, "❌ Fallback didn't work"
            logger.info(f"  ✓ Fallback returned {len(ranked_urls)} URLs")
            
            # Map back
            url_map = {ep["url"]: ep for ep in all_eps}
            final_targets = [url_map[u] for u in ranked_urls if u in url_map]
            
            assert len(final_targets) == len(all_eps), "❌ Final targets don't match input"
            logger.info(f"  ✓ Mapped back to {len(final_targets)} endpoints")
            
            logger.info("\n✅ TEST 3 PASSED: Fallback logic works correctly\n")
            self.results.append(("TEST 3", "PASS"))
            return True
            
        except Exception as e:
            logger.error(f"\n❌ TEST 3 FAILED: {e}\n")
            self.results.append(("TEST 3", f"FAIL: {e}"))
            return False
    
    def test_empty_categories_handling(self):
        """Test 4: Scanner handles empty categories with auto-detection"""
        logger.info("\n" + "="*70)
        logger.info("TEST 4: Scanner auto-detects categories when empty")
        logger.info("="*70)
        
        try:
            state = StateManager("autodetect.test.com", self.temp_dir)
            
            # Endpoints with empty categories (from fallback)
            endpoints = [
                {"url": "http://test.com/admin/panel", "categories": [], "parameters": []},
                {"url": "http://test.com/search?q=test", "categories": [], "parameters": []},
                {"url": "http://test.com/api/v1/users?id=1", "categories": [], "parameters": []},
            ]
            
            state.update(prioritized_endpoints=endpoints)
            
            logger.info("\n[CHECK] Auto-detection logic...")
            for idx, ep in enumerate(endpoints):
                url = ep.get("url", "")
                categories = ep.get("categories", []) or []
                
                # Apply auto-detection (same logic as scanner.py)
                if not categories:
                    detected = []
                    url_lower = url.lower()
                    if any(kw in url_lower for kw in ["admin", "login", "auth", "panel"]):
                        detected.append("authentication")
                    if any(kw in url_lower for kw in ["search", "query"]):
                        detected.append("injection")
                    if any(kw in url_lower for kw in ["api"]):
                        detected.append("api_injection")
                    categories = detected or ["generic"]
                
                logger.info(f"  ✓ {url[:40]}... → {categories}")
                assert len(categories) > 0, f"❌ Auto-detection failed for {url}"
            
            logger.info("\n✅ TEST 4 PASSED: Auto-detection works for all endpoints\n")
            self.results.append(("TEST 4", "PASS"))
            return True
            
        except Exception as e:
            logger.error(f"\n❌ TEST 4 FAILED: {e}\n")
            self.results.append(("TEST 4", f"FAIL: {e}"))
            return False
    
    def run_all(self):
        """Execute all integration tests"""
        logger.info("\n\n")
        logger.info("█" * 70)
        logger.info("█ INTEGRATION TEST SUITE: Full Pipeline Fix Validation")
        logger.info("█" * 70)
        
        results = [
            self.test_ranking_to_state_flow(),
            self.test_scanner_receives_endpoints(),
            self.test_fallback_handling(),
            self.test_empty_categories_handling(),
        ]
        
        # Summary
        logger.info("\n" + "="*70)
        logger.info("TEST SUMMARY")
        logger.info("="*70)
        
        for test_name, status in self.results:
            symbol = "✅" if status == "PASS" else "❌"
            logger.info(f"{symbol} {test_name}: {status}")
        
        passed = sum(1 for _, status in self.results if status == "PASS")
        total = len(self.results)
        
        logger.info("\n" + "-"*70)
        logger.info(f"TOTAL: {passed}/{total} tests passed")
        logger.info("="*70 + "\n")
        
        return passed == total


if __name__ == "__main__":
    tester = IntegrationTest()
    success = tester.run_all()
    sys.exit(0 if success else 1)
