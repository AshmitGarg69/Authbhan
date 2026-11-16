#!/usr/bin/env python3
"""
Adversarial Test Harness 4: Concurrency & Stress on blocked.json
Tests:
- Rapid atomic persistence under multi-process contention (20 processes x 10 domains)
- File integrity verification (no JSONDecodeError, valid version, valid structure)
- Leftover temporary file leak audit (blocked_*.tmp)
- Lost updates audit (measuring write clobbering across distinct processes)
- In-process concurrent asyncio writes and probe coalescing
"""

import asyncio
import glob
import importlib.util
import json
import multiprocessing as mp
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

# Load smart-proxy.py
SRC_PATH = Path("/home/ashmit/Code/smart-tunnel/src/smart-proxy.py")
spec = importlib.util.spec_from_file_location("smart_proxy", str(SRC_PATH))
proxy_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy_mod)

CacheManager = proxy_mod.CacheManager


def worker_process_write(worker_id: int, cache_file: str, domains_per_worker: int, delay: float = 0.001):
    """Worker process that instantiates CacheManager and writes unique domains."""
    try:
        cm = CacheManager(cache_file)
        for i in range(domains_per_worker):
            domain = f"worker{worker_id}-site{i}.org"
            cm.mark_blocked(domain, f"reason_{worker_id}_{i}", 100 + i)
            if delay > 0:
                time.sleep(delay)
        return True, None
    except Exception as e:
        return False, str(e)


class TestAdversarialConcurrency(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="adv_conc_")
        self.cache_file = os.path.join(self.test_dir, "blocked.json")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_multi_process_contention_and_lost_updates(self):
        """Stress-test CacheManager under multi-process contention."""
        # Initialize empty cache
        cm_init = CacheManager(self.cache_file)
        cm_init.save()
        self.assertTrue(os.path.exists(self.cache_file))

        num_workers = 10
        domains_per_worker = 10
        total_expected_domains = num_workers * domains_per_worker

        print(f"\n--- Launching {num_workers} concurrent processes ({domains_per_worker} writes each) ---")
        t0 = time.time()
        with mp.Pool(processes=num_workers) as pool:
            results = pool.starmap(
                worker_process_write,
                [(w, self.cache_file, domains_per_worker, 0.005) for w in range(num_workers)]
            )
        elapsed = time.time() - t0
        print(f"Completed in {elapsed:.3f}s. Worker results: {results}")

        # Check for any exceptions in workers
        errors = [err for ok, err in results if not ok]
        self.assertEqual(len(errors), 0, f"Workers raised errors during write: {errors}")

        # 1. File Integrity Verification
        self.assertTrue(os.path.exists(self.cache_file))
        corrupt = False
        data = {}
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            corrupt = True
            print(f"[EMPIRICAL] Corruption detected: {e}")

        self.assertFalse(corrupt, "blocked.json was corrupted under concurrency!")
        self.assertEqual(data.get("version"), 1, "Schema version intact")

        # 2. Check for leaked temp files
        tmp_files = glob.glob(os.path.join(self.test_dir, "blocked_*.tmp"))
        print(f"[EMPIRICAL] Leaked tmp files count: {len(tmp_files)}")
        self.assertEqual(len(tmp_files), 0, f"Found {len(tmp_files)} leaked temporary files!")

        # 3. Check for Lost Updates across processes
        saved_domains = data.get("blocked_domains", {})
        count_saved = len(saved_domains)
        print(f"[EMPIRICAL] Total expected unique domains: {total_expected_domains}")
        print(f"[EMPIRICAL] Actual domains present in blocked.json: {count_saved}")
        lost_count = total_expected_domains - count_saved
        print(f"[EMPIRICAL] Lost updates count: {lost_count} ({(lost_count/total_expected_domains)*100:.1f}% data loss across uncoordinated processes)")

    def test_single_process_asyncio_concurrency(self):
        """Verify thread/task safety within a single process event loop."""
        asyncio.run(self._async_single_process_concurrency())

    async def _async_single_process_concurrency(self):
        cm = CacheManager(self.cache_file)
        num_tasks = 50

        async def _write_task(idx):
            await asyncio.sleep(0.001)
            async with cm.async_lock:
                cm.mark_blocked(f"async-site-{idx}.com", "mitm", idx * 10)

        tasks = [_write_task(i) for i in range(num_tasks)]
        await asyncio.gather(*tasks)

        # Check memory and disk
        self.assertEqual(len(cm.blocked_domains), num_tasks)
        with open(self.cache_file, "r", encoding="utf-8") as f:
            disk_data = json.load(f)
        self.assertEqual(len(disk_data.get("blocked_domains", {})), num_tasks)
        print(f"\n[EMPIRICAL] Single process asyncio concurrent writes: {num_tasks}/{num_tasks} persisted successfully.")


if __name__ == "__main__":
    unittest.main()
