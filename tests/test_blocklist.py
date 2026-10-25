"""
tests/test_blocklist.py  —  Unit Tests for Blocklist Manager & Hot Reload
========================================================================
"""

import os
import time
import tempfile
import unittest
import threading
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.blocklist import Blocklist


class TestBlocklist(unittest.TestCase):
    def setUp(self):
        self.bl = Blocklist(lookup_cache_size=256)

    def test_basic_and_subdomain_blocking(self):
        self.bl.add_domain("doubleclick.net", "ads")
        self.bl.add_domain("bad-tracker.com", "trackers")

        # Exact match
        blocked, cat = self.bl.is_blocked("doubleclick.net")
        self.assertTrue(blocked)
        self.assertEqual(cat, "ads")

        # Subdomain match
        blocked, cat = self.bl.is_blocked("ads.doubleclick.net")
        self.assertTrue(blocked)
        self.assertEqual(cat, "ads")

        blocked, cat = self.bl.is_blocked("deep.sub.ads.doubleclick.net")
        self.assertTrue(blocked)
        self.assertEqual(cat, "ads")

        # Unblocked domain
        blocked, _ = self.bl.is_blocked("google.com")
        self.assertFalse(blocked)

        # Trailing dot handling
        blocked, cat = self.bl.is_blocked("doubleclick.net.")
        self.assertTrue(blocked)

    def test_allowlist_override(self):
        self.bl.add_domain("doubleclick.net", "ads")
        self.bl.add_to_allowlist("safe.doubleclick.net")

        # Parent is blocked
        blocked, _ = self.bl.is_blocked("ads.doubleclick.net")
        self.assertTrue(blocked)

        # Allowlisted subdomain is allowed
        blocked, _ = self.bl.is_blocked("safe.doubleclick.net")
        self.assertFalse(blocked)

    def test_atomic_reload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ads_file = os.path.join(tmpdir, "ads.txt")
            allow_file = os.path.join(tmpdir, "allowlist.txt")

            with open(ads_file, "w") as f:
                f.write("blocked1.com\nblocked2.com\n")
            with open(allow_file, "w") as f:
                f.write("allowed1.com\n")

            self.bl.load_all_blocklists(tmpdir)
            self.bl.load_allowlist(allow_file)

            self.assertTrue(self.bl.is_blocked("blocked1.com")[0])
            self.assertFalse(self.bl.is_blocked("allowed1.com")[0])

            # Update file and reload
            with open(ads_file, "w") as f:
                f.write("blocked3.com\n")

            self.bl.reload(tmpdir, allow_file)

            self.assertFalse(self.bl.is_blocked("blocked1.com")[0])
            self.assertTrue(self.bl.is_blocked("blocked3.com")[0])

    def test_thread_safety_during_queries_and_reload(self):
        # 10,000 domains
        for i in range(10000):
            self.bl.blocked_domains[f"ad-{i}.com"] = "ads"

        stop_event = threading.Event()

        def reader():
            while not stop_event.is_set():
                self.bl.is_blocked("ad-50.com")
                self.bl.is_blocked("safe-query.com")

        def writer():
            for i in range(50):
                self.bl.add_domain(f"new-ad-{i}.com", "ads")
                time.sleep(0.001)

        readers = [threading.Thread(target=reader) for _ in range(4)]
        w = threading.Thread(target=writer)

        for r in readers:
            r.start()
        w.start()

        w.join()
        stop_event.set()
        for r in readers:
            r.join()

        self.assertTrue(self.bl.is_blocked("new-ad-0.com")[0])


if __name__ == "__main__":
    unittest.main()
