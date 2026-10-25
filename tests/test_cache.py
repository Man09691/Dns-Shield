"""
tests/test_cache.py  —  Unit Tests for DNS Cache & LRU Eviction & Negative Cache
=================================================================================
"""

import time
import struct
import unittest
import threading
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.cache import DNSCache


def make_dummy_response(domain, rcode=0):
    """Helper to create dummy DNS response bytes with given RCODE."""
    # Byte 2-3 contains flags: 0x8180 for standard response (rcode=0)
    flags = 0x8180 | (rcode & 0x0F)
    return struct.pack(">HHHHHH", 0x1234, flags, 1, 1 if rcode == 0 else 0, 0, 0) + b"\x07example\x03com\x00\x00\x01\x00\x01"


class TestDNSCache(unittest.TestCase):
    def test_basic_get_put(self):
        cache = DNSCache(max_size=10, min_ttl=60, max_ttl=3600)
        resp = make_dummy_response("example.com", rcode=0)
        cache.put("example.com", 1, resp, ttl=120)

        data, remaining = cache.get("example.com", 1)
        self.assertIsNotNone(data)
        self.assertEqual(data, resp)
        self.assertTrue(remaining > 50)

        # Case insensitivity & trailing dot
        data2, _ = cache.get("EXAMPLE.COM.", 1)
        self.assertEqual(data2, resp)

    def test_lru_eviction_order(self):
        # Cache capacity of 3
        cache = DNSCache(max_size=3, min_ttl=60, max_ttl=3600)
        r1 = make_dummy_response("domain1.com")
        r2 = make_dummy_response("domain2.com")
        r3 = make_dummy_response("domain3.com")
        r4 = make_dummy_response("domain4.com")

        cache.put("domain1.com", 1, r1, 60)
        cache.put("domain2.com", 1, r2, 60)
        cache.put("domain3.com", 1, r3, 60)

        # Access domain1.com so it becomes recently used: Order is now [2, 3, 1]
        cache.get("domain1.com", 1)

        # Put 4th entry: Should evict domain2.com (least recently used)
        cache.put("domain4.com", 1, r4, 60)

        self.assertIsNone(cache.get("domain2.com", 1)[0], "domain2.com should be evicted by LRU")
        self.assertIsNotNone(cache.get("domain1.com", 1)[0], "domain1.com was accessed recently and should remain")
        self.assertIsNotNone(cache.get("domain3.com", 1)[0], "domain3.com should remain")
        self.assertIsNotNone(cache.get("domain4.com", 1)[0], "domain4.com should remain")

    def test_negative_cache_and_hits_counter(self):
        cache = DNSCache(max_size=10, min_ttl=60, max_ttl=3600)
        nx_resp = make_dummy_response("nonexistent.org", rcode=3)

        cache.put("nonexistent.org", 1, nx_resp, ttl=600)

        stats_before = cache.get_stats()
        self.assertEqual(stats_before["negative_hits"], 0)
        self.assertEqual(stats_before["hits"], 0)

        # Query nonexistent.org (hit 1)
        data1, rem1 = cache.get("nonexistent.org", 1)
        self.assertIsNotNone(data1)
        stats1 = cache.get_stats()
        self.assertEqual(stats1["hits"], 1)
        self.assertEqual(stats1["negative_hits"], 1)

        # Query nonexistent.org again (hit 2)
        data2, rem2 = cache.get("nonexistent.org", 1)
        self.assertIsNotNone(data2)
        stats2 = cache.get_stats()
        self.assertEqual(stats2["hits"], 2)
        self.assertEqual(stats2["negative_hits"], 2)

        # Query regular domain (should increment hits but NOT negative_hits)
        pos_resp = make_dummy_response("google.com", rcode=0)
        cache.put("google.com", 1, pos_resp, ttl=60)
        cache.get("google.com", 1)
        stats3 = cache.get_stats()
        self.assertEqual(stats3["hits"], 3)
        self.assertEqual(stats3["negative_hits"], 2)

    def test_thread_safety(self):
        cache = DNSCache(max_size=50, min_ttl=60, max_ttl=3600)

        def worker(thread_id):
            for i in range(200):
                domain = f"domain-{i % 20}.com"
                if i % 2 == 0:
                    cache.put(domain, 1, make_dummy_response(domain), 60)
                else:
                    cache.get(domain, 1)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        stats = cache.get_stats()
        self.assertLessEqual(stats["entries"], 50)


if __name__ == "__main__":
    unittest.main()
