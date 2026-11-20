"""
tests/test_stats.py  —  Unit tests for Phase 1.1 to 1.4 requirements
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.stats import DNSStats
from dns.cache import DNSCache
from dns.forwarder import DNSForwardResponse, get_upstream_stats, reset_stats


class TestDNSStatsPhases(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp_dir, "test_queries.db")
        self.stats = DNSStats(db_path=self.db_path)
        reset_stats()

    def tearDown(self):
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except Exception:
            pass

    def test_phase_1_1_cache_ratio(self):
        """
        1. Cache ratio: hits / (hits + forwarded), not hits/total
        """
        # Scenario:
        # 10 queries blocked
        # 4 queries cache hit
        # 6 queries forwarded to upstream
        # Total queries = 20
        # Old (wrong) ratio would be: 4 / 20 = 0.2
        # Correct ratio must be: 4 / (4 + 6) = 4 / 10 = 0.40

        for i in range(10):
            self.stats.add(f"blocked{i}.com", blocked=True, latency_ms=0.1, upstream="0.0.0.0")

        for i in range(4):
            self.stats.add(f"cached{i}.com", cached=True, latency_ms=0.05, upstream="")

        for i in range(6):
            self.stats.add(f"forwarded{i}.com", blocked=False, cached=False, latency_ms=25.0, upstream="8.8.8.8")

        data = self.stats.get_stats()
        self.assertEqual(data["total"], 20)
        self.assertEqual(data["blocked"], 10)
        self.assertEqual(data["cache_hits"], 4)
        self.assertEqual(data["cache_misses"], 6)

        # In Phase 1.4 cache structure
        self.assertIn("cache", data)
        self.assertEqual(data["cache"]["hits"], 4)
        self.assertEqual(data["cache"]["misses"], 6)
        self.assertAlmostEqual(data["cache"]["ratio"], 0.4, places=2)

    def test_phase_1_2_latencies(self):
        """
        2. Track 3 separate latencies: internal_lookup_ns, blocked_ms, forwarded_ms.
           Return p50/p95 for forwarded.
        """
        # Add blocked queries with known latencies: 1.0ms, 2.0ms, 3.0ms -> avg = 2.0ms
        self.stats.add("block1.com", blocked=True, latency_ms=1.0, upstream="0.0.0.0", internal_lookup_ns=2000)
        self.stats.add("block2.com", blocked=True, latency_ms=2.0, upstream="0.0.0.0", internal_lookup_ns=3000)
        self.stats.add("block3.com", blocked=True, latency_ms=3.0, upstream="0.0.0.0", internal_lookup_ns=4000)

        # Add forwarded queries with varying latencies: 10, 20, 30, 40, 50, 60, 70, 80, 90, 100 ms
        for lat in [10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0]:
            self.stats.add("example.com", blocked=False, cached=False, latency_ms=lat, upstream="8.8.8.8", internal_lookup_ns=1500)

        data = self.stats.get_stats()
        self.assertIn("latency", data)
        lat = data["latency"]
        self.assertIn("internal_us", lat)
        self.assertIn("blocked_ms", lat)
        self.assertIn("forwarded_p50", lat)
        self.assertIn("forwarded_p95", lat)

        self.assertAlmostEqual(lat["blocked_ms"], 2.0, places=1)
        # p50 of [10..100] is 55.0
        self.assertAlmostEqual(lat["forwarded_p50"], 55.0, places=1)
        # p95 should be >= 90.0
        self.assertGreaterEqual(lat["forwarded_p95"], 90.0)

        # internal_lookup_ns averages: (2000+3000+4000 + 10*1500) / 13 = 24000 / 13 = 1846 ns = ~1.85 us
        self.assertAlmostEqual(lat["internal_us"], 1.85, delta=0.5)

    def test_phase_1_3_upstream_tracking(self):
        """
        3. Track which upstream (8.8.8.8 or 1.1.1.1) won. Group by upstream IP, not answer IP.
        """
        # Simulate forwarder winner wrapper
        resp = DNSForwardResponse(b"\x12\x34response", upstream="1.1.1.1", elapsed=12.5)
        self.assertEqual(resp.upstream, "1.1.1.1")
        self.assertEqual(resp.winner, "1.1.1.1")
        self.assertTrue(isinstance(resp, bytes))

        # Log queries to stats with upstream IPs
        for _ in range(7):
            self.stats.log_query("127.0.0.1", "google.com", "A", action="FORWARDED", response_ms=20.0, upstream_ip="8.8.8.8")
        for _ in range(3):
            self.stats.log_query("127.0.0.1", "cloudflare.com", "A", action="FORWARDED", response_ms=15.0, upstream_ip="1.1.1.1")

        data = self.stats.get_stats()
        self.assertIn("upstream", data)
        upstreams = {u["ip"]: u for u in data["upstream"]}
        self.assertIn("8.8.8.8", upstreams)
        self.assertIn("1.1.1.1", upstreams)

        # Ensure answer IPs are not in upstream list
        for u in data["upstream"]:
            self.assertIn(u["ip"], ("8.8.8.8", "1.1.1.1"))

        self.assertEqual(upstreams["8.8.8.8"]["queries"], 7)
        self.assertEqual(upstreams["1.1.1.1"]["queries"], 3)
        self.assertAlmostEqual(upstreams["8.8.8.8"]["avg_ms"], 20.0, places=1)
        self.assertAlmostEqual(upstreams["1.1.1.1"]["avg_ms"], 15.0, places=1)

    def test_phase_1_4_api_stats_structure(self):
        """
        4. Dashboard API /api/stats schema check:
           {
               cache: {live, hits, misses, expired, ratio},
               upstream: [{ip: "8.8.8.8", queries, avg_ms, fails}],
               latency: {internal_us, blocked_ms, forwarded_p50, forwarded_p95}
           }
        """
        cache = DNSCache(max_size=100)
        self.stats.set_cache_ref(cache)
        cache.put("example.com", 1, b"dummy", ttl=60)

        data = self.stats.get_stats()

        # Check cache object
        self.assertIn("cache", data)
        self.assertSetEqual(set(data["cache"].keys()), {"live", "hits", "misses", "expired", "ratio"})
        self.assertEqual(data["cache"]["live"], 1)
        self.assertEqual(data["cache"]["hits"], 0)
        self.assertEqual(data["cache"]["misses"], 0)
        self.assertEqual(data["cache"]["expired"], 0)
        self.assertEqual(data["cache"]["ratio"], 0.0)

        # Check upstream object
        self.assertIn("upstream", data)
        self.assertTrue(isinstance(data["upstream"], list))
        self.assertGreaterEqual(len(data["upstream"]), 1)
        for u in data["upstream"]:
            self.assertIn("ip", u)
            self.assertIn("queries", u)
            self.assertIn("avg_ms", u)
            self.assertIn("fails", u)

        # Check latency object
        self.assertIn("latency", data)
        self.assertSetEqual(set(data["latency"].keys()), {"internal_us", "blocked_ms", "forwarded_p50", "forwarded_p95"})

        # Check preserved count
        self.assertEqual(data["blocklist_size"], 235974)

    def test_weighted_latencies_and_totals(self):
        """
        Verify:
        - total = blocked + forwarded + cached
        - overall_avg_ms is weighted: (blocked*blocked_avg + forwarded*forwarded_avg + cached*cached_avg)/total
        - separate: avg_blocked, avg_forwarded, avg_cached, avg_internal
        - cache_ratio = cached / (cached + forwarded)
        """
        # 6 blocked queries at 1.0ms each
        for i in range(6):
            self.stats.add(f"b{i}.com", blocked=True, latency_ms=1.0, upstream="0.0.0.0", internal_lookup_ns=200000)

        # 9 cached queries at 2.0ms each
        for i in range(9):
            self.stats.add(f"c{i}.com", cached=True, latency_ms=2.0, upstream="", internal_lookup_ns=100000)

        # 12 forwarded queries at 10.0ms each
        for i in range(12):
            self.stats.add(f"f{i}.com", blocked=False, cached=False, latency_ms=10.0, upstream="8.8.8.8", internal_lookup_ns=300000)

        data = self.stats.get_stats()
        self.assertEqual(data["blocked"], 6)
        self.assertEqual(data["cached"], 9)
        self.assertEqual(data["forwarded"], 12)
        self.assertEqual(data["total"], 27)
        self.assertEqual(data["total"], data["blocked"] + data["cached"] + data["forwarded"])

        # Cache ratio = 9 / (9 + 12) = 9/21 = 42.9%
        self.assertAlmostEqual(data["cache_ratio"], 42.9, places=1)

        # Separate averages
        self.assertAlmostEqual(data["blocked_avg_ms"], 1.0, places=1)
        self.assertAlmostEqual(data["cached_avg_ms"], 2.0, places=1)
        self.assertAlmostEqual(data["forwarded_avg_ms"], 10.0, places=1)

        # Weighted overall avg ms = (6*1.0 + 9*2.0 + 12*10.0) / 27 = (6 + 18 + 120) / 27 = 144 / 27 = 5.33ms
        expected_weighted = (6 * 1.0 + 9 * 2.0 + 12 * 10.0) / 27.0
        self.assertAlmostEqual(data["overall_avg_ms"], expected_weighted, places=2)


if __name__ == "__main__":
    unittest.main()

