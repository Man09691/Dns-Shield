"""
tests/test_flood.py  —  Flood Stress Tests for DNS Shield Port 53
================================================================
Verifies DNS Shield behavior under high query flood conditions:
1. Send 1000 UDP queries to 127.0.0.1:53 in 10 seconds.
2. Mix of QTYPEs: A (1), AAAA (28), HTTPS (65).
3. Mix of domains: google.com, youtube.com, doubleclick.net, beacons5.gvt3.com.
4. Server does NOT crash and continues to respond to queries after flood.
5. BLOCKED queries are excluded from rate limiter.
6. Allowed/Forwarded queries are rate limited if over 300/10s for localhost.
7. No query takes more than 5000 ms, and CACHED queries after flood are < 5 ms.
8. Uses socket, timeout 2 sec, only tests against 127.0.0.1:53.
"""

import os
import sys
import time
import socket
import struct
import threading
import unittest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dns.server import DNSServer
from dns.blocklist import Blocklist
from dns.cache import DNSCache
from dns.ratelimit import RateLimiter
from dns.stats import Stats


def encode_dns_domain(domain: str) -> bytes:
    """Encode a domain string into DNS wire format labels."""
    encoded = b""
    for part in domain.rstrip(".").split("."):
        encoded += bytes([len(part)]) + part.encode("ascii")
    encoded += b"\x00"
    return encoded


def build_raw_dns_query(domain: str, qtype: int = 1, query_id: int = 0x1234) -> bytes:
    """Build a standard DNS query packet."""
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = encode_dns_domain(domain) + struct.pack(">HH", qtype, 1)
    return header + question


class TestDNSFlood(unittest.TestCase):
    server = None
    server_thread = None

    @classmethod
    def setUpClass(cls):
        # Configure test server on 127.0.0.1:53
        config = {
            "listen_host": "127.0.0.1",
            "listen_port": 53,
            "upstream_dns": "8.8.8.8",
            "upstream_fallback": "1.1.1.1",
            "blocking_mode": "zero_ip",
            "client_allowlist_enabled": True,
            "client_allowlist": ["127.0.0.1", "::1", "192.168.0.0/16"],
            "upstream_validation": True,
            "allowed_upstreams": ["8.8.8.8", "1.1.1.1"],
        }
        bl = Blocklist()
        # Add required test domains to blocklist
        bl.add_domain("doubleclick.net", "custom")
        bl.add_domain("beacons5.gvt3.com", "ads")
        bl.add_to_allowlist("google.com")
        bl.add_to_allowlist("youtube.com")

        cache = DNSCache(max_size=2000)
        # Standard localhost rate limit is 300 queries per 10s
        rate_limiter = RateLimiter(
            max_queries=50,
            window_seconds=10,
            block_seconds=30,
            localhost_max_queries=300,
            domain_burst_limit=300,
        )
        stats = Stats(db_path=":memory:")

        cls.server = DNSServer(config, bl, cache, rate_limiter, stats)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.stop()
            time.sleep(0.2)

    def test_01_flood_1000_queries_under_10s(self):
        """
        Send 1000 UDP queries to 127.0.0.1:53 in <= 10s.
        Mix of A, AAAA, HTTPS for google.com, youtube.com, doubleclick.net, beacons5.gvt3.com.
        Check server does not crash, responds within 5000ms, and cached queries < 5ms.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)

        # Pre-warm google.com in cache
        warm_query = build_raw_dns_query("google.com", 1, 0x0001)
        sock.sendto(warm_query, ("127.0.0.1", 53))
        try:
            sock.recvfrom(512)
        except socket.timeout:
            pass

        domains = ["google.com", "youtube.com", "doubleclick.net", "beacons5.gvt3.com"]
        qtypes = [1, 28, 65]  # A, AAAA, HTTPS

        total_queries = 1000
        sent = 0
        received = 0
        latencies = []
        blocked_count = 0
        rate_limited_count = 0
        cached_or_forwarded_count = 0

        t_flood_start = time.time()

        for i in range(total_queries):
            domain = domains[i % len(domains)]
            qtype = qtypes[i % len(qtypes)]
            qid = (i + 10) & 0xFFFF
            packet = build_raw_dns_query(domain, qtype, qid)

            t0 = time.perf_counter()
            sock.sendto(packet, ("127.0.0.1", 53))
            sent += 1

            try:
                data, _ = sock.recvfrom(512)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                received += 1
                latencies.append(elapsed_ms)

                # Check requirement: No query takes more than 5000 ms
                self.assertLess(
                    elapsed_ms,
                    5000.0,
                    f"Query {i} ({domain}, qtype {qtype}) took {elapsed_ms:.1f}ms > 5000ms",
                )

                flags = struct.unpack(">H", data[2:4])[0]
                rcode = flags & 0x000F
                if b"\x00\x00\x00\x00" in data[12:]:
                    blocked_count += 1
                elif rcode == 5:
                    rate_limited_count += 1
                else:
                    cached_or_forwarded_count += 1

            except socket.timeout:
                pass

            # Pacing: ~0.007s delay keeps 1000 queries running within 8 to 10 seconds
            time.sleep(0.007)

        flood_duration = time.time() - t_flood_start

        print(
            f"\n[FLOOD TEST SUMMARY] 1000 queries completed in {flood_duration:.2f}s | "
            f"Sent: {sent}, Received: {received}, Blocked: {blocked_count}, "
            f"Rate-Limited: {rate_limited_count}, Cached/Forwarded: {cached_or_forwarded_count}"
        )

        # Server must not crash
        self.assertTrue(self.server.running, "Server crashed during flood!")
        self.assertGreaterEqual(
            received, 900, f"Expected at least 900 responses, got {received}"
        )

        # Check server responds to a new query after flood
        sock.sendto(build_raw_dns_query("doubleclick.net", 1, 0xEEEE), ("127.0.0.1", 53))
        after_data, _ = sock.recvfrom(512)
        self.assertIsNotNone(after_data, "Server did not respond after flood!")
        self.assertIn(b"\x00\x00\x00\x00", after_data[12:], "doubleclick.net must be blocked (0.0.0.0)")

        # Check CACHED query after flood is under 5 ms
        cached_query = build_raw_dns_query("google.com", 1, 0xCAFE)
        t_cache0 = time.perf_counter()
        sock.sendto(cached_query, ("127.0.0.1", 53))
        cache_resp, _ = sock.recvfrom(512)
        cache_elapsed_ms = (time.perf_counter() - t_cache0) * 1000.0

        print(f"[FLOOD TEST] CACHED query after flood took {cache_elapsed_ms:.2f}ms")
        self.assertLess(
            cache_elapsed_ms,
            5.0,
            f"CACHED query after flood exceeded 5ms: {cache_elapsed_ms:.2f}ms",
        )

        sock.close()

    def test_02_rate_limiter_blocked_excluded_and_forwarded_limited(self):
        """
        Verify:
        - BLOCKED queries are excluded from rate limiter.
        - Allowed/Forwarded queries are rate limited if over 300/10s for localhost (127.0.0.1).
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)

        # Wait for any prior background threads to settle, then reset rate limiter
        time.sleep(0.5)
        with self.server.rate_limiter.lock:
            self.server.rate_limiter.query_times.clear()
            self.server.rate_limiter.blocked_clients.clear()
            self.server.rate_limiter.domain_query_times.clear()
            self.server.rate_limiter.blocked_domain_clients.clear()

        # Step 1: Send 100 BLOCKED queries in rapid succession
        for i in range(100):
            query = build_raw_dns_query("doubleclick.net", 1, i + 1)
            sock.sendto(query, ("127.0.0.1", 53))
            resp, _ = sock.recvfrom(512)
            flags = struct.unpack(">H", resp[2:4])[0]
            rcode = flags & 0x000F
            self.assertEqual(rcode, 0, f"Blocked query {i} should return RCODE 0, got {rcode}")
            self.assertIn(b"\x00\x00\x00\x00", resp[12:], "Must contain 0.0.0.0 answer")

        # Verify that BLOCKED queries were NOT added to client rate limit tracking
        with self.server.rate_limiter.lock:
            lh_times = self.server.rate_limiter.query_times.get("127.0.0.1", [])
            self.assertEqual(
                len(lh_times),
                0,
                f"Blocked queries should not count towards rate limit! Found {len(lh_times)} records",
            )

        # Step 2: Rate limit check for localhost (limit is 300/10s)
        # Send 300 allowed queries from 127.0.0.1
        for i in range(300):
            domain = f"allowed-query-{i}.test"
            # Put in cache to avoid slow external upstream forwards
            self.server.cache.put(domain, 1, build_raw_dns_query(domain, 1, 0x1111), 300)
            query = build_raw_dns_query(domain, 1, i + 200)
            sock.sendto(query, ("127.0.0.1", 53))
            resp, _ = sock.recvfrom(512)
            flags = struct.unpack(">H", resp[2:4])[0]
            rcode = flags & 0x000F
            self.assertEqual(
                rcode,
                0,
                f"Query {i+1} within limit (<=300) should succeed, got RCODE {rcode}",
            )

        # Query 301 should exceed 300/10s limit and return REFUSED (RCODE 5)
        over_query = build_raw_dns_query("allowed-over-limit.test", 1, 0x9999)
        sock.sendto(over_query, ("127.0.0.1", 53))
        over_resp, _ = sock.recvfrom(512)
        over_flags = struct.unpack(">H", over_resp[2:4])[0]
        over_rcode = over_flags & 0x000F
        self.assertEqual(
            over_rcode,
            5,
            f"301st allowed query should be rate-limited (REFUSED RCODE 5), got RCODE {over_rcode}",
        )

        # Step 3: Verify BLOCKED query still passes through even when 127.0.0.1 is currently rate-limited
        blocked_query = build_raw_dns_query("beacons5.gvt3.com", 1, 0x8888)
        sock.sendto(blocked_query, ("127.0.0.1", 53))
        b_resp, _ = sock.recvfrom(512)
        b_flags = struct.unpack(">H", b_resp[2:4])[0]
        b_rcode = b_flags & 0x000F
        self.assertEqual(
            b_rcode,
            0,
            f"Blocked query must NOT be rate limited even when client is blocked, got RCODE {b_rcode}",
        )
        self.assertIn(b"\x00\x00\x00\x00", b_resp[12:], "Must contain 0.0.0.0 answer")

        sock.close()


if __name__ == "__main__":
    unittest.main()
