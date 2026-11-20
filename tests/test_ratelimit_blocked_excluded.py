"""
tests/test_ratelimit_blocked_excluded.py
=========================================
Unit and integration tests verifying:
1. Blocked queries do NOT count towards rate limit:
   - 100 BLOCKED queries in 5s do NOT trigger rate limit for next allowed query.
2. Localhost rate limit raised to 300:
   - 300 allowed queries in 10s from 127.0.0.1 do NOT rate limit, 301st does.
3. Blocklist file watcher SHA256 hashing and cache preservation:
   - Reload with same hash does NOT clear DNS cache.
   - If rebuilt count is same as before, cache is preserved.
4. Per-domain burst protection:
   - Flooding one domain does not block unrelated domains for the same client.
"""

import os
import sys
import time
import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from dns.ratelimit import RateLimiter
from dns.blocklist import Blocklist
from dns.cache import DNSCache, get_cache_instance
from dns.server import DNSServer
from dns.parser import parse_question, parse_header


def encode_domain(domain):
    """Encode a domain name into DNS wire format."""
    encoded = b""
    for label in domain.rstrip(".").split("."):
        encoded += bytes([len(label)]) + label.encode("ascii")
    encoded += b"\x00"
    return encoded


def build_query(domain, qtype=1, query_id=0x1234):
    """Build a minimal standard DNS query packet."""
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = encode_domain(domain) + struct.pack(">HH", qtype, 1)
    return header + question


def build_plain_a_response(query_data, ip="93.184.216.34", query_id=0x1234):
    """Build a standard A record DNS response packet."""
    domain, qtype, qclass, question_end = parse_question(query_data)
    name = encode_domain(domain)
    ip_bytes = bytes(map(int, ip.split(".")))
    rr = name + struct.pack(">HHIH", 1, 1, 300, 4) + ip_bytes
    header = struct.pack(">HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
    question_section = query_data[12:question_end]
    return header + question_section + rr


def make_test_server(blocklist=None, cache=None, rate_limiter=None):
    """Helper to instantiate DNSServer with mocked socket and stats."""
    config = {
        "listen_port": 53,
        "listen_ip": "127.0.0.1",
        "blocking_mode": "zero_ip",
        "upstream_dns": "8.8.8.8",
        "upstream_fallback": "1.1.1.1",
        "upstream_timeout": 1.0,
        "upstream_port": 53,
    }
    bl = blocklist or Blocklist(lookup_cache_size=256)
    c = cache or DNSCache(max_size=500, min_ttl=60, max_ttl=3600)
    rl = rate_limiter or RateLimiter(max_queries=50, window_seconds=10, block_seconds=30, localhost_max_queries=300)
    stats_mock = MagicMock()

    server = DNSServer(config, bl, c, rl, stats_mock)
    server.sock = MagicMock()
    server.running = True
    return server


class TestRateLimitBlockedExcluded(unittest.TestCase):

    def test_blocked_queries_do_not_count_towards_rate_limit(self):
        """
        100 BLOCKED queries in 5s should NOT trigger rate limit for next allowed query.
        Client IP is non-localhost (limit 50/10s).
        """
        bl = Blocklist(lookup_cache_size=256)
        bl.add_domain("doubleclick.net", "ads")

        # Standard client IP limit is 50 queries per 10s
        rl = RateLimiter(max_queries=50, window_seconds=10, block_seconds=30, localhost_max_queries=300)
        server = make_test_server(blocklist=bl, rate_limiter=rl)

        client_ip = "192.168.1.100"
        client_addr = (client_ip, 54321)

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        # 1. Send 100 queries for blocked domain
        blocked_query = build_query("doubleclick.net")
        for i in range(100):
            server._handle_query(blocked_query, client_addr)

        self.assertEqual(len(sent_packets), 100)
        # Verify rate limiter did not record blocked queries (query_times is empty)
        self.assertEqual(len(rl.query_times.get(client_ip, [])), 0,
                         "Blocked queries must not increment client query counter")

        # 2. Next query for an allowed domain must succeed and not be rate limited
        allowed_query = build_query("example.com")
        fake_upstream = build_plain_a_response(allowed_query, ip="93.184.216.34")

        with patch("dns.server.forward_query", return_value=fake_upstream):
            server._handle_query(allowed_query, client_addr)

        self.assertEqual(len(sent_packets), 101)
        resp = sent_packets[-1]
        flags = struct.unpack(">H", resp[2:4])[0]
        rcode = flags & 0x000F
        self.assertEqual(rcode, 0, "Allowed query after 100 blocked queries must return NOERROR (0), not REFUSED (5)")

        # Counter for allowed query is now exactly 1
        self.assertEqual(len(rl.query_times[client_ip]), 1)

    def test_localhost_rate_limit_300(self):
        """
        300 allowed queries in 10s from 127.0.0.1 should NOT rate limit, 301st should.
        """
        rl = RateLimiter(max_queries=50, window_seconds=10, block_seconds=30, localhost_max_queries=300)
        localhost_ip = "127.0.0.1"

        # Queries 1 to 300 should all pass
        for i in range(1, 301):
            is_limited = rl.is_rate_limited(localhost_ip, domain=f"query-{i}.example.com")
            self.assertFalse(is_limited, f"Localhost query #{i} should NOT be rate limited")

        # Query 301 should be rate limited
        is_limited_301 = rl.is_rate_limited(localhost_ip, domain="query-301.example.com")
        self.assertTrue(is_limited_301, "Query #301 from 127.0.0.1 MUST be rate limited")

        # Standard non-localhost client is limited at 50
        remote_ip = "10.0.0.99"
        for i in range(1, 51):
            self.assertFalse(rl.is_rate_limited(remote_ip, domain=f"remote-{i}.example.com"),
                             f"Remote query #{i} should NOT be rate limited")
        self.assertTrue(rl.is_rate_limited(remote_ip, domain="remote-51.example.com"),
                        "Query #51 from remote IP MUST be rate limited")

    def test_reload_same_hash_does_not_clear_cache(self):
        """
        Reload with same SHA256 hash should NOT clear DNS cache.
        If rebuilt count is same as before, do NOT clear cache.
        """
        cache = get_cache_instance()
        cache.clear()

        with tempfile.TemporaryDirectory() as tmpdir:
            b_dir = os.path.join(tmpdir, "blocklists")
            os.makedirs(b_dir, exist_ok=True)
            ads_file = os.path.join(b_dir, "ads.txt")
            allow_file = os.path.join(tmpdir, "allowlist.txt")

            with open(ads_file, "w") as f:
                f.write("badad1.com\nbadad2.com\n")
            with open(allow_file, "w") as f:
                f.write("safe1.com\n")

            bl = Blocklist(lookup_cache_size=256)
            bl.load_all_blocklists(b_dir)
            bl.load_allowlist(allow_file)

            # Rebuild count should be 2
            self.assertEqual(bl.blocklist_size, 2)

            # Store an entry in DNS cache
            dummy_resp = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            cache.put("my-cached-domain.com", 1, dummy_resp, ttl=300)

            # Verify entry is present in cache
            entry, _ = cache.get("my-cached-domain.com", 1)
            self.assertIsNotNone(entry, "Entry must exist in cache")

            # 1. check_and_reload_if_changed when files haven't changed
            reloaded = bl.check_and_reload_if_changed(b_dir, allow_file)
            self.assertFalse(reloaded, "Should not reload when SHA256 hashes match")

            entry, _ = cache.get("my-cached-domain.com", 1)
            self.assertIsNotNone(entry, "Cache must NOT be cleared when hash unchanged")

            # 2. Modify mtime without changing content
            new_mtime = time.time() + 60
            os.utime(ads_file, (new_mtime, new_mtime))

            reloaded_mtime = bl.check_and_reload_if_changed(b_dir, allow_file)
            self.assertFalse(reloaded_mtime, "Should NOT reload when mtime changes but content SHA256 matches")

            entry, _ = cache.get("my-cached-domain.com", 1)
            self.assertIsNotNone(entry, "Cache must NOT be cleared on mtime change if hash unchanged")

            # 3. Direct reload with same domain count (rebuilt count is same as before)
            bl.reload_with_active_filter()
            entry, _ = cache.get("my-cached-domain.com", 1)
            self.assertIsNotNone(entry, "Cache must NOT be cleared when rebuilt count is same as before (2 == 2)")

            # 4. Modify content (SHA256 changes) and domain count changes
            with open(ads_file, "a") as f:
                f.write("badad3.com\n")

            reloaded_content = bl.check_and_reload_if_changed(b_dir, allow_file)
            self.assertTrue(reloaded_content, "Must reload when file content SHA256 changed")

            entry, _ = cache.get("my-cached-domain.com", 1)
            self.assertIsNone(entry, "Cache SHOULD be cleared when domain count changed (2 -> 3)")

    def test_per_domain_burst_protection(self):
        """
        Per-domain burst protection:
        One flooding domain (e.g. beacons.gvt2.com) cannot block www.google.com for the same client.
        """
        rl = RateLimiter(max_queries=100, window_seconds=10, block_seconds=30, domain_burst_limit=20)
        client_ip = "192.168.2.50"

        # Flood beacons.gvt2.com 20 times (burst limit 20)
        for _ in range(20):
            self.assertFalse(rl.is_rate_limited(client_ip, domain="beacons.gvt2.com"))

        # 21st query for beacons.gvt2.com should be rate limited
        self.assertTrue(rl.is_rate_limited(client_ip, domain="beacons.gvt2.com"),
                        "21st query to same domain should trigger per-domain burst protection")

        # But queries to www.google.com from the same client MUST still be allowed!
        self.assertFalse(rl.is_rate_limited(client_ip, domain="www.google.com"),
                         "www.google.com must NOT be blocked when beacons.gvt2.com is rate limited")


if __name__ == "__main__":
    unittest.main(verbosity=2)
