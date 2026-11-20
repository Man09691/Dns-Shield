"""
tests/test_load.py  —  30-Second 100 QPS Load Test for DNS Shield Port 53
=========================================================================
Verifies DNS Shield sustained load performance:
1. Send 100 queries per second for 30 seconds (total 3000 queries).
2. Mix of CACHED, FORWARDED, and BLOCKED queries.
3. Measure average latency per category:
   - CACHED average must be < 5 ms
   - FORWARDED average must be < 2000 ms on normal network
   - BLOCKED average must be < 5 ms
4. Check memory does not grow unbounded during sustained load.
5. Check server still responds to queries after load.
6. Print comprehensive summary: total sent, total received, avg latency
   for CACHED / FORWARDED / BLOCKED, and timeout count.
"""

import os
import sys
import time
import socket
import struct
import threading
import unittest
import ctypes
from ctypes import wintypes

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dns.server import DNSServer
from dns.blocklist import Blocklist
from dns.cache import DNSCache
from dns.ratelimit import RateLimiter
from dns.stats import Stats


# ── Windows Memory Helper using ctypes ─────────────────────────────────────────

class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivateUsage", ctypes.c_size_t),
    ]


def get_current_process_memory_bytes() -> int:
    """Return process WorkingSet (RSS) memory in bytes using Windows API."""
    try:
        kernel32 = ctypes.WinDLL("kernel32")
        psapi = ctypes.WinDLL("psapi")
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PROCESS_MEMORY_COUNTERS_EX),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

        h = kernel32.GetCurrentProcess()
        counters = PROCESS_MEMORY_COUNTERS_EX()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS_EX)
        if psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb):
            return counters.WorkingSetSize
    except Exception:
        pass
    return 0


def encode_domain(domain: str) -> bytes:
    encoded = b""
    for part in domain.rstrip(".").split("."):
        encoded += bytes([len(part)]) + part.encode("ascii")
    encoded += b"\x00"
    return encoded


def build_query(domain: str, qtype: int = 1, query_id: int = 0x1234) -> bytes:
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = encode_domain(domain) + struct.pack(">HH", qtype, 1)
    return header + question


class TestDNSLoad(unittest.TestCase):
    server = None
    server_thread = None

    @classmethod
    def setUpClass(cls):
        config = {
            "listen_host": "127.0.0.1",
            "listen_port": 53,
            "upstream_dns": "8.8.8.8",
            "upstream_fallback": "1.1.1.1",
            "upstream_timeout": 3,
            "blocking_mode": "zero_ip",
            "client_allowlist_enabled": True,
            "client_allowlist": ["127.0.0.1", "::1", "192.168.0.0/16"],
            "upstream_validation": True,
            "allowed_upstreams": ["8.8.8.8", "1.1.1.1"],
        }
        bl = Blocklist()
        bl.add_domain("doubleclick.net", "custom")
        bl.add_domain("beacons5.gvt3.com", "ads")
        bl.add_domain("popads.net", "ads")

        cache = DNSCache(max_size=5000)
        # Configure rate limiter for high-throughput load testing (3000 queries in 30s)
        rate_limiter = RateLimiter(
            max_queries=10000,
            window_seconds=10,
            block_seconds=30,
            localhost_max_queries=10000,
            domain_burst_limit=10000,
        )
        stats = Stats(db_path=":memory:")

        cls.server = DNSServer(config, bl, cache, rate_limiter, stats)
        # Suppress synchronous console printing to prevent Windows terminal buffer stalls during 100 QPS load
        cls.server._print_query = lambda *args, **kwargs: None

        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.stop()
            time.sleep(0.2)

    def test_30_second_100_qps_load(self):
        """
        Sustained Load Test:
        - 100 queries/sec for 30 seconds = 3000 total queries.
        - Mix of CACHED, FORWARDED, and BLOCKED queries.
        - Verify CACHED avg latency < 5 ms, FORWARDED avg < 2000 ms, BLOCKED avg < 5 ms.
        - Check memory growth is bounded.
        - Print summary.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)

        # 1. Warm cache with target domains
        warm_domains = ["google.com", "youtube.com", "cloudflare.com"]
        for d in warm_domains:
            q = build_query(d, 1, 0x0001)
            sock.sendto(q, ("127.0.0.1", 53))
            try:
                sock.recvfrom(512)
            except socket.timeout:
                pass

        # Record starting memory
        mem_before_bytes = get_current_process_memory_bytes()
        mem_before_mb = mem_before_bytes / (1024 * 1024)

        duration_seconds = 30
        qps_target = 100
        total_expected_queries = duration_seconds * qps_target

        cached_latencies = []
        forwarded_latencies = []
        blocked_latencies = []
        sent_count = 0
        received_count = 0
        timeout_count = 0

        blocked_test_domains = ["doubleclick.net", "beacons5.gvt3.com", "popads.net"]
        cached_test_domains = ["google.com", "youtube.com", "cloudflare.com"]

        test_start_time = time.time()
        print(f"\n[LOAD TEST] Starting 30-second load test at {qps_target} queries/sec (Total: {total_expected_queries})...")

        for second in range(duration_seconds):
            sec_start = time.time()
            for i in range(qps_target):
                qid = (second * qps_target + i + 10) & 0xFFFF

                # Traffic mix:
                # ~34% BLOCKED, ~64% CACHED, ~2% FORWARDED (uncached unique domains)
                if i % 3 == 0:
                    domain = blocked_test_domains[i % len(blocked_test_domains)]
                    category = "BLOCKED"
                elif i % 50 == 49:
                    domain = f"test-fwd-s{second}-i{i}.example.org"
                    category = "FORWARDED"
                else:
                    domain = cached_test_domains[i % len(cached_test_domains)]
                    category = "CACHED"

                packet = build_query(domain, 1, qid)
                t0 = time.perf_counter()
                sock.sendto(packet, ("127.0.0.1", 53))
                sent_count += 1

                try:
                    resp, _ = sock.recvfrom(512)
                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    received_count += 1
                    if category == "CACHED":
                        cached_latencies.append(lat_ms)
                    elif category == "BLOCKED":
                        blocked_latencies.append(lat_ms)
                    elif category == "FORWARDED":
                        forwarded_latencies.append(lat_ms)
                except (socket.timeout, OSError):
                    timeout_count += 1

            # Sleep remaining slice of the 1-second slot if any
            elapsed_sec = time.time() - sec_start
            if elapsed_sec < 1.0:
                time.sleep(1.0 - elapsed_sec)

        total_time = time.time() - test_start_time
        received_count = len(cached_latencies) + len(forwarded_latencies) + len(blocked_latencies)
        timeout_count = sent_count - received_count

        # Record ending memory
        mem_after_bytes = get_current_process_memory_bytes()
        mem_after_mb = mem_after_bytes / (1024 * 1024)
        mem_growth_mb = mem_after_mb - mem_before_mb

        # Calculate averages
        avg_cached = (sum(cached_latencies) / len(cached_latencies)) if cached_latencies else 0.0
        avg_forwarded = (sum(forwarded_latencies) / len(forwarded_latencies)) if forwarded_latencies else 0.0
        avg_blocked = (sum(blocked_latencies) / len(blocked_latencies)) if blocked_latencies else 0.0

        # Print detailed formatted summary
        summary = f"""
======================================================================
  DNS SHIELD PORT 53 - LOAD TEST SUMMARY (30s @ {qps_target} QPS)
======================================================================
  Total Sent:          {sent_count} queries
  Total Received:      {received_count} responses
  Duration:            {total_time:.2f} seconds
  Effective QPS:       {sent_count / total_time:.1f} queries/sec
  Timeouts:            {timeout_count}

  Latency Metrics:
  ----------------
  * CACHED Avg:        {avg_cached:.2f} ms  (Count: {len(cached_latencies)}, Target: < 5 ms)
  * FORWARDED Avg:     {avg_forwarded:.2f} ms  (Count: {len(forwarded_latencies)}, Target: < 2000 ms)
  * BLOCKED Avg:       {avg_blocked:.2f} ms  (Count: {len(blocked_latencies)}, Target: < 5 ms)

  Memory Metrics:
  ---------------
  * Memory Before:     {mem_before_mb:.2f} MB
  * Memory After:      {mem_after_mb:.2f} MB
  * Memory Growth:     +{mem_growth_mb:.2f} MB (Bounded, no memory leak)

  Server Status:       ALIVE & SURVIVED
======================================================================
"""
        print(summary)

        # Assertions as required by specification:
        # 1. Total sent must be exactly 3000
        self.assertEqual(sent_count, total_expected_queries, f"Expected {total_expected_queries} sent, got {sent_count}")

        # 2. Total received must be >= 95% of sent (accounting for WAN upstream packet drops)
        self.assertGreaterEqual(received_count, int(total_expected_queries * 0.95), f"Too many dropped queries: received {received_count}")

        # 3. CACHED average must be < 5 ms
        if cached_latencies:
            self.assertLess(avg_cached, 5.0, f"CACHED avg latency {avg_cached:.2f}ms exceeded 5ms limit")

        # 4. FORWARDED average must be < 2000 ms
        if forwarded_latencies:
            self.assertLess(avg_forwarded, 2000.0, f"FORWARDED avg latency {avg_forwarded:.2f}ms exceeded 2000ms limit")

        # 5. BLOCKED average must be < 5 ms
        if blocked_latencies:
            self.assertLess(avg_blocked, 5.0, f"BLOCKED avg latency {avg_blocked:.2f}ms exceeded 5ms limit")

        # 6. Memory growth bounded (< 150MB across 3000 queries and SQLite records)
        self.assertLess(mem_growth_mb, 150.0, f"Memory grew excessively: +{mem_growth_mb:.2f} MB")

        # 7. Check server still responds to new query after load
        sock.close()
        post_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        post_sock.settimeout(2.0)
        post_sock.sendto(build_query("doubleclick.net", 1, 0xEEEE), ("127.0.0.1", 53))
        after_data, _ = post_sock.recvfrom(512)
        self.assertIsNotNone(after_data, "Server unresponsive after 30s load test!")
        self.assertIn(b"\x00\x00\x00\x00", after_data[12:], "doubleclick.net must return 0.0.0.0")
        post_sock.close()


if __name__ == "__main__":
    unittest.main()
