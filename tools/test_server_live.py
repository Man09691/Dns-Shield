"""
tools/test_server_live.py  —  Integration test for live DNSServer
"""
import time
import socket
import struct
import threading
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.server import DNSServer
from dns.blocklist import Blocklist
from dns.cache import DNSCache
from dns.ratelimit import RateLimiter
from dns.stats import Stats


def build_query(domain, qtype=1):
    query_id = 0x1234
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = b""
    for part in domain.split("."):
        question += bytes([len(part)]) + part.encode("ascii")
    question += b"\x00" + struct.pack(">HH", qtype, 1)
    return header + question


def run_live_test():
    with open("config.json", "r") as f:
        config = json.load(f)

    # Use port 5053
    config["listen_port"] = 5053

    blocklist = Blocklist()
    blocklist.load_all_blocklists("blocklists")
    blocklist.load_allowlist("allowlist.txt")

    cache = DNSCache(max_size=100)
    rate_limiter = RateLimiter(max_queries=100, window_seconds=10, block_seconds=30)
    stats = Stats(db_file="queries.db")

    server = DNSServer(config, blocklist, cache, rate_limiter, stats)

    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)

    try:
        # Test 1: Blocked domain (doubleclick.net)
        q_blocked = build_query("doubleclick.net")
        sock.sendto(q_blocked, ("127.0.0.1", 5053))
        resp, _ = sock.recvfrom(512)
        ip = ".".join(str(b) for b in resp[-4:])
        print(f"Test 1 - doubleclick.net: IP={ip} (Expected 0.0.0.0)")
        assert ip == "0.0.0.0", f"Expected 0.0.0.0, got {ip}"

        # Test 2: Subdomain of blocked (ads.doubleclick.net)
        q_sub = build_query("ads.doubleclick.net")
        sock.sendto(q_sub, ("127.0.0.1", 5053))
        resp, _ = sock.recvfrom(512)
        ip = ".".join(str(b) for b in resp[-4:])
        print(f"Test 2 - ads.doubleclick.net: IP={ip} (Expected 0.0.0.0)")
        assert ip == "0.0.0.0", f"Expected 0.0.0.0, got {ip}"

        # Test 3: Unblocked domain (example.com)
        q_real = build_query("example.com")
        sock.sendto(q_real, ("127.0.0.1", 5053))
        resp, _ = sock.recvfrom(512)
        print(f"Test 3 - example.com: got upstream response ({len(resp)} bytes)")

        # Test 4: Query again to test cache hit
        sock.sendto(q_real, ("127.0.0.1", 5053))
        resp2, _ = sock.recvfrom(512)
        c_stats = cache.get_stats()
        print(f"Test 4 - Cache stats: {c_stats}")
        assert c_stats["hits"] >= 1, "Cache hit expected on second query"

        # Test 5: Negative cache (NXDOMAIN)
        q_nx = build_query(f"nx-domain-test-{int(time.time())}.org")
        sock.sendto(q_nx, ("127.0.0.1", 5053))
        resp_nx1, _ = sock.recvfrom(512)
        # Query again for NXDOMAIN
        sock.sendto(q_nx, ("127.0.0.1", 5053))
        resp_nx2, _ = sock.recvfrom(512)
        c_stats2 = cache.get_stats()
        print(f"Test 5 - Negative cache stats: {c_stats2}")
        assert c_stats2["negative_hits"] >= 1, "Expected negative_hits >= 1"

        print("\nALL LIVE INTEGRATION TESTS PASSED SUCCESSFULLY!")

    finally:
        sock.close()
        server.stop()


if __name__ == "__main__":
    run_live_test()
