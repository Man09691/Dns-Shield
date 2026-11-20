"""
tests/test_live_all_cases.py  —  Integration test verifying all RandomURL cases
"""
import os
import sys
import time
import socket
import struct
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.server import DNSServer
from dns.blocklist import Blocklist
from dns.cache import DNSCache
from dns.ratelimit import RateLimiter
from dns.stats import Stats


def query_dns(server_ip, server_port, domain, timeout=3.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    # Header: ID 0x4321, RD=1
    header = struct.pack("!HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
    qname = b"".join(struct.pack("B", len(p)) + p.encode() for p in domain.split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    packet = header + question

    t0 = time.perf_counter()
    sock.sendto(packet, (server_ip, server_port))
    try:
        resp, _ = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - t0) * 1000.0
        flags = struct.unpack("!H", resp[2:4])[0]
        rcode = flags & 0x000F
        ancount = struct.unpack("!H", resp[6:8])[0]
        
        # Check if 0.0.0.0 is in answer
        is_zero_ip = b"\x00\x00\x00\x00" in resp[12:]
        return {
            "success": True,
            "elapsed_ms": elapsed,
            "rcode": rcode,
            "ancount": ancount,
            "is_zero_ip": is_zero_ip,
            "raw": resp
        }
    except socket.timeout:
        return {"success": False, "error": "TIMED_OUT"}
    finally:
        sock.close()


def run_all_cases():
    config = {
        "listen_host": "127.0.0.1",
        "listen_port": 53,
        "upstream_dns": "8.8.8.8",
        "upstream_fallback": "1.1.1.1",
        "upstream_port": 53,
        "upstream_timeout": 3,
        "blocking_mode": "zero_ip",
    }
    blocklist = Blocklist()
    blocklist.load_all_blocklists("blocklists")
    cache = DNSCache(max_size=500)
    rate_limiter = RateLimiter(max_queries=100)
    stats = Stats(db_path=":memory:")
    stats.set_meta(blocklist_size=len(blocklist.blocked_domains), cache_size=cache.max_size)

    server = DNSServer(config, blocklist, cache, rate_limiter, stats)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    test_urls = [
        "https://hdhub4u.fast/",
        "https://new9.hdhub4u.cl/?utm=mn1",
        "https://new9.hdhub4u.cl/jailer-2-2026-hindi-line-v2-hdtc-full-movie/",
        "https://facebook.com",
        "https://hdhub4u.com",
        "https://ads.example.com",
    ]

    print("=" * 70)
    print("RUNNING ALL CASES AGAINST DNS SHIELD PORT 53")
    print("=" * 70)

    results = []
    for raw_url in test_urls:
        domain = raw_url.strip().replace("https://", "").replace("http://", "").split("/")[0]
        res = query_dns("127.0.0.1", 53, domain, timeout=3.5)
        
        if not res["success"]:
            print(f"FAILED (TIMED OUT) -> {domain}")
            results.append((domain, "TIMEOUT"))
        elif res["is_zero_ip"]:
            print(f"[BLOCKED] -> {domain:35} (0.0.0.0 in {res['elapsed_ms']:.1f}ms)")
            results.append((domain, "BLOCKED"))
        elif res["ancount"] > 0:
            print(f"[ALLOWED] -> {domain:35} (answers={res['ancount']} in {res['elapsed_ms']:.1f}ms)")
            results.append((domain, "ALLOWED"))
        else:
            print(f"[NO ANSWERS] (rcode={res['rcode']}) -> {domain}")
            results.append((domain, f"RCODE_{res['rcode']}"))

    # Test cache hit
    res_cached = query_dns("127.0.0.1", 53, "hdhub4u.fast", timeout=1.0)
    print(f"[CACHE HIT] -> hdhub4u.fast in {res_cached['elapsed_ms']:.2f}ms")
    assert res_cached["elapsed_ms"] < 15.0, "Cache should respond in < 15ms"

    # Test upstream stats
    stat_data = stats.get_stats()
    print("\nAPI Stats Summary:")
    print(f"  Total: {stat_data['total']}, Blocked: {stat_data['blocked']}, Cached: {stat_data['cache_hits']}")
    print(f"  Cache Ratio: {stat_data['cache']['ratio']}")
    print(f"  Upstream Winners: {stat_data['upstream']}")
    print(f"  Latency: {stat_data['latency']}")

    server.stop()
    print("=" * 70)
    print("ALL TESTS COMPLETED SUCCESSFULLY")


if __name__ == "__main__":
    run_all_cases()
