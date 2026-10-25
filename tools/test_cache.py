"""
tools/test_cache.py  —  Test DNS Cache Behaviour
==================================================
Queries the same domain twice and compares the latency
to demonstrate that the second query is served from cache.
"""

import socket
import struct
import time
import random
import sys


def build_query(domain, qtype=1):
    """Build a DNS A query."""
    query_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question_name = b""
    for label in domain.split("."):
        question_name += struct.pack("B", len(label))
        question_name += label.encode("ascii")
    question_name += b"\x00"
    question_footer = struct.pack(">HH", qtype, 1)
    return header + question_name + question_footer


def query_server(domain):
    """Send a DNS query and return the response time in ms."""
    query = build_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    start = time.time()
    sock.sendto(query, ("127.0.0.1", 5053))
    response, _ = sock.recvfrom(4096)
    elapsed = (time.time() - start) * 1000

    sock.close()
    return elapsed, response


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    print(f"\n  Cache Test: querying '{domain}' twice\n")

    # First query (cache miss — forwarded to upstream)
    print("  Query 1 (should be FORWARDED to upstream)...")
    time1, resp1 = query_server(domain)
    print(f"    Time: {time1:.1f}ms")

    # Small delay
    time.sleep(0.1)

    # Second query (cache hit — should be much faster)
    print("  Query 2 (should be CACHED)...")
    time2, resp2 = query_server(domain)
    print(f"    Time: {time2:.1f}ms")

    # Compare
    print(f"\n  Speedup: {time1/time2:.1f}x faster from cache")
    if time2 < time1:
        print("  PASS: Second query was faster (cache is working)")
    else:
        print("  NOTE: Cache may not have kicked in (try again)")


if __name__ == "__main__":
    main()
