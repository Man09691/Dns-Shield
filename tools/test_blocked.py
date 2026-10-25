"""
tools/test_blocked.py  —  Test Blocked Domain Resolution
==========================================================
Sends a DNS query for a blocked domain and verifies it returns 0.0.0.0.
Also tests subdomain blocking.
"""

import socket
import struct
import time
import random


def build_query(domain, qtype=1):
    """Build a DNS A query for the given domain."""
    query_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question_name = b""
    for label in domain.split("."):
        question_name += struct.pack("B", len(label))
        question_name += label.encode("ascii")
    question_name += b"\x00"
    question_footer = struct.pack(">HH", qtype, 1)
    return header + question_name + question_footer, query_id


def test_domain(domain, expect_blocked=True):
    """Send a query and check if the domain was blocked."""
    print(f"\n  Testing: {domain}")
    print(f"  Expected: {'BLOCKED (0.0.0.0)' if expect_blocked else 'ALLOWED (real IP)'}")

    query, qid = build_query(domain)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    start = time.time()
    sock.sendto(query, ("127.0.0.1", 5053))

    try:
        response, _ = sock.recvfrom(4096)
        elapsed = (time.time() - start) * 1000

        # Check RCODE
        flags = struct.unpack(">H", response[2:4])[0]
        rcode = flags & 0x000F
        ancount = struct.unpack(">H", response[6:8])[0]

        if rcode == 3:
            print(f"  Result: NXDOMAIN (blocked via NXDOMAIN mode)  [{elapsed:.1f}ms]")
            result = "blocked"
        elif ancount > 0:
            # Get the last 4 bytes of the answer as the IP
            # (simplified — works for single A-record answers)
            ip_bytes = response[-4:]
            ip = ".".join(str(b) for b in ip_bytes)
            print(f"  Result: {ip}  [{elapsed:.1f}ms]")
            result = "blocked" if ip == "0.0.0.0" else "allowed"
        else:
            print(f"  Result: No answers  [{elapsed:.1f}ms]")
            result = "unknown"

        status = "PASS" if (result == "blocked") == expect_blocked else "FAIL"
        print(f"  Status: {status}")

    except socket.timeout:
        print("  ERROR: No response (timeout)")
    finally:
        sock.close()


def main():
    print("=" * 50)
    print("  Blocklist Test Suite")
    print("=" * 50)

    # Test blocked domains
    test_domain("doubleclick.net", expect_blocked=True)
    test_domain("googlesyndication.com", expect_blocked=True)

    # Test subdomain blocking (parent domain is blocked)
    test_domain("ads.doubleclick.net", expect_blocked=True)
    test_domain("tracking.ads.doubleclick.net", expect_blocked=True)

    # Test allowed domains
    test_domain("youtube.com", expect_blocked=False)
    test_domain("google.com", expect_blocked=False)

    print("\n" + "=" * 50)
    print("  Tests complete!")
    print("=" * 50)


if __name__ == "__main__":
    main()
