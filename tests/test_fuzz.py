"""
tests/test_fuzz.py  —  Fuzzing and Malformed Packet Robustness Tests
===================================================================
Verifies DNS Shield server stability against malformed / fuzz packets:
1. Empty packet (0 bytes)
2. 1-byte packet (0x00, 0xFF)
3. Truncated DNS headers (< 12 bytes)
4. Random garbage byte payloads (12, 30, 100, 512, 1024 bytes)
5. Very long domain names (1000 characters)
6. Invalid QTYPE 999
7. Wrong / zero Transaction IDs
8. Compression pointer loop and out-of-range pointer offsets
9. Server must NOT crash, must drop / return FORMERR / SERVFAIL / safe response,
   and must still respond to next valid query for www.google.com.
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


def encode_domain(domain: str) -> bytes:
    encoded = b""
    for part in domain.rstrip(".").split("."):
        encoded += bytes([len(part)]) + part.encode("ascii")
    encoded += b"\x00"
    return encoded


def build_query(domain: str, qtype: int = 1, query_id: int = 0xCAFE) -> bytes:
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = encode_domain(domain) + struct.pack(">HH", qtype, 1)
    return header + question


class TestDNSFuzz(unittest.TestCase):
    server = None
    server_thread = None

    @classmethod
    def setUpClass(cls):
        config = {
            "listen_host": "127.0.0.1",
            "listen_port": 53,
            "upstream_dns": "8.8.8.8",
            "upstream_fallback": "1.1.1.1",
            "blocking_mode": "zero_ip",
            "client_allowlist_enabled": True,
            "client_allowlist": ["127.0.0.1", "::1"],
            "upstream_validation": True,
            "allowed_upstreams": ["8.8.8.8", "1.1.1.1"],
        }
        bl = Blocklist()
        bl.add_domain("doubleclick.net", "custom")
        cache = DNSCache(max_size=1000)
        rate_limiter = RateLimiter(
            max_queries=50,
            window_seconds=10,
            block_seconds=30,
            localhost_max_queries=1000,
            domain_burst_limit=1000,
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

    def _query_server(self, packet: bytes, timeout: float = 2.0):
        """Send a packet and return response bytes or None if timed out / ignored."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, ("127.0.0.1", 53))
            resp, _ = sock.recvfrom(4096)
            return resp
        except (socket.timeout, ConnectionResetError):
            return None
        finally:
            sock.close()

    def test_01_fuzz_malformed_packets_and_survival(self):
        """
        Send all required malformed packet varieties.
        Server must not crash, must handle or ignore them cleanly,
        and must respond to the subsequent valid query for www.google.com.
        """
        # Long domain ~1000 chars: 15 labels of 63 chars = 960 chars + dots
        long_qname = b"".join(b"\x3f" + b"a" * 63 for _ in range(15)) + b"\x00"
        long_domain_packet = (
            struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + long_qname
            + struct.pack(">HH", 1, 1)
        )

        # Invalid QTYPE 999
        invalid_qtype_packet = (
            struct.pack(">HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
            + encode_domain("google.com")
            + struct.pack(">HH", 999, 1)
        )

        # Compression pointer loop (pointer at byte 12 pointing back to byte 12)
        loop_pointer_packet = (
            struct.pack(">HHHHHH", 0x5555, 0x0100, 1, 0, 0, 0)
            + b"\xc0\x0c"
            + struct.pack(">HH", 1, 1)
        )

        fuzz_vectors = [
            ("empty_packet", b""),
            ("1_byte_zero", b"\x00"),
            ("1_byte_ff", b"\xff"),
            ("truncated_header_2_bytes", b"\x12\x34"),
            ("truncated_header_6_bytes", b"\x12\x34\x01\x00\x00\x01"),
            ("truncated_header_11_bytes", b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00"),
            ("random_12_bytes", os.urandom(12)),
            ("random_30_bytes", os.urandom(30)),
            ("random_100_bytes", os.urandom(100)),
            ("random_512_bytes", os.urandom(512)),
            ("random_1024_bytes", os.urandom(1024)),
            ("long_domain_1000_chars", long_domain_packet),
            ("invalid_qtype_999", invalid_qtype_packet),
            ("wrong_txid_zero", struct.pack(">HHHHHH", 0x0000, 0x0100, 1, 0, 0, 0) + encode_domain("google.com") + struct.pack(">HH", 1, 1)),
            ("compression_loop_pointer", loop_pointer_packet),
            ("out_of_bounds_pointer", struct.pack(">HHHHHH", 0x6666, 0x0100, 1, 0, 0, 0) + b"\xc0\xff\x00\x01\x00\x01"),
        ]

        for name, pkt in fuzz_vectors:
            with self.subTest(fuzz_case=name):
                # Send fuzz packet
                resp = self._query_server(pkt, timeout=0.8)

                # Server must remain running
                self.assertTrue(
                    self.server.running,
                    f"Server crashed while handling fuzz packet '{name}'!",
                )
                self.assertTrue(
                    self.server_thread.is_alive(),
                    f"Server thread died while handling fuzz packet '{name}'!",
                )

                # If server responded, verify it returned an acceptable DNS response
                if resp is not None:
                    self.assertGreaterEqual(len(resp), 12, "Response must have at least a 12-byte header")
                    flags = struct.unpack(">H", resp[2:4])[0]
                    qr = (flags >> 15) & 1
                    rcode = flags & 0x000F
                    self.assertEqual(qr, 1, "Response packet must have QR=1")
                    # Acceptable rcodes for fuzz / malformed / query:
                    # 0 (NOERROR), 1 (FORMERR), 2 (SERVFAIL), 4 (NOTIMP), 5 (REFUSED)
                    self.assertIn(
                        rcode,
                        [0, 1, 2, 4, 5],
                        f"Unexpected RCODE {rcode} for fuzz case {name}",
                    )

                # Server must respond to next valid query for www.google.com
                valid_query = build_query("www.google.com", 1, 0x7777)
                valid_resp = self._query_server(valid_query, timeout=2.5)
                self.assertIsNotNone(
                    valid_resp,
                    f"Server failed to respond to valid query 'www.google.com' after fuzz case '{name}'",
                )
                self.assertGreaterEqual(len(valid_resp), 12)
                v_flags = struct.unpack(">H", valid_resp[2:4])[0]
                v_rcode = v_flags & 0x000F
                self.assertEqual(
                    v_rcode,
                    0,
                    f"Valid query 'www.google.com' returned unexpected RCODE {v_rcode} after {name}",
                )

    def test_02_server_process_alive_after_all_fuzz_cases(self):
        """
        Verify server thread and socket are still alive and healthy after all fuzz tests.
        """
        self.assertTrue(self.server.running, "Server is not running!")
        self.assertTrue(self.server_thread.is_alive(), "Server thread is dead!")

        # Verify normal query and blocked query both still function normally
        # 1. Blocked domain
        b_query = build_query("doubleclick.net", 1, 0x8888)
        b_resp = self._query_server(b_query, timeout=2.0)
        self.assertIsNotNone(b_resp, "Server did not answer blocked query after fuzzing")
        self.assertIn(b"\x00\x00\x00\x00", b_resp[12:], "doubleclick.net should return 0.0.0.0")

        # 2. Legitimate domain
        g_query = build_query("www.google.com", 1, 0x9999)
        g_resp = self._query_server(g_query, timeout=2.5)
        self.assertIsNotNone(g_resp, "Server did not answer www.google.com query after fuzzing")
        g_flags = struct.unpack(">H", g_resp[2:4])[0]
        self.assertEqual(g_flags & 0x000F, 0, "www.google.com must return NOERROR (0)")


if __name__ == "__main__":
    unittest.main()

