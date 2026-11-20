"""
tests/test_tcp_edns0.py  —  Unit tests for TCP listener, EDNS0 OPT parsing, truncation, and filters
"""

import os
import sys
import struct
import sqlite3
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dns.server import DNSServer
from dns.parser import parse_edns0_payload_size, parse_header
from dns.stats import DNSStats
from dns.dashboard import app


def build_raw_query(domain="example.com", qtype=1, query_id=0x1234, edns_payload=None):
    arcount = 1 if edns_payload is not None else 0
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, arcount)
    labels = domain.split(".")
    qname = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)

    additional = b""
    if edns_payload is not None:
        # OPT record: name=0x00, type=41 (OPT), class=payload_size, ttl=0, rdlen=0
        additional = b"\x00" + struct.pack(">HHIH", 41, edns_payload, 0, 0)

    return header + question + additional


class TestTCPAndEDNS0(unittest.TestCase):

    def setUp(self):
        self.mock_config = {
            "listen_host": "127.0.0.1",
            "listen_port": 5353,
            "upstream_dns": "8.8.8.8",
            "blocking_mode": "zero_ip",
        }
        self.mock_blocklist = MagicMock()
        self.mock_blocklist.is_blocked.return_value = (False, None)
        self.mock_blocklist.blocked_domains = set()

        self.mock_cache = MagicMock()
        self.mock_cache.get.return_value = (None, 0)
        self.mock_cache.entries = {}

        self.mock_ratelimit = MagicMock()
        self.mock_ratelimit.is_rate_limited.return_value = False

        self.mock_stats = MagicMock()

        self.server = DNSServer(
            self.mock_config,
            self.mock_blocklist,
            self.mock_cache,
            self.mock_ratelimit,
            self.mock_stats,
        )

    def test_udp_works(self):
        """Test 1: Verify UDP query processing and UDP transport logging."""
        query_data = build_raw_query("google.com", qtype=1, query_id=0xABCD)
        fake_upstream_response = bytearray(query_data)
        fake_upstream_response[2] = 0x81  # QR=1
        fake_upstream_response[3] = 0x80  # RA=1
        fake_upstream_response = bytes(fake_upstream_response)

        with patch("dns.server.forward_query", return_value=fake_upstream_response):
            self.server._send_response = MagicMock()
            self.server._handle_query(query_data, ("127.0.0.1", 54321), transport="UDP")

            self.server._send_response.assert_called_once()
            args, kwargs = self.server._send_response.call_args
            self.assertEqual(kwargs.get("transport"), "UDP")

            # Check stats logged UDP transport
            self.mock_stats.log_query.assert_called()
            log_kwargs = self.mock_stats.log_query.call_args[1]
            self.assertEqual(log_kwargs.get("transport"), "UDP")

    def test_tcp_works(self):
        """Test 2: Verify TCP query processing with 2-byte length prefix and TCP transport logging."""
        query_data = build_raw_query("example.org", qtype=1, query_id=0x4321)
        fake_upstream_response = bytearray(query_data)
        fake_upstream_response[2] = 0x81
        fake_upstream_response[3] = 0x80
        fake_upstream_response = bytes(fake_upstream_response)

        # Mock TCP client connection
        tcp_packet = struct.pack(">H", len(query_data)) + query_data
        mock_conn = MagicMock()
        mock_conn.recv.side_effect = [tcp_packet[:2], tcp_packet[2:]]

        with patch("dns.server.forward_query", return_value=fake_upstream_response):
            self.server.handle_tcp_client(mock_conn, ("127.0.0.1", 54322))

            # Verify sendall was called with 2-byte length prefix + response
            mock_conn.sendall.assert_called_once()
            sent_data = mock_conn.sendall.call_args[0][0]
            self.assertGreater(len(sent_data), 2)
            prefix_len = struct.unpack(">H", sent_data[:2])[0]
            self.assertEqual(prefix_len, len(sent_data) - 2)

            # Check stats logged TCP transport
            self.mock_stats.log_query.assert_called()
            log_kwargs = self.mock_stats.log_query.call_args[1]
            self.assertEqual(log_kwargs.get("transport"), "TCP")

    def test_edns0_payload_size_parsing(self):
        """Test 3: Verify EDNS0 OPT record parsing extracts advertised UDP payload size."""
        # Query with EDNS0 payload size 4096
        edns_query = build_raw_query("cloudflare.com", qtype=65, edns_payload=4096)
        hdr = parse_header(edns_query)
        self.assertEqual(hdr["arcount"], 1)

        payload_sz = parse_edns0_payload_size(edns_query, hdr)
        self.assertEqual(payload_sz, 4096)

        # Query without EDNS0 OPT record defaults to 512
        normal_query = build_raw_query("cloudflare.com", qtype=1, edns_payload=None)
        normal_hdr = parse_header(normal_query)
        self.assertEqual(normal_hdr["arcount"], 0)

        default_sz = parse_edns0_payload_size(normal_query, normal_hdr)
        self.assertEqual(default_sz, 512)

    def test_udp_truncation_sets_tc_flag(self):
        """Test 4: Verify UDP responses exceeding payload size have TC bit set and are truncated."""
        query_data = build_raw_query("large-record.com", qtype=1, query_id=0x9999)

        # Create a large dummy upstream response (> 512 bytes)
        big_response = bytearray(query_data)
        big_response[2] = 0x81
        big_response[3] = 0x80
        big_response.extend(b"\x00" * 600)  # Total > 600 bytes
        big_response = bytes(big_response)

        with patch("dns.server.forward_query", return_value=big_response):
            self.server._send_response = MagicMock()
            # Send via UDP without EDNS0 (default max 512 bytes)
            self.server._handle_query(query_data, ("127.0.0.1", 54323), transport="UDP")

            self.server._send_response.assert_called_once()
            resp_sent = self.server._send_response.call_args[0][0]
            self.assertLessEqual(len(resp_sent), 512)

            # TC bit is 0x0200
            flags = struct.unpack(">H", resp_sent[2:4])[0]
            self.assertTrue(bool(flags & 0x0200), "TC bit must be set when truncated")

            # In contrast, TCP must NOT truncate
            self.server._send_response.reset_mock()
            mock_conn = MagicMock()
            self.server._handle_query(query_data, ("127.0.0.1", 54323), transport="TCP", tcp_conn=mock_conn)
            tcp_resp_sent = self.server._send_response.call_args[0][0]
            self.assertEqual(len(tcp_resp_sent), len(big_response))

    def test_filter_type(self):
        """Test 5: Verify /api/queries and /api/logs filter by QTYPE."""
        # Use test memory DB
        test_stats = DNSStats(db_path=":memory:")
        test_stats.add("a.com", "1.1.1.1", qtype="A", transport="UDP")
        test_stats.add("aaaa.com", "1.1.1.1", qtype="AAAA", transport="UDP")
        test_stats.add("https.com", "1.1.1.1", qtype="HTTPS", transport="TCP")

        client = app.test_client()
        with patch("dns.dashboard.stats", test_stats):
            # Test /api/queries with type=AAAA
            res = client.get("/api/queries?type=AAAA&per_page=50&page=1")
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            queries = data.get("queries", [])
            self.assertGreaterEqual(len(queries), 1)
            for q in queries:
                self.assertEqual(q.get("qtype") or q.get("type"), "AAAA")

            # Test /api/types endpoint
            res_types = client.get("/api/types")
            self.assertEqual(res_types.status_code, 200)
            types_list = res_types.get_json()
            self.assertTrue(isinstance(types_list, list))
            self.assertIn("AAAA", types_list)

    def test_filter_transport(self):
        """Test 6: Verify /api/queries and /api/logs filter by transport (UDP vs TCP)."""
        test_stats = DNSStats(db_path=":memory:")
        test_stats.add("udp1.com", "1.1.1.1", qtype="A", transport="UDP")
        test_stats.add("udp2.com", "1.1.1.1", qtype="A", transport="UDP")
        test_stats.add("tcp1.com", "1.1.1.1", qtype="A", transport="TCP")

        client = app.test_client()
        with patch("dns.dashboard.stats", test_stats):
            # Test /api/queries with transport=TCP
            res_tcp = client.get("/api/queries?transport=TCP&per_page=50&page=1")
            self.assertEqual(res_tcp.status_code, 200)
            tcp_queries = res_tcp.get_json().get("queries", [])
            self.assertGreaterEqual(len(tcp_queries), 1)
            for q in tcp_queries:
                self.assertEqual(q.get("transport"), "TCP")

            # Test /api/queries with transport=UDP
            res_udp = client.get("/api/queries?transport=UDP&per_page=50&page=1")
            self.assertEqual(res_udp.status_code, 200)
            udp_queries = res_udp.get_json().get("queries", [])
            self.assertGreaterEqual(len(udp_queries), 2)
            for q in udp_queries:
                self.assertEqual(q.get("transport"), "UDP")


if __name__ == "__main__":
    unittest.main()

