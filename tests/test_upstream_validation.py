"""
tests/test_upstream_validation.py  —  Unit tests for Security S4: Upstream Validation
=====================================================================================
Validates upstream DNS responses before caching or forwarding:
1. Source IP check (must match authorized upstreams)
2. Transaction ID check (must match query TXID)
3. QR flag check (must be a response, not a query)
4. QNAME match check (case-insensitive match)
5. Private/spoofed IP check (DNS Rebinding protection)
6. Server retry on alternative upstream and SERVFAIL on failure
"""

import os
import sys
import struct
import socket
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dns.server import DNSServer, validate_upstream_response
from dns.builder import build_servfail_response


def build_raw_response(domain="example.com", qtype=1, query_id=0x1234, ip="93.184.216.34", qr=1, rcode=0):
    flags = (qr << 15) | 0x0180 | (rcode & 0x0F)
    header = struct.pack(">HHHHHH", query_id, flags, 1, 1 if ip else 0, 0, 0)
    labels = domain.split(".")
    qname = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)

    answers = b""
    if ip:
        name_ptr = struct.pack(">H", 0xC00C)
        ttl = 300
        ip_bytes = socket.inet_aton(ip)
        answers = name_ptr + struct.pack(">HHIH", qtype, 1, ttl, len(ip_bytes)) + ip_bytes

    return header + question + answers


class TestUpstreamValidation(unittest.TestCase):

    def setUp(self):
        self.config = {
            "listen_host": "127.0.0.1",
            "listen_port": 5353,
            "upstream_dns": "8.8.8.8",
            "upstream_fallback": "1.1.1.1",
            "upstream_validation": True,
            "allowed_upstreams": ["8.8.8.8", "1.1.1.1"],
            "client_allowlist_enabled": False,
        }
        self.mock_blocklist = MagicMock()
        self.mock_blocklist.is_blocked.return_value = (False, None)
        self.mock_blocklist.blocked_domains = set()
        self.mock_blocklist.allowed_domains = {"intranet.corp"}

        self.mock_cache = MagicMock()
        self.mock_cache.get.return_value = (None, 0)
        self.mock_cache.entries = {}

        self.mock_ratelimit = MagicMock()
        self.mock_ratelimit.is_rate_limited.return_value = False

        self.mock_stats = MagicMock()

        self.server = DNSServer(
            self.config,
            self.mock_blocklist,
            self.mock_cache,
            self.mock_ratelimit,
            self.mock_stats
        )

    def test_valid_response_passes(self):
        """Test 1: Valid upstream response passes validation cleanly."""
        resp = build_raw_response(domain="example.com", query_id=0x1234, ip="93.184.216.34")
        valid, msg = validate_upstream_response(
            resp, source_ip="8.8.8.8", expected_id=0x1234, expected_domain="example.com"
        )
        self.assertTrue(valid, f"Expected valid response to pass, got: {msg}")
        self.assertEqual(msg, "OK")

    def test_wrong_txid_fails(self):
        """Test 2: Transaction ID mismatch must be rejected (spoofing protection)."""
        resp = build_raw_response(domain="example.com", query_id=0x9999, ip="93.184.216.34")
        valid, msg = validate_upstream_response(
            resp, source_ip="8.8.8.8", expected_id=0x1234, expected_domain="example.com"
        )
        self.assertFalse(valid, "Expected mismatched TXID to fail")
        self.assertIn("Transaction ID mismatch", msg)

    def test_wrong_source_ip_fails(self):
        """Test 3: Response from unauthorized source IP must be dropped."""
        resp = build_raw_response(domain="example.com", query_id=0x1234, ip="93.184.216.34")
        valid, msg = validate_upstream_response(
            resp, source_ip="198.51.100.77", expected_id=0x1234, expected_domain="example.com",
            allowed_upstreams=["8.8.8.8", "1.1.1.1"]
        )
        self.assertFalse(valid, "Expected unauthorized source IP to fail")
        self.assertIn("not an authorized upstream", msg)

    def test_mismatched_qname_fails(self):
        """Test 4: Response with mismatched QNAME must be rejected."""
        resp = build_raw_response(domain="evil-target.com", query_id=0x1234, ip="93.184.216.34")
        valid, msg = validate_upstream_response(
            resp, source_ip="8.8.8.8", expected_id=0x1234, expected_domain="example.com"
        )
        self.assertFalse(valid, "Expected mismatched QNAME to fail")
        self.assertIn("QNAME mismatch", msg)

    def test_spoofed_private_ip_fails(self):
        """Test 5: Public domain resolving to private RFC1918 / loopback IP must be dropped (DNS Rebinding)."""
        for private_ip in ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]:
            resp = build_raw_response(domain="bank-portal.com", query_id=0x1234, ip=private_ip)
            valid, msg = validate_upstream_response(
                resp, source_ip="8.8.8.8", expected_id=0x1234, expected_domain="bank-portal.com",
                allowlist=self.mock_blocklist
            )
            self.assertFalse(valid, f"Expected private IP {private_ip} to be rejected for public domain")
            self.assertIn("Spoofed private IP", msg)

    def test_allowlisted_domain_allows_private_ip(self):
        """Test 6: Domain explicitly in allowlist is permitted to return private IP."""
        resp = build_raw_response(domain="intranet.corp", query_id=0x1234, ip="192.168.1.50")
        valid, msg = validate_upstream_response(
            resp, source_ip="8.8.8.8", expected_id=0x1234, expected_domain="intranet.corp",
            allowlist=self.mock_blocklist
        )
        self.assertTrue(valid, f"Allowlisted domain should permit internal IP: {msg}")

    def test_qr_flag_zero_fails(self):
        """Test 7: Response packet with QR flag 0 (Query packet) must be dropped."""
        resp = build_raw_response(domain="example.com", query_id=0x1234, ip="93.184.216.34", qr=0)
        valid, msg = validate_upstream_response(
            resp, source_ip="8.8.8.8", expected_id=0x1234, expected_domain="example.com"
        )
        self.assertFalse(valid, "Packet with QR=0 must be rejected")
        self.assertIn("QR flag is 0", msg)

    @patch("dns.server.forward_query")
    def test_server_retries_and_servfails_on_invalid(self, mock_forward):
        """Test 8: Server drops invalid response from primary, retries secondary, and SERVFAILS if both fail."""
        # Both upstreams return packets with mismatched TXID
        bad_resp1 = build_raw_response(domain="example.com", query_id=0x9999, ip="93.184.216.34")
        bad_resp2 = build_raw_response(domain="example.com", query_id=0x8888, ip="93.184.216.34")

        mock_forward.side_effect = [bad_resp1, bad_resp2]

        # Query packet for example.com with ID 0x1234
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        qname = b"\x07example\x03com\x00"
        query_pkt = header + qname + struct.pack(">HH", 1, 1)

        sent_packets = []
        def fake_send(pkt, addr, transport="UDP", tcp_conn=None):
            sent_packets.append(pkt)

        self.server._send_response = fake_send
        self.server._handle_query(query_pkt, ("127.0.0.1", 12345))

        self.assertGreaterEqual(len(sent_packets), 1)
        resp = sent_packets[0]
        # Check SERVFAIL: flags 0x8182 has RCODE 2
        flags = struct.unpack(">H", resp[2:4])[0]
        rcode = flags & 0x000F
        self.assertEqual(rcode, 2, "Expected SERVFAIL (RCODE 2) when all upstreams fail validation")
        self.assertTrue(self.mock_stats.record_invalid_upstream.called)


if __name__ == "__main__":
    unittest.main()

