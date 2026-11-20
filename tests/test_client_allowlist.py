"""
tests/test_client_allowlist.py  —  Unit tests for Security S5: Client Allowlist
==============================================================================
Validates client IP access control before blocking, rate limiting, or forwarding:
1. Localhost 127.0.0.1 and ::1 allowed unconditionally
2. LAN 192.168.1.10 allowed via 192.168.0.0/16
3. 10.0.0.5 allowed via 10.0.0.0/8
4. Public 8.8.8.8 blocked (returns REFUSED RCODE 5) when enabled
5. Public 8.8.8.8 allowed when allowlist is disabled
6. Server integration: refused client is not counted as BLOCKED and receives RCODE 5
"""

import os
import sys
import struct
import unittest
from unittest.mock import MagicMock, patch

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dns.server import DNSServer, check_client_allowed


class TestClientAllowlist(unittest.TestCase):

    def setUp(self):
        self.config_enabled = {
            "listen_host": "127.0.0.1",
            "listen_port": 5353,
            "upstream_dns": "8.8.8.8",
            "client_allowlist_enabled": True,
            "client_allowlist": [
                "127.0.0.1",
                "::1",
                "192.168.0.0/16",
                "10.0.0.0/8",
                "172.16.0.0/12"
            ]
        }
        self.config_disabled = {
            "listen_host": "127.0.0.1",
            "listen_port": 5353,
            "upstream_dns": "8.8.8.8",
            "client_allowlist_enabled": False,
            "client_allowlist": ["127.0.0.1"]
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
            self.config_enabled,
            self.mock_blocklist,
            self.mock_cache,
            self.mock_ratelimit,
            self.mock_stats
        )

    def test_localhost_allowed(self):
        """Test 1: Localhost 127.0.0.1 and ::1 are always allowed."""
        self.assertTrue(check_client_allowed("127.0.0.1", self.config_enabled))
        self.assertTrue(check_client_allowed("::1", self.config_enabled))
        # Even with empty allowlist
        self.assertTrue(check_client_allowed("127.0.0.1", {"client_allowlist_enabled": True, "client_allowlist": []}))

    def test_lan_192_168_allowed(self):
        """Test 2: LAN address 192.168.1.10 allowed via 192.168.0.0/16 CIDR."""
        self.assertTrue(check_client_allowed("192.168.1.10", self.config_enabled))
        self.assertTrue(check_client_allowed("192.168.254.200", self.config_enabled))

    def test_10_network_allowed(self):
        """Test 3: Private network address 10.0.0.5 allowed via 10.0.0.0/8 CIDR."""
        self.assertTrue(check_client_allowed("10.0.0.5", self.config_enabled))
        self.assertTrue(check_client_allowed("10.200.50.1", self.config_enabled))

    def test_public_ip_blocked_when_enabled(self):
        """Test 4: Public IP (e.g. 8.8.8.8, 203.0.113.50) blocked when allowlist enabled."""
        self.assertFalse(check_client_allowed("8.8.8.8", self.config_enabled))
        self.assertFalse(check_client_allowed("1.1.1.1", self.config_enabled))
        self.assertFalse(check_client_allowed("203.0.113.50", self.config_enabled))

    def test_public_ip_allowed_when_disabled(self):
        """Test 5: Public IP allowed when client allowlist is disabled."""
        self.assertTrue(check_client_allowed("8.8.8.8", self.config_disabled))
        self.assertTrue(check_client_allowed("203.0.113.50", self.config_disabled))

    def test_server_responds_refused_for_unauthorized_client(self):
        """Test 6: Server drops query from unauthorized client and responds with REFUSED (RCODE 5)."""
        header = struct.pack(">HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0)
        qname = b"\x06google\x03com\x00"
        query_pkt = header + qname + struct.pack(">HH", 1, 1)

        sent_packets = []
        def fake_send(pkt, addr, transport="UDP", tcp_conn=None):
            sent_packets.append((pkt, addr))

        self.server._send_response = fake_send

        # Simulate query from unauthorized public IP 8.8.8.8
        self.server._handle_query(query_pkt, ("8.8.8.8", 53535))

        self.assertEqual(len(sent_packets), 1)
        resp, addr = sent_packets[0]
        self.assertEqual(addr[0], "8.8.8.8")

        # Verify RCODE 5 (REFUSED)
        flags = struct.unpack(">H", resp[2:4])[0]
        rcode = flags & 0x000F
        self.assertEqual(rcode, 5, "Expected RCODE 5 (REFUSED) for unauthorized client")

        # Verify client_blocked recorded
        self.assertTrue(self.mock_stats.record_client_blocked.called)
        # Verify blocklist check was NOT counted as blocked
        self.assertFalse(self.mock_blocklist.is_blocked.called)


if __name__ == "__main__":
    unittest.main()

