"""
tests/test_cname_cloaking.py  --  CNAME Cloaking / Cloaking-bypass tests
=========================================================================

Computer Networks concept:
  CNAME (Canonical Name) records let one domain alias to another.
  Trackers exploit this: a first-party "clean" domain CNAMEs to a blocked
  third-party tracker.  Standard DNS blocking only checks the queried
  domain, so the CNAME target slips through.

  CNAME cloaking example:
    client asks:  safe-looking.com  A ?
    upstream responds:
      safe-looking.com   CNAME   xnl-4-quadvlicks.com
      xnl-4-quadvlicks.com CNAME sub.greenmotors.club
      sub.greenmotors.club A     93.184.216.34
    Without CNAME chasing: forwarded to client  (tracker bypasses blocklist!)
    With CNAME chasing:    blocked (0.0.0.0)    (detected!)

Tests in this file:
  1. extract_cname_chain_from_packet() -- parser unit tests
  2. DNSServer._handle_query() CNAME blocking integration tests (mocked)
  3. Normal A/AAAA responses without CNAME still forwarded correctly
  4. Multi-hop CNAME chain (3 hops) detected
  5. Allowlist still wins over CNAME block
"""

import os
import sys
import struct
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, call

# Allow running from project root or tests/ directory
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from dns.parser import (
    parse_domain_name,
    extract_cname_chain_from_packet,
    parse_response,
    parse_answer_section,
)
from dns.builder import build_blocked_response


# ─────────────────────────────────────────────────────────────────────────────
# DNS packet helpers (build raw DNS packets for testing)
# ─────────────────────────────────────────────────────────────────────────────

def encode_domain(domain):
    """Encode a domain name into DNS label format (RFC 1035 §3.1)."""
    encoded = b""
    for label in domain.rstrip(".").split("."):
        encoded += bytes([len(label)]) + label.encode("ascii")
    encoded += b"\x00"  # root label terminator
    return encoded


def build_query(domain, qtype=1, query_id=0x1234):
    """Build a minimal DNS A query packet."""
    # Header: ID, FLAGS(standard query), QDCOUNT=1, rest=0
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = encode_domain(domain) + struct.pack(">HH", qtype, 1)
    return header + question


def build_response_with_cname(query_data, cname_chain, final_ip="93.184.216.34", query_id=0x1234):
    """
    Build a fake upstream DNS response that contains a CNAME chain.

    Args:
        query_data: original query bytes (we echo the question section)
        cname_chain: list of CNAME targets in order, e.g. ["c1.evil.com", "c2.tracker.com"]
                     The last entry resolves to final_ip via an A record.
        final_ip: the IPv4 address at the end of the chain (or None for CNAME-only)
        query_id: DNS query ID

    The function builds answer records WITHOUT compression pointers so that
    extract_cname_chain_from_packet() can parse the rdata directly.
    """
    # Parse question from query to find question_end
    from dns.parser import parse_question
    domain, qtype, qclass, question_end = parse_question(query_data)

    # Build answer records
    answers = b""
    ancount = 0

    # First CNAME: queried domain -> cname_chain[0]
    # Then for each pair cname_chain[i] -> cname_chain[i+1]
    all_cnames = [(domain, cname_chain[0])] if cname_chain else []
    for i in range(len(cname_chain) - 1):
        all_cnames.append((cname_chain[i], cname_chain[i + 1]))

    for src, tgt in all_cnames:
        name = encode_domain(src)
        rdata = encode_domain(tgt)
        # TYPE=5 (CNAME), CLASS=1 (IN), TTL=300, RDLENGTH=len(rdata)
        rr = name + struct.pack(">HHIH", 5, 1, 300, len(rdata)) + rdata
        answers += rr
        ancount += 1

    # Final A record for the last CNAME target (or the domain itself)
    if final_ip and cname_chain:
        last = cname_chain[-1]
        name = encode_domain(last)
        ip_bytes = bytes(int(x) for x in final_ip.split("."))
        rr = name + struct.pack(">HHIH", 1, 1, 300, 4) + ip_bytes
        answers += rr
        ancount += 1

    # Flags: QR=1 RD=1 RA=1 RCODE=0
    flags = 0x8180
    header = struct.pack(">HHHHHH", query_id, flags, 1, ancount, 0, 0)
    question_section = query_data[12:question_end]
    return header + question_section + answers


def build_plain_a_response(query_data, ip="142.250.195.46", query_id=0x1234):
    """Build a plain A record response with no CNAME."""
    from dns.parser import parse_question
    domain, qtype, qclass, question_end = parse_question(query_data)

    name = encode_domain(domain)
    ip_bytes = bytes(int(x) for x in ip.split("."))
    rr = name + struct.pack(">HHIH", 1, 1, 300, 4) + ip_bytes

    flags = 0x8180
    header = struct.pack(">HHHHHH", query_id, flags, 1, 1, 0, 0)
    question_section = query_data[12:question_end]
    return header + question_section + rr


# ─────────────────────────────────────────────────────────────────────────────
# 1. Parser unit tests  --  extract_cname_chain_from_packet
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractCnameChain(unittest.TestCase):

    def test_single_cname(self):
        """Single CNAME hop is extracted correctly."""
        query = build_query("safe-looking.com")
        response = build_response_with_cname(query, ["quadvlicks.com"])
        parsed = parse_response(response)
        cnames = extract_cname_chain_from_packet(response, parsed["answers"])
        self.assertIn("quadvlicks.com", cnames)

    def test_multi_hop_cname_chain(self):
        """All hops in a 3-hop CNAME chain are returned."""
        query = build_query("innocent.com")
        chain = ["hop1.cname.com", "hop2.tracker.net", "greenmotors.club"]
        response = build_response_with_cname(query, chain)
        parsed = parse_response(response)
        cnames = extract_cname_chain_from_packet(response, parsed["answers"])
        self.assertIn("hop1.cname.com", cnames)
        self.assertIn("hop2.tracker.net", cnames)
        self.assertIn("greenmotors.club", cnames)
        # Order: should follow chain order
        self.assertEqual(cnames[0], "hop1.cname.com")
        self.assertEqual(cnames[-1], "greenmotors.club")

    def test_no_cname_in_plain_a_response(self):
        """A response with only an A record returns empty CNAME list."""
        query = build_query("google.com")
        response = build_plain_a_response(query)
        parsed = parse_response(response)
        cnames = extract_cname_chain_from_packet(response, parsed["answers"])
        self.assertEqual(cnames, [])

    def test_cname_lowercase(self):
        """CNAME targets are always returned lowercased."""
        query = build_query("example.com")
        response = build_response_with_cname(query, ["QUADVLICKS.COM"])
        parsed = parse_response(response)
        cnames = extract_cname_chain_from_packet(response, parsed["answers"])
        self.assertTrue(all(c == c.lower() for c in cnames))

    def test_cname_trailing_dot_stripped(self):
        """Trailing dots on CNAME targets are stripped by the server logic."""
        query = build_query("example.com")
        response = build_response_with_cname(query, ["quadvlicks.com"])
        parsed = parse_response(response)
        cnames = extract_cname_chain_from_packet(response, parsed["answers"])
        for c in cnames:
            self.assertFalse(c.endswith("."), f"Trailing dot found: {c!r}")

    def test_subdomain_cname_target(self):
        """Subdomain CNAME targets like xnl-4-quadvlicks.com are extracted."""
        query = build_query("ads.hdhub4u.com")
        response = build_response_with_cname(query, ["xnl-4-quadvlicks.com"])
        parsed = parse_response(response)
        cnames = extract_cname_chain_from_packet(response, parsed["answers"])
        self.assertIn("xnl-4-quadvlicks.com", cnames)


# ─────────────────────────────────────────────────────────────────────────────
# 2. DNSServer integration tests  (fully mocked, no live sockets)
# ─────────────────────────────────────────────────────────────────────────────

def make_server(blocklist, extra_config=None):
    """Create a DNSServer instance with mocked socket and stats."""
    from dns.server import DNSServer
    from dns.cache import DNSCache
    from dns.ratelimit import RateLimiter

    config = {
        "listen_host": "127.0.0.1",
        "listen_port": 53,
        "upstream_dns": "8.8.8.8",
        "upstream_fallback": "1.1.1.1",
        "upstream_port": 53,
        "upstream_timeout": 3,
        "blocking_mode": "zero_ip",
        "cache_size": 512,
        "blocklist_dir": "blocklists",
        "allowlist_file": "allowlist.txt",
    }
    if extra_config:
        config.update(extra_config)

    cache = DNSCache(max_size=512)
    rate_limiter = RateLimiter(max_queries=100, window_seconds=1)
    stats_mock = MagicMock()
    stats_mock.set_cache_ref = MagicMock()
    stats_mock.set_meta = MagicMock()

    server = DNSServer(config, blocklist, cache, rate_limiter, stats_mock)
    server.sock = MagicMock()   # don't bind a real socket
    server.running = True
    return server


class TestCNAMECloakingIntegration(unittest.TestCase):
    """
    Test DNSServer._handle_query() with mocked forward_query() to inject
    fake upstream responses containing CNAME records.
    """

    def _make_blocklist(self, domains):
        """Return a Blocklist pre-loaded with the given domains."""
        from dns.blocklist import Blocklist
        bl = Blocklist(lookup_cache_size=256)
        for domain, category in domains:
            bl.add_domain(domain, category)
        return bl

    # ── Test 1: single CNAME to blocked domain ──────────────────────────────

    def test_single_cname_blocked(self):
        """
        Query for innocent domain whose CNAME resolves to greenmotors.club
        (a blocked domain) => server must return BLOCKED response, not forward.
        """
        bl = self._make_blocklist([("greenmotors.club", "custom")])
        server = make_server(bl)

        query_data = build_query("innocent-looking.com")
        fake_upstream = build_response_with_cname(
            query_data, ["greenmotors.club"], final_ip="1.2.3.4"
        )

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)
        client_addr = ("127.0.0.1", 12345)

        with patch("dns.server.forward_query", return_value=fake_upstream):
            server._handle_query(query_data, client_addr)

        self.assertEqual(len(sent_packets), 1, "Expected exactly one response sent")
        # Verify it's a blocked response (0.0.0.0 in A record answer)
        response = sent_packets[0]
        # Parse the response header ancount > 0 and rcode == 0
        ancount = struct.unpack(">H", response[6:8])[0]
        self.assertGreater(ancount, 0, "Blocked response should have an answer (0.0.0.0)")
        # Verify stats.log_query was called with BLOCKED status
        server.stats.log_query.assert_called()
        call_args = server.stats.log_query.call_args
        self.assertIn("BLOCKED", call_args[0])

    # ── Test 2: multi-hop CNAME chain ───────────────────────────────────────

    def test_multi_hop_cname_chain_blocked(self):
        """
        3-hop CNAME chain: innocent.com -> hop1.com -> hop2.net -> quadvlicks.com
        quadvlicks.com is blocked => entire query must be blocked.
        """
        bl = self._make_blocklist([("quadvlicks.com", "custom")])
        server = make_server(bl)

        query_data = build_query("innocent.com")
        chain = ["hop1.clean.com", "hop2.relay.net", "quadvlicks.com"]
        fake_upstream = build_response_with_cname(query_data, chain)

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        with patch("dns.server.forward_query", return_value=fake_upstream):
            server._handle_query(query_data, ("127.0.0.1", 9999))

        self.assertEqual(len(sent_packets), 1)
        call_args = server.stats.log_query.call_args
        self.assertIn("BLOCKED", call_args[0])
        # Category should contain [CNAME]
        kwargs = call_args[1] if call_args[1] else {}
        category = kwargs.get("category", "")
        self.assertIn("CNAME", category, f"Expected [CNAME] in category, got: {category!r}")

    # ── Test 3: subdomain of blocked CNAME target ───────────────────────────

    def test_subdomain_cname_target_blocked(self):
        """
        CNAME target xnl-4-quadvlicks.com is added explicitly to the
        blocklist.  It must be blocked when it appears as a CNAME target.
        Note: DNS suffix matching only matches actual subdomains (.quadvlicks.com),
        not strings that happen to contain 'quadvlicks' as a substring.
        Real-world blocklists include the exact domain, e.g. xnl-4-quadvlicks.com.
        """
        bl = self._make_blocklist([
            ("quadvlicks.com", "custom"),
            ("xnl-4-quadvlicks.com", "custom"),   # exact entry as found in OISD
        ])
        server = make_server(bl)

        query_data = build_query("ads.hdhub4u.com")
        fake_upstream = build_response_with_cname(
            query_data, ["xnl-4-quadvlicks.com"], final_ip="5.6.7.8"
        )

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        with patch("dns.server.forward_query", return_value=fake_upstream):
            server._handle_query(query_data, ("127.0.0.1", 9999))

        self.assertEqual(len(sent_packets), 1)
        call_args = server.stats.log_query.call_args
        self.assertIn("BLOCKED", call_args[0])

    # ── Test 4: clean CNAME (not blocked) ───────────────────────────────────

    def test_clean_cname_forwarded(self):
        """
        CNAME to a domain NOT in blocklist must be forwarded normally.
        e.g., www.example.com CNAME example.com (no-op CNAME, common pattern)
        """
        bl = self._make_blocklist([("greenmotors.club", "custom")])
        server = make_server(bl)

        query_data = build_query("www.example.com")
        fake_upstream = build_response_with_cname(
            query_data, ["example.com"], final_ip="93.184.216.34"
        )

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        with patch("dns.server.forward_query", return_value=fake_upstream):
            server._handle_query(query_data, ("127.0.0.1", 9999))

        self.assertEqual(len(sent_packets), 1)
        call_args = server.stats.log_query.call_args
        # Should be FORWARDED, not BLOCKED
        self.assertIn("FORWARDED", call_args[0])

    # ── Test 5: plain A response (no CNAME) still forwarded ─────────────────

    def test_plain_a_response_not_blocked(self):
        """
        Normal A query without any CNAME in response must be forwarded
        unchanged — CNAME chasing must not affect non-CNAME responses.
        """
        bl = self._make_blocklist([("greenmotors.club", "custom")])
        server = make_server(bl)

        query_data = build_query("google.com")
        fake_upstream = build_plain_a_response(query_data, ip="142.250.195.46")

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        with patch("dns.server.forward_query", return_value=fake_upstream):
            server._handle_query(query_data, ("127.0.0.1", 9999))

        self.assertEqual(len(sent_packets), 1)
        call_args = server.stats.log_query.call_args
        self.assertIn("FORWARDED", call_args[0])

    # ── Test 6: original domain blocked (pre-CNAME check still works) ───────

    def test_original_domain_blocked_before_cname_check(self):
        """
        If the original queried domain is in the blocklist, it must be
        blocked immediately — no forwarding happens at all.
        """
        bl = self._make_blocklist([("doubleclick.net", "ads")])
        server = make_server(bl)

        query_data = build_query("doubleclick.net")

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        with patch("dns.server.forward_query") as mock_fwd:
            server._handle_query(query_data, ("127.0.0.1", 9999))
            mock_fwd.assert_not_called()   # never reached upstream

        self.assertEqual(len(sent_packets), 1)
        call_args = server.stats.log_query.call_args
        self.assertIn("BLOCKED", call_args[0])

    # ── Test 7: allowlist overrides CNAME block ─────────────────────────────

    def test_allowlisted_domain_not_blocked_even_if_cname_would_match(self):
        """
        If the QUERIED domain is in the allowlist, the allowlist check runs
        BEFORE forwarding — the query is forwarded without any CNAME check.
        (Allowlist protects the user's explicitly trusted domains.)

        Note: allowlist applies to the queried domain, not the CNAME target.
        CNAME targets are only checked for block, not for allow override.
        This keeps the behavior intentional: trusting a domain doesn't mean
        trusting any tracker it CNAMEs to.
        """
        from dns.blocklist import Blocklist
        bl = Blocklist(lookup_cache_size=256)
        bl.add_domain("greenmotors.club", "custom")
        bl.add_to_allowlist("trusted-site.com")  # allowlist the queried domain

        server = make_server(bl)

        # Query for the allowlisted domain — it should not be blocked
        query_data = build_query("trusted-site.com")
        fake_upstream = build_plain_a_response(query_data, "1.2.3.4")

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        with patch("dns.server.forward_query", return_value=fake_upstream):
            server._handle_query(query_data, ("127.0.0.1", 9999))

        self.assertEqual(len(sent_packets), 1)
        call_args = server.stats.log_query.call_args
        # Should be FORWARDED (allowlisted domain bypasses block entirely)
        self.assertIn("FORWARDED", call_args[0])

    # ── Test 8: greenmotors.club in custom.txt is blocked ───────────────────

    def test_greenmotors_club_in_custom_blocklist(self):
        """
        Verify greenmotors.club and quadvlicks.com (added to custom.txt in
        this session) are correctly loaded and blocked by Blocklist.
        Also verifies that actual subdomains (sub.quadvlicks.com) are
        blocked via suffix match, while unrelated domains containing the
        string 'quadvlicks' are NOT auto-blocked (xnl-4-quadvlicks.com is
        a different registrable domain -- must be listed explicitly).
        """
        from dns.blocklist import Blocklist
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            custom_path = os.path.join(tmpdir, "custom.txt")
            with open(custom_path, "w") as f:
                f.write("# custom\ngreenmotors.club\nquadvlicks.com\n")

            bl = Blocklist(lookup_cache_size=256)
            bl.load_all_blocklists(tmpdir)

            # Exact match
            blocked, cat = bl.is_blocked("greenmotors.club")
            self.assertTrue(blocked, "greenmotors.club must be blocked")
            self.assertEqual(cat, "custom")

            blocked, cat = bl.is_blocked("quadvlicks.com")
            self.assertTrue(blocked, "quadvlicks.com must be blocked")

            # Real subdomain of quadvlicks.com IS blocked via suffix match
            blocked, cat = bl.is_blocked("sub.quadvlicks.com")
            self.assertTrue(blocked, "sub.quadvlicks.com (real subdomain) must be blocked")

            # sub.greenmotors.club also blocked via suffix match
            blocked, cat = bl.is_blocked("sub.greenmotors.club")
            self.assertTrue(blocked, "sub.greenmotors.club (real subdomain) must be blocked")

            # xnl-4-quadvlicks.com is a DIFFERENT domain (not a subdomain)
            # It must NOT be auto-blocked unless explicitly listed
            blocked, cat = bl.is_blocked("xnl-4-quadvlicks.com")
            self.assertFalse(
                blocked,
                "xnl-4-quadvlicks.com is not a subdomain of quadvlicks.com; "
                "it must be listed explicitly in blocklist to be blocked"
            )
            # (In practice, OISD and AdGuard lists do include it explicitly.)

    # ── Test 9: CNAME to non-blocked domain + blocked A fallback ────────────

    def test_cname_to_blocked_subdomain_via_suffix_match(self):
        """
        CNAME target sub.greenmotors.club must be blocked via suffix match
        when greenmotors.club is in the blocklist.
        """
        bl = self._make_blocklist([("greenmotors.club", "custom")])
        server = make_server(bl)

        query_data = build_query("cloaked-ad.example.com")
        fake_upstream = build_response_with_cname(
            query_data, ["sub.greenmotors.club"], final_ip="10.20.30.40"
        )

        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        with patch("dns.server.forward_query", return_value=fake_upstream):
            server._handle_query(query_data, ("127.0.0.1", 9999))

        self.assertEqual(len(sent_packets), 1)
        call_args = server.stats.log_query.call_args
        self.assertIn("BLOCKED", call_args[0])


# ─────────────────────────────────────────────────────────────────────────────
# 3. Rate-limit path is unaffected (regression)
# ─────────────────────────────────────────────────────────────────────────────

class TestRegressionRateLimit(unittest.TestCase):

    def test_rate_limited_client_gets_refused(self):
        """Rate-limited client still gets REFUSED, not affected by CNAME logic."""
        from dns.blocklist import Blocklist
        bl = Blocklist(lookup_cache_size=64)

        from dns.server import DNSServer
        from dns.cache import DNSCache
        from dns.ratelimit import RateLimiter

        config = {
            "listen_host": "127.0.0.1",
            "listen_port": 53,
            "upstream_dns": "8.8.8.8",
            "upstream_fallback": "1.1.1.1",
            "upstream_port": 53,
            "upstream_timeout": 3,
            "blocking_mode": "zero_ip",
            "cache_size": 64,
        }
        cache = DNSCache(max_size=64)
        rate_limiter = MagicMock()
        rate_limiter.is_rate_limited.return_value = True   # always rate limited
        stats_mock = MagicMock()
        stats_mock.set_cache_ref = MagicMock()
        stats_mock.set_meta = MagicMock()

        server = DNSServer(config, bl, cache, rate_limiter, stats_mock)
        server.sock = MagicMock()
        server.running = True

        query_data = build_query("google.com")
        sent_packets = []
        server.sock.sendto = lambda data, addr: sent_packets.append(data)

        with patch("dns.server.forward_query") as mock_fwd:
            server._handle_query(query_data, ("10.0.0.1", 9999))
            mock_fwd.assert_not_called()

        self.assertEqual(len(sent_packets), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
