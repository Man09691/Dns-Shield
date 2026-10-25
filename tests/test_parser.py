"""
tests/test_parser.py  —  Unit Tests for DNS Parser and Builder
===============================================================
Computer Networks concept: Testing DNS packet construction and parsing.

Run with:  python -m pytest tests/test_parser.py -v
    or:    python -m unittest tests.test_parser -v
"""

import struct
import unittest
import sys
import os

# Add the project root to the path so we can import dns modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.parser import parse_header, parse_question, parse_domain_name, parse_answer_section, get_min_ttl
from dns.builder import build_blocked_response, build_refused_response, swap_query_id


class TestParseHeader(unittest.TestCase):
    """Test the DNS header parser."""

    def test_normal_header(self):
        """A standard query header with 1 question."""
        # ID=0x1234, FLAGS=0x0100 (standard query, RD=1),
        # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        data = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        result = parse_header(data)
        self.assertEqual(result["id"], 0x1234)
        self.assertEqual(result["flags"], 0x0100)
        self.assertEqual(result["qdcount"], 1)
        self.assertEqual(result["ancount"], 0)

    def test_too_short(self):
        """Should raise ValueError for packets shorter than 12 bytes."""
        with self.assertRaises(ValueError):
            parse_header(b"\x00" * 5)

    def test_response_header(self):
        """A response header with 1 question and 2 answers."""
        data = struct.pack(">HHHHHH", 0xABCD, 0x8180, 1, 2, 0, 0)
        result = parse_header(data)
        self.assertEqual(result["id"], 0xABCD)
        self.assertEqual(result["flags"], 0x8180)
        self.assertEqual(result["ancount"], 2)


class TestParseDomainName(unittest.TestCase):
    """Test DNS domain name parsing (label encoding + compression)."""

    def test_simple_domain(self):
        """Parse 'youtube.com' in label format."""
        # \x07youtube\x03com\x00
        name_bytes = b"\x07youtube\x03com\x00"
        # Put a 12-byte dummy header before the name (parse_domain_name takes offset)
        data = b"\x00" * 12 + name_bytes
        name, end_offset = parse_domain_name(data, 12)
        self.assertEqual(name, "youtube.com")
        self.assertEqual(end_offset, 12 + len(name_bytes))

    def test_three_labels(self):
        """Parse 'www.example.com' in label format."""
        name_bytes = b"\x03www\x07example\x03com\x00"
        data = b"\x00" * 12 + name_bytes
        name, end_offset = parse_domain_name(data, 12)
        self.assertEqual(name, "www.example.com")

    def test_compression_pointer(self):
        """
        Test a compression pointer (0xC0 + offset).
        Build a packet where the answer uses a pointer to the question's name.
        """
        # Domain "test.com" at offset 12
        question_name = b"\x04test\x03com\x00"
        # Dummy header (12 bytes) + question name + QTYPE + QCLASS
        header = b"\x00" * 12
        qtype_qclass = struct.pack(">HH", 1, 1)
        question = header + question_name + qtype_qclass

        # Now add an answer with a compression pointer to offset 12
        pointer = struct.pack(">H", 0xC00C)  # points to byte 12
        data = question + pointer

        # Parse the name at the pointer position
        name, end_offset = parse_domain_name(data, len(question))
        self.assertEqual(name, "test.com")
        # After a pointer, the offset should be right after the 2-byte pointer
        self.assertEqual(end_offset, len(question) + 2)


class TestParseQuestion(unittest.TestCase):
    """Test parsing the question section of a DNS query."""

    def test_a_query(self):
        """Parse a standard A query for 'google.com'."""
        # Build a proper query packet
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        name = b"\x06google\x03com\x00"
        qtype_qclass = struct.pack(">HH", 1, 1)  # A, IN
        data = header + name + qtype_qclass

        domain, qtype, qclass, qend = parse_question(data)
        self.assertEqual(domain, "google.com")
        self.assertEqual(qtype, 1)
        self.assertEqual(qclass, 1)
        self.assertEqual(qend, len(data))

    def test_case_insensitive(self):
        """Domain names should be lowercased."""
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        name = b"\x06Google\x03COM\x00"
        qtype_qclass = struct.pack(">HH", 1, 1)
        data = header + name + qtype_qclass

        domain, _, _, _ = parse_question(data)
        self.assertEqual(domain, "google.com")

    def test_aaaa_query(self):
        """Parse an AAAA query."""
        header = struct.pack(">HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0)
        name = b"\x07example\x03com\x00"
        qtype_qclass = struct.pack(">HH", 28, 1)  # AAAA, IN
        data = header + name + qtype_qclass

        domain, qtype, qclass, qend = parse_question(data)
        self.assertEqual(domain, "example.com")
        self.assertEqual(qtype, 28)


class TestBuildBlockedResponse(unittest.TestCase):
    """Test building blocked DNS responses."""

    def test_zero_ip_response(self):
        """Blocked response should return 0.0.0.0 in zero_ip mode."""
        # Build a query for doubleclick.net
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        name = b"\x0bdoubleclick\x03net\x00"
        qtype_qclass = struct.pack(">HH", 1, 1)
        query = header + name + qtype_qclass
        question_end = len(query)

        response = build_blocked_response(query, question_end, 0x1234, qtype=1, mode="zero_ip")

        # Parse the response header
        resp_header = parse_header(response)
        self.assertEqual(resp_header["id"], 0x1234)
        self.assertEqual(resp_header["ancount"], 1)

        # The last 4 bytes should be 0.0.0.0
        ip = response[-4:]
        self.assertEqual(ip, bytes([0, 0, 0, 0]))

    def test_nxdomain_response(self):
        """NXDOMAIN response should have RCODE=3 and no answers."""
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        name = b"\x0bdoubleclick\x03net\x00"
        qtype_qclass = struct.pack(">HH", 1, 1)
        query = header + name + qtype_qclass
        question_end = len(query)

        response = build_blocked_response(query, question_end, 0x1234, qtype=1, mode="nxdomain")

        resp_header = parse_header(response)
        self.assertEqual(resp_header["id"], 0x1234)
        self.assertEqual(resp_header["ancount"], 0)
        # RCODE should be 3 (NXDOMAIN)
        rcode = resp_header["flags"] & 0x000F
        self.assertEqual(rcode, 3)

    def test_aaaa_blocked_response(self):
        """AAAA blocked response should return :: (16 zero bytes)."""
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        name = b"\x04test\x03com\x00"
        qtype_qclass = struct.pack(">HH", 28, 1)
        query = header + name + qtype_qclass
        question_end = len(query)

        response = build_blocked_response(query, question_end, 0x1234, qtype=28, mode="zero_ip")

        # The last 16 bytes should be all zeros (IPv6 ::)
        ipv6 = response[-16:]
        self.assertEqual(ipv6, b'\x00' * 16)


class TestSwapQueryId(unittest.TestCase):
    """Test swapping the query ID in a cached response."""

    def test_swap_id(self):
        """The first 2 bytes should change, rest should stay the same."""
        original = struct.pack(">H", 0x1111) + b"\xAA\xBB\xCC"
        modified = swap_query_id(original, 0x2222)
        self.assertEqual(struct.unpack(">H", modified[:2])[0], 0x2222)
        self.assertEqual(modified[2:], b"\xAA\xBB\xCC")


class TestGetMinTtl(unittest.TestCase):
    """Test TTL extraction."""

    def test_min_of_multiple(self):
        """Should return the smallest TTL."""
        answers = [
            {"ttl": 300, "type": 1, "rdlength": 4, "rdata": b"\x00" * 4},
            {"ttl": 60, "type": 1, "rdlength": 4, "rdata": b"\x00" * 4},
            {"ttl": 3600, "type": 1, "rdlength": 4, "rdata": b"\x00" * 4},
        ]
        self.assertEqual(get_min_ttl(answers), 60)

    def test_empty_answers(self):
        """Should return the default TTL when no answers."""
        self.assertEqual(get_min_ttl([], default=120), 120)


if __name__ == "__main__":
    unittest.main()
