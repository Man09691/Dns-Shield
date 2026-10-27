"""
dns/builder.py  —  DNS Response Builder
========================================
Computer Networks concept: Building DNS response packets (RFC 1035 Section 4).

This module builds DNS response packets from scratch using struct.pack().
We build responses for:
  - Blocked domains (return 0.0.0.0 or :: or NXDOMAIN)
  - Cached responses (swap the query ID to match the new client)
"""

import struct


def build_blocked_response(data, question_end, query_id, qtype=1, mode="zero_ip"):
    """
    Build a response that "blocks" a domain.

    Parameters:
      data:         the original query packet (we re-use the question section)
      question_end: byte offset where the question section ends
      query_id:     the client's query ID (must echo it back)
      qtype:        1 = A record, 28 = AAAA record
      mode:         "zero_ip" -> respond with 0.0.0.0 / ::
                    "nxdomain" -> respond with RCODE 3 (name does not exist)

    The DNS header flags we set:
      0x8180 = QR(1) + RD(1) + RA(1), RCODE=0 (no error)
      0x8183 = QR(1) + RD(1) + RA(1), RCODE=3 (NXDOMAIN = name not found)

    Flag bits breakdown (for viva):
      Bit 15: QR = 1   (this is a Response, not a Query)
      Bit 8:  RD = 1   (Recursion Desired – echoed from the query)
      Bit 7:  RA = 1   (Recursion Available – we support it)
      Bits 0-3: RCODE  (0 = no error, 3 = NXDOMAIN)
    """
    if mode == "nxdomain":
        # NXDOMAIN: RCODE=3, no answer records
        # 0x8183 = 1000 0001 1000 0011 in binary
        flags = 0x8183
        header = struct.pack(">HHHHHH",
            query_id,
            flags,
            1,  # QDCOUNT: 1 question (echo back the question)
            0,  # ANCOUNT: 0 answers (no data)
            0,  # NSCOUNT: 0 authority records
            0,  # ARCOUNT: 0 additional records
        )
        question_section = data[12:question_end]
        return header + question_section

    # ── mode == "zero_ip" (default) ──
    # Return 0.0.0.0 for A queries, :: (all zeros) for AAAA queries.

    # 0x8180 = 1000 0001 1000 0000 in binary (no error)
    flags = 0x8180
    header = struct.pack(">HHHHHH",
        query_id,
        flags,
        1,  # QDCOUNT: 1 question
        1,  # ANCOUNT: 1 answer
        0,  # NSCOUNT
        0,  # ARCOUNT
    )

    # Copy the question section from the original query
    question_section = data[12:question_end]

    # Build the answer record:
    # NAME: use a compression pointer to the name in the question section.
    #   0xC00C means "the name starts at byte offset 12" (0x0C = 12).
    #   This is always where the question's domain name starts.
    name_pointer = struct.pack(">H", 0xC00C)

    if qtype == 28:
        # AAAA record: respond with :: (16 zero bytes = IPv6 all-zeros)
        answer_type = struct.pack(">H", 28)   # TYPE = AAAA
        answer_class = struct.pack(">H", 1)   # CLASS = IN
        answer_ttl = struct.pack(">I", 60)    # TTL = 60 seconds
        ip_bytes = b'\x00' * 16               # :: in IPv6
        answer_rdlength = struct.pack(">H", 16)
    else:
        # A record: respond with 0.0.0.0 (4 zero bytes)
        answer_type = struct.pack(">H", 1)    # TYPE = A
        answer_class = struct.pack(">H", 1)   # CLASS = IN
        answer_ttl = struct.pack(">I", 60)    # TTL = 60 seconds
        ip_bytes = bytes([0, 0, 0, 0])        # 0.0.0.0
        answer_rdlength = struct.pack(">H", 4)

    answer_section = (
        name_pointer + answer_type + answer_class +
        answer_ttl + answer_rdlength + ip_bytes
    )

    return header + question_section + answer_section


def build_refused_response(data, question_end, query_id):
    """
    Build a REFUSED response (RCODE=5).
    Used when a client is rate-limited.

    0x8185 = QR(1) + RD(1) + RA(1) + RCODE=5
    """
    flags = 0x8185
    header = struct.pack(">HHHHHH", query_id, flags, 1, 0, 0, 0)
    question_section = data[12:question_end]
    return header + question_section


def build_servfail_response(data, question_end, query_id):
    """
    Build a SERVFAIL response (RCODE=2).
    Used when upstream DNS query fails or times out.

    0x8182 = QR(1) + RD(1) + RA(1) + RCODE=2 (Server Failure)
    """
    flags = 0x8182
    header = struct.pack(">HHHHHH", query_id, flags, 1, 0, 0, 0)
    question_section = data[12:question_end]
    return header + question_section


def swap_query_id(response_data, new_id):
    """
    Replace the first 2 bytes of a DNS response with a new query ID.

    This is needed for cached responses: the cached response has the OLD
    client's query ID, but we need to send it back with the NEW client's ID.

    DNS spec says: the response ID MUST match the query ID.
    """
    # Pack the new ID as a big-endian unsigned short, replace bytes 0-1
    new_id_bytes = struct.pack(">H", new_id)
    return new_id_bytes + response_data[2:]
