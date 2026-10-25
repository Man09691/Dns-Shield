"""
dns/parser.py  —  DNS Packet Parser
====================================
Computer Networks concept: DNS message format (RFC 1035 Section 4).

A DNS packet has:
  - A 12-byte HEADER (ID, flags, counts)
  - A QUESTION section  (domain name + qtype + qclass)
  - ANSWER / AUTHORITY / ADDITIONAL sections in responses

This module parses those sections from raw bytes using the struct module.
We also handle DNS name compression (pointers starting with 0xC0).
"""

import struct


# ──────────────────────────────────────────────────────────────
# Header parsing
# ──────────────────────────────────────────────────────────────

def parse_header(data):
    """
    Parse the 12-byte DNS header.

    Header layout (each field is big-endian):
      Bytes 0-1:   ID       – query identifier (client picks this)
      Bytes 2-3:   FLAGS    – QR, OPCODE, AA, TC, RD, RA, RCODE
      Bytes 4-5:   QDCOUNT  – number of questions
      Bytes 6-7:   ANCOUNT  – number of answer records
      Bytes 8-9:   NSCOUNT  – number of authority records
      Bytes 10-11: ARCOUNT  – number of additional records

    Returns a dict with these fields for easy access.
    Raises ValueError if the packet is too short.
    """
    if len(data) < 12:
        raise ValueError(f"Packet too short for DNS header: {len(data)} bytes")

    # ">HHHHHH" means 6 unsigned 16-bit integers in big-endian (network) order
    query_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", data[:12]
    )

    return {
        "id": query_id,
        "flags": flags,
        "rcode": flags & 0x000F,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }


# ──────────────────────────────────────────────────────────────
# Domain name parsing (with compression pointer support)
# ──────────────────────────────────────────────────────────────

def parse_domain_name(data, offset):
    """
    Parse a DNS domain name starting at 'offset' in 'data'.

    DNS names are encoded as a series of labels:
      - Each label starts with a LENGTH byte, then that many ASCII chars.
      - A zero-length label marks the end.
      - A COMPRESSION POINTER is two bytes: first byte has top 2 bits set
        (0xC0), and the remaining 14 bits give an offset into the packet
        where the rest of the name can be found. This saves space.

    Returns: (domain_name_string, new_offset)
      new_offset = position right after this name field in the packet
                   (important: if a pointer is used, new_offset is right
                    after the 2-byte pointer, NOT after the pointed-to name)
    """
    labels = []
    jumped = False        # did we follow a compression pointer?
    original_offset = None  # where to resume reading after the pointer
    max_jumps = 20        # safety limit to prevent infinite loops

    jumps = 0
    while jumps < max_jumps:
        if offset >= len(data):
            raise ValueError(f"Name parsing went past end of packet at offset {offset}")

        length = data[offset]

        # ── Compression pointer (top 2 bits are 11) ──
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated compression pointer")
            # The pointer is a 14-bit offset into the packet.
            # We mask off the top 2 bits: (length & 0x3F) gives the high byte.
            pointer = ((length & 0x3F) << 8) | data[offset + 1]

            if not jumped:
                # Remember where to continue reading AFTER this 2-byte pointer
                original_offset = offset + 2
            jumped = True
            offset = pointer
            jumps += 1
            continue

        # ── End of name (zero-length label) ──
        if length == 0:
            offset += 1
            break

        # ── Normal label ──
        offset += 1
        if offset + length > len(data):
            raise ValueError(f"Label length {length} goes past end of packet")
        label = data[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    else:
        raise ValueError("Too many compression pointer jumps (possible loop)")

    domain = ".".join(labels)

    # If we followed a pointer, the "real" next position is right after
    # the 2-byte pointer, not where the pointer led us.
    if jumped:
        return domain, original_offset
    else:
        return domain, offset


def parse_question(data):
    """
    Parse the first question from a DNS packet.

    The question section starts at byte 12 (right after the header).
    It contains:
      - The domain name (variable length, label-encoded)
      - QTYPE  (2 bytes) – e.g. 1 = A record, 28 = AAAA record
      - QCLASS (2 bytes) – almost always 1 = IN (Internet)

    Returns: (domain_name, qtype, qclass, question_end_offset)
    """
    domain_name, offset = parse_domain_name(data, 12)

    if offset + 4 > len(data):
        raise ValueError("Packet truncated in question section (no qtype/qclass)")

    # ">HH" = two big-endian unsigned 16-bit integers
    qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
    question_end = offset + 4

    # Always lowercase the domain name for consistent comparisons
    domain_name = domain_name.lower()

    return domain_name, qtype, qclass, question_end


# ──────────────────────────────────────────────────────────────
# Answer section parsing (for reading upstream responses)
# ──────────────────────────────────────────────────────────────

def parse_answer_section(data, start_offset, count):
    """
    Parse 'count' resource records (answers) starting at 'start_offset'.

    Each resource record (RR) has:
      - NAME      (variable, may be a compression pointer)
      - TYPE      (2 bytes)
      - CLASS     (2 bytes)
      - TTL       (4 bytes, unsigned 32-bit) – time to live in seconds
      - RDLENGTH  (2 bytes) – length of the RDATA
      - RDATA     (variable) – the actual data (e.g. an IP address)

    Returns: (list_of_records, offset_after_last_record)
    Each record is a dict with: name, type, class, ttl, rdlength, rdata, rdata_offset
    """
    records = []
    offset = start_offset

    for _ in range(count):
        # Parse the name (could be a pointer like 0xC00C)
        name, offset = parse_domain_name(data, offset)

        if offset + 10 > len(data):
            raise ValueError("Packet truncated in answer record")

        # ">HHIH" = type(2) + class(2) + ttl(4) + rdlength(2)
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10

        if offset + rdlength > len(data):
            raise ValueError("Packet truncated in answer RDATA")

        rdata = data[offset:offset + rdlength]
        rdata_offset = offset
        offset += rdlength

        records.append({
            "name": name.lower(),
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "rdlength": rdlength,
            "rdata": rdata,
            "rdata_offset": rdata_offset,
        })

    return records, offset


def parse_response(data):
    """
    Parse a complete DNS response: header + question + all answer records.

    This is used to read upstream responses so we can extract TTLs and IPs.

    Returns a dict with:
      - header:    the parsed header dict
      - domain:    the queried domain name
      - qtype:     the query type
      - qclass:    the query class
      - question_end: byte offset where the question section ends
      - answers:   list of parsed answer records
    """
    header = parse_header(data)
    domain, qtype, qclass, question_end = parse_question(data)

    answers = []
    if header["ancount"] > 0:
        answers, _ = parse_answer_section(data, question_end, header["ancount"])

    return {
        "header": header,
        "domain": domain,
        "qtype": qtype,
        "qclass": qclass,
        "question_end": question_end,
        "answers": answers,
    }


def get_answer_ips(answers):
    """
    Extract human-readable IP addresses from answer records.

    For A records (type 1): 4 bytes -> "x.x.x.x"
    For AAAA records (type 28): 16 bytes -> we just show the hex for simplicity
    """
    ips = []
    for record in answers:
        if record["type"] == 1 and record["rdlength"] == 4:
            # A record: 4 bytes = IPv4 address
            ip = ".".join(str(b) for b in record["rdata"])
            ips.append(ip)
        elif record["type"] == 28 and record["rdlength"] == 16:
            # AAAA record: 16 bytes = IPv6 address
            # Format as groups of 4 hex digits separated by colons
            parts = []
            for i in range(0, 16, 2):
                parts.append(f"{record['rdata'][i]:02x}{record['rdata'][i+1]:02x}")
            ips.append(":".join(parts))
    return ips


def get_min_ttl(answers, default=60):
    """
    Get the minimum TTL from a list of answer records.

    We use the minimum so we don't cache longer than the shortest-lived record.
    Returns the default if there are no answers.
    """
    ttls = [r["ttl"] for r in answers if r["ttl"] > 0]
    if ttls:
        return min(ttls)
    return default
