"""
tools/test_client.py  —  DNS Test Client
==========================================
Computer Networks concept: Building a DNS query packet from scratch.

Usage:
  python tools/test_client.py youtube.com
  python tools/test_client.py doubleclick.net
  python tools/test_client.py example.com AAAA

Builds a DNS query packet with struct (no libraries), sends it to
the local DNS server, parses and prints the response.
"""

import socket
import struct
import sys
import time
import random


def build_query(domain, qtype=1):
    """
    Build a DNS query packet from scratch.

    Parameters:
      domain: e.g. "youtube.com"
      qtype:  1 = A record (IPv4), 28 = AAAA record (IPv6)

    DNS query packet layout:
      HEADER (12 bytes):
        ID     (2 bytes) - random identifier
        FLAGS  (2 bytes) - 0x0100 = standard query with recursion desired
        QDCOUNT (2 bytes) - 1 question
        ANCOUNT (2 bytes) - 0 answers
        NSCOUNT (2 bytes) - 0 authority
        ARCOUNT (2 bytes) - 0 additional

      QUESTION:
        NAME  - label-encoded domain name
        QTYPE  (2 bytes)
        QCLASS (2 bytes) - 1 = IN (Internet)
    """
    # Random query ID (2 bytes, 0-65535)
    query_id = random.randint(0, 65535)

    # Header: ID=random, FLAGS=0x0100 (RD=1), QDCOUNT=1, rest=0
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)

    # Encode the domain name as DNS labels
    # "youtube.com" -> b'\x07youtube\x03com\x00'
    # Each label: 1 byte length + the ASCII characters
    question_name = b""
    for label in domain.split("."):
        length = len(label)
        question_name += struct.pack("B", length)  # 1-byte label length
        question_name += label.encode("ascii")
    question_name += b"\x00"  # end of name (zero-length label)

    # QTYPE and QCLASS
    question_footer = struct.pack(">HH", qtype, 1)  # qtype, class=IN

    return header + question_name + question_footer, query_id


def parse_response(data):
    """
    Parse a DNS response and print the results.
    """
    if len(data) < 12:
        print("ERROR: Response too short")
        return

    # Parse header
    query_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        ">HHHHHH", data[:12]
    )

    # RCODE is the last 4 bits of the flags
    rcode = flags & 0x000F
    rcode_names = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
                   3: "NXDOMAIN", 5: "REFUSED"}

    print(f"  Response ID: {query_id}")
    print(f"  Flags: 0x{flags:04X}")
    print(f"  RCODE: {rcode} ({rcode_names.get(rcode, 'UNKNOWN')})")
    print(f"  Answers: {ancount}")

    if ancount == 0:
        if rcode == 3:
            print("  Result: NXDOMAIN (domain blocked or does not exist)")
        return

    # Skip the question section to get to answers
    pos = 12
    # Skip domain name in question
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if (length & 0xC0) == 0xC0:
            pos += 2
            break
        pos += 1 + length
    pos += 4  # skip QTYPE + QCLASS

    # Parse each answer
    for i in range(ancount):
        if pos >= len(data):
            break

        # Skip the name (may be a pointer)
        if (data[pos] & 0xC0) == 0xC0:
            pos += 2  # compression pointer is 2 bytes
        else:
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 1  # skip the zero terminator

        if pos + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[pos:pos+10])
        pos += 10

        if pos + rdlength > len(data):
            break

        rdata = data[pos:pos + rdlength]
        pos += rdlength

        # Print the record
        if rtype == 1 and rdlength == 4:
            ip = ".".join(str(b) for b in rdata)
            print(f"  Answer {i+1}: A  {ip}  TTL={ttl}")
        elif rtype == 28 and rdlength == 16:
            parts = []
            for j in range(0, 16, 2):
                parts.append(f"{rdata[j]:02x}{rdata[j+1]:02x}")
            ipv6 = ":".join(parts)
            print(f"  Answer {i+1}: AAAA  {ipv6}  TTL={ttl}")
        elif rtype == 5:
            print(f"  Answer {i+1}: CNAME  (rdlength={rdlength})  TTL={ttl}")
        else:
            print(f"  Answer {i+1}: type={rtype}  rdlength={rdlength}  TTL={ttl}")


def main():
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage: python tools/test_client.py <domain> [A|AAAA]")
        print("Examples:")
        print("  python tools/test_client.py youtube.com")
        print("  python tools/test_client.py doubleclick.net")
        print("  python tools/test_client.py example.com AAAA")
        sys.exit(1)

    domain = sys.argv[1]
    qtype_str = sys.argv[2].upper() if len(sys.argv) > 2 else "A"
    qtype_map = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "CNAME": 5}
    qtype = qtype_map.get(qtype_str, 1)

    server_ip = "127.0.0.1"
    server_port = 5053

    print(f"Querying {domain} ({qtype_str}) via {server_ip}:{server_port}")

    # Build the query packet
    query_packet, query_id = build_query(domain, qtype)

    # Send the query
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    start_time = time.time()
    sock.sendto(query_packet, (server_ip, server_port))

    try:
        response, _ = sock.recvfrom(4096)
        elapsed = (time.time() - start_time) * 1000

        print(f"\n  Response received in {elapsed:.1f}ms ({len(response)} bytes)")
        parse_response(response)
    except socket.timeout:
        print("  ERROR: No response (timeout after 5 seconds)")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
