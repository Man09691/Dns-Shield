import socket
import struct

def parse_question(data):
    pos = 12
    labels = []
    while True:
        length = data[pos]
        if length == 0:
            pos += 1
            break
        pos += 1
        label = data[pos:pos+length].decode()
        labels.append(label)
        pos += length
    domain_name = ".".join(labels)
    qtype, qclass = struct.unpack(">HH", data[pos:pos+4])
    pos += 4
    question_end = pos
    return domain_name, qtype, qclass, question_end


def load_blocklist(filename="blocklist.txt"):
    with open(filename) as f:
        return set(line.strip() for line in f if line.strip())


def build_blocked_response(data, question_end, query_id):
    flags = 0x8180
    header = struct.pack(">HHHHHH", query_id, flags, 1, 1, 0, 0)
    question_section = data[12:question_end]
    name_pointer = struct.pack(">H", 0xC00C)
    qtype = struct.pack(">H", 1)
    qclass = struct.pack(">H", 1)
    ttl = struct.pack(">I", 60)
    ip_bytes = bytes([0, 0, 0, 0])  # 0.0.0.0 means "blocked"
    rdlength = struct.pack(">H", 4)
    answer_section = name_pointer + qtype + qclass + ttl + rdlength + ip_bytes
    return header + question_section + answer_section


def forward_to_real_dns(data, upstream="8.8.8.8", port=53):
    forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    forward_sock.settimeout(2)
    forward_sock.sendto(data, (upstream, port))
    response, _ = forward_sock.recvfrom(512)
    forward_sock.close()
    return response


blocklist = load_blocklist()
print(f"Loaded {len(blocklist)} blocked domains")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 5053))

print("DNS server listening on port 5053...")

while True:
    try:
        data, client_address = sock.recvfrom(512)
    except ConnectionResetError:
        continue

    header = struct.unpack(">HHHHHH", data[:12])
    query_id = header[0]

    domain_name, qtype, qclass, question_end = parse_question(data)
    print(f"\nDomain asked: {domain_name}")

    if domain_name in blocklist:
        response = build_blocked_response(data, question_end, query_id)
        sock.sendto(response, client_address)
        print(f"BLOCKED: {domain_name}")
    else:
        try:
            real_response = forward_to_real_dns(data)
            sock.sendto(real_response, client_address)
            print(f"Forwarded real answer for {domain_name}")
        except socket.timeout:
            print(f"Upstream DNS did not respond in time for {domain_name}")