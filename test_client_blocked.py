
import socket

# This builds a real DNS question for "doubleclick.net" - an ad domain
# Same hex-building pattern as before, just different letters/lengths.
query = bytes.fromhex(
    "5678" +                    # a different ID, just to tell this apart
    "0100" +                    # flags (standard question)
    "0001" +                    # 1 question
    "0000" + "0000" + "0000" +  # 0 answers, 0 authority, 0 additional
    "0b646f75626c65636c69636b" +  # 11 "doubleclick"
    "036e6574" +                 # 3 "net"
    "00" +                       # end of name
    "0001" +                     # type A
    "0001"                       # class IN
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(query, ('127.0.0.1', 5053))
print("Sent test DNS query for doubleclick.net")

response, _ = sock.recvfrom(512)
print(f"Got response: {response}")

# Quick readable check: the last 4 bytes of the response are the IP address
ip_bytes = response[-4:]
ip = ".".join(str(b) for b in ip_bytes)
print(f"IP returned: {ip}")