import socket

# DNS query for "iitram.ac.in"
query = bytes.fromhex(
    "1234" +      # ID
    "0100" +      # flags (standard question)
    "0001" +      # 1 question
    "0000" +      # 0 answers
    "0000" +      # 0 authority records
    "0000" +      # 0 additional records
    "0669697472616d" +  # 6 "iitram"
    "026163" +           # 2 "ac"
    "02696e" +           # 2 "in"
    "00" +               # end of name
    "0001" +              # type A (IPv4 address)
    "0001"                # class IN (internet)
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(query, ('127.0.0.1', 5053))

print("Sent test DNS query for iitram.ac.in")