import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
import struct
import unittest
from dns.forwarder import forward_query

def build_query(domain, qtype=1):
    """google.com ke liye raw DNS packet banata hai"""
    # Header: ID 0x1234, flags 0x0100, QD=1
    header = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
    # QNAME
    qname = b''.join(struct.pack('B', len(p)) + p.encode() for p in domain.split('.')) + b'\x00'
    question = qname + struct.pack('!HH', qtype, 1)
    return header + question

class TestForwarder(unittest.TestCase):
    def test_google(self):
        pkt = build_query("google.com")
        start = time.time()
        resp = forward_query(pkt, timeout=3)
        elapsed = (time.time() - start)*1000
        self.assertIsNotNone(resp, "8.8.8.8 / 1.1.1.1 dono fail")
        print(f"\ngoogle.com -> {elapsed:.1f}ms (winner should be ~20-90ms) resp_len={len(resp)}")
        self.assertTrue(len(resp) > 12)

    def test_example(self):
        pkt = build_query("example.com")
        resp = forward_query(pkt, timeout=3)
        self.assertIsNotNone(resp)
        print(f"example.com -> OK len={len(resp)}")

    def test_parallel_fast(self):
        """Parallel race ka test - 500ms se kam me aana chahiye"""
        pkt = build_query("cloudflare.com")
        start = time.time()
        resp = forward_query(pkt, timeout=3)
        elapsed = (time.time() - start)*1000
        self.assertIsNotNone(resp)
        print(f"cloudflare.com parallel -> {elapsed:.1f}ms")
        self.assertLess(elapsed, 500, "500ms se zyada matlab parallel kaam nahi kar raha")

    def test_extra_upstream(self):
        pkt = build_query("example.com")
        resp = forward_query(pkt, extra_upstreams=["9.9.9.9"], timeout=3)
        self.assertIsNotNone(resp)
        print(f"with 9.9.9.9 extra -> OK")

if __name__ == "__main__":
    unittest.main(verbosity=2)