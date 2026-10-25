import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import time
import unittest
from dns.ratelimit import RateLimiter

class TestRateLimiter(unittest.TestCase):
    def test_under_limit(self):
        rl = RateLimiter(max_queries=5, window_seconds=10, block_seconds=10)
        ip = "192.168.1.1"
        for i in range(5):
            self.assertFalse(rl.is_rate_limited(ip))
        print("5 query tak OK")

    def test_over_limit_block(self):
        rl = RateLimiter(max_queries=5, window_seconds=10, block_seconds=10)
        ip = "192.168.1.2"
        for _ in range(5):
            rl.is_rate_limited(ip)
        self.assertTrue(rl.is_rate_limited(ip))
        print("6th query pe BLOCK - pass")

    def test_different_ip(self):
        rl = RateLimiter(max_queries=2, window_seconds=10, block_seconds=10)
        rl.is_rate_limited("1.1.1.1")
        rl.is_rate_limited("1.1.1.1")
        self.assertTrue(rl.is_rate_limited("1.1.1.1"))
        self.assertFalse(rl.is_rate_limited("2.2.2.2"))
        print("Different IP independent - pass")

    def test_block_expires(self):
        # yaha max=1 rakha hai - 1 allow, 2nd block
        rl = RateLimiter(max_queries=1, window_seconds=10, block_seconds=1)
        ip = "10.0.0.1"
        self.assertFalse(rl.is_rate_limited(ip)) # 1st OK
        self.assertTrue(rl.is_rate_limited(ip)) # 2nd BLOCK
        print("Blocked, 1.2 sec wait...")
        time.sleep(1.2)
        self.assertFalse(rl.is_rate_limited(ip))
        print("Block expire - pass")

    def test_sliding_window(self):
        # window=1 aur block bhi=1, taaki dono 1 sec me khatam ho
        rl = RateLimiter(max_queries=2, window_seconds=1, block_seconds=1)
        ip = "10.0.0.2"
        rl.is_rate_limited(ip)
        rl.is_rate_limited(ip)
        self.assertTrue(rl.is_rate_limited(ip))
        print("Window full, 1.1 sec wait...")
        time.sleep(1.1)
        self.assertFalse(rl.is_rate_limited(ip))
        print("Sliding window - pass")

    def test_get_blocked_clients(self):
        rl = RateLimiter(max_queries=1, window_seconds=10, block_seconds=10)
        rl.is_rate_limited("5.5.5.5")
        rl.is_rate_limited("5.5.5.5")
        blocked = rl.get_blocked_clients()
        self.assertEqual(len(blocked), 1)
        print(f"Blocked list OK - pass")

if __name__ == "__main__":
    unittest.main(verbosity=2)