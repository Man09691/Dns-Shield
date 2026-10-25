"""
dns/ratelimit.py  —  Per-Client Rate Limiter
=============================================
Computer Networks concept: Rate limiting / DDoS protection.

Prevents any single client IP from overwhelming the DNS server by
limiting how many queries they can send in a time window.

Uses a sliding window approach:
  - Track timestamps of recent queries per client IP.
  - If a client exceeds the limit, block them temporarily.
"""
"""
dns/ratelimit.py  —  Perfect Per-Client Rate Limiter
O(1) sliding window with deque + auto cleanup
"""

import time
import threading
import logging
import collections

logger = logging.getLogger("dns.ratelimit")

class RateLimiter:
    def __init__(self, max_queries=50, window_seconds=10, block_seconds=30):
        self.max_queries = max_queries
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds

        # ip -> deque[timestamps]  O(1) popleft
        self.query_times = {}
        # ip -> expiry epoch
        self.blocked_clients = {}
        self.lock = threading.Lock()

    def is_rate_limited(self, client_ip):
        now = time.time()
        with self.lock:
            # 1. blocked hai kya?
            expiry = self.blocked_clients.get(client_ip)
            if expiry is not None:
                if now < expiry:
                    return True
                # block khatam
                del self.blocked_clients[client_ip]
                self.query_times.pop(client_ip, None)

            # 2. deque lao ya banao
            dq = self.query_times.get(client_ip)
            if dq is None:
                dq = collections.deque()
                self.query_times[client_ip] = dq

            # 3. purane timestamp nikalo - O(k) par amortized O(1)
            cutoff = now - self.window_seconds
            while dq and dq[0] <= cutoff:
                dq.popleft()

            # 4. limit check - pehle check phir append
            if len(dq) >= self.max_queries:
                self.blocked_clients[client_ip] = now + self.block_seconds
                logger.warning(
                    f"Rate limit {client_ip}: {len(dq)} in {self.window_seconds}s -> block {self.block_seconds}s"
                )
                return True

            dq.append(now)

            # 5. auto cleanup - agar client 5 min se inactive toh nikal do
            if len(self.query_times) > 5000:
                self._cleanup_stale(now)

            return False

    def _cleanup_stale(self, now):
        # bina lock ke call mat karna, andar se lock already hai
        stale_cutoff = now - (self.window_seconds * 10)
        for ip in list(self.query_times.keys()):
            dq = self.query_times[ip]
            if not dq or dq[-1] < stale_cutoff:
                del self.query_times[ip]

    def get_blocked_clients(self):
        now = time.time()
        result = []
        with self.lock:
            for ip, expiry in list(self.blocked_clients.items()):
                if now < expiry:
                    result.append({
                        "ip": ip,
                        "blocked_until": expiry,
                        "remaining_seconds": round(expiry - now, 1),
                    })
                else:
                    del self.blocked_clients[ip]
                    self.query_times.pop(ip, None)
        return result

    def get_stats(self):
        with self.lock:
            active = sum(1 for dq in self.query_times.values() if dq)
            return {
                "active_clients": active,
                "blocked_clients": len(self.blocked_clients),
                "max_queries": self.max_queries,
                "window_seconds": self.window_seconds,
                "block_seconds": self.block_seconds,
            }