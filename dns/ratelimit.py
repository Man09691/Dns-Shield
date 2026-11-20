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
    def __init__(self, max_queries=50, window_seconds=10, block_seconds=30, localhost_max_queries=300, domain_burst_limit=50):
        self.max_queries = max_queries
        self.localhost_max_queries = localhost_max_queries
        self.domain_burst_limit = domain_burst_limit
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds

        # ip -> deque[timestamps]  O(1) popleft
        self.query_times = {}
        # ip -> expiry epoch
        self.blocked_clients = {}

        # (ip, domain) -> deque[timestamps] for per-domain burst protection
        self.domain_query_times = {}
        # (ip, domain) -> expiry epoch
        self.blocked_domain_clients = {}

        self.lock = threading.Lock()

    def is_rate_limited(self, client_ip, domain=None):
        now = time.time()
        is_localhost = client_ip in ("127.0.0.1", "::1", "localhost")
        effective_limit = self.localhost_max_queries if is_localhost else self.max_queries

        with self.lock:
            # ── 1. Per-Domain Burst Protection ──
            # A single flooding domain (e.g. beacons.gvt2.com) is throttled individually
            # so it cannot block legitimate domains (e.g. www.google.com).
            if domain:
                clean_domain = domain.rstrip(".").lower()
                dom_key = (client_ip, clean_domain)

                # Check if this specific domain is blocked for this client
                dom_expiry = self.blocked_domain_clients.get(dom_key)
                if dom_expiry is not None:
                    if now < dom_expiry:
                        return True
                    del self.blocked_domain_clients[dom_key]
                    self.domain_query_times.pop(dom_key, None)

                # Check domain-level sliding window
                dom_dq = self.domain_query_times.get(dom_key)
                if dom_dq is None:
                    dom_dq = collections.deque()
                    self.domain_query_times[dom_key] = dom_dq

                cutoff = now - self.window_seconds
                while dom_dq and dom_dq[0] <= cutoff:
                    dom_dq.popleft()

                dom_limit = self.domain_burst_limit if is_localhost else min(self.domain_burst_limit, self.max_queries)
                if len(dom_dq) >= dom_limit:
                    self.blocked_domain_clients[dom_key] = now + self.block_seconds
                    logger.warning(
                        f"Domain burst limit {client_ip} -> {clean_domain}: {len(dom_dq)} in {self.window_seconds}s -> block {self.block_seconds}s"
                    )
                    return True

            # ── 2. Per-IP Rate Limiting ──
            # Check if whole client IP is blocked
            expiry = self.blocked_clients.get(client_ip)
            if expiry is not None:
                if now < expiry:
                    return True
                del self.blocked_clients[client_ip]
                self.query_times.pop(client_ip, None)

            dq = self.query_times.get(client_ip)
            if dq is None:
                dq = collections.deque()
                self.query_times[client_ip] = dq

            cutoff = now - self.window_seconds
            while dq and dq[0] <= cutoff:
                dq.popleft()

            if len(dq) >= effective_limit:
                self.blocked_clients[client_ip] = now + self.block_seconds
                logger.warning(
                    f"Rate limit {client_ip}: {len(dq)} in {self.window_seconds}s (limit {effective_limit}) -> block {self.block_seconds}s"
                )
                return True

            # Record timestamp for IP and domain
            dq.append(now)
            if domain:
                dom_dq.append(now)

            # Auto cleanup stale entries
            if len(self.query_times) > 5000 or len(self.domain_query_times) > 10000:
                self._cleanup_stale(now)

            return False

    def _cleanup_stale(self, now):
        stale_cutoff = now - (self.window_seconds * 10)
        for ip in list(self.query_times.keys()):
            dq = self.query_times[ip]
            if not dq or dq[-1] < stale_cutoff:
                del self.query_times[ip]
        for key in list(self.domain_query_times.keys()):
            dq = self.domain_query_times[key]
            if not dq or dq[-1] < stale_cutoff:
                del self.domain_query_times[key]

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