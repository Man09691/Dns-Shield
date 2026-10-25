"""
dns/cache.py  —  DNS Response Cache (True LRU + Negative Cache)
===============================================================
Computer Networks concept: Caching to reduce latency and upstream traffic.

When we get a response from the upstream DNS server, we store it so that
the next time someone asks for the same domain, we can answer instantly
from the cache instead of asking upstream again.

Features:
  - Cache key: (lowercased domain name without trailing dot, query type)
  - Cache value: (raw response bytes, expiry timestamp, original TTL)
  - True LRU eviction using collections.OrderedDict with move_to_end
  - Negative Caching for NXDOMAIN responses (RFC 2308) with negative_hits counter
  - Full thread-safety protected by a threading.Lock
"""

import time
import threading
import logging
from collections import OrderedDict

logger = logging.getLogger("dns.cache")


class DNSCache:
    def __init__(self, max_size=1024, min_ttl=60, max_ttl=3600):
        self.max_size = max_size
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.entries = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.negative_hits = 0
        self.lock = threading.Lock()

    def _is_nxdomain(self, response_bytes):
        """Check if response packet RCODE is 3 (NXDOMAIN)."""
        if not response_bytes or len(response_bytes) < 4:
            return False
        # Byte 3 lower 4 bits are RCODE
        return (response_bytes[3] & 0x0F) == 3

    def get(self, domain, qtype):
        """
        Lookup response in cache.
        Returns: (response_bytes, remaining_ttl) if found and not expired,
                 otherwise (None, 0).
        """
        key = (domain.rstrip(".").lower(), qtype)
        with self.lock:
            if key in self.entries:
                response_bytes, expiry_time, original_ttl = self.entries[key]
                remaining = expiry_time - time.time()
                if remaining > 0:
                    self.hits += 1
                    self.entries.move_to_end(key)
                    if self._is_nxdomain(response_bytes):
                        self.negative_hits += 1
                    return response_bytes, remaining
                else:
                    # Expired entry
                    del self.entries[key]
            self.misses += 1
            return None, 0

    def put(self, domain, qtype, response_bytes, ttl):
        """Store response in cache with LRU eviction."""
        key = (domain.rstrip(".").lower(), qtype)

        # Negative cache cap (RFC 2308 recommends capping negative caching)
        if self._is_nxdomain(response_bytes):
            ttl = min(ttl, 300)

        ttl = max(self.min_ttl, min(self.max_ttl, ttl))
        expiry_time = time.time() + ttl

        with self.lock:
            if self.max_size <= 0:
                return

            if key in self.entries:
                self.entries[key] = (response_bytes, expiry_time, ttl)
                self.entries.move_to_end(key)
            else:
                while len(self.entries) >= self.max_size and self.entries:
                    self._evict_oldest()
                self.entries[key] = (response_bytes, expiry_time, ttl)

    def _evict_oldest(self):
        """Evicts the least recently used entry (first in OrderedDict)."""
        if not self.entries:
            return
        self.entries.popitem(last=False)

    def clear(self):
        """Clear all cache entries."""
        with self.lock:
            self.entries.clear()
            logger.info("Cache cleared")

    def cleanup_expired(self):
        """Evict all expired entries from cache."""
        now = time.time()
        with self.lock:
            expired_keys = [k for k, (_, expiry, _) in self.entries.items() if expiry <= now]
            for k in expired_keys:
                del self.entries[k]

    def get_stats(self):
        """Return cache statistics including hits, misses, negative_hits, hit_rate."""
        with self.lock:
            total = self.hits + self.misses
            hit_rate = (self.hits / total * 100) if total > 0 else 0.0
            return {
                "entries": len(self.entries),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "negative_hits": self.negative_hits,
                "hit_rate": round(hit_rate, 1),
            }

    def get_entries(self):
        """Return list of active cache entries."""
        now = time.time()
        result = []
        with self.lock:
            for (domain, qtype), (_, expiry, original_ttl) in self.entries.items():
                remaining = max(0.0, expiry - now)
                result.append({
                    "domain": domain,
                    "qtype": qtype,
                    "remaining_ttl": round(remaining, 1),
                    "original_ttl": original_ttl,
                })
        return result