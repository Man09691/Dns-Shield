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
    def __init__(self, max_size=None, min_ttl=60, max_ttl=3600):
        global _shared_cache_instance
        _shared_cache_instance = self
        if max_size is None or str(max_size).strip().lower() == "auto":
            max_size = get_default_cache_size()
        else:
            try:
                max_size = int(max_size)
            except (ValueError, TypeError):
                max_size = get_default_cache_size()
        self.max_size = max_size
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.stale_ttl = 60  # SERVE-STALE SIMPLE: Keep expired entries for 60s extra as stale
        self.entries = OrderedDict()
        self.hits = 0
        self.misses = 0
        self.negative_hits = 0
        self.expired = 0
        self.lock = threading.Lock()
        self.pinned_domains = set()
        self.prefetch_handler = None
        self._prefetch_in_flight = {}
        try:
            from dns.watchlist import watchlist_manager
            self.pinned_domains = set(watchlist_manager.get_domains())
        except Exception:
            pass

    def _is_pinned(self, domain: str) -> bool:
        """Check if domain or its www variant is in pinned domains."""
        if not domain or not self.pinned_domains:
            return False
        d = domain.rstrip(".").lower()
        if d in self.pinned_domains:
            return True
        if d.startswith("www.") and d[4:] in self.pinned_domains:
            return True
        return False

    def add_pinned(self, domain: str):
        """Add domain to pinned set (never evicted, serve-stale enabled)."""
        if not domain:
            return
        with self.lock:
            self.pinned_domains.add(domain.rstrip(".").lower())

    def remove_pinned(self, domain: str):
        """Remove domain from pinned set and evict associated entries."""
        if not domain:
            return
        d = domain.rstrip(".").lower()
        with self.lock:
            self.pinned_domains.discard(d)
            keys_to_remove = [k for k in self.entries if k[0] == d or (k[0].startswith("www.") and k[0][4:] == d)]
            for k in keys_to_remove:
                del self.entries[k]

    def set_pinned_domains(self, domains):
        """Update pinned domains set."""
        with self.lock:
            self.pinned_domains = {d.rstrip(".").lower() for d in domains}

    def set_prefetch_handler(self, handler):
        """Register callback for background prefetching: handler(domain, qtype, qclass)."""
        self.prefetch_handler = handler

    def _trigger_prefetch(self, domain: str, qtype: int = 1, qclass: int = 1):
        """
        PREFETCH SIMPLE:
        For Watchlist domains ONLY, 60 sec before expiry, fetch A, AAAA, HTTPS all 3 together in background.
        User query must NOT wait for prefetch.
        """
        if not self.prefetch_handler:
            return
        clean_d = domain.rstrip(".").lower()
        if not self._is_pinned(clean_d):
            return

        now = time.time()
        last_req = self._prefetch_in_flight.get(clean_d, 0.0)
        if now - last_req < 10.0:
            return
        self._prefetch_in_flight[clean_d] = now

        def _worker(d=clean_d):
            try:
                import inspect
                sig = inspect.signature(self.prefetch_handler)
                if len(sig.parameters) >= 2:
                    self.prefetch_handler(d, (1, 28, 65))
                else:
                    self.prefetch_handler(d)
            except Exception as e:
                logger.debug(f"Background prefetch failed for {d}: {e}")

        t = threading.Thread(target=_worker, daemon=True, name=f"prefetch-{clean_d}")
        t.start()

    def _is_nxdomain(self, response_bytes):
        """Check if response packet RCODE is 3 (NXDOMAIN)."""
        if not response_bytes or len(response_bytes) < 4:
            return False
        # Byte 3 lower 4 bits are RCODE
        return (response_bytes[3] & 0x0F) == 3

    def get(self, domain, qtype, qclass=1):
        """
        Lookup response in cache.
        Returns: (response_bytes, remaining_ttl) if found and fresh (remaining > 0),
                 otherwise (None, 0).
        Cache key: (domain_lower, qtype, qclass)
        PREFETCH SIMPLE:
          - For Watchlist domains ONLY, triggers background prefetch of A, AAAA, HTTPS together
            if remaining TTL <= 60s. User query does NOT wait.
        """
        domain_lower = domain.rstrip(".").lower()
        key = (domain_lower, int(qtype), int(qclass))
        is_pinned_domain = self._is_pinned(domain)
        with self.lock:
            if key in self.entries:
                response_bytes, expiry_time, original_ttl = self.entries[key]
                now = time.time()
                remaining = expiry_time - now
                if remaining > 0:
                    self.hits += 1
                    self.entries.move_to_end(key)
                    if self._is_nxdomain(response_bytes):
                        self.negative_hits += 1
                    # PREFETCH SIMPLE: For Watchlist domains ONLY, 60 sec before expiry, fetch A, AAAA, HTTPS together in background
                    if is_pinned_domain and remaining <= 60:
                        self._trigger_prefetch(domain, qtype, qclass)
                    return response_bytes, remaining
                else:
                    # Expired entry: evict only if older than 60s stale window
                    if now >= expiry_time + self.stale_ttl:
                        del self.entries[key]
                        self.expired += 1
            self.misses += 1
            return None, 0

    def get_stale(self, domain, qtype, qclass=1):
        """
        SERVE-STALE SIMPLE:
        When cache entry expires, keep it for 60 sec extra as stale.
        Returns response_bytes if entry is within 60s stale window (now < expiry_time + 60).
        Otherwise returns None.
        """
        domain_lower = domain.rstrip(".").lower()
        key = (domain_lower, int(qtype), int(qclass))
        now = time.time()
        with self.lock:
            if key in self.entries:
                response_bytes, expiry_time, _ = self.entries[key]
                if now < expiry_time + self.stale_ttl:
                    return response_bytes
                else:
                    del self.entries[key]
                    self.expired += 1
            return None

    def put(self, domain, qtype, response_bytes, ttl, qclass=1):
        """Store response in cache with LRU eviction and per-entry TTL."""
        domain_lower = domain.rstrip(".").lower()
        key = (domain_lower, int(qtype), int(qclass))

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
        try:
            from dns.stats import stats
            stats.set_meta(cache_size=len(self.entries), cache_live=len(self.entries), cache_expired=self.expired)
        except Exception:
            pass

    def _evict_oldest(self):
        """Evicts the least recently used non-pinned entry."""
        if not self.entries:
            return
        for key in list(self.entries.keys()):
            domain = key[0]
            if not self._is_pinned(domain):
                del self.entries[key]
                return
        # Fallback if all entries in cache are pinned
        self.entries.popitem(last=False)

    def clear(self):
        """Clear all cache entries."""
        with self.lock:
            self.entries.clear()
            logger.info("Cache cleared")
        try:
            from dns.stats import stats
            stats.set_meta(cache_size=0, cache_live=0, cache_expired=self.expired)
        except Exception:
            pass

    def cleanup_expired(self):
        """Evict all dead entries (expired by more than 60s stale window) from cache."""
        now = time.time()
        with self.lock:
            expired_keys = [
                k for k, (_, expiry, _) in self.entries.items()
                if now >= expiry + self.stale_ttl and not self._is_pinned(k[0])
            ]
            for k in expired_keys:
                del self.entries[k]
            self.expired += len(expired_keys)
        try:
            from dns.stats import stats
            stats.set_meta(cache_size=len(self.entries), cache_live=len(self.entries), cache_expired=self.expired)
        except Exception:
            pass

    def get_stats(self):
        """Return cache statistics including live, hits, misses, expired, ratio."""
        with self.lock:
            now = time.time()
            live = sum(1 for _, expiry, _ in self.entries.values() if expiry > now)
            forwarded = self.misses
            total = self.hits + forwarded
            ratio = round(self.hits / total, 4) if total > 0 else 0.0
            return {
                "live": live,
                "hits": self.hits,
                "misses": self.misses,
                "expired": self.expired,
                "ratio": ratio,
                "entries": len(self.entries),
                "max_size": self.max_size,
                "negative_hits": self.negative_hits,
                "hit_rate": round(ratio * 100, 1),
            }

    def set_max_size(self, new_size):
        """
        Update maximum cache capacity.
        Handles 'auto', evicts oldest LRU entries if current count > new_size.
        """
        if new_size is None or str(new_size).strip().lower() == "auto":
            target_size = get_default_cache_size()
        else:
            try:
                target_size = int(new_size)
            except (ValueError, TypeError):
                target_size = get_default_cache_size()

        with self.lock:
            self.max_size = target_size
            evicted_count = 0
            while self.max_size >= 0 and len(self.entries) > self.max_size and self.entries:
                self._evict_oldest()
                evicted_count += 1
            if evicted_count > 0:
                logger.info(f"Evicted {evicted_count} cache entries after shrinking max_size to {self.max_size}")

        try:
            from dns.stats import stats
            stats.set_meta(cache_size=len(self.entries), cache_max_size=self.max_size)
        except Exception:
            pass

        return self.max_size

    def get_entries(self):
        """Return list of active cache entries."""
        now = time.time()
        result = []
        with self.lock:
            for key, (_, expiry, original_ttl) in self.entries.items():
                domain = key[0]
                qtype = key[1]
                qclass = key[2] if len(key) > 2 else 1
                remaining = max(0.0, expiry - now)
                result.append({
                    "domain": domain,
                    "qtype": qtype,
                    "qclass": qclass,
                    "remaining_ttl": round(remaining, 1),
                    "original_ttl": original_ttl,
                })
        return result


def get_system_ram_gb():
    """
    Detect physical system RAM in gigabytes across Windows, Linux, and macOS.
    Defaults to 8.0 GB if detection is unavailable.
    """
    try:
        import psutil
        return round(psutil.virtual_memory().total / (1024 ** 3), 2)
    except Exception:
        pass

    try:
        # Windows GlobalMemoryStatusEx
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            return round(stat.ullTotalPhys / (1024 ** 3), 2)
    except Exception:
        pass

    try:
        # POSIX sysconf
        import os
        pages = os.sysconf("SC_PHYS_PAGES")
        page_size = os.sysconf("SC_PAGE_SIZE")
        return round((pages * page_size) / (1024 ** 3), 2)
    except Exception:
        pass

    return 8.0


def get_default_cache_size(ram_gb=None):
    """
    Return default cache size based on available system RAM:
      - < 4GB  : 1000
      - 6-8GB  : 5000 (user system has ~7GB / 7.75GB)
      - > 8GB  : 10000
    Logs "[CACHE] Auto-selected 5000 for 7.75GB"
    """
    if ram_gb is None:
        ram_gb = get_system_ram_gb()

    if ram_gb < 4.0:
        size = 1000
    elif ram_gb > 8.0:
        size = 10000
    else:
        # 4.0 <= ram_gb <= 8.0 (6-8GB bracket, user system has ~7.75GB)
        size = 5000

    log_msg = f"[CACHE] Auto-selected {size} for {ram_gb}GB"
    logger.info(log_msg)
    print(log_msg)
    return size


def get_cache_warning(new_size):
    """
    Return a warning dictionary if new_size > 5000.
    None if <=5000 else dict with level, title, msg about O(1) not slow, memory 2.5MB->5MB.
    """
    try:
        size_int = int(new_size)
    except (ValueError, TypeError):
        return None

    if size_int > 5000:
        mem_mb = round((size_int / 5000.0) * 2.5, 1)
        msg = f"Cache lookup is O(1) so not slow, memory increases from 2.5MB to {mem_mb}MB, stale risk."
        return {
            "warning": True,
            "level": "warning",
            "title": "Large Cache Size Warning",
            "size": size_int,
            "message": msg,
            "msg": msg,
            "detailed_message": (
                f"DNS cache lookup remains O(1) in-memory hash table time (not slow), "
                f"but memory footprint increases from ~2.5MB to ~{mem_mb}MB. "
                f"Higher cache capacities also increase the risk of retaining stale DNS records "
                f"if upstream IP mappings change before cached TTL expiration."
            ),
            "revert_size": 5000,
        }
    return None


_shared_cache_instance = None


def get_cache_instance():
    """Return shared global DNSCache instance."""
    global _shared_cache_instance
    if _shared_cache_instance is None:
        _shared_cache_instance = DNSCache(max_size=get_default_cache_size())
    return _shared_cache_instance
def get_auto_cache_size():
    return get_default_cache_size()

# Alias for backward compatibility
get_auto_cache_size = get_auto_cache_size