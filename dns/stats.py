"""
dns/stats.py  —  Query Statistics and SQLite Logger
=====================================================
Computer Networks concept: Network monitoring and logging.

Tracks every DNS query in two places:
  1. An in-memory counter (for fast dashboard access)
  2. A SQLite database (for persistent query history)

Stats tracked:
  - Total queries, blocked count, cached count, forwarded count
  - Per-domain counts (top domains, top blocked)
  - Per-client counts
  - Latency measurements (cached vs forwarded)
  - Queries-per-minute over time
"""

import time
import sqlite3
import threading
import logging
from collections import defaultdict

logger = logging.getLogger("dns.stats")


class Stats:
    """
    Query statistics tracker with SQLite persistence.
    All methods are thread-safe.
    """

    def __init__(self, db_file="queries.db"):
        self.db_file = db_file
        self.lock = threading.Lock()
        self.start_time = time.time()

        # In-memory counters (fast access for dashboard)
        self.total_queries = 0
        self.blocked_count = 0
        self.cached_count = 0
        self.forwarded_count = 0
        self.rate_limited_count = 0
        self.timeout_count = 0

        # Per-domain and per-client counters
        self.domain_counts = defaultdict(int)
        self.blocked_domain_counts = defaultdict(int)
        self.client_counts = defaultdict(int)

        # Latency tracking
        self.cached_latencies = []     # list of ms values
        self.forwarded_latencies = []  # list of ms values

        # Queries per minute (for time-series chart)
        # Each entry: (timestamp, count_in_that_minute)
        self.qpm_buckets = defaultdict(int)  # minute_timestamp -> count

        # Recent queries (for live table, keep last 100)
        self.recent_queries = []

        # Initialize the SQLite database
        self._init_db()

    def _init_db(self):
        """Create the queries table if it doesn't exist."""
        try:
            conn = sqlite3.connect(self.db_file)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS queries (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   REAL,
                    client_ip   TEXT,
                    domain      TEXT,
                    qtype       INTEGER,
                    action      TEXT,
                    category    TEXT,
                    response_ms REAL,
                    answer_ip   TEXT
                )
            """)
            # Index for faster dashboard queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON queries(timestamp)
            """)
            conn.commit()
            conn.close()
            logger.info(f"Query database initialized: {self.db_file}")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")

    def log_query(self, client_ip, domain, qtype, action, category=None,
                  response_ms=0, answer_ip=None):
        """
        Log a single DNS query to memory and SQLite.

        Parameters:
          client_ip:    IP of the client that sent the query
          domain:       the queried domain name
          qtype:        query type (1=A, 28=AAAA, etc.)
          action:       one of: BLOCKED, CACHED, FORWARDED, RATE_LIMITED, TIMEOUT
          category:     blocklist category (if blocked)
          response_ms:  how long the response took in milliseconds
          answer_ip:    the IP address(es) in the response
        """
        now = time.time()

        with self.lock:
            # Update in-memory counters
            self.total_queries += 1
            self.domain_counts[domain] += 1
            self.client_counts[client_ip] += 1

            if action == "BLOCKED":
                self.blocked_count += 1
                self.blocked_domain_counts[domain] += 1
            elif action == "CACHED":
                self.cached_count += 1
                self.cached_latencies.append(response_ms)
            elif action == "FORWARDED":
                self.forwarded_count += 1
                self.forwarded_latencies.append(response_ms)
            elif action == "RATE_LIMITED":
                self.rate_limited_count += 1
            elif action == "TIMEOUT":
                self.timeout_count += 1

            # Track queries per minute
            minute_bucket = int(now // 60) * 60  # round down to minute
            self.qpm_buckets[minute_bucket] += 1

            # Add to recent queries (keep last 100)
            entry = {
                "timestamp": now,
                "client_ip": client_ip,
                "domain": domain,
                "qtype": qtype,
                "action": action,
                "category": category or "",
                "response_ms": round(response_ms, 2),
                "answer_ip": answer_ip or "",
            }
            self.recent_queries.append(entry)
            if len(self.recent_queries) > 100:
                self.recent_queries = self.recent_queries[-100:]

        # Write to SQLite (outside the lock to avoid blocking)
        try:
            conn = sqlite3.connect(self.db_file)
            conn.execute(
                "INSERT INTO queries (timestamp, client_ip, domain, qtype, "
                "action, category, response_ms, answer_ip) VALUES (?,?,?,?,?,?,?,?)",
                (now, client_ip, domain, qtype, action, category or "",
                 round(response_ms, 2), answer_ip or "")
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to write query to database: {e}")

    def get_summary(self):
        """Return a summary dict for the dashboard."""
        with self.lock:
            total = self.total_queries
            blocked_pct = (self.blocked_count / total * 100) if total > 0 else 0

            cache_total = len(self.cached_latencies) + len(self.forwarded_latencies)
            # Note: cache hit rate is hits out of (hits + forwarded), not total
            cache_lookups = self.cached_count + self.forwarded_count
            cache_hit_rate = (self.cached_count / cache_lookups * 100) if cache_lookups > 0 else 0

            avg_cached_ms = (
                sum(self.cached_latencies) / len(self.cached_latencies)
                if self.cached_latencies else 0
            )
            avg_forwarded_ms = (
                sum(self.forwarded_latencies) / len(self.forwarded_latencies)
                if self.forwarded_latencies else 0
            )

            uptime = time.time() - self.start_time

            return {
                "total_queries": total,
                "blocked_count": self.blocked_count,
                "blocked_pct": round(blocked_pct, 1),
                "cached_count": self.cached_count,
                "forwarded_count": self.forwarded_count,
                "rate_limited_count": self.rate_limited_count,
                "timeout_count": self.timeout_count,
                "cache_hit_rate": round(cache_hit_rate, 1),
                "avg_cached_ms": round(avg_cached_ms, 2),
                "avg_forwarded_ms": round(avg_forwarded_ms, 2),
                "uptime_seconds": round(uptime, 0),
                "active_clients": len(self.client_counts),
            }

    def get_recent_queries(self, limit=50):
        """Return the last N queries (for the live table)."""
        with self.lock:
            return list(reversed(self.recent_queries[-limit:]))

    def get_top_domains(self, limit=10):
        """Return the top N queried domains."""
        with self.lock:
            sorted_domains = sorted(
                self.domain_counts.items(), key=lambda x: x[1], reverse=True
            )
            return [{"domain": d, "count": c} for d, c in sorted_domains[:limit]]

    def get_top_blocked(self, limit=10):
        """Return the top N blocked domains."""
        with self.lock:
            sorted_domains = sorted(
                self.blocked_domain_counts.items(), key=lambda x: x[1], reverse=True
            )
            return [{"domain": d, "count": c} for d, c in sorted_domains[:limit]]

    def get_top_clients(self, limit=10):
        """Return the top N clients by query count."""
        with self.lock:
            sorted_clients = sorted(
                self.client_counts.items(), key=lambda x: x[1], reverse=True
            )
            return [{"client": c, "count": n} for c, n in sorted_clients[:limit]]

    def get_qpm_series(self, minutes=30):
        """
        Return queries-per-minute for the last N minutes.
        Used for the time-series chart on the dashboard.
        """
        now = time.time()
        current_minute = int(now // 60) * 60
        result = []

        with self.lock:
            for i in range(minutes, -1, -1):
                minute_ts = current_minute - (i * 60)
                count = self.qpm_buckets.get(minute_ts, 0)
                result.append({
                    "time": minute_ts,
                    "count": count,
                })

        return result
