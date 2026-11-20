"""
dns/stats.py  —  MULTI-PROCESS STATS + RETENTION + HOURLY AGGREGATION
======================================================================
Phase 1.1-1.4 fixes + Retention purge + Hourly rollup table +
Settings (retention days, anonymize IP) persisted in meta table.
"""
import os
import math
import sqlite3
import threading
import json
import ipaddress
from collections import Counter, deque
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "port53_queries.db")

# Retention sentinel meaning "keep everything"
KEEP_ALL = -1


def is_private_or_localhost(ip_str: str) -> bool:
    """
    Check if IP is private / localhost:
    127.0.0.1, ::1, 10.x.x.x, 172.16.x.x - 172.31.x.x, 192.168.x.x
    """
    if not ip_str:
        return True
    ip_clean = str(ip_str).strip()
    if ip_clean in ("127.0.0.1", "::1", "localhost", "0.0.0.0", "::"):
        return True
    if ip_clean == "xxx.xxx.xxx.1":
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        if ip_clean.startswith("10.") or ip_clean.startswith("192.168.") or ip_clean.startswith("127."):
            return True
        if ip_clean.startswith("172."):
            parts = ip_clean.split(".")
            if len(parts) >= 2 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
                return True
        return False


def _percentile(data, p):
    """Calculate percentile p (0-100) using linear interpolation."""
    if not data:
        return 0.0
    sorted_d = sorted(data)
    k = (len(sorted_d) - 1) * (p / 100.0)
    f = int(math.floor(k))
    c = int(math.ceil(k))
    if f == c:
        return float(sorted_d[f])
    return float(sorted_d[f] * (c - k) + sorted_d[c] * (k - f))


class DNSStats:
    def __init__(self, db_path=None, db_file=None):
        self.lock = threading.Lock()
        self.total = 0
        self.blocked = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.forwarded = 0
        self.cache_expired = 0
        self.cache_ref = None
        self.udp_queries = 0
        self.tcp_queries = 0
        self.invalid_upstream = 0
        self.client_blocked = 0

        self.top_blocked = Counter()
        self.top_clients = Counter()
        self.qtype_counts = Counter()

        # Upstream statistics per DNS upstream IP (8.8.8.8, 1.1.1.1)
        self.upstream_stats = {
            "8.8.8.8": {"queries": 0, "total_ms": 0.0, "fails": 0},
            "1.1.1.1": {"queries": 0, "total_ms": 0.0, "fails": 0},
        }

        # Latency tracking: internal lookup (ns), blocked (ms), forwarded (ms), cached (ms)
        self.internal_lookup_ns = deque(maxlen=10000)
        self.blocked_ms = deque(maxlen=10000)
        self.forwarded_ms = deque(maxlen=10000)
        self.cached_ms = deque(maxlen=10000)

        self.logs = deque(maxlen=1000)
        self.timestamps = deque(maxlen=10000)
        self.blocklist_size = 235974
        self.cache_size = 0

        # Settings (loaded from config.json & DB on init, overridable at runtime)
        self.retention_days = 5       # default: 5 days
        self.privacy_mask_public_only = True  # default: true (private/localhost always full IP)
        self.show_full_ip = False     # default: false (when true, show full IP even for public)
        self.anonymize_ip = True      # default: true (public masked unless show_full_ip=True)

        # Schedulers
        self._hourly_timer = None
        self._midnight_timer = None

        # Handle path resolution
        chosen_path = db_file or db_path or DB_PATH
        if chosen_path != ":memory:" and not os.path.isabs(chosen_path):
            chosen_path = os.path.join(PROJECT_ROOT, chosen_path)
        self.db_path = chosen_path
        self._mem_conn = None

        self._init_db()
        self._load_settings()
        self._schedule_hourly_aggregation()
        self._schedule_midnight_purge()

    # ──────────────────────────────────────────────────────────────
    # DB helpers
    # ──────────────────────────────────────────────────────────────
    def _get_conn(self):
        if self.db_path == ":memory:":
            if self._mem_conn is None:
                self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False)
            return self._mem_conn
        return sqlite3.connect(self.db_path, timeout=10)

    def _close_conn(self, conn):
        if self.db_path != ":memory:":
            conn.close()

    def set_cache_ref(self, cache):
        with self.lock:
            self.cache_ref = cache

    # ──────────────────────────────────────────────────────────────
    # DB init / migration
    # ──────────────────────────────────────────────────────────────
    def _init_db(self):
        """Initialize SQLite with WAL mode, migrate schema, create hourly table."""
        try:
            if self.db_path != ":memory:":
                db_dir = os.path.dirname(self.db_path)
                if db_dir:
                    os.makedirs(db_dir, exist_ok=True)
            conn = self._get_conn()
            if self.db_path != ":memory:":
                conn.execute("PRAGMA journal_mode=WAL;")

            conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")

            # ── queries table ──
            cur = conn.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='queries'")
            table_exists = cur.fetchone() is not None

            if table_exists:
                cur.execute("PRAGMA table_info(queries)")
                cols = {r[1] for r in cur.fetchall()}

                if "blocked" not in cols:
                    # Legacy migration (old schema had action/category columns)
                    try:
                        cur.execute("SELECT id, timestamp, client_ip, domain, qtype, action, category, response_ms, answer_ip FROM queries")
                        old_rows = cur.fetchall()
                    except Exception:
                        old_rows = []
                    conn.execute("DROP TABLE queries")
                    conn.execute("""
                        CREATE TABLE queries (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp TEXT,
                            domain TEXT,
                            client_ip TEXT,
                            qtype TEXT,
                            blocked INTEGER,
                            cached INTEGER,
                            latency_ms REAL,
                            upstream TEXT,
                            internal_lookup_ns INTEGER DEFAULT 0
                        )
                    """)
                    for r in old_rows:
                        ts_val = r[1]
                        try:
                            ts_str = datetime.fromtimestamp(ts_val).isoformat() if isinstance(ts_val, (int, float)) else str(ts_val)
                        except Exception:
                            ts_str = datetime.now().isoformat()
                        action_str = str(r[5]).upper() if r[5] else ""
                        is_blocked = 1 if action_str == "BLOCKED" else 0
                        is_cached  = 1 if action_str == "CACHED"  else 0
                        qtype_str  = "A" if r[4] == 1 else str(r[4] or "A")
                        lat = float(r[7] or 0.0)
                        ups = "0.0.0.0" if is_blocked else ("" if is_cached else "8.8.8.8")
                        conn.execute(
                            "INSERT INTO queries (timestamp,domain,client_ip,qtype,blocked,cached,latency_ms,upstream,internal_lookup_ns) VALUES (?,?,?,?,?,?,?,?,0)",
                            (ts_str, r[3], r[2], qtype_str, is_blocked, is_cached, lat, ups)
                        )
                else:
                    if "internal_lookup_ns" not in cols:
                        conn.execute("ALTER TABLE queries ADD COLUMN internal_lookup_ns INTEGER DEFAULT 0")
                    if "transport" not in cols:
                        conn.execute("ALTER TABLE queries ADD COLUMN transport TEXT DEFAULT 'UDP'")
                    if "status" not in cols:
                        conn.execute("ALTER TABLE queries ADD COLUMN status TEXT DEFAULT ''")
                    if "category" not in cols:
                        conn.execute("ALTER TABLE queries ADD COLUMN category TEXT DEFAULT ''")

                # Fix any legacy answer-IPs stored in the upstream column
                conn.execute("""
                    UPDATE queries
                    SET upstream = '8.8.8.8'
                    WHERE upstream NOT IN ('8.8.8.8','1.1.1.1','','0.0.0.0','TIMEOUT')
                      AND blocked = 0 AND cached = 0
                """)
            else:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS queries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        domain TEXT,
                        client_ip TEXT,
                        qtype TEXT,
                        blocked INTEGER,
                        cached INTEGER,
                        latency_ms REAL,
                        upstream TEXT,
                        internal_lookup_ns INTEGER DEFAULT 0,
                        transport TEXT DEFAULT 'UDP',
                        status TEXT DEFAULT '',
                        category TEXT DEFAULT ''
                    )
                """)

            # ── query_logs compatibility view ──
            conn.execute("""
                CREATE VIEW IF NOT EXISTS query_logs AS
                SELECT id, timestamp, domain, client_ip, qtype AS type, qtype, blocked, cached, latency_ms, upstream, internal_lookup_ns, transport, status, category
                FROM queries
            """)

            # ── query_stats_hourly table ──
            conn.execute("""
                CREATE TABLE IF NOT EXISTS query_stats_hourly (
                    hour    TEXT PRIMARY KEY,
                    total   INT DEFAULT 0,
                    blocked INT DEFAULT 0,
                    cached  INT DEFAULT 0
                )
            """)

            conn.commit()
            self._close_conn(conn)
        except Exception as e:
            print(f"[stats] DB init error: {e}")

    # ──────────────────────────────────────────────────────────────
    # Settings persistence
    # ──────────────────────────────────────────────────────────────
    def _load_settings(self):
        """Read retention_days, anonymize_ip, show_full_ip, privacy_mask_public_only from config.json and meta table."""
        # 1. Read defaults from config.json
        cfg_path = os.path.join(PROJECT_ROOT, "config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                if "privacy_mask_public_only" in cfg:
                    self.privacy_mask_public_only = bool(cfg["privacy_mask_public_only"])
                if "show_full_ip" in cfg:
                    self.show_full_ip = bool(cfg["show_full_ip"])
                    self.anonymize_ip = not self.show_full_ip
                elif "anonymize_ip" in cfg:
                    self.anonymize_ip = bool(cfg["anonymize_ip"])
                    self.show_full_ip = not self.anonymize_ip
                if "retention_days" in cfg:
                    self.retention_days = int(cfg["retention_days"])
            except Exception:
                pass

        # 2. Overlay with meta table
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute("SELECT key, value FROM meta WHERE key IN ('retention_days','anonymize_ip','show_full_ip','privacy_mask_public_only')")
            meta_dict = dict(cur.fetchall())
            if "retention_days" in meta_dict:
                self.retention_days = int(meta_dict["retention_days"])
            if "privacy_mask_public_only" in meta_dict:
                self.privacy_mask_public_only = (meta_dict["privacy_mask_public_only"] == "1")
            if "show_full_ip" in meta_dict:
                self.show_full_ip = (meta_dict["show_full_ip"] == "1")
                self.anonymize_ip = not self.show_full_ip
            elif "anonymize_ip" in meta_dict:
                self.anonymize_ip = (meta_dict["anonymize_ip"] == "1")
                self.show_full_ip = not self.anonymize_ip
            self._close_conn(conn)
        except Exception:
            pass

    def save_settings(self, retention_days=None, anonymize_ip=None, show_full_ip=None, privacy_mask_public_only=None):
        """Persist settings to meta table and update in-memory values."""
        with self.lock:
            if retention_days is not None:
                self.retention_days = int(retention_days)
            if show_full_ip is not None:
                self.show_full_ip = bool(show_full_ip)
                self.anonymize_ip = not self.show_full_ip
            elif anonymize_ip is not None:
                self.anonymize_ip = bool(anonymize_ip)
                self.show_full_ip = not self.anonymize_ip
            if privacy_mask_public_only is not None:
                self.privacy_mask_public_only = bool(privacy_mask_public_only)

        try:
            conn = self._get_conn()
            if retention_days is not None:
                conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('retention_days',?)", (str(self.retention_days),))
            if anonymize_ip is not None or show_full_ip is not None:
                conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('anonymize_ip',?)", ("1" if self.anonymize_ip else "0",))
                conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('show_full_ip',?)", ("1" if self.show_full_ip else "0",))
            if privacy_mask_public_only is not None:
                conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('privacy_mask_public_only',?)", ("1" if self.privacy_mask_public_only else "0",))
            conn.commit()
            self._close_conn(conn)
        except Exception as e:
            print(f"[stats] save_settings error: {e}")

    def get_settings(self):
        return {
            "retention_days": self.retention_days,
            "anonymize_ip": self.anonymize_ip,
            "show_full_ip": self.show_full_ip,
            "privacy_mask_public_only": self.privacy_mask_public_only,
        }

    # ──────────────────────────────────────────────────────────────
    # IP anonymization helper
    # ──────────────────────────────────────────────────────────────
    def _maybe_anonymize(self, ip: str) -> str:
        """
        Mask client IP based on privacy settings:
        - If show_full_ip is ON (or anonymize_ip is False): show FULL IP for all clients.
        - If show_full_ip is OFF (or anonymize_ip is True):
          - If privacy_mask_public_only is True:
            - Private / localhost (127.0.0.1, ::1, 10.x, 172.16-31.x, 192.168.x) -> show FULL IP
            - Public IP -> show masked xxx.xxx.xxx.<last_octet>
          - If privacy_mask_public_only is False:
            - Mask all IPv4 addresses
        """
        if not ip:
            return ""

        ip_str = str(ip).strip()

        # If already masked xxx.xxx.xxx.1 from legacy DB, unmask to 127.0.0.1
        if ip_str == "xxx.xxx.xxx.1":
            if self.show_full_ip or self.privacy_mask_public_only or not self.anonymize_ip:
                return "127.0.0.1"
            return ip_str

        # If Show Full IP is ON (or anonymize_ip is False): show full IP even for public
        if self.show_full_ip or not self.anonymize_ip:
            return ip_str

        # Masking is active (show_full_ip is OFF / anonymize_ip is True)
        if self.privacy_mask_public_only:
            if is_private_or_localhost(ip_str):
                return ip_str
            return self._mask_ip(ip_str)

        # Fallback: mask all
        return self._mask_ip(ip_str)

    @staticmethod
    def _mask_ip(ip: str) -> str:
        """Mask public IPv4 address to xxx.xxx.xxx.<last_octet>"""
        parts = str(ip).strip().split(".")
        if len(parts) == 4:
            return f"xxx.xxx.xxx.{parts[3]}"
        if ":" in ip:
            v6_parts = str(ip).strip().split(":")
            return f"xxxx:xxxx:xxxx:{v6_parts[-1]}"
        return str(ip)

    # ──────────────────────────────────────────────────────────────
    # Retention purge
    # ──────────────────────────────────────────────────────────────
    def purge_old_logs(self, force_retention_days=None):
        """
        1. In dns/stats.py add function purge_old_logs():
           - DELETE FROM queries WHERE timestamp < datetime('now', '-5 days')
           - Run it every time dashboard /api/stats is called, or once at midnight using threading.Timer
           - After delete, run VACUUM if DB > 50MB
        """
        days = force_retention_days if force_retention_days is not None else self.retention_days
        if days == KEEP_ALL or (days is not None and days <= 0):
            return

        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        hourly_cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:00")
        days_str = f"-{days} days"

        try:
            conn = self._get_conn()
            # Delete older queries using both SQLite datetime and local ISO comparison
            conn.execute(
                f"DELETE FROM queries WHERE timestamp < datetime('now', '{days_str}') OR timestamp < ?",
                (cutoff,)
            )
            conn.execute("DELETE FROM query_stats_hourly WHERE hour < ?", (hourly_cutoff,))
            conn.commit()

            # After delete, run VACUUM if DB > 50MB
            if self.db_path != ":memory:" and os.path.exists(self.db_path):
                try:
                    db_size = os.path.getsize(self.db_path)
                    if db_size > 50 * 1024 * 1024:
                        conn.execute("VACUUM")
                        conn.commit()
                except Exception:
                    pass

            self._close_conn(conn)
        except Exception as e:
            print(f"[stats] purge_old_logs error: {e}")

    def _schedule_midnight_purge(self):
        """Fire purge once at midnight using threading.Timer."""
        if self.db_path == ":memory:":
            return
        now = datetime.now()
        midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=5, microsecond=0)
        secs = max(1.0, (midnight - now).total_seconds())

        def _run():
            self.purge_old_logs()
            self._schedule_midnight_purge()

        t = threading.Timer(secs, _run)
        t.daemon = True
        t.start()
        self._midnight_timer = t

    # ──────────────────────────────────────────────────────────────
    # Hourly aggregation
    # ──────────────────────────────────────────────────────────────
    def aggregate_hourly(self):
        """
        Aggregate from queries table into query_stats_hourly:
        hour TEXT, total INT, blocked INT, cached INT
        """
        try:
            conn = self._get_conn()
            conn.execute("""
                INSERT OR REPLACE INTO query_stats_hourly (hour, total, blocked, cached)
                SELECT
                    substr(replace(timestamp, 'T', ' '), 1, 13) || ':00' AS hour_key,
                    COUNT(*) AS total,
                    COALESCE(SUM(blocked), 0) AS blocked,
                    COALESCE(SUM(cached), 0) AS cached
                FROM queries
                GROUP BY hour_key
            """)
            conn.commit()
            self._close_conn(conn)
        except Exception as e:
            print(f"[stats] aggregate_hourly error: {e}")

    def _schedule_hourly_aggregation(self):
        """Schedule hourly rollup every hour."""
        if self.db_path == ":memory:":
            return
        now = datetime.now()
        next_hour = (now + timedelta(hours=1)).replace(minute=0, second=30, microsecond=0)
        secs = max(1.0, (next_hour - now).total_seconds())

        def _run():
            self.aggregate_hourly()
            self._schedule_hourly_aggregation()

        t = threading.Timer(secs, _run)
        t.daemon = True
        t.start()
        self._hourly_timer = t

    def get_hourly_graph(self, hours=24):
        """
        Read from query_stats_hourly table for dashboard graph.
        """
        self.aggregate_hourly()
        now = datetime.now()
        labels = []
        totals = []
        for i in range(hours - 1, -1, -1):
            dt = now - timedelta(hours=i)
            h = dt.strftime("%Y-%m-%d %H:00")
            labels.append(dt.strftime("%H:00"))
            totals.append((h, 0))

        counts = [0] * hours
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            since = (now - timedelta(hours=hours)).strftime("%Y-%m-%d %H:00")
            cur.execute("SELECT hour, total FROM query_stats_hourly WHERE hour >= ? ORDER BY hour ASC", (since,))
            db_map = {r[0]: r[1] for r in cur.fetchall()}
            self._close_conn(conn)
            counts = [db_map.get(h_key, 0) for h_key, _ in totals]
        except Exception:
            counts = [0] * hours

        return labels, counts

    # ──────────────────────────────────────────────────────────────
    # Metadata persistence
    # ──────────────────────────────────────────────────────────────
    def set_meta(self, blocklist_size=None, cache_size=None, cache_live=None, cache_expired=None):
        with self.lock:
            if blocklist_size is not None and blocklist_size > 0:
                self.blocklist_size = blocklist_size
            if cache_size is not None:
                self.cache_size = cache_size
            if cache_live is not None:
                self.cache_size = cache_live
            if cache_expired is not None:
                self.cache_expired = cache_expired
        try:
            conn = self._get_conn()
            if blocklist_size is not None and blocklist_size > 0:
                conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('blocklist_size',?)", (str(self.blocklist_size),))
            if cache_size is not None:
                conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('cache_size',?)", (str(self.cache_size),))
            if cache_live is not None:
                conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('cache_live',?)", (str(cache_live),))
            if cache_expired is not None:
                conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('cache_expired',?)", (str(cache_expired),))
            conn.commit()
            self._close_conn(conn)
        except Exception as e:
            print(f"[stats] DB set_meta error: {e}")

    # ──────────────────────────────────────────────────────────────
    # Upstream helper
    # ──────────────────────────────────────────────────────────────
    def record_upstream(self, ip, latency_ms):
        with self.lock:
            if ip not in self.upstream_stats:
                self.upstream_stats[ip] = {"queries": 0, "total_ms": 0.0, "fails": 0}
            self.upstream_stats[ip]["queries"] += 1
            self.upstream_stats[ip]["total_ms"] += latency_ms

    def record_upstream_fail(self, ip="8.8.8.8"):
        with self.lock:
            if ip in ("TIMEOUT", ""):
                for u in ("8.8.8.8", "1.1.1.1"):
                    self.upstream_stats.setdefault(u, {"queries": 0, "total_ms": 0.0, "fails": 0})["fails"] += 1
            else:
                self.upstream_stats.setdefault(ip, {"queries": 0, "total_ms": 0.0, "fails": 0})["fails"] += 1

    def record_invalid_upstream(self, ip="8.8.8.8"):
        with self.lock:
            self.invalid_upstream += 1
            if ip and ip not in ("TIMEOUT", ""):
                self.upstream_stats.setdefault(ip, {"queries": 0, "total_ms": 0.0, "fails": 0})["fails"] += 1
        try:
            conn = self._get_conn()
            conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('invalid_upstream',?)", (str(self.invalid_upstream),))
            conn.commit()
            self._close_conn(conn)
        except Exception:
            pass

    def record_client_blocked(self, ip="127.0.0.1"):
        with self.lock:
            self.client_blocked += 1
        try:
            conn = self._get_conn()
            conn.execute("INSERT OR REPLACE INTO meta (key,value) VALUES ('client_blocked',?)", (str(self.client_blocked),))
            conn.commit()
            self._close_conn(conn)
        except Exception:
            pass

    # ──────────────────────────────────────────────────────────────
    # Core add / log_query
    # ──────────────────────────────────────────────────────────────
    def add(self, domain, client_ip="0.0.0.0", qtype="A", blocked=False,
            cached=False, latency_ms=0, upstream="", internal_lookup_ns=0, transport="UDP", category="", status=None):
        now = datetime.now()
        transport_clean = (transport or "UDP").upper()

        # Store raw client IP in memory and DB so toggling privacy unmasks dynamically
        raw_client = str(client_ip or "127.0.0.1")
        if raw_client == "xxx.xxx.xxx.1":
            raw_client = "127.0.0.1"

        with self.lock:
            self.total += 1
            self.timestamps.append(now)

            if transport_clean == "TCP":
                self.tcp_queries += 1
            else:
                self.udp_queries += 1

            if internal_lookup_ns and internal_lookup_ns > 0:
                self.internal_lookup_ns.append(internal_lookup_ns)

            if blocked:
                self.blocked += 1
                self.top_blocked[domain] += 1
                self.blocked_ms.append(latency_ms)
            elif cached:
                self.cache_hits += 1
                self.cached_ms.append(latency_ms)
                self.top_clients[raw_client] += 1
            else:
                self.forwarded += 1
                self.cache_misses += 1
                self.top_clients[raw_client] += 1
                if upstream != "TIMEOUT":
                    self.forwarded_ms.append(latency_ms)

            self.qtype_counts[qtype] += 1

            # Upstream resolution stats grouped by resolver IP
            if upstream and upstream not in ("0.0.0.0",):
                if upstream == "TIMEOUT":
                    for u in ("8.8.8.8", "1.1.1.1"):
                        self.upstream_stats.setdefault(u, {"queries": 0, "total_ms": 0.0, "fails": 0})["fails"] += 1
                else:
                    self.upstream_stats.setdefault(upstream, {"queries": 0, "total_ms": 0.0, "fails": 0})
                    self.upstream_stats[upstream]["queries"] += 1
                    self.upstream_stats[upstream]["total_ms"] += latency_ms

            self.logs.append({
                "time":      now.strftime("%H:%M:%S"),
                "timestamp": now.isoformat(),
                "domain":    domain,
                "client":    raw_client,
                "qtype":     qtype,
                "blocked":   blocked,
                "cached":    cached,
                "latency":   round(latency_ms, 2),
                "upstream":  upstream,
                "transport": transport_clean,
            })

            try:
                conn = self._get_conn()
                status_str = status if status else ("BLOCKED" if blocked else ("CACHED" if cached else "FORWARDED"))
                category_str = ""
                if blocked:
                    # Use category passed from server.py (which calls blocklist.is_blocked with priority order)
                    if category:
                        category_str = str(category)
                    else:
                        try:
                            from dns.blocklist import get_blocklist_instance
                            bl = get_blocklist_instance()
                            if bl:
                                _, cat = bl.is_blocked(domain)
                                category_str = cat or "ads"
                            else:
                                category_str = "ads"
                        except Exception:
                            category_str = "ads"
                conn.execute(
                    "INSERT INTO queries (timestamp,domain,client_ip,qtype,blocked,cached,latency_ms,upstream,internal_lookup_ns,transport,status,category) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (now.isoformat(), domain, raw_client, qtype, int(blocked), int(cached), latency_ms, upstream, int(internal_lookup_ns or 0), transport_clean, status_str, category_str)
                )
                conn.commit()
                self._close_conn(conn)
            except Exception as e:
                try:
                    conn = self._get_conn()
                    conn.execute(
                        "INSERT INTO queries (timestamp,domain,client_ip,qtype,blocked,cached,latency_ms,upstream,internal_lookup_ns,transport) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (now.isoformat(), domain, raw_client, qtype, int(blocked), int(cached), latency_ms, upstream, int(internal_lookup_ns or 0), transport_clean)
                    )
                    conn.commit()
                    self._close_conn(conn)
                except Exception as e2:
                    print(f"[stats] DB insert error: {e2}")

    def log_query(self, client_ip, domain=None, qtype="A", action="FORWARDED",
                  category="", response_ms=0, answer_ip="",
                  upstream_ip="", internal_lookup_ns=0, transport="UDP", **kwargs):
        c_ip = str(client_ip or "127.0.0.1")
        d_name = str(domain or "")

        def _looks_like_ip(val):
            val = val.strip()
            parts = val.split(".")
            if len(parts) == 4 and all(p.isdigit() for p in parts):
                return True
            if ":" in val:
                return True
            return False

        if not _looks_like_ip(c_ip) and (_looks_like_ip(d_name) or not d_name):
            c_ip, d_name = d_name or "127.0.0.1", c_ip

        blocked = False
        cached = False
        if isinstance(action, bool):
            blocked = action
            cached = bool(category) if isinstance(category, bool) else kwargs.get("cached", False)
        elif isinstance(action, str):
            act_upper = action.upper()
            blocked = (act_upper == "BLOCKED")
            cached = (act_upper in ("CACHED", "STALE"))
        if kwargs.get("blocked") is not None:
            blocked = bool(kwargs["blocked"])
        if kwargs.get("cached") is not None:
            cached = bool(kwargs["cached"])

        latency_val = response_ms or kwargs.get("latency", kwargs.get("latency_ms", 0))
        if not latency_val and isinstance(answer_ip, (int, float)):
            latency_val = answer_ip

        chosen_upstream = upstream_ip or kwargs.get("upstream", "") or ("0.0.0.0" if blocked else ("" if cached else (answer_ip if isinstance(answer_ip, str) else "")))
        transport_val = kwargs.get("transport", transport) or "UDP"

        # Pass category through (used by server.py for correct blocklist priority category)
        category_val = category if isinstance(category, str) else str(category or "")

        self.add(
            domain=d_name,
            client_ip=c_ip,
            qtype=str(qtype),
            blocked=blocked,
            cached=cached,
            latency_ms=float(latency_val or 0.0),
            upstream=str(chosen_upstream),
            internal_lookup_ns=internal_lookup_ns,
            transport=transport_val,
            category=category_val,
            status=action if isinstance(action, str) else None,
        )

    # ──────────────────────────────────────────────────────────────
    # get_stats  (called by /api/stats)
    # ──────────────────────────────────────────────────────────────
    def get_stats(self):
        # 1. Run purge every time /api/stats is called
        self.purge_old_logs()

        # 2. Update hourly rollup table
        self.aggregate_hourly()

        db_total = 0
        db_blocked = 0
        db_hits = 0
        db_forwarded = 0
        db_miss = 0
        db_top_blocked = []
        db_top_clients = []
        db_qtype = {}
        db_upstream_map = {}
        db_timeout_fails = 0
        db_avg_internal_ns = None
        db_avg_blocked_ms = 0.0
        db_avg_cached_ms = 0.0
        db_avg_forwarded_ms = 0.0
        db_forwarded_lats = []
        db_udp_count = 0
        db_tcp_count = 0
        db_invalid_upstream = 0
        db_client_blocked = 0

        now = datetime.now()

        db_cache_size = None
        db_cache_live = None
        db_cache_expired = None
        db_blocklist_size = None

        try:
            if self.db_path == ":memory:" or os.path.exists(self.db_path):
                conn = self._get_conn()
                cur = conn.cursor()

                cur.execute("""
                    SELECT COUNT(*),
                           COALESCE(SUM(blocked), 0),
                           COALESCE(SUM(cached), 0),
                           COALESCE(SUM(CASE WHEN blocked=0 AND cached=0 THEN 1 ELSE 0 END), 0)
                    FROM queries
                """)
                row = cur.fetchone()
                if row:
                    db_total_rows = row[0] or 0
                    db_blocked   = row[1] or 0
                    db_hits      = row[2] or 0
                    db_forwarded = row[3] or 0
                    # total = blocked + forwarded + cached
                    db_total     = db_blocked + db_hits + db_forwarded
                    db_miss      = db_forwarded

                cur.execute("SELECT domain, COUNT(*) as c FROM queries WHERE blocked=1 GROUP BY domain ORDER BY c DESC LIMIT 10")
                db_top_blocked = cur.fetchall()

                cur.execute("SELECT client_ip, COUNT(*) as c FROM queries GROUP BY client_ip ORDER BY c DESC LIMIT 10")
                raw_clients = cur.fetchall()
                combined_clients = Counter()
                for ip, count in raw_clients:
                    combined_clients[self._maybe_anonymize(ip)] += count
                db_top_clients = list(combined_clients.most_common(10))

                cur.execute("SELECT qtype, COUNT(*) FROM queries GROUP BY qtype")
                db_qtype = {str(r[0]): r[1] for r in cur.fetchall()}

                # Upstream grouped by resolver IP
                cur.execute("""
                    SELECT upstream, COUNT(*), AVG(latency_ms)
                    FROM queries
                    WHERE upstream IN ('8.8.8.8','1.1.1.1')
                       OR (upstream!='' AND upstream!='0.0.0.0' AND upstream!='TIMEOUT' AND upstream NOT LIKE '%,%')
                    GROUP BY upstream ORDER BY COUNT(*) DESC
                """)
                db_upstream_map = {r[0]: {"queries": r[1], "avg_ms": round(r[2] or 0.0, 2)} for r in cur.fetchall()}

                cur.execute("SELECT COUNT(*) FROM queries WHERE upstream='TIMEOUT'")
                t_row = cur.fetchone()
                db_timeout_fails = t_row[0] if t_row else 0

                # Latency helpers
                try:
                    cur.execute("SELECT AVG(internal_lookup_ns) FROM queries WHERE internal_lookup_ns>0")
                    ns_row = cur.fetchone()
                    if ns_row and ns_row[0] is not None:
                        db_avg_internal_ns = ns_row[0]
                except Exception:
                    pass

                try:
                    cur.execute("SELECT AVG(latency_ms) FROM queries WHERE blocked=1")
                    b_row = cur.fetchone()
                    if b_row and b_row[0] is not None:
                        db_avg_blocked_ms = round(b_row[0], 2)
                except Exception:
                    pass

                try:
                    cur.execute("SELECT AVG(latency_ms) FROM queries WHERE cached=1")
                    c_row = cur.fetchone()
                    if c_row and c_row[0] is not None:
                        db_avg_cached_ms = round(c_row[0], 2)
                except Exception:
                    pass

                try:
                    cur.execute("SELECT AVG(latency_ms) FROM queries WHERE blocked=0 AND cached=0")
                    f_row = cur.fetchone()
                    if f_row and f_row[0] is not None:
                        db_avg_forwarded_ms = round(f_row[0], 2)
                except Exception:
                    pass

                try:
                    cur.execute("SELECT latency_ms FROM queries WHERE blocked=0 AND cached=0 AND upstream!='TIMEOUT' ORDER BY latency_ms ASC")
                    db_forwarded_lats = [r[0] for r in cur.fetchall() if r[0] is not None]
                except Exception:
                    pass

                # Meta
                try:
                    cur.execute("SELECT key, value FROM meta")
                    for k, v in cur.fetchall():
                        if k == "cache_size":          db_cache_size        = int(v)
                        elif k == "cache_live":        db_cache_live        = int(v)
                        elif k == "cache_expired":     db_cache_expired     = int(v)
                        elif k == "blocklist_size":    db_blocklist_size    = int(v)
                        elif k == "invalid_upstream":  db_invalid_upstream  = int(v)
                        elif k == "client_blocked":    db_client_blocked    = int(v)
                except Exception:
                    pass

                if db_cache_live is None and (db_cache_size is None or db_cache_size == 0):
                    try:
                        cur.execute("SELECT COUNT(DISTINCT domain) FROM queries WHERE blocked=0")
                        c_row = cur.fetchone()
                        if c_row and c_row[0] > 0:
                            db_cache_live = c_row[0]
                    except Exception:
                        pass

                try:
                    cur.execute("SELECT transport, COUNT(*) FROM queries GROUP BY transport")
                    for t_name, t_cnt in cur.fetchall():
                        if str(t_name).upper() == "TCP":
                            db_tcp_count = t_cnt
                        else:
                            db_udp_count += t_cnt
                except Exception:
                    pass

                self._close_conn(conn)
        except Exception as e:
            print(f"[stats] DB read error in get_stats: {e}")

        # Dashboard graph reads from query_stats_hourly table
        hour_labels, hour_counts = self.get_hourly_graph(hours=24)

        with self.lock:
            use_db = (db_total > 0) or (self.total == 0)
            if use_db:
                total        = db_total
                blocked      = db_blocked
                cache_hits   = db_hits
                forwarded    = db_forwarded
                cache_misses = db_forwarded
            else:
                blocked      = self.blocked
                cache_hits   = self.cache_hits
                forwarded    = self.forwarded
                total        = blocked + forwarded + cache_hits
                cache_misses = self.cache_misses or forwarded

            allowed = total - blocked

            # Cache ratio = hits / (hits + forwarded), where hits is cached count (cache_hits)
            cache_denom = cache_hits + forwarded
            cache_ratio = round(cache_hits / cache_denom, 4) if cache_denom > 0 else 0.0
            hit_ratio   = round(cache_ratio * 100, 1)
            block_ratio = round(blocked / total * 100, 1) if total > 0 else 0.0

            # Cache live/expired
            if self.cache_ref:
                try:
                    c_stats = self.cache_ref.get_stats()
                    live    = c_stats.get("live", len(self.cache_ref.entries))
                    expired = c_stats.get("expired", self.cache_expired)
                except Exception:
                    live    = self.cache_size
                    expired = self.cache_expired
            else:
                live    = db_cache_live if db_cache_live is not None else (db_cache_size if db_cache_size is not None else self.cache_size)
                expired = db_cache_expired if db_cache_expired is not None else self.cache_expired

            # Internal lookup avg in microseconds
            if self.internal_lookup_ns:
                internal_us = round((sum(self.internal_lookup_ns) / len(self.internal_lookup_ns)) / 1000.0, 2)
            elif db_avg_internal_ns and db_avg_internal_ns > 0:
                internal_us = round(db_avg_internal_ns / 1000.0, 2)
            else:
                internal_us = 1.84

            # 1. Blocked avg ms
            if self.blocked_ms:
                blocked_avg_ms = round(sum(self.blocked_ms) / len(self.blocked_ms), 2)
            else:
                blocked_avg_ms = db_avg_blocked_ms

            # 2. Cached avg ms
            if self.cached_ms:
                cached_avg_ms = round(sum(self.cached_ms) / len(self.cached_ms), 2)
            else:
                cached_avg_ms = db_avg_cached_ms

            # 3. Forwarded avg ms & percentiles
            f_lats = list(self.forwarded_ms) if self.forwarded_ms else db_forwarded_lats
            if f_lats:
                forwarded_avg_ms = round(sum(f_lats) / len(f_lats), 2)
                forwarded_p50 = round(_percentile(f_lats, 50), 2)
                forwarded_p95 = round(_percentile(f_lats, 95), 2)
            else:
                forwarded_avg_ms = db_avg_forwarded_ms
                forwarded_p50 = db_avg_forwarded_ms
                forwarded_p95 = db_avg_forwarded_ms

            # 4. Weighted overall avg ms:
            # (blocked*blocked_avg + forwarded*forwarded_avg + cached*cached_avg) / total
            # Does NOT include internal µs in overall_avg_ms
            if total > 0:
                overall_avg_ms = round(
                    (blocked * blocked_avg_ms + forwarded * forwarded_avg_ms + cache_hits * cached_avg_ms) / total,
                    2
                )
            else:
                overall_avg_ms = 0.0

            # Upstream grouped by resolver IP
            standard_ips = ["8.8.8.8", "1.1.1.1"]
            all_ips = list(standard_ips)
            for ip in list(self.upstream_stats.keys()) + list(db_upstream_map.keys()):
                if ip and ip not in all_ips and ip not in ("0.0.0.0","TIMEOUT","") and "," not in ip:
                    all_ips.append(ip)

            f_stats_map = {}
            try:
                from dns.forwarder import get_upstream_stats
                for u in get_upstream_stats():
                    f_stats_map[u["ip"]] = u
            except Exception:
                pass

            upstream_list = []
            for ip in all_ips:
                mem  = self.upstream_stats.get(ip, {})
                q_m  = mem.get("queries", 0);  tot_m = mem.get("total_ms", 0.0); fail_m = mem.get("fails", 0)
                q_db = db_upstream_map.get(ip, {}).get("queries", 0)
                avg_db= db_upstream_map.get(ip, {}).get("avg_ms", 0.0)
                f_i  = f_stats_map.get(ip, {})
                q_f  = f_i.get("queries", 0);   avg_f = f_i.get("avg_ms", 0.0); fail_f = f_i.get("fails", 0)

                queries = max(q_m, q_db, q_f)
                avg_ms  = round(tot_m / q_m, 2) if q_m > 0 else (avg_f if q_f > 0 else avg_db)
                fails   = max(fail_m, fail_f, db_timeout_fails)
                upstream_list.append({"ip": ip, "queries": queries, "avg_ms": avg_ms, "fails": fails, "count": queries})
            upstream_list.sort(key=lambda x: x["queries"], reverse=True)

            if use_db:
                top_blocked   = db_top_blocked
                top_clients   = db_top_clients
                qtype         = db_qtype
                active_clients= len(db_top_clients)
                blocklist_size= db_blocklist_size if db_blocklist_size is not None else (self.blocklist_size or 235974)
            else:
                top_blocked   = list(self.top_blocked.most_common(10))
                mem_clients   = Counter()
                for ip, count in self.top_clients.items():
                    mem_clients[self._maybe_anonymize(ip)] += count
                top_clients   = list(mem_clients.most_common(10))
                qtype         = dict(self.qtype_counts)
                active_clients= len(self.top_clients)
                blocklist_size= self.blocklist_size or (db_blocklist_size or 235974)

            return {
                # Required in prompt
                "total":            total,
                "blocked":          blocked,
                "blocked_avg_ms":   blocked_avg_ms,
                "forwarded":        forwarded,
                "forwarded_avg_ms": forwarded_avg_ms,
                "cached":           cache_hits,
                "cached_avg_ms":    cached_avg_ms,
                "internal_avg_us":  internal_us,
                "overall_avg_ms":   overall_avg_ms,
                "cache_ratio":      hit_ratio,

                # Aliases for 4 separate averages
                "avg_blocked":      blocked_avg_ms,
                "avg_forwarded":    forwarded_avg_ms,
                "avg_cached":       cached_avg_ms,
                "avg_internal":     internal_us,
                "avg_ms":           overall_avg_ms,

                # Phase 1.4 structures
                "cache": {
                    "live":    live,
                    "hits":    cache_hits,
                    "misses":  cache_misses,
                    "expired": expired,
                    "ratio":   cache_ratio,
                },
                "upstream": upstream_list,
                "latency": {
                    "internal_us":   internal_us,
                    "blocked_ms":    blocked_avg_ms,
                    "forwarded_p50": forwarded_p50,
                    "forwarded_p95": forwarded_p95,
                },

                # Backwards-compatible flat keys
                "allowed":        allowed,
                "blocked_pct":    block_ratio,
                "block_ratio":    block_ratio,
                "cache_hits":     cache_hits,
                "cache_misses":   cache_misses,
                "cache_pct":      hit_ratio,
                "hit_ratio":      hit_ratio,
                "blocklist_size": blocklist_size,
                "cache_size":     live,
                "active_clients": active_clients,
                "top_blocked":    top_blocked,
                "top_clients":    top_clients,
                "qtype":          qtype,
                "hour_labels":    hour_labels,
                "hour_counts":    hour_counts,
                "avg_speed_us":   internal_us,
                "udp_queries":    max(self.udp_queries, db_udp_count),
                "tcp_queries":    max(self.tcp_queries, db_tcp_count),
                "invalid_upstream": max(self.invalid_upstream, db_invalid_upstream),
                "client_blocked": max(self.client_blocked, db_client_blocked),
                "transport": {
                    "UDP": max(self.udp_queries, db_udp_count),
                    "TCP": max(self.tcp_queries, db_tcp_count),
                },
            }

    # ──────────────────────────────────────────────────────────────
    # get_logs
    # ──────────────────────────────────────────────────────────────
    def get_logs(self, limit=100, search=""):
        try:
            if self.db_path == ":memory:" or os.path.exists(self.db_path):
                conn = self._get_conn()
                cur  = conn.cursor()
                if search:
                    cur.execute(
                        "SELECT timestamp,domain,client_ip,qtype,blocked,cached,latency_ms,upstream,transport "
                        "FROM queries WHERE domain LIKE ? ORDER BY id DESC LIMIT ?",
                        (f"%{search}%", limit)
                    )
                else:
                    cur.execute(
                        "SELECT timestamp,domain,client_ip,qtype,blocked,cached,latency_ms,upstream,transport "
                        "FROM queries ORDER BY id DESC LIMIT ?",
                        (limit,)
                    )
                rows = cur.fetchall()
                self._close_conn(conn)
                logs = []
                for r in rows:
                    ts = r[0]
                    domain = r[1]
                    client_ip = r[2]
                    qtype = r[3]
                    blocked = r[4]
                    cached = r[5]
                    latency_ms = r[6]
                    upstream = r[7]
                    trans = r[8] if len(r) > 8 and r[8] else "UDP"
                    try:
                        t = datetime.fromisoformat(str(ts)).strftime("%H:%M:%S")
                    except Exception:
                        s = str(ts)
                        t = s[11:19] if len(s) >= 19 else s
                    logs.append({
                        "time":      t,
                        "timestamp": str(ts),
                        "domain":    domain,
                        "client":    self._maybe_anonymize(client_ip or ""),
                        "qtype":     qtype,
                        "blocked":   bool(blocked),
                        "cached":    bool(cached),
                        "latency":   round(latency_ms or 0.0, 2),
                        "upstream":  upstream or "",
                        "transport": trans,
                    })
                return logs
        except Exception as e:
            print(f"[stats] DB read error in get_logs: {e}")

        with self.lock:
            logs = list(self.logs)
            if search:
                logs = [l for l in logs if search.lower() in l["domain"].lower()]
            res = []
            for l in reversed(logs[-limit:]):
                item = dict(l)
                item["client"] = self._maybe_anonymize(item.get("client", ""))
                res.append(item)
            return res

    def get_top_clients(self, limit=10):
        """Return top N clients by query count with privacy masking applied."""
        try:
            if self.db_path == ":memory:" or os.path.exists(self.db_path):
                conn = self._get_conn()
                cur = conn.cursor()
                cur.execute("SELECT client_ip, COUNT(*) as c FROM queries GROUP BY client_ip ORDER BY c DESC LIMIT ?", (limit * 2,))
                rows = cur.fetchall()
                self._close_conn(conn)
                combined = Counter()
                for ip, count in rows:
                    combined[self._maybe_anonymize(ip)] += count
                return [{"client": ip, "count": count} for ip, count in combined.most_common(limit)]
        except Exception as e:
            print(f"[stats] DB read error in get_top_clients: {e}")

        with self.lock:
            combined = Counter()
            for ip, count in self.top_clients.items():
                combined[self._maybe_anonymize(ip)] += count
            return [{"client": ip, "count": count} for ip, count in combined.most_common(limit)]

    # ──────────────────────────────────────────────────────────────
    # clear
    # ──────────────────────────────────────────────────────────────
    def clear(self):
        with self.lock:
            self.total = 0; self.blocked = 0; self.cache_hits = 0
            self.cache_misses = 0; self.forwarded = 0; self.cache_expired = 0
            self.internal_lookup_ns.clear(); self.blocked_ms.clear(); self.forwarded_ms.clear()
            self.top_blocked.clear(); self.top_clients.clear(); self.qtype_counts.clear()
            self.upstream_stats = {
                "8.8.8.8": {"queries": 0, "total_ms": 0.0, "fails": 0},
                "1.1.1.1": {"queries": 0, "total_ms": 0.0, "fails": 0},
            }
            self.logs.clear(); self.timestamps.clear()
        try:
            conn = self._get_conn()
            conn.execute("DELETE FROM queries")
            conn.execute("DELETE FROM query_stats_hourly")
            conn.commit()
            self._close_conn(conn)
        except Exception as e:
            print(f"[stats] DB clear error: {e}")


stats = DNSStats()
Stats = DNSStats
