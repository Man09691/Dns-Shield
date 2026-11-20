"""
dns/dashboard.py  —  Production-Ready DNS Shield Dashboard & Management APIs
=============================================================================
Port 8081.
Run: python -m dns.dashboard

Web Pages:
  GET /            → Dashboard (Live stats, 24h line chart, top 10 blocked)
  GET /logs        → Query Logs (Real-time table, search, filter, pagination)
  GET /lookup      → Domain Lookup (Instant check, allow/block actions)
  GET /blocklists  → Blocklists (4 categories, counts, toggles, metadata)
  GET /allowlist   → Allowlist (Add/Remove trusted domains)
  GET /analytics   → Analytics (24h hourly activity & category breakdown charts)
  GET /settings    → Settings (Retention slider, IP anonymization, maintenance)

APIs:
  GET    /api/stats               → Live stats from DB (no cache, includes db_size, categories)
  GET    /api/logs                → Query logs (supports limit=100, search, filter)
  GET    /api/hourly?hours=24     → 24h hourly aggregate data for charts
  GET    /api/settings            → Current retention, anonymize, DB size
  POST   /api/settings            → Update retention & anonymize
  POST   /api/purge               → Purge logs older than retention setting
  GET/POST /api/clear             → Wipe all logs + VACUUM
  GET    /api/check?domain=...    → Check if domain is blocked + category + source
  GET    /api/blocklists          → List of 4 blocklist files with counts & status
  POST   /api/blocklists          → Toggle enable / disable blocklist
  POST   /api/blocklists/toggle   → Alias for toggle
  GET    /api/allowlist           → List of allowed domains
  POST   /api/allowlist           → Add domain to allowlist.txt
  DELETE /api/allowlist           → Remove domain from allowlist.txt (?domain=xxx or body)
  POST   /api/blocklist           → Add domain to blocklists/custom.txt
  GET    /api/categories          → Category distribution counts
"""

import os
import sys
import sqlite3
import json
import logging
import time
import copy
import threading
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template, request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dns.stats import stats
from dns.blocklist import Blocklist
from dns.cache import get_default_cache_size, get_cache_warning, get_system_ram_gb, get_cache_instance
from dns.watchlist import watchlist_manager, normalize_watchlist_input, get_suggestions

# ─────────────────────────────────────────────────────────────────────────────
# IN-MEMORY API CACHE (TTL 2.0s for instant UI navigation)
# ─────────────────────────────────────────────────────────────────────────────
_api_cache = {}
_api_cache_lock = threading.Lock()

def get_cached_api(key, ttl=2.0):
    now = time.monotonic()
    with _api_cache_lock:
        if key in _api_cache:
            ts, val = _api_cache[key]
            if now - ts < ttl:
                return copy.deepcopy(val)
    return None

def set_cached_api(key, val):
    now = time.monotonic()
    with _api_cache_lock:
        _api_cache[key] = (now, copy.deepcopy(val))

def invalidate_api_cache(prefix=None):
    with _api_cache_lock:
        if prefix:
            keys_to_del = [k for k in _api_cache if k.startswith(prefix)]
            for k in keys_to_del:
                del _api_cache[k]
        else:
            _api_cache.clear()

DB_PATH = os.path.join(PROJECT_ROOT, "port53_queries.db")
if hasattr(stats, "db_path") and stats.db_path != DB_PATH:
    stats.db_path = DB_PATH

logger = logging.getLogger("dns.dashboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def check_port_53():
    """
    Check if port 53 bind fails with PermissionError / WinError 10013.
    Shows clear message advising to Run as Administrator.
    """
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", 53))
        sock.close()
    except (PermissionError, OSError) as e:
        if isinstance(e, PermissionError) or getattr(e, "winerror", None) == 10013 or getattr(e, "errno", None) == 13:
            print("\n" + "=" * 70)
            print("Run as Administrator - python main.py needs admin for port 53")
            print("=" * 70 + "\n")
            logger.warning("Run as Administrator - python main.py needs admin for port 53")
            return False
    except Exception:
        pass
    return True

TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "templates")
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# Initialize Blocklist instance for fast lookups & management
blocklist_dir = os.path.join(PROJECT_ROOT, "blocklists")
allowlist_path = os.path.join(PROJECT_ROOT, "allowlist.txt")

blocklist_manager = Blocklist()
blocklist_manager.load_all_blocklists(blocklist_dir)
blocklist_manager.load_allowlist(allowlist_path)

# Track disabled blocklists in memory
disabled_blocklists = set()


@app.after_request
def add_cors_and_security_headers(response):
    """Add CORS and cache-control headers."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response


# ─────────────────────────────────────────────────────────────────────────────
# PAGE ROUTES (Separate page per feature, rendering Jinja templates)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def page_dashboard():
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/logs")
def page_logs():
    return render_template("logs.html", active_page="logs")


@app.route("/lookup")
def page_lookup():
    return render_template("lookup.html", active_page="lookup")


@app.route("/blocklists")
@app.route("/blocklist")
def page_blocklists():
    return render_template("blocklists.html", active_page="blocklists")


@app.route("/allowlist")
def page_allowlist():
    return render_template("allowlist.html", active_page="allowlist")


@app.route("/analytics")
def page_analytics():
    return render_template("analytics.html", active_page="analytics")


@app.route("/settings")
def page_settings():
    return render_template("settings.html", active_page="settings")


@app.route("/watchlist")
def page_watchlist():
    return render_template("watchlist.html", active_page="watchlist")


# ─────────────────────────────────────────────────────────────────────────────
# CORE API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

def recalculate_blocked_categories_in_db():
    """
    Backfill / re-calculate category for all blocked queries in the database
    using priority order: Malware > Trackers > Custom > Ads.
    """
    try:
        conn = stats._get_conn() if hasattr(stats, "_get_conn") else sqlite3.connect(stats.db_path, timeout=10)
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(queries)")
        cols = {r[1] for r in cur.fetchall()}
        if "category" not in cols:
            if hasattr(stats, "_close_conn"):
                stats._close_conn(conn)
            else:
                conn.close()
            return
        cur.execute("SELECT DISTINCT domain FROM queries WHERE blocked = 1 OR status = 'BLOCKED'")
        domains = [r[0] for r in cur.fetchall() if r[0]]
        for d in domains:
            if blocklist_manager:
                is_blk, cat = blocklist_manager.is_blocked(d)
                if is_blk and cat:
                    cur.execute("UPDATE queries SET category = ? WHERE domain = ? AND (blocked = 1 OR status = 'BLOCKED')", (cat, d))
        conn.commit()
        if hasattr(stats, "_close_conn"):
            stats._close_conn(conn)
        else:
            conn.close()
    except Exception as e:
        logger.error(f"Error recalculating blocked categories in DB: {e}")

try:
    recalculate_blocked_categories_in_db()
except Exception:
    pass


def get_blocked_categories_24h():
    """
    Queries DB and calculates real blocked counts by category in priority order:
    Malware > Trackers > Custom > Ads.
    Returns blocked_by_category dict and total blocked count in 24h.
    """
    from collections import OrderedDict
    cat_counts = OrderedDict([("malware", 0), ("trackers", 0), ("custom", 0), ("ads", 0)])
    total_blocked = 0
    try:
        now = datetime.now()
        since_iso = (now - timedelta(hours=24)).isoformat()
        since_str = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
        conn = stats._get_conn() if hasattr(stats, "_get_conn") else sqlite3.connect(stats.db_path, timeout=10)
        cur = conn.cursor()

        # Check existing columns
        cur.execute("PRAGMA table_info(queries)")
        cols = {r[1] for r in cur.fetchall()}

        # Re-evaluate category per domain to ensure priority order is strictly respected
        cur.execute(
            "SELECT domain, category, COUNT(*) FROM queries WHERE (status = 'BLOCKED' OR blocked = 1) AND (timestamp >= ? OR timestamp >= ?) GROUP BY domain",
            (since_iso, since_str)
        )
        rows = cur.fetchall()
        for domain, db_cat, count in rows:
            cat = None
            if blocklist_manager:
                _, bcat = blocklist_manager.is_blocked(domain)
                if bcat:
                    cat = bcat.lower().strip()
            if not cat and db_cat:
                cat = str(db_cat).lower().strip()
            if not cat:
                cat = "ads"
            if "[" in cat:
                cat = cat.split("[")[0].strip()

            if cat in cat_counts:
                cat_counts[cat] += count
            else:
                cat_counts["ads"] += count
            total_blocked += count

        # If zero in last 24h, check all-time blocked queries from DB so analytics is never empty
        if total_blocked == 0:
            cur.execute("SELECT domain, category, COUNT(*) FROM queries WHERE status = 'BLOCKED' OR blocked = 1 GROUP BY domain")
            for domain, db_cat, count in cur.fetchall():
                cat = None
                if blocklist_manager:
                    _, bcat = blocklist_manager.is_blocked(domain)
                    if bcat:
                        cat = bcat.lower().strip()
                if not cat and db_cat:
                    cat = str(db_cat).lower().strip()
                if not cat:
                    cat = "ads"
                if "[" in cat:
                    cat = cat.split("[")[0].strip()

                if cat in cat_counts:
                    cat_counts[cat] += count
                else:
                    cat_counts["ads"] += count
                total_blocked += count

        if hasattr(stats, "_close_conn"):
            stats._close_conn(conn)
        else:
            conn.close()
    except Exception as e:
        logger.error(f"Error computing 24h blocked categories: {e}")

    return dict(cat_counts), total_blocked

    return cat_counts, total_blocked


@app.route("/api/stats")
def api_stats():
    """
    Returns total, blocked, cached, forwarded, blocked_avg_ms, forwarded_avg_ms,
    cached_avg_ms, internal_avg_us, overall_avg_ms, cache_ratio, etc.
    Cached in memory for 2.0 seconds for high-speed UI navigation.
    """
    cached = get_cached_api("stats", ttl=2.0)
    if cached is not None:
        return jsonify(cached)

    try:
        data = stats.get_stats()
        total = data.get("total", 0)
        blocked = data.get("blocked", 0)
        cached = data.get("cached", data.get("cache_hits", 0))
        forwarded = data.get("forwarded", 0)

        blocked_avg_ms = data.get("blocked_avg_ms", data.get("latency", {}).get("blocked_ms", 0.0))
        forwarded_avg_ms = data.get("forwarded_avg_ms", 0.0)
        cached_avg_ms = data.get("cached_avg_ms", 0.0)
        internal_avg_us = data.get("internal_avg_us", data.get("latency", {}).get("internal_us", 0.0))
        overall_avg_ms = data.get("overall_avg_ms", 0.0)

        blocked_pct = data.get("blocked_pct", round((blocked / total * 100), 1) if total > 0 else 0.0)
        cache_ratio = data.get("cache_ratio", 0.0)

        # Database disk size
        db_path = stats.db_path
        db_size_mb = 0.0
        db_size_str = "0 KB"
        if db_path != ":memory:" and os.path.exists(db_path):
            try:
                bytes_sz = os.path.getsize(db_path)
                db_size_mb = round(bytes_sz / (1024 * 1024), 2)
                db_size_str = f"{db_size_mb} MB" if db_size_mb >= 1.0 else f"{round(bytes_sz / 1024, 1)} KB"
            except Exception as e:
                logger.error(f"Error calculating DB size: {e}")

        # Compute category distribution from 24h blocked queries for Analytics & Dashboard
        cat_breakdown, total_blocked_24h = get_blocked_categories_24h()
        if total_blocked_24h == 0 and data.get("top_blocked"):
            for item in data.get("top_blocked", []):
                d = item[0] if isinstance(item, (list, tuple)) else str(item)
                c = item[1] if isinstance(item, (list, tuple)) and len(item) > 1 else 1
                is_blk, cat = blocklist_manager.is_blocked(d)
                k = cat if cat in cat_breakdown else "ads"
                cat_breakdown[k] += c

        data["total"] = total
        data["blocked"] = blocked
        data["blocked_avg_ms"] = blocked_avg_ms
        data["forwarded"] = forwarded
        data["forwarded_avg_ms"] = forwarded_avg_ms
        data["cached"] = cached
        data["cached_avg_ms"] = cached_avg_ms
        data["internal_avg_us"] = internal_avg_us
        data["overall_avg_ms"] = overall_avg_ms
        data["avg_ms"] = overall_avg_ms
        data["avg_blocked"] = blocked_avg_ms
        data["avg_forwarded"] = forwarded_avg_ms
        data["avg_cached"] = cached_avg_ms
        data["avg_internal"] = internal_avg_us
        data["blocked_pct"] = blocked_pct
        data["cache_pct"] = cache_ratio
        data["cache_ratio"] = cache_ratio
        data["db_size"] = db_size_str
        data["db_size_str"] = db_size_str
        data["db_size_mb"] = db_size_mb
        data["categories"] = cat_breakdown
        data["blocked_by_category"] = cat_breakdown
        data["total_blocked_24h"] = total_blocked_24h

        # Raw sum of all 4 source files (dynamically calculated)
        total_raw_rules = 0
        if blocklist_manager and hasattr(blocklist_manager, "source_counts") and blocklist_manager.source_counts:
            total_raw_rules = sum(blocklist_manager.source_counts.values())

        if blocklist_manager is not None and getattr(blocklist_manager, "blocked_domains", None) is not None:
            active_bl_size = len(blocklist_manager.blocked_domains)
        elif "blocklist_size" in data and data["blocklist_size"] is not None:
            active_bl_size = int(data["blocklist_size"])
        elif hasattr(stats, "blocklist_size") and stats.blocklist_size:
            active_bl_size = int(stats.blocklist_size)
        else:
            active_bl_size = 0

        if total_raw_rules == 0 and active_bl_size > 0:
            total_raw_rules = active_bl_size

        data["total_raw_rules"] = total_raw_rules
        data["total_unique_rules"] = active_bl_size
        data["blocklist_size"] = active_bl_size
        data["rules"] = active_bl_size
        data["total_unique"] = active_bl_size
        data["rules_active"] = active_bl_size
        data["total_rules"] = total_raw_rules

        # Dynamic ports from config.json
        server_port = 53
        dashboard_port = 8081
        cfg_path = os.path.join(PROJECT_ROOT, "config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    _cfg = json.load(f)
                    server_port = _cfg.get("listen_port", 53)
                    dashboard_port = _cfg.get("dashboard_port", 8081)
            except Exception:
                pass
        data["server_port"] = server_port
        data["dashboard_port"] = dashboard_port
        data["invalid_upstream"] = data.get("invalid_upstream", 0)
        data["client_blocked"] = data.get("client_blocked", 0)
        try:
            data["watchlist_count"] = len(watchlist_manager.get_domains())
        except Exception:
            data["watchlist_count"] = 0

        set_cached_api("stats", data)
        return jsonify(data)
    except Exception as e:
        logger.error(f"Error in /api/stats: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


def _fetch_query_logs(req_args):
    """
    Helper to fetch filtered & paginated query logs from queries DB / query_logs view.
    Supports:
      - limit / per_page
      - offset / page
      - search / domain
      - filter / status
      - type / qtype
      - transport
    """
    per_page = req_args.get("per_page")
    if per_page is not None:
        try:
            limit = int(per_page)
        except (TypeError, ValueError):
            limit = 50
    else:
        try:
            limit = int(req_args.get("limit", 50))
        except (TypeError, ValueError):
            limit = 50
    limit = max(1, min(limit, 1000))

    page_arg = req_args.get("page")
    if page_arg is not None:
        try:
            p = max(1, int(page_arg))
            offset = (p - 1) * limit
        except (TypeError, ValueError):
            offset = 0
    else:
        try:
            offset = int(req_args.get("offset", 0))
        except (TypeError, ValueError):
            offset = 0
    offset = max(0, offset)

    search = req_args.get("search", req_args.get("domain", "")).strip()
    status_filter = req_args.get("filter", req_args.get("status", "ALL")).upper().strip()
    type_filter = req_args.get("type", req_args.get("qtype", "All")).strip()
    transport_filter = req_args.get("transport", "All").strip()

    where_clauses = []
    params = []

    if search:
        where_clauses.append("(domain LIKE ? OR client_ip LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    if status_filter == "BLOCKED":
        where_clauses.append("blocked = 1")
    elif status_filter == "CACHED":
        where_clauses.append("cached = 1")
    elif status_filter == "FORWARDED":
        where_clauses.append("blocked = 0 AND cached = 0")
    elif status_filter == "RATE_LIMITED":
        where_clauses.append("upstream = '0.0.0.0' AND blocked = 1")

    if type_filter and type_filter.upper() not in ("ALL", "ALL TYPES"):
        where_clauses.append("qtype = ?")
        params.append(type_filter.upper())

    if transport_filter and transport_filter.upper() not in ("ALL", "ALL TRANSPORT"):
        where_clauses.append("transport = ?")
        params.append(transport_filter.upper())

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    logs = []
    total_count = 0

    try:
        conn = stats._get_conn() if hasattr(stats, "_get_conn") else sqlite3.connect(stats.db_path, timeout=10)
        cur = conn.cursor()

        if not where_sql:
            cached_count = get_cached_api("logs_total_count", ttl=2.0)
            if cached_count is not None:
                total_count = cached_count
            else:
                cur.execute("SELECT COUNT(*) FROM queries")
                row = cur.fetchone()
                total_count = row[0] if row else 0
                set_cached_api("logs_total_count", total_count)
        else:
            cur.execute(f"SELECT COUNT(*) FROM queries {where_sql}", params)
            row = cur.fetchone()
            total_count = row[0] if row else 0

        cur.execute(f"""
            SELECT id, timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream, transport
            FROM queries
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, params + [limit, offset])

        rows = cur.fetchall()
        if hasattr(stats, "_close_conn"):
            stats._close_conn(conn)
        else:
            conn.close()

        for r in rows:
            _id = r[0]
            ts = r[1]
            domain = r[2]
            client_ip = r[3]
            qtype = r[4]
            blk = r[5]
            cch = r[6]
            lat_ms = r[7]
            upstream = r[8]
            trans = r[9] if len(r) > 9 and r[9] else "UDP"

            try:
                t_str = datetime.fromisoformat(str(ts)).strftime("%H:%M:%S")
            except Exception:
                s = str(ts)
                t_str = s[11:19] if len(s) >= 19 else s

            status = "BLOCKED" if blk else ("CACHED" if cch else "FORWARDED")
            client_display = stats._maybe_anonymize(client_ip or "")

            logs.append({
                "id": _id,
                "time": t_str,
                "timestamp": str(ts),
                "client": client_display,
                "domain": domain or "",
                "type": qtype or "A",
                "qtype": qtype or "A",
                "status": status,
                "blocked": bool(blk),
                "cached": bool(cch),
                "latency": round(lat_ms or 0.0, 2),
                "upstream": upstream or "",
                "transport": trans,
            })
    except Exception as e:
        logger.error(f"Error fetching query logs: {e}", exc_info=True)
        raw_logs = stats.get_logs(limit=limit, search=search)
        if type_filter and type_filter.upper() not in ("ALL", "ALL TYPES"):
            raw_logs = [l for l in raw_logs if l.get("qtype", "").upper() == type_filter.upper()]
        if transport_filter and transport_filter.upper() not in ("ALL", "ALL TRANSPORT"):
            raw_logs = [l for l in raw_logs if l.get("transport", "UDP").upper() == transport_filter.upper()]
        logs = raw_logs
        total_count = len(logs)

    total_pages = (total_count + limit - 1) // limit if total_count > 0 else 1
    page = (offset // limit) + 1

    return logs, total_count, limit, offset, page, total_pages


@app.route("/api/logs")
def api_logs():
    """
    Returns query logs from port53_queries.db.
    Supports limit, offset, search, filter, type, transport.
    """
    logs, total_count, limit, offset, page, total_pages = _fetch_query_logs(request.args)

    paginate_param = str(request.args.get("paginate", "")).strip().lower()
    is_paginate = paginate_param in ("1", "true", "yes") or "paginate" in request.args
    has_offset = offset > 0
    has_search = bool(request.args.get("search", ""))
    has_filter = bool(
        (request.args.get("filter", "ALL").upper() != "ALL") or
        (request.args.get("type", "All").upper() not in ("ALL", "ALL TYPES")) or
        (request.args.get("transport", "All").upper() not in ("ALL", "ALL TRANSPORT"))
    )

    if is_paginate or has_offset or has_search or has_filter or request.args.get("page") or request.args.get("per_page"):
        return jsonify({
            "logs": logs,
            "queries": logs,
            "total": total_count,
            "limit": limit,
            "per_page": limit,
            "offset": offset,
            "page": page,
            "total_pages": total_pages
        })

    return jsonify(logs)


@app.route("/api/queries")
def api_queries():
    """
    Wireshark-style query logs API:
    GET /api/queries?type=A&transport=UDP&search=...&per_page=50&page=1
    """
    logs, total_count, limit, offset, page, total_pages = _fetch_query_logs(request.args)
    return jsonify({
        "queries": logs,
        "logs": logs,
        "total": total_count,
        "limit": limit,
        "per_page": limit,
        "offset": offset,
        "page": page,
        "total_pages": total_pages
    })


@app.route("/api/types")
def api_types():
    """Returns list of distinct query types recorded in the system."""
    try:
        conn = stats._get_conn() if hasattr(stats, "_get_conn") else sqlite3.connect(stats.db_path, timeout=10)
        cur = conn.cursor()
        try:
            cur.execute("SELECT DISTINCT type FROM query_logs WHERE type IS NOT NULL AND type != '' ORDER BY type")
        except Exception:
            cur.execute("SELECT DISTINCT qtype FROM queries WHERE qtype IS NOT NULL AND qtype != '' ORDER BY qtype")
        types = [r[0] for r in cur.fetchall() if r[0]]
        if hasattr(stats, "_close_conn"):
            stats._close_conn(conn)
        else:
            conn.close()
        if not types:
            types = ["A", "AAAA", "CNAME", "HTTPS", "MX", "NS", "PTR", "TXT"]
        return jsonify(types)
    except Exception as e:
        logger.error(f"Error in /api/types: {e}", exc_info=True)
        return jsonify(["A", "AAAA", "CNAME", "HTTPS", "MX", "NS", "PTR", "TXT"])


@app.route("/api/hourly")
def api_hourly():
    """
    Returns 24h hourly aggregate data from query_stats_hourly table.
    Cached in memory for 2.0 seconds.
    """
    try:
        hours = int(request.args.get("hours", 24))
        hours = max(1, min(hours, 720))

        cache_key = f"hourly_{hours}"
        cached = get_cached_api(cache_key, ttl=2.0)
        if cached is not None:
            return jsonify(cached)

        labels, counts = stats.get_hourly_graph(hours=hours)

        blocked_counts = [0] * hours
        allowed_counts = [0] * hours
        cached_counts = [0] * hours

        now = datetime.now()
        since = (now - timedelta(hours=hours)).strftime("%Y-%m-%d %H:00")
        conn = stats._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT hour, total, blocked, cached FROM query_stats_hourly WHERE hour >= ? ORDER BY hour ASC", (since,))
        db_map = {r[0]: (r[1], r[2], r[3]) for r in cur.fetchall()}
        stats._close_conn(conn)

        for idx, i in enumerate(range(hours - 1, -1, -1)):
            dt = now - timedelta(hours=i)
            h_key = dt.strftime("%Y-%m-%d %H:00")
            if h_key in db_map:
                tot, blk, cch = db_map[h_key]
                blocked_counts[idx] = blk
                cached_counts[idx] = cch
                allowed_counts[idx] = max(0, tot - blk)
            else:
                tot = counts[idx] if idx < len(counts) else 0
                allowed_counts[idx] = tot

        res_payload = {
            "labels": labels,
            "counts": counts,
            "allowed": allowed_counts,
            "blocked": blocked_counts,
            "cached": cached_counts,
        }
        set_cached_api(cache_key, res_payload)
        return jsonify(res_payload)
    except Exception as e:
        logger.error(f"Error in /api/hourly: {e}", exc_info=True)
        return jsonify({"labels": [], "counts": [], "allowed": [], "blocked": []}), 500


@app.route("/api/analytics")
def api_analytics():
    """
    Returns combined telemetry for Analytics page: stats, 24h hourly data,
    categories, latency percentiles, and qtype distribution.
    Cached in memory for 2.0s for instant SPA switching.
    """
    cached = get_cached_api("analytics_combined", ttl=2.0)
    if cached is not None:
        return jsonify(cached)

    try:
        # Get or compute stats
        st_data = get_cached_api("stats", ttl=2.0)
        if st_data is None:
            api_stats()
            st_data = get_cached_api("stats", ttl=2.0)
        if st_data is None:
            st_data = stats.get_stats()
            cat_breakdown, _ = get_blocked_categories_24h()
            st_data["categories"] = cat_breakdown

        # Get or compute 24h hourly
        hourly_data = get_cached_api("hourly_24", ttl=2.0)
        if hourly_data is None:
            labels, counts = stats.get_hourly_graph(hours=24)
            blocked_counts = [0] * 24
            allowed_counts = [0] * 24
            cached_counts = [0] * 24
            now = datetime.now()
            since = (now - timedelta(hours=24)).strftime("%Y-%m-%d %H:00")
            conn = stats._get_conn()
            cur = conn.cursor()
            cur.execute("SELECT hour, total, blocked, cached FROM query_stats_hourly WHERE hour >= ? ORDER BY hour ASC", (since,))
            db_map = {r[0]: (r[1], r[2], r[3]) for r in cur.fetchall()}
            stats._close_conn(conn)
            for idx, i in enumerate(range(23, -1, -1)):
                dt = now - timedelta(hours=i)
                h_key = dt.strftime("%Y-%m-%d %H:00")
                if h_key in db_map:
                    tot, blk, cch = db_map[h_key]
                    blocked_counts[idx] = blk
                    cached_counts[idx] = cch
                    allowed_counts[idx] = max(0, tot - blk)
                else:
                    tot = counts[idx] if idx < len(counts) else 0
                    allowed_counts[idx] = tot
            hourly_data = {
                "labels": labels,
                "counts": counts,
                "allowed": allowed_counts,
                "blocked": blocked_counts,
                "cached": cached_counts,
            }
            set_cached_api("hourly_24", hourly_data)

        cat_counts, total_blocked_24h = get_blocked_categories_24h()
        unique_rules = st_data.get("total_unique_rules", len(blocklist_manager.blocked_domains) if blocklist_manager and getattr(blocklist_manager, "blocked_domains", None) is not None else 0)
        raw_rules = st_data.get("total_raw_rules", sum(blocklist_manager.source_counts.values()) if blocklist_manager and hasattr(blocklist_manager, "source_counts") else unique_rules)

        combined = {
            "stats": st_data,
            "hourly": hourly_data,
            "blocked_by_category": cat_counts,
            "categories": cat_counts,
            "total_blocked_24h": total_blocked_24h,
            "total_unique_rules": unique_rules,
            "total_raw_rules": raw_rules,
            "qtype": st_data.get("qtype", {}),
            "latency": st_data.get("latency", {}),
            "cache": st_data.get("cache", {}),
            "upstream": st_data.get("upstream", [])
        }
        set_cached_api("analytics_combined", combined)
        return jsonify(combined)
    except Exception as e:
        logger.error(f"Error in /api/analytics: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500



@app.route("/api/cache/default", methods=["GET"])
def api_cache_default():
    """
    Returns default cache size based on detected host system RAM.
    """
    try:
        ram_gb = get_system_ram_gb()
        default_sz = get_default_cache_size(ram_gb)
        warning = get_cache_warning(default_sz)
        return jsonify({
            "status": "ok",
            "default_size": default_sz,
            "ram_gb": ram_gb,
            "auto_label": f"Auto ({default_sz} for {int(ram_gb)}GB)",
            "warning": warning,
        })
    except Exception as e:
        logger.error(f"Error in /api/cache/default: {e}", exc_info=True)
        return jsonify({"status": "error", "error": str(e), "warning": None}), 500


@app.route("/api/cache/size", methods=["GET", "POST"])
def api_cache_size():
    """
    GET:  Returns current cache size, default size, live entries, and warning field.
    POST: Updates cache max capacity (calls cache.set_max_size), evicting entries if smaller.
    """
    try:
        cache_obj = getattr(stats, "cache_ref", None) or get_cache_instance()
        ram_gb = get_system_ram_gb()
        default_sz = get_default_cache_size(ram_gb)

        if request.method == "POST":
            data = request.get_json(silent=True) or request.form or {}
            raw_size = data.get("size")
            if raw_size is None:
                return jsonify({"status": "error", "message": "Missing 'size' field", "warning": None}), 400

            if str(raw_size).strip().lower() == "auto":
                new_size = default_sz
            else:
                try:
                    new_size = int(raw_size)
                    if new_size <= 0:
                        return jsonify({"status": "error", "message": "Cache size must be positive", "warning": None}), 400
                except (ValueError, TypeError):
                    return jsonify({"status": "error", "message": "Invalid cache size value", "warning": None}), 400

            # Update cache max size (evicts excess entries if smaller)
            if hasattr(cache_obj, "set_max_size"):
                cache_obj.set_max_size(new_size)

            global_inst = get_cache_instance()
            if global_inst and global_inst != cache_obj and hasattr(global_inst, "set_max_size"):
                global_inst.set_max_size(new_size)

            # Persist to config.json if present
            try:
                cfg_file = os.path.join(PROJECT_ROOT, "config.json")
                if os.path.exists(cfg_file):
                    with open(cfg_file, "r", encoding="utf-8") as f:
                        cfg_data = json.load(f)
                    cfg_data["cache_size"] = new_size
                    with open(cfg_file, "w", encoding="utf-8") as f:
                        json.dump(cfg_data, f, indent=4)
            except Exception as err:
                logger.warning(f"Could not persist cache_size to config.json: {err}")

            warning = get_cache_warning(new_size)
            return jsonify({
                "status": "ok",
                "size": new_size,
                "max_size": new_size,
                "default_size": default_sz,
                "entries": len(cache_obj.entries) if hasattr(cache_obj, "entries") else 0,
                "warning": warning,
            })

        # GET request
        current_max = getattr(cache_obj, "max_size", default_sz)
        current_entries = len(cache_obj.entries) if hasattr(cache_obj, "entries") else 0
        warning = get_cache_warning(current_max)

        return jsonify({
            "status": "ok",
            "size": current_max,
            "max_size": current_max,
            "current_entries": current_entries,
            "default_size": default_sz,
            "auto_label": f"Auto ({default_sz} for {int(ram_gb)}GB)",
            "ram_gb": ram_gb,
            "warning": warning,
        })
    except Exception as e:
        logger.error(f"Error in /api/cache/size: {e}", exc_info=True)
        return jsonify({"status": "error", "error": str(e), "warning": None}), 500


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    """Returns current retention_days, anonymize_ip, DB size in MB/KB, total queries."""
    try:
        settings = stats.get_settings()
        db_path = stats.db_path
        db_size_mb = 0.0
        db_size_str = "0 KB"
        total_records = 0

        if db_path != ":memory:" and os.path.exists(db_path):
            try:
                bytes_sz = os.path.getsize(db_path)
                db_size_mb = round(bytes_sz / (1024 * 1024), 2)
                db_size_str = f"{db_size_mb} MB" if db_size_mb >= 1.0 else f"{round(bytes_sz / 1024, 1)} KB"
                conn = sqlite3.connect(db_path, timeout=10)
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM queries")
                row = cur.fetchone()
                total_records = row[0] if row else 0
                conn.close()
            except Exception as e:
                logger.error(f"Error reading DB info: {e}")

        settings["db_size"] = db_size_str
        settings["db_size_mb"] = db_size_mb
        settings["db_size_str"] = db_size_str
        settings["total_records"] = total_records

        cfg_path = os.path.join(PROJECT_ROOT, "config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    settings["client_allowlist_enabled"] = cfg.get("client_allowlist_enabled", True)
                    settings["client_allowlist"] = cfg.get("client_allowlist", ["127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])
                    settings["upstream_validation"] = cfg.get("upstream_validation", True)
                    settings["allowed_upstreams"] = cfg.get("allowed_upstreams", ["8.8.8.8", "1.1.1.1"])
            except Exception:
                pass

        return jsonify(settings)
    except Exception as e:
        logger.error(f"Error in GET /api/settings: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    """Updates retention_days, anonymize_ip, show_full_ip, and/or privacy_mask_public_only."""
    try:
        data = request.get_json(silent=True) or {}
        retention_days = data.get("retention_days")
        anonymize_ip = data.get("anonymize_ip")
        show_full_ip = data.get("show_full_ip")
        privacy_mask_public_only = data.get("privacy_mask_public_only")

        if retention_days is not None:
            try:
                retention_days = int(retention_days)
                if retention_days not in (1, 5, 7, 30, -1):
                    return jsonify({"error": "retention_days must be 1, 5, 7, 30, or -1 (keep all)"}), 400
            except (TypeError, ValueError):
                return jsonify({"error": "retention_days must be an integer"}), 400

        if anonymize_ip is not None:
            anonymize_ip = bool(anonymize_ip)
        if show_full_ip is not None:
            show_full_ip = bool(show_full_ip)
        if privacy_mask_public_only is not None:
            privacy_mask_public_only = bool(privacy_mask_public_only)

        stats.save_settings(
            retention_days=retention_days,
            anonymize_ip=anonymize_ip,
            show_full_ip=show_full_ip,
            privacy_mask_public_only=privacy_mask_public_only
        )

        cfg_path = os.path.join(PROJECT_ROOT, "config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                updated_cfg = False
                if "client_allowlist_enabled" in data:
                    cfg["client_allowlist_enabled"] = bool(data["client_allowlist_enabled"])
                    updated_cfg = True
                if "client_allowlist" in data:
                    val = data["client_allowlist"]
                    if isinstance(val, str):
                        cfg["client_allowlist"] = [line.strip() for line in val.splitlines() if line.strip()]
                    elif isinstance(val, list):
                        cfg["client_allowlist"] = [str(x).strip() for x in val if str(x).strip()]
                    updated_cfg = True
                if "upstream_validation" in data:
                    cfg["upstream_validation"] = bool(data["upstream_validation"])
                    updated_cfg = True
                if "allowed_upstreams" in data:
                    val = data["allowed_upstreams"]
                    if isinstance(val, str):
                        cfg["allowed_upstreams"] = [line.strip() for line in val.splitlines() if line.strip()]
                    elif isinstance(val, list):
                        cfg["allowed_upstreams"] = [str(x).strip() for x in val if str(x).strip()]
                    updated_cfg = True
                if updated_cfg:
                    with open(cfg_path, "w", encoding="utf-8") as f:
                        json.dump(cfg, f, indent=4)
            except Exception as e:
                logger.error(f"Error updating config.json: {e}")

        res_settings = stats.get_settings()
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    res_settings["client_allowlist_enabled"] = cfg.get("client_allowlist_enabled", True)
                    res_settings["client_allowlist"] = cfg.get("client_allowlist", [])
                    res_settings["upstream_validation"] = cfg.get("upstream_validation", True)
                    res_settings["allowed_upstreams"] = cfg.get("allowed_upstreams", [])
            except Exception:
                pass

        invalidate_api_cache()
        return jsonify({"status": "ok", "message": "Saved", "settings": res_settings})
    except Exception as e:
        logger.error(f"Error in POST /api/settings: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/purge", methods=["POST"])
def api_purge():
    """Manually triggers retention purge."""
    try:
        invalidate_api_cache()
        stats.purge_old_logs()
        days_label = "all" if stats.retention_days == -1 else f"{stats.retention_days} day(s)"
        return jsonify({"status": "ok", "message": f"Purged logs older than {days_label}"})
    except Exception as e:
        logger.error(f"Error in /api/purge: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/clear", methods=["GET", "POST"])
def api_clear():
    """Clears all query logs and runs VACUUM to compact database."""
    try:
        invalidate_api_cache()
        stats.clear()
        if stats.db_path != ":memory:" and os.path.exists(stats.db_path):
            try:
                conn = sqlite3.connect(stats.db_path, timeout=10)
                conn.execute("VACUUM")
                conn.close()
            except Exception as e:
                logger.error(f"Error during VACUUM: {e}")
        return jsonify({"status": "ok", "message": "All logs cleared and database compacted"})
    except Exception as e:
        logger.error(f"Error in /api/clear: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# DOMAIN LOOKUP & FILTERING APIS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/check")
def api_check():
    """
    Checks if a domain is blocked.
    Returns: {domain, blocked: bool, category: "ads"|"trackers"|"malware"|"custom"|null, source: "blocklist name"}
    """
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "domain parameter required"}), 400

    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()
    is_blocked, category = blocklist_manager.is_blocked(clean_domain)

    source = None
    if is_blocked:
        source_map = {
            "ads": "blocklists/ads.txt",
            "trackers": "blocklists/trackers.txt",
            "malware": "blocklists/malware.txt",
            "custom": "blocklists/custom.txt",
        }
        source = source_map.get(category, f"blocklists/{category}.txt" if category else "Blocklist")
    else:
        curr = clean_domain
        while curr:
            if curr in blocklist_manager.allowed_domains:
                source = "allowlist.txt"
                break
            dot = curr.find(".")
            if dot == -1:
                break
            curr = curr[dot + 1:]

    # Update watchlist hit if checked via Domain Lookup
    if watchlist_manager.is_in_watchlist(clean_domain):
        watchlist_manager.record_hit(clean_domain)

    return jsonify({
        "domain": clean_domain,
        "blocked": bool(is_blocked),
        "category": category,
        "source": source
    })


@app.route("/api/blocklist/sources", methods=["GET", "POST"])
def api_blocklist_sources():
    """
    GET:  Returns dict of active sources status, counts dict, and blocklist_size:
          {"ads.txt": true, "trackers.txt": true, "malware.txt": false, ... , counts: {"ads.txt": 234386, ...}}
    POST: Accepts {source: "ads.txt", enabled: false}
          Updates active_blocklists, reloads blocklist with active filter, returns new blocklist_size.
    """
    try:
        if request.method == "POST":
            data = request.get_json(silent=True) or request.form or {}
            source = data.get("source") or data.get("name")
            if not source:
                return jsonify({"status": "error", "message": "Missing 'source' parameter"}), 400

            norm_source = str(source).strip()
            if not norm_source.endswith(".txt"):
                norm_source += ".txt"

            if norm_source not in ("ads.txt", "trackers.txt", "malware.txt", "custom.txt"):
                return jsonify({"status": "error", "message": f"Unknown blocklist source: {source}"}), 400

            enabled_val = data.get("enabled")
            if enabled_val is None:
                current_active = blocklist_manager.get_active_sources()
                enabled = not current_active.get(norm_source, True)
            elif isinstance(enabled_val, str):
                enabled = enabled_val.strip().lower() not in ("false", "0", "off", "no")
            else:
                enabled = bool(enabled_val)

            new_size = blocklist_manager.set_source_active(norm_source, enabled)
            try:
                from dns.cache import get_cache_instance
                get_cache_instance().clear()
                print(f"[BLOCKLIST] Cache cleared after toggle {norm_source} enabled={enabled}")
            except Exception:
                pass

            active = blocklist_manager.get_active_sources()
            counts = getattr(blocklist_manager, "source_counts", {})
            if not counts:
                for k in ["ads.txt", "trackers.txt", "malware.txt", "custom.txt"]:
                    counts[k] = len(blocklist_manager.source_domains.get(k, {}))

            total_rules = sum(counts.values()) if counts else 290396

            resp = dict(active)
            resp["status"] = "ok"
            resp["source"] = norm_source
            resp["enabled"] = enabled
            resp["new_blocklist_size"] = new_size
            resp["blocklist_size"] = new_size
            resp["total_rules"] = total_rules
            resp["total_unique"] = new_size
            resp["counts"] = counts
            return jsonify(resp)

        # GET request
        active = blocklist_manager.get_active_sources()
        counts = getattr(blocklist_manager, "source_counts", {})
        if not counts:
            for k in ["ads.txt", "trackers.txt", "malware.txt", "custom.txt"]:
                counts[k] = len(blocklist_manager.source_domains.get(k, {}))

        total_rules = sum(counts.values()) if counts else 290396
        current_size = len(blocklist_manager.blocked_domains)

        resp = dict(active)
        resp["counts"] = counts
        resp["blocklist_size"] = current_size
        resp["total_unique"] = current_size
        resp["total_rules"] = total_rules
        return jsonify(resp)
    except Exception as e:
        logger.error(f"Error in /api/blocklist/sources: {e}", exc_info=True)
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/blocklists", methods=["GET", "POST"])
def api_blocklists():
    """
    GET: Returns list of 4 blocklists: ads, trackers, malware, custom with real counts and last_updated.
    POST: Toggles enable/disable of a blocklist file.
    """
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form or {}
        name = (data.get("name") or data.get("source") or "").strip()
        enabled = data.get("enabled", True)

        if name and not name.endswith(".txt"):
            name = name + ".txt"

        if not name or name not in ["ads.txt", "trackers.txt", "malware.txt", "custom.txt"]:
            return jsonify({"error": "Invalid blocklist name"}), 400

        if isinstance(enabled, str):
            enabled = enabled.strip().lower() not in ("false", "0", "off", "no")
        else:
            enabled = bool(enabled)

        new_size = blocklist_manager.set_source_active(name, enabled)
        invalidate_api_cache()
        try:
            from dns.cache import get_cache_instance
            get_cache_instance().clear()
            print(f"[BLOCKLIST] Cache cleared after toggle {name} enabled={enabled}")
        except Exception:
            pass
        return jsonify({
            "status": "ok",
            "name": name,
            "source": name,
            "enabled": enabled,
            "new_blocklist_size": new_size,
            "blocklist_size": new_size,
        })

    # GET logic
    categories_info = [
        {"name": "ads.txt", "category": "ads", "title": "Advertising & Telemetry", "color": "amber", "badge": "Ads"},
        {"name": "trackers.txt", "category": "trackers", "title": "Behavioral Trackers", "color": "rose", "badge": "Trackers"},
        {"name": "malware.txt", "category": "malware", "title": "Malware & Phishing", "color": "purple", "badge": "Malware"},
        {"name": "custom.txt", "category": "custom", "title": "Custom Blacklist", "color": "blue", "badge": "Custom"},
    ]

    result = []
    total_loaded = 0
    active_sources = blocklist_manager.get_active_sources()

    for info in categories_info:
        file_path = os.path.join(blocklist_dir, info["name"])
        count = blocklist_manager.source_counts.get(info["name"], 0)
        mtime_str = "Never"
        file_size_str = "0 B"

        if os.path.exists(file_path):
            try:
                mtime = os.path.getmtime(file_path)
                mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                size_b = os.path.getsize(file_path)
                file_size_str = f"{round(size_b / (1024*1024), 2)} MB" if size_b >= 1024*1024 else f"{round(size_b/1024, 1)} KB"

                if count == 0:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and not line.startswith("!"):
                                count += 1
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")

        total_loaded += count
        enabled = active_sources.get(info["name"], True)

        result.append({
            "name": info["name"],
            "category": info["category"],
            "title": info["title"],
            "badge": info["badge"],
            "color": info["color"],
            "count": count,
            "enabled": enabled,
            "last_updated": mtime_str,
            "size_str": file_size_str,
        })

    total_unique = len(blocklist_manager.blocked_domains) if (blocklist_manager and len(blocklist_manager.blocked_domains) > 0) else total_loaded

    return jsonify({
        "blocklists": result,
        "total_rules": total_loaded,
        "total_raw_rules": total_loaded,
        "total_unique": total_unique,
        "total_unique_rules": total_unique
    })


@app.route("/api/blocklists/toggle", methods=["POST"])
def api_blocklists_toggle():
    """Toggle enable/disable for a blocklist file (convenience endpoint)."""
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()

    if not name or name not in ["ads.txt", "trackers.txt", "malware.txt", "custom.txt"]:
        return jsonify({"error": "Invalid blocklist name"}), 400

    if name in disabled_blocklists:
        disabled_blocklists.remove(name)
        enabled = True
    else:
        disabled_blocklists.add(name)
        enabled = False

    blocklist_manager.reload(blocklist_dir, allowlist_path)
    invalidate_api_cache()
    return jsonify({"status": "ok", "name": name, "enabled": enabled})


@app.route("/api/allowlist", methods=["GET", "POST", "DELETE"])
def api_allowlist():
    """Manage allowlist.txt: GET list, POST add, DELETE remove."""
    if request.method == "GET":
        domains = []
        if os.path.exists(allowlist_path):
            try:
                with open(allowlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split()
                            d = parts[0] if parts else line
                            domains.append(d.lower())
            except Exception as e:
                logger.error(f"Error reading allowlist: {e}")

        unique_domains = list(dict.fromkeys(domains))
        return jsonify({"domains": unique_domains, "total": len(unique_domains)})

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        domain = data.get("domain", "").strip()
        if not domain:
            return jsonify({"error": "domain is required"}), 400

        clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()

        existing = set()
        if os.path.exists(allowlist_path):
            with open(allowlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if parts:
                            existing.add(parts[0].lower())

        if clean_domain not in existing:
            with open(allowlist_path, "a", encoding="utf-8") as f:
                f.write(f"\n{clean_domain}\n")

        blocklist_manager.add_to_allowlist(clean_domain)
        invalidate_api_cache()
        try:
            get_cache_instance().clear()
        except Exception:
            pass
        return jsonify({
            "status": "ok",
            "message": f"'{clean_domain}' added to allowlist",
            "domain": clean_domain
        })

    if request.method == "DELETE":
        domain = request.args.get("domain", "").strip()
        if not domain:
            data = request.get_json(silent=True) or {}
            domain = data.get("domain", "").strip()
        if not domain:
            return jsonify({"error": "domain is required"}), 400

        clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()

        if os.path.exists(allowlist_path):
            lines = []
            with open(allowlist_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    raw = line.strip()
                    if raw and not raw.startswith("#"):
                        parts = raw.split()
                        if parts and parts[0].lower() == clean_domain:
                            continue
                    lines.append(line)

            with open(allowlist_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

        blocklist_manager.remove_from_allowlist(clean_domain)
        invalidate_api_cache()
        return jsonify({
            "status": "ok",
            "message": f"'{clean_domain}' removed from allowlist",
            "domain": clean_domain
        })


@app.route("/api/blocklist", methods=["POST"])
def api_blocklist_post():
    """Adds a domain to blocklists/custom.txt and in-memory blocklist manager."""
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    category = data.get("category", "custom").strip()
    if not domain:
        return jsonify({"error": "domain is required"}), 400

    clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()
    custom_path = os.path.join(blocklist_dir, "custom.txt")

    existing = set()
    if os.path.exists(custom_path):
        with open(custom_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if parts:
                        existing.add(parts[0].lower())

    if clean_domain not in existing:
        with open(custom_path, "a", encoding="utf-8") as f:
            f.write(f"\n{clean_domain}\n")

    blocklist_manager.add_domain(clean_domain, category=category)
    invalidate_api_cache()
    return jsonify({
        "status": "ok",
        "message": f"'{clean_domain}' added to custom blocklist",
        "domain": clean_domain
    })


@app.route("/api/categories")
def api_categories():
    """Returns 24h blocked-by-category distribution for analytics (cached 2.0s)."""
    cached = get_cached_api("categories_24h", ttl=2.0)
    if cached is not None:
        return jsonify(cached)
    cat_counts, total_blocked_24h = get_blocked_categories_24h()
    unique_rules = len(blocklist_manager.blocked_domains) if blocklist_manager and getattr(blocklist_manager, "blocked_domains", None) is not None else 0
    raw_rules = sum(blocklist_manager.source_counts.values()) if blocklist_manager and hasattr(blocklist_manager, "source_counts") else unique_rules
    res = {
        "blocked_by_category": cat_counts,
        "categories": cat_counts,
        "total": total_blocked_24h,
        "total_blocked_24h": total_blocked_24h,
        "total_unique_rules": unique_rules,
        "total_raw_rules": raw_rules,
    }
    set_cached_api("categories_24h", res)
    return jsonify(res)


@app.route("/api/watchlist", methods=["GET", "POST", "DELETE"])
def api_watchlist():
    """
    Manage pinned watchlist:
      GET    → [{domain, added_at, last_hit, cache_status}], total
      POST   → {input: "YouTube"} or {domain: "YouTube"} -> normalizes and pins
      DELETE → {domain: "youtube.com"} or ?domain=... -> unpins and evicts
    """
    cache_obj = get_cache_instance()

    if request.method == "GET":
        items = watchlist_manager.get_all(cache_obj)
        return jsonify({
            "watchlist": items,
            "items": items,
            "total": len(items)
        })

    if request.method == "POST":
        data = request.get_json(silent=True) or request.form or {}
        raw_input = data.get("input", data.get("domain", "")).strip()
        if not raw_input:
            return jsonify({
                "status": "error",
                "error": "Domain input cannot be empty",
                "message": "Domain input cannot be empty"
            }), 400

        success, msg, entry = watchlist_manager.add(raw_input, cache_obj)
        invalidate_api_cache()
        if not success:
            suggestion = entry.get("suggestion") if isinstance(entry, dict) else None
            domain_name = entry.get("domain", raw_input) if isinstance(entry, dict) else raw_input
            return jsonify({
                "status": "error",
                "error": msg,
                "message": msg,
                "domain": domain_name,
                "suggestion": suggestion,
            }), 400

        return jsonify({
            "status": "ok",
            "message": msg,
            "domain": entry["domain"],
            "item": entry
        })

    if request.method == "DELETE":
        domain = request.args.get("domain", "").strip()
        if not domain:
            data = request.get_json(silent=True) or request.form or {}
            domain = data.get("domain", "").strip()
        if not domain:
            return jsonify({
                "status": "error",
                "error": "Domain is required",
                "message": "Domain is required"
            }), 400

        success, msg = watchlist_manager.remove(domain, cache_obj)
        invalidate_api_cache()
        if not success:
            return jsonify({
                "status": "error",
                "error": msg,
                "message": msg,
                "domain": domain
            }), 404

        return jsonify({
            "status": "ok",
            "message": msg,
            "domain": domain
        })


@app.route("/api/watchlist/suggest")
def api_watchlist_suggest():
    """Returns Google-like matching domain suggestions for autocomplete."""
    q = request.args.get("q", "").strip().lower()
    return jsonify(get_suggestions(q))


@app.route("/api/watchlist/fix", methods=["POST"])
def api_watchlist_fix():
    """Fixes an invalid domain in watchlist to its suggested real domain."""
    data = request.get_json(silent=True) or request.form or {}
    old_domain = data.get("old_domain", "").strip().lower()
    new_domain = data.get("new_domain", "").strip().lower()
    if not old_domain or not new_domain:
        return jsonify({"status": "error", "message": "Missing old_domain or new_domain"}), 400

    cache_obj = get_cache_instance()
    watchlist_manager.remove(old_domain, cache_obj)
    success, msg, entry = watchlist_manager.add(new_domain, cache_obj)
    invalidate_api_cache()
    if not success:
        return jsonify({"status": "error", "message": msg}), 400
    return jsonify({
        "status": "ok",
        "message": f"Fixed {old_domain} -> {new_domain}",
        "domain": new_domain,
        "item": entry
    })


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def main():
    check_port_53()
    print("=" * 60)
    print("  DNS Shield Dashboard  ->  http://localhost:8081")
    print("  DNS Server Port       ->  53")
    print("=" * 60)
    app.run(host="0.0.0.0", port=8081, debug=True, use_reloader=False)


if __name__ == "__main__":
    main()
