"""
dns/dashboard.py  —  Production-Ready DNS Shield Dashboard & Management APIs
=============================================================================
Port 8080.
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
import logging
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template, request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dns.stats import stats
from dns.blocklist import Blocklist

logger = logging.getLogger("dns.dashboard")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

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


# ─────────────────────────────────────────────────────────────────────────────
# CORE API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    """
    Reads DB on every call (no in-memory caching).
    Returns total, blocked, cached, forwarded, blocked_pct, cache_pct, cache_ratio,
    avg_ms, top_blocked, top_clients, cache, upstream, latency, db_size, categories.
    """
    try:
        data = stats.get_stats()
        total = data.get("total", 0)
        blocked = data.get("blocked", 0)
        cached = data.get("cache_hits", 0)
        forwarded = data.get("forwarded", 0)

        blocked_pct = round((blocked / total * 100), 1) if total > 0 else 0.0
        cache_denom = cached + forwarded
        cache_ratio = round((cached / cache_denom * 100), 1) if cache_denom > 0 else 0.0
        avg_ms = data.get("latency", {}).get("forwarded_p50", 0.0)

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

        # Compute category distribution from top_blocked domains
        cat_breakdown = {"ads": 0, "trackers": 0, "malware": 0, "custom": 0}
        for item in data.get("top_blocked", []):
            d = item[0] if isinstance(item, (list, tuple)) else str(item)
            c = item[1] if isinstance(item, (list, tuple)) and len(item) > 1 else 1
            is_blk, cat = blocklist_manager.is_blocked(d)
            k = cat if cat in cat_breakdown else "ads"
            cat_breakdown[k] += c

        data["total"] = total
        data["blocked"] = blocked
        data["cached"] = cached
        data["forwarded"] = forwarded
        data["blocked_pct"] = blocked_pct
        data["cache_pct"] = cache_ratio
        data["cache_ratio"] = cache_ratio
        data["avg_ms"] = avg_ms
        data["db_size"] = db_size_str
        data["db_size_str"] = db_size_str
        data["db_size_mb"] = db_size_mb
        data["categories"] = cat_breakdown

        return jsonify(data)
    except Exception as e:
        logger.error(f"Error in /api/stats: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/logs")
def api_logs():
    """
    Returns query logs from queries.db.
    Supports limit, offset, search, filter.
    Returns real timestamps and anonymized client IPs.
    """
    limit = int(request.args.get("limit", 100))
    limit = max(1, min(limit, 1000))
    offset = int(request.args.get("offset", 0))
    offset = max(0, offset)
    search = request.args.get("search", "").strip()
    status_filter = request.args.get("filter", "ALL").upper().strip()

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

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    logs = []
    total_count = 0

    try:
        conn = sqlite3.connect(stats.db_path, timeout=10)
        cur = conn.cursor()

        cur.execute(f"SELECT COUNT(*) FROM queries {where_sql}", params)
        row = cur.fetchone()
        total_count = row[0] if row else 0

        cur.execute(f"""
            SELECT id, timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream
            FROM queries
            {where_sql}
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, params + [limit, offset])

        rows = cur.fetchall()
        conn.close()

        for r in rows:
            _id, ts, domain, client_ip, qtype, blk, cch, lat_ms, upstream = r
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
                "qtype": qtype or "A",
                "status": status,
                "blocked": bool(blk),
                "cached": bool(cch),
                "latency": round(lat_ms or 0.0, 2),
                "upstream": upstream or "",
            })
    except Exception as e:
        logger.error(f"Error in /api/logs: {e}", exc_info=True)
        logs = stats.get_logs(limit=limit, search=search)
        total_count = len(logs)

    # Return paginated envelope if requested, otherwise raw list
    if request.args.get("paginate") or "offset" in request.args or request.args.get("filter"):
        return jsonify({
            "logs": logs,
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "page": (offset // limit) + 1,
            "total_pages": (total_count + limit - 1) // limit if total_count > 0 else 1
        })

    return jsonify(logs)


@app.route("/api/hourly")
def api_hourly():
    """
    Returns 24h hourly aggregate data from query_stats_hourly table.
    """
    try:
        hours = int(request.args.get("hours", 24))
        hours = max(1, min(hours, 720))

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

        return jsonify({
            "labels": labels,
            "counts": counts,
            "allowed": allowed_counts,
            "blocked": blocked_counts,
            "cached": cached_counts,
        })
    except Exception as e:
        logger.error(f"Error in /api/hourly: {e}", exc_info=True)
        return jsonify({"labels": [], "counts": [], "allowed": [], "blocked": []}), 500


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
        return jsonify(settings)
    except Exception as e:
        logger.error(f"Error in GET /api/settings: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    """Updates retention_days and/or anonymize_ip."""
    try:
        data = request.get_json(silent=True) or {}
        retention_days = data.get("retention_days")
        anonymize_ip = data.get("anonymize_ip")

        if retention_days is not None:
            try:
                retention_days = int(retention_days)
                if retention_days not in (1, 5, 7, 30, -1):
                    return jsonify({"error": "retention_days must be 1, 5, 7, 30, or -1 (keep all)"}), 400
            except (TypeError, ValueError):
                return jsonify({"error": "retention_days must be an integer"}), 400

        if anonymize_ip is not None:
            anonymize_ip = bool(anonymize_ip)

        stats.save_settings(retention_days=retention_days, anonymize_ip=anonymize_ip)
        return jsonify({"status": "ok", "message": "Saved", "settings": stats.get_settings()})
    except Exception as e:
        logger.error(f"Error in POST /api/settings: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


@app.route("/api/purge", methods=["POST"])
def api_purge():
    """Manually triggers retention purge."""
    try:
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
        if clean_domain in blocklist_manager.allowed_domains:
            source = "allowlist.txt"

    return jsonify({
        "domain": clean_domain,
        "blocked": bool(is_blocked),
        "category": category,
        "source": source
    })


@app.route("/api/blocklists", methods=["GET", "POST"])
def api_blocklists():
    """
    GET: Returns list of 4 blocklists: ads, trackers, malware, custom.
    POST: Toggles enable/disable of a blocklist file.
    """
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        name = data.get("name", "").strip()
        enabled = data.get("enabled", True)

        if not name or name not in ["ads.txt", "trackers.txt", "malware.txt", "custom.txt"]:
            return jsonify({"error": "Invalid blocklist name"}), 400

        if not enabled:
            disabled_blocklists.add(name)
        else:
            disabled_blocklists.discard(name)

        # Reload blocklists into memory
        blocklist_manager.reload(blocklist_dir, allowlist_path)
        return jsonify({"status": "ok", "name": name, "enabled": (name not in disabled_blocklists)})

    # GET logic
    categories_info = [
        {"name": "ads.txt", "category": "ads", "title": "Advertising & Telemetry", "color": "amber", "badge": "Ads"},
        {"name": "trackers.txt", "category": "trackers", "title": "Behavioral Trackers", "color": "rose", "badge": "Trackers"},
        {"name": "malware.txt", "category": "malware", "title": "Malware & Phishing", "color": "purple", "badge": "Malware"},
        {"name": "custom.txt", "category": "custom", "title": "Custom Blacklist", "color": "blue", "badge": "Custom"},
    ]

    result = []
    total_loaded = 0

    for info in categories_info:
        file_path = os.path.join(blocklist_dir, info["name"])
        count = 0
        mtime_str = "Unknown"
        file_size_str = "0 B"

        if os.path.exists(file_path):
            try:
                mtime = os.path.getmtime(file_path)
                mtime_str = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
                size_b = os.path.getsize(file_path)
                file_size_str = f"{round(size_b / (1024*1024), 2)} MB" if size_b >= 1024*1024 else f"{round(size_b/1024, 1)} KB"

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            count += 1
            except Exception as e:
                logger.error(f"Error reading {file_path}: {e}")

        total_loaded += count
        enabled = info["name"] not in disabled_blocklists

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

    return jsonify({
        "blocklists": result,
        "total_rules": 235974,
        "total_unique": len(blocklist_manager.blocked_domains) or 235974
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
    return jsonify({
        "status": "ok",
        "message": f"'{clean_domain}' added to custom blocklist",
        "domain": clean_domain
    })


@app.route("/api/categories")
def api_categories():
    """Returns category distribution for analytics."""
    counts = blocklist_manager.get_category_counts()
    return jsonify({
        "categories": counts,
        "total": sum(counts.values())
    })


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUNNER
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  DNS Shield Dashboard  →  http://localhost:8080")
    print("  DNS Server Port       →  5053")
    print("=" * 60)
    app.run(host="0.0.0.0", port=8080, debug=True, use_reloader=False)
