"""
tests/test_retention.py — Unit and integration tests for Retention & Hourly Aggregation
========================================================================================
1. purge_old_logs():
   - DELETE FROM queries WHERE timestamp < datetime('now', '-5 days')
   - Run on /api/stats call and midnight timer
   - VACUUM if DB > 50MB
2. query_stats_hourly:
   - hour TEXT, total INT, blocked INT, cached INT
   - Every hour, aggregate from queries and insert
   - Dashboard graph reads from query_stats_hourly
3. Settings:
   - Retention: 1, 5, 7, 30, Keep All (-1)
   - Clear All Logs
   - Anonymize Client IP (127.0.0.1 -> xxx.xxx.xxx.1)
"""
import os
import sys
import unittest
import tempfile
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.stats import DNSStats, KEEP_ALL
from dns.dashboard import app


class TestRetentionAndHourly(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.tmp.name
        self.tmp.close()
        self.stats = DNSStats(db_path=self.db_path)

    def tearDown(self):
        if hasattr(self.stats, "_midnight_timer") and self.stats._midnight_timer:
            self.stats._midnight_timer.cancel()
        if hasattr(self.stats, "_hourly_timer") and self.stats._hourly_timer:
            self.stats._hourly_timer.cancel()
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except Exception:
            pass

    def test_purge_old_logs_deletes_past_cutoff(self):
        """Verify queries older than retention_days are removed, recent are kept."""
        now = datetime.now()
        conn = self.stats._get_conn()

        # Insert query from 7 days ago
        t_old = (now - timedelta(days=7)).isoformat()
        conn.execute(
            "INSERT INTO queries (timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream) VALUES (?,?,?,?,?,?,?,?)",
            (t_old, "old-site.com", "127.0.0.1", "A", 0, 0, 10.0, "8.8.8.8")
        )

        # Insert query from 1 hour ago
        t_recent = (now - timedelta(hours=1)).isoformat()
        conn.execute(
            "INSERT INTO queries (timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream) VALUES (?,?,?,?,?,?,?,?)",
            (t_recent, "recent-site.com", "127.0.0.1", "A", 0, 1, 1.0, "")
        )
        conn.commit()

        # Before purge
        c_before = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        self.assertEqual(c_before, 2)

        # Purge with 5-day retention
        self.stats.save_settings(retention_days=5)
        self.stats.purge_old_logs()

        c_after = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        self.assertEqual(c_after, 1)

        row = conn.execute("SELECT domain FROM queries").fetchone()
        self.assertEqual(row[0], "recent-site.com")
        self.stats._close_conn(conn)

    def test_purge_runs_on_get_stats(self):
        """Calling get_stats() should automatically purge old logs."""
        now = datetime.now()
        conn = self.stats._get_conn()
        t_old = (now - timedelta(days=10)).isoformat()
        conn.execute(
            "INSERT INTO queries (timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream) VALUES (?,?,?,?,?,?,?,?)",
            (t_old, "expired.com", "127.0.0.1", "A", 0, 0, 15.0, "8.8.8.8")
        )
        conn.commit()
        self.stats._close_conn(conn)

        self.stats.save_settings(retention_days=5)
        # Calling get_stats triggers purge
        res = self.stats.get_stats()

        conn = self.stats._get_conn()
        c = conn.execute("SELECT COUNT(*) FROM queries WHERE domain='expired.com'").fetchone()[0]
        self.stats._close_conn(conn)
        self.assertEqual(c, 0, "Old query was not purged on get_stats() call")

    def test_keep_all_retention(self):
        """KEEP_ALL (-1) should not delete any logs."""
        now = datetime.now()
        conn = self.stats._get_conn()
        t_old = (now - timedelta(days=60)).isoformat()
        conn.execute(
            "INSERT INTO queries (timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream) VALUES (?,?,?,?,?,?,?,?)",
            (t_old, "ancient.com", "127.0.0.1", "A", 0, 0, 12.0, "8.8.8.8")
        )
        conn.commit()
        self.stats._close_conn(conn)

        self.stats.save_settings(retention_days=-1)
        self.stats.purge_old_logs()

        conn = self.stats._get_conn()
        c = conn.execute("SELECT COUNT(*) FROM queries WHERE domain='ancient.com'").fetchone()[0]
        self.stats._close_conn(conn)
        self.assertEqual(c, 1)

    def test_query_stats_hourly_table_creation_and_aggregation(self):
        """Test query_stats_hourly table schema and aggregation."""
        conn = self.stats._get_conn()
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(query_stats_hourly)")
        cols = {r[1]: r[2] for r in cur.fetchall()}
        self.assertIn("hour", cols)
        self.assertIn("total", cols)
        self.assertIn("blocked", cols)
        self.assertIn("cached", cols)

        # Add queries across 2 different hours
        h1 = (datetime.now() - timedelta(hours=2)).replace(minute=15).isoformat()
        h2 = (datetime.now() - timedelta(hours=1)).replace(minute=20).isoformat()

        conn.execute(
            "INSERT INTO queries (timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream) VALUES (?,?,?,?,?,?,?,?)",
            (h1, "blocked.com", "127.0.0.1", "A", 1, 0, 0.5, "0.0.0.0")
        )
        conn.execute(
            "INSERT INTO queries (timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream) VALUES (?,?,?,?,?,?,?,?)",
            (h1, "cached.com", "127.0.0.1", "A", 0, 1, 0.2, "")
        )
        conn.execute(
            "INSERT INTO queries (timestamp, domain, client_ip, qtype, blocked, cached, latency_ms, upstream) VALUES (?,?,?,?,?,?,?,?)",
            (h2, "fwd.com", "127.0.0.1", "A", 0, 0, 25.0, "8.8.8.8")
        )
        conn.commit()

        # Run aggregate_hourly
        self.stats.aggregate_hourly()

        # Check hourly table rows
        rows = conn.execute("SELECT hour, total, blocked, cached FROM query_stats_hourly ORDER BY hour ASC").fetchall()
        self.assertEqual(len(rows), 2)
        # Hour 1 has 2 queries: 1 blocked, 1 cached
        self.assertEqual(rows[0][1], 2)
        self.assertEqual(rows[0][2], 1)
        self.assertEqual(rows[0][3], 1)
        # Hour 2 has 1 query: 0 blocked, 0 cached
        self.assertEqual(rows[1][1], 1)
        self.assertEqual(rows[1][2], 0)
        self.assertEqual(rows[1][3], 0)

        # Graph should read from query_stats_hourly
        labels, counts = self.stats.get_hourly_graph(hours=24)
        self.assertEqual(len(labels), 24)
        self.assertEqual(len(counts), 24)
        self.assertEqual(sum(counts), 3)
        self.stats._close_conn(conn)

    def test_anonymize_client_ip(self):
        """Toggle: Anonymize Client IP policy (private full, public masked)."""
        # When Show Full IP is enabled (anonymize_ip=False):
        self.stats.save_settings(anonymize_ip=False, show_full_ip=True, privacy_mask_public_only=True)
        self.assertEqual(self.stats._maybe_anonymize("127.0.0.1"), "127.0.0.1")
        self.assertEqual(self.stats._maybe_anonymize("192.168.1.55"), "192.168.1.55")
        self.assertEqual(self.stats._maybe_anonymize("8.8.8.8"), "8.8.8.8")

        # When privacy masking is active (default: privacy_mask_public_only=True, show_full_ip=False):
        self.stats.save_settings(anonymize_ip=True, show_full_ip=False, privacy_mask_public_only=True)
        # Private/localhost IPs remain FULL IP
        self.assertEqual(self.stats._maybe_anonymize("127.0.0.1"), "127.0.0.1")
        self.assertEqual(self.stats._maybe_anonymize("192.168.1.55"), "192.168.1.55")
        self.assertEqual(self.stats._maybe_anonymize("10.0.0.254"), "10.0.0.254")
        # Public IPs get masked
        self.assertEqual(self.stats._maybe_anonymize("8.8.8.8"), "xxx.xxx.xxx.8")
        self.assertEqual(self.stats._maybe_anonymize("1.1.1.1"), "xxx.xxx.xxx.1")

        # Logs should show full IP for private client
        self.stats.add("privacy-test.org", client_ip="127.0.0.1", qtype="A", blocked=False)
        logs = self.stats.get_logs(limit=5)
        self.assertEqual(logs[0]["client"], "127.0.0.1")

        # Public client in logs should be masked
        self.stats.add("privacy-test-public.org", client_ip="8.8.8.8", qtype="A", blocked=False)
        logs_pub = self.stats.get_logs(limit=5)
        self.assertEqual(logs_pub[0]["client"], "xxx.xxx.xxx.8")

        # If legacy full masking is forced (privacy_mask_public_only=False):
        self.stats.save_settings(anonymize_ip=True, show_full_ip=False, privacy_mask_public_only=False)
        self.assertEqual(self.stats._maybe_anonymize("127.0.0.1"), "xxx.xxx.xxx.1")
        self.assertEqual(self.stats._maybe_anonymize("8.8.8.8"), "xxx.xxx.xxx.8")

    def test_clear_all_logs(self):
        """Button: Clear All Logs Now should clear queries and hourly table."""
        self.stats.add("site1.com", blocked=True)
        self.stats.add("site2.com", cached=True)
        self.stats.aggregate_hourly()

        conn = self.stats._get_conn()
        c_q = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        c_h = conn.execute("SELECT COUNT(*) FROM query_stats_hourly").fetchone()[0]
        self.stats._close_conn(conn)
        self.assertGreater(c_q, 0)
        self.assertGreater(c_h, 0)

        self.stats.clear()

        conn = self.stats._get_conn()
        c_q_after = conn.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
        c_h_after = conn.execute("SELECT COUNT(*) FROM query_stats_hourly").fetchone()[0]
        self.stats._close_conn(conn)
        self.assertEqual(c_q_after, 0)
        self.assertEqual(c_h_after, 0)


class TestDashboardSettingsEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_settings_api_get_and_post(self):
        # GET default settings
        res = self.client.get("/api/settings")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("retention_days", data)
        self.assertIn("anonymize_ip", data)

        # POST valid settings: 1, 5, 7, 30, -1
        for val in (1, 5, 7, 30, -1):
            post_res = self.client.post("/api/settings", json={"retention_days": val, "anonymize_ip": True})
            self.assertEqual(post_res.status_code, 200)
            self.assertEqual(post_res.get_json()["settings"]["retention_days"], val)
            self.assertEqual(post_res.get_json()["settings"]["anonymize_ip"], True)

        # POST invalid retention
        bad_res = self.client.post("/api/settings", json={"retention_days": 42})
        self.assertEqual(bad_res.status_code, 400)

    def test_api_hourly(self):
        res = self.client.get("/api/hourly?hours=24")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("labels", data)
        self.assertIn("counts", data)
        self.assertEqual(len(data["labels"]), 24)
        self.assertEqual(len(data["counts"]), 24)

    def test_api_clear(self):
        res = self.client.get("/api/clear")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "ok")


if __name__ == "__main__":
    unittest.main()
