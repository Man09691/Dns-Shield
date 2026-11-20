"""
tests/test_dashboard_production.py  —  Unit & Integration tests for rebuilt Dashboard UI & APIs
"""
import os
import sys
import json
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.dashboard import app, stats


class TestDashboardProduction(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_pages_render_html(self):
        """Verify all 7 pages render HTTP 200 with proper HTML."""
        routes = [
            ("/", "DNS SHIELD"),
            ("/logs", "Query Logs"),
            ("/lookup", "Domain Blocklist Inspector"),
            ("/blocklists", "Active Blocklists"),
            ("/allowlist", "Trusted Allowlist"),
            ("/analytics", "DNS Analytics"),
            ("/settings", "System Settings"),
        ]
        for url, expected_text in routes:
            res = self.client.get(url)
            self.assertEqual(res.status_code, 200, f"Route {url} failed with status {res.status_code}")
            html = res.get_data(as_text=True)
            self.assertIn(expected_text, html, f"Expected text '{expected_text}' not found in {url}")
            self.assertIn("DNS SHIELD", html)
            self.assertIn("53", html)

    def test_api_stats_schema(self):
        """Verify /api/stats schema and required keys."""
        res = self.client.get("/api/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        # Check required fields
        for key in ["total", "blocked", "cached", "forwarded", "blocked_pct", "cache_pct", "avg_ms", "top_blocked", "top_clients"]:
            self.assertIn(key, data, f"Key '{key}' missing from /api/stats")

        # Check nested objects
        self.assertIn("cache", data)
        self.assertIn("upstream", data)
        self.assertIn("latency", data)
        self.assertGreaterEqual(data["blocklist_size"], 235974)

    def test_api_logs(self):
        """Verify /api/logs returns list or paginated object."""
        res = self.client.get("/api/logs?limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(isinstance(data, list))

        # Test paginated call
        res_paginated = self.client.get("/api/logs?limit=10&offset=0&paginate=1")
        self.assertEqual(res_paginated.status_code, 200)
        p_data = res_paginated.get_json()
        self.assertIn("logs", p_data)
        self.assertIn("total", p_data)
        self.assertIn("limit", p_data)
        self.assertIn("offset", p_data)

    def test_api_hourly(self):
        """Verify /api/hourly returns 24h data."""
        res = self.client.get("/api/hourly?hours=24")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("labels", data)
        self.assertIn("counts", data)
        self.assertEqual(len(data["labels"]), 24)

    def test_api_check_domain(self):
        """Verify /api/check identifies blocked and allowed domains."""
        # connect.facebook.net -> blocked (tracker)
        res_tracker = self.client.get("/api/check?domain=connect.facebook.net")
        self.assertEqual(res_tracker.status_code, 200)
        data_tracker = res_tracker.get_json()
        self.assertEqual(data_tracker["domain"], "connect.facebook.net")
        self.assertTrue(data_tracker["blocked"])
        self.assertEqual(data_tracker["category"], "trackers")

        # facebook.com -> allowed (main site)
        res_fb = self.client.get("/api/check?domain=facebook.com")
        self.assertEqual(res_fb.status_code, 200)
        data_fb = res_fb.get_json()
        self.assertEqual(data_fb["domain"], "facebook.com")
        self.assertFalse(data_fb["blocked"])

        # google.com -> allowed
        res_google = self.client.get("/api/check?domain=google.com")
        self.assertEqual(res_google.status_code, 200)
        data_google = res_google.get_json()
        self.assertEqual(data_google["domain"], "google.com")
        self.assertFalse(data_google["blocked"])

    def test_api_blocklists(self):
        """Verify /api/blocklists returns 4 lists and total count."""
        res = self.client.get("/api/blocklists")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("blocklists", data)
        self.assertEqual(len(data["blocklists"]), 4)
        names = {b["name"] for b in data["blocklists"]}
        self.assertEqual(names, {"ads.txt", "trackers.txt", "malware.txt", "custom.txt"})
        self.assertGreaterEqual(data["total_rules"], 235974)

    def test_api_allowlist_workflow(self):
        """Verify allowlist GET, POST, DELETE."""
        test_domain = "unit-test-whitelist.example.org"

        # POST add
        res_post = self.client.post("/api/allowlist", json={"domain": test_domain})
        self.assertEqual(res_post.status_code, 200)
        self.assertEqual(res_post.get_json()["status"], "ok")

        # GET check presence
        res_get = self.client.get("/api/allowlist")
        self.assertEqual(res_get.status_code, 200)
        domains = res_get.get_json()["domains"]
        self.assertIn(test_domain, domains)

        # DELETE remove
        res_del = self.client.delete("/api/allowlist", json={"domain": test_domain})
        self.assertEqual(res_del.status_code, 200)
        self.assertEqual(res_del.get_json()["status"], "ok")

        # GET check absence
        res_get2 = self.client.get("/api/allowlist")
        domains2 = res_get2.get_json()["domains"]
        self.assertNotIn(test_domain, domains2)

    def test_api_settings_and_purge(self):
        """Verify settings GET, POST, and purge."""
        res_get = self.client.get("/api/settings")
        self.assertEqual(res_get.status_code, 200)
        data = res_get.get_json()
        self.assertIn("retention_days", data)
        self.assertIn("anonymize_ip", data)
        self.assertIn("db_size_mb", data)
        self.assertIn("total_records", data)

        # POST valid
        res_post = self.client.post("/api/settings", json={"retention_days": 7, "anonymize_ip": True})
        self.assertEqual(res_post.status_code, 200)
        self.assertEqual(res_post.get_json()["settings"]["retention_days"], 7)

        # Restore default
        self.client.post("/api/settings", json={"retention_days": 5, "anonymize_ip": False})

        # Purge
        res_purge = self.client.post("/api/purge")
        self.assertEqual(res_purge.status_code, 200)
        self.assertEqual(res_purge.get_json()["status"], "ok")

    def test_client_ip_masking_policy(self):
        """
        Verify privacy masking policy:
        - Private/localhost (127.0.0.1) -> full IP, not xxx.xxx.xxx.1
        - Public (8.8.8.8) -> xxx.xxx.xxx.8
        - When show_full_ip is toggled ON -> 8.8.8.8 shows full IP
        - Top Clients in /api/stats and /api/queries use identical masking logic
        """
        # 1. Ensure privacy_mask_public_only=True and show_full_ip=False
        res_set = self.client.post("/api/settings", json={
            "privacy_mask_public_only": True,
            "show_full_ip": False,
            "anonymize_ip": True
        })
        self.assertEqual(res_set.status_code, 200)
        settings = self.client.get("/api/settings").get_json()
        self.assertTrue(settings.get("privacy_mask_public_only"))
        self.assertFalse(settings.get("show_full_ip"))

        # 2. Add queries: one from 127.0.0.1, one from public 8.8.8.8
        stats.add(domain="local-test.example.com", client_ip="127.0.0.1", qtype="A", blocked=False, cached=False, latency_ms=1.5, upstream="8.8.8.8")
        stats.add(domain="public-test.example.com", client_ip="8.8.8.8", qtype="A", blocked=False, cached=False, latency_ms=2.0, upstream="8.8.8.8")

        # 3. Test /api/queries with default policy
        res_q = self.client.get("/api/queries?per_page=10&page=1")
        self.assertEqual(res_q.status_code, 200)
        queries = res_q.get_json()["queries"]

        q_local = next((q for q in queries if q.get("domain") == "local-test.example.com"), None)
        self.assertIsNotNone(q_local)
        self.assertEqual(q_local.get("client"), "127.0.0.1", "127.0.0.1 must NOT be masked to xxx.xxx.xxx.1")

        q_public = next((q for q in queries if q.get("domain") == "public-test.example.com"), None)
        self.assertIsNotNone(q_public)
        self.assertEqual(q_public.get("client"), "xxx.xxx.xxx.8", "Public IP 8.8.8.8 must be masked to xxx.xxx.xxx.8")

        # 4. Test Top Clients in /api/stats
        res_stats = self.client.get("/api/stats")
        self.assertEqual(res_stats.status_code, 200)
        top_clients_dict = dict(res_stats.get_json().get("top_clients", []))
        self.assertIn("127.0.0.1", top_clients_dict)
        self.assertIn("xxx.xxx.xxx.8", top_clients_dict)
        self.assertNotIn("xxx.xxx.xxx.1", top_clients_dict)

        # 5. Toggle Show full IP = True
        res_toggle = self.client.post("/api/settings", json={"show_full_ip": True, "anonymize_ip": False})
        self.assertEqual(res_toggle.status_code, 200)

        res_q_full = self.client.get("/api/queries?per_page=10&page=1")
        queries_full = res_q_full.get_json()["queries"]

        q_public_full = next((q for q in queries_full if q.get("domain") == "public-test.example.com"), None)
        self.assertIsNotNone(q_public_full)
        self.assertEqual(q_public_full.get("client"), "8.8.8.8", "When show_full_ip=True, 8.8.8.8 must be unmasked")

        res_stats_full = self.client.get("/api/stats")
        top_clients_full = dict(res_stats_full.get_json().get("top_clients", []))
        self.assertIn("8.8.8.8", top_clients_full)
        self.assertIn("127.0.0.1", top_clients_full)

        # Restore default settings
        self.client.post("/api/settings", json={"show_full_ip": False, "anonymize_ip": True})


if __name__ == "__main__":
    unittest.main()

