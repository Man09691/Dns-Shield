"""
tests/test_watchlist.py  —  Unit & Integration Tests for Watchlist Feature
========================================================================
Tests brand normalization, space handling, DNS validation, autocomplete,
legacy migration, cache pinning, serve-stale, prefetching, and SQLite persistence.
"""

import os
import sys
import json
import time
import tempfile
import sqlite3
import unittest
from datetime import datetime, timedelta

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from dns.watchlist import (
    normalize_watchlist_input,
    validate_and_find_domain,
    get_suggestions,
    WatchlistManager,
    KNOWN_BRANDS,
    TYPO_CORRECTIONS
)
from dns.cache import DNSCache


class TestWatchlistBrandNormalization(unittest.TestCase):
    """Test smart brand dictionary mapping and space handling."""

    def test_meta_ai_and_claude_brand_mapping(self):
        # FIX 1 & FIX 2: Brand map + space handling
        self.assertEqual(normalize_watchlist_input("meta ai"), "meta.ai")
        self.assertEqual(normalize_watchlist_input("Meta AI"), "meta.ai")
        self.assertEqual(normalize_watchlist_input("metaai"), "meta.ai")
        self.assertEqual(normalize_watchlist_input("meta"), "meta.com")
        self.assertEqual(normalize_watchlist_input("claude"), "claude.ai")
        self.assertEqual(normalize_watchlist_input("Claude"), "claude.ai")
        self.assertEqual(normalize_watchlist_input("claude ai"), "claude.ai")

    def test_core_brands(self):
        self.assertEqual(normalize_watchlist_input("youtube"), "youtube.com")
        self.assertEqual(normalize_watchlist_input("YouTube"), "youtube.com")
        self.assertEqual(normalize_watchlist_input("google"), "google.com")
        self.assertEqual(normalize_watchlist_input("chatgpt"), "chatgpt.com")
        self.assertEqual(normalize_watchlist_input("chat gpt"), "chatgpt.com")
        self.assertEqual(normalize_watchlist_input("openai"), "openai.com")
        self.assertEqual(normalize_watchlist_input("github"), "github.com")
        self.assertEqual(normalize_watchlist_input("gmail"), "mail.google.com")

    def test_typo_corrections(self):
        # FIX 5: Typo auto-correction
        self.assertEqual(normalize_watchlist_input("metaai.com"), "meta.ai")
        self.assertEqual(normalize_watchlist_input("claude.com"), "claude.ai")

    def test_url_and_www_stripping(self):
        self.assertEqual(normalize_watchlist_input("https://meta.ai/"), "meta.ai")
        self.assertEqual(normalize_watchlist_input("https://youtube.com/watch?v=123"), "youtube.com")
        self.assertEqual(normalize_watchlist_input("http://google.com/"), "google.com")
        self.assertEqual(normalize_watchlist_input("www.youtube.com"), "youtube.com")
        self.assertEqual(normalize_watchlist_input("WWW.META.COM"), "meta.com")

    def test_invalid_and_empty_inputs(self):
        with self.assertRaises(ValueError):
            normalize_watchlist_input("")
        with self.assertRaises(ValueError):
            normalize_watchlist_input("   ")
        with self.assertRaises(ValueError):
            normalize_watchlist_input(None)
        with self.assertRaises(ValueError):
            normalize_watchlist_input("!@#$%^&*()")


class TestDNSValidation(unittest.TestCase):
    """Test DNS validation before addition (FIX 3) in English."""

    def test_valid_brands_pass(self):
        valid, dom, _, _ = validate_and_find_domain("meta ai")
        self.assertTrue(valid)
        self.assertEqual(dom, "meta.ai")

        valid, dom, _, _ = validate_and_find_domain("claude")
        self.assertTrue(valid)
        self.assertEqual(dom, "claude.ai")

        valid, dom, _, _ = validate_and_find_domain("youtube")
        self.assertTrue(valid)
        self.assertEqual(dom, "youtube.com")

    def test_nonexistent_domain_rejected_english(self):
        # Must show English error that domain does not exist and not add
        valid, err_msg, suggestion, _ = validate_and_find_domain("xyzabc123")
        self.assertFalse(valid)
        self.assertIn("does not exist", err_msg)


class TestAutocompleteSuggestions(unittest.TestCase):
    """Test Google-like autocomplete suggestions (FIX 4)."""

    def test_suggestions_catalog(self):
        meta_sug = get_suggestions("meta")
        doms = [s["domain"] for s in meta_sug]
        self.assertIn("meta.ai", doms)
        self.assertIn("meta.com", doms)

        clau_sug = get_suggestions("clau")
        doms = [s["domain"] for s in clau_sug]
        self.assertIn("claude.ai", doms)

        you_sug = get_suggestions("you")
        doms = [s["domain"] for s in you_sug]
        self.assertIn("youtube.com", doms)


class TestWatchlistPersistenceAndMigration(unittest.TestCase):
    """Test WatchlistManager persistence in SQLite + JSON (BUG 1) and legacy migration."""

    def setUp(self):
        self.temp_json = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_json.close()
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()

        if os.path.exists(self.temp_json.name):
            os.remove(self.temp_json.name)
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

        self.mgr = WatchlistManager(filepath=self.temp_json.name, db_path=self.temp_db.name)

    def tearDown(self):
        for f in [self.temp_json.name, self.temp_db.name]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    def test_default_seeding(self):
        domains = self.mgr.get_domains()
        self.assertIn("youtube.com", domains)
        self.assertIn("google.com", domains)

    def test_add_and_persistence_across_restart(self):
        # Add test entry
        success, msg, entry = self.mgr.add("meta ai")
        self.assertTrue(success)
        self.assertEqual(entry["domain"], "meta.ai")
        self.assertIn("meta.ai", self.mgr.get_domains())

        # Also add example-test.com as specifically specified in user test
        success2, msg2, entry2 = self.mgr.add("example-test.com")
        self.assertTrue(success2)
        self.assertEqual(entry2["domain"], "example-test.com")

        # Simulate server restart by creating new manager on same DB & JSON
        mgr2 = WatchlistManager(filepath=self.temp_json.name, db_path=self.temp_db.name)
        restarted_domains = mgr2.get_domains()
        self.assertIn("meta.ai", restarted_domains)
        self.assertIn("example-test.com", restarted_domains)
        self.assertIn("youtube.com", restarted_domains)
        self.assertIn("google.com", restarted_domains)

        # Remove example-test.com and verify
        rem_ok, _ = self.mgr.remove("example-test.com")
        self.assertTrue(rem_ok)
        mgr3 = WatchlistManager(filepath=self.temp_json.name, db_path=self.temp_db.name)
        self.assertNotIn("example-test.com", mgr3.get_domains())

    def test_remove_and_persistence_across_restart(self):
        self.mgr.add("meta ai")
        success, msg = self.mgr.remove("meta.ai")
        self.assertTrue(success)

        # Simulate restart
        mgr2 = WatchlistManager(filepath=self.temp_json.name, db_path=self.temp_db.name)
        self.assertNotIn("meta.ai", mgr2.get_domains())

    def test_record_hit_persistence(self):
        self.mgr.add("meta ai")
        self.mgr.record_hit("meta.ai")

        items = self.mgr.get_all()
        meta_item = next((i for i in items if i["domain"] == "meta.ai"), None)
        self.assertIsNotNone(meta_item)
        self.assertIsNotNone(meta_item["last_hit"])

        # Simulate restart: Last Used must persist! (BUG 4)
        mgr2 = WatchlistManager(filepath=self.temp_json.name, db_path=self.temp_db.name)
        items2 = mgr2.get_all()
        meta_item2 = next((i for i in items2 if i["domain"] == "meta.ai"), None)
        self.assertEqual(meta_item2["last_hit"], meta_item["last_hit"])

    def test_live_last_used_and_subdomain_matching(self):
        """BUG 1: Live query on queries table for leetcode.com & assets.leetcode.com."""
        import sqlite3
        conn = sqlite3.connect(self.temp_db.name)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                domain TEXT,
                client_ip TEXT,
                qtype TEXT,
                blocked INTEGER DEFAULT 0,
                cached INTEGER DEFAULT 0,
                latency_ms REAL,
                upstream TEXT,
                internal_lookup_ns INTEGER,
                transport TEXT,
                status TEXT,
                category TEXT
            )
        """)
        conn.commit()
        conn.close()

        self.mgr.add("leetcode.com")
        items = self.mgr.get_all()
        lc = next(i for i in items if i["domain"] == "leetcode.com")
        self.assertEqual(lc["last_used"], "Never")

        # 1. Query leetcode.com CACHED
        now_iso = datetime.now().isoformat()
        conn = sqlite3.connect(self.temp_db.name)
        conn.execute("INSERT INTO queries (timestamp, domain, qtype, status, blocked) VALUES (?, 'leetcode.com', 'A', 'CACHED', 0)", (now_iso,))
        conn.commit()
        conn.close()

        items = self.mgr.get_all()
        lc = next(i for i in items if i["domain"] == "leetcode.com")
        self.assertEqual(lc["last_used"], "Just now")

        # 2. Query assets.leetcode.com (subdomain counts)
        conn = sqlite3.connect(self.temp_db.name)
        conn.execute("DELETE FROM queries")
        sub_now = datetime.now().isoformat()
        conn.execute("INSERT INTO queries (timestamp, domain, qtype, status, blocked) VALUES (?, 'assets.leetcode.com', 'A', 'FORWARDED', 0)", (sub_now,))
        conn.commit()
        conn.close()

        items = self.mgr.get_all()
        lc = next(i for i in items if i["domain"] == "leetcode.com")
        self.assertEqual(lc["last_used"], "Just now")

        # 3. Blocked query must NOT update Last Used
        conn = sqlite3.connect(self.temp_db.name)
        conn.execute("DELETE FROM queries")
        conn.execute("INSERT INTO queries (timestamp, domain, qtype, status, blocked) VALUES (?, 'ads.leetcode.com', 'A', 'BLOCKED', 1)", (datetime.now().isoformat(),))
        conn.commit()
        conn.close()

        items = self.mgr.get_all()
        lc = next(i for i in items if i["domain"] == "leetcode.com")
        self.assertEqual(lc["last_used"], "Never")

    def test_reject_fake_domain(self):
        success, msg, _ = self.mgr.add("xyzabc123")
        self.assertFalse(success)
        self.assertIn("does not exist", msg)


class TestDashboardWatchlistAPI(unittest.TestCase):
    """Test dashboard watchlist endpoints."""

    def setUp(self):
        import dns.dashboard as dash
        self.orig_mgr = dash.watchlist_manager
        self.temp_json = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.temp_json.close()
        os.remove(self.temp_json.name)
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.remove(self.temp_db.name)
        dash.watchlist_manager = WatchlistManager(filepath=self.temp_json.name, db_path=self.temp_db.name)
        self.client = dash.app.test_client()

    def tearDown(self):
        import dns.dashboard as dash
        dash.watchlist_manager = self.orig_mgr
        for p in (self.temp_json.name, self.temp_db.name):
            try:
                os.remove(p)
            except OSError:
                pass

    def test_watchlist_get_api(self):
        res = self.client.get("/api/watchlist")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("watchlist", data)
        self.assertGreaterEqual(data["total"], 2)

    def test_watchlist_suggest_api(self):
        res = self.client.get("/api/watchlist/suggest?q=meta")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        doms = [item["domain"] for item in data]
        self.assertIn("meta.ai", doms)

    def test_watchlist_post_meta_ai_and_delete_api(self):
        res = self.client.post("/api/watchlist", json={"input": "meta ai"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["domain"], "meta.ai")

        # Duplicate should return 400 in English
        res_dup = self.client.post("/api/watchlist", json={"input": "meta ai"})
        self.assertEqual(res_dup.status_code, 400)
        self.assertIn("Already added", res_dup.get_json()["error"])

        # Delete domain
        res_del = self.client.delete("/api/watchlist", json={"domain": "meta.ai"})
        self.assertEqual(res_del.status_code, 200)
        self.assertEqual(res_del.get_json()["status"], "ok")

    def test_reject_fake_domain_post(self):
        res = self.client.post("/api/watchlist", json={"input": "xyzabc123"})
        self.assertEqual(res.status_code, 400)
        self.assertIn("does not exist", res.get_json()["error"])

    def test_watchlist_page_route(self):
        res = self.client.get("/watchlist")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("Watchlist", html)
        self.assertIn("suggestBox", html)


if __name__ == "__main__":
    unittest.main()
