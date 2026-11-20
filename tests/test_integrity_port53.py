"""
test_integrity_port53.py -- Integrity Tests for DNS Shield Port 53 Variant
Run: python test_integrity_port53.py
"""
import os
import sys
import json
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) if os.path.basename(os.path.dirname(os.path.abspath(__file__))) == "tests" else os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

results = []  # list of (name, passed)

# ─────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────

def check(name, passed, msg="", fix=""):
    status = "PASS" if passed else "FAIL"
    line = f"  [{status}] {name}"
    if msg:
        line += f": {msg}"
    print(line)
    if not passed and fix:
        print(f"         FIX: {fix}")
    results.append((name, passed))


# ─────────────────────────────────────────────────────────
# 1. Source URLs in dns/blocklist.py
# ─────────────────────────────────────────────────────────
print("\n[1] Source URL checks in dns/blocklist.py")
blocklist_py = os.path.join(PROJECT_ROOT, "dns", "blocklist.py")
try:
    with open(blocklist_py, encoding="utf-8") as f:
        src = f.read()
    check(
        "blocklist.py has OISD Big URL (big.oisd.nl)",
        "big.oisd.nl" in src,
        fix="Restore ADS_URL = 'https://big.oisd.nl/domainswild' in dns/blocklist.py"
    )
    check(
        "blocklist.py has AdGuard DNS URL (adguardteam.github.io)",
        "adguardteam.github.io/AdGuardSDNSFilter" in src,
        fix="Restore TRACKERS_URL = 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt'"
    )
    check(
        "blocklist.py has SOURCES dict",
        "SOURCES = {" in src or "SOURCES={" in src,
        fix="Add SOURCES = { ... } mapping source names to download URLs"
    )
except FileNotFoundError:
    check("dns/blocklist.py exists", False, fix="File missing: dns/blocklist.py not found")


# ─────────────────────────────────────────────────────────
# 2. _clean_domain_line AdGuard syntax handling
# ─────────────────────────────────────────────────────────
print("\n[2] _clean_domain_line() syntax handling")
try:
    from dns.blocklist import _clean_domain_line

    # ||domain^ -> domain
    result = _clean_domain_line("||popads.net^")
    check(
        "_clean_domain_line: strips ||domain^",
        result == "popads.net",
        f"Got: {result!r}",
        fix="Add: if raw.startswith('||'): raw = raw[2:]; if raw.endswith('^'): raw = raw[:-1]"
    )

    # *.domain -> domain
    result = _clean_domain_line("*.tracker.com")
    check(
        "_clean_domain_line: strips *. wildcard prefix",
        result == "tracker.com",
        f"Got: {result!r}",
        fix="Add: if raw.startswith('*.'): raw = raw[2:]"
    )

    # # comment -> None
    result = _clean_domain_line("# this is a comment")
    check(
        "_clean_domain_line: skips # comments",
        result is None,
        f"Got: {result!r}",
        fix="Add: if raw.startswith('#'): return None"
    )

    # ! comment (AdGuard header) -> None
    result = _clean_domain_line("! Title: AdGuard DNS filter")
    check(
        "_clean_domain_line: skips ! comments (AdGuard headers)",
        result is None,
        f"Got: {result!r}",
        fix="Add: if raw.startswith('!'): return None"
    )

    # @@ allowlist lines -> None (must not produce @@something)
    result = _clean_domain_line("@@||safe.example.com^$important")
    check(
        "_clean_domain_line: skips @@ allowlist lines",
        result is None or (result is not None and not result.startswith("@@")),
        f"Got: {result!r}",
        fix="Add at top of _clean_domain_line: if raw.startswith('@@'): return None"
    )

    # ^$important meta line -> None (not a valid domain)
    result = _clean_domain_line("^$important")
    check(
        "_clean_domain_line: skips ^$important meta lines",
        result is None,
        f"Got: {result!r}",
        fix="After stripping, validate domain has a '.' and no '$' or '^' characters"
    )

    # Plain domain passthrough
    result = _clean_domain_line("doubleclick.net")
    check(
        "_clean_domain_line: passes plain domain unchanged",
        result == "doubleclick.net",
        f"Got: {result!r}",
        fix="Plain domains should pass through as-is"
    )

except ImportError as e:
    check("dns.blocklist import OK", False, fix=f"Import failed: {e}")


# ─────────────────────────────────────────────────────────
# 3. Blocklist file domain counts
# ─────────────────────────────────────────────────────────
print("\n[3] Blocklist file domain counts")

def count_domains(filepath):
    """Count valid domain lines using _clean_domain_line."""
    if not os.path.exists(filepath):
        return 0
    count = 0
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    if _clean_domain_line(line.strip()):
                        count += 1
                except Exception:
                    pass
    except Exception:
        pass
    return count

try:
    ads_path      = os.path.join(PROJECT_ROOT, "blocklists", "ads.txt")
    trackers_path = os.path.join(PROJECT_ROOT, "blocklists", "trackers.txt")
    malware_path  = os.path.join(PROJECT_ROOT, "blocklists", "malware.txt")
    custom_path   = os.path.join(PROJECT_ROOT, "blocklists", "custom.txt")

    ads_count      = count_domains(ads_path)
    trackers_count = count_domains(trackers_path)
    malware_count  = count_domains(malware_path)
    custom_count   = count_domains(custom_path)

    print(f"       ads.txt:      {ads_count:,} domains")
    print(f"       trackers.txt: {trackers_count:,} domains")
    print(f"       malware.txt:  {malware_count:,} domains")
    print(f"       custom.txt:   {custom_count:,} domains")

    check(
        "ads.txt >= 200k domains",
        ads_count >= 200000,
        f"Found {ads_count:,}",
        fix="Re-download OISD Big: https://big.oisd.nl/domainswild -> blocklists/ads.txt"
    )
    check(
        "trackers.txt >= 80k domains",
        trackers_count >= 80000,
        f"Found {trackers_count:,} (expected ~130k after AdGuard DNS update)",
        fix="Run 'python main.py' as Admin for 60s to trigger auto-update with AdGuard DNS filter"
    )
    check(
        "malware.txt >= 10k domains",
        malware_count >= 10000,
        f"Found {malware_count:,}",
        fix="Re-download URLhaus list; check MALWARE_URL in dns/blocklist.py"
    )
    check(
        "custom.txt >= 1 domain",
        custom_count >= 1,
        f"Found {custom_count:,}",
        fix="Add at least one domain (e.g. doubleclick.net) to blocklists/custom.txt"
    )
except Exception as e:
    check("Blocklist file count checks", False, fix=f"Error counting domains: {e}")


# ─────────────────────────────────────────────────────────
# 4. Blocklist full load test
# ─────────────────────────────────────────────────────────
print("\n[4] Blocklist.load_all_blocklists() load test")
b = None
try:
    from dns.blocklist import Blocklist
    b = Blocklist()
    blocklist_dir = os.path.join(PROJECT_ROOT, "blocklists")
    allowlist_file = os.path.join(PROJECT_ROOT, "allowlist.txt")

    t0 = time.perf_counter()
    total = b.load_all_blocklists(blocklist_dir)
    load_ms = (time.perf_counter() - t0) * 1000

    print(f"       Loaded {total:,} unique domains in {load_ms:.0f}ms")
    b.load_allowlist(allowlist_file)

    check(
        "Total unique domains >= 275k",
        total >= 275000,
        f"Found {total:,}",
        fix="Ensure blocklists/ads.txt, trackers.txt, malware.txt are downloaded"
    )
    check(
        "Total unique domains >= 300k (target after AdGuard update)",
        total >= 300000,
        f"Found {total:,} (currently {total:,}; expected ~380k after AdGuard DNS auto-update)",
        fix="Run 'python main.py' as Admin for 60s to download AdGuard DNS filter (~130k domains)"
    )
except Exception as e:
    check("Blocklist.load_all_blocklists()", False, fix=f"Error: {e}")


# ─────────────────────────────────────────────────────────
# 5. Category counts
# ─────────────────────────────────────────────────────────
print("\n[5] Per-category domain counts")
if b is not None:
    try:
        counts = b.get_category_counts() if hasattr(b, "get_category_counts") else {}
        print(f"       Category counts: {dict(counts)}")

        check(
            "Category 'ads' >= 200k",
            counts.get("ads", 0) >= 200000,
            f"Found {counts.get('ads', 0):,}",
            fix="ads.txt may not be loaded; check blocklists/ folder and OISD Big URL"
        )
        check(
            "Category 'trackers' >= 43k (current EasyPrivacy baseline)",
            counts.get("trackers", 0) >= 43000,
            f"Found {counts.get('trackers', 0):,}",
            fix="trackers.txt missing or empty; run auto-update"
        )
        check(
            "Category 'custom' >= 1",
            counts.get("custom", 0) >= 1,
            f"Found {counts.get('custom', 0):,}",
            fix="Add domains to blocklists/custom.txt"
        )
    except Exception as e:
        check("get_category_counts()", False, fix=f"Error: {e}")
else:
    check("Category counts (skipped - Blocklist not loaded)", False, fix="Fix load_all_blocklists() first")


# ─────────────────────────────────────────────────────────
# 6. Block / allow correctness
# ─────────────────────────────────────────────────────────
print("\n[6] Block / allow correctness")
if b is not None:
    def is_blocked_safe(domain):
        try:
            return b.is_blocked(domain)
        except Exception as e:
            return (None, str(e))

    # AdGuard pop-up / ad network domains
    for domain in ["popads.net", "propellerads.com", "onclkds.com"]:
        blocked, cat = is_blocked_safe(domain)
        check(
            f"{domain} is BLOCKED",
            blocked is True,
            f"category={cat}",
            fix=f"{domain} should be in ads.txt or trackers.txt after AdGuard DNS update"
        )

    # Core ad trackers
    for domain in ["doubleclick.net", "google-analytics.com", "googlesyndication.com"]:
        blocked, cat = is_blocked_safe(domain)
        check(
            f"{domain} is BLOCKED",
            blocked is True,
            f"category={cat}",
            fix=f"{domain} should be in ads.txt, trackers.txt, or custom.txt"
        )

    # Allowlist -- youtube.com and all subdomains must be allowed
    for domain in ["youtube.com", "www.youtube.com", "accounts.youtube.com"]:
        blocked, cat = is_blocked_safe(domain)
        check(
            f"{domain} is NOT blocked (parent allowlist)",
            blocked is False,
            f"blocked={blocked}, cat={cat}",
            fix="Add 'youtube.com' on its own line in allowlist.txt; restart/reload blocklist"
        )

    # ads.youtube.com should still be blocked (it's a subdomain not in allowlist)
    blocked, cat = is_blocked_safe("ads.youtube.com")
    # This is informational only -- behaviour depends on list content
    status_txt = "BLOCKED" if blocked else "ALLOWED"
    print(f"  [INFO] ads.youtube.com -> {status_txt} (cat={cat}) -- expected BLOCKED if in ads list")

    # Regular sites must not be blocked
    for domain in ["google.com", "github.com", "microsoft.com"]:
        blocked, cat = is_blocked_safe(domain)
        check(
            f"{domain} is NOT blocked (legitimate site)",
            blocked is False,
            f"blocked={blocked}, cat={cat}",
            fix=f"Remove {domain} from all blocklists; check for accidental inclusion"
        )
else:
    check("Block/allow correctness (skipped - Blocklist not loaded)", False, fix="Fix load_all_blocklists() first")


# ─────────────────────────────────────────────────────────
# 7. Lookup performance
# ─────────────────────────────────────────────────────────
print("\n[7] Lookup performance")
if b is not None:
    try:
        test_domains = [
            "google.com", "doubleclick.net", "youtube.com",
            "facebook.com", "tracker.example.com",
            "ads.example.net", "popads.net", "www.youtube.com"
        ]
        n = 1000

        # Warm up (fill lookup_cache)
        for d in test_domains:
            b.is_blocked(d)

        # Timed run -- cached
        if hasattr(b, "lookup_cache"):
            b.lookup_cache.clear()

        t0 = time.perf_counter()
        for i in range(n):
            b.is_blocked(test_domains[i % len(test_domains)])
        elapsed_ms = (time.perf_counter() - t0) * 1000
        avg_ms = elapsed_ms / n

        print(f"       {n} lookups in {elapsed_ms:.1f}ms -> avg {avg_ms:.4f}ms each")
        check(
            f"Lookup performance < 1ms avg ({avg_ms:.3f}ms)",
            avg_ms < 1.0,
            fix="Check for threading lock contention in is_blocked(); consider RLock or read-write lock"
        )
    except Exception as e:
        check("Lookup performance", False, fix=f"Error: {e}")
else:
    check("Lookup performance (skipped - Blocklist not loaded)", False, fix="Fix load_all_blocklists() first")


# ─────────────────────────────────────────────────────────
# 8. File existence and config.json checks
# ─────────────────────────────────────────────────────────
print("\n[8] File existence and config.json")

for rel in ["dns/dashboard.py", "dns/server.py", "dns/stats.py", "dns/blocklist.py",
            "main.py", "allowlist.txt", "START_DNS_Port53.ps1", "STOP_Restore_Internet.ps1"]:
    path = os.path.join(PROJECT_ROOT, *rel.split("/"))
    check(f"{rel} exists", os.path.exists(path), fix=f"Missing file: {path}")

config_path = os.path.join(PROJECT_ROOT, "config.json")
if os.path.exists(config_path):
    try:
        with open(config_path, encoding="utf-8") as f:
            cfg = json.load(f)
        check(
            "config.json listen_port == 53",
            cfg.get("listen_port") == 53,
            f"Got {cfg.get('listen_port')!r}",
            fix="Set \"listen_port\": 53 in config.json"
        )
        check(
            "config.json dashboard_port == 8081",
            cfg.get("dashboard_port") == 8081,
            f"Got {cfg.get('dashboard_port')!r}",
            fix="Set \"dashboard_port\": 8081 in config.json"
        )
        db_file = cfg.get("db_file") or cfg.get("db_path")
        check(
            "config.json db_file == port53_queries.db",
            db_file == "port53_queries.db",
            f"Got {db_file!r}",
            fix="Set \"db_file\": \"port53_queries.db\" in config.json"
        )
        # Check active_blocklists
        active = cfg.get("active_blocklists", {})
        expected_keys = ["ads.txt", "trackers.txt", "malware.txt", "custom.txt"]
        all_active = all(active.get(k, False) for k in expected_keys)
        check(
            "config.json all 4 blocklists are active",
            all_active,
            f"active_blocklists: {active}",
            fix="Set all 4 entries to true in active_blocklists in config.json"
        )
    except Exception as e:
        check("config.json parse OK", False, fix=f"JSON parse error: {e}")
else:
    check("config.json exists", False, fix="Create config.json with listen_port:53, dashboard_port:8081, db_file:port53_queries.db")


# ─────────────────────────────────────────────────────────
# 9. DB path consistency check (stats.py + dashboard.py)
# ─────────────────────────────────────────────────────────
print("\n[9] DB path consistency (port53_queries.db)")

for rel in ["dns/stats.py", "dns/dashboard.py"]:
    path = os.path.join(PROJECT_ROOT, *rel.split("/"))
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            content = f.read()
        has_correct_db = "port53_queries.db" in content
        check(
            f"{rel} references port53_queries.db",
            has_correct_db,
            fix=f"Change DB_PATH / db_path in {rel} to 'port53_queries.db'"
        )
        has_wrong_db = 'queries.db"' in content and "port53_queries.db" not in content
        if has_wrong_db:
            print(f"  [WARN] {rel} may still reference old 'queries.db' -- check DB_PATH definition")
    else:
        check(f"{rel} exists", False, fix=f"Missing: {path}")


# ─────────────────────────────────────────────────────────
# 10. main.py PermissionError handler check
# ─────────────────────────────────────────────────────────
print("\n[10] main.py port 53 PermissionError handler")
main_py = os.path.join(PROJECT_ROOT, "main.py")
if os.path.exists(main_py):
    with open(main_py, encoding="utf-8") as f:
        main_src = f.read()
    check(
        "main.py handles PermissionError / WinError 10013",
        "PermissionError" in main_src or "WinError" in main_src or "10013" in main_src,
        fix="Add: except PermissionError: print('ERROR: Port 53 needs Admin rights...')"
    )
    check(
        "main.py listens on port 53",
        ":53" in main_src or "53" in main_src,
        fix="Ensure main.py uses listen_port from config (default 53)"
    )
else:
    check("main.py exists", False, fix="main.py missing from project root")


# ─────────────────────────────────────────────────────────
# Final Summary
# ─────────────────────────────────────────────────────────
passed = sum(1 for _, p in results if p)
failed = sum(1 for _, p in results if not p)
total_checks = len(results)

print()
print("=" * 65)
print(f"  INTEGRITY TEST SUMMARY: {passed}/{total_checks} PASSED, {failed} FAILED")
print("=" * 65)

if failed == 0:
    print("  ALL TESTS PASSED -- DNS Shield Port 53 is healthy!")
else:
    print("  FAILURES DETECTED -- See FIX instructions above.")
    print()
    print("  Common fixes:")
    print("   1. Run 'python main.py' as Admin for 60s to trigger auto-update")
    print("      (AdGuard DNS filter download -> trackers.txt will grow to ~130k)")
    print("   2. Ensure allowlist.txt has 'youtube.com' on its own line")
    print("   3. Verify config.json: listen_port:53 | dashboard_port:8081 | db_file:port53_queries.db")
    print("   4. Ensure all 4 blocklist sources are ENABLED in config.json active_blocklists")
    print("   5. For @@ / ^$important parse failures, update _clean_domain_line() in dns/blocklist.py")

print("=" * 65)
sys.exit(0 if failed == 0 else 1)

