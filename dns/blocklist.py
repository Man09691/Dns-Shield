"""
dns/blocklist.py  —  Domain Blocklist Manager (High Performance + Hot Reload)

Computer Networks concept: DNS-level content filtering.

Optimized for 100,000+ (1 Lakh+) domains:
    - O(1) set/dict suffix walk: checks labels instead of looping
    - Fast LRU lookup_cache: popular domains in microseconds
    - Hot-reload with atomic dictionary swap: zero downtime
    - Background auto-update via daemon thread with atomic os.replace
"""

import os
import time
import logging
import threading
from collections import OrderedDict
import requests
import urllib.request

logger = logging.getLogger("dns.blocklist")

def download_ads(url, filepath):
    """Download blocklist from URL to filepath atomically."""
    try:
        print(f"[AutoUpdate] Downloading {url} ...")
        logger.info(f"[Auto-Update] Downloading from {url}")
        r = requests.get(url, timeout=60, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DNS-Adblock"
        })
        r.raise_for_status()
        tmp = filepath + ".tmp"
        with open(tmp, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(r.text)
        os.replace(tmp, filepath)
        print(f"[AutoUpdate] Done, {len(r.text)} bytes -> {filepath}")
        logger.info(f"[Auto-Update] Saved {len(r.text)} bytes")
        return True
    except Exception as e:
        print(f"[AutoUpdate] Failed: {e}")
        logger.error(f"[Auto-Update] Failed: {e}")
        return False

class Blocklist:
    def __init__(self, lookup_cache_size=4096):
        self.blocked_domains = {}
        self.allowed_domains = set()
        self.lock = threading.Lock()
        self.lookup_cache = OrderedDict()
        self.lookup_cache_size = lookup_cache_size
        self.file_mtimes = {}

    def _parse_line(self, line):
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1", "::1"):
            domain = parts[1].lower()
        else:
            domain = parts[0].lower()
        if domain.startswith("*."):
            domain = domain[2:]
        domain = domain.rstrip(".")
        if domain and domain != "localhost":
            return domain
        return None

    def load_blocklist_file(self, filepath, category="custom"):
        count = 0
        try:
            mtime = os.path.getmtime(filepath)
            with self.lock:
                self.file_mtimes[filepath] = mtime
            new_entries = {}
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    domain = self._parse_line(line)
                    if domain:
                        new_entries[domain] = category
                        count += 1
            with self.lock:
                self.blocked_domains.update(new_entries)
                self.lookup_cache.clear()
        except FileNotFoundError:
            logger.warning(f"Blocklist file not found: {filepath}")
            return 0
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            return 0
        logger.info(f"Loaded {count} domains from {filepath} [{category}]")
        return count

    def load_all_blocklists(self, blocklist_dir):
        total = 0
        if not os.path.isdir(blocklist_dir):
            logger.warning(f"Blocklist dir not found: {blocklist_dir}")
            return 0
        for filename in sorted(os.listdir(blocklist_dir)):
            if filename.endswith(".txt"):
                category = filename[:-4]
                filepath = os.path.join(blocklist_dir, filename)
                total += self.load_blocklist_file(filepath, category)
        with self.lock:
            unique_count = len(self.blocked_domains)
        logger.info(f"Total blocked loaded: {total} | Unique: {unique_count}")
        return unique_count

    def load_allowlist(self, filepath):
        count = 0
        try:
            mtime = os.path.getmtime(filepath)
            new_allowed = set()
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    domain = self._parse_line(line)
                    if domain:
                        new_allowed.add(domain)
                        count += 1
            with self.lock:
                self.allowed_domains.update(new_allowed)
                self.file_mtimes[filepath] = mtime
                self.lookup_cache.clear()
        except FileNotFoundError:
            logger.info(f"No allowlist at {filepath} (OK)")
            return 0
        except Exception as e:
            logger.error(f"Error reading allowlist {filepath}: {e}")
            return 0
        logger.info(f"Loaded {count} allowed domains from {filepath}")
        return count

    def is_blocked(self, domain):
        domain = domain.rstrip(".").lower()
        with self.lock:
            if domain in self.lookup_cache:
                self.lookup_cache.move_to_end(domain)
                return self.lookup_cache[domain]
            allowed = self.allowed_domains
            blocked = self.blocked_domains

        check_domain = domain
        while check_domain:
            if check_domain in allowed:
                result = (False, None)
                self._add_to_lookup_cache(domain, result)
                return result
            dot_pos = check_domain.find(".")
            if dot_pos == -1:
                break
            check_domain = check_domain[dot_pos + 1:]

        check_domain = domain
        while check_domain:
            if check_domain in blocked:
                result = (True, blocked[check_domain])
                self._add_to_lookup_cache(domain, result)
                return result
            dot_pos = check_domain.find(".")
            if dot_pos == -1:
                break
            check_domain = check_domain[dot_pos + 1:]

        result = (False, None)
        self._add_to_lookup_cache(domain, result)
        return result

    def _add_to_lookup_cache(self, domain, result):
        with self.lock:
            if domain in self.lookup_cache:
                self.lookup_cache.move_to_end(domain)
            self.lookup_cache[domain] = result
            if len(self.lookup_cache) > self.lookup_cache_size:
                self.lookup_cache.popitem(last=False)

    def add_domain(self, domain, category="custom"):
        domain = domain.rstrip(".").lower()
        with self.lock:
            self.blocked_domains[domain] = category
            self.lookup_cache.pop(domain, None)

    def remove_domain(self, domain):
        domain = domain.rstrip(".").lower()
        with self.lock:
            if domain in self.blocked_domains:
                del self.blocked_domains[domain]
                self.lookup_cache.pop(domain, None)
                return True
        return False

    def add_to_allowlist(self, domain):
        domain = domain.rstrip(".").lower()
        with self.lock:
            self.allowed_domains.add(domain)
            self.lookup_cache.pop(domain, None)

    def remove_from_allowlist(self, domain):
        domain = domain.rstrip(".").lower()
        with self.lock:
            if domain in self.allowed_domains:
                self.allowed_domains.remove(domain)
                self.lookup_cache.pop(domain, None)
                return True
        return False

    def get_category_counts(self):
        counts = {}
        with self.lock:
            for cat in self.blocked_domains.values():
                counts[cat] = counts.get(cat, 0) + 1
        return counts

    def reload(self, blocklist_dir, allowlist_file):
        new_blocked = {}
        new_allowed = set()
        new_mtimes = {}

        if os.path.exists(allowlist_file):
            try:
                new_mtimes[allowlist_file] = os.path.getmtime(allowlist_file)
                with open(allowlist_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        d = self._parse_line(line)
                        if d:
                            new_allowed.add(d)
            except Exception as e:
                logger.error(f"Error reading allowlist {allowlist_file}: {e}")

        if os.path.isdir(blocklist_dir):
            for filename in sorted(os.listdir(blocklist_dir)):
                if filename.endswith(".txt"):
                    filepath = os.path.join(blocklist_dir, filename)
                    category = filename[:-4]
                    try:
                        new_mtimes[filepath] = os.path.getmtime(filepath)
                        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                d = self._parse_line(line)
                                if d:
                                    new_blocked[d] = category
                    except Exception as e:
                        logger.error(f"Error reading blocklist {filepath}: {e}")

        with self.lock:
            self.blocked_domains = new_blocked
            self.allowed_domains = new_allowed
            self.file_mtimes = new_mtimes
            self.lookup_cache.clear()

        logger.info(f"Blocklists reloaded atomically: {len(new_blocked)} blocked, {len(new_allowed)} allowed")
        return len(new_blocked)

    def check_and_reload_if_changed(self, blocklist_dir, allowlist_file):
        with self.lock:
            tracked_files = dict(self.file_mtimes)
        changed = False
        if os.path.isdir(blocklist_dir):
            current_files = {os.path.join(blocklist_dir, f) for f in os.listdir(blocklist_dir) if f.endswith(".txt")}
            if os.path.exists(allowlist_file):
                current_files.add(allowlist_file)
            if set(tracked_files.keys()) != current_files:
                changed = True
        if not changed:
            for filepath, last_mtime in tracked_files.items():
                try:
                    if os.path.getmtime(filepath) != last_mtime:
                        changed = True
                        break
                except OSError:
                    changed = True
                    break
        if changed:
            logger.info("Blocklist files changed on disk, auto-reloading...")
            self.reload(blocklist_dir, allowlist_file)
            return True
        return False

    def start_auto_update(self, blocklist_dir, allowlist_file, interval_hours=168, oisd_url="https://small.oisd.nl/domainswild/"):
        """
        Har interval_hours (default 168h = 7 din) me auto download + reload
        """
        def download_and_reload():
            final_file = os.path.join(blocklist_dir, "ads.txt")
            if download_ads(oisd_url, final_file):
                self.reload(blocklist_dir, allowlist_file)

        def loop():
            while True:
                time.sleep(interval_hours * 3600)
                download_and_reload()

        t = threading.Thread(target=loop, daemon=True, name="AutoUpdateDaemon")
        t.start()
        logger.info(f"[Auto-Update] Daemon started (every {interval_hours}h)")
        print(f"[Auto-Update] Started, har {interval_hours}h me update")
        return t

    # backward compatible alias for old code
    def start_auto_updater(self, blocklist_dir, allowlist_file, days=7, url="https://small.oisd.nl/domainswild/"):
        return self.start_auto_update(blocklist_dir, allowlist_file, interval_hours=days*24, oisd_url=url)