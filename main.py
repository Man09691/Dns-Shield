"""
main.py  —  Entry Point for the DNS Server
=============================================
Computer Networks concept: DNS server application.

This file:
  1. Loads the configuration from config.json
  2. Sets up logging (console + file)
  3. Initializes all modules (blocklist, cache, rate limiter, stats)
  4. Starts the DNS server (in a background thread)
  5. Runs auto-update in background daemon thread if enabled

Usage:
  python main.py

The DNS server listens on port 5053 by default (no admin needed).
Change to port 53 in config.json (requires Administrator on Windows).
"""

import json
import os
import sys
import logging
import threading
from logging.handlers import RotatingFileHandler

from dns.server import DNSServer
from dns.blocklist import Blocklist
from dns.cache import DNSCache
from dns.ratelimit import RateLimiter
from dns.stats import Stats


def load_config(config_file="config.json"):
    """Load configuration from config.json."""
    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = json.load(f)
        print(f"Loaded config from {config_file}")
        return config
    except FileNotFoundError:
        print(f"WARNING: {config_file} not found, using defaults")
        return {}
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {config_file}: {e}")
        sys.exit(1)


def setup_logging(config):
    """
    Set up logging to both console and a rotating log file.

    Log levels:
      DEBUG   - very detailed (packet parsing details)
      INFO    - normal operation (each query)
      WARNING - recoverable issues (timeouts, malformed packets)
      ERROR   - serious problems
    """
    log_file = config.get("log_file", "dns_server.log")

    # Create a root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    # Console handler: show INFO and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                                    datefmt="%H:%M:%S")
    console_handler.setFormatter(console_fmt)

    # File handler: rotating log (max 5 MB, keep 3 backups)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(name)s  %(message)s")
    file_handler.setFormatter(file_fmt)

    # Avoid duplicate handlers if setup_logging is called multiple times
    root_logger.handlers.clear()
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    logging.info(f"Logging to console and {log_file}")


def main():
    """Main entry point: load config, init modules, start server."""

    # ── Load configuration ──
    config = load_config()

    # ── Set up logging ──
    setup_logging(config)
    logger = logging.getLogger("main")

    # ── Initialize the blocklist ──
    blocklist = Blocklist()
    blocklist_dir = config.get("blocklist_dir", "blocklists")
    allowlist_file = config.get("allowlist_file", "allowlist.txt")

    total_blocked = blocklist.load_all_blocklists(blocklist_dir)
    total_allowed = blocklist.load_allowlist(allowlist_file)
    logger.info(f"Loaded {total_blocked} blocked domains and {total_allowed} allowed domains")

    # ── Background auto-update (daemon thread) ──
    if config.get("auto_update"):
        blocklist.start_auto_update(
            blocklist_dir,
            allowlist_file,
            interval_hours=config.get("update_interval_hours", 24),
            oisd_url=config.get("oisd_url", "https://small.oisd.nl/domainswild/")
        )

    # ── Initialize the cache ──
    cache = DNSCache(
        max_size=config.get("cache_size", 1024),
        min_ttl=config.get("cache_min_ttl", 60),
        max_ttl=config.get("cache_max_ttl", 3600),
    )

    # ── Initialize the rate limiter ──
    rate_limiter = RateLimiter(
        max_queries=config.get("rate_limit_queries", 50),
        window_seconds=config.get("rate_limit_window", 10),
        block_seconds=config.get("rate_limit_block_seconds", 30),
    )

    # ── Initialize stats ──
    stats = Stats(db_file=config.get("db_file", "queries.db"))

    # ── Create and start the DNS server ──
    server = DNSServer(config, blocklist, cache, rate_limiter, stats)

    print("\n" + "=" * 60)
    print("  DNS Server with Ad/Tracker Blocking")
    print(f"  Listening on {config.get('listen_host', '0.0.0.0')}:"
          f"{config.get('listen_port', 5053)}")
    print(f"  Upstream DNS: {config.get('upstream_dns', '8.8.8.8')} "
          f"(fallback: {config.get('upstream_fallback', '1.1.1.1')})")
    print(f"  Blocking mode: {config.get('blocking_mode', 'zero_ip')}")
    print(f"  Blocked domains: {total_blocked}")
    print("=" * 60)
    print("  Press Ctrl+C to stop\n")

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()
        print("Server stopped.")


if __name__ == "__main__":
    main()
