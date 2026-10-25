"""
tools/update_blocklists.py  —  Download and Update Blocklists
=============================================================
Downloads the latest ad/tracker blocklist in the background or CLI.
Uses a temporary file and atomic os.replace so active DNS queries
are never blocked and never encounter half-written files.
"""

import os
import sys
import json
import threading
import urllib.request
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger("tools.update_blocklists")

# Default paths relative to project root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config.json")


def load_config():
    """Load configuration from config.json if available."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not load config.json: {e}")
    return {}


def download_blocklist(url=None, blocklist_file=None, temp_file=None):
    """
    Synchronously download blocklist into temp_file and atomically replace blocklist_file.
    Returns: (success: bool, domain_count: int, bytes_count: int)
    """
    config = load_config()
    oisd_url = url or config.get("oisd_url", "https://small.oisd.nl/domainswild/")
    blocklist_dir = os.path.join(PROJECT_ROOT, config.get("blocklist_dir", "blocklists"))
    os.makedirs(blocklist_dir, exist_ok=True)

    target_file = blocklist_file or os.path.join(blocklist_dir, "ads.txt")
    temporary_file = temp_file or (target_file + ".tmp")

    logger.info(f"Downloading blocklist from {oisd_url} ...")
    try:
        req = urllib.request.Request(
            oisd_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) DNS-Adblock"}
        )
        with urllib.request.urlopen(req, timeout=60) as response:
            data = response.read()

        # Write to temporary file
        with open(temporary_file, "wb") as f:
            f.write(data)

        # Count domains in temp file
        count = 0
        with open(temporary_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    count += 1

        # Atomic replace
        os.replace(temporary_file, target_file)
        logger.info(f"Successfully updated {target_file}: {len(data):,} bytes, {count:,} domains.")
        return True, count, len(data)

    except Exception as e:
        logger.error(f"Download failed: {e}")
        if os.path.exists(temporary_file):
            try:
                os.remove(temporary_file)
            except OSError:
                pass
        return False, 0, 0


def download_in_background(url=None, blocklist_file=None, temp_file=None, on_complete=None):
    """
    Start blocklist download in a background daemon thread.
    Does not block DNS server or caller.
    """
    def worker():
        logger.info("Background blocklist download started...")
        success, count, size = download_blocklist(url, blocklist_file, temp_file)
        if success and on_complete:
            try:
                on_complete()
            except Exception as e:
                logger.error(f"Callback error after blocklist update: {e}")

    thread = threading.Thread(target=worker, daemon=True, name="BlocklistDownloader")
    thread.start()
    logger.info("Blocklist download launched in background daemon thread.")
    return thread


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Download and update DNS blocklist")
    parser.add_argument("--url", help="URL of blocklist to download", default=None)
    parser.add_argument("--background", action="store_true", help="Run in background daemon thread")
    args = parser.parse_args()

    if args.background:
        t = download_in_background(url=args.url)
        t.join(timeout=120)
    else:
        success, count, size = download_blocklist(url=args.url)
        if not success:
            sys.exit(1)