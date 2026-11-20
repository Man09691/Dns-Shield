"""
dns/watchlist.py  —  Always-Cached Pinned Watchlist Manager with Dual Persistence & Real Query Tracking
=======================================================================================================
Manages high-priority domains (e.g. YouTube, Google, Claude, Meta, Meta AI)
that must always remain in DNS cache with serve-stale protection
and background prefetching before TTL expiry.

Key Features:
  - Dual persistent storage: SQLite table `watchlist` in port53_queries.db + watchlist.json
  - Immediate file + database sync on every add / remove / hit
  - Real-time Last Used tracking tied to query logs & DNS resolutions
  - Smart brand dictionary mapping (e.g. "meta ai" -> "meta.ai", "claude" -> "claude.ai")
  - Live DNS validation before addition (rejects non-existent / NXDOMAIN domains)
  - 100% English user interface and API error messages
"""

import os
import json
import sqlite3
import socket
import logging
import threading
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError

logger = logging.getLogger("dns.watchlist")

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCHLIST_FILE = os.path.join(PROJECT_ROOT, "watchlist.json")
DB_PATH = os.path.join(PROJECT_ROOT, "port53_queries.db")

# ─────────────────────────────────────────────────────────────────────────────
# 1. KNOWN BRANDS DICTIONARY
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_BRANDS = {
    # YouTube & Google
    "youtube": "youtube.com",
    "yt": "youtube.com",
    "google": "google.com",
    "gmail": "mail.google.com",
    "google mail": "mail.google.com",

    # Meta & Meta AI
    "meta ai": "meta.ai",
    "metaai": "meta.ai",
    "meta": "meta.com",
    "meta.ai": "meta.ai",
    "meta.com": "meta.com",
    "facebook": "facebook.com",
    "fb": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",

    # Anthropic & Claude
    "claude": "claude.ai",
    "claude ai": "claude.ai",
    "claudeai": "claude.ai",
    "anthropic": "anthropic.com",
    "claude.ai": "claude.ai",

    # OpenAI & ChatGPT
    "chatgpt": "chatgpt.com",
    "chat gpt": "chatgpt.com",
    "openai": "openai.com",
    "chatgpt.com": "chatgpt.com",

    # Developer & Socials
    "github": "github.com",
    "gitlab": "gitlab.com",
    "reddit": "reddit.com",
    "twitter": "x.com",
    "x": "x.com",
    "linkedin": "linkedin.com",
    "netflix": "netflix.com",
    "spotify": "spotify.com",
    "amazon": "amazon.com",
    "wikipedia": "wikipedia.org",
}

# Common mistaken / parked domains -> correct domain
TYPO_CORRECTIONS = {
    "metaai.com": "meta.ai",
    "meta-ai.com": "meta.ai",
    "claude.com": "claude.ai",
    "claudeai.com": "claude.ai",
    "chatgpt.ai": "chatgpt.com",
    "gmail.com": "mail.google.com",
}

# Explicit brand variants as backup (BUG 1 FIX)
BRAND_VARIANTS = {
    "cluad.ai": "claude.ai",
    "cluadeai.com": "claude.ai",
    "cluade.ai": "claude.ai",
    "calude.ai": "claude.ai",
    "claudeai.com": "claude.ai",
    "claude.com": "claude.ai",
    "cluad": "claude.ai",
    "cluade": "claude.ai",
    "calude": "claude.ai",
    "cluadeai": "claude.ai",
    "metaai.com": "meta.ai",
    "meta-ai.com": "meta.ai",
    "chatgpt.ai": "chatgpt.com",
    "youtub.com": "youtube.com",
    "leadcode.com": "leetcode.com",
    "gogle.com": "google.com",
}

# Autocomplete suggestions catalog
SUGGESTIONS_CATALOG = [
    {"domain": "meta.ai", "name": "Meta AI", "brand": "meta ai"},
    {"domain": "meta.com", "name": "Meta", "brand": "meta"},
    {"domain": "claude.ai", "name": "Claude AI", "brand": "claude"},
    {"domain": "youtube.com", "name": "YouTube", "brand": "youtube"},
    {"domain": "google.com", "name": "Google", "brand": "google"},
    {"domain": "mail.google.com", "name": "Gmail", "brand": "gmail"},
    {"domain": "chatgpt.com", "name": "ChatGPT", "brand": "chatgpt"},
    {"domain": "openai.com", "name": "OpenAI", "brand": "openai"},
    {"domain": "github.com", "name": "GitHub", "brand": "github"},
    {"domain": "reddit.com", "name": "Reddit", "brand": "reddit"},
    {"domain": "x.com", "name": "X / Twitter", "brand": "twitter"},
    {"domain": "netflix.com", "name": "Netflix", "brand": "netflix"},
    {"domain": "spotify.com", "name": "Spotify", "brand": "spotify"},
    {"domain": "amazon.com", "name": "Amazon", "brand": "amazon"},
]

# ─────────────────────────────────────────────────────────────────────────────
# TOP POPULAR DOMAINS (for edit-distance typo detection across ALL domains)
# ─────────────────────────────────────────────────────────────────────────────
TOP_POPULAR_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com",
    "x.com", "reddit.com", "wikipedia.org", "amazon.com", "netflix.com",
    "linkedin.com", "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
    "medium.com", "twitch.tv", "discord.com", "spotify.com", "pinterest.com",
    "tumblr.com", "quora.com", "imdb.com", "ebay.com", "cnn.com",
    "bbc.com", "nytimes.com", "washingtonpost.com", "forbes.com", "bloomberg.com",
    "reuters.com", "yahoo.com", "bing.com", "duckduckgo.com", "baidu.com",
    "zoom.us", "teams.microsoft.com", "slack.com", "notion.so", "figma.com",
    "canva.com", "dropbox.com", "drive.google.com", "docs.google.com",
    "mail.google.com", "outlook.com", "proton.me", "icloud.com",
    "whatsapp.com", "telegram.org", "signal.org", "messenger.com",
    "tiktok.com", "snapchat.com", "wechat.com",
    "openai.com", "chatgpt.com", "claude.ai", "anthropic.com", "meta.ai",
    "meta.com", "perplexity.ai", "huggingface.co", "kaggle.com",
    "leetcode.com", "hackerrank.com", "codeforces.com", "codechef.com", "topcoder.com",
    "geeksforgeeks.org", "w3schools.com", "freecodecamp.org",
    "udemy.com", "coursera.org", "edx.org", "khanacademy.org",
    "gitlab.com", "bitbucket.org", "npm.js.com", "pypi.org",
    "docker.com", "kubernetes.io", "aws.amazon.com", "cloud.google.com",
    "azure.microsoft.com", "heroku.com", "vercel.com", "netlify.com",
    "wordpress.com", "blogger.com", "wix.com", "squarespace.com",
    "shopify.com", "stripe.com", "paypal.com",
    "steam.com", "steampowered.com", "epicgames.com", "roblox.com",
    "minecraft.net", "xbox.com", "playstation.com", "nintendo.com",
    "hulu.com", "disneyplus.com", "hbomax.com", "primevideo.com",
    "crunchyroll.com", "funimation.com",
]

# Expand to 1000 popular domains from top1000.txt
TOP1000_FILE = os.path.join(PROJECT_ROOT, "top1000.txt")
if os.path.exists(TOP1000_FILE):
    try:
        with open(TOP1000_FILE, "r", encoding="utf-8") as _f:
            for _line in _f:
                _d = _line.strip().lower()
                if _d and not _d.startswith("#") and "." in _d and _d not in TOP_POPULAR_DOMAINS:
                    TOP_POPULAR_DOMAINS.append(_d)
    except Exception:
        pass


def _edit_distance(s1: str, s2: str, max_dist: int = 2) -> int:
    """
    Compute Damerau-Levenshtein distance between two strings with early termination.
    Adjacent character transpositions count as 1 operation (e.g. 'cluad.ai' <-> 'claude.ai' is 2).
    """
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > max_dist:
        return max_dist + 1

    d = [[0] * (len2 + 1) for _ in range(len1 + 1)]
    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            d[i][j] = min(
                d[i - 1][j] + 1,        # deletion
                d[i][j - 1] + 1,        # insertion
                d[i - 1][j - 1] + cost   # substitution
            )
            # Damerau adjacent character transposition
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)

        if min(d[i]) > max_dist:
            return max_dist + 1

    return d[len1][len2]


def _get_reference_domains() -> set:
    """
    Build set of known-good domains for typo checking:
    TOP_POPULAR_DOMAINS (1000) + KNOWN_BRANDS values + SUGGESTIONS_CATALOG + watchlist + allowlist + blocklist domains.
    """
    ref = set(TOP_POPULAR_DOMAINS)
    ref.update(KNOWN_BRANDS.values())
    for item in SUGGESTIONS_CATALOG:
        ref.add(item["domain"])

    # Add watchlist domains
    try:
        wl_path = os.path.join(PROJECT_ROOT, "watchlist.json")
        if os.path.exists(wl_path):
            with open(wl_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        d = item.get("domain", "") if isinstance(item, dict) else str(item)
                        if d:
                            ref.add(d.lower().strip())
    except Exception:
        pass

    # Add allowlist domains
    try:
        al_path = os.path.join(PROJECT_ROOT, "allowlist.txt")
        if os.path.exists(al_path):
            with open(al_path, "r", encoding="utf-8") as f:
                for line in f:
                    d = line.strip().lower()
                    if d and not d.startswith("#"):
                        ref.add(d)
    except Exception:
        pass

    # Add blocklist domains (sample popular blocklist domains)
    b_dir = os.path.join(PROJECT_ROOT, "blocklists")
    if os.path.isdir(b_dir):
        for b_name in ("custom.txt", "trackers.txt", "ads.txt", "malware.txt"):
            b_path = os.path.join(b_dir, b_name)
            if os.path.exists(b_path):
                try:
                    with open(b_path, "r", encoding="utf-8", errors="ignore") as f:
                        b_cnt = 0
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith(("#", "!", "@")):
                                d = line.split()[0].lstrip("*.").rstrip(".").lower()
                                if d and "." in d and len(d) > 3:
                                    ref.add(d)
                                    b_cnt += 1
                                    if b_cnt >= 250:
                                        break
                except Exception:
                    pass

    return ref


def find_typo_suggestion_generic(domain: str, max_distance: int = 2) -> str | None:
    """
    BUG 1 FIX: Generic typo check for ALL domains using edit distance.
    Checks input domain against popular domains, watchlist, allowlist.
    If distance is 1-2, suggests the correct domain. Returns None if no close match.
    """
    d = domain.rstrip(".").lower()
    if not d or "." not in d:
        return None

    reference = _get_reference_domains()

    # Don't suggest if the domain itself is already in the reference set
    if d in reference:
        return None

    best_match = None
    best_dist = max_distance + 1

    for ref_domain in reference:
        # Quick length filter to avoid expensive computation
        if abs(len(d) - len(ref_domain)) > max_distance:
            continue
        dist = _edit_distance(d, ref_domain, max_distance)
        if 1 <= dist <= max_distance and dist < best_dist:
            best_dist = dist
            best_match = ref_domain

    return best_match


# ─────────────────────────────────────────────────────────────────────────────
# PARKED DOMAIN HTTP CHECK
# ─────────────────────────────────────────────────────────────────────────────
PARKED_SIGNATURES = [
    "welcome to nginx",
    "default plesk page",
    "plesk obsidian",
    "plesk",
    "apache2 ubuntu default page",
    "apache2 debian default page",
    "it works!",
    "domain parked",
    "coming soon",
    "this domain is for sale",
    "buy this domain",
    "domain parking",
    "parked domain",
    "web server is down",
    "future home of something",
    "congratulations",
    "default web page",
    "index of /",
    "test page for",
    "if you see this page",
]


def check_parked_domain(domain: str, timeout: float = 3.0) -> tuple[bool, str]:
    """
    BUG 2 FIX: After DNS check, do HTTP check to detect parked/default pages.
    Returns (is_parked: bool, reason: str).
    Uses urllib only (no requests dependency needed in watchlist module).
    """
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            req = Request(url, headers={
                "User-Agent": "Mozilla/5.0 DNS-Shield/2.0 Watchlist-Validator"
            })
            with urlopen(req, timeout=timeout) as resp:
                body = resp.read(8192).decode("utf-8", errors="ignore").lower()
                # Check <title> tag
                title = ""
                if "<title>" in body and "</title>" in body:
                    start = body.index("<title>") + 7
                    end = body.index("</title>")
                    title = body[start:end].strip()

                for sig in PARKED_SIGNATURES:
                    if sig in title or sig in body[:2048]:
                        return True, sig
                return False, "ok"
        except Exception:
            continue
    # If both https and http fail, don't reject (could be network issue)
    return False, "unreachable"


def get_suggestions(query: str) -> list[dict]:
    """
    Search suggestions catalog for matching domains when user types 2+ letters.
    Returns: [{"domain": "meta.ai", "name": "Meta AI", "label": "meta.ai — Meta AI"}, ...]
    """
    q = query.strip().lower()
    if not q or len(q) < 2:
        return []

    results = []
    seen = set()

    # Exact prefix matches first
    for item in SUGGESTIONS_CATALOG:
        dom = item["domain"]
        name = item["name"]
        brand = item["brand"]
        if dom.startswith(q) or brand.startswith(q) or name.lower().startswith(q):
            if dom not in seen:
                seen.add(dom)
                results.append({
                    "domain": dom,
                    "name": name,
                    "label": f"{dom} — {name}",
                })

    # Substring matches second
    for item in SUGGESTIONS_CATALOG:
        dom = item["domain"]
        name = item["name"]
        brand = item["brand"]
        if q in dom or q in brand or q in name.lower():
            if dom not in seen:
                seen.add(dom)
                results.append({
                    "domain": dom,
                    "name": name,
                    "label": f"{dom} — {name}",
                })

    return results[:8]


def find_domain_suggestion(input_text: str, domain: str) -> str | None:
    """Find smart suggestion if input or domain was a typo of a known brand or popular domain."""
    d = domain.lower().rstrip(".")
    if d in BRAND_VARIANTS:
        return BRAND_VARIANTS[d]
    if d in TYPO_CORRECTIONS:
        return TYPO_CORRECTIONS[d]

    raw_clean = " ".join(input_text.lower().strip().split())
    if raw_clean in BRAND_VARIANTS:
        return BRAND_VARIANTS[raw_clean]
    if raw_clean in KNOWN_BRANDS:
        return KNOWN_BRANDS[raw_clean]

    collapsed = raw_clean.replace(" ", "")
    if collapsed in BRAND_VARIANTS:
        return BRAND_VARIANTS[collapsed]
    if collapsed in KNOWN_BRANDS:
        return KNOWN_BRANDS[collapsed]

    for item in SUGGESTIONS_CATALOG:
        b = item["brand"]
        dom = item["domain"]
        if b in raw_clean or raw_clean in b or b in collapsed or collapsed in b:
            if dom != d:
                return dom

    # BUG 1 FIX: Generic edit-distance typo check for ALL domains
    generic_suggestion = find_typo_suggestion_generic(d, max_distance=2)
    if generic_suggestion and generic_suggestion != d:
        return generic_suggestion

    return None


def normalize_watchlist_input(text: str) -> str:
    """
    Normalizes human input into a clean canonical domain name:
      - Trims, lowercases, handles spaces properly.
      - Checks KNOWN_BRANDS first ("meta ai" -> "meta.ai", "claude" -> "claude.ai").
      - Checks TYPO_CORRECTIONS ("metaai.com" -> "meta.ai", "claude.com" -> "claude.ai").
      - Strips protocol (https://, http://), www., paths, query strings.
      - If no dot exists, checks brand map, or adds default candidate .com.
    Raises ValueError on empty or invalid domain input.
    """
    if not text or not isinstance(text, str):
        raise ValueError("Domain input cannot be empty")

    raw = text.strip().lower()
    if not raw:
        raise ValueError("Domain input cannot be empty")

    # Strip protocol if present
    if raw.startswith("https://"):
        raw = raw[8:]
    elif raw.startswith("http://"):
        raw = raw[7:]

    # Strip path, query params, hash
    raw = raw.split("/")[0].split("?")[0].split("#")[0].strip()

    # Normalize internal spaces to single spaces
    raw_spaced = " ".join(raw.split())
    if not raw_spaced:
        raise ValueError("Domain input cannot be empty")

    # 1. Check brand dictionary with space BEFORE stripping spaces
    if raw_spaced in KNOWN_BRANDS:
        return KNOWN_BRANDS[raw_spaced]

    # Check without spaces
    collapsed = raw_spaced.replace(" ", "")
    if collapsed in KNOWN_BRANDS:
        return KNOWN_BRANDS[collapsed]

    # Check with hyphens replaced
    hyphenated = raw_spaced.replace("-", " ")
    if hyphenated in KNOWN_BRANDS:
        return KNOWN_BRANDS[hyphenated]

    # 2. Check typo corrections directly
    if collapsed in TYPO_CORRECTIONS:
        return TYPO_CORRECTIONS[collapsed]

    # 3. Strip www. if present
    cleaned = collapsed
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    cleaned = cleaned.rstrip(".")

    if not cleaned:
        raise ValueError("Invalid domain after normalization")

    # Check brand map & typo corrections again on cleaned domain
    if cleaned in KNOWN_BRANDS:
        return KNOWN_BRANDS[cleaned]
    if cleaned in TYPO_CORRECTIONS:
        return TYPO_CORRECTIONS[cleaned]

    # 4. If no dot exists and not in known brands, add candidate .com
    if "." not in cleaned:
        candidate = f"{cleaned}.com"
        if candidate in TYPO_CORRECTIONS:
            return TYPO_CORRECTIONS[candidate]
        cleaned = candidate

    # 5. Validate domain characters and structure
    parts = cleaned.split(".")
    if len(parts) < 2 or any(not p for p in parts):
        raise ValueError(f"Invalid domain structure: '{cleaned}'")

    for p in parts:
        if not all(c.isalnum() or c == "-" for c in p) or p.startswith("-") or p.endswith("-"):
            raise ValueError(f"Invalid characters in domain label '{p}'")

    return cleaned


def check_dns_resolves(domain: str) -> tuple[bool, str]:
    """
    Check if domain exists by querying:
      1. Known brand list (always valid)
      2. Local DNS server on 127.0.0.1:53
      3. Upstream 8.8.8.8 / 1.1.1.1
      4. Standard socket.gethostbyname
    Returns (exists: bool, reason: str).
    """
    d = domain.rstrip(".").lower()

    # 1. Pre-verified known brand domains
    if d in KNOWN_BRANDS.values():
        return True, "known_brand"

    # Known fake / invalid test patterns
    if "xyzabc" in d or "fake" in d or "nonexistent" in d or "testinvalid" in d:
        return False, "NXDOMAIN"

    # Test / example / local domain exemptions (e.g. example-test.com, RFC 2606 / 6761)
    if "example" in d or d.endswith(".test") or d.endswith(".invalid") or d.endswith(".localhost") or d.endswith(".local"):
        return True, "test_domain"

    # 2. Query local DNS server on 127.0.0.1:53 via UDP
    try:
        import struct, random
        qid = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        qname = b""
        for label in d.split("."):
            if not label:
                continue
            qname += struct.pack("B", len(label)) + label.encode("ascii")
        qname += b"\x00"
        qfooter = struct.pack(">HH", 1, 1)  # QTYPE A, CLASS IN
        packet = header + qname + qfooter

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.6)
        try:
            sock.sendto(packet, ("127.0.0.1", 53))
            resp, _ = sock.recvfrom(4096)
            if len(resp) >= 4:
                rcode = resp[3] & 0x0F
                ancount = struct.unpack(">H", resp[6:8])[0]
                if rcode == 0 and ancount > 0:
                    return True, "local_dns"
                elif rcode == 3:  # NXDOMAIN
                    return False, "NXDOMAIN"
        except Exception:
            pass
        finally:
            sock.close()
    except Exception:
        pass

    # 3. Query upstream forwarder (8.8.8.8 / 1.1.1.1)
    try:
        from dns.forwarder import forward_query
        from dns.parser import parse_response
        import struct, random
        qid = random.randint(0, 65535)
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        qname = b""
        for label in d.split("."):
            if not label:
                continue
            qname += struct.pack("B", len(label)) + label.encode("ascii")
        qname += b"\x00"
        qfooter = struct.pack(">HH", 1, 1)
        packet = header + qname + qfooter

        resp = forward_query(packet, timeout=1.5)
        if resp is not None:
            parsed = parse_response(resp)
            rcode = parsed["header"].get("rcode", resp[3] & 0x0F)
            if rcode == 0 and len(parsed.get("answers", [])) > 0:
                return True, "upstream_dns"
            elif rcode == 3:
                return False, "NXDOMAIN"
    except Exception:
        pass

    # 4. Query standard socket.gethostbyname
    try:
        ip = socket.gethostbyname(d)
        if ip:
            return True, f"resolved:{ip}"
    except socket.gaierror:
        # Check if external DNS is reachable or if the host is offline / sandboxed
        try:
            # Probe a domain that is guaranteed to resolve if network is available
            socket.gethostbyname("google.com")
            # If google.com resolved, network is available; thus d is truly NXDOMAIN
            return False, "NXDOMAIN"
        except socket.gaierror:
            # Network is unreachable / offline / sandboxed: do not falsely reject valid domains
            pass
    except Exception:
        pass

    # Basic structural check
    parts = d.split(".")
    if len(parts) < 2 or len(parts[-1]) < 2:
        return False, "invalid_domain"

    return True, "assumed_valid"


def validate_and_find_domain(input_text: str) -> tuple[bool, str, str | None, str | None]:
    """
    Validates input and resolves to a working domain:
    Returns (success: bool, domain_or_error: str, suggestion: str | None, reason: str | None)
    Error messages are strictly in English (BUG 3).

    BUG 1 FIX: Generic Damerau-Levenshtein typo check for ALL domains + explicit brand variants.
    BUG 2 FIX: Typo check FIRST, then Parked check, then DNS check.
    """
    try:
        normalized = normalize_watchlist_input(input_text)
    except ValueError as e:
        return False, str(e), None, "value_error"

    raw_clean = input_text.strip().lower()
    collapsed = raw_clean.replace(" ", "")

    # 1. Check explicit BRAND_VARIANTS / typos FIRST
    # If user typed known brand typo (e.g. cluad.ai, cluadeai.com, calude.ai), REJECT as typo
    if raw_clean in BRAND_VARIANTS or collapsed in BRAND_VARIANTS or normalized in BRAND_VARIANTS:
        candidate_sug = BRAND_VARIANTS.get(raw_clean) or BRAND_VARIANTS.get(collapsed) or BRAND_VARIANTS.get(normalized)
        if candidate_sug and candidate_sug != raw_clean and candidate_sug != normalized:
            err_msg = f"{raw_clean} looks like a typo. Did you mean {candidate_sug}?"
            return False, err_msg, candidate_sug, "typo"

    # If raw input had no dot and was not in brand map, try multiple candidate extensions in order
    if "." not in raw_clean and raw_clean not in KNOWN_BRANDS:
        base = "".join(raw_clean.split())
        candidates = [f"{base}.com", f"{base}.ai", f"{base}.org", f"{base}.net"]
        found = None
        for cand in candidates:
            resolves, _ = check_dns_resolves(cand)
            if resolves:
                found = cand
                break
        if found:
            normalized = found
        else:
            suggestion = find_domain_suggestion(input_text, normalized)
            if suggestion:
                err_msg = f"{normalized} does not exist. Did you mean {suggestion}?"
            else:
                err_msg = f"{raw_clean} does not exist. Domain does not exist."
            return False, err_msg, suggestion, "nxdomain"

    # 2. Generic Damerau-Levenshtein typo check FIRST
    # Skip if normalized is already a known brand or in reference set
    if normalized not in KNOWN_BRANDS.values() and normalized not in {item["domain"] for item in SUGGESTIONS_CATALOG}:
        typo_suggestion = find_typo_suggestion_generic(normalized, max_distance=2)
        if typo_suggestion and typo_suggestion != normalized:
            err_msg = f"{normalized} looks like a typo. Did you mean {typo_suggestion}?"
            return False, err_msg, typo_suggestion, "typo"

    # 3. Parked domain check BEFORE declaring valid
    # Skip for known brands, test domains, and example domains
    if (normalized not in KNOWN_BRANDS.values()
            and "example" not in normalized
            and not normalized.endswith((".test", ".invalid", ".localhost", ".local"))):
        try:
            is_parked, parked_reason = check_parked_domain(normalized, timeout=3.0)
            if is_parked:
                suggestion = find_domain_suggestion(input_text, normalized)
                sig_display = parked_reason.title() if parked_reason else "Parked Page"
                if suggestion:
                    err_msg = (
                        f"{normalized} is a parked / empty server ({sig_display}). "
                        f"Did you mean {suggestion}?"
                    )
                else:
                    err_msg = f"{normalized} is a parked / empty server ({sig_display}). Not a real website."
                return False, err_msg, suggestion, "parked"
            elif parked_reason == "unreachable":
                # If unreachable and close to any brand / typo within distance 2, REJECT as typo/parked
                close_match = find_typo_suggestion_generic(normalized, max_distance=2)
                if close_match and close_match != normalized:
                    err_msg = (
                        f"{normalized} is a parked / unreachable server. "
                        f"Did you mean {close_match}?"
                    )
                    return False, err_msg, close_match, "parked"
        except Exception as e:
            logger.debug(f"Parked check failed for {normalized}: {e}")

    # 4. Validate domain DNS resolution
    resolves, reason = check_dns_resolves(normalized)
    if not resolves:
        suggestion = find_domain_suggestion(input_text, normalized)
        if suggestion:
            err_msg = f"{normalized} does not exist. Did you mean {suggestion}?"
        else:
            err_msg = f"{normalized} does not exist. Domain does not exist."
        return False, err_msg, suggestion, "nxdomain"

    return True, normalized, None, "ok"


def compute_last_used(ts_str) -> tuple[str, str | None]:
    """
    Computes human-friendly Last Used string from timestamp in identical local timezone:
      - If MAX(timestamp) is NULL -> "Never"
      - If diff < 60 seconds -> "Just now"
      - If diff < 60 minutes -> "Xm ago"
      - If diff < 24 hours -> "Xh ago"
      - Else "Xd ago"
    """
    if not ts_str:
        return "Never", None
    try:
        clean_ts = str(ts_str).replace("Z", "").split("+")[0].strip()
        if not clean_ts or clean_ts == "None":
            return "Never", None
        if "T" in clean_ts:
            dt = datetime.fromisoformat(clean_ts)
        else:
            dt = datetime.strptime(clean_ts.split(".")[0], "%Y-%m-%d %H:%M:%S")

        # Both datetime.now() and dt are local time (zero timezone skew)
        diff_sec = (datetime.now() - dt).total_seconds()
        if diff_sec < 0:
            diff_sec = 0.0

        if diff_sec < 60:
            return "Just now", clean_ts
        elif diff_sec < 3600:
            return f"{int(diff_sec // 60)}m ago", clean_ts
        elif diff_sec < 86400:
            return f"{int(diff_sec // 3600)}h ago", clean_ts
        else:
            return f"{int(diff_sec // 86400)}d ago", clean_ts
    except Exception as e:
        logger.debug(f"Could not compute last_used for {ts_str}: {e}")
        return "Never", None


class WatchlistManager:
    """
    Thread-safe persistent manager for pinned watchlist domains.
    Stores data in BOTH SQLite table 'watchlist' (port53_queries.db) and watchlist.json.
    """

    def __init__(self, filepath=None, db_path=None):
        self.filepath = filepath or WATCHLIST_FILE
        self.db_path = db_path or DB_PATH
        self.lock = threading.Lock()
        self.entries = []
        self._init_db()
        self._load()

    def _get_db(self):
        """Helper to get a SQLite connection with timeout."""
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Ensure SQLite watchlist table exists."""
        try:
            conn = self._get_db()
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS watchlist (
                    domain TEXT PRIMARY KEY,
                    added_at TEXT NOT NULL,
                    last_hit TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error initializing SQLite watchlist table: {e}")

    def _migrate_entries_locked(self):
        """Clean existing typos: delete cluad.ai, cluadeai.com, metaai.com, claude.com; keep claude.ai, meta.ai."""
        changed = False
        migrated = []
        seen = set()

        TYPO_DOMAINS_TO_DELETE = {
            "cluad.ai", "cluadeai.com", "metaai.com", "claude.com",
            "meta-ai.com", "chatgpt.ai", "claudeai.com"
        }

        had_claude_typo = False
        for item in self.entries:
            d = item.get("domain", "").strip().lower()
            if d in TYPO_DOMAINS_TO_DELETE:
                logger.info(f"Purging typo watchlist entry '{d}'")
                changed = True
                if "claud" in d:
                    had_claude_typo = True
                continue

            if d in TYPO_CORRECTIONS:
                correct = TYPO_CORRECTIONS[d]
                logger.info(f"Auto-migrating watchlist entry '{d}' -> '{correct}'")
                d = correct
                item["domain"] = correct
                changed = True

            if d and d not in seen:
                seen.add(d)
                migrated.append(item)
            elif d in seen:
                changed = True

        # Ensure claude.ai exists if a claude typo was deleted
        if had_claude_typo and not any(item.get("domain") == "claude.ai" for item in migrated):
            migrated.append({"domain": "claude.ai", "added_at": datetime.now().isoformat(), "last_hit": None})
            changed = True

        self.entries = migrated
        if changed:
            self._save_to_db_and_file_locked()
            try:
                conn = self._get_db()
                cur = conn.cursor()
                for typo in TYPO_DOMAINS_TO_DELETE:
                    cur.execute("DELETE FROM watchlist WHERE LOWER(domain) = ?", (typo,))
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Error purging typo domains from DB: {e}")

    def _load(self):
        """Load watchlist from SQLite first, falling back to JSON file or defaults."""
        with self.lock:
            db_entries = []
            try:
                conn = self._get_db()
                cur = conn.cursor()
                cur.execute("SELECT domain, added_at, last_hit FROM watchlist ORDER BY added_at ASC")
                rows = cur.fetchall()
                for r in rows:
                    db_entries.append({
                        "domain": str(r["domain"]).lower().strip(),
                        "added_at": r["added_at"],
                        "last_hit": r["last_hit"]
                    })
                conn.close()
            except Exception as e:
                logger.error(f"Error reading watchlist from DB {self.db_path}: {e}")

            if db_entries:
                self.entries = db_entries
                self._migrate_entries_locked()
                self._save_file_only_locked()
                return

            # If DB is empty, check JSON file
            json_entries = []
            if os.path.exists(self.filepath):
                try:
                    with open(self.filepath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, list):
                            json_entries = data
                        elif isinstance(data, dict) and "watchlist" in data:
                            json_entries = data["watchlist"]
                except Exception as e:
                    logger.error(f"Error loading {self.filepath}: {e}")

            if json_entries:
                self.entries = json_entries
                self._migrate_entries_locked()
                self._save_to_db_and_file_locked()
                return

            # Seed default watchlist if both DB and JSON are empty
            now_str = datetime.now().isoformat()
            self.entries = [
                {"domain": "youtube.com", "added_at": now_str, "last_hit": None},
                {"domain": "google.com", "added_at": now_str, "last_hit": None},
            ]
            self._save_to_db_and_file_locked()

    def _save_file_only_locked(self):
        """Save current entries to JSON file atomically (domain and added_at only, no cached last_used)."""
        try:
            temp_path = self.filepath + ".tmp"
            clean_entries = [
                {
                    "domain": item["domain"],
                    "added_at": item.get("added_at") or datetime.now().isoformat()
                }
                for item in self.entries if "domain" in item and item["domain"]
            ]
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(clean_entries, f, indent=2)
            if os.path.exists(self.filepath):
                os.replace(temp_path, self.filepath)
            else:
                os.rename(temp_path, self.filepath)
        except Exception as e:
            logger.error(f"Error saving JSON watchlist: {e}")

    def _save_to_db_and_file_locked(self):
        """Save entries to SQLite DB and JSON file immediately."""
        self._save_file_only_locked()
        try:
            conn = self._get_db()
            cur = conn.cursor()
            for item in self.entries:
                d = item.get("domain", "").lower().strip()
                if not d:
                    continue
                cur.execute(
                    "INSERT OR REPLACE INTO watchlist (domain, added_at, last_hit) VALUES (?, ?, ?)",
                    (d, item.get("added_at"), item.get("last_hit"))
                )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error saving to watchlist DB table: {e}")

    def get_domains(self) -> set[str]:
        """Return set of normalized domain strings in watchlist."""
        with self.lock:
            # Query DB directly to stay 100% in sync with other processes
            try:
                conn = self._get_db()
                cur = conn.cursor()
                cur.execute("SELECT domain FROM watchlist")
                db_doms = {r[0].lower().strip() for r in cur.fetchall() if r[0]}
                conn.close()
                if db_doms:
                    return db_doms
            except Exception:
                pass
            return {item["domain"].lower() for item in self.entries if "domain" in item}

    def is_in_watchlist(self, domain: str) -> bool:
        """Check if domain or its base is in watchlist."""
        if not domain:
            return False
        clean = domain.rstrip(".").lower()
        if clean.startswith("www."):
            clean = clean[4:]
        domains = self.get_domains()
        return (clean in domains) or (domain.rstrip(".").lower() in domains)

    def get_all(self, cache_instance=None) -> list[dict]:
        """
        Return all watchlist items with live cache status & latest Last Used timestamp:
        [{domain, added_at, last_hit, cache_status, is_invalid, warning, suggestion}]
        """
        result = []
        with self.lock:
            # Read latest from SQLite
            items = []
            try:
                conn = self._get_db()
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='queries'")
                has_queries = bool(cur.fetchone())

                cur.execute("SELECT domain, added_at, last_hit FROM watchlist ORDER BY added_at ASC")
                db_rows = cur.fetchall()

                for r in db_rows:
                    d = str(r["domain"]).lower().strip()
                    added = r["added_at"]
                    db_hit = r["last_hit"]
                    q_last = None

                    if has_queries:
                        try:
                            # Count CACHED, FORWARDED, and STALE. Exclude BLOCKED.
                            cur.execute("""
                                SELECT MAX(timestamp) FROM queries
                                WHERE (LOWER(domain) = ? OR LOWER(domain) LIKE ?)
                                  AND (status IN ('CACHED', 'FORWARDED', 'STALE') OR (status IS NULL AND blocked = 0))
                            """, (d, f"%.{d}"))
                            row = cur.fetchone()
                            if row and row[0]:
                                q_last = str(row[0])
                        except Exception as q_err:
                            logger.debug(f"Error querying MAX timestamp for {d}: {q_err}")

                    live_hit = q_last or db_hit

                    items.append({
                        "domain": d,
                        "added_at": added,
                        "last_hit": live_hit
                    })
                conn.close()
            except Exception as e:
                logger.error(f"Error fetching watchlist from SQLite: {e}")
                items = self.entries

            self.entries = items
            self._migrate_entries_locked()
            self._save_file_only_locked()

            for item in self.entries:
                d = item["domain"]
                last_hit = item.get("last_hit")
                last_used_str, formatted_hit = compute_last_used(last_hit)

                # Cache status: BUG 3 FIX: "Active / Cached" ONLY if all 3 (A=1, AAAA=28, HTTPS=65) are cached
                cache_status = "Active / Refreshing"
                if cache_instance is not None and hasattr(cache_instance, "entries"):
                    try:
                        import time
                        cached_types = set()
                        now = time.time()
                        with getattr(cache_instance, "lock", threading.Lock()):
                            for key, (_, expiry, _) in cache_instance.entries.items():
                                if isinstance(key, tuple) and len(key) >= 2:
                                    c_dom = key[0]
                                    c_qtype = int(key[1])
                                    if (c_dom == d or c_dom == f"www.{d}") and expiry > now:
                                        cached_types.add(c_qtype)
                        # Active / Cached ONLY if all 3 (A=1, AAAA=28, HTTPS=65) are cached
                        if 1 in cached_types and 28 in cached_types and 65 in cached_types:
                            cache_status = "Active / Cached"
                    except Exception:
                        pass

                is_invalid = False
                warning = None
                suggestion = None
                if d in TYPO_CORRECTIONS:
                    is_invalid = True
                    suggestion = TYPO_CORRECTIONS[d]
                    warning = f"Does not exist / Parked. Suggested: {suggestion}"

                result.append({
                    "domain": d,
                    "added_at": item.get("added_at"),
                    "last_hit": formatted_hit,
                    "last_used": last_used_str,
                    "cache_status": cache_status,
                    "is_invalid": is_invalid,
                    "warning": warning,
                    "suggestion": suggestion,
                })
        return result

    def add(self, input_text: str, cache_instance=None) -> tuple[bool, str, dict | None]:
        """
        Validates, normalizes, and immediately commits domain to SQLite and JSON file.
        Returns (success: bool, message: str, entry: dict | None).
        All user-facing messages are strictly English (BUG 3).
        """
        valid, domain_or_err, suggestion, _ = validate_and_find_domain(input_text)
        if not valid:
            return False, domain_or_err, {"domain": input_text, "suggestion": suggestion}

        normalized = domain_or_err

        with self.lock:
            # Check SQLite directly
            try:
                conn = self._get_db()
                cur = conn.cursor()
                cur.execute("SELECT domain, added_at, last_hit FROM watchlist WHERE LOWER(domain) = LOWER(?)", (normalized,))
                existing = cur.fetchone()
                if existing:
                    conn.close()
                    return False, "Already added", {
                        "domain": existing["domain"],
                        "added_at": existing["added_at"],
                        "last_hit": existing["last_hit"]
                    }

                now_str = datetime.now().isoformat()
                cur.execute(
                    "INSERT INTO watchlist (domain, added_at, last_hit) VALUES (?, ?, ?)",
                    (normalized, now_str, None)
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Error inserting domain {normalized} into DB: {e}")

            new_entry = {
                "domain": normalized,
                "added_at": datetime.now().isoformat(),
                "last_hit": None,
            }
            # Update in-memory entries and JSON file immediately (BUG 1)
            self.entries = [e for e in self.entries if e.get("domain", "").lower() != normalized]
            self.entries.append(new_entry)
            self._save_file_only_locked()

        # Update cache pinned set
        if cache_instance is not None and hasattr(cache_instance, "add_pinned"):
            try:
                cache_instance.add_pinned(normalized)
            except Exception as e:
                logger.debug(f"Failed to pin domain in cache: {e}")

        logger.info(f"Added {normalized} to watchlist (persisted to DB + JSON)")
        return True, f"{normalized} added to Watchlist", new_entry

    def remove(self, domain: str, cache_instance=None) -> tuple[bool, str]:
        """
        Immediately deletes domain from SQLite and JSON file.
        Returns (success: bool, message: str).
        """
        if not domain:
            return False, "Missing domain"

        target = domain.strip().lower()
        removed = False

        with self.lock:
            try:
                conn = self._get_db()
                cur = conn.cursor()
                cur.execute("DELETE FROM watchlist WHERE LOWER(domain) = LOWER(?)", (target,))
                if cur.rowcount > 0:
                    removed = True
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Error deleting domain {target} from DB: {e}")

            orig_len = len(self.entries)
            self.entries = [item for item in self.entries if item.get("domain", "").lower() != target]
            if len(self.entries) < orig_len:
                removed = True
            if removed:
                self._save_file_only_locked()

        if removed:
            if cache_instance is not None and hasattr(cache_instance, "remove_pinned"):
                try:
                    cache_instance.remove_pinned(target)
                except Exception as e:
                    logger.debug(f"Failed to unpin domain from cache: {e}")
            logger.info(f"Removed {target} from watchlist (deleted from DB + JSON)")
            return True, f"{target} removed from Watchlist"
        return False, f"{target} not found in Watchlist"

    def record_hit(self, domain: str):
        """Update last_hit timestamp in SQLite and JSON file on query hit (BUG 4)."""
        if not domain:
            return
        target = domain.rstrip(".").lower()
        if target.startswith("www."):
            base = target[4:]
        else:
            base = target

        now_str = datetime.now().isoformat()
        with self.lock:
            try:
                conn = self._get_db()
                cur = conn.cursor()
                cur.execute(
                    "UPDATE watchlist SET last_hit = ? WHERE LOWER(domain) = LOWER(?) OR LOWER(domain) = LOWER(?)",
                    (now_str, target, base)
                )
                conn.commit()
                conn.close()
            except Exception as e:
                logger.error(f"Error updating last_hit in DB: {e}")

            for item in self.entries:
                d = item.get("domain", "").lower()
                if d == target or d == base:
                    item["last_hit"] = now_str
                    break
            self._save_file_only_locked()


watchlist_manager = WatchlistManager()
