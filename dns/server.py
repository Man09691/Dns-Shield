"""
dns/server.py  —  DNS Server with CNAME Cloaking Detection
=========================================================
Handles: blocklist check -> cache -> upstream forward -> CNAME chase
CNAME cloaking: tracker uses a clean-looking domain that CNAMEs to a
blocked domain. We chase the full CNAME chain in every upstream response
and block if any hop is in the blocklist.
"""

import os
import socket
import struct
import threading
import time
import logging
import json
import ipaddress

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from dns.parser import (
    parse_header, parse_question, parse_response, get_answer_ips,
    get_min_ttl, extract_cname_chain_from_packet, parse_edns0_payload_size
)
from dns.builder import build_blocked_response, build_refused_response, build_servfail_response, swap_query_id
from dns.forwarder import forward_query
from dns.stats import stats as global_stats

logger = logging.getLogger("dns.server")


def _disable_windows_udp_connreset(sock):
    try:
        sock.ioctl(-1744830452, False)
        logger.debug("Disabled Windows UDP CONNRESET")
    except (AttributeError, OSError, ValueError):
        pass


def check_client_allowed(client_ip: str, config: dict = None) -> bool:
    """
    Task S5: Client Allowlist Check.
    1. Always allow 127.0.0.1 and ::1 even if allowlist is empty or disabled.
    2. Read from config: 'client_allowlist' and 'client_allowlist_enabled'.
    3. Support CIDR ranges (e.g. 192.168.0.0/16) and single IPs using ipaddress module.
    4. If client IP is not in allowlist and enabled -> return False (REFUSED).
    5. If allowlist is disabled -> allow all (return True).
    """
    if not client_ip:
        return True

    ip_str = str(client_ip).strip()
    if ip_str in ("127.0.0.1", "::1", "localhost"):
        return True

    if config is None:
        cfg_path = os.path.join(PROJECT_ROOT, "config.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except Exception:
                config = {}
        else:
            config = {}

    enabled = config.get("client_allowlist_enabled", True)
    if not enabled:
        return True

    allowlist = config.get("client_allowlist", [
        "127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"
    ])

    try:
        c_addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for entry in allowlist:
        entry_str = str(entry).strip()
        if not entry_str:
            continue
        try:
            if "/" in entry_str:
                net = ipaddress.ip_network(entry_str, strict=False)
                if c_addr in net:
                    return True
            else:
                target = ipaddress.ip_address(entry_str)
                if c_addr == target:
                    return True
        except ValueError:
            continue

    return False


def validate_upstream_response(
    response_data: bytes,
    source_ip: str = "8.8.8.8",
    expected_id: int = None,
    expected_domain: str = None,
    allowed_upstreams: list = None,
    allowlist = None,
    blocklist = None,
    **kwargs
) -> tuple[bool, str]:
    """
    Task S4: Upstream response validation.
    Checks before caching or returning to client:
    1. Source IP must be exactly the upstream queried (in allowed_upstreams, e.g. 8.8.8.8 or 1.1.1.1).
    2. Transaction ID must match the request Transaction ID.
    3. QR flag must be 1 (response, not query).
    4. QNAME in response must match QNAME asked for (case-insensitive).
    5. If response for a public domain contains a private / spoofed IP (10.x, 192.168.x, 172.16.x, 127.0.0.1)
       in A/AAAA answer and that domain is NOT in allowlist.txt -> drop as spoofed.
    Returns (True, "OK") if valid, else (False, reason).
    """
    if isinstance(response_data, (bytes, bytearray)) and isinstance(source_ip, (bytes, bytearray)):
        req_bytes = response_data
        resp_bytes = source_ip
        actual_source_ip = kwargs.get("source_ip", expected_id if isinstance(expected_id, str) else "8.8.8.8")
        req_header = parse_header(req_bytes)
        req_domain, _, _, _ = parse_question(req_bytes)
        return validate_upstream_response(
            response_data=resp_bytes,
            source_ip=actual_source_ip,
            expected_id=req_header["id"],
            expected_domain=req_domain,
            allowed_upstreams=allowed_upstreams,
            allowlist=allowlist,
            blocklist=blocklist,
        )

    if not response_data or len(response_data) < 12:
        return False, "Response packet is empty or smaller than 12-byte DNS header"

    # 1. Source IP check
    allowed = allowed_upstreams if allowed_upstreams is not None else ["8.8.8.8", "1.1.1.1"]
    if source_ip not in allowed:
        return False, f"Source IP '{source_ip}' is not an authorized upstream ({allowed})"

    # 2. Transaction ID check
    resp_id = struct.unpack(">H", response_data[:2])[0]
    if expected_id is not None and resp_id != expected_id:
        return False, f"Transaction ID mismatch: expected {expected_id}, got {resp_id}"

    # 3. QR flag check
    flags = struct.unpack(">H", response_data[2:4])[0]
    qr = (flags >> 15) & 1
    if qr != 1:
        return False, "QR flag is 0: packet is a query, not a DNS response"

    # 4. QNAME match check
    try:
        resp_domain, _, _, _ = parse_question(response_data)
        if expected_domain is not None:
            if resp_domain.lower().rstrip(".") != expected_domain.lower().rstrip("."):
                return False, f"QNAME mismatch: expected '{expected_domain}', got '{resp_domain}'"
    except Exception as e:
        return False, f"Could not parse QNAME from response: {e}"

    # 5. Private/spoofed IP check (DNS Rebinding protection)
    domain_to_check = expected_domain or resp_domain
    clean_domain = domain_to_check.lower().rstrip(".")
    is_allowed = False

    if allowlist is not None:
        if hasattr(allowlist, "allowed_domains"):
            allowed_set = getattr(allowlist, "allowed_domains", set())
            is_allowed = clean_domain in allowed_set or any(clean_domain.endswith("." + a) for a in allowed_set)
        elif hasattr(allowlist, "is_allowlisted"):
            is_allowed = allowlist.is_allowlisted(clean_domain)
        elif isinstance(allowlist, (set, list, tuple)):
            is_allowed = clean_domain in allowlist or any(clean_domain.endswith("." + a) for a in allowlist)

    if not is_allowed:
        try:
            parsed = parse_response(response_data)
            # If the response contains a CNAME chain pointing to a blocked domain,
            # this query will be intercepted and blocked by CNAME cloaking defense,
            # not treated as a DNS rebinding failure.
            cname_is_blocked = False
            if blocklist is not None:
                cname_targets = extract_cname_chain_from_packet(
                    response_data, parsed.get("answers", [])
                )
                for ct in cname_targets:
                    cname_clean = ct.rstrip(".")
                    b, _ = blocklist.is_blocked(cname_clean)
                    if b:
                        cname_is_blocked = True
                        break

            if not cname_is_blocked:
                answer_ips = get_answer_ips(parsed.get("answers", []))
                for ip_str in answer_ips:
                    try:
                        ip_obj = ipaddress.ip_address(ip_str)
                        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                            return False, f"Spoofed private IP {ip_str} in response for public domain {domain_to_check}"
                    except ValueError:
                        pass
        except Exception as e:
            logger.debug(f"Error checking answer IPs for private spoofing: {e}")

    return True, "OK"


class DNSServer:
    def __init__(self, config, blocklist, cache, rate_limiter, stats_obj):
        self.config = config
        self.blocklist = blocklist
        self.cache = cache
        self.rate_limiter = rate_limiter
        # stats_obj main.py se aayega, nahi toh global singleton use karo
        self.stats = stats_obj if stats_obj is not None else global_stats

        # Fallback cache size to system RAM default if not configured
        from dns.cache import get_default_cache_size
        if "cache_size" not in config or config.get("cache_size") is None:
            default_sz = get_default_cache_size()
            self.config["cache_size"] = default_sz
            if hasattr(self.cache, "set_max_size"):
                self.cache.set_max_size(default_sz)

        self.listen_host = config.get("listen_host", "0.0.0.0")
        self.listen_port = config.get("listen_port", 53)
        self.upstream_dns = config.get("upstream_dns", "8.8.8.8")
        self.upstream_fallback = config.get("upstream_fallback", "1.1.1.1")
        self.upstream_port = config.get("upstream_port", 53)
        self.upstream_timeout = config.get("upstream_timeout", 3)
        self.blocking_mode = config.get("blocking_mode", "zero_ip")
        self.upstream_validation = config.get("upstream_validation", True)
        self.allowed_upstreams = config.get("allowed_upstreams", ["8.8.8.8", "1.1.1.1"])
        self.client_allowlist_enabled = config.get("client_allowlist_enabled", True)
        self.client_allowlist = config.get("client_allowlist", ["127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"])

        self.sock = None
        self.tcp_sock = None
        self.running = False

        # Connect cache to stats for accurate live & expired counters
        if hasattr(self.stats, "set_cache_ref"):
            self.stats.set_cache_ref(self.cache)

        # Blocklist size dashboard ko dikhane ke liye
        try:
            self.stats.set_meta(
                blocklist_size=len(self.blocklist.blocked_domains),
                cache_size=len(self.cache.entries) if hasattr(self.cache, "entries") else 0,
            )
        except Exception:
            self.stats.set_meta(blocklist_size=235974, cache_size=0)

        # Watchlist integration
        try:
            from dns.watchlist import watchlist_manager
            self.watchlist = watchlist_manager
            if hasattr(self.cache, "set_prefetch_handler"):
                self.cache.set_prefetch_handler(self._prefetch_watchlist_domain)
            if hasattr(self.cache, "set_pinned_domains"):
                self.cache.set_pinned_domains(self.watchlist.get_domains())
        except Exception as e:
            logger.debug(f"Watchlist initialization error: {e}")
            self.watchlist = None

    def _prefetch_watchlist_domain(self, domain: str, qtypes=(1, 28, 65)):
        """
        PREFETCH SIMPLE:
        For Watchlist domains ONLY, fetch A (1), AAAA (28), and HTTPS (65) all 3 together in background.
        User query must NOT wait for prefetch.
        """
        clean_d = domain.rstrip(".").lower()
        if hasattr(self, "watchlist") and self.watchlist and not self.watchlist.is_in_watchlist(clean_d):
            return

        for qt in qtypes:
            try:
                self._prefetch_single_record(clean_d, qt)
            except Exception as e:
                logger.debug(f"[WATCHLIST PREFETCH] Error prefetching {clean_d} qtype={qt}: {e}")

    def _prefetch_single_record(self, domain: str, qtype: int):
        """Fetch a single record type from upstream and cache it."""
        # Blocked domains still NOT cached
        if self.blocklist and self.blocklist.is_blocked(domain)[0]:
            return

        try:
            import random
            qid = random.randint(0, 65535)
            header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
            qname = b""
            for label in domain.strip(".").split("."):
                if not label:
                    continue
                qname += struct.pack("B", len(label)) + label.encode("ascii")
            qname += b"\x00"
            qfooter = struct.pack(">HH", qtype, 1)
            query_bytes = header + qname + qfooter

            resp = forward_query(
                query_bytes,
                upstream_dns=self.upstream_dns,
                upstream_port=self.upstream_port,
                fallback_dns=self.upstream_fallback,
                timeout=self.upstream_timeout,
            )
            if resp is not None:
                winner_ip = getattr(resp, "upstream", getattr(resp, "winner", self.upstream_dns))
                is_valid, _ = self.validate_upstream_response(resp, winner_ip, qid, domain)
                if is_valid:
                    parsed = parse_response(resp)
                    cnames = extract_cname_chain_from_packet(resp, parsed.get("answers", []))
                    for c in cnames:
                        if self.blocklist.is_blocked(c.rstrip('.'))[0]:
                            return
                    rcode = parsed["header"].get("rcode", 0)
                    ttl = 60
                    if parsed.get("answers"):
                        ttl = get_min_ttl(parsed["answers"])
                    elif rcode == 3:
                        ttl = 300
                    if ttl > 0:
                        self.cache.put(domain, qtype, resp, ttl)
                        logger.info(f"[WATCHLIST PREFETCH] Updated {domain} (qtype {qtype}) TTL={ttl}s")
        except Exception as e:
            logger.debug(f"[WATCHLIST PREFETCH] Error prefetching {domain} qtype={qtype}: {e}")

    def check_client_allowed(self, client_ip: str) -> bool:
        return check_client_allowed(client_ip, self.config)

    def validate_upstream_response(self, response_data, source_ip, expected_id, expected_domain):
        if not self.config.get("upstream_validation", True):
            return True, "OK"
        allowed = self.config.get("allowed_upstreams", ["8.8.8.8", "1.1.1.1"])
        allowlist = getattr(self.blocklist, "allowed_domains", None)
        return validate_upstream_response(
            response_data=response_data,
            source_ip=source_ip,
            expected_id=expected_id,
            expected_domain=expected_domain,
            allowed_upstreams=allowed,
            allowlist=allowlist,
            blocklist=self.blocklist,
        )

    def start(self):
        # Ensure blocklist is fully loaded before server starts listening on UDP/TCP
        if hasattr(self.blocklist, "blocked_domains"):
            if not self.blocklist.blocked_domains or len(self.blocklist.blocked_domains) == 0:
                blocklist_dir = self.config.get("blocklist_dir", "blocklists")
                if not os.path.isabs(blocklist_dir):
                    blocklist_dir = os.path.join(PROJECT_ROOT, blocklist_dir)
                allowlist_file = self.config.get("allowlist_file", "allowlist.txt")
                if not os.path.isabs(allowlist_file):
                    allowlist_file = os.path.join(PROJECT_ROOT, allowlist_file)
                if hasattr(self.blocklist, "load_allowlist"):
                    self.blocklist.load_allowlist(allowlist_file)
                self.blocklist.load_all_blocklists(blocklist_dir)

            loaded_count = len(self.blocklist.blocked_domains)
            logger.info(f"Loaded {loaded_count} domains")
            print(f"Loaded {loaded_count} domains")

        # UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _disable_windows_udp_connreset(self.sock)
        self.sock.bind((self.listen_host, self.listen_port))

        # TCP socket
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.tcp_sock.bind((self.listen_host, self.listen_port))
            self.tcp_sock.listen(10)
        except Exception as e:
            logger.error(f"Failed to bind TCP socket on {self.listen_host}:{self.listen_port}: {e}")

        self.running = True

        logger.info(f"DNS server listening on {self.listen_host}:{self.listen_port} (UDP+TCP)")
        print(f"DNS server listening on {self.listen_host}:{self.listen_port} (UDP+TCP)")

        cleanup_thread = threading.Thread(target=self._cache_cleanup_loop, daemon=True)
        cleanup_thread.start()

        tcp_thread = threading.Thread(target=self._tcp_accept_loop, daemon=True)
        tcp_thread.start()

        self._receive_loop()

    def _tcp_accept_loop(self):
        while self.running:
            try:
                conn, client_addr = self.tcp_sock.accept()
            except OSError:
                if not self.running:
                    break
                continue
            thread = threading.Thread(
                target=self.handle_tcp_client,
                args=(conn, client_addr),
                daemon=True,
            )
            thread.start()

    def handle_tcp_client(self, conn, client_addr=None):
        if client_addr is None:
            try:
                client_addr = conn.getpeername()
            except Exception:
                client_addr = ("127.0.0.1", 0)
        try:
            conn.settimeout(5.0)
            len_bytes = conn.recv(2)
            if len(len_bytes) < 2:
                return
            msg_len = struct.unpack(">H", len_bytes)[0]
            data = bytearray()
            while len(data) < msg_len:
                chunk = conn.recv(msg_len - len(data))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) < msg_len:
                return
            self._handle_query(bytes(data), client_addr, transport="TCP", tcp_conn=conn)
        except Exception as e:
            logger.debug(f"TCP client error from {client_addr}: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _receive_loop(self):
        while self.running:
            try:
                data, client_addr = self.sock.recvfrom(4096)
            except ConnectionResetError:
                continue
            except OSError as e:
                if self.running:
                    logger.error(f"Socket error in receive loop: {e}")
                continue

            thread = threading.Thread(
                target=self._handle_query,
                args=(data, client_addr),
                daemon=True,
            )
            thread.start()

    def _handle_query(self, data, client_addr, transport="UDP", tcp_conn=None):
        start_time = time.time()
        client_ip = client_addr[0]

        try:
            header = parse_header(data)
            query_id = header["id"]
            domain, qtype, qclass, question_end = parse_question(data)
            payload_size = parse_edns0_payload_size(data, header)
        except (ValueError, IndexError, struct.error) as e:
            logger.warning(f"Malformed packet from {client_ip}: {e}")
            return

        qtype_names = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS", 65: "HTTPS"}
        qtype_str = qtype_names.get(qtype, str(qtype))

        def _truncate_if_needed(resp):
            if transport == "UDP" and len(resp) > payload_size:
                flags = struct.unpack(">H", resp[2:4])[0]
                flags |= 0x0200  # TC bit (truncation)
                resp = resp[:2] + struct.pack(">H", flags) + resp[4:]
                return resp[:payload_size]
            return resp

        # ── S5: Client Allowlist Check (BEFORE blocking / rate limit / cache / forward) ──
        if not self.check_client_allowed(client_ip):
            elapsed = (time.time() - start_time) * 1000
            response = build_refused_response(data, question_end, query_id)
            response = _truncate_if_needed(response)
            self._send_response(response, client_addr, transport=transport, tcp_conn=tcp_conn)
            if hasattr(self.stats, "record_client_blocked"):
                self.stats.record_client_blocked(client_ip)
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "CLIENT_BLOCKED",
                    category="client_allowlist", response_ms=elapsed,
                    upstream_ip="-", internal_lookup_ns=0,
                    transport=transport, blocked=False, cached=False
                )
            except Exception: pass
            logger.warning(f"CLIENT_BLOCKED  {client_ip}  {domain}  {qtype_str}  [REFUSED RCODE 5]  [{transport}]")
            self._print_query("REFUSED", client_ip, domain, qtype_str, elapsed, category="CLIENT_BLOCKED", transport=transport)
            return

        # Measure internal lookup time (ns): blocklist check + rate limit check + cache lookup
        t_lookup_start = time.perf_counter_ns()

        # ── 1. Blocklist check FIRST (do NOT count towards rate limit) ──
        blocked, category = self.blocklist.is_blocked(domain)
        if blocked:
            lookup_ns = time.perf_counter_ns() - t_lookup_start
            response = build_blocked_response(
                data, question_end, query_id, qtype, self.blocking_mode
            )
            response = _truncate_if_needed(response)
            self._send_response(response, client_addr, transport=transport, tcp_conn=tcp_conn)
            elapsed = (time.time() - start_time) * 1000
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "BLOCKED",
                    category=category, response_ms=elapsed,
                    upstream_ip="0.0.0.0", internal_lookup_ns=lookup_ns,
                    transport=transport
                )
            except Exception: pass
            logger.info(f"BLOCKED      {client_ip}  {domain}  {qtype_str}  [{category}]  [{transport}]")
            self._print_query("BLOCKED", client_ip, domain, qtype_str, elapsed, category=category, transport=transport)
            return

        # ── 2. Rate limit check (BEFORE cache, only for non-blocked queries) with per-domain burst protection ──
        if self.rate_limiter.is_rate_limited(client_ip, domain=domain):
            lookup_ns = time.perf_counter_ns() - t_lookup_start
            response = build_refused_response(data, question_end, query_id)
            response = _truncate_if_needed(response)
            self._send_response(response, client_addr, transport=transport, tcp_conn=tcp_conn)
            elapsed = (time.time() - start_time) * 1000
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "BLOCKED",
                    category="rate_limit", response_ms=elapsed,
                    upstream_ip="0.0.0.0", internal_lookup_ns=lookup_ns,
                    transport=transport
                )
            except Exception: pass
            logger.info(f"RATE_LIMITED  {client_ip}  {domain}  {qtype_str}  [{transport}]")
            return

        # ── 3. Cache lookup (BEFORE forwarding, AFTER blocklist and rate limit) ──
        cached_response, remaining_ttl = self.cache.get(domain, qtype, qclass)
        lookup_ns = time.perf_counter_ns() - t_lookup_start

        if cached_response is not None:
            response = swap_query_id(cached_response, query_id)
            response = _truncate_if_needed(response)
            self._send_response(response, client_addr, transport=transport, tcp_conn=tcp_conn)
            elapsed = (time.time() - start_time) * 1000
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "CACHED",
                    response_ms=elapsed, upstream_ip="",
                    internal_lookup_ns=lookup_ns,
                    transport=transport
                )
            except Exception: pass
            logger.info(f"CACHED       {client_ip}  {domain}  {qtype_str}  TTL={remaining_ttl:.0f}s  {elapsed:.1f}ms  [{transport}]")
            self._print_query("CACHED", client_ip, domain, qtype_str, elapsed, transport=transport)
            if hasattr(self, "watchlist") and self.watchlist and self.watchlist.is_in_watchlist(domain):
                self.watchlist.record_hit(domain)
            return

        # Check if we have a stale cached entry (within 60s stale window)
        stale_response = None
        if hasattr(self.cache, "get_stale"):
            stale_response = self.cache.get_stale(domain, qtype, qclass)

        # Forward to upstream: if stale entry is available, cap timeout at 2.0s without TCP fallback
        fwd_timeout = 2.0 if stale_response is not None else self.upstream_timeout
        use_tcp_fallback = False if stale_response is not None else True

        winner_ip = None
        try:
            upstream_response = forward_query(
                data,
                upstream_dns=self.upstream_dns,
                upstream_port=self.upstream_port,
                fallback_dns=self.upstream_fallback,
                timeout=fwd_timeout,
                tcp_fallback=use_tcp_fallback,
            )
        except Exception as e:
            logger.error(f"Error forwarding query for {domain}: {e}")
            upstream_response = None

        if upstream_response is not None:
            winner_ip = getattr(upstream_response, "upstream", getattr(upstream_response, "winner", self.upstream_dns))
            is_valid, reason = self.validate_upstream_response(upstream_response, winner_ip, query_id, domain)
            if not is_valid:
                logger.warning(f"INVALID_UPSTREAM from {winner_ip} for {domain}: {reason}")
                if hasattr(self.stats, "record_invalid_upstream"):
                    self.stats.record_invalid_upstream(winner_ip)
                if stale_response is not None:
                    upstream_response = None
                else:
                    # Try the other upstream
                    alt_upstream = self.upstream_fallback if winner_ip == self.upstream_dns else self.upstream_dns
                    logger.info(f"Retrying query for {domain} with alternative upstream {alt_upstream}...")
                    try:
                        resp2 = forward_query(
                            data,
                            upstream_dns=alt_upstream,
                            upstream_port=self.upstream_port,
                            fallback_dns="",
                            timeout=self.upstream_timeout,
                        )
                    except Exception as e2:
                        logger.error(f"Error querying backup upstream {alt_upstream}: {e2}")
                        resp2 = None

                    if resp2 is not None:
                        is_valid2, reason2 = self.validate_upstream_response(resp2, alt_upstream, query_id, domain)
                        if is_valid2:
                            upstream_response = resp2
                            winner_ip = alt_upstream
                        else:
                            logger.warning(f"INVALID_UPSTREAM also from backup {alt_upstream} for {domain}: {reason2}")
                            if hasattr(self.stats, "record_invalid_upstream"):
                                self.stats.record_invalid_upstream(alt_upstream)
                            upstream_response = None
                    else:
                        upstream_response = None

        # ── SERVE-STALE SIMPLE FALLBACK ─────────────────────────────────────
        if upstream_response is None:
            if stale_response is not None:
                elapsed = (time.time() - start_time) * 1000
                stale_pkt = swap_query_id(stale_response, query_id)
                stale_pkt = _truncate_if_needed(stale_pkt)
                self._send_response(stale_pkt, client_addr, transport=transport, tcp_conn=tcp_conn)
                try:
                    self.stats.log_query(
                        client_ip, domain, qtype_str, "STALE",
                        category="serve_stale",
                        response_ms=elapsed,
                        upstream_ip="STALE",
                        internal_lookup_ns=lookup_ns,
                        transport=transport,
                        cached=True
                    )
                except Exception:
                    pass
                logger.info(f"STALE        {client_ip}  {domain}  {qtype_str}  {elapsed:.1f}ms  [Serve-Stale fallback]  [{transport}]")
                self._print_query("STALE", client_ip, domain, qtype_str, elapsed, category="STALE", transport=transport)
                if hasattr(self, "watchlist") and self.watchlist and self.watchlist.is_in_watchlist(domain):
                    self.watchlist.record_hit(domain)
                return

            elapsed = (time.time() - start_time) * 1000
            status_label = "INVALID_UPSTREAM" if winner_ip else "TIMEOUT"
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "FORWARDED",
                    category="INVALID_UPSTREAM" if winner_ip else "",
                    response_ms=elapsed, upstream_ip="TIMEOUT" if not winner_ip else winner_ip,
                    internal_lookup_ns=lookup_ns,
                    transport=transport
                )
            except Exception: pass
            logger.warning(f"{status_label}      {client_ip}  {domain}  {qtype_str}  {elapsed:.1f}ms  [{transport}]")
            self._print_query(status_label, client_ip, domain, qtype_str, elapsed, transport=transport)
            # Send SERVFAIL response back so client does not hang / timeout
            servfail_response = build_servfail_response(data, question_end, query_id)
            servfail_response = _truncate_if_needed(servfail_response)
            self._send_response(servfail_response, client_addr, transport=transport, tcp_conn=tcp_conn)
            return

        winner_ip = getattr(upstream_response, "upstream", getattr(upstream_response, "winner", self.upstream_dns))

        answer_ip = ""
        ttl = 60
        rcode = 0
        try:
            parsed = parse_response(upstream_response)
            rcode = parsed["header"].get("rcode", parsed["header"]["flags"] & 0x000F)
            if parsed["answers"]:
                ttl = get_min_ttl(parsed["answers"])
                ips = get_answer_ips(parsed["answers"])
                answer_ip = ", ".join(ips)
            elif rcode == 3:
                ttl = min(ttl, 300)
            elif rcode == 0:
                # NODATA response (RFC 2308 Section 3 negative caching)
                ttl = min(getattr(self.cache, "min_ttl", 60), 300)
            else:
                ttl = 0
        except Exception as e:
            logger.debug(f"Could not parse upstream response for {domain}: {e}")
            ttl = 0

        # ── CNAME CLOAKING CHECK ─────────────────────────────────────────────
        try:
            parsed_for_cname = parse_response(upstream_response)
            cname_targets = extract_cname_chain_from_packet(
                upstream_response, parsed_for_cname.get("answers", [])
            )
        except Exception:
            cname_targets = []

        for cname_target in cname_targets:
            cname_clean = cname_target.rstrip(".")
            cname_blocked, cname_category = self.blocklist.is_blocked(cname_clean)
            if cname_blocked:
                cname_response = build_blocked_response(
                    data, question_end, query_id, qtype, self.blocking_mode
                )
                cname_response = _truncate_if_needed(cname_response)
                self._send_response(cname_response, client_addr, transport=transport, tcp_conn=tcp_conn)
                elapsed = (time.time() - start_time) * 1000
                try:
                    self.stats.log_query(
                        client_ip, domain, qtype_str, "BLOCKED",
                        category=f"{cname_category} [CNAME]",
                        response_ms=elapsed,
                        upstream_ip="0.0.0.0",
                        internal_lookup_ns=lookup_ns,
                        transport=transport
                    )
                except Exception:
                    pass
                log_msg = (
                    f"CNAME CLOAKING  {client_ip}  {domain}  {qtype_str}  "
                    f"-> {cname_target} [{cname_category}]  [{transport}]"
                )
                logger.warning(log_msg)
                self._print_query(
                    "BLOCKED", client_ip, domain, qtype_str, elapsed,
                    category=f"{cname_category} [CNAME:{cname_clean}]",
                    transport=transport
                )
                return   # do NOT send the upstream response

        # Only cache responses that passed CNAME cloaking and validation
        if ttl > 0 and (rcode == 0 or rcode == 3):
            self.cache.put(domain, qtype, upstream_response, ttl, qclass=qclass)

        final_response = _truncate_if_needed(upstream_response)
        self._send_response(final_response, client_addr, transport=transport, tcp_conn=tcp_conn)
        elapsed = (time.time() - start_time) * 1000

        try:
            # Group by upstream resolver IP (winner_ip), not answer_ip
            self.stats.log_query(
                client_ip, domain, qtype_str, "FORWARDED",
                response_ms=elapsed, upstream_ip=winner_ip,
                internal_lookup_ns=lookup_ns,
                transport=transport
            )
        except Exception: pass
        logger.info(f"FORWARDED    {client_ip}  {domain}  {qtype_str}  via {winner_ip} -> {answer_ip}  TTL={ttl}s  {elapsed:.1f}ms  [{transport}]")
        self._print_query("FORWARDED", client_ip, domain, qtype_str, elapsed, answer_ip=f"{winner_ip} ({answer_ip})", transport=transport)
        if hasattr(self, "watchlist") and self.watchlist and self.watchlist.is_in_watchlist(domain):
            self.watchlist.record_hit(domain)

    def _send_response(self, response, client_addr, transport="UDP", tcp_conn=None):
        try:
            if transport == "TCP" and tcp_conn is not None:
                packet = struct.pack(">H", len(response)) + response
                tcp_conn.sendall(packet)
            else:
                self.sock.sendto(response, client_addr)
        except Exception as e:
            logger.error(f"Failed to send response to {client_addr} ({transport}): {e}")

    def _print_query(self, action, client_ip, domain, qtype_str, elapsed_ms, category=None, answer_ip=None, transport="UDP"):
        parts = [f"{action:<12}", client_ip, f"[{transport}]", f"{domain}", f"({qtype_str})"]
        if category:
            parts.append(f"[{category}]")
        if answer_ip:
            parts.append(f"-> {answer_ip}")
        parts.append(f"{elapsed_ms:.1f}ms")
        print("  ".join(parts))

    def _cache_cleanup_loop(self):
        while self.running:
            time.sleep(30)
            self.cache.cleanup_expired()
            # PREFETCH SIMPLE: Check if any watchlist domain in cache is near expiry (<=60s)
            if hasattr(self, "watchlist") and self.watchlist:
                try:
                    wl_domains = set(self.watchlist.get_domains())
                    now = time.time()
                    with getattr(self.cache, "lock", threading.Lock()):
                        entries_snapshot = list(self.cache.entries.items())
                    for key, (_, expiry, _) in entries_snapshot:
                        if isinstance(key, tuple) and len(key) >= 2:
                            dom = key[0]
                            if dom in wl_domains and (0 < expiry - now <= 60):
                                self._prefetch_watchlist_domain(dom)
                except Exception:
                    pass
            blocklist_dir = self.config.get("blocklist_dir", "blocklists")
            allowlist_file = self.config.get("allowlist_file", "allowlist.txt")
            self.blocklist.check_and_reload_if_changed(blocklist_dir, allowlist_file)

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.tcp_sock:
            try:
                self.tcp_sock.close()
            except Exception:
                pass
        logger.info("DNS server stopped")
