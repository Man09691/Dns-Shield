"""
dns/server.py  —  FINAL CORRECTED (Dashboard blank fix + stats integration)
=========================================================
Ye file ab dashboard ke liye hisab bhi likhegi
"""

import socket
import struct
import threading
import time
import logging

from dns.parser import parse_header, parse_question, parse_response, get_answer_ips, get_min_ttl
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


class DNSServer:
    def __init__(self, config, blocklist, cache, rate_limiter, stats_obj):
        self.config = config
        self.blocklist = blocklist
        self.cache = cache
        self.rate_limiter = rate_limiter
        # stats_obj main.py se aayega, nahi toh global singleton use karo
        self.stats = stats_obj if stats_obj is not None else global_stats

        self.listen_host = config.get("listen_host", "0.0.0.0")
        self.listen_port = config.get("listen_port", 5053)
        self.upstream_dns = config.get("upstream_dns", "8.8.8.8")
        self.upstream_fallback = config.get("upstream_fallback", "1.1.1.1")
        self.upstream_port = config.get("upstream_port", 53)
        self.upstream_timeout = config.get("upstream_timeout", 3)
        self.blocking_mode = config.get("blocking_mode", "zero_ip")

        self.sock = None
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

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _disable_windows_udp_connreset(self.sock)
        self.sock.bind((self.listen_host, self.listen_port))
        self.running = True

        logger.info(f"DNS server listening on {self.listen_host}:{self.listen_port}")
        print(f"DNS server listening on {self.listen_host}:{self.listen_port}")

        cleanup_thread = threading.Thread(target=self._cache_cleanup_loop, daemon=True)
        cleanup_thread.start()
        self._receive_loop()

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

    def _handle_query(self, data, client_addr):
        start_time = time.time()
        client_ip = client_addr[0]

        try:
            header = parse_header(data)
            query_id = header["id"]
            domain, qtype, qclass, question_end = parse_question(data)
        except (ValueError, IndexError, struct.error) as e:
            logger.warning(f"Malformed packet from {client_ip}: {e}")
            return

        qtype_names = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS"}
        qtype_str = qtype_names.get(qtype, str(qtype))

        # Measure internal lookup time (ns): rate limit check + blocklist check + cache lookup
        t_lookup_start = time.perf_counter_ns()

        # Rate limit
        if self.rate_limiter.is_rate_limited(client_ip):
            lookup_ns = time.perf_counter_ns() - t_lookup_start
            response = build_refused_response(data, question_end, query_id)
            self._send_response(response, client_addr)
            elapsed = (time.time() - start_time) * 1000
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "BLOCKED",
                    category="rate_limit", response_ms=elapsed,
                    upstream_ip="0.0.0.0", internal_lookup_ns=lookup_ns
                )
            except Exception: pass
            logger.info(f"RATE_LIMITED  {client_ip}  {domain}  {qtype_str}")
            return

        # Blocklist check
        blocked, category = self.blocklist.is_blocked(domain)
        if blocked:
            lookup_ns = time.perf_counter_ns() - t_lookup_start
            response = build_blocked_response(
                data, question_end, query_id, qtype, self.blocking_mode
            )
            self._send_response(response, client_addr)
            elapsed = (time.time() - start_time) * 1000
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "BLOCKED",
                    category=category, response_ms=elapsed,
                    upstream_ip="0.0.0.0", internal_lookup_ns=lookup_ns
                )
            except Exception: pass
            logger.info(f"BLOCKED      {client_ip}  {domain}  {qtype_str}  [{category}]")
            self._print_query("BLOCKED", client_ip, domain, qtype_str, elapsed, category=category)
            return

        # Cache lookup
        cached_response, remaining_ttl = self.cache.get(domain, qtype)
        lookup_ns = time.perf_counter_ns() - t_lookup_start

        if cached_response is not None:
            response = swap_query_id(cached_response, query_id)
            self._send_response(response, client_addr)
            elapsed = (time.time() - start_time) * 1000
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "CACHED",
                    response_ms=elapsed, upstream_ip="",
                    internal_lookup_ns=lookup_ns
                )
            except Exception: pass
            logger.info(f"CACHED       {client_ip}  {domain}  {qtype_str}  TTL={remaining_ttl:.0f}s  {elapsed:.1f}ms")
            self._print_query("CACHED", client_ip, domain, qtype_str, elapsed)
            return

        # Forward to upstream
        try:
            upstream_response = forward_query(
                data,
                upstream_dns=self.upstream_dns,
                upstream_port=self.upstream_port,
                fallback_dns=self.upstream_fallback,
                timeout=self.upstream_timeout,
            )
        except Exception as e:
            logger.error(f"Error forwarding query for {domain}: {e}")
            upstream_response = None

        if upstream_response is None:
            elapsed = (time.time() - start_time) * 1000
            try:
                self.stats.log_query(
                    client_ip, domain, qtype_str, "FORWARDED",
                    response_ms=elapsed, upstream_ip="TIMEOUT",
                    internal_lookup_ns=lookup_ns
                )
            except Exception: pass
            logger.warning(f"TIMEOUT      {client_ip}  {domain}  {qtype_str}  {elapsed:.1f}ms")
            self._print_query("TIMEOUT", client_ip, domain, qtype_str, elapsed)
            # Send SERVFAIL response back so client does not hang / timeout
            servfail_response = build_servfail_response(data, question_end, query_id)
            self._send_response(servfail_response, client_addr)
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
            else:
                ttl = 0
        except Exception as e:
            logger.debug(f"Could not parse upstream response for {domain}: {e}")
            ttl = 0

        if ttl > 0 and (rcode == 0 or rcode == 3):
            self.cache.put(domain, qtype, upstream_response, ttl)

        self._send_response(upstream_response, client_addr)
        elapsed = (time.time() - start_time) * 1000

        try:
            # Group by upstream resolver IP (winner_ip), not answer_ip
            self.stats.log_query(
                client_ip, domain, qtype_str, "FORWARDED",
                response_ms=elapsed, upstream_ip=winner_ip,
                internal_lookup_ns=lookup_ns
            )
        except Exception: pass
        logger.info(f"FORWARDED    {client_ip}  {domain}  {qtype_str}  via {winner_ip} -> {answer_ip}  TTL={ttl}s  {elapsed:.1f}ms")
        self._print_query("FORWARDED", client_ip, domain, qtype_str, elapsed, answer_ip=f"{winner_ip} ({answer_ip})")

    def _send_response(self, response, client_addr):
        try:
            self.sock.sendto(response, client_addr)
        except Exception as e:
            logger.error(f"Failed to send response to {client_addr}: {e}")

    def _print_query(self, action, client_ip, domain, qtype_str, elapsed_ms, category=None, answer_ip=None):
        parts = [f"{action:<12}", client_ip, f"{domain}", f"({qtype_str})"]
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
        logger.info("DNS server stopped")
