"""
dns/server.py  —  DNS Server (UDP Loop + Decision Logic)
=========================================================
Computer Networks concepts:
  - UDP socket programming (connectionless, fast, no handshake)
  - Port binding and packet reception
  - Multi-threaded request handling (one thread per query)

This is the heart of the DNS server. It:
  1. Listens on a UDP port (default 5053) for DNS queries
  2. Spawns a thread for each incoming query
  3. Follows the decision flow:
       Rate limit check -> Allowlist -> Blocklist -> Cache -> Forward

IMPORTANT Windows note:
  Windows throws ConnectionResetError (WinError 10054) on UDP sockets
  when a previous sendto() target was unreachable. This is a known quirk.
  We handle it by catching the error and also disabling the ICMP error
  reporting on the socket using SIO_UDP_CONNRESET.
"""

import socket
import struct
import threading
import time
import logging
import ctypes

from dns.parser import parse_header, parse_question, parse_response, get_answer_ips, get_min_ttl
from dns.builder import build_blocked_response, build_refused_response, swap_query_id
from dns.forwarder import forward_query

logger = logging.getLogger("dns.server")


def _disable_windows_udp_connreset(sock):
    """
    Disable the Windows UDP CONNRESET error.

    On Windows, if we sendto() a client that then closes its socket,
    the next recvfrom() will raise ConnectionResetError. This is because
    Windows reports the ICMP "port unreachable" error to the UDP socket.

    SIO_UDP_CONNRESET = 0x9800000C
    Setting it to False tells Windows to NOT raise the error.
    """
    try:
        # SIO_UDP_CONNRESET = 0x9800000C
        # Python's socket.ioctl needs it as a proper integer value.
        # On some Windows/Python combos, just pass the raw constant.
        sock.ioctl(-1744830452, False)  # -1744830452 is 0x9800000C as signed int32
        logger.debug("Disabled Windows UDP CONNRESET (SIO_UDP_CONNRESET)")
    except (AttributeError, OSError, ValueError):
        # Not on Windows, or ioctl not available, or not supported — that's fine
        pass


class DNSServer:
    """
    The main DNS server class.

    Reads configuration and wires together all the modules:
      blocklist, cache, rate limiter, forwarder, stats.
    """

    def __init__(self, config, blocklist, cache, rate_limiter, stats):
        self.config = config
        self.blocklist = blocklist
        self.cache = cache
        self.rate_limiter = rate_limiter
        self.stats = stats

        # Read config values
        self.listen_host = config.get("listen_host", "0.0.0.0")
        self.listen_port = config.get("listen_port", 5053)
        self.upstream_dns = config.get("upstream_dns", "8.8.8.8")
        self.upstream_fallback = config.get("upstream_fallback", "1.1.1.1")
        self.upstream_port = config.get("upstream_port", 53)
        self.upstream_timeout = config.get("upstream_timeout", 3)
        self.blocking_mode = config.get("blocking_mode", "zero_ip")

        self.sock = None
        self.running = False

    def start(self):
        """
        Start the DNS server.
        Creates the UDP socket, binds it, and enters the receive loop.
        """
        # Create a UDP (SOCK_DGRAM) socket using IPv4 (AF_INET)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # SO_REUSEADDR lets us restart the server quickly without
        # waiting for the old socket to time out
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Fix the Windows UDP CONNRESET issue
        _disable_windows_udp_connreset(self.sock)

        # Bind to the configured address and port
        self.sock.bind((self.listen_host, self.listen_port))
        self.running = True

        logger.info(f"DNS server listening on {self.listen_host}:{self.listen_port}")
        print(f"DNS server listening on {self.listen_host}:{self.listen_port}")

        # Start the cache cleanup thread
        cleanup_thread = threading.Thread(target=self._cache_cleanup_loop, daemon=True)
        cleanup_thread.start()

        # Main receive loop
        self._receive_loop()

    def _receive_loop(self):
        """
        The main loop: receive UDP packets and handle each in a new thread.

        We use a 4096-byte receive buffer (not 512) to handle larger responses.
        Each query is handled in its own thread so one slow upstream lookup
        doesn't block other clients.
        """
        while self.running:
            try:
                # recvfrom() blocks until a packet arrives
                # Returns (data, (client_ip, client_port))
                data, client_addr = self.sock.recvfrom(4096)
            except ConnectionResetError:
                # Windows quirk: ignore and continue
                continue
            except OSError as e:
                if self.running:
                    logger.error(f"Socket error in receive loop: {e}")
                continue

            # Handle each query in a separate thread
            thread = threading.Thread(
                target=self._handle_query,
                args=(data, client_addr),
                daemon=True,
            )
            thread.start()

    def _handle_query(self, data, client_addr):
        """
        Handle a single DNS query. This is the core decision logic.

        Flow (from the project brief):
          1. Parse header + question (drop on error)
          2. If client is rate-limited -> refuse + log
          3. If domain is in allowlist -> skip to step 5
          4. If domain is blocked -> build blocked response + log
          5. If in cache and not expired -> reply from cache + log
          6. Otherwise forward to upstream -> cache + reply + log
        """
        start_time = time.time()
        client_ip = client_addr[0]

        # ── Step 1: Parse the DNS packet ──
        try:
            header = parse_header(data)
            query_id = header["id"]
            domain, qtype, qclass, question_end = parse_question(data)
        except (ValueError, IndexError, struct.error) as e:
            # Malformed packet — drop it silently
            logger.warning(f"Malformed packet from {client_ip}: {e}")
            return

        # qtype names for logging
        qtype_names = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS"}
        qtype_str = qtype_names.get(qtype, str(qtype))

        # ── Step 2: Rate limit check ──
        if self.rate_limiter.is_rate_limited(client_ip):
            response = build_refused_response(data, question_end, query_id)
            self._send_response(response, client_addr)
            elapsed = (time.time() - start_time) * 1000
            self.stats.log_query(client_ip, domain, qtype, "RATE_LIMITED",
                                 response_ms=elapsed)
            logger.info(f"RATE_LIMITED  {client_ip}  {domain}  {qtype_str}")
            return

        # ── Step 3 & 4: Allowlist and Blocklist check ──
        # (allowlist check is done inside blocklist.is_blocked())
        blocked, category = self.blocklist.is_blocked(domain)
        if blocked:
            response = build_blocked_response(
                data, question_end, query_id, qtype, self.blocking_mode
            )
            self._send_response(response, client_addr)
            elapsed = (time.time() - start_time) * 1000
            self.stats.log_query(client_ip, domain, qtype, "BLOCKED",
                                 category=category, response_ms=elapsed,
                                 answer_ip="0.0.0.0")
            logger.info(f"BLOCKED      {client_ip}  {domain}  {qtype_str}  [{category}]")
            self._print_query("BLOCKED", client_ip, domain, qtype_str, elapsed, category=category)
            return

        # ── Step 5: Cache lookup ──
        cached_response, remaining_ttl = self.cache.get(domain, qtype)
        if cached_response is not None:
            # Cache hit! Swap the query ID to match this client's ID.
            response = swap_query_id(cached_response, query_id)
            self._send_response(response, client_addr)
            elapsed = (time.time() - start_time) * 1000
            self.stats.log_query(client_ip, domain, qtype, "CACHED",
                                 response_ms=elapsed)
            logger.info(f"CACHED       {client_ip}  {domain}  {qtype_str}  "
                        f"TTL={remaining_ttl:.0f}s  {elapsed:.1f}ms")
            self._print_query("CACHED", client_ip, domain, qtype_str, elapsed)
            return

        # ── Step 6: Forward to upstream DNS ──
        upstream_response = forward_query(
            data,
            upstream_dns=self.upstream_dns,
            upstream_port=self.upstream_port,
            fallback_dns=self.upstream_fallback,
            timeout=self.upstream_timeout,
        )

        if upstream_response is None:
            # Both upstream servers timed out
            elapsed = (time.time() - start_time) * 1000
            self.stats.log_query(client_ip, domain, qtype, "TIMEOUT",
                                 response_ms=elapsed)
            logger.warning(f"TIMEOUT      {client_ip}  {domain}  {qtype_str}  {elapsed:.1f}ms")
            self._print_query("TIMEOUT", client_ip, domain, qtype_str, elapsed)
            return

        # Parse the response to extract TTL and answer IPs (for caching & logging)
        answer_ip = ""
        ttl = 60  # default TTL if we can't parse
        rcode = 0
        try:
            parsed = parse_response(upstream_response)
            rcode = parsed["header"].get("rcode", parsed["header"]["flags"] & 0x000F)
            if parsed["answers"]:
                ttl = get_min_ttl(parsed["answers"])
                ips = get_answer_ips(parsed["answers"])
                answer_ip = ", ".join(ips)
            elif rcode == 3:
                # NXDOMAIN: cache negative response (RFC 2308)
                ttl = min(ttl, 300)
            else:
                ttl = 0
        except Exception as e:
            logger.debug(f"Could not parse upstream response for {domain}: {e}")
            ttl = 0

        # Cache the response before sending to avoid client race condition
        if ttl > 0 and (rcode == 0 or rcode == 3):
            self.cache.put(domain, qtype, upstream_response, ttl)

        # Send the upstream response back to the client
        self._send_response(upstream_response, client_addr)
        elapsed = (time.time() - start_time) * 1000

        self.stats.log_query(client_ip, domain, qtype, "FORWARDED",
                             response_ms=elapsed, answer_ip=answer_ip)
        logger.info(f"FORWARDED    {client_ip}  {domain}  {qtype_str}  "
                    f"-> {answer_ip}  TTL={ttl}s  {elapsed:.1f}ms")
        self._print_query("FORWARDED", client_ip, domain, qtype_str, elapsed, answer_ip=answer_ip)

    def _send_response(self, response, client_addr):
        """Send a DNS response packet to the client."""
        try:
            self.sock.sendto(response, client_addr)
        except Exception as e:
            logger.error(f"Failed to send response to {client_addr}: {e}")

    def _print_query(self, action, client_ip, domain, qtype_str, elapsed_ms,
                     category=None, answer_ip=None):
        """Print a one-line summary to the console (human-readable)."""
        parts = [f"{action:<12}", client_ip, f"{domain}", f"({qtype_str})"]
        if category:
            parts.append(f"[{category}]")
        if answer_ip:
            parts.append(f"-> {answer_ip}")
        parts.append(f"{elapsed_ms:.1f}ms")
        print("  ".join(parts))

    def _cache_cleanup_loop(self):
        """
        Background thread that periodically cleans expired cache entries
        and checks for blocklist updates on disk. Runs every 30 seconds.
        """
        while self.running:
            time.sleep(30)
            self.cache.cleanup_expired()
            blocklist_dir = self.config.get("blocklist_dir", "blocklists")
            allowlist_file = self.config.get("allowlist_file", "allowlist.txt")
            self.blocklist.check_and_reload_if_changed(blocklist_dir, allowlist_file)

    def stop(self):
        """Stop the DNS server."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        logger.info("DNS server stopped")
