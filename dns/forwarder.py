"""
dns/forwarder.py  —  Upstream DNS Forwarder
=============================================
Computer Networks concept: DNS forwarding / recursive resolution.

When our server doesn't know the answer (not blocked, not cached),
it forwards the query to an upstream DNS server (like Google 8.8.8.8
or Cloudflare 1.1.1.1) and relays the response back to the client.

Features:
  - Parallel race between 8.8.8.8 and 1.1.1.1: first valid response wins
  - Pure standard library socket & threading (no dnspython clash with local dns/)
  - Accurate upstream winner tracking (queries, avg_ms, fails)
  - Returns DNSForwardResponse (bytes subclass with .upstream, .winner, .elapsed_ms)
"""

import socket
import logging
import threading
import time
import queue
import struct

logger = logging.getLogger("dns.forwarder")

_lock = threading.Lock()
_queries = {"8.8.8.8": 0, "1.1.1.1": 0}
_total_ms = {"8.8.8.8": 0.0, "1.1.1.1": 0.0}
_fail_count = {"8.8.8.8": 0, "1.1.1.1": 0}
_last_winner = None


class DNSForwardResponse(bytes):
    """
    Subclass of bytes that preserves the raw DNS packet while attaching
    metadata about which upstream won and how long it took.
    """
    def __new__(cls, data, upstream="8.8.8.8", elapsed=0.0):
        obj = super().__new__(cls, data)
        obj.upstream = str(upstream)
        obj.winner = str(upstream)
        obj.elapsed_ms = float(elapsed)
        return obj


def get_last_winner():
    with _lock:
        return _last_winner


def get_upstream_stats():
    """
    Return upstream metrics grouped by resolver IP:
    [{ip: "8.8.8.8", queries: ..., avg_ms: ..., fails: ...}, ...]
    """
    with _lock:
        result = []
        for ip in ["8.8.8.8", "1.1.1.1"]:
            q = _queries.get(ip, 0)
            tot = _total_ms.get(ip, 0.0)
            avg = round(tot / q, 2) if q > 0 else 0.0
            fails = _fail_count.get(ip, 0)
            result.append({
                "ip": ip,
                "queries": q,
                "avg_ms": avg,
                "fails": fails,
                "count": q
            })
        return result


def reset_stats():
    """Reset all upstream metrics."""
    global _last_winner
    with _lock:
        for k in list(_queries.keys()):
            _queries[k] = 0
            _total_ms[k] = 0.0
            _fail_count[k] = 0
        _last_winner = None


def _worker_udp(data, server_ip, port, timeout, out_q):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.sendto(data, (server_ip, port))
        resp, _ = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - t0) * 1000.0
        with _lock:
            _queries[server_ip] = _queries.get(server_ip, 0) + 1
            _total_ms[server_ip] = _total_ms.get(server_ip, 0.0) + elapsed
        try:
            out_q.put_nowait((resp, server_ip, elapsed))
        except queue.Full:
            pass
    except Exception as e:
        with _lock:
            _fail_count[server_ip] = _fail_count.get(server_ip, 0) + 1
        logger.debug(f"Upstream UDP {server_ip}:{port} failed: {e}")
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _worker_tcp(data, server_ip, port, timeout):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.connect((server_ip, port))
        length = struct.pack(">H", len(data))
        sock.sendall(length + data)
        len_bytes = sock.recv(2)
        if len(len_bytes) < 2:
            return None, 0.0
        resp_len = struct.unpack(">H", len_bytes)[0]
        chunks = []
        recvd = 0
        while recvd < resp_len:
            chunk = sock.recv(min(4096, resp_len - recvd))
            if not chunk:
                break
            chunks.append(chunk)
            recvd += len(chunk)
        elapsed = (time.perf_counter() - t0) * 1000.0
        return b"".join(chunks), elapsed
    except Exception as e:
        logger.debug(f"Upstream TCP {server_ip}:{port} failed: {e}")
        return None, 0.0
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def forward_query(data, upstream_dns="8.8.8.8", upstream_port=53,
                  fallback_dns="1.1.1.1", timeout=3, extra_upstreams=None,
                  return_winner=False):
    """
    Forward query to upstream DNS servers in parallel race.
    First valid response wins. Returns DNSForwardResponse or None.
    """
    global _last_winner

    upstreams = [upstream_dns, fallback_dns]
    if extra_upstreams:
        upstreams.extend(extra_upstreams)

    # Deduplicate while preserving order
    seen = set()
    uniq = []
    for ip in upstreams:
        if ip and ip not in seen:
            seen.add(ip)
            seen.add(ip)
            uniq.append(ip)
    upstreams = uniq

    out_q = queue.Queue(maxsize=1)
    threads = []
    # Set socket timeout slightly lower than total timeout so threads exit cleanly
    sock_timeout = max(1.0, float(timeout) - 0.5)

    for ip in upstreams:
        t = threading.Thread(
            target=_worker_udp,
            args=(data, ip, upstream_port, sock_timeout, out_q),
            daemon=True
        )
        t.start()
        threads.append(t)

    try:
        resp, winner, elapsed = out_q.get(timeout=timeout)
        with _lock:
            _last_winner = winner
        logger.info(f"Forwarder winner: {winner} in {elapsed:.1f}ms | active={upstreams}")
        if return_winner:
            return resp, winner
        return DNSForwardResponse(resp, upstream=winner, elapsed=elapsed)
    except queue.Empty:
        # UDP timed out; attempt quick TCP fallback on primary
        for ip in upstreams:
            tcp_resp, tcp_elapsed = _worker_tcp(data, ip, upstream_port, timeout=1.5)
            if tcp_resp:
                with _lock:
                    _queries[ip] = _queries.get(ip, 0) + 1
                    _total_ms[ip] = _total_ms.get(ip, 0.0) + tcp_elapsed
                    _last_winner = ip
                logger.info(f"Forwarder TCP winner: {ip} in {tcp_elapsed:.1f}ms")
                if return_winner:
                    return tcp_resp, ip
                return DNSForwardResponse(tcp_resp, upstream=ip, elapsed=tcp_elapsed)

        logger.warning(f"All upstreams timed out: {upstreams}")
        if return_winner:
            return None, "TIMEOUT"
        return None


def _send_and_receive(data, server_ip, port, timeout):
    """Legacy helper for single-server query."""
    q = queue.Queue(maxsize=1)
    _worker_udp(data, server_ip, port, timeout, q)
    try:
        resp, _, _ = q.get_nowait()
        return resp
    except queue.Empty:
        return None
