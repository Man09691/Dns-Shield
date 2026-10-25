"""
dns/forwarder.py  —  Upstream DNS Forwarder
=============================================
Computer Networks concept: DNS forwarding / recursive resolution.

When our server doesn't know the answer (not blocked, not cached),
it forwards the query to an upstream DNS server (like Google 8.8.8.8)
and relays the response back to the client.

This module handles:
  - Sending the query to the primary upstream server
  - Falling back to a secondary server on timeout
  - Configurable timeout
"""
"""
dns/forwarder.py  —  Perfect Upstream Forwarder

1. Parallel race: 8.8.8.8 aur 1.1.1.1 dono ko ek saath puchta hai, jo pehle jawab dega wahi lega
2. EWMA latency tracker: kaunsa fast hai yaad rakhega
3. Auto blacklist: 3 baar fail hua toh 60 sec ke liye band
4. Zero blocking: thread + queue se fastest win
"""

import socket
import logging
import threading
import time
import queue

logger = logging.getLogger("dns.forwarder")

# Thread-safe stats
_lock = threading.Lock()
_latency = {}  # ip -> avg latency ms
_fail_count = {}
_blacklist_until = {}

def _is_blacklisted(ip):
    with _lock:
        until = _blacklist_until.get(ip, 0)
        return time.time() < until

def _record_success(ip, elapsed):
    with _lock:
        old = _latency.get(ip, elapsed)
        # EWMA 70% old + 30% new
        _latency[ip] = old * 0.7 + elapsed * 0.3
        _fail_count[ip] = 0

def _record_failure(ip):
    with _lock:
        _fail_count[ip] = _fail_count.get(ip, 0) + 1
        if _fail_count[ip] >= 3:
            _blacklist_until[ip] = time.time() + 60
            logger.warning(f"{ip} blacklisted for 60s after 3 fails")

def _worker(data, server_ip, port, timeout, out_q):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        start = time.monotonic()
        sock.sendto(data, (server_ip, port))
        response, _ = sock.recvfrom(4096)
        elapsed = time.monotonic() - start
        sock.close()
        _record_success(server_ip, elapsed)
        # sirf pehla success queue me jayega
        try:
            out_q.put_nowait((response, elapsed, server_ip))
        except queue.Full:
            pass
    except Exception as e:
        _record_failure(server_ip)
        logger.debug(f"{server_ip} failed: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

def forward_query(data, upstream_dns="8.8.8.8", upstream_port=53,
                  fallback_dns="1.1.1.1", timeout=3, extra_upstreams=None):
    """
    Same signature as old, but ab parallel hai.
    """
    upstreams = [upstream_dns, fallback_dns]
    if extra_upstreams:
        upstreams.extend(extra_upstreams)
    
    # dedup
    seen = set()
    uniq = []
    for ip in upstreams:
        if ip not in seen:
            uniq.append(ip)
            seen.add(ip)
    upstreams = uniq

    # blacklist walo ko hatao, par agar sab blacklist hai toh force try
    active = [ip for ip in upstreams if not _is_blacklisted(ip)]
    if not active:
        active = upstreams

    q = queue.Queue(maxsize=1)
    threads = []
    for ip in active:
        t = threading.Thread(target=_worker, args=(data, ip, upstream_port, timeout, q), daemon=True)
        t.start()
        threads.append(t)

    try:
        response, elapsed, winner = q.get(timeout=timeout)
        logger.info(f"Forwarder winner: {winner} in {elapsed*1000:.1f}ms | active={active}")
        return response
    except queue.Empty:
        logger.error(f"All upstreams timed out: {active}")
        return None

# purana function bhi rakha for backward compat
def _send_and_receive(data, server_ip, port, timeout):
    q = queue.Queue(maxsize=1)
    _worker(data, server_ip, port, timeout, q)
    try:
        resp, _, _ = q.get_nowait()
        return resp
    except queue.Empty:
        return None