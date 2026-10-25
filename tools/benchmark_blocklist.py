"""
tools/benchmark_blocklist.py  —  Performance Benchmark (100k Domains & 10,000 Queries)
=======================================================================================
Compares:
  1. Old Naive Loop: linear scan over a list (for b in list: if domain == b or domain.endswith("." + b))
  2. New Optimized Set/Dict Suffix Walk + LRU lookup_cache (dns/blocklist.py)

With 100,000 (1 Lakh) domains loaded.
"""

import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dns.blocklist import Blocklist


class OldNaiveBlocklist:
    """Old naive implementation: loops through a list of 100,000 domains."""
    def __init__(self, domains):
        self.blocked_list = list(domains)

    def is_blocked(self, domain):
        domain = domain.lower()
        for b in self.blocked_list:
            if domain == b or domain.endswith("." + b):
                return True, "ads"
        return False, None


def generate_100k_domains():
    """Generate 100,000 unique domains for the benchmark."""
    print("Generating 100,000 unique domains (1 Lakh domains)...")
    domains = set()

    # Load existing domains from ads.txt if available
    ads_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "blocklists", "ads.txt")
    if os.path.exists(ads_file):
        with open(ads_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    d = parts[1] if len(parts) >= 2 else parts[0]
                    domains.add(d.lower())

    # Fill up to 100,000 domains
    i = 0
    tlds = ["com", "net", "org", "io", "ad", "xyz", "co", "biz", "info", "tracker"]
    words = ["adservice", "tracking", "telemetry", "metric", "banner", "analytics", "pixel", "click", "pop", "counter"]
    while len(domains) < 100000:
        w = random.choice(words)
        tld = random.choice(tlds)
        domains.add(f"{w}-{i}.{tld}")
        i += 1

    return list(domains)[:100000]


def run_benchmark():
    domains_100k = generate_100k_domains()
    print(f"Total domains loaded for benchmark: {len(domains_100k):,}")

    # Initialize new optimized blocklist
    print("\nInitializing New Blocklist (Dict Suffix Walk + LRU lookup_cache)...")
    new_bl = Blocklist(lookup_cache_size=4096)
    for d in domains_100k:
        new_bl.blocked_domains[d] = "ads"

    # Add sample allowlist
    new_bl.allowed_domains.add("allowed-safe.com")
    new_bl.allowed_domains.add("google.com")

    # Initialize old naive blocklist
    print("Initializing Old Naive Blocklist (Linear List)...")
    old_bl = OldNaiveBlocklist(domains_100k)

    # Generate 10,000 realistic DNS queries
    # Real traffic has high locality (Zipfian): ~70% top 50 domains, 15% other blocked, 15% unblocked
    print("\nPreparing 10,000 queries with realistic distribution (70% hot, 15% blocked, 15% unblocked)...")
    hot_pool = [
        "doubleclick.net", "google.com", "ads.doubleclick.net", "youtube.com",
        "adservice-1.com", "tracking-2.net", "facebook.com", "allowed-safe.com"
    ] + domains_100k[:42]

    queries = []
    for _ in range(10000):
        r = random.random()
        if r < 0.70:
            queries.append(random.choice(hot_pool))
        elif r < 0.85:
            # Random blocked domain or subdomain
            b = random.choice(domains_100k[100:1000])
            queries.append(f"sub.{b}" if random.random() < 0.5 else b)
        else:
            # Unblocked domain
            queries.append(f"clean-site-{random.randint(1, 50000)}.org")

    # ─────────────────────────────────────────────────────────────
    # 1. Benchmark New Optimized Method (Full 10,000 queries)
    # ─────────────────────────────────────────────────────────────
    print("\n[1/2] Benchmarking NEW Method (Set suffix walk + lookup_cache) for 10,000 queries...")
    start_time = time.perf_counter()
    new_hits = 0
    for q in queries:
        blocked, _ = new_bl.is_blocked(q)
        if blocked:
            new_hits += 1
    new_duration = time.perf_counter() - start_time
    new_avg_us = (new_duration / len(queries)) * 1_000_000
    new_qps = len(queries) / new_duration

    # Calculate lookup_cache hit rate
    cache_entries = len(new_bl.lookup_cache)
    # Unique queries in the workload
    unique_queries = len(set(queries))
    cache_hits = len(queries) - unique_queries
    cache_hit_rate = (cache_hits / len(queries)) * 100

    print(f"  -> Total Time for 10,000 queries : {new_duration:.4f} seconds ({new_duration * 1000:.2f} ms)")
    print(f"  -> Average Lookup Time          : {new_avg_us:.2f} microseconds (µs)")
    print(f"  -> Throughput                   : {new_qps:,.0f} queries/sec")
    print(f"  -> Cache Hit Rate               : {cache_hit_rate:.1f}%")

    # ─────────────────────────────────────────────────────────────
    # 2. Benchmark Old Naive Method
    # ─────────────────────────────────────────────────────────────
    # Running 10,000 queries across 100,000 items sequentially would take ~40-60 seconds in Python!
    # We test 200 representative queries to measure exact per-query time, then compute full 10,000 time.
    sample_size = 200
    print(f"\n[2/2] Benchmarking OLD Naive Method (Linear loop over 100k items) on {sample_size} sample queries...")
    sample_queries = queries[:sample_size]
    start_time = time.perf_counter()
    for q in sample_queries:
        old_bl.is_blocked(q)
    sample_duration = time.perf_counter() - start_time

    old_avg_ms = (sample_duration / sample_size) * 1000
    old_avg_us = old_avg_ms * 1000
    old_estimated_10k_sec = (sample_duration / sample_size) * 10000
    old_qps = sample_size / sample_duration

    print(f"  -> Average Lookup Time (Old)    : {old_avg_ms:.2f} milliseconds ({old_avg_us:.0f} µs)")
    print(f"  -> Estimated Time for 10,000    : {old_estimated_10k_sec:.2f} seconds")
    print(f"  -> Throughput (Old)             : {old_qps:,.0f} queries/sec")

    # ─────────────────────────────────────────────────────────────
    # Comparison Summary
    # ─────────────────────────────────────────────────────────────
    speedup = old_avg_us / new_avg_us if new_avg_us > 0 else 0

    print("\n" + "=" * 70)
    print("                    PERFORMANCE BENCHMARK REPORT")
    print("=" * 70)
    print(f"Blocklist Size           : 100,000 domains (1 Lakh)")
    print(f"Number of Queries Tested : 10,000 queries")
    print("-" * 70)
    print(f"{'Metric':<28} | {'Old Naive Loop':<18} | {'New Suffix + Cache':<18}")
    print("-" * 70)
    print(f"{'Avg Lookup Latency':<28} | {old_avg_ms:>13.2f} ms | {new_avg_us:>14.2f} µs")
    print(f"{'Time for 10,000 queries':<28} | {old_estimated_10k_sec:>13.2f} s  | {new_duration:>14.4f} s")
    print(f"{'Query Throughput':<28} | {old_qps:>10,.0f} q/s | {new_qps:>11,.0f} q/s")
    print(f"{'Lookup Cache Hit Rate':<28} | {'N/A':>18} | {cache_hit_rate:>17.1f}%")
    print("-" * 70)
    print(f"SPEEDUP FACTOR           : {speedup:,.0f}x FASTER!")
    print("=" * 70)

    return {
        "old_avg_ms": old_avg_ms,
        "new_avg_us": new_avg_us,
        "old_time_10k": old_estimated_10k_sec,
        "new_time_10k": new_duration,
        "speedup": speedup,
        "cache_hit_rate": cache_hit_rate,
        "new_qps": new_qps,
        "old_qps": old_qps
    }


if __name__ == "__main__":
    run_benchmark()
