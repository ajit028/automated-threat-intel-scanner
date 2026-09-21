#!/usr/bin/env python3
"""
Automated Threat Intel Scanner — Performance & Throughput Benchmark
===================================================================
Tests and verifies concurrent IOC extraction, SQLite caching throughput,
and multi-threaded enrichment processing capacity.

Usage:
    python tests/benchmark.py
    python tests/benchmark.py --iocs 500 --threads 10
"""

import argparse
import os
import sys
import time
import random
import hashlib
from typing import List, Dict, Tuple

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_extractor import extract_iocs, count_iocs
from cache import set_cached_result, get_cached_result, init_db
from scanner import scan_iocs_sync

# ─── Synthetic Data Generator ────────────────────────────────────────────────

def generate_synthetic_iocs(count: int = 200) -> Tuple[str, Dict[str, List[str]]]:
    """
    Generate synthetic log text with mixed IOC types.
    """
    lines = []
    expected: Dict[str, List[str]] = {
        "ipv4": [],
        "domain": [],
        "md5": [],
        "sha256": [],
        "url": []
    }

    domains_pool = ["malicious-c2.org", "dark-threat.net", "botnet-relay.co", "apt-group.ru", "phish-bank.com"]
    
    for i in range(count):
        # Generate random public IPv4 (avoiding 10.x, 192.168.x, 127.x)
        o1 = random.randint(11, 126)
        o2 = random.randint(1, 254)
        o3 = random.randint(1, 254)
        o4 = random.randint(1, 254)
        ip = f"{o1}.{o2}.{o3}.{o4}"
        expected["ipv4"].append(ip)

        # Generate hashes
        raw_seed = f"threat_{i}_{time.time()}_{random.random()}".encode("utf-8")
        md5_val = hashlib.md5(raw_seed).hexdigest()
        sha256_val = hashlib.sha256(raw_seed).hexdigest()
        expected["md5"].append(md5_val)
        expected["sha256"].append(sha256_val)

        # Generate domain & URL
        d = f"sub{i}.{random.choice(domains_pool)}"
        url = f"http://{d}/payload_{i}.bin"
        expected["domain"].append(d)
        expected["url"].append(url)

        # Build realistic syslog/SIEM line
        timestamp = "2026-09-21T10:15:30.123Z"
        log_line = (
            f"{timestamp} firewalld[4410]: ALERT inbound connection from {ip} "
            f"accessing {url} with hash {sha256_val} MD5:{md5_val}"
        )
        lines.append(log_line)

    return "\n".join(lines), expected


# ─── Benchmark Functions ─────────────────────────────────────────────────────

def benchmark_extraction(log_text: str, total_raw_iocs: int) -> Dict[str, float]:
    """Measure IOC regex extraction throughput."""
    text_size_mb = len(log_text.encode("utf-8")) / (1024 * 1024)
    
    start_time = time.perf_counter()
    extracted = extract_iocs(log_text)
    duration = time.perf_counter() - start_time

    extracted_count = count_iocs(extracted)
    iocs_per_sec = extracted_count / duration if duration > 0 else 0
    mb_per_sec = text_size_mb / duration if duration > 0 else 0

    return {
        "duration_sec": duration,
        "extracted_count": extracted_count,
        "iocs_per_sec": iocs_per_sec,
        "mb_per_sec": mb_per_sec,
        "text_size_mb": text_size_mb
    }


def benchmark_cache_throughput(num_records: int = 500) -> Dict[str, float]:
    """Measure SQLite cache write and read throughput."""
    init_db()
    test_iocs = [f"203.0.113.{i}" for i in range(num_records)]
    
    # Write benchmark
    start_write = time.perf_counter()
    for ip in test_iocs:
        dummy_data = {
            "ioc": ip,
            "type": "ipv4",
            "risk_score": 10,
            "classification": "CLEAN",
            "details": "Benchmark Cache Test",
            "cached": False
        }
        set_cached_result(ip, "ipv4", dummy_data)
    write_duration = time.perf_counter() - start_write
    write_throughput = num_records / write_duration if write_duration > 0 else 0

    # Read benchmark
    start_read = time.perf_counter()
    hit_count = 0
    for ip in test_iocs:
        record = get_cached_result(ip)
        if record:
            hit_count += 1
    read_duration = time.perf_counter() - start_read
    read_throughput = hit_count / read_duration if read_duration > 0 else 0

    return {
        "num_records": num_records,
        "write_duration": write_duration,
        "write_throughput": write_throughput,
        "read_duration": read_duration,
        "read_throughput": read_throughput,
        "hit_rate_pct": (hit_count / num_records) * 100
    }


def benchmark_concurrent_scanning(
    extracted_iocs: Dict[str, List[str]],
    max_threads: int = 10
) -> Dict[str, float]:
    """Measure concurrent scanning and pipeline throughput."""
    total_iocs = count_iocs(extracted_iocs)
    
    # Prepopulate cache for simulated high-throughput lookup without rate-limiting external APIs
    config = {
        "vt_api_key": "",
        "abuseipdb_api_key": "",
        "max_threads": max_threads,
        "rate_limit_seconds": 0.0  # Zero delay for throughput testing
    }

    start_time = time.perf_counter()
    results = scan_iocs_sync(extracted_iocs, config, verbose=False)
    duration = time.perf_counter() - start_time

    throughput = len(results) / duration if duration > 0 else 0

    return {
        "threads": max_threads,
        "total_scanned": len(results),
        "duration_sec": duration,
        "throughput_iocs_per_sec": throughput,
        "avg_latency_ms": (duration / len(results) * 1000) if results else 0
    }


# ─── Main Benchmark Runner ───────────────────────────────────────────────────

def run_benchmark(count: int = 200, threads: int = 10):
    print("==================================================================")
    print(" 🚀 AUTOMATED THREAT INTEL SCANNER — PERFORMANCE BENCHMARK")
    print("==================================================================")
    print(f"[*] Generating {count} synthetic incident log entries...")
    log_text, _ = generate_synthetic_iocs(count)
    print(f"[+] Payload generated: {len(log_text):,} bytes ({len(log_text.splitlines())} lines)\n")

    # 1. Extraction Benchmark
    print("--- 1. IOC Regex Extraction Engine Benchmark ---")
    ext_stats = benchmark_extraction(log_text, count * 5)
    print(f"  • Extracted IOCs:    {ext_stats['extracted_count']:,}")
    print(f"  • Duration:          {ext_stats['duration_sec'] * 1000:.2f} ms")
    print(f"  • Processing Speed:  {ext_stats['iocs_per_sec']:,.1f} IOCs/sec ({ext_stats['mb_per_sec']:.2f} MB/s)")

    # 2. SQLite Cache Benchmark
    print("\n--- 2. SQLite Cache Engine Benchmark ---")
    cache_stats = benchmark_cache_throughput(num_records=min(300, count * 2))
    print(f"  • Tested Records:    {cache_stats['num_records']}")
    print(f"  • Write Speed:       {cache_stats['write_throughput']:,.1f} writes/sec ({cache_stats['write_duration']*1000:.1f}ms total)")
    print(f"  • Read Speed:        {cache_stats['read_throughput']:,.1f} reads/sec ({cache_stats['read_duration']*1000:.1f}ms total)")
    print(f"  • Cache Hit Rate:    {cache_stats['hit_rate_pct']:.1f}%")

    # 3. Concurrent Thread Pipeline Throughput
    print(f"\n--- 3. Multi-Threaded Pipeline Throughput ({threads} workers) ---")
    extracted = extract_iocs(log_text)
    scan_stats = benchmark_concurrent_scanning(extracted, max_threads=threads)
    print(f"  • Total Scanned:     {scan_stats['total_scanned']:,} IOCs")
    print(f"  • Concurrency:       {scan_stats['threads']} worker threads")
    print(f"  • Elapsed Time:      {scan_stats['duration_sec']:.4f}s")
    print(f"  • Pipeline Rate:     {scan_stats['throughput_iocs_per_sec']:,.1f} IOCs/sec")
    print(f"  • Avg IOC Latency:   {scan_stats['avg_latency_ms']:.3f} ms")

    print("\n==================================================================")
    print(f" ✅ BENCHMARK COMPLETED SUCCESSFULLY (Throughput: {scan_stats['throughput_iocs_per_sec']:,.0f} IOCs/sec)")
    print("==================================================================")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Threat Intel Scanner Benchmark")
    parser.add_argument("--iocs", type=int, default=150, help="Number of log records to generate")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent worker threads")
    args = parser.parse_args()
    run_benchmark(count=args.iocs, threads=args.threads)
