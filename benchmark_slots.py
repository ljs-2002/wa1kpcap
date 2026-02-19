"""Benchmark: __slots__ optimization before/after comparison.

Measures NativePipeline end-to-end throughput on a pcap file,
plus isolated Python object construction microbenchmarks.
"""
import time
import os
import sys
import statistics

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(__file__))


def benchmark_pipeline(pcap_path: str, rounds: int = 7) -> dict:
    """Benchmark NativePipeline end-to-end throughput."""
    from wa1kpcap.native import _wa1kpcap_native as _native

    protocols_dir = os.path.join(os.path.dirname(__file__), "wa1kpcap", "native", "protocols")
    parser = _native.NativeParser(protocols_dir)

    times = []
    pkt_count = 0

    for i in range(rounds):
        count = 0
        t0 = time.perf_counter()
        with _native.NativePipeline(pcap_path, parser, None, False) as pipeline:
            for pkt in pipeline:
                count += 1
        elapsed = time.perf_counter() - t0
        times.append(elapsed)
        pkt_count = count
        print(f"  Round {i+1}/{rounds}: {count:,} pkts in {elapsed:.3f}s = {count/elapsed:,.0f} pkt/s")

    med = statistics.median(times)
    best = min(times)
    return {
        'packets': pkt_count,
        'median_s': med,
        'best_s': best,
        'median_pps': pkt_count / med,
        'best_pps': pkt_count / best,
        'times': times,
    }


def benchmark_object_construction(pcap_path: str, rounds: int = 7) -> dict:
    """Benchmark isolated Python object construction cost.

    Measures:
    1. C++ parse_packet_struct only (no Python objects)
    2. Full parse_to_dataclass (C++ + Python objects)
    3. Delta = Python object construction cost
    """
    from wa1kpcap.native import _wa1kpcap_native as _native

    protocols_dir = os.path.join(os.path.dirname(__file__), "wa1kpcap", "native", "protocols")
    parser = _native.NativeParser(protocols_dir)

    # Read all raw packets first
    reader = _native.NativePcapReader(pcap_path)
    raw_packets = list(reader)
    N = len(raw_packets)
    print(f"  Loaded {N:,} raw packets")

    # Benchmark C++ struct-only path
    struct_times = []
    for i in range(rounds):
        t0 = time.perf_counter()
        for ts, raw, caplen, wirelen, lt in raw_packets:
            parser.parse_packet_struct(raw, lt, False)
        elapsed = time.perf_counter() - t0
        struct_times.append(elapsed)

    # Benchmark full dataclass path
    full_times = []
    for i in range(rounds):
        t0 = time.perf_counter()
        for ts, raw, caplen, wirelen, lt in raw_packets:
            parser.parse_to_dataclass(raw, lt, False, ts, caplen, wirelen)
        elapsed = time.perf_counter() - t0
        full_times.append(elapsed)

    med_struct = statistics.median(struct_times)
    med_full = statistics.median(full_times)
    med_pyobj = med_full - med_struct

    us_struct = med_struct / N * 1e6
    us_full = med_full / N * 1e6
    us_pyobj = med_pyobj / N * 1e6

    return {
        'packets': N,
        'us_struct': us_struct,
        'us_full': us_full,
        'us_pyobj': us_pyobj,
        'med_struct': med_struct,
        'med_full': med_full,
    }


def benchmark_info_construction(rounds: int = 500_000) -> dict:
    """Microbenchmark individual Info class construction."""
    from wa1kpcap.core.packet import EthernetInfo, IPInfo, TCPInfo, UDPInfo

    results = {}

    # EthernetInfo
    t0 = time.perf_counter()
    for _ in range(rounds):
        EthernetInfo(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66", type=0x0800)
    elapsed = time.perf_counter() - t0
    results['EthernetInfo'] = elapsed / rounds * 1e6

    # IPInfo
    t0 = time.perf_counter()
    for _ in range(rounds):
        IPInfo(version=4, src="192.168.1.1", dst="10.0.0.1", proto=6, ttl=64, len=1500, id=12345, flags=2, offset=0)
    elapsed = time.perf_counter() - t0
    results['IPInfo'] = elapsed / rounds * 1e6

    # TCPInfo
    t0 = time.perf_counter()
    for _ in range(rounds):
        TCPInfo(sport=12345, dport=80, seq=100, ack_num=200, flags=0x18, win=65535, urgent=0, options=b"")
    elapsed = time.perf_counter() - t0
    results['TCPInfo'] = elapsed / rounds * 1e6

    # UDPInfo
    t0 = time.perf_counter()
    for _ in range(rounds):
        UDPInfo(sport=12345, dport=53, len=100)
    elapsed = time.perf_counter() - t0
    results['UDPInfo'] = elapsed / rounds * 1e6

    return results


def main():
    pcap_path = r"D:\Project\Dataset\USTCTFC2016\ustc-tfc2016\Benign\FTP.pcap"
    if not os.path.exists(pcap_path):
        print(f"ERROR: pcap not found: {pcap_path}")
        sys.exit(1)

    file_size_mb = os.path.getsize(pcap_path) / 1024 / 1024
    print("=" * 70)
    print(f"Benchmark: __slots__ optimization")
    print(f"File: {os.path.basename(pcap_path)} ({file_size_mb:.1f} MB)")
    print("=" * 70)

    # 1. Pipeline throughput
    print("\n--- NativePipeline end-to-end throughput ---")
    pipeline_result = benchmark_pipeline(pcap_path, rounds=7)
    print(f"\n  Median: {pipeline_result['median_pps']:,.0f} pkt/s")
    print(f"  Best:   {pipeline_result['best_pps']:,.0f} pkt/s")
    print(f"  Median: {pipeline_result['packets'] / pipeline_result['median_s'] * 66 / 1e6:.1f} Mpkt/min")

    # 2. Object construction breakdown
    print("\n--- Object construction breakdown ---")
    obj_result = benchmark_object_construction(pcap_path, rounds=7)
    print(f"\n  C++ parse_packet_struct:        {obj_result['us_struct']:.2f} us/pkt")
    print(f"  Python object construction:     {obj_result['us_pyobj']:.2f} us/pkt")
    print(f"  Total (parse_to_dataclass):     {obj_result['us_full']:.2f} us/pkt")
    print(f"  Python overhead ratio:          {obj_result['us_pyobj']/obj_result['us_full']*100:.0f}%")

    # 3. Individual Info class construction
    print("\n--- Individual Info class construction ---")
    info_result = benchmark_info_construction()
    for cls_name, us in info_result.items():
        print(f"  {cls_name:20s}: {us:.3f} us")

    print("\n" + "=" * 70)
    print("Done.")


if __name__ == "__main__":
    main()
