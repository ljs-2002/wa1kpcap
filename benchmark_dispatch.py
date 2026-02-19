"""Benchmark: if-else vs unordered_map protocol dispatch.

Measures pure C++ parse_packet_struct throughput on real pcap data.
Runs multiple iterations, reports median pkt/s and MB/s.
"""
import time
import os
import sys
import statistics

# Ensure wa1kpcap is importable
sys.path.insert(0, os.path.dirname(__file__))

PCAP_DIR = r"D:\Project\Dataset\USTCTFC2016\ustc-tfc2016\Benign"
# Use multiple pcaps for a good mix of protocols
PCAP_FILES = ["FTP.pcap", "MySQL.pcap", "WorldOfWarcraft.pcap", "Gmail.pcap"]

WARMUP_ROUNDS = 1
BENCH_ROUNDS = 5


def load_raw_packets(pcap_path, max_packets=None):
    """Read raw packets from pcap using our native reader."""
    from wa1kpcap.native import _wa1kpcap_native as _native
    packets = []
    reader = _native.NativePcapReader(pcap_path)
    for ts, raw, caplen, wirelen, lt in reader:
        packets.append((raw, lt))
        if max_packets and len(packets) >= max_packets:
            break
    return packets


def bench_parse_struct(packets, parser, rounds=5):
    """Benchmark parse_packet_struct on pre-loaded packets."""
    times = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        for raw, lt in packets:
            parser.parse_packet_struct(raw, lt, False)
        elapsed = time.perf_counter() - t0
        times.append(elapsed)
    return times


def main():
    from wa1kpcap.native import _wa1kpcap_native as _native

    # Collect all packets
    all_packets = []
    total_bytes = 0
    for fname in PCAP_FILES:
        path = os.path.join(PCAP_DIR, fname)
        if not os.path.exists(path):
            print(f"  SKIP {fname} (not found)")
            continue
        pkts = load_raw_packets(path)
        all_packets.extend(pkts)
        total_bytes += os.path.getsize(path)
        print(f"  Loaded {fname}: {len(pkts):,} packets")

    print(f"\nTotal: {len(all_packets):,} packets, {total_bytes/1024/1024:.1f} MB")

    # Create parser
    proto_dir = os.path.join(os.path.dirname(__file__), "wa1kpcap", "native", "protocols")
    parser = _native.NativeParser(proto_dir)

    # Warmup
    print(f"\nWarmup ({WARMUP_ROUNDS} rounds)...")
    bench_parse_struct(all_packets, parser, WARMUP_ROUNDS)

    # Benchmark
    print(f"Benchmarking ({BENCH_ROUNDS} rounds)...")
    times = bench_parse_struct(all_packets, parser, BENCH_ROUNDS)

    # Report
    n = len(all_packets)
    mb = total_bytes / 1024 / 1024
    print(f"\n{'='*60}")
    print(f"Results: parse_packet_struct")
    print(f"{'='*60}")
    for i, t in enumerate(times):
        print(f"  Round {i+1}: {t:.3f}s  ({n/t:,.0f} pkt/s, {mb/t:.1f} MB/s)")

    med = statistics.median(times)
    best = min(times)
    print(f"\n  Median: {med:.3f}s  ({n/med:,.0f} pkt/s, {mb/med:.1f} MB/s)")
    print(f"  Best:   {best:.3f}s  ({n/best:,.0f} pkt/s, {mb/best:.1f} MB/s)")
    print(f"  Stdev:  {statistics.stdev(times)*1000:.1f}ms")

    # Also benchmark full pipeline (parse + build dataclass)
    print(f"\n{'='*60}")
    print(f"Results: parse_to_dataclass (struct + Python object construction)")
    print(f"{'='*60}")

    times2 = []
    for _ in range(BENCH_ROUNDS):
        t0 = time.perf_counter()
        for raw, lt in all_packets:
            parser.parse_to_dataclass(raw, lt, False)
        elapsed = time.perf_counter() - t0
        times2.append(elapsed)

    for i, t in enumerate(times2):
        print(f"  Round {i+1}: {t:.3f}s  ({n/t:,.0f} pkt/s, {mb/t:.1f} MB/s)")

    med2 = statistics.median(times2)
    best2 = min(times2)
    print(f"\n  Median: {med2:.3f}s  ({n/med2:,.0f} pkt/s, {mb/med2:.1f} MB/s)")
    print(f"  Best:   {best2:.3f}s  ({n/best2:,.0f} pkt/s, {mb/best2:.1f} MB/s)")


if __name__ == "__main__":
    main()
