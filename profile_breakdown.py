"""
Profile: separate C++ parsing time vs Python object construction time.

Uses parse_packet_struct (returns C++ struct, no Python dataclass construction)
vs parse_to_dataclass (C++ parse + Python construction) to isolate the two phases.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

def main():
    from wa1kpcap.native import _wa1kpcap_native as _native
    from pathlib import Path

    pcap_path = r"D:\Project\Dataset\USTCTFC2016\ustc-tfc2016\Malware\Nsis-ay.pcap"
    protocols_dir = str(Path(__file__).parent / 'wa1kpcap' / 'native' / 'protocols')
    parser = _native.NativeParser(protocols_dir)

    # First pass: read all packets into memory (eliminate I/O from benchmarks)
    print(f"Reading {os.path.basename(pcap_path)} ({os.path.getsize(pcap_path)/1024/1024:.0f} MB)...")
    reader = _native.NativePcapReader(pcap_path)
    raw_packets = []  # list of (timestamp, bytes, caplen, wirelen, link_type)
    for pkt_tuple in reader:
        raw_packets.append(pkt_tuple)
    print(f"Loaded {len(raw_packets):,} packets into memory\n")

    N = len(raw_packets)

    # ── Benchmark 1: Full pipeline (NativePipeline) ──
    print("=" * 70)
    print("Benchmark 1: NativePipeline (fused C++ mmap→parse→dataclass)")
    print("=" * 70)
    count = 0
    t0 = time.perf_counter()
    with _native.NativePipeline(pcap_path, parser, None, False) as pipeline:
        for pkt in pipeline:
            count += 1
    t_pipeline = time.perf_counter() - t0
    print(f"  {count:,} packets in {t_pipeline:.3f}s = {count/t_pipeline:,.0f} pkt/s")

    # ── Benchmark 2: C++ parse only (parse_packet_struct → NativeParsedPacket) ──
    print()
    print("=" * 70)
    print("Benchmark 2: C++ parse only (parse_packet_struct → C++ struct)")
    print("=" * 70)
    t0 = time.perf_counter()
    for ts, raw, caplen, wirelen, lt in raw_packets:
        parser.parse_packet_struct(raw, lt, False)
    t_cpp_parse = time.perf_counter() - t0
    print(f"  {N:,} packets in {t_cpp_parse:.3f}s = {N/t_cpp_parse:,.0f} pkt/s")

    # ── Benchmark 3: parse_to_dataclass (C++ parse + Python construction) ──
    print()
    print("=" * 70)
    print("Benchmark 3: parse_to_dataclass (C++ parse + Python construction)")
    print("=" * 70)
    t0 = time.perf_counter()
    for ts, raw, caplen, wirelen, lt in raw_packets:
        parser.parse_to_dataclass(raw, lt, False, ts, caplen, wirelen)
    t_full = time.perf_counter() - t0
    print(f"  {N:,} packets in {t_full:.3f}s = {N/t_full:,.0f} pkt/s")

    # ── Benchmark 4: Python for-loop baseline ──
    print()
    print("=" * 70)
    print("Benchmark 4: Python for-loop baseline (no parsing)")
    print("=" * 70)
    t0 = time.perf_counter()
    for ts, raw, caplen, wirelen, lt in raw_packets:
        pass
    t_loop = time.perf_counter() - t0
    print(f"  {N:,} iterations in {t_loop:.3f}s")

    # ── Analysis ──
    print()
    print("=" * 70)
    print("Analysis: Time breakdown (parse_to_dataclass)")
    print("=" * 70)

    t_python_obj = t_full - t_cpp_parse
    pct_cpp = t_cpp_parse / t_full * 100
    pct_py = t_python_obj / t_full * 100

    print(f"  Total parse_to_dataclass:       {t_full:.3f}s  (100%)")
    print(f"  ├─ C++ parsing (struct):        {t_cpp_parse:.3f}s  ({pct_cpp:.1f}%)")
    print(f"  └─ Python obj construction:     {t_python_obj:.3f}s  ({pct_py:.1f}%)")
    print(f"  NativePipeline (with mmap I/O): {t_pipeline:.3f}s")
    print(f"  Python loop overhead:           {t_loop:.3f}s")
    print()
    print(f"  Per-packet:")
    print(f"    C++ parse:              {t_cpp_parse/N*1e6:.2f} us")
    print(f"    Python construction:    {t_python_obj/N*1e6:.2f} us")
    print(f"    Total:                  {t_full/N*1e6:.2f} us")
    print()

    if t_python_obj > 0:
        print(f"  If Python construction were FREE, max speedup: {t_full/t_cpp_parse:.2f}x")
    print(f"  If C++ parse were FREE, max speedup:           {t_full/t_python_obj:.2f}x")


if __name__ == '__main__':
    main()
