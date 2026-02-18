"""
Real C++ profiling using embedded chrono instrumentation.
Measures actual time spent in each phase of parse_packet_struct.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(__file__))

from pathlib import Path
from wa1kpcap.native import _wa1kpcap_native as _native


def main():
    protocols_dir = str(Path(__file__).parent / 'wa1kpcap' / 'native' / 'protocols')
    parser = _native.NativeParser(protocols_dir)

    pcap_path = r"D:\Project\Dataset\USTCTFC2016\ustc-tfc2016\Malware\Nsis-ay.pcap"
    if not os.path.exists(pcap_path):
        print(f"pcap not found: {pcap_path}")
        return

    # Read all packets
    reader = _native.NativePcapReader(pcap_path)
    raw_packets = []
    for pkt_tuple in reader:
        raw_packets.append(pkt_tuple)
    print(f"Loaded {len(raw_packets):,} packets from {os.path.basename(pcap_path)}")

    # ═══════════════════════════════════════════════════════════
    # Warmup (profiling disabled)
    # ═══════════════════════════════════════════════════════════
    print("\nWarming up...")
    for ts, raw, caplen, wirelen, lt in raw_packets[:5000]:
        parser.parse_packet_struct(raw, lt, False)

    # ═══════════════════════════════════════════════════════════
    # Profiled run: parse_packet_struct only (C++ side)
    # ═══════════════════════════════════════════════════════════
    print("Running profiled parse_packet_struct...")
    _native.profiling_enable()

    for ts, raw, caplen, wirelen, lt in raw_packets:
        parser.parse_packet_struct(raw, lt, False)

    stats = _native.profiling_get_stats()
    _native.profiling_disable()

    n_pkts = stats['total_packets']
    n_layers = stats['total_layers']
    total_ns = stats['total_ns']
    parse_layer_ns = stats['parse_layer_ns']
    fill_struct_ns = stats['fill_struct_ns']
    next_proto_ns = stats['next_proto_ns']

    # Overhead = total - parse_layer - fill_struct (loop control, proto lookup, etc.)
    overhead_ns = total_ns - parse_layer_ns - fill_struct_ns

    print(f"\n{'='*75}")
    print(f"C++ parse_packet_struct profiling — {n_pkts:,} packets, {n_layers:,} layers")
    print(f"{'='*75}")
    print(f"\n  Phase breakdown:")
    print(f"  {'Phase':<30s}  {'Total ms':>10s}  {'Per-pkt ns':>10s}  {'%':>6s}")
    print(f"  {'-'*30}  {'-'*10}  {'-'*10}  {'-'*6}")

    for label, ns in [
        ('parse_layer (all)', parse_layer_ns),
        ('  next_proto lookup', next_proto_ns),
        ('  field parsing', parse_layer_ns - next_proto_ns),
        ('fill_struct (fill_*)', fill_struct_ns),
        ('loop overhead', overhead_ns),
        ('TOTAL', total_ns),
    ]:
        ms = ns / 1e6
        per_pkt = ns / n_pkts
        pct = ns / total_ns * 100
        print(f"  {label:<30s}  {ms:10.1f}  {per_pkt:10.0f}  {pct:5.1f}%")

    # ═══════════════════════════════════════════════════════════
    # Per-primitive breakdown
    # ═══════════════════════════════════════════════════════════
    prims = stats['primitives']
    print(f"\n  Per-primitive breakdown (inside parse_layer):")
    print(f"  {'Primitive':<20s}  {'Count':>10s}  {'Total ms':>10s}  {'Per-call ns':>12s}  {'% of parse':>10s}")
    print(f"  {'-'*20}  {'-'*10}  {'-'*10}  {'-'*12}  {'-'*10}")

    field_parse_ns = parse_layer_ns - next_proto_ns
    sorted_prims = sorted(prims.items(), key=lambda x: x[1]['ns'], reverse=True)
    prim_total_ns = 0
    for name, p in sorted_prims:
        ns = p['ns']
        count = p['count']
        prim_total_ns += ns
        if count == 0:
            continue
        ms = ns / 1e6
        per_call = ns / count
        pct = ns / field_parse_ns * 100 if field_parse_ns > 0 else 0
        print(f"  {name:<20s}  {count:10,}  {ms:10.1f}  {per_call:12.0f}  {pct:9.1f}%")

    # Unaccounted time in parse_layer (FieldMap init, field iteration loop, etc.)
    unaccounted = field_parse_ns - prim_total_ns
    print(f"  {'(unaccounted)':<20s}  {'':>10s}  {unaccounted/1e6:10.1f}  {unaccounted/n_layers:12.0f}  {unaccounted/field_parse_ns*100:9.1f}%")

    # ═══════════════════════════════════════════════════════════
    # Per-layer averages
    # ═══════════════════════════════════════════════════════════
    print(f"\n  Averages:")
    print(f"    Layers per packet:     {n_layers / n_pkts:.2f}")
    print(f"    parse_layer per layer: {parse_layer_ns / n_layers:.0f} ns")
    print(f"    fill_struct per layer: {fill_struct_ns / n_layers:.0f} ns")
    print(f"    next_proto per layer:  {next_proto_ns / n_layers:.0f} ns")

    # ═══════════════════════════════════════════════════════════
    # Profiled run: parse_to_dataclass (C++ + Python construction)
    # ═══════════════════════════════════════════════════════════
    import time
    print(f"\n{'='*75}")
    print(f"End-to-end: parse_to_dataclass (C++ + Python obj construction)")
    print(f"{'='*75}")

    _native.profiling_enable()
    t0 = time.perf_counter()
    for ts, raw, caplen, wirelen, lt in raw_packets:
        parser.parse_to_dataclass(raw, lt, False, 1.0, 100, 100)
    t1 = time.perf_counter()
    stats2 = _native.profiling_get_stats()
    _native.profiling_disable()

    wall_ns = (t1 - t0) * 1e9
    cpp_ns = stats2['total_ns']
    py_ns = wall_ns - cpp_ns

    print(f"  {'Phase':<30s}  {'Total ms':>10s}  {'Per-pkt ns':>10s}  {'%':>6s}")
    print(f"  {'-'*30}  {'-'*10}  {'-'*10}  {'-'*6}")
    for label, ns in [
        ('C++ parse_packet_struct', cpp_ns),
        ('Python obj construction', py_ns),
        ('Python→C++ call overhead', wall_ns - cpp_ns - py_ns),  # should be ~0
        ('TOTAL (wall)', wall_ns),
    ]:
        ms = ns / 1e6
        per_pkt = ns / n_pkts
        pct = ns / wall_ns * 100
        print(f"  {label:<30s}  {ms:10.1f}  {per_pkt:10.0f}  {pct:5.1f}%")


if __name__ == '__main__':
    main()
