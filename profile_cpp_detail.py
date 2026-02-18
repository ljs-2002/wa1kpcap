"""
Fine-grained C++ profiling: isolate where time is spent in parse_packet_struct.

Strategy: construct synthetic packets of varying complexity and measure
parse_packet_struct (C++ only, no Python construction) to isolate:
  1. parse_layer overhead (YAML field iteration + FieldMap insertion)
  2. fill_* overhead (FieldMap → struct extraction)
  3. next_protocol lookup overhead
  4. per-layer overhead (how much does each additional layer cost?)

Also: compare parse_layer (returns FieldMap) vs hypothetical zero-work baseline.
"""

import os
import sys
import time
import struct

sys.path.insert(0, os.path.dirname(__file__))


def build_eth_only():
    """Ethernet frame with unknown ethertype (no next layer)."""
    return b'\x00' * 6 + b'\x00' * 6 + b'\x99\x99'  # ethertype 0x9999 = unknown


def build_eth_ip():
    """Ethernet + IPv4 (protocol=0xFF = unknown, no transport layer)."""
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, 0, 0, 64, 0xFF, 0,
        b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02')
    return b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00' + ip_header


def build_eth_ip_tcp():
    """Ethernet + IPv4 + TCP (no payload, no next protocol)."""
    tcp_header = struct.pack('!HHIIBBHHH',
        12345, 80, 1000, 0, (5 << 4), 0x02, 65535, 0, 0)
    ip_total = 20 + len(tcp_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 6, 0,
        b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02')
    return b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00' + ip_header + tcp_header


def build_eth_ip_udp():
    """Ethernet + IPv4 + UDP (no payload)."""
    udp = struct.pack('!HHHH', 12345, 9999, 8, 0)
    ip_total = 20 + len(udp)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 17, 0,
        b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02')
    return b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00' + ip_header + udp


def build_eth_ip_udp_dns():
    """Ethernet + IPv4 + UDP(53) + minimal DNS query."""
    # Minimal DNS: header(12) + 1 question (example.com = 12 bytes + 4 bytes qtype/qclass)
    dns_header = struct.pack('!HHHHHH',
        0x1234,  # transaction ID
        0x0100,  # flags: standard query
        1, 0, 0, 0)  # 1 question, 0 answers
    # Question: \x07example\x03com\x00 + type A (1) + class IN (1)
    question = b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
    dns_payload = dns_header + question

    udp_len = 8 + len(dns_payload)
    udp = struct.pack('!HHHH', 12345, 53, udp_len, 0)
    ip_total = 20 + udp_len
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 17, 0,
        b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02')
    return b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00' + ip_header + udp + dns_payload


def build_eth_ip_tcp_tls_ch():
    """Ethernet + IPv4 + TCP(443) + TLS ClientHello (minimal)."""
    # Minimal TLS ClientHello
    # Extensions: SNI (type=0x0000)
    sni_host = b'example.com'
    sni_entry = struct.pack('!BH', 0, len(sni_host)) + sni_host
    sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
    ext_sni = struct.pack('!HH', 0x0000, len(sni_list)) + sni_list

    extensions = ext_sni
    extensions_len = len(extensions)

    # ClientHello body
    client_hello = struct.pack('!HH', 0x0303, 32)  # version TLS 1.2, random length
    client_hello += b'\x00' * 32  # random
    client_hello += b'\x00'  # session_id length = 0
    client_hello += struct.pack('!H', 2) + struct.pack('!H', 0x1301)  # 1 cipher suite
    client_hello += b'\x01\x00'  # compression methods
    client_hello += struct.pack('!H', extensions_len) + extensions

    # Handshake header
    handshake = struct.pack('!B', 1)  # ClientHello
    handshake += struct.pack('!I', len(client_hello))[1:]  # 3-byte length
    handshake += client_hello

    # TLS record
    tls_record = struct.pack('!BHH', 22, 0x0301, len(handshake)) + handshake

    tcp_header = struct.pack('!HHIIBBHHH',
        12345, 443, 1000, 2000, (5 << 4), 0x18, 65535, 0, 0)
    ip_total = 20 + len(tcp_header) + len(tls_record)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 6, 0,
        b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02')
    return b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00' + ip_header + tcp_header + tls_record


def timeit(func, n, warmup=2000):
    for _ in range(warmup):
        func()
    t0 = time.perf_counter()
    for _ in range(n):
        func()
    elapsed = time.perf_counter() - t0
    return elapsed, elapsed / n * 1e9


def main():
    from wa1kpcap.native import _wa1kpcap_native as _native
    from pathlib import Path

    protocols_dir = str(Path(__file__).parent / 'wa1kpcap' / 'native' / 'protocols')
    parser = _native.NativeParser(protocols_dir)

    N = 200_000

    packets = {
        'Eth only (1 layer, 3 fixed)':           build_eth_only(),
        'Eth+IP (2 layers, 13 fixed+computed)':   build_eth_ip(),
        'Eth+IP+TCP (3 layers, 22 fixed+bf+comp)': build_eth_ip_tcp(),
        'Eth+IP+UDP (3 layers, 17 fixed)':        build_eth_ip_udp(),
        'Eth+IP+UDP+DNS (4 layers, hardcoded)':   build_eth_ip_udp_dns(),
        'Eth+IP+TCP+TLS CH (3+TLS, ext_list)':   build_eth_ip_tcp_tls_ch(),
    }

    # ═══════════════════════════════════════════════════════════
    # Part 1: parse_packet_struct (C++ parse → C++ struct)
    # ═══════════════════════════════════════════════════════════
    print(f"Iterations: {N:,}\n")
    print("=" * 75)
    print("Part 1: parse_packet_struct (C++ parse only, no Python obj construction)")
    print("=" * 75)

    results_struct = {}
    for label, raw in packets.items():
        def bench(r=raw):
            return parser.parse_packet_struct(r, 1, False)
        elapsed, ns = timeit(bench, N)
        results_struct[label] = ns
        print(f"  {label:50s}  {ns:8.0f} ns/pkt")

    # ═══════════════════════════════════════════════════════════
    # Part 2: parse_to_dataclass (C++ parse + Python construction)
    # ═══════════════════════════════════════════════════════════
    print()
    print("=" * 75)
    print("Part 2: parse_to_dataclass (C++ parse + Python obj construction)")
    print("=" * 75)

    results_full = {}
    for label, raw in packets.items():
        def bench(r=raw):
            return parser.parse_to_dataclass(r, 1, False, 1.0, len(r), len(r))
        elapsed, ns = timeit(bench, N)
        results_full[label] = ns
        print(f"  {label:50s}  {ns:8.0f} ns/pkt")

    # ═══════════════════════════════════════════════════════════
    # Part 3: Incremental cost analysis
    # ═══════════════════════════════════════════════════════════
    print()
    print("=" * 75)
    print("Part 3: Incremental cost analysis (C++ struct path)")
    print("=" * 75)

    labels = list(packets.keys())
    ns_vals = [results_struct[l] for l in labels]

    print(f"  {'Layer added':50s}  {'C++ ns':>8s}  {'Delta':>8s}  {'Py obj ns':>9s}  {'Py delta':>9s}")
    print(f"  {'-'*50}  {'-'*8}  {'-'*8}  {'-'*9}  {'-'*9}")
    for i, label in enumerate(labels):
        cpp_ns = results_struct[label]
        full_ns = results_full[label]
        py_ns = full_ns - cpp_ns
        cpp_delta = cpp_ns - ns_vals[i-1] if i > 0 else cpp_ns
        py_delta = py_ns - (results_full[labels[i-1]] - results_struct[labels[i-1]]) if i > 0 else py_ns
        print(f"  {label:50s}  {cpp_ns:8.0f}  {cpp_delta:+8.0f}  {py_ns:9.0f}  {py_delta:+9.0f}")

    # ═══════════════════════════════════════════════════════════
    # Part 4: Real pcap breakdown by protocol mix
    # ═══════════════════════════════════════════════════════════
    pcap_path = r"D:\Project\Dataset\USTCTFC2016\ustc-tfc2016\Malware\Nsis-ay.pcap"
    if os.path.exists(pcap_path):
        print()
        print("=" * 75)
        print(f"Part 4: Real pcap protocol mix — {os.path.basename(pcap_path)}")
        print("=" * 75)

        reader = _native.NativePcapReader(pcap_path)
        raw_packets = []
        for pkt_tuple in reader:
            raw_packets.append(pkt_tuple)

        # Classify packets by what layers they have
        from collections import Counter
        proto_counts = Counter()
        sample_by_type = {}

        for ts, raw, caplen, wirelen, lt in raw_packets:
            pkt = parser.parse_packet_struct(raw, lt, False)
            layers = []
            if pkt.eth is not None: layers.append('eth')
            if pkt.ip is not None: layers.append('ip')
            if pkt.ip6 is not None: layers.append('ip6')
            if pkt.tcp is not None: layers.append('tcp')
            if pkt.udp is not None: layers.append('udp')
            if pkt.dns is not None: layers.append('dns')
            if pkt.tls is not None: layers.append('tls')
            key = '+'.join(layers) if layers else 'empty'
            proto_counts[key] += 1
            if key not in sample_by_type:
                sample_by_type[key] = (raw, lt)

        print(f"\n  Protocol mix ({len(raw_packets):,} packets):")
        for key, count in proto_counts.most_common(10):
            pct = count / len(raw_packets) * 100
            print(f"    {key:30s}  {count:8,}  ({pct:5.1f}%)")

        # Benchmark each type separately
        print(f"\n  Per-type parse_packet_struct timing (N={min(N, 100_000):,}):")
        bench_n = min(N, 100_000)
        for key, count in proto_counts.most_common(10):
            raw, lt = sample_by_type[key]
            def bench(r=raw, l=lt):
                return parser.parse_packet_struct(r, l, False)
            _, ns = timeit(bench, bench_n, warmup=1000)
            print(f"    {key:30s}  {ns:8.0f} ns/pkt  (x{count:,} = {ns*count/1e6:.1f} ms total)")


if __name__ == '__main__':
    main()
