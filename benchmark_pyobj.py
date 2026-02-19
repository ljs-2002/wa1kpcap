"""Profiling: Python object construction overhead breakdown.

Measures each stage of the C++ → Python object pipeline to identify
where time is spent and what optimizations would help most.

Stages measured:
  1. parse_packet_struct (pure C++)
  2. build_dataclass_from_struct (C++ → Python object construction)
  3. Individual Info class construction overhead
  4. ParsedPacket.__init__ overhead (layers dict building)
  5. _fields dict construction inside ProtocolInfo.__init__
"""
import time
import os
import sys
import statistics

sys.path.insert(0, os.path.dirname(__file__))

PCAP_DIR = r"D:\Project\Dataset\USTCTFC2016\ustc-tfc2016\Benign"
PCAP_FILES = ["FTP.pcap", "MySQL.pcap", "WorldOfWarcraft.pcap", "Gmail.pcap"]
ROUNDS = 5


def load_raw_packets(pcap_path):
    from wa1kpcap.native import _wa1kpcap_native as _native
    packets = []
    reader = _native.NativePcapReader(pcap_path)
    for ts, raw, caplen, wirelen, lt in reader:
        packets.append((ts, raw, caplen, wirelen, lt))
    return packets


def fmt(label, times, n_pkts, width=55):
    med = statistics.median(times)
    best = min(times)
    pps = n_pkts / med if med > 0 else 0
    print(f"  {label:<{width}} {med*1000:8.1f} ms  ({pps:,.0f} pkt/s)")
    return med


def main():
    from wa1kpcap.native import _wa1kpcap_native as _native
    from wa1kpcap.core.packet import (
        ParsedPacket, ProtocolInfo, ProtocolRegistry,
        EthernetInfo, IPInfo, IP6Info, TCPInfo, UDPInfo,
        TLSInfo, DNSInfo, ARPInfo, ICMPInfo, ICMP6Info,
    )

    # Load packets
    all_packets = []
    for fname in PCAP_FILES:
        path = os.path.join(PCAP_DIR, fname)
        if not os.path.exists(path):
            print(f"  SKIP {fname}")
            continue
        pkts = load_raw_packets(path)
        all_packets.extend(pkts)
        print(f"  Loaded {fname}: {len(pkts):,} packets")

    N = len(all_packets)
    print(f"\nTotal: {N:,} packets, {ROUNDS} rounds each\n")

    proto_dir = os.path.join(os.path.dirname(__file__), "wa1kpcap", "native", "protocols")
    parser = _native.NativeParser(proto_dir)

    # Warmup
    for ts, raw, caplen, wirelen, lt in all_packets[:1000]:
        parser.parse_to_dataclass(raw, lt, False, ts, caplen, wirelen)

    # ── Stage 1: Pure C++ parse_packet_struct ──
    times_struct = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for ts, raw, caplen, wirelen, lt in all_packets:
            parser.parse_packet_struct(raw, lt, False)
        times_struct.append(time.perf_counter() - t0)

    # ── Stage 2: Full pipeline (parse + Python object construction) ──
    times_full = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for ts, raw, caplen, wirelen, lt in all_packets:
            parser.parse_to_dataclass(raw, lt, False, ts, caplen, wirelen)
        times_full.append(time.perf_counter() - t0)

    # ── Stage 3: Isolate Python-only overhead ──
    # Pre-parse all packets to C++ structs, then measure only the Python construction
    # We can't call build_dataclass_from_struct separately, but we can measure
    # the difference: full - struct = Python object construction

    # ── Stage 4: Micro-benchmark individual Info class construction ──
    # Simulate what build_dataclass_from_struct does on the Python side

    # 4a: EthernetInfo construction
    times_eth = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            EthernetInfo("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 0x0800, b"")
        times_eth.append(time.perf_counter() - t0)

    # 4b: IPInfo construction
    times_ip = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            IPInfo(4, "192.168.1.1", "10.0.0.1", 6, 64, 1500, 12345, 0x4000, 0, b"")
        times_ip.append(time.perf_counter() - t0)

    # 4c: TCPInfo construction
    times_tcp = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            TCPInfo(12345, 80, 100000, 200000, 0x18, 65535, 0, b"", b"")
        times_tcp.append(time.perf_counter() - t0)

    # 4d: UDPInfo construction
    times_udp = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            UDPInfo(12345, 53, 100, b"")
        times_udp.append(time.perf_counter() - t0)

    # 4e: Bare ProtocolInfo (just dict storage)
    times_bare = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            ProtocolInfo(fields={'a': 1, 'b': 'x', 'c': 3})
        times_bare.append(time.perf_counter() - t0)

    # 4f: Plain dict construction (baseline — no class overhead)
    times_dict = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            d = {'src': "192.168.1.1", 'dst': "10.0.0.1", 'proto': 6,
                 'ttl': 64, 'len': 1500, 'id': 12345, 'flags': 0x4000,
                 'offset': 0, 'version': 4, '_raw': b""}
        times_dict.append(time.perf_counter() - t0)

    # ── Stage 5: ParsedPacket.__init__ overhead ──
    # Pre-create Info objects, measure only ParsedPacket construction
    eth_obj = EthernetInfo("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", 0x0800, b"")
    ip_obj = IPInfo(4, "192.168.1.1", "10.0.0.1", 6, 64, 1500, 12345, 0x4000, 0, b"")
    tcp_obj = TCPInfo(12345, 80, 100000, 200000, 0x18, 65535, 0, b"", b"")
    fk = (("10.0.0.1", 80, "192.168.1.1", 12345, 6),
          "192.168.1.1", "10.0.0.1", 12345, 80, 6)

    times_pkt_init = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            ParsedPacket(
                0.0, b"", 1, 100, 100, 1500, 40, 60,
                eth_obj, ip_obj, None, tcp_obj, None, None, None, None, None,
                True, -1, -1,
                None, None, None, None,
                b"", fk, None, None, None)
        times_pkt_init.append(time.perf_counter() - t0)

    # ── Stage 6: pybind11 type conversion overhead ──
    # Measure C++ → Python string conversion (simulates what pybind11 does)
    times_str_conv = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            # Simulate creating ~15 Python objects from C++ values
            # (strings, ints, bytes — what pybind11 does per packet)
            s1 = str("192.168.1.1")
            s2 = str("10.0.0.1")
            s3 = str("aa:bb:cc:dd:ee:ff")
            s4 = str("11:22:33:44:55:66")
            _ = bytes(b"")
        times_str_conv.append(time.perf_counter() - t0)

    # ── Stage 7: Measure _fields dict overhead specifically ──
    # Compare: dict literal vs dict from positional args (what Info.__init__ does)
    times_dict_literal = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            d = {'version': 4, 'src': "192.168.1.1", 'dst': "10.0.0.1",
                 'proto': 6, 'ttl': 64, 'len': 1500, 'id': 12345,
                 'flags': 0x4000, 'offset': 0, '_raw': b""}
        times_dict_literal.append(time.perf_counter() - t0)

    times_dict_prebuilt = []
    # What if we pass a pre-built dict (fields=dict) instead of positional args?
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            d = {'version': 4, 'src': "192.168.1.1", 'dst': "10.0.0.1",
                 'proto': 6, 'ttl': 64, 'len': 1500, 'id': 12345,
                 'flags': 0x4000, 'offset': 0, '_raw': b""}
            IPInfo(fields=d)
        times_dict_prebuilt.append(time.perf_counter() - t0)

    # ── Stage 8: What if Info classes used __slots__ with direct attrs instead of _fields dict? ──
    class IPInfoSlots:
        __slots__ = ('version', 'src', 'dst', 'proto', 'ttl', 'len',
                     'id', 'flags', 'offset', '_raw')
        def __init__(self, version=0, src="", dst="", proto=0, ttl=0,
                     length=0, id=0, flags=0, offset=0, _raw=b""):
            self.version = version
            self.src = src
            self.dst = dst
            self.proto = proto
            self.ttl = ttl
            self.len = length
            self.id = id
            self.flags = flags
            self.offset = offset
            self._raw = _raw

    times_slots = []
    for _ in range(ROUNDS):
        t0 = time.perf_counter()
        for _ in range(N):
            IPInfoSlots(4, "192.168.1.1", "10.0.0.1", 6, 64, 1500, 12345, 0x4000, 0, b"")
        times_slots.append(time.perf_counter() - t0)

    # ── Report ──
    print("=" * 80)
    print("PROFILING RESULTS: Python Object Construction Breakdown")
    print("=" * 80)

    print("\n── End-to-End Pipeline ──")
    t_struct = fmt("1. parse_packet_struct (pure C++)", times_struct, N)
    t_full = fmt("2. parse_to_dataclass (C++ + Python objects)", times_full, N)
    t_pyobj = t_full - t_struct
    pct = t_pyobj / t_full * 100 if t_full > 0 else 0
    print(f"  {'→ Python object construction (2 - 1)':<55} {t_pyobj*1000:8.1f} ms  ({pct:.1f}% of total)")

    print("\n── Individual Info Class Construction (pure Python, N calls each) ──")
    fmt("3a. EthernetInfo(src, dst, type, _raw)", times_eth, N)
    fmt("3b. IPInfo(version, src, dst, proto, ...10 args)", times_ip, N)
    fmt("3c. TCPInfo(sport, dport, seq, ack, ...9 args)", times_tcp, N)
    fmt("3d. UDPInfo(sport, dport, len, _raw)", times_udp, N)
    fmt("3e. ProtocolInfo(fields={3 keys})", times_bare, N)

    print("\n── ParsedPacket.__init__ (pre-built Info objects, N calls) ──")
    fmt("4.  ParsedPacket(ts, raw, ..., eth, ip, tcp, ...)", times_pkt_init, N)

    print("\n── Baselines & Alternatives ──")
    fmt("5a. Plain dict (10 keys, no class)", times_dict, N)
    fmt("5b. Dict literal (10 keys)", times_dict_literal, N)
    fmt("5c. IPInfo(fields=prebuilt_dict)", times_dict_prebuilt, N)
    fmt("5d. IPInfoSlots (direct __slots__, no _fields dict)", times_slots, N)
    fmt("5e. String creation overhead (5 str/bytes per pkt)", times_str_conv, N)

    # ── Estimated breakdown ──
    print("\n── Estimated Per-Packet Breakdown ──")
    med_struct = statistics.median(times_struct)
    med_full = statistics.median(times_full)
    med_eth = statistics.median(times_eth)
    med_ip = statistics.median(times_ip)
    med_tcp = statistics.median(times_tcp)
    med_pkt = statistics.median(times_pkt_init)
    med_slots = statistics.median(times_slots)
    med_dict = statistics.median(times_dict)

    us_struct = med_struct / N * 1e6
    us_full = med_full / N * 1e6
    us_pyobj = (med_full - med_struct) / N * 1e6
    us_eth = med_eth / N * 1e6
    us_ip = med_ip / N * 1e6
    us_tcp = med_tcp / N * 1e6
    us_pkt = med_pkt / N * 1e6
    us_slots = med_slots / N * 1e6
    us_dict = med_dict / N * 1e6

    print(f"  C++ parsing:                    {us_struct:6.2f} us/pkt")
    print(f"  Python object construction:     {us_pyobj:6.2f} us/pkt")
    print(f"  Total (parse_to_dataclass):     {us_full:6.2f} us/pkt")
    print()
    print(f"  Typical packet (ETH+IP+TCP):")
    print(f"    EthernetInfo:                 {us_eth:6.2f} us")
    print(f"    IPInfo:                       {us_ip:6.2f} us")
    print(f"    TCPInfo:                      {us_tcp:6.2f} us")
    print(f"    ParsedPacket.__init__:        {us_pkt:6.2f} us")
    print(f"    Sum (ETH+IP+TCP+ParsedPkt):  {us_eth+us_ip+us_tcp+us_pkt:6.2f} us")
    print()
    print(f"  Alternative: __slots__ IPInfo:  {us_slots:6.2f} us  (vs {us_ip:.2f} us current)")
    print(f"  Alternative: plain dict:        {us_dict:6.2f} us  (no class overhead)")

    # ── Theoretical analysis ──
    print("\n" + "=" * 80)
    print("THEORETICAL ANALYSIS")
    print("=" * 80)

    info_sum = us_eth + us_ip + us_tcp + us_pkt
    pybind_overhead = us_pyobj - info_sum
    print(f"""
Per-packet Python object cost:          {us_pyobj:.2f} us
  ├─ Info class construction (sum):     {info_sum:.2f} us  ({info_sum/us_pyobj*100:.0f}%)
  │   ├─ _fields dict creation:         ~{us_ip - us_slots:.2f} us/class (dict vs __slots__)
  │   └─ Python class __init__ call:    ~{us_slots:.2f} us/class (irreducible)
  ├─ pybind11 type conversion + call:   ~{pybind_overhead:.2f} us  ({pybind_overhead/us_pyobj*100:.0f}%)
  │   (C++ str→py::str, int→py::int, calling Python from C++)
  └─ flow_key_cache tuple creation:     included in pybind11 overhead

Optimization potential:
  1. YAML-driven auto-fill (eliminate hand-coded fill lambdas):
     → Affects C++ fill_dispatch_ only ({us_struct:.2f} us), NOT Python objects.
     → Saves dev effort, ~0% runtime improvement.

  2. __slots__ direct attrs (eliminate _fields dict):
     → Saves ~{us_ip - us_slots:.2f} us per Info class × ~3 classes/pkt
     → Estimated saving: ~{(us_ip - us_slots) * 3:.2f} us/pkt ({(us_ip - us_slots) * 3 / us_pyobj * 100:.0f}% of Python overhead)

  3. Lazy construction (don't build Info objects until accessed):
     → Saves up to {info_sum:.2f} us/pkt if layers never accessed
     → Requires C++ to hold NativeParsedPacket, Python proxy on access

  4. C++ dict pass-through (skip Info classes, use raw dicts):
     → Saves ~{info_sum - (us_dict * 3 + us_pkt):.2f} us/pkt
     → Loses typed properties, IDE autocomplete

  5. Reduce pybind11 crossing (batch or avoid per-field conversion):
     → Hardest to optimize, ~{pybind_overhead:.2f} us/pkt
     → Would require architectural change (e.g., memoryview, shared memory)
""")


if __name__ == "__main__":
    main()
