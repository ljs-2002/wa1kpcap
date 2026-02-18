"""
Benchmark: compare Python object construction methods for custom protocols.

Tests 5 approaches:
1. Built-in struct path  — real end-to-end via parse_to_dataclass (baseline)
2. Current extra_layers   — real end-to-end via parse_to_dataclass with custom YAML
3. Scheme A (positional)  — Python simulation: cls(*args)
4. Scheme B (__new__+dict) — Python simulation: __new__ + _fields = dict
5. Scheme C (cached strs) — Python simulation: __new__ + pre-cached py str keys

Also runs a full-pcap benchmark on Nsis-ay.pcap to show real-world throughput.
"""

import os
import sys
import time
import struct
import shutil
import tempfile
import statistics

sys.path.insert(0, os.path.dirname(__file__))

from wa1kpcap.core.packet import ProtocolInfo, ProtocolRegistry


# ── Custom protocol for testing ──

class MyProtoInfo(ProtocolInfo):
    __slots__ = ()

    def __init__(self, magic=None, version=None, msg_len=None, msg_id=None,
                 fields: dict | None = None, **kwargs):
        if fields is not None:
            super().__init__(fields=fields, **kwargs)
        else:
            super().__init__(fields={
                'magic': magic, 'version': version,
                'msg_len': msg_len, 'msg_id': msg_id,
            })

    @property
    def magic(self): return self._fields.get('magic')
    @property
    def version(self): return self._fields.get('version')
    @property
    def msg_len(self): return self._fields.get('msg_len')
    @property
    def msg_id(self): return self._fields.get('msg_id')


# ── Packet builders ──

def build_tcp_syn_packet():
    """Ethernet + IPv4 + TCP SYN (built-in protocol, struct path)."""
    tcp_header = struct.pack('!HHIIBBHHH',
        12345, 443,       # src/dst port
        1000, 0,          # seq, ack
        (5 << 4), 0x02,   # data_offset=5, flags=SYN
        65535, 0, 0)      # window, checksum, urgent
    ip_total = 20 + len(tcp_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 6, 0,
        b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02')
    eth = b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00'
    return eth + ip_header + tcp_header


def build_myproto_packet():
    """Ethernet + IPv4 + UDP(7777) + myproto."""
    myproto = struct.pack('!BBHH', 0xAB, 2, 6, 42)
    udp_len = 8 + len(myproto)
    udp = struct.pack('!HHHH', 12345, 7777, udp_len, 0)
    ip_total = 20 + udp_len
    ip_header = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, ip_total, 0, 0, 64, 17, 0,
        b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02')
    eth = b'\x00' * 6 + b'\x00' * 6 + b'\x08\x00'
    return eth + ip_header + udp + myproto


def setup_custom_protocols_dir():
    """Create temp dir with standard YAMLs + myproto + patched UDP."""
    src_dir = os.path.normpath(os.path.join(
        os.path.dirname(__file__), 'wa1kpcap', 'native', 'protocols'))
    tmpdir = tempfile.mkdtemp(prefix='bench_proto_')

    for f in os.listdir(src_dir):
        if f.endswith('.yaml') and f != 'udp.yaml':
            shutil.copy2(os.path.join(src_dir, f), tmpdir)

    with open(os.path.join(tmpdir, 'udp.yaml'), 'w') as f:
        f.write("""\
name: udp
fields:
  - name: src_port
    type: fixed
    size: 2
    format: uint
  - name: dst_port
    type: fixed
    size: 2
    format: uint
  - name: length
    type: fixed
    size: 2
    format: uint
  - name: checksum
    type: fixed
    size: 2
    format: uint

next_protocol:
  field: [dst_port, src_port]
  mapping:
    53: dns
    7777: myproto
""")

    with open(os.path.join(tmpdir, 'myproto.yaml'), 'w') as f:
        f.write("""\
name: myproto
fields:
  - name: magic
    type: fixed
    size: 1
    format: uint
  - name: version
    type: fixed
    size: 1
    format: uint
  - name: msg_len
    type: fixed
    size: 2
    format: uint
  - name: msg_id
    type: fixed
    size: 2
    format: uint
""")
    return tmpdir


def timeit(func, n, warmup=1000):
    """Run func n times, return (total_seconds, per_call_ns)."""
    for _ in range(warmup):
        func()
    t0 = time.perf_counter()
    for _ in range(n):
        func()
    elapsed = time.perf_counter() - t0
    return elapsed, elapsed / n * 1e9


def main():
    from wa1kpcap.native import _wa1kpcap_native as _native
    from wa1kpcap.native.converter import dict_to_parsed_packet
    from pathlib import Path

    N = 100_000
    print(f"Iterations per test: {N:,}\n")

    # ── Setup ──
    registry = ProtocolRegistry.get_instance()
    registry.register('myproto', MyProtoInfo)

    std_dir = str(Path(__file__).parent / 'wa1kpcap' / 'native' / 'protocols')
    custom_dir = setup_custom_protocols_dir()

    std_parser = _native.NativeParser(std_dir)
    custom_parser = _native.NativeParser(custom_dir)

    tcp_raw = build_tcp_syn_packet()
    myproto_raw = build_myproto_packet()

    # ═══════════════════════════════════════════════════════════
    # Part 1: End-to-end parse_to_dataclass benchmarks
    # ═══════════════════════════════════════════════════════════
    print("=" * 70)
    print("Part 1: End-to-end parse_to_dataclass (C++ parse + Python construction)")
    print("=" * 70)

    # 1. Built-in TCP via struct path
    def bench_builtin_tcp():
        return std_parser.parse_to_dataclass(tcp_raw, 1, False, 1.0, len(tcp_raw), len(tcp_raw))

    elapsed, ns = timeit(bench_builtin_tcp, N)
    pkt = bench_builtin_tcp()
    print(f"1. Built-in TCP (struct path):     {ns:8.0f} ns/pkt  ({N/elapsed:10,.0f} pkt/s)")
    assert pkt.tcp is not None

    # 2. Custom myproto via extra_layers path
    def bench_custom_myproto():
        return custom_parser.parse_to_dataclass(myproto_raw, 1, False, 1.0, len(myproto_raw), len(myproto_raw))

    elapsed, ns = timeit(bench_custom_myproto, N)
    pkt = bench_custom_myproto()
    print(f"2. Custom myproto (extra_layers):  {ns:8.0f} ns/pkt  ({N/elapsed:10,.0f} pkt/s)")
    assert 'myproto' in pkt.layers

    # ═══════════════════════════════════════════════════════════
    # Part 2: Isolated Python object construction microbenchmark
    # ═══════════════════════════════════════════════════════════
    print()
    print("=" * 70)
    print("Part 2: Isolated Python object construction (no C++ parsing)")
    print("=" * 70)

    # Simulate the dict that C++ would produce for myproto
    sample_fields = {'magic': 0xAB, 'version': 2, 'msg_len': 6, 'msg_id': 42}
    field_names = ['magic', 'version', 'msg_len', 'msg_id']
    field_values = [0xAB, 2, 6, 42]

    # Current extra_layers path: registry.create(name, fields_dict)
    def bench_current():
        return registry.create('myproto', dict(sample_fields))

    elapsed, ns = timeit(bench_current, N)
    print(f"Current (registry.create + kwargs): {ns:7.0f} ns/call  ({N/elapsed:10,.0f} call/s)")

    # Scheme A: positional args — cls(magic, version, msg_len, msg_id)
    def bench_scheme_a():
        return MyProtoInfo(0xAB, 2, 6, 42)

    elapsed, ns = timeit(bench_scheme_a, N)
    print(f"Scheme A (positional args):         {ns:7.0f} ns/call  ({N/elapsed:10,.0f} call/s)")

    # Scheme B: __new__ + assign _fields dict
    def bench_scheme_b():
        obj = MyProtoInfo.__new__(MyProtoInfo)
        obj._fields = {'magic': 0xAB, 'version': 2, 'msg_len': 6, 'msg_id': 42}
        return obj

    elapsed, ns = timeit(bench_scheme_b, N)
    print(f"Scheme B (__new__ + dict literal):  {ns:7.0f} ns/call  ({N/elapsed:10,.0f} call/s)")

    # Scheme C: __new__ + pre-cached keys + dict.fromkeys-style
    cached_cls = MyProtoInfo
    cached_keys = tuple(field_names)  # pre-interned

    def bench_scheme_c():
        obj = cached_cls.__new__(cached_cls)
        obj._fields = dict(zip(cached_keys, (0xAB, 2, 6, 42)))
        return obj

    elapsed, ns = timeit(bench_scheme_c, N)
    print(f"Scheme C (cached cls+keys, zip):    {ns:7.0f} ns/call  ({N/elapsed:10,.0f} call/s)")

    # Baseline: built-in style — direct dict construction (what C++ does for known protocols)
    def bench_builtin_style():
        obj = MyProtoInfo.__new__(MyProtoInfo)
        obj._fields = {'magic': 0xAB, 'version': 2, 'msg_len': 6, 'msg_id': 42}
        return obj

    # This is same as B — the point is C++ would do this with pre-cached py::str keys

    # Extra: raw ProtocolInfo (generic fallback, no subclass)
    def bench_generic():
        return ProtocolInfo(fields={'magic': 0xAB, 'version': 2, 'msg_len': 6, 'msg_id': 42})

    elapsed, ns = timeit(bench_generic, N)
    print(f"Generic ProtocolInfo(fields=dict):  {ns:7.0f} ns/call  ({N/elapsed:10,.0f} call/s)")

    # ═══════════════════════════════════════════════════════════
    # Part 3: Full pcap throughput (if available)
    # ═══════════════════════════════════════════════════════════
    pcap_path = r"D:\Project\Dataset\USTCTFC2016\ustc-tfc2016\Malware\Nsis-ay.pcap"
    if os.path.exists(pcap_path):
        print()
        print("=" * 70)
        print(f"Part 3: Full pcap throughput — {os.path.basename(pcap_path)}")
        print(f"         ({os.path.getsize(pcap_path) / 1024 / 1024:.0f} MB)")
        print("=" * 70)

        # Use NativePipeline for real throughput
        count = 0
        t0 = time.perf_counter()
        with _native.NativePipeline(pcap_path, std_parser, None, False) as pipeline:
            for pkt in pipeline:
                count += 1
        elapsed = time.perf_counter() - t0

        print(f"Packets: {count:,}")
        print(f"Time:    {elapsed:.2f}s")
        print(f"Speed:   {count/elapsed:,.0f} pkt/s  ({os.path.getsize(pcap_path)/1024/1024/elapsed:.0f} MB/s)")

    # Cleanup
    shutil.rmtree(custom_dir, ignore_errors=True)
    registry._registry.pop('myproto', None)


if __name__ == '__main__':
    main()
