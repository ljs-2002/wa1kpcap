"""
Tests for the native C++ engine.

Tests cover:
- NativePcapReader (pcap/pcapng reading)
- NativeParser (protocol parsing via YAML + 8 primitives)
- NativeFilter (BPF filtering on parsed dicts)
- Converter (dict → ParsedPacket)
- Integration: Wa1kPcap(engine="native") vs Wa1kPcap(engine="dpkt")
"""

from __future__ import annotations

import struct
import pytest
from pathlib import Path

# ── Helpers ──

TEST_DIR = Path(__file__).parent.parent / "test"


def build_pcap_bytes(packets: list[tuple[float, bytes]], link_type: int = 1) -> bytes:
    """Build a minimal pcap file in memory.

    Args:
        packets: List of (timestamp, raw_bytes) tuples
        link_type: DLT link type (default: Ethernet)

    Returns:
        Complete pcap file as bytes
    """
    # Global header: magic, version 2.4, thiszone=0, sigfigs=0, snaplen=65535, network=link_type
    header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type)
    body = b''
    for ts, data in packets:
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1e6)
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        body += pkt_header + data
    return header + body


def build_ethernet_ipv4_tcp_packet(
    src_mac: str = "aa:bb:cc:dd:ee:01",
    dst_mac: str = "aa:bb:cc:dd:ee:02",
    src_ip: str = "192.168.1.1",
    dst_ip: str = "192.168.1.2",
    src_port: int = 12345,
    dst_port: int = 443,
    flags: int = 0x02,  # SYN
    seq: int = 1000,
    payload: bytes = b"",
) -> bytes:
    """Build a raw Ethernet/IPv4/TCP packet."""
    # Ethernet header
    dst_bytes = bytes(int(x, 16) for x in dst_mac.split(':'))
    src_bytes = bytes(int(x, 16) for x in src_mac.split(':'))
    eth = dst_bytes + src_bytes + struct.pack('>H', 0x0800)

    # IPv4 header (20 bytes, no options)
    tcp_len = 20 + len(payload)
    ip_total = 20 + tcp_len
    ip_parts = [int(x) for x in src_ip.split('.')]
    src_ip_bytes = bytes(ip_parts)
    ip_parts = [int(x) for x in dst_ip.split('.')]
    dst_ip_bytes = bytes(ip_parts)

    ip = struct.pack('>BBHHHBBH4s4s',
                     0x45,       # version=4, ihl=5
                     0,          # DSCP/ECN
                     ip_total,   # total length
                     0x1234,     # identification
                     0x4000,     # flags=DF, offset=0
                     64,         # TTL
                     6,          # protocol=TCP
                     0,          # checksum (0 = skip)
                     src_ip_bytes,
                     dst_ip_bytes)

    # TCP header (20 bytes, no options)
    tcp = struct.pack('>HHIIBBHHH',
                      src_port,
                      dst_port,
                      seq,
                      0,          # ack
                      0x50,       # data offset = 5 (20 bytes)
                      flags,
                      65535,      # window
                      0,          # checksum
                      0)          # urgent pointer

    return eth + ip + tcp + payload


# ── Test: NATIVE_AVAILABLE detection ──

class TestNativeAvailability:
    """Test that the native module detection works."""

    def test_native_import_does_not_crash(self):
        """Importing wa1kpcap.native should never raise."""
        from wa1kpcap.native import NATIVE_AVAILABLE
        # NATIVE_AVAILABLE is True if C++ module is compiled, False otherwise
        assert isinstance(NATIVE_AVAILABLE, bool)


# ── Test: Converter ──

class TestConverter:
    """Test dict_to_parsed_packet conversion."""

    def test_empty_dict(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet
        pkt = dict_to_parsed_packet({}, 1.0, b'\x00' * 14, 1)
        assert pkt.timestamp == 1.0
        assert pkt.eth is None
        assert pkt.ip is None
        assert pkt.tcp is None

    def test_ethernet_ipv4_tcp(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet

        d = {
            "ethernet": {"src": "aa:bb:cc:dd:ee:01", "dst": "aa:bb:cc:dd:ee:02", "ether_type": 0x0800},
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 60,
                "identification": 0x1234, "df": 1, "mf": 0, "fragment_offset": 0,
                "ttl": 64, "protocol": 6,
                "src": "192.168.1.1", "dst": "192.168.1.2",
            },
            "tcp": {
                "src_port": 12345, "dst_port": 443,
                "seq": 1000, "ack_num": 0,
                "data_offset": 5, "flags": 2,
                "window": 65535, "urgent_pointer": 0,
                "header_length": 20,
            },
            "app_len": 0,
        }

        pkt = dict_to_parsed_packet(d, 1000.0, b'\x00' * 54, 1)

        assert pkt.eth is not None
        assert pkt.eth.src == "aa:bb:cc:dd:ee:01"
        assert pkt.eth.type == 0x0800

        assert pkt.ip is not None
        assert pkt.ip.src == "192.168.1.1"
        assert pkt.ip.dst == "192.168.1.2"
        assert pkt.ip.proto == 6
        assert pkt.ip.ttl == 64

        assert pkt.tcp is not None
        assert pkt.tcp.sport == 12345
        assert pkt.tcp.dport == 443
        assert pkt.tcp.seq == 1000
        assert pkt.tcp.flags == 2
        assert pkt.tcp.syn is True

    def test_ipv6_udp(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet

        d = {
            "ipv6": {
                "version": 6, "next_header": 17, "hop_limit": 64,
                "flow_label": 0, "payload_length": 20,
                "src": "::1", "dst": "::2",
            },
            "udp": {
                "src_port": 53, "dst_port": 1234, "length": 20,
            },
            "app_len": 12,
        }

        pkt = dict_to_parsed_packet(d, 2000.0, b'\x00' * 60, 101)

        assert pkt.ip6 is not None
        assert pkt.ip6.src == "::1"
        assert pkt.ip6.next_header == 17

        assert pkt.udp is not None
        assert pkt.udp.sport == 53
        assert pkt.udp.dport == 1234

    def test_tls_info(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet

        d = {
            "tls_record": {
                "content_type": 22, "version_major": 3, "version_minor": 3,
                "record_length": 100,
            },
            "tls_handshake": {"handshake_type": 1, "handshake_length": 96},
            "tls_client_hello": {
                "cipher_suites": [0x1301, 0x1302, 0xc02c],
            },
        }

        pkt = dict_to_parsed_packet(d, 3000.0, b'\x00' * 100, 1)

        assert pkt.tls is not None
        assert pkt.tls.version == "3.3"
        assert pkt.tls.content_type == 22
        assert pkt.tls.handshake_type == 1
        assert pkt.tls.cipher_suites == [0x1301, 0x1302, 0xc02c]

    def test_dns_info(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet

        d = {
            "dns": {
                "flags": 0x8180, "question_count": 1, "answer_count": 1,
                "authority_count": 0, "additional_count": 0,
                "response_code": 0,
            },
        }

        pkt = dict_to_parsed_packet(d, 4000.0, b'\x00' * 50, 1)

        assert pkt.dns is not None
        assert pkt.dns.question_count == 1
        assert pkt.dns.answer_count == 1
        assert pkt.dns.is_response is True

    def test_ip_fragment_flags(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet

        d = {
            "ipv4": {
                "version": 4, "ihl": 5, "total_length": 1500,
                "identification": 0xABCD, "df": 0, "mf": 1, "fragment_offset": 0,
                "ttl": 64, "protocol": 6,
                "src": "10.0.0.1", "dst": "10.0.0.2",
            },
        }

        pkt = dict_to_parsed_packet(d, 5000.0, b'\x00' * 100, 1)

        assert pkt.ip is not None
        assert pkt.ip.is_fragment is True
        assert pkt.ip.more_fragments is True
        assert pkt.ip.offset == 0


# ── Test: Engine parameter in Wa1kPcap ──

class TestEngineParameter:
    """Test that the engine parameter is accepted."""

    def test_native_engine_default(self):
        from wa1kpcap import Wa1kPcap
        analyzer = Wa1kPcap()
        assert analyzer._engine == "native"

    def test_dpkt_engine_explicit(self):
        from wa1kpcap import Wa1kPcap
        analyzer = Wa1kPcap(engine="dpkt")
        assert analyzer._engine == "dpkt"

    def test_native_engine_raises_if_unavailable(self):
        from wa1kpcap.native import NATIVE_AVAILABLE
        if NATIVE_AVAILABLE:
            pytest.skip("Native engine is available, can't test unavailability")

        from wa1kpcap import Wa1kPcap
        with pytest.raises(RuntimeError, match="Native C\\+\\+ engine not available"):
            Wa1kPcap(engine="native")


# ── Test: dpkt path still works (regression) ──

class TestDpktRegression:
    """Ensure the dpkt path is completely unaffected by native engine changes."""

    def test_analyze_file_dpkt(self):
        """Basic dpkt analysis should still work."""
        pcap_file = TEST_DIR / "single.pcap"
        if not pcap_file.exists():
            pytest.skip("Test pcap not found")

        from wa1kpcap import Wa1kPcap
        analyzer = Wa1kPcap(engine="dpkt")
        flows = analyzer.analyze_file(pcap_file)
        assert isinstance(flows, list)

    def test_analyze_with_bpf_filter_dpkt(self):
        """BPF filter should still work with dpkt engine."""
        pcap_file = TEST_DIR / "single.pcap"
        if not pcap_file.exists():
            pytest.skip("Test pcap not found")

        from wa1kpcap import Wa1kPcap
        analyzer = Wa1kPcap(engine="dpkt", bpf_filter="tcp or udp")
        flows = analyzer.analyze_file(pcap_file)
        assert isinstance(flows, list)


# ── Test: Native engine integration (only if compiled) ──

class TestNativeIntegration:
    """Integration tests that only run if the native C++ module is compiled."""

    @pytest.fixture(autouse=True)
    def skip_if_no_native(self):
        from wa1kpcap.native import NATIVE_AVAILABLE
        if not NATIVE_AVAILABLE:
            pytest.skip("Native C++ engine not compiled")

    def test_native_pcap_reader(self):
        """Test NativePcapReader can read a pcap file."""
        pcap_file = TEST_DIR / "single.pcap"
        if not pcap_file.exists():
            pytest.skip("Test pcap not found")

        from wa1kpcap.native import _wa1kpcap_native as native
        reader = native.NativePcapReader(str(pcap_file))
        packets = []
        with reader:
            for ts, data, caplen, wirelen, lt in reader:
                packets.append((ts, data, caplen, wirelen, lt))

        assert len(packets) > 0
        assert all(isinstance(ts, float) for ts, *_ in packets)

    def test_native_parser(self):
        """Test NativeParser can parse a packet."""
        from wa1kpcap.native import _wa1kpcap_native as native

        protocols_dir = str(Path(__file__).parent.parent / "wa1kpcap" / "native" / "protocols")
        parser = native.NativeParser(protocols_dir)

        # Build a simple Ethernet/IPv4/TCP packet
        raw = build_ethernet_ipv4_tcp_packet()
        result = parser.parse_packet(raw, 1)  # DLT_EN10MB = 1

        assert isinstance(result, dict)
        assert "ethernet" in result or "ipv4" in result

    def test_native_filter(self):
        """Test NativeFilter matches correctly."""
        from wa1kpcap.native import _wa1kpcap_native as native

        f = native.NativeFilter("tcp and port 443")

        # Should match a dict with TCP port 443
        d = {
            "ipv4": {"protocol": 6, "src": "1.2.3.4", "dst": "5.6.7.8"},
            "tcp": {"src_port": 12345, "dst_port": 443},
        }
        assert f.matches(d) is True

        # Should not match UDP
        d2 = {
            "ipv4": {"protocol": 17, "src": "1.2.3.4", "dst": "5.6.7.8"},
            "udp": {"src_port": 12345, "dst_port": 80},
        }
        assert f.matches(d2) is False

    def test_native_analyze_file(self):
        """Test Wa1kPcap(engine='native') produces flows."""
        pcap_file = TEST_DIR / "single.pcap"
        if not pcap_file.exists():
            pytest.skip("Test pcap not found")

        from wa1kpcap import Wa1kPcap
        analyzer = Wa1kPcap(engine="native")
        flows = analyzer.analyze_file(pcap_file)
        assert isinstance(flows, list)
        assert len(flows) > 0

    def test_native_vs_dpkt_flow_count(self):
        """Native and dpkt engines should produce the same number of flows."""
        pcap_file = TEST_DIR / "single.pcap"
        if not pcap_file.exists():
            pytest.skip("Test pcap not found")

        from wa1kpcap import Wa1kPcap

        dpkt_flows = Wa1kPcap(engine="dpkt").analyze_file(pcap_file)
        native_flows = Wa1kPcap(engine="native").analyze_file(pcap_file)

        assert len(native_flows) == len(dpkt_flows), (
            f"Flow count mismatch: native={len(native_flows)}, dpkt={len(dpkt_flows)}"
        )

    def test_native_vs_dpkt_five_tuples(self):
        """Native and dpkt engines should produce the same 5-tuples."""
        pcap_file = TEST_DIR / "single.pcap"
        if not pcap_file.exists():
            pytest.skip("Test pcap not found")

        from wa1kpcap import Wa1kPcap

        dpkt_flows = Wa1kPcap(engine="dpkt").analyze_file(pcap_file)
        native_flows = Wa1kPcap(engine="native").analyze_file(pcap_file)

        dpkt_keys = {str(f.key) for f in dpkt_flows}
        native_keys = {str(f.key) for f in native_flows}

        assert native_keys == dpkt_keys, (
            f"5-tuple mismatch:\n  native-only: {native_keys - dpkt_keys}\n"
            f"  dpkt-only: {dpkt_keys - native_keys}"
        )

    def test_flow_buffer(self):
        """Test FlowBuffer append and available."""
        from wa1kpcap.native import _wa1kpcap_native as native

        buf = native.FlowBuffer()
        assert buf.available() == 0

        buf.append(b'\x16\x03\x03\x00\x05hello')
        assert buf.available() == 10

        buf.clear()
        assert buf.available() == 0

    def test_native_with_bpf_filter(self):
        """Test native engine with BPF filter."""
        pcap_file = TEST_DIR / "single.pcap"
        if not pcap_file.exists():
            pytest.skip("Test pcap not found")

        from wa1kpcap import Wa1kPcap
        analyzer = Wa1kPcap(engine="native", bpf_filter="tcp or udp")
        flows = analyzer.analyze_file(pcap_file)
        assert isinstance(flows, list)


# ── TLS packet building helpers ──

def build_tls_extension(ext_type: int, ext_data: bytes) -> bytes:
    """Build a single TLS extension: [2B type][2B length][data]."""
    return struct.pack('>HH', ext_type, len(ext_data)) + ext_data


def build_sni_extension(hostname: str) -> bytes:
    """Build SNI extension (type 0x0000)."""
    name_bytes = hostname.encode('ascii')
    # server_name_list: [2B list_len][1B name_type=0][2B name_len][name]
    sni_data = struct.pack('>HBH', len(name_bytes) + 3, 0, len(name_bytes)) + name_bytes
    return build_tls_extension(0x0000, sni_data)


def build_supported_groups_extension(groups: list[int]) -> bytes:
    """Build supported_groups extension (type 0x000A)."""
    groups_data = struct.pack('>H', len(groups) * 2)
    for g in groups:
        groups_data += struct.pack('>H', g)
    return build_tls_extension(0x000A, groups_data)


def build_signature_algorithms_extension(algorithms: list[int]) -> bytes:
    """Build signature_algorithms extension (type 0x000D)."""
    alg_data = struct.pack('>H', len(algorithms) * 2)
    for a in algorithms:
        alg_data += struct.pack('>H', a)
    return build_tls_extension(0x000D, alg_data)


def build_alpn_extension(protocols: list[str]) -> bytes:
    """Build ALPN extension (type 0x0010)."""
    proto_data = b''
    for p in protocols:
        pb = p.encode('ascii')
        proto_data += struct.pack('B', len(pb)) + pb
    alpn_data = struct.pack('>H', len(proto_data)) + proto_data
    return build_tls_extension(0x0010, alpn_data)


def build_tls_client_hello_record(
    cipher_suites: list[int],
    extensions_bytes: bytes,
    version: tuple[int, int] = (3, 3),
) -> bytes:
    """Build a complete TLS record containing a ClientHello handshake."""
    # ClientHello body
    body = struct.pack('BB', version[0], version[1])  # client_version
    body += b'\x00' * 32  # random
    body += b'\x00'  # session_id length = 0
    # cipher_suites
    body += struct.pack('>H', len(cipher_suites) * 2)
    for cs in cipher_suites:
        body += struct.pack('>H', cs)
    body += b'\x01\x00'  # compression_methods: 1 method, null
    # extensions total length + extensions
    body += struct.pack('>H', len(extensions_bytes)) + extensions_bytes

    # Handshake header: type=1 (ClientHello), 3B length
    hs = struct.pack('B', 1) + struct.pack('>I', len(body))[1:]  # 3-byte length
    hs += body

    # TLS record header: content_type=22, version=0x0301, 2B length
    record = struct.pack('BBB', 22, 3, 1) + struct.pack('>H', len(hs)) + hs
    return record


def build_tls_server_hello_record(
    cipher_suite: int,
    extensions_bytes: bytes,
    version: tuple[int, int] = (3, 3),
) -> bytes:
    """Build a complete TLS record containing a ServerHello handshake."""
    # ServerHello body
    body = struct.pack('BB', version[0], version[1])  # server_version
    body += b'\x00' * 32  # random
    body += b'\x00'  # session_id length = 0
    body += struct.pack('>H', cipher_suite)
    body += b'\x00'  # compression_method = null
    # extensions total length + extensions
    body += struct.pack('>H', len(extensions_bytes)) + extensions_bytes

    # Handshake header: type=2 (ServerHello), 3B length
    hs = struct.pack('B', 2) + struct.pack('>I', len(body))[1:]
    hs += body

    # TLS record header
    record = struct.pack('BBB', 22, 3, 3) + struct.pack('>H', len(hs)) + hs
    return record


# ── Test: Native TLS field parsing ──

class TestNativeTLSParsing:
    """Test that the native C++ engine correctly parses TLS extension fields
    from crafted binary packets via the ext_list primitive and parse_tls_record."""

    @pytest.fixture(autouse=True)
    def skip_if_no_native(self):
        from wa1kpcap.native import NATIVE_AVAILABLE
        if not NATIVE_AVAILABLE:
            pytest.skip("Native C++ engine not compiled")

    @pytest.fixture
    def parser(self):
        from wa1kpcap.native import _wa1kpcap_native as native
        protocols_dir = str(Path(__file__).parent.parent / "wa1kpcap" / "native" / "protocols")
        return native.NativeParser(protocols_dir)

    # ── parse_tls_record: ClientHello with all 4 extensions ──

    def test_parse_tls_record_client_hello_sni(self, parser):
        """parse_tls_record extracts SNI from a ClientHello."""
        exts = build_sni_extension("example.com")
        record = build_tls_client_hello_record([0x1301], exts)
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.sni == "example.com"

    def test_parse_tls_record_client_hello_cipher_suites(self, parser):
        """parse_tls_record extracts cipher_suites from a ClientHello."""
        record = build_tls_client_hello_record([0x1301, 0x1302, 0xc02c], b'')
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.cipher_suites == [0x1301, 0x1302, 0xc02c]
        assert pkt.tls.handshake_type == 1

    def test_parse_tls_record_client_hello_supported_groups(self, parser):
        """parse_tls_record extracts supported_groups from a ClientHello."""
        exts = build_supported_groups_extension([0x0017, 0x0018, 0x0019])
        record = build_tls_client_hello_record([0x1301], exts)
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.supported_groups == [0x0017, 0x0018, 0x0019]

    def test_parse_tls_record_client_hello_signature_algorithms(self, parser):
        """parse_tls_record extracts signature_algorithms from a ClientHello."""
        exts = build_signature_algorithms_extension([0x0401, 0x0501, 0x0601])
        record = build_tls_client_hello_record([0x1301], exts)
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.signature_algorithms == [0x0401, 0x0501, 0x0601]

    def test_parse_tls_record_client_hello_alpn(self, parser):
        """parse_tls_record extracts ALPN protocols from a ClientHello."""
        exts = build_alpn_extension(["h2", "http/1.1"])
        record = build_tls_client_hello_record([0x1301], exts)
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.alpn == ["h2", "http/1.1"]

    def test_parse_tls_record_client_hello_all_extensions(self, parser):
        """parse_tls_record extracts all 4 extension types from a single ClientHello."""
        exts = (
            build_sni_extension("all-exts.example.org")
            + build_supported_groups_extension([0x001d, 0x0017])
            + build_signature_algorithms_extension([0x0804, 0x0401])
            + build_alpn_extension(["h2"])
        )
        record = build_tls_client_hello_record([0xc02c, 0xc02b], exts)
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.handshake_type == 1
        assert pkt.tls.sni == "all-exts.example.org"
        assert pkt.tls.cipher_suites == [0xc02c, 0xc02b]
        assert pkt.tls.supported_groups == [0x001d, 0x0017]
        assert pkt.tls.signature_algorithms == [0x0804, 0x0401]
        assert pkt.tls.alpn == ["h2"]

    # ── parse_tls_record: ServerHello ──

    def test_parse_tls_record_server_hello_cipher_suite(self, parser):
        """parse_tls_record extracts selected cipher_suite from a ServerHello."""
        record = build_tls_server_hello_record(0xc02c, b'')
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.handshake_type == 2
        assert pkt.tls.cipher_suite == 0xc02c

    def test_parse_tls_record_server_hello_alpn(self, parser):
        """parse_tls_record extracts ALPN from a ServerHello."""
        exts = build_alpn_extension(["h2"])
        record = build_tls_server_hello_record(0x1301, exts)
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.alpn == ["h2"]

    # ── parse_tls_record: TLS version and record_length ──

    def test_parse_tls_record_version(self, parser):
        """parse_tls_record extracts TLS record version."""
        record = build_tls_client_hello_record([0x1301], b'')
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.version == "3.1"  # record header version
        assert pkt.tls.content_type == 22

    def test_parse_tls_record_record_length(self, parser):
        """parse_tls_record extracts record_length."""
        record = build_tls_client_hello_record([0x1301], b'')
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.record_length == len(record) - 5

    # ── parse_tls_record: edge cases ──

    def test_parse_tls_record_unknown_extensions_skipped(self, parser):
        """Unknown extension types are silently skipped."""
        unknown_ext = build_tls_extension(0xFFFF, b'\xde\xad\xbe\xef')
        sni_ext = build_sni_extension("known.example.com")
        exts = unknown_ext + sni_ext
        record = build_tls_client_hello_record([0x1301], exts)
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.sni == "known.example.com"

    def test_parse_tls_record_empty_extensions(self, parser):
        """ClientHello with zero extensions still parses cipher_suites."""
        record = build_tls_client_hello_record([0x1301, 0x1302], b'')
        pkt = parser.parse_tls_record(record)

        assert pkt.tls is not None
        assert pkt.tls.cipher_suites == [0x1301, 0x1302]
        assert pkt.tls.sni == ""
        assert pkt.tls.alpn == []
        assert pkt.tls.supported_groups == []
        assert pkt.tls.signature_algorithms == []

    def test_parse_tls_record_non_handshake(self, parser):
        """A non-handshake TLS record (application_data) has no handshake fields."""
        app_data = b'\x17\x03\x03\x00\x05hello'
        pkt = parser.parse_tls_record(app_data)

        assert pkt.tls is not None
        assert pkt.tls.content_type == 23
        assert pkt.tls.handshake_type == -1

    # ── Full packet path: TCP payload captured, then parsed via parse_tls_record ──

    def test_full_packet_captures_tls_payload(self, parser):
        """parse_to_dataclass captures raw TCP payload containing TLS data."""
        exts = (
            build_sni_extension("dataclass.example.com")
            + build_alpn_extension(["h2", "http/1.1"])
        )
        tls_record = build_tls_client_hello_record([0xc02c, 0xc02b, 0x1301], exts)
        raw = build_ethernet_ipv4_tcp_packet(
            src_port=54321, dst_port=443,
            flags=0x18, seq=100, payload=tls_record,
        )

        pkt = parser.parse_to_dataclass(raw, 1, False, 1000.0, len(raw), len(raw))

        assert pkt.tcp is not None
        assert pkt.tcp.sport == 54321
        assert pkt.tcp.dport == 443
        # TCP payload should contain the TLS record bytes
        assert pkt.has_payload
        assert bytes(pkt.payload) == tls_record

    def test_full_packet_payload_round_trip_via_parse_tls_record(self, parser):
        """TCP payload from parse_to_dataclass can be fed to parse_tls_record."""
        exts = build_sni_extension("roundtrip.example.com") + build_alpn_extension(["h2"])
        tls_record = build_tls_client_hello_record([0x1301], exts)
        raw = build_ethernet_ipv4_tcp_packet(
            src_port=54321, dst_port=443,
            flags=0x18, seq=100, payload=tls_record,
        )

        pkt = parser.parse_to_dataclass(raw, 1, False, 1000.0, len(raw), len(raw))
        # Now parse the captured payload as a TLS record
        tls_pkt = parser.parse_tls_record(bytes(pkt.payload))

        assert tls_pkt.tls is not None
        assert tls_pkt.tls.sni == "roundtrip.example.com"
        assert tls_pkt.tls.alpn == ["h2"]
        assert tls_pkt.tls.cipher_suites == [0x1301]

    # ── Native TLS reassembly via analyzer ──

    def test_native_tls_reassembly_single_record(self):
        """Native analyzer reassembles a single TLS record and populates packet TLS info."""
        import tempfile, os
        from wa1kpcap import Wa1kPcap

        exts = (
            build_sni_extension("reassembly.example.com")
            + build_alpn_extension(["h2"])
            + build_supported_groups_extension([0x001d])
            + build_signature_algorithms_extension([0x0804])
        )
        tls_record = build_tls_client_hello_record([0xc02c], exts)

        syn = build_ethernet_ipv4_tcp_packet(
            src_port=50000, dst_port=443, flags=0x02, seq=0)
        syn_ack = build_ethernet_ipv4_tcp_packet(
            src_ip="192.168.1.2", dst_ip="192.168.1.1",
            src_port=443, dst_port=50000, flags=0x12, seq=0)
        ack_pkt = build_ethernet_ipv4_tcp_packet(
            src_port=50000, dst_port=443, flags=0x10, seq=1)
        ch = build_ethernet_ipv4_tcp_packet(
            src_port=50000, dst_port=443, flags=0x18, seq=1,
            payload=tls_record)

        pcap_data = build_pcap_bytes([
            (1.0, syn), (1.001, syn_ack), (1.002, ack_pkt), (1.003, ch),
        ])

        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(pcap_data)
            tmp_path = f.name

        try:
            analyzer = Wa1kPcap(engine="native")
            flows = analyzer.analyze_file(tmp_path)
            assert len(flows) >= 1

            tls_pkt = None
            for flow in flows:
                for p in flow.packets:
                    if p.tls is not None:
                        tls_pkt = p
                        break
                if tls_pkt:
                    break

            assert tls_pkt is not None, "Should have a packet with TLS info"

            info = tls_pkt.tls
            assert info.handshake_type == 1
            sni_val = info.sni
            if isinstance(sni_val, list):
                assert "reassembly.example.com" in sni_val
            else:
                assert sni_val == "reassembly.example.com"
            assert info.alpn == ["h2"]
            assert info.supported_groups == [0x001d]
            assert info.signature_algorithms == [0x0804]
        finally:
            os.unlink(tmp_path)

    def test_native_tls_reassembly_fragmented_record(self):
        """Native analyzer reassembles a TLS record split across two TCP segments."""
        import tempfile, os
        from wa1kpcap import Wa1kPcap

        exts = build_sni_extension("fragmented.example.com")
        tls_record = build_tls_client_hello_record([0x1301], exts)

        mid = len(tls_record) // 2
        frag1 = tls_record[:mid]
        frag2 = tls_record[mid:]

        syn = build_ethernet_ipv4_tcp_packet(
            src_port=50001, dst_port=443, flags=0x02, seq=0)
        syn_ack = build_ethernet_ipv4_tcp_packet(
            src_ip="192.168.1.2", dst_ip="192.168.1.1",
            src_port=443, dst_port=50001, flags=0x12, seq=0)
        ack_pkt = build_ethernet_ipv4_tcp_packet(
            src_port=50001, dst_port=443, flags=0x10, seq=1)
        pkt1 = build_ethernet_ipv4_tcp_packet(
            src_port=50001, dst_port=443, flags=0x18, seq=1,
            payload=frag1)
        pkt2 = build_ethernet_ipv4_tcp_packet(
            src_port=50001, dst_port=443, flags=0x18, seq=1 + len(frag1),
            payload=frag2)

        pcap_data = build_pcap_bytes([
            (1.0, syn), (1.001, syn_ack), (1.002, ack_pkt),
            (1.003, pkt1), (1.004, pkt2),
        ])

        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            f.write(pcap_data)
            tmp_path = f.name

        try:
            analyzer = Wa1kPcap(engine="native")
            flows = analyzer.analyze_file(tmp_path)

            found_sni = False
            for flow in flows:
                for p in flow.packets:
                    if p.tls is not None:
                        sni_val = p.tls.sni
                        if isinstance(sni_val, list) and "fragmented.example.com" in sni_val:
                            found_sni = True
                        elif sni_val == "fragmented.example.com":
                            found_sni = True

            assert found_sni, "Fragmented TLS record should be reassembled and SNI extracted"
        finally:
            os.unlink(tmp_path)

    # ── NativeEngine.parse_tls_record Python wrapper ──

    def test_native_engine_parse_tls_record_wrapper(self):
        """NativeEngine.parse_tls_record returns a struct with TLS info."""
        from wa1kpcap.native.engine import NativeEngine

        engine = NativeEngine()
        exts = build_sni_extension("wrapper.example.com") + build_alpn_extension(["h2"])
        record = build_tls_client_hello_record([0x1301], exts)

        result = engine.parse_tls_record(record)
        assert result is not None
        assert result.tls.sni == "wrapper.example.com"
        assert result.tls.alpn == ["h2"]

    def test_native_engine_parse_tls_record_invalid_data(self):
        """NativeEngine.parse_tls_record returns None for empty data."""
        from wa1kpcap.native.engine import NativeEngine

        engine = NativeEngine()
        # Empty data is too short to parse any tls_record fields
        result = engine.parse_tls_record(b'')
        assert result is None


class TestPayloadHeuristics:
    """Test YAML-configured payload heuristic protocol detection."""

    @pytest.fixture(autouse=True)
    def skip_if_no_native(self):
        from wa1kpcap.native import NATIVE_AVAILABLE
        if not NATIVE_AVAILABLE:
            pytest.skip("Native C++ engine not compiled")

    @pytest.fixture
    def parser(self):
        from wa1kpcap.native import _wa1kpcap_native as native
        protocols_dir = str(Path(__file__).parent.parent / "wa1kpcap" / "native" / "protocols")
        return native.NativeParser(protocols_dir)

    def test_tls_heuristic_on_nonstandard_port(self, parser):
        """TLS ClientHello on non-standard port 8443 should be identified via heuristics."""
        tls_record = build_tls_client_hello_record([0x1301], build_sni_extension("heuristic.example.com"))
        raw = build_ethernet_ipv4_tcp_packet(
            src_port=54321, dst_port=8443,
            flags=0x18, seq=100, payload=tls_record,
        )
        pkt = parser.parse_to_dataclass(raw, 1, False, 1000.0, len(raw), len(raw))

        assert pkt.tls is not None
        assert pkt.tls.content_type == 22
        assert pkt.tls.sni == ["heuristic.example.com"]

    def test_tls_heuristic_application_data(self, parser):
        """TLS application data (content_type=23) should match heuristic."""
        # Build a TLS application data record: type=23, version=3.3, length=5, payload="hello"
        tls_app_data = struct.pack('BBB', 23, 3, 3) + struct.pack('>H', 5) + b'hello'
        raw = build_ethernet_ipv4_tcp_packet(
            src_port=54321, dst_port=9999,
            flags=0x18, seq=100, payload=tls_app_data,
        )
        pkt = parser.parse_to_dataclass(raw, 1, False, 1000.0, len(raw), len(raw))

        assert pkt.tls is not None
        assert pkt.tls.content_type == 23

    def test_heuristic_no_match_random_payload(self, parser):
        """Random payload should not trigger any heuristic."""
        random_payload = bytes([0xFF, 0x00, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56])
        raw = build_ethernet_ipv4_tcp_packet(
            src_port=54321, dst_port=9999,
            flags=0x18, seq=100, payload=random_payload,
        )
        pkt = parser.parse_to_dataclass(raw, 1, False, 1000.0, len(raw), len(raw))

        assert pkt.tls is None

    def test_heuristic_min_length_too_short(self, parser):
        """Payload shorter than min_length should not match."""
        # 4 bytes is less than min_length=5 for TLS heuristic
        short_payload = bytes([0x16, 0x03, 0x01, 0x00])
        raw = build_ethernet_ipv4_tcp_packet(
            src_port=54321, dst_port=9999,
            flags=0x18, seq=100, payload=short_payload,
        )
        pkt = parser.parse_to_dataclass(raw, 1, False, 1000.0, len(raw), len(raw))

        assert pkt.tls is None

    def test_empty_payload_no_crash(self, parser):
        """Empty TCP payload should not crash heuristic evaluation."""
        raw = build_ethernet_ipv4_tcp_packet(
            src_port=54321, dst_port=9999,
            flags=0x02, seq=100, payload=b"",
        )
        pkt = parser.parse_to_dataclass(raw, 1, False, 1000.0, len(raw), len(raw))

        assert pkt.tls is None
