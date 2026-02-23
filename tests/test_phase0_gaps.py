"""Phase 0 gap tests: IPv4/IPv6/TCP/UDP native field parsing,
tcp_flags stats, up/down ratios, app_layer_parsing parameter.
"""

from __future__ import annotations

import struct
import socket
import pytest
import numpy as np

# ── Reuse helpers from test_link_layer_protocols ──
from test_link_layer_protocols import (
    build_ipv4, build_ipv6, build_udp, build_eth,
    _get_native_parser, DLT_EN10MB, DLT_RAW,
)

from wa1kpcap.features.extractor import FlowFeatures
from wa1kpcap.core.flow import Flow, FlowKey


# ── TCP helper ──

def build_tcp(sport=12345, dport=80, seq=1000, ack=0, flags=0x02,
              window=65535, payload=b"") -> bytes:
    """Minimal TCP header (20 bytes, data_offset=5) + payload."""
    data_offset_and_reserved = (5 << 4)  # data_offset=5 (20 bytes), reserved=0
    hdr = struct.pack('>HHIIBBHHH',
                      sport, dport,
                      seq, ack,
                      data_offset_and_reserved, flags,
                      window,
                      0,  # checksum
                      0)  # urgent pointer
    return hdr + payload


# ═══════════════════════════════════════════════════════════════════
# IPv4 field parsing (native engine, synthetic bytes)
# ═══════════════════════════════════════════════════════════════════

class TestIPv4FieldParsing:
    """Verify IPv4 header fields are correctly parsed by the native engine."""

    def test_ipv4_basic_fields(self):
        parser = _get_native_parser()
        udp = build_udp(sport=1111, dport=2222)
        ip = build_ipv4(src="10.0.0.1", dst="10.0.0.2", proto=17, payload=udp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.ip is not None
        assert pkt.ip.src == "10.0.0.1"
        assert pkt.ip.dst == "10.0.0.2"
        assert pkt.ip.proto == 17
        assert pkt.ip.ttl == 64
        assert pkt.ip.version == 4

    def test_ipv4_total_length(self):
        parser = _get_native_parser()
        payload = b"\x00" * 100
        udp = build_udp(sport=1000, dport=2000, payload=payload)
        ip = build_ipv4(proto=17, payload=udp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.ip is not None
        expected_len = 20 + 8 + 100  # IP hdr + UDP hdr + payload
        assert pkt.ip.len == expected_len

    def test_ipv4_identification(self):
        parser = _get_native_parser()
        ip = build_ipv4(proto=17, payload=build_udp())
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.ip is not None
        assert pkt.ip.id == 0x1234  # hardcoded in build_ipv4

    def test_ipv4_raw_dlt(self):
        """IPv4 over DLT_RAW (no Ethernet header)."""
        parser = _get_native_parser()
        ip = build_ipv4(src="172.16.0.1", dst="172.16.0.2", proto=17,
                        payload=build_udp())
        pkt = parser.parse_to_dataclass(ip, DLT_RAW)

        assert pkt.eth is None
        assert pkt.ip is not None
        assert pkt.ip.src == "172.16.0.1"
        assert pkt.ip.dst == "172.16.0.2"


# ═══════════════════════════════════════════════════════════════════
# IPv6 field parsing (native engine, synthetic bytes)
# ═══════════════════════════════════════════════════════════════════

class TestIPv6FieldParsing:
    """Verify IPv6 header fields are correctly parsed by the native engine."""

    def test_ipv6_basic_fields(self):
        parser = _get_native_parser()
        udp = build_udp(sport=3333, dport=4444)
        ip6 = build_ipv6(src="2001:db8::1", dst="2001:db8::2",
                         next_header=17, payload=udp)
        raw = build_eth(ethertype=0x86DD) + ip6
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.ip6 is not None
        assert pkt.ip6.src == "2001:db8::1"
        assert pkt.ip6.dst == "2001:db8::2"
        assert pkt.ip6.next_header == 17
        assert pkt.ip6.hop_limit == 64

    def test_ipv6_payload_length(self):
        parser = _get_native_parser()
        payload = b"\x00" * 50
        udp = build_udp(sport=100, dport=200, payload=payload)
        ip6 = build_ipv6(next_header=17, payload=udp)
        raw = build_eth(ethertype=0x86DD) + ip6
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.ip6 is not None
        expected_payload_len = 8 + 50  # UDP hdr + payload
        assert pkt.ip6.len == expected_payload_len

    def test_ipv6_raw_dlt(self):
        """IPv6 over DLT_RAW."""
        parser = _get_native_parser()
        udp = build_udp()
        ip6 = build_ipv6(src="::1", dst="::2", next_header=17, payload=udp)
        pkt = parser.parse_to_dataclass(ip6, DLT_RAW)

        assert pkt.eth is None
        assert pkt.ip6 is not None
        assert pkt.ip6.src == "::1"


# ═══════════════════════════════════════════════════════════════════
# TCP field parsing (native engine, synthetic bytes)
# ═══════════════════════════════════════════════════════════════════

class TestTCPFieldParsing:
    """Verify TCP header fields are correctly parsed by the native engine."""

    def test_tcp_basic_fields(self):
        parser = _get_native_parser()
        tcp = build_tcp(sport=8080, dport=443, seq=100000, ack=200000,
                        flags=0x18, window=32768)
        ip = build_ipv4(proto=6, payload=tcp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.tcp is not None
        assert pkt.tcp.sport == 8080
        assert pkt.tcp.dport == 443
        assert pkt.tcp.seq == 100000
        assert pkt.tcp.ack_num == 200000
        assert pkt.tcp.flags == 0x18
        assert pkt.tcp.win == 32768

    def test_tcp_syn_flag(self):
        parser = _get_native_parser()
        tcp = build_tcp(flags=0x02)  # SYN
        ip = build_ipv4(proto=6, payload=tcp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.tcp is not None
        assert pkt.tcp.syn is True
        assert pkt.tcp.ack is False
        assert pkt.tcp.fin is False

    def test_tcp_synack_flags(self):
        parser = _get_native_parser()
        tcp = build_tcp(flags=0x12)  # SYN+ACK
        ip = build_ipv4(proto=6, payload=tcp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.tcp is not None
        assert pkt.tcp.syn is True
        assert pkt.tcp.ack is True

    def test_tcp_fin_flag(self):
        parser = _get_native_parser()
        tcp = build_tcp(flags=0x11)  # FIN+ACK
        ip = build_ipv4(proto=6, payload=tcp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.tcp is not None
        assert pkt.tcp.fin is True
        assert pkt.tcp.ack is True

    def test_tcp_rst_flag(self):
        parser = _get_native_parser()
        tcp = build_tcp(flags=0x04)  # RST
        ip = build_ipv4(proto=6, payload=tcp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.tcp is not None
        assert pkt.tcp.rst is True

    def test_tcp_with_payload(self):
        parser = _get_native_parser()
        tcp = build_tcp(sport=80, dport=5000, flags=0x18,
                        payload=b"HTTP/1.1 200 OK\r\n")
        ip = build_ipv4(proto=6, payload=tcp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.tcp is not None
        assert pkt.tcp.sport == 80
        assert pkt.tcp.dport == 5000

    def test_tcp_over_ipv6(self):
        parser = _get_native_parser()
        tcp = build_tcp(sport=22, dport=50000, flags=0x02)
        ip6 = build_ipv6(src="fe80::1", dst="fe80::2", next_header=6,
                         payload=tcp)
        raw = build_eth(ethertype=0x86DD) + ip6
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.ip6 is not None
        assert pkt.tcp is not None
        assert pkt.tcp.sport == 22
        assert pkt.tcp.dport == 50000


# ═══════════════════════════════════════════════════════════════════
# UDP field parsing (native engine, synthetic bytes)
# ═══════════════════════════════════════════════════════════════════

class TestUDPFieldParsing:
    """Verify UDP header fields are correctly parsed by the native engine."""

    def test_udp_basic_fields(self):
        parser = _get_native_parser()
        udp = build_udp(sport=5353, dport=5353, payload=b"\x00" * 20)
        ip = build_ipv4(proto=17, payload=udp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.udp is not None
        assert pkt.udp.sport == 5353
        assert pkt.udp.dport == 5353
        assert pkt.udp.len == 28  # 8 + 20

    def test_udp_over_ipv6(self):
        parser = _get_native_parser()
        udp = build_udp(sport=546, dport=547)
        ip6 = build_ipv6(src="fe80::1", dst="ff02::1:2", next_header=17,
                         payload=udp)
        raw = build_eth(ethertype=0x86DD) + ip6
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.ip6 is not None
        assert pkt.udp is not None
        assert pkt.udp.sport == 546
        assert pkt.udp.dport == 547

    def test_udp_empty_payload(self):
        parser = _get_native_parser()
        udp = build_udp(sport=9999, dport=8888)
        ip = build_ipv4(proto=17, payload=udp)
        raw = build_eth(ethertype=0x0800) + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.udp is not None
        assert pkt.udp.sport == 9999
        assert pkt.udp.dport == 8888
        assert pkt.udp.len == 8


# ═══════════════════════════════════════════════════════════════════
# tcp_flags statistics in compute_statistics()
# ═══════════════════════════════════════════════════════════════════

class TestTcpFlagsStatistics:
    """Verify tcp_flags are included in compute_statistics() output."""

    def test_tcp_flags_stats_present(self):
        features = FlowFeatures()
        features.packet_lengths = np.array([100, 200, 300], dtype=np.int32)
        features.tcp_flags = np.array([0x02, 0x12, 0x10], dtype=np.uint8)
        features.timestamps = np.array([0.0, 1.0, 2.0], dtype=np.float64)

        stats = features.compute_statistics()

        assert 'tcp_flags' in stats
        tf = stats['tcp_flags']
        assert tf['count'] == 3
        assert tf['min'] == 0x02
        assert tf['max'] == 0x12

    def test_tcp_flags_stats_empty(self):
        features = FlowFeatures()
        features.packet_lengths = np.array([100], dtype=np.int32)
        features.timestamps = np.array([0.0], dtype=np.float64)
        # tcp_flags left empty

        stats = features.compute_statistics()
        # tcp_flags should not be in stats when empty
        assert 'tcp_flags' not in stats

    def test_tcp_flags_stats_single(self):
        features = FlowFeatures()
        features.packet_lengths = np.array([100], dtype=np.int32)
        features.tcp_flags = np.array([0x18], dtype=np.uint8)
        features.timestamps = np.array([0.0], dtype=np.float64)

        stats = features.compute_statistics()
        assert 'tcp_flags' in stats
        assert stats['tcp_flags']['count'] == 1
        assert stats['tcp_flags']['mean'] == 0x18


# ═══════════════════════════════════════════════════════════════════
# up_down_pkt_ratio / up_down_byte_ratio
# ═══════════════════════════════════════════════════════════════════

class TestUpDownRatios:
    """Verify up/down packet and byte ratios in compute_statistics()."""

    def test_ratios_with_bidirectional(self):
        features = FlowFeatures()
        # Positive = forward (up), negative = reverse (down)
        features.packet_lengths = np.array([100, 200, -150, -250], dtype=np.int32)
        features.timestamps = np.array([0.0, 1.0, 2.0, 3.0], dtype=np.float64)

        stats = features.compute_statistics()

        assert 'up_down_pkt_ratio' in stats
        assert 'up_down_byte_ratio' in stats
        # 2 up packets, 2 down packets → ratio = 1.0
        assert stats['up_down_pkt_ratio'] == 1.0
        # up bytes = 100+200=300, down bytes = 150+250=400 → ratio = 0.75
        assert stats['up_down_byte_ratio'] == 0.75

    def test_ratios_all_forward(self):
        features = FlowFeatures()
        features.packet_lengths = np.array([100, 200, 300], dtype=np.int32)
        features.timestamps = np.array([0.0, 1.0, 2.0], dtype=np.float64)

        stats = features.compute_statistics()

        # No down packets → ratio = 0.0
        assert stats['up_down_pkt_ratio'] == 0.0
        assert stats['up_down_byte_ratio'] == 0.0

    def test_ratios_empty(self):
        features = FlowFeatures()
        stats = features.compute_statistics()

        assert stats['up_down_pkt_ratio'] == 0.0
        assert stats['up_down_byte_ratio'] == 0.0


# ═══════════════════════════════════════════════════════════════════
# app_layer_parsing parameter
# ═══════════════════════════════════════════════════════════════════

class TestAppLayerParsing:
    """Verify app_layer_parsing parameter is accepted and validated."""

    def test_valid_modes(self):
        from wa1kpcap import Wa1kPcap
        for mode in ("full", "port_only", "none"):
            analyzer = Wa1kPcap(engine="native", app_layer_parsing=mode)
            assert analyzer.app_layer_parsing == mode

    def test_invalid_mode_raises(self):
        from wa1kpcap import Wa1kPcap
        with pytest.raises(ValueError, match="Invalid app_layer_parsing"):
            Wa1kPcap(engine="native", app_layer_parsing="invalid")

    def test_mode_none_skips_app_layer(self):
        """With mode='none', DNS on port 53 should not be parsed."""
        parser = _get_native_parser()
        # Build a DNS-like packet on port 53
        dns_payload = b"\x00" * 20  # dummy
        udp = build_udp(sport=1234, dport=53, payload=dns_payload)
        ip = build_ipv4(proto=17, payload=udp)
        raw = build_eth(ethertype=0x0800) + ip

        # app_layer_mode=2 (none) should skip DNS parsing
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB, app_layer_mode=2)
        assert pkt.udp is not None
        assert pkt.udp.dport == 53
        # DNS should not be parsed
        assert pkt.dns is None

    def test_mode_full_parses_dns(self):
        """With mode='full' (0), DNS on port 53 should be parsed."""
        parser = _get_native_parser()
        # Build a minimal valid DNS query
        # Header: ID=0x1234, flags=0x0100 (standard query), qdcount=1
        dns_hdr = struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
        # Query: example.com, type A, class IN
        qname = b"\x07example\x03com\x00"
        query = qname + struct.pack('>HH', 1, 1)  # type=A, class=IN
        dns_payload = dns_hdr + query

        udp = build_udp(sport=1234, dport=53, payload=dns_payload)
        ip = build_ipv4(proto=17, payload=udp)
        raw = build_eth(ethertype=0x0800) + ip

        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB, app_layer_mode=0)
        assert pkt.udp is not None
        assert pkt.dns is not None
        assert pkt.dns.queries, "DNS queries field should not be empty"
        assert 'example.com' in pkt.dns.queries[0], (
            f"expected 'example.com' in queries, got {pkt.dns.queries}"
        )
