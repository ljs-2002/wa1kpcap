"""Tests for ARP, ICMP, and ICMPv6 protocol support.

Covers:
- Python Info class construction and properties
- Native C++ fast-path parsing (struct path)
- Dict-path converter
- End-to-end: raw packet bytes → ParsedPacket with correct fields
"""

from __future__ import annotations

import struct
import socket
import pytest


# ── Helpers: raw packet builders ──

def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(':'))


def _ip4_bytes(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET, ip)


def _ip6_bytes(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip)


def build_eth(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02", ethertype=0x0800) -> bytes:
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack('>H', ethertype)


def build_arp_request(
    sender_mac="aa:bb:cc:00:00:01", sender_ip="192.168.1.1",
    target_mac="00:00:00:00:00:00", target_ip="192.168.1.2",
) -> bytes:
    """Build a standard ARP request (Ethernet + ARP)."""
    eth = build_eth(src=sender_mac, dst="ff:ff:ff:ff:ff:ff", ethertype=0x0806)
    arp = struct.pack('>HHBBH',
                      1,       # hw_type = Ethernet
                      0x0800,  # proto_type = IPv4
                      6,       # hw_size
                      4,       # proto_size
                      1)       # opcode = request
    arp += _mac_bytes(sender_mac) + _ip4_bytes(sender_ip)
    arp += _mac_bytes(target_mac) + _ip4_bytes(target_ip)
    return eth + arp


def build_arp_reply(
    sender_mac="aa:bb:cc:00:00:02", sender_ip="192.168.1.2",
    target_mac="aa:bb:cc:00:00:01", target_ip="192.168.1.1",
) -> bytes:
    """Build a standard ARP reply (Ethernet + ARP)."""
    eth = build_eth(src=sender_mac, dst=target_mac, ethertype=0x0806)
    arp = struct.pack('>HHBBH',
                      1, 0x0800, 6, 4,
                      2)  # opcode = reply
    arp += _mac_bytes(sender_mac) + _ip4_bytes(sender_ip)
    arp += _mac_bytes(target_mac) + _ip4_bytes(target_ip)
    return eth + arp


def build_ipv4_header(src="192.168.1.1", dst="192.168.1.2", proto=1, payload_len=0) -> bytes:
    total_len = 20 + payload_len
    return struct.pack('>BBHHHBBH4s4s',
                       0x45, 0, total_len, 0x1234, 0x4000,
                       64, proto, 0,
                       _ip4_bytes(src), _ip4_bytes(dst))


def build_icmp_echo_request(id=0x1234, seq=1, payload=b'\x00' * 8) -> bytes:
    """Build ICMP Echo Request (type=8, code=0)."""
    icmp = struct.pack('>BBH', 8, 0, 0)  # type, code, checksum placeholder
    icmp += struct.pack('>HH', id, seq)
    icmp += payload
    return icmp


def build_icmp_dest_unreachable(code=1, payload=b'\x00' * 8) -> bytes:
    """Build ICMP Destination Unreachable (type=3)."""
    icmp = struct.pack('>BBH', 3, code, 0)
    icmp += struct.pack('>I', 0)  # unused 4 bytes
    icmp += payload
    return icmp


def build_eth_ipv4_icmp(icmp_data: bytes, src_ip="192.168.1.1", dst_ip="192.168.1.2") -> bytes:
    eth = build_eth(ethertype=0x0800)
    ip = build_ipv4_header(src=src_ip, dst=dst_ip, proto=1, payload_len=len(icmp_data))
    return eth + ip + icmp_data


def build_ipv6_header(src="::1", dst="::2", next_header=58, payload_len=0) -> bytes:
    """Build a minimal IPv6 header (40 bytes)."""
    return struct.pack('>IHBB16s16s',
                       0x60000000,    # version=6, traffic class=0, flow label=0
                       payload_len,   # payload length
                       next_header,   # next header
                       64,            # hop limit
                       _ip6_bytes(src),
                       _ip6_bytes(dst))


def build_icmpv6_echo_request(id=0x5678, seq=1, payload=b'\x00' * 8) -> bytes:
    """Build ICMPv6 Echo Request (type=128, code=0)."""
    icmp6 = struct.pack('>BBH', 128, 0, 0)
    icmp6 += struct.pack('>HH', id, seq)
    icmp6 += payload
    return icmp6


def build_icmpv6_neighbor_solicitation() -> bytes:
    """Build ICMPv6 Neighbor Solicitation (type=135, code=0)."""
    icmp6 = struct.pack('>BBH', 135, 0, 0)
    icmp6 += struct.pack('>I', 0)  # reserved
    icmp6 += _ip6_bytes("fe80::1")  # target address
    return icmp6


def build_eth_ipv6_icmpv6(icmpv6_data: bytes, src="::1", dst="::2") -> bytes:
    eth = build_eth(ethertype=0x86DD)
    ip6 = build_ipv6_header(src=src, dst=dst, next_header=58, payload_len=len(icmpv6_data))
    return eth + ip6 + icmpv6_data


# ── Test: Python Info classes ──

class TestARPInfoClass:
    def test_construction_and_properties(self):
        from wa1kpcap.core.packet import ARPInfo
        info = ARPInfo(hw_type=1, proto_type=0x0800, opcode=1,
                       sender_mac="aa:bb:cc:00:00:01", sender_ip="192.168.1.1",
                       target_mac="00:00:00:00:00:00", target_ip="192.168.1.2")
        assert info.hw_type == 1
        assert info.proto_type == 0x0800
        assert info.opcode == 1
        assert info.sender_mac == "aa:bb:cc:00:00:01"
        assert info.sender_ip == "192.168.1.1"
        assert info.target_mac == "00:00:00:00:00:00"
        assert info.target_ip == "192.168.1.2"

    def test_setter(self):
        from wa1kpcap.core.packet import ARPInfo
        info = ARPInfo()
        info.opcode = 2
        info.sender_ip = "10.0.0.1"
        assert info.opcode == 2
        assert info.sender_ip == "10.0.0.1"

    def test_fields_constructor(self):
        from wa1kpcap.core.packet import ARPInfo
        info = ARPInfo(fields={'opcode': 1, 'sender_ip': '1.2.3.4'})
        assert info.opcode == 1
        assert info.sender_ip == '1.2.3.4'


class TestICMPInfoClass:
    def test_construction(self):
        from wa1kpcap.core.packet import ICMPInfo
        info = ICMPInfo(type=8, code=0)
        assert info.type == 8
        assert info.code == 0

    def test_setter(self):
        from wa1kpcap.core.packet import ICMPInfo
        info = ICMPInfo()
        info.type = 3
        info.code = 1
        assert info.type == 3
        assert info.code == 1


class TestICMP6InfoClass:
    def test_construction(self):
        from wa1kpcap.core.packet import ICMP6Info
        info = ICMP6Info(type=128, code=0, checksum=0xABCD)
        assert info.type == 128
        assert info.code == 0
        assert info.checksum == 0xABCD

    def test_setter(self):
        from wa1kpcap.core.packet import ICMP6Info
        info = ICMP6Info()
        info.type = 135
        info.code = 0
        assert info.type == 135
        assert info.code == 0


# ── Test: ParsedPacket integration ──

class TestParsedPacketNewProtocols:
    def test_arp_property(self):
        from wa1kpcap.core.packet import ParsedPacket, ARPInfo
        pkt = ParsedPacket(timestamp=1.0, raw_data=b'\x00' * 42)
        assert pkt.arp is None
        pkt.arp = ARPInfo(opcode=1, sender_ip="10.0.0.1")
        assert pkt.arp is not None
        assert pkt.arp.opcode == 1
        assert pkt.arp.sender_ip == "10.0.0.1"
        # Clear
        pkt.arp = None
        assert pkt.arp is None

    def test_icmp6_property(self):
        from wa1kpcap.core.packet import ParsedPacket, ICMP6Info
        pkt = ParsedPacket(timestamp=1.0, raw_data=b'\x00' * 62)
        assert pkt.icmp6 is None
        pkt.icmp6 = ICMP6Info(type=128, code=0)
        assert pkt.icmp6 is not None
        assert pkt.icmp6.type == 128
        pkt.icmp6 = None
        assert pkt.icmp6 is None

    def test_constructor_with_arp(self):
        from wa1kpcap.core.packet import ParsedPacket, ARPInfo
        arp = ARPInfo(opcode=2, sender_ip="10.0.0.2")
        pkt = ParsedPacket(timestamp=1.0, raw_data=b'\x00' * 42, arp=arp)
        assert pkt.arp is not None
        assert pkt.arp.opcode == 2

    def test_constructor_with_icmp6(self):
        from wa1kpcap.core.packet import ParsedPacket, ICMP6Info
        icmp6 = ICMP6Info(type=135, code=0)
        pkt = ParsedPacket(timestamp=1.0, raw_data=b'\x00' * 62, icmp6=icmp6)
        assert pkt.icmp6 is not None
        assert pkt.icmp6.type == 135

    def test_layers_dict_keys(self):
        from wa1kpcap.core.packet import ParsedPacket, ARPInfo, ICMPInfo, ICMP6Info
        pkt = ParsedPacket(timestamp=1.0, raw_data=b'\x00' * 42,
                           arp=ARPInfo(opcode=1),
                           icmp=ICMPInfo(type=8),
                           icmp6=ICMP6Info(type=128))
        assert 'arp' in pkt.layers
        assert 'icmp' in pkt.layers
        assert 'icmpv6' in pkt.layers


# ── Test: Converter dict path ──

class TestConverterNewProtocols:
    def test_arp_dict(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet
        d = {
            "ethernet": {"src": "aa:bb:cc:00:00:01", "dst": "ff:ff:ff:ff:ff:ff", "ether_type": 0x0806},
            "arp": {
                "hw_type": 1, "proto_type": 0x0800, "opcode": 1,
                "sender_mac": "aa:bb:cc:00:00:01", "sender_ip": "192.168.1.1",
                "target_mac": "00:00:00:00:00:00", "target_ip": "192.168.1.2",
            },
        }
        pkt = dict_to_parsed_packet(d, 1.0, b'\x00' * 42, 1)
        assert pkt.arp is not None
        assert pkt.arp.opcode == 1
        assert pkt.arp.sender_ip == "192.168.1.1"
        assert pkt.arp.target_ip == "192.168.1.2"
        assert pkt.arp.hw_type == 1

    def test_icmp_dict(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet
        d = {
            "ethernet": {"src": "aa:bb:cc:00:00:01", "dst": "aa:bb:cc:00:00:02", "ether_type": 0x0800},
            "ipv4": {"version": 4, "total_length": 28, "protocol": 1,
                     "ttl": 64, "src": "192.168.1.1", "dst": "192.168.1.2"},
            "icmp": {"type": 8, "code": 0},
        }
        pkt = dict_to_parsed_packet(d, 1.0, b'\x00' * 42, 1)
        assert pkt.icmp is not None
        assert pkt.icmp.type == 8
        assert pkt.icmp.code == 0

    def test_icmpv6_dict(self):
        from wa1kpcap.native.converter import dict_to_parsed_packet
        d = {
            "ethernet": {"src": "aa:bb:cc:00:00:01", "dst": "aa:bb:cc:00:00:02", "ether_type": 0x86DD},
            "ipv6": {"version": 6, "payload_length": 12, "next_header": 58,
                     "hop_limit": 64, "src": "::1", "dst": "::2"},
            "icmpv6": {"type": 128, "code": 0, "checksum": 0},
        }
        pkt = dict_to_parsed_packet(d, 1.0, b'\x00' * 62, 1)
        assert pkt.icmp6 is not None
        assert pkt.icmp6.type == 128
        assert pkt.icmp6.code == 0


# ── Test: Native C++ fast-path (end-to-end) ──

def _get_native_parser():
    """Get native parser, skip if not available."""
    try:
        from wa1kpcap.native import NATIVE_AVAILABLE
        if not NATIVE_AVAILABLE:
            pytest.skip("Native engine not available")
        from wa1kpcap.native.engine import NativeEngine
        engine = NativeEngine()
        return engine._parser
    except ImportError:
        pytest.skip("Native engine not available")


class TestNativeARPParsing:
    def test_arp_request(self):
        parser = _get_native_parser()
        raw = build_arp_request()
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.arp is not None
        assert pkt.arp.opcode == 1
        assert pkt.arp.hw_type == 1
        assert pkt.arp.proto_type == 0x0800
        assert pkt.arp.sender_mac == "aa:bb:cc:00:00:01"
        assert pkt.arp.sender_ip == "192.168.1.1"
        assert pkt.arp.target_mac == "00:00:00:00:00:00"
        assert pkt.arp.target_ip == "192.168.1.2"

    def test_arp_reply(self):
        parser = _get_native_parser()
        raw = build_arp_reply()
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.arp is not None
        assert pkt.arp.opcode == 2
        assert pkt.arp.sender_mac == "aa:bb:cc:00:00:02"
        assert pkt.arp.sender_ip == "192.168.1.2"
        assert pkt.arp.target_mac == "aa:bb:cc:00:00:01"
        assert pkt.arp.target_ip == "192.168.1.1"

    def test_arp_ethernet_layer(self):
        parser = _get_native_parser()
        raw = build_arp_request()
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.eth is not None
        assert pkt.eth.type == 0x0806
        # ARP is leaf — no IP/TCP/UDP
        assert pkt.ip is None
        assert pkt.tcp is None
        assert pkt.udp is None


class TestNativeICMPParsing:
    def test_icmp_echo_request(self):
        parser = _get_native_parser()
        icmp_data = build_icmp_echo_request(id=0x1234, seq=1)
        raw = build_eth_ipv4_icmp(icmp_data)
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.ip is not None
        assert pkt.ip.proto == 1
        assert pkt.icmp is not None
        assert pkt.icmp.type == 8
        assert pkt.icmp.code == 0

    def test_icmp_dest_unreachable(self):
        parser = _get_native_parser()
        icmp_data = build_icmp_dest_unreachable(code=1)
        raw = build_eth_ipv4_icmp(icmp_data)
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.icmp is not None
        assert pkt.icmp.type == 3
        assert pkt.icmp.code == 1

    def test_icmp_no_tcp_udp(self):
        parser = _get_native_parser()
        icmp_data = build_icmp_echo_request()
        raw = build_eth_ipv4_icmp(icmp_data)
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.tcp is None
        assert pkt.udp is None


class TestNativeICMPv6Parsing:
    def test_icmpv6_echo_request(self):
        parser = _get_native_parser()
        icmpv6_data = build_icmpv6_echo_request(id=0x5678, seq=1)
        raw = build_eth_ipv6_icmpv6(icmpv6_data)
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.ip6 is not None
        assert pkt.ip6.next_header == 58
        assert pkt.icmp6 is not None
        assert pkt.icmp6.type == 128
        assert pkt.icmp6.code == 0

    def test_icmpv6_neighbor_solicitation(self):
        parser = _get_native_parser()
        icmpv6_data = build_icmpv6_neighbor_solicitation()
        raw = build_eth_ipv6_icmpv6(icmpv6_data)
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.icmp6 is not None
        assert pkt.icmp6.type == 135
        assert pkt.icmp6.code == 0

    def test_icmpv6_no_tcp_udp(self):
        parser = _get_native_parser()
        icmpv6_data = build_icmpv6_echo_request()
        raw = build_eth_ipv6_icmpv6(icmpv6_data)
        pkt = parser.parse_to_dataclass(raw, 1)
        assert pkt.tcp is None
        assert pkt.udp is None


# ── Test: NativeParsedPacket struct path (direct C++ struct) ──

class TestNativeStructPath:
    """Test that parse_packet_struct populates the new protocol structs."""

    def test_arp_struct(self):
        try:
            from wa1kpcap.native.engine import NativeEngine
            engine = NativeEngine()
        except ImportError:
            pytest.skip("Native engine not available")
        raw = build_arp_request()
        pkt = engine._parser.parse_packet_struct(raw, 1)
        assert pkt.arp is not None
        assert pkt.arp.opcode == 1
        assert pkt.arp.sender_ip == "192.168.1.1"

    def test_icmp_struct(self):
        try:
            from wa1kpcap.native.engine import NativeEngine
            engine = NativeEngine()
        except ImportError:
            pytest.skip("Native engine not available")
        icmp_data = build_icmp_echo_request()
        raw = build_eth_ipv4_icmp(icmp_data)
        pkt = engine._parser.parse_packet_struct(raw, 1)
        assert pkt.icmp is not None
        assert pkt.icmp.type == 8

    def test_icmpv6_struct(self):
        try:
            from wa1kpcap.native.engine import NativeEngine
            engine = NativeEngine()
        except ImportError:
            pytest.skip("Native engine not available")
        icmpv6_data = build_icmpv6_echo_request()
        raw = build_eth_ipv6_icmpv6(icmpv6_data)
        pkt = engine._parser.parse_packet_struct(raw, 1)
        assert pkt.icmp6 is not None
        assert pkt.icmp6.type == 128


# ── Test: __init__.py exports ──

class TestExports:
    def test_core_init_exports(self):
        from wa1kpcap.core import ARPInfo, ICMP6Info, ICMPInfo
        assert ARPInfo is not None
        assert ICMP6Info is not None
        assert ICMPInfo is not None

    def test_packet_module_exports(self):
        from wa1kpcap.core.packet import ARPInfo, ICMP6Info, ICMPInfo
        assert ARPInfo is not None
        assert ICMP6Info is not None
        assert ICMPInfo is not None
