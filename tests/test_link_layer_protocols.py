"""Tests for link-layer protocol promotion: VLAN, SLL, SLL2, raw_ip, bsd_loopback, nflog.

Each test constructs raw packet bytes and feeds them through the C++ native engine
via parse_to_dataclass(), verifying that fields are correctly parsed.
"""

from __future__ import annotations

import struct
import socket
import pytest


# ── Helpers ──

def _mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(':'))


def _ip4_bytes(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET, ip)


def _ip6_bytes(ip: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, ip)


def build_ipv4(src="10.0.0.1", dst="10.0.0.2", proto=6, payload=b"") -> bytes:
    """Minimal IPv4 header (20 bytes, no options) + payload."""
    total_len = 20 + len(payload)
    hdr = struct.pack('>BBHHHBBH',
                      0x45,           # version=4, ihl=5
                      0,              # tos
                      total_len,
                      0x1234,         # identification
                      0,              # flags+frag
                      64,             # ttl
                      proto,          # protocol
                      0)              # checksum (0 = skip)
    hdr += _ip4_bytes(src) + _ip4_bytes(dst)
    return hdr + payload


def build_ipv6(src="2001:db8::1", dst="2001:db8::2", next_header=6, payload=b"") -> bytes:
    """Minimal IPv6 header (40 bytes) + payload."""
    hdr = struct.pack('>IHBB',
                      0x60000000,       # version=6, traffic class=0, flow label=0
                      len(payload),     # payload length
                      next_header,
                      64)               # hop limit
    hdr += _ip6_bytes(src) + _ip6_bytes(dst)
    return hdr + payload


def build_udp(sport=12345, dport=53, payload=b"") -> bytes:
    """Minimal UDP header (8 bytes) + payload."""
    length = 8 + len(payload)
    return struct.pack('>HHHH', sport, dport, length, 0) + payload


def build_eth(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02", ethertype=0x0800) -> bytes:
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack('>H', ethertype)


def _get_native_parser():
    """Get native parser, skip if not available."""
    from wa1kpcap.native import NATIVE_AVAILABLE
    if not NATIVE_AVAILABLE:
        pytest.skip("Native engine not available")
    from wa1kpcap.native.engine import NativeEngine
    engine = NativeEngine()
    return engine._parser


# ── Link type constants ──
DLT_NULL = 0           # BSD loopback
DLT_EN10MB = 1         # Ethernet
DLT_RAW = 101          # Raw IP
DLT_LOOP = 108         # BSD loopback (OpenBSD)
DLT_LINUX_SLL = 113    # Linux cooked capture v1
DLT_NFLOG = 239        # NFLOG
DLT_LINUX_SLL2 = 276   # Linux cooked capture v2


# ═══════════════════════════════════════════════════════════════════
# VLAN (802.1Q)
# ═══════════════════════════════════════════════════════════════════

class TestVLANParsing:
    """Test VLAN fast-path parsing from raw bytes."""

    def _build_vlan_packet(self, vlan_id=100, priority=5, dei=0,
                           inner_ethertype=0x0800, inner_payload=b"") -> bytes:
        """Ethernet(ethertype=0x8100) + VLAN tag (4 bytes) + inner payload."""
        eth = build_eth(ethertype=0x8100)
        tci = (priority << 13) | (dei << 12) | (vlan_id & 0x0FFF)
        vlan_tag = struct.pack('>HH', tci, inner_ethertype)
        return eth + vlan_tag + inner_payload

    def test_vlan_basic(self):
        parser = _get_native_parser()
        ip_payload = build_ipv4(src="192.168.1.10", dst="192.168.1.20", proto=17,
                                payload=build_udp(sport=1234, dport=80))
        raw = self._build_vlan_packet(vlan_id=42, priority=3, dei=1,
                                      inner_ethertype=0x0800, inner_payload=ip_payload)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.vlan is not None
        assert pkt.vlan.vlan_id == 42
        assert pkt.vlan.priority == 3
        assert pkt.vlan.dei == 1
        assert pkt.vlan.ether_type == 0x0800

        # Inner IP should also be parsed
        assert pkt.ip is not None
        assert pkt.ip.src == "192.168.1.10"
        assert pkt.ip.dst == "192.168.1.20"

    def test_vlan_ipv6(self):
        parser = _get_native_parser()
        ip6_payload = build_ipv6(src="2001:db8::1", dst="2001:db8::2", next_header=17,
                                 payload=build_udp())
        raw = self._build_vlan_packet(vlan_id=200, priority=0, dei=0,
                                      inner_ethertype=0x86DD, inner_payload=ip6_payload)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.vlan is not None
        assert pkt.vlan.vlan_id == 200
        assert pkt.vlan.ether_type == 0x86DD
        assert pkt.ip6 is not None
        assert pkt.ip6.src == "2001:db8::1"

    def test_vlan_qinq(self):
        """Double-tagged (Q-in-Q): outer VLAN wraps inner VLAN wraps IPv4."""
        parser = _get_native_parser()
        ip_payload = build_ipv4()
        # Inner VLAN: id=200, ethertype=0x0800
        inner_tci = (0 << 13) | (0 << 12) | 200
        inner_vlan = struct.pack('>HH', inner_tci, 0x0800)
        # Outer VLAN: id=100, ethertype=0x8100 (points to inner VLAN)
        raw = self._build_vlan_packet(vlan_id=100, priority=7, dei=0,
                                      inner_ethertype=0x8100,
                                      inner_payload=inner_vlan + ip_payload)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        # The fast-path should parse the outer VLAN; inner VLAN chains
        assert pkt.vlan is not None
        assert pkt.ip is not None

    def test_vlan_flow_key_includes_vlan_id(self):
        """Flow key cache should include vlan_id."""
        parser = _get_native_parser()
        ip_payload = build_ipv4(src="10.0.0.1", dst="10.0.0.2", proto=17,
                                payload=build_udp(sport=100, dport=200))
        raw = self._build_vlan_packet(vlan_id=42, inner_ethertype=0x0800,
                                      inner_payload=ip_payload)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt._flow_key_cache is not None
        # 7-element tuple: (canonical, src_ip, dst_ip, src_port, dst_port, protocol, vlan_id)
        assert len(pkt._flow_key_cache) == 7
        assert pkt._flow_key_cache[6] == 42  # vlan_id


# ═══════════════════════════════════════════════════════════════════
# Linux SLL (cooked capture v1)
# ═══════════════════════════════════════════════════════════════════

class TestSLLParsing:
    """Test Linux SLL fast-path parsing from raw bytes."""

    def _build_sll_packet(self, packet_type=0, arphrd_type=1,
                          addr=b"\xaa\xbb\xcc\x00\x00\x01\x00\x00",
                          protocol=0x0800, payload=b"") -> bytes:
        """Linux SLL header (16 bytes) + payload."""
        addr_len = 6
        # Pad addr to 8 bytes
        addr_padded = (addr + b"\x00" * 8)[:8]
        hdr = struct.pack('>HHH', packet_type, arphrd_type, addr_len)
        hdr += addr_padded
        hdr += struct.pack('>H', protocol)
        return hdr + payload

    def test_sll_ipv4(self):
        parser = _get_native_parser()
        ip_payload = build_ipv4(src="172.16.0.1", dst="172.16.0.2", proto=17,
                                payload=build_udp(sport=5000, dport=5001))
        raw = self._build_sll_packet(packet_type=0, arphrd_type=1,
                                     protocol=0x0800, payload=ip_payload)
        pkt = parser.parse_to_dataclass(raw, DLT_LINUX_SLL)

        assert pkt.sll is not None
        assert pkt.sll.packet_type == 0
        assert pkt.sll.arphrd_type == 1
        assert pkt.sll.protocol == 0x0800
        assert pkt.sll.addr == "aa:bb:cc:00:00:01"

        assert pkt.ip is not None
        assert pkt.ip.src == "172.16.0.1"
        assert pkt.ip.dst == "172.16.0.2"

    def test_sll_ipv6(self):
        parser = _get_native_parser()
        ip6_payload = build_ipv6(src="fe80::1", dst="fe80::2", next_header=17,
                                 payload=build_udp())
        raw = self._build_sll_packet(protocol=0x86DD, payload=ip6_payload)
        pkt = parser.parse_to_dataclass(raw, DLT_LINUX_SLL)

        assert pkt.sll is not None
        assert pkt.sll.protocol == 0x86DD
        assert pkt.ip6 is not None

    def test_sll_arp(self):
        """SLL carrying ARP."""
        parser = _get_native_parser()
        arp = struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1)  # ARP request
        arp += _mac_bytes("aa:bb:cc:00:00:01") + _ip4_bytes("10.0.0.1")
        arp += _mac_bytes("00:00:00:00:00:00") + _ip4_bytes("10.0.0.2")
        raw = self._build_sll_packet(protocol=0x0806, payload=arp)
        pkt = parser.parse_to_dataclass(raw, DLT_LINUX_SLL)

        assert pkt.sll is not None
        assert pkt.arp is not None
        assert pkt.arp.opcode == 1


# ═══════════════════════════════════════════════════════════════════
# Linux SLL2 (cooked capture v2)
# ═══════════════════════════════════════════════════════════════════

class TestSLL2Parsing:
    """Test Linux SLL2 fast-path parsing from raw bytes."""

    def _build_sll2_packet(self, protocol_type=0x0800, interface_index=3,
                           arphrd_type=1, packet_type=0,
                           addr=b"\xaa\xbb\xcc\xdd\xee\xff\x00\x00",
                           payload=b"") -> bytes:
        """Linux SLL2 header (20 bytes) + payload."""
        addr_len = 6
        addr_padded = (addr + b"\x00" * 8)[:8]
        hdr = struct.pack('>HH', protocol_type, 0)  # protocol_type + reserved
        hdr += struct.pack('>I', interface_index)
        hdr += struct.pack('>HBB', arphrd_type, packet_type, addr_len)
        hdr += addr_padded
        return hdr + payload

    def test_sll2_ipv4(self):
        parser = _get_native_parser()
        ip_payload = build_ipv4(src="10.1.1.1", dst="10.1.1.2", proto=6)
        raw = self._build_sll2_packet(protocol_type=0x0800, interface_index=7,
                                      payload=ip_payload)
        pkt = parser.parse_to_dataclass(raw, DLT_LINUX_SLL2)

        assert pkt.sll2 is not None
        assert pkt.sll2.protocol_type == 0x0800
        assert pkt.sll2.interface_index == 7
        assert pkt.sll2.arphrd_type == 1
        assert pkt.sll2.packet_type == 0
        assert pkt.sll2.addr == "aa:bb:cc:dd:ee:ff"

        assert pkt.ip is not None
        assert pkt.ip.src == "10.1.1.1"

    def test_sll2_ipv6(self):
        parser = _get_native_parser()
        ip6_payload = build_ipv6(src="::1", dst="::2", next_header=17,
                                 payload=build_udp())
        raw = self._build_sll2_packet(protocol_type=0x86DD, payload=ip6_payload)
        pkt = parser.parse_to_dataclass(raw, DLT_LINUX_SLL2)

        assert pkt.sll2 is not None
        assert pkt.sll2.protocol_type == 0x86DD
        assert pkt.ip6 is not None


# ═══════════════════════════════════════════════════════════════════
# Raw IP (DLT_RAW)
# ═══════════════════════════════════════════════════════════════════

class TestRawIPParsing:
    """Test raw_ip transparent fast-path: version nibble → ipv4/ipv6."""

    def test_raw_ipv4(self):
        parser = _get_native_parser()
        raw = build_ipv4(src="1.2.3.4", dst="5.6.7.8", proto=17,
                         payload=build_udp(sport=9999, dport=8888))
        pkt = parser.parse_to_dataclass(raw, DLT_RAW)

        assert pkt.ip is not None
        assert pkt.ip.src == "1.2.3.4"
        assert pkt.ip.dst == "5.6.7.8"
        assert pkt.udp is not None
        assert pkt.udp.sport == 9999

    def test_raw_ipv6(self):
        parser = _get_native_parser()
        raw = build_ipv6(src="2001:db8::a", dst="2001:db8::b", next_header=17,
                         payload=build_udp(sport=4000, dport=4001))
        pkt = parser.parse_to_dataclass(raw, DLT_RAW)

        assert pkt.ip6 is not None
        assert pkt.ip6.src == "2001:db8::a"
        assert pkt.ip6.dst == "2001:db8::b"
        assert pkt.udp is not None
        assert pkt.udp.sport == 4000

    def test_raw_ip_no_eth(self):
        """Raw IP should NOT have an ethernet layer."""
        parser = _get_native_parser()
        raw = build_ipv4()
        pkt = parser.parse_to_dataclass(raw, DLT_RAW)

        assert pkt.eth is None
        assert pkt.ip is not None


# ═══════════════════════════════════════════════════════════════════
# BSD Loopback (DLT_NULL / DLT_LOOP)
# ═══════════════════════════════════════════════════════════════════

class TestBSDLoopbackParsing:
    """Test bsd_loopback transparent fast-path: AF field → ipv4/ipv6."""

    def _build_loopback_ipv4(self, src="127.0.0.1", dst="127.0.0.2") -> bytes:
        """BSD loopback: 4-byte AF header + IPv4."""
        # AF_INET = 2 in host byte order; on little-endian this is 0x02000000
        af = struct.pack('=I', 2)  # native byte order
        return af + build_ipv4(src=src, dst=dst, proto=17, payload=build_udp())

    def _build_loopback_ipv6(self, src="::1", dst="::1") -> bytes:
        """BSD loopback: 4-byte AF header + IPv6."""
        # AF_INET6: 30 on macOS/BSD, 10 on Linux — the parser converts to ethertype
        # Use AF=30 (common BSD value)
        af = struct.pack('=I', 30)
        return af + build_ipv6(src=src, dst=dst, next_header=17, payload=build_udp())

    def test_loopback_ipv4(self):
        parser = _get_native_parser()
        raw = self._build_loopback_ipv4(src="127.0.0.1", dst="127.0.0.2")
        pkt = parser.parse_to_dataclass(raw, DLT_NULL)

        assert pkt.eth is None
        assert pkt.ip is not None
        assert pkt.ip.src == "127.0.0.1"
        assert pkt.ip.dst == "127.0.0.2"

    def test_loopback_ipv6(self):
        parser = _get_native_parser()
        raw = self._build_loopback_ipv6(src="::1", dst="::1")
        pkt = parser.parse_to_dataclass(raw, DLT_NULL)

        assert pkt.eth is None
        assert pkt.ip6 is not None

    def test_loopback_dlt_loop(self):
        """DLT_LOOP (108) should also work as bsd_loopback."""
        parser = _get_native_parser()
        raw = self._build_loopback_ipv4()
        pkt = parser.parse_to_dataclass(raw, DLT_LOOP)

        assert pkt.ip is not None


# ═══════════════════════════════════════════════════════════════════
# NFLOG (DLT_NFLOG)
# ═══════════════════════════════════════════════════════════════════

class TestNFLOGParsing:
    """Test nflog transparent fast-path: TLV walk → NFULA_PAYLOAD → ipv4/ipv6."""

    def _build_nflog_packet(self, af_family=2, payload=b"") -> bytes:
        """Build NFLOG header + TLV with NFULA_PAYLOAD (type=9).

        NFLOG header: 1 byte af_family, 1 byte version, 2 bytes resource_id
        TLV: 2 bytes length (including header), 2 bytes type, then data
        TLV length is padded to 4-byte boundary.
        """
        nflog_hdr = struct.pack('BBH', af_family, 0, 0)  # af, version, resource_id

        # Build NFULA_PAYLOAD TLV (type=9)
        tlv_data = payload
        tlv_len = 4 + len(tlv_data)  # 4 = TLV header size
        tlv = struct.pack('<HH', tlv_len, 9) + tlv_data  # type=9 = NFULA_PAYLOAD
        # Pad to 4-byte boundary
        pad = (4 - (len(tlv) % 4)) % 4
        tlv += b"\x00" * pad

        return nflog_hdr + tlv

    def test_nflog_ipv4(self):
        parser = _get_native_parser()
        ip_data = build_ipv4(src="192.168.0.1", dst="192.168.0.2", proto=17,
                             payload=build_udp(sport=3000, dport=3001))
        raw = self._build_nflog_packet(af_family=2, payload=ip_data)
        pkt = parser.parse_to_dataclass(raw, DLT_NFLOG)

        assert pkt.eth is None
        assert pkt.ip is not None
        assert pkt.ip.src == "192.168.0.1"
        assert pkt.ip.dst == "192.168.0.2"
        assert pkt.udp is not None
        assert pkt.udp.sport == 3000

    def test_nflog_ipv6(self):
        parser = _get_native_parser()
        ip6_data = build_ipv6(src="fd00::1", dst="fd00::2", next_header=17,
                              payload=build_udp())
        raw = self._build_nflog_packet(af_family=10, payload=ip6_data)
        pkt = parser.parse_to_dataclass(raw, DLT_NFLOG)

        assert pkt.ip6 is not None
        assert pkt.ip6.src == "fd00::1"

    def test_nflog_with_extra_tlv(self):
        """NFLOG with a non-payload TLV before the payload TLV."""
        parser = _get_native_parser()
        ip_data = build_ipv4(src="10.0.0.1", dst="10.0.0.2")

        nflog_hdr = struct.pack('BBH', 2, 0, 0)

        # First TLV: NFULA_PREFIX (type=3), some dummy data
        prefix_data = b"iptables\x00"
        prefix_len = 4 + len(prefix_data)
        prefix_tlv = struct.pack('<HH', prefix_len, 3) + prefix_data
        pad = (4 - (len(prefix_tlv) % 4)) % 4
        prefix_tlv += b"\x00" * pad

        # Second TLV: NFULA_PAYLOAD (type=9)
        payload_len = 4 + len(ip_data)
        payload_tlv = struct.pack('<HH', payload_len, 9) + ip_data

        raw = nflog_hdr + prefix_tlv + payload_tlv
        pkt = parser.parse_to_dataclass(raw, DLT_NFLOG)

        assert pkt.ip is not None
        assert pkt.ip.src == "10.0.0.1"
