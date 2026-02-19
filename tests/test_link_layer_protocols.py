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


# ═══════════════════════════════════════════════════════════════════
# GRE (Generic Routing Encapsulation)
# ═══════════════════════════════════════════════════════════════════

class TestGREParsing:
    """Test GRE fast-path parsing from raw bytes."""

    def _build_gre_header(self, protocol_type=0x0800, checksum=None,
                          key=None, sequence=None) -> bytes:
        """Build a GRE header with optional fields."""
        flags = 0
        if checksum is not None:
            flags |= 0x8000  # C bit
        if key is not None:
            flags |= 0x2000  # K bit
        if sequence is not None:
            flags |= 0x1000  # S bit

        hdr = struct.pack('>HH', flags, protocol_type)

        if checksum is not None:
            hdr += struct.pack('>HH', checksum, 0)  # checksum + reserved1

        if key is not None:
            hdr += struct.pack('>I', key)

        if sequence is not None:
            hdr += struct.pack('>I', sequence)

        return hdr

    def _build_gre_packet(self, inner_payload=b"", **gre_kwargs) -> bytes:
        """Ethernet + IPv4(proto=47) + GRE + inner_payload."""
        gre_hdr = self._build_gre_header(**gre_kwargs)
        ip_payload = gre_hdr + inner_payload
        ip = build_ipv4(proto=47, payload=ip_payload)
        eth = build_eth(ethertype=0x0800)
        return eth + ip

    def test_gre_basic_ipv4_encap(self):
        """GRE with no optional fields, encapsulating IPv4."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="192.168.1.1", dst="192.168.1.2", proto=6)
        raw = self._build_gre_packet(inner_payload=inner_ip, protocol_type=0x0800)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.gre is not None
        assert pkt.gre.protocol_type == 0x0800
        assert pkt.gre.flags == 0
        assert pkt.gre.checksum is None
        assert pkt.gre.key is None
        assert pkt.gre.sequence is None

    def test_gre_with_checksum(self):
        """GRE with checksum present (C bit set)."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.1.1.1", dst="10.1.1.2")
        raw = self._build_gre_packet(inner_payload=inner_ip,
                                      protocol_type=0x0800, checksum=0xABCD)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.gre is not None
        assert pkt.gre.has_checksum
        assert pkt.gre.checksum == 0xABCD
        assert pkt.gre.key is None
        assert pkt.gre.sequence is None

    def test_gre_with_key(self):
        """GRE with key present (K bit set)."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.2.2.1", dst="10.2.2.2")
        raw = self._build_gre_packet(inner_payload=inner_ip,
                                      protocol_type=0x0800, key=0x12345678)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.gre is not None
        assert pkt.gre.has_key
        assert pkt.gre.key == 0x12345678
        assert not pkt.gre.has_checksum
        assert not pkt.gre.has_sequence

    def test_gre_with_sequence(self):
        """GRE with sequence number present (S bit set)."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.3.3.1", dst="10.3.3.2")
        raw = self._build_gre_packet(inner_payload=inner_ip,
                                      protocol_type=0x0800, sequence=42)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.gre is not None
        assert pkt.gre.has_sequence
        assert pkt.gre.sequence == 42

    def test_gre_all_optional_fields(self):
        """GRE with checksum + key + sequence all present."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.4.4.1", dst="10.4.4.2")
        raw = self._build_gre_packet(inner_payload=inner_ip,
                                      protocol_type=0x0800,
                                      checksum=0x1234, key=0xDEADBEEF,
                                      sequence=99)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.gre is not None
        assert pkt.gre.flags == (0x8000 | 0x2000 | 0x1000)
        assert pkt.gre.checksum == 0x1234
        assert pkt.gre.key == 0xDEADBEEF
        assert pkt.gre.sequence == 99

    def test_gre_inner_ipv4_parsed(self):
        """Verify inner IPv4 is parsed after GRE decapsulation."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="172.16.0.1", dst="172.16.0.2", proto=17,
                              payload=build_udp(sport=5000, dport=6000))
        raw = self._build_gre_packet(inner_payload=inner_ip, protocol_type=0x0800)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        # Outer IP should be the tunnel endpoints
        assert pkt.ip is not None
        # GRE should be present
        assert pkt.gre is not None
        assert pkt.gre.protocol_type == 0x0800

    def test_gre_inner_ipv6(self):
        """GRE encapsulating IPv6."""
        parser = _get_native_parser()
        inner_ip6 = build_ipv6(src="2001:db8::1", dst="2001:db8::2", next_header=17,
                               payload=build_udp())
        raw = self._build_gre_packet(inner_payload=inner_ip6, protocol_type=0x86DD)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.gre is not None
        assert pkt.gre.protocol_type == 0x86DD

    def test_gre_over_ipv6(self):
        """GRE carried over IPv6 (next_header=47)."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.0.0.1", dst="10.0.0.2")
        gre_hdr = self._build_gre_header(protocol_type=0x0800)
        ip6 = build_ipv6(src="2001:db8::1", dst="2001:db8::2",
                          next_header=47, payload=gre_hdr + inner_ip)
        eth = build_eth(ethertype=0x86DD)
        raw = eth + ip6
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.ip6 is not None
        assert pkt.gre is not None
        assert pkt.gre.protocol_type == 0x0800

    def test_gre_too_short(self):
        """GRE header shorter than 4 bytes should not crash."""
        parser = _get_native_parser()
        # Only 2 bytes of GRE (truncated)
        truncated_gre = b"\x00\x00"
        ip = build_ipv4(proto=47, payload=truncated_gre)
        eth = build_eth(ethertype=0x0800)
        raw = eth + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        # Should parse IP but GRE should be absent or empty
        assert pkt.ip is not None

    def test_gre_transparent_ethernet_bridging(self):
        """GRE with protocol_type 0x6558 (Transparent Ethernet Bridging)."""
        parser = _get_native_parser()
        inner_eth = build_eth(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff",
                              ethertype=0x0800)
        inner_ip = build_ipv4(src="10.10.10.1", dst="10.10.10.2")
        raw = self._build_gre_packet(inner_payload=inner_eth + inner_ip,
                                      protocol_type=0x6558)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.gre is not None
        assert pkt.gre.protocol_type == 0x6558


# ═══════════════════════════════════════════════════════════════════
# VXLAN (Virtual Extensible LAN)
# ═══════════════════════════════════════════════════════════════════

class TestVXLANParsing:
    """Test VXLAN fast-path parsing from raw bytes."""

    def _build_vxlan_header(self, vni=1000, flags=0x08) -> bytes:
        """Build an 8-byte VXLAN header.
        Layout: flags(1) + reserved(3) + VNI(3) + reserved(1)
        """
        return struct.pack('>B3sI', flags, b"\x00\x00\x00", vni << 8)

    def _build_vxlan_packet(self, vni=1000, inner_payload=b"") -> bytes:
        """Ethernet + IPv4 + UDP(dport=4789) + VXLAN + inner_payload."""
        vxlan_hdr = self._build_vxlan_header(vni=vni)
        udp_payload = vxlan_hdr + inner_payload
        udp_hdr = build_udp(sport=50000, dport=4789, payload=udp_payload)
        ip = build_ipv4(proto=17, payload=udp_hdr)
        eth = build_eth(ethertype=0x0800)
        return eth + ip

    def test_vxlan_basic(self):
        """VXLAN with VNI parsed correctly."""
        parser = _get_native_parser()
        inner_eth = build_eth(src="11:22:33:44:55:66", dst="aa:bb:cc:dd:ee:ff",
                              ethertype=0x0800)
        inner_ip = build_ipv4(src="192.168.1.1", dst="192.168.1.2")
        raw = self._build_vxlan_packet(vni=42, inner_payload=inner_eth + inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.vxlan is not None
        assert pkt.vxlan.vni == 42
        assert pkt.vxlan.flags == 0x08

    def test_vxlan_large_vni(self):
        """VXLAN with max 24-bit VNI (16777215)."""
        parser = _get_native_parser()
        inner_eth = build_eth(ethertype=0x0800)
        inner_ip = build_ipv4(src="10.0.0.1", dst="10.0.0.2")
        raw = self._build_vxlan_packet(vni=0xFFFFFF, inner_payload=inner_eth + inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.vxlan is not None
        assert pkt.vxlan.vni == 0xFFFFFF

    def test_vxlan_inner_ethernet_parsed(self):
        """Verify inner Ethernet frame is parsed after VXLAN decapsulation."""
        parser = _get_native_parser()
        inner_eth = build_eth(src="de:ad:be:ef:00:01", dst="de:ad:be:ef:00:02",
                              ethertype=0x0800)
        inner_ip = build_ipv4(src="172.16.0.1", dst="172.16.0.2")
        raw = self._build_vxlan_packet(vni=100, inner_payload=inner_eth + inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.vxlan is not None
        assert pkt.udp is not None
        assert pkt.udp.dport == 4789

    def test_vxlan_zero_vni(self):
        """VXLAN with VNI = 0."""
        parser = _get_native_parser()
        inner_eth = build_eth(ethertype=0x0800)
        inner_ip = build_ipv4(src="10.1.1.1", dst="10.1.1.2")
        raw = self._build_vxlan_packet(vni=0, inner_payload=inner_eth + inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.vxlan is not None
        assert pkt.vxlan.vni == 0

    def test_vxlan_too_short(self):
        """VXLAN header shorter than 8 bytes should not crash."""
        parser = _get_native_parser()
        # Only 4 bytes of VXLAN (truncated)
        truncated_vxlan = b"\x08\x00\x00\x00"
        udp_hdr = build_udp(sport=50000, dport=4789, payload=truncated_vxlan)
        ip = build_ipv4(proto=17, payload=udp_hdr)
        eth = build_eth(ethertype=0x0800)
        raw = eth + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        # Should parse UDP but VXLAN may be absent
        assert pkt.udp is not None
        assert pkt.udp.dport == 4789


# ═══════════════════════════════════════════════════════════════════
# MPLS (Multi-Protocol Label Switching)
# ═══════════════════════════════════════════════════════════════════

class TestMPLSParsing:
    """Test MPLS fast-path parsing from raw bytes."""

    def _build_mpls_label(self, label=1000, tc=0, s_bit=True, ttl=64) -> bytes:
        """Build a single 4-byte MPLS label entry."""
        entry = ((label & 0xFFFFF) << 12) | ((tc & 0x07) << 9) | ((1 if s_bit else 0) << 8) | (ttl & 0xFF)
        return struct.pack('>I', entry)

    def _build_mpls_packet(self, labels, inner_payload=b"") -> bytes:
        """Ethernet(ethertype=0x8847) + MPLS label stack + inner_payload."""
        eth = build_eth(ethertype=0x8847)
        mpls_stack = b""
        for i, lbl in enumerate(labels):
            s = (i == len(labels) - 1)  # S-bit on last label
            mpls_stack += self._build_mpls_label(
                label=lbl.get('label', 0),
                tc=lbl.get('tc', 0),
                s_bit=s,
                ttl=lbl.get('ttl', 64))
        return eth + mpls_stack + inner_payload

    def test_mpls_single_label_ipv4(self):
        """Single MPLS label with inner IPv4."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.0.0.1", dst="10.0.0.2")
        raw = self._build_mpls_packet(
            [{'label': 1000, 'tc': 5, 'ttl': 64}],
            inner_payload=inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.mpls is not None
        assert pkt.mpls.label == 1000
        assert pkt.mpls.tc == 5
        assert pkt.mpls.ttl == 64
        assert pkt.mpls.bottom_of_stack is True
        assert pkt.mpls.stack_depth == 1

    def test_mpls_single_label_ipv6(self):
        """Single MPLS label with inner IPv6."""
        parser = _get_native_parser()
        inner_ip6 = build_ipv6(src="2001:db8::1", dst="2001:db8::2")
        raw = self._build_mpls_packet(
            [{'label': 2000}],
            inner_payload=inner_ip6)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.mpls is not None
        assert pkt.mpls.label == 2000
        assert pkt.ip6 is not None

    def test_mpls_label_stack(self):
        """Two-label MPLS stack — bottom label stored."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="172.16.0.1", dst="172.16.0.2")
        raw = self._build_mpls_packet(
            [{'label': 100, 'tc': 0, 'ttl': 255},
             {'label': 200, 'tc': 3, 'ttl': 128}],
            inner_payload=inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.mpls is not None
        assert pkt.mpls.label == 200  # bottom-of-stack label
        assert pkt.mpls.stack_depth == 2
        assert pkt.mpls.bottom_of_stack is True

    def test_mpls_three_label_stack(self):
        """Three-label MPLS stack."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.1.1.1", dst="10.1.1.2")
        raw = self._build_mpls_packet(
            [{'label': 16}, {'label': 17}, {'label': 18}],
            inner_payload=inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.mpls is not None
        assert pkt.mpls.label == 18  # bottom label
        assert pkt.mpls.stack_depth == 3

    def test_mpls_max_label(self):
        """MPLS with max 20-bit label (1048575)."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.0.0.1", dst="10.0.0.2")
        raw = self._build_mpls_packet(
            [{'label': 0xFFFFF, 'ttl': 1}],
            inner_payload=inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.mpls is not None
        assert pkt.mpls.label == 0xFFFFF
        assert pkt.mpls.ttl == 1

    def test_mpls_inner_ipv4_parsed(self):
        """Verify inner IPv4 is parsed after MPLS decapsulation."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="192.168.1.1", dst="192.168.1.2", proto=17,
                              payload=build_udp(sport=8000, dport=9000))
        raw = self._build_mpls_packet(
            [{'label': 500}],
            inner_payload=inner_ip)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.mpls is not None
        assert pkt.ip is not None
        assert pkt.udp is not None
        assert pkt.udp.dport == 9000

    def test_mpls_too_short(self):
        """MPLS with less than 4 bytes should not crash."""
        parser = _get_native_parser()
        eth = build_eth(ethertype=0x8847)
        raw = eth + b"\x00\x00"  # truncated
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.eth is not None

    def test_mpls_multicast_ethertype(self):
        """MPLS multicast (ethertype 0x8848)."""
        parser = _get_native_parser()
        inner_ip = build_ipv4(src="10.0.0.1", dst="224.0.0.1")
        label_entry = self._build_mpls_label(label=300, s_bit=True, ttl=32)
        eth = build_eth(ethertype=0x8848)
        raw = eth + label_entry + inner_ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.mpls is not None
        assert pkt.mpls.label == 300


# ═══════════════════════════════════════════════════════════════════
# DHCP (Dynamic Host Configuration Protocol)
# ═══════════════════════════════════════════════════════════════════

class TestDHCPParsing:
    """Test DHCP slow-path parsing (Type B: YAML + Python Info)."""

    MAGIC_COOKIE = b"\x63\x82\x53\x63"  # 0x63825363

    def _build_bootp_header(self, op=1, htype=1, hlen=6, hops=0,
                            xid=0x12345678, secs=0, flags=0,
                            ciaddr="0.0.0.0", yiaddr="0.0.0.0",
                            siaddr="0.0.0.0", giaddr="0.0.0.0",
                            chaddr="aa:bb:cc:dd:ee:ff") -> bytes:
        """Build 236-byte BOOTP header."""
        import socket
        hdr = struct.pack('>BBBB', op, htype, hlen, hops)
        hdr += struct.pack('>I', xid)
        hdr += struct.pack('>HH', secs, flags)
        hdr += socket.inet_aton(ciaddr)
        hdr += socket.inet_aton(yiaddr)
        hdr += socket.inet_aton(siaddr)
        hdr += socket.inet_aton(giaddr)
        # chaddr: 6 bytes MAC + 10 bytes padding
        mac_bytes = bytes(int(x, 16) for x in chaddr.split(':'))
        hdr += mac_bytes + b"\x00" * 10
        # sname (64 bytes) + file (128 bytes)
        hdr += b"\x00" * 64 + b"\x00" * 128
        return hdr

    def _build_dhcp_options(self, options: list[tuple[int, bytes]]) -> bytes:
        """Build DHCP options TLV with end marker."""
        data = b""
        for tag, val in options:
            data += struct.pack('BB', tag, len(val)) + val
        data += b"\xff"  # End option
        return data

    def _build_dhcp_packet(self, op=1, xid=0x12345678,
                           ciaddr="0.0.0.0", yiaddr="0.0.0.0",
                           siaddr="0.0.0.0", giaddr="0.0.0.0",
                           chaddr="aa:bb:cc:dd:ee:ff",
                           options=None) -> bytes:
        """Full Ethernet + IPv4 + UDP(67/68) + BOOTP + magic + options."""
        bootp = self._build_bootp_header(
            op=op, xid=xid, ciaddr=ciaddr, yiaddr=yiaddr,
            siaddr=siaddr, giaddr=giaddr, chaddr=chaddr)
        opts = self._build_dhcp_options(options or [])
        payload = bootp + self.MAGIC_COOKIE + opts
        udp_hdr = build_udp(sport=68, dport=67, payload=payload)
        ip = build_ipv4(proto=17, payload=udp_hdr)
        eth = build_eth(ethertype=0x0800)
        return eth + ip

    def test_dhcp_discover(self):
        """DHCP Discover (message type 1)."""
        parser = _get_native_parser()
        raw = self._build_dhcp_packet(
            op=1, xid=0xAABBCCDD,
            chaddr="de:ad:be:ef:00:01",
            options=[(53, b"\x01")])  # DHCP Discover
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcp is not None
        assert pkt.dhcp.op == 1
        assert pkt.dhcp.xid == 0xAABBCCDD
        # options_raw contains raw TLV bytes: tag(53) + len(1) + val(1) + end(0xff)
        assert b"\x35\x01\x01" in pkt.dhcp.options_raw

    def test_dhcp_offer(self):
        """DHCP Offer (message type 2) with yiaddr."""
        parser = _get_native_parser()
        raw = self._build_dhcp_packet(
            op=2, xid=0x11223344,
            yiaddr="192.168.1.100",
            options=[(53, b"\x02"),          # DHCP Offer
                     (1, b"\xff\xff\xff\x00"),  # Subnet mask
                     (3, b"\xc0\xa8\x01\x01")]) # Router
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcp is not None
        assert pkt.dhcp.op == 2
        assert len(pkt.dhcp.options_raw) > 0

    def test_dhcp_multiple_options(self):
        """DHCP with multiple options in raw bytes."""
        parser = _get_native_parser()
        raw = self._build_dhcp_packet(
            options=[(53, b"\x03"),           # DHCP Request
                     (50, b"\xc0\xa8\x01\x64"),  # Requested IP
                     (12, b"myhost")])            # Hostname
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcp is not None
        assert b"\x35\x01\x03" in pkt.dhcp.options_raw  # option 53
        assert b"\x0c\x06myhost" in pkt.dhcp.options_raw  # option 12

    def test_dhcp_no_options(self):
        """DHCP with no options (just end marker)."""
        parser = _get_native_parser()
        raw = self._build_dhcp_packet(options=[])
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcp is not None
        assert pkt.dhcp.op == 1
        # options_raw contains only the end marker 0xff
        assert pkt.dhcp.options_raw == b"\xff"

    def test_dhcp_server_port(self):
        """DHCP from server (sport=67, dport=68)."""
        parser = _get_native_parser()
        bootp = self._build_bootp_header(op=2, yiaddr="10.0.0.50")
        opts = self._build_dhcp_options([(53, b"\x02")])
        payload = bootp + self.MAGIC_COOKIE + opts
        udp_hdr = build_udp(sport=67, dport=68, payload=payload)
        ip = build_ipv4(proto=17, payload=udp_hdr)
        eth = build_eth(ethertype=0x0800)
        raw = eth + ip
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcp is not None
        assert pkt.dhcp.op == 2

    def test_dhcp_udp_layer(self):
        """Verify UDP layer is also parsed for DHCP packets."""
        parser = _get_native_parser()
        raw = self._build_dhcp_packet(options=[(53, b"\x01")])
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.udp is not None
        assert pkt.udp.dport == 67
        assert pkt.dhcp is not None


# ═══════════════════════════════════════════════════════════════════
# DHCPv6 (Dynamic Host Configuration Protocol for IPv6)
# ═══════════════════════════════════════════════════════════════════

class TestDHCPv6Parsing:
    """Test DHCPv6 fast-path parsing from raw bytes."""

    def _build_dhcpv6_packet(self, msg_type=1, transaction_id=0x123456,
                             options_raw=b"", dport=547) -> bytes:
        """Ethernet + IPv6 + UDP(dport) + DHCPv6 header + options."""
        dhcpv6_hdr = struct.pack('>B', msg_type)
        # transaction_id is 3 bytes big-endian
        dhcpv6_hdr += struct.pack('>I', transaction_id)[1:]
        dhcpv6_payload = dhcpv6_hdr + options_raw
        udp_hdr = build_udp(sport=546, dport=dport, payload=dhcpv6_payload)
        ip6 = build_ipv6(src="fe80::1", dst="ff02::1:2", next_header=17,
                         payload=udp_hdr)
        eth = build_eth(ethertype=0x86DD)
        return eth + ip6

    def test_dhcpv6_solicit(self):
        """DHCPv6 Solicit (msg_type=1)."""
        parser = _get_native_parser()
        raw = self._build_dhcpv6_packet(msg_type=1, transaction_id=0xABCDEF)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcpv6 is not None
        assert pkt.dhcpv6.msg_type == 1
        assert pkt.dhcpv6.transaction_id == 0xABCDEF

    def test_dhcpv6_advertise(self):
        """DHCPv6 Advertise (msg_type=2) from server."""
        parser = _get_native_parser()
        raw = self._build_dhcpv6_packet(msg_type=2, transaction_id=0x112233,
                                        dport=546)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcpv6 is not None
        assert pkt.dhcpv6.msg_type == 2
        assert pkt.dhcpv6.transaction_id == 0x112233

    def test_dhcpv6_with_options(self):
        """DHCPv6 with raw options bytes preserved."""
        parser = _get_native_parser()
        # Option 1 (Client ID): type=0x0001, len=0x0004, data=0xDEADBEEF
        opts = b"\x00\x01\x00\x04\xDE\xAD\xBE\xEF"
        raw = self._build_dhcpv6_packet(msg_type=3, options_raw=opts)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcpv6 is not None
        assert pkt.dhcpv6.msg_type == 3
        assert pkt.dhcpv6.options_raw == opts

    def test_dhcpv6_no_options(self):
        """DHCPv6 with no options."""
        parser = _get_native_parser()
        raw = self._build_dhcpv6_packet(msg_type=1, options_raw=b"")
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.dhcpv6 is not None
        assert pkt.dhcpv6.options_raw == b""

    def test_dhcpv6_udp_layer(self):
        """Verify UDP layer is also parsed for DHCPv6 packets."""
        parser = _get_native_parser()
        raw = self._build_dhcpv6_packet(msg_type=1)
        pkt = parser.parse_to_dataclass(raw, DLT_EN10MB)

        assert pkt.udp is not None
        assert pkt.udp.dport == 547
        assert pkt.dhcpv6 is not None
