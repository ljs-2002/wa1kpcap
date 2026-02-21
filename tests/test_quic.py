"""Tests for QUIC protocol parsing, decryption, and flow-state Short Header identification."""

import struct
import pytest

from wa1kpcap.core.packet import QUICInfo, ParsedPacket, UDPInfo, IPInfo


# ── Helpers: build synthetic packets ──

def _build_eth_ipv4_udp(udp_payload: bytes, sport=12345, dport=443,
                         src_ip="192.168.1.1", dst_ip="10.0.0.1") -> bytes:
    """Build Ethernet + IPv4 + UDP + payload."""
    # UDP header
    udp_len = 8 + len(udp_payload)
    udp_hdr = struct.pack(">HHHH", sport, dport, udp_len, 0)

    # IPv4 header (20 bytes, proto=17 UDP)
    ip_total = 20 + udp_len
    ip_hdr = (
        b"\x45\x00"
        + struct.pack(">H", ip_total)
        + b"\x00\x00\x00\x00\x40\x11\x00\x00"
        + _ip_to_bytes(src_ip)
        + _ip_to_bytes(dst_ip)
    )

    # Ethernet header (14 bytes, type=0x0800)
    eth_hdr = b"\x00" * 12 + b"\x08\x00"

    return eth_hdr + ip_hdr + udp_hdr + udp_payload


def _ip_to_bytes(ip_str: str) -> bytes:
    return bytes(int(x) for x in ip_str.split("."))


def _build_quic_long_header(packet_type=0, version=0x00000001,
                             dcid=b"\x08\x39\x4c\x2a\x11\x22\x33\x44",
                             scid=b"", token=b"",
                             payload=b"\x00" * 50) -> bytes:
    """Build a QUIC Long Header packet (Initial by default)."""
    first_byte = 0xc0 | (packet_type << 4)
    header = bytes([first_byte])
    header += struct.pack(">I", version)
    header += bytes([len(dcid)]) + dcid
    header += bytes([len(scid)]) + scid

    # Token (only for Initial, type=0)
    if packet_type == 0:
        header += bytes([len(token)]) + token

    # Payload length as varint (1-byte for < 64)
    header += bytes([len(payload)])
    return header + payload


def _build_quic_short_header(spin_bit=True, dcid=b"\x08\x39\x4c\x2a\x11\x22\x33\x44",
                              payload=b"\x00" * 30) -> bytes:
    """Build a QUIC Short Header (1-RTT) packet."""
    # Bit 7 = 0 (short), Bit 6 = 1 (fixed), Bit 5 = spin_bit
    first_byte = 0x40 | (0x20 if spin_bit else 0x00)
    return bytes([first_byte]) + dcid + payload


# ── Test: QUICInfo dataclass ──

class TestQUICInfo:
    def test_default_values(self):
        q = QUICInfo()
        assert q.is_long_header is True
        assert q.packet_type == 0
        assert q.version == 0
        assert q.dcid == b""
        assert q.scid == b""
        assert q.spin_bit is False
        assert q.sni is None
        assert q.alpn is None
        assert q.cipher_suites is None
        assert q.version_str == ""
        assert q.packet_type_str == ""

    def test_long_header_values(self):
        q = QUICInfo(
            is_long_header=True,
            packet_type=0,
            version=0x00000001,
            dcid=b"\x01\x02\x03\x04",
            dcid_len=4,
            version_str="QUICv1",
            packet_type_str="Initial",
        )
        assert q.is_long_header is True
        assert q.version == 0x00000001
        assert q.dcid_len == 4
        assert q.version_str == "QUICv1"
        assert q.packet_type_str == "Initial"

    def test_short_header_values(self):
        q = QUICInfo(
            is_long_header=False,
            spin_bit=True,
            dcid=b"\xaa\xbb",
            dcid_len=2,
            packet_type_str="1-RTT",
        )
        assert q.is_long_header is False
        assert q.spin_bit is True
        assert q.dcid == b"\xaa\xbb"
        assert q.packet_type_str == "1-RTT"

    def test_fields_constructor(self):
        q = QUICInfo(fields={
            "is_long_header": False,
            "spin_bit": True,
            "sni": "example.com",
            "alpn": ["h3"],
        })
        assert q.is_long_header is False
        assert q.spin_bit is True
        assert q.sni == "example.com"
        assert q.alpn == ["h3"]

    def test_merge(self):
        """merge() copies None fields from other — non-None fields are kept."""
        q1 = QUICInfo(is_long_header=True, sni="example.com", version=1)
        q2 = QUICInfo(is_long_header=False, alpn=["h3"])
        q1.merge(q2)  # merge is in-place, only fills None slots
        assert q1.sni == "example.com"
        assert q1.alpn == ["h3"]  # was None in q1, filled from q2

    def test_fields_property(self):
        q = QUICInfo(version=1, sni="test.com")
        d = q._fields
        assert d["version"] == 1
        assert d["sni"] == "test.com"


# ── Test: Native struct path — Long Header parsing ──

class TestQUICLongHeaderStruct:
    @pytest.fixture(autouse=True)
    def setup_engine(self):
        try:
            from wa1kpcap.native.engine import NativeEngine
            self.engine = NativeEngine()
        except (ImportError, RuntimeError):
            pytest.skip("Native engine not available")

    def test_initial_v1(self):
        dcid = b"\x08\x39\x4c\x2a\x11\x22\x33\x44"
        quic_pkt = _build_quic_long_header(
            packet_type=0, version=0x00000001, dcid=dcid)
        raw = _build_eth_ipv4_udp(quic_pkt)
        pkt = self.engine._parser.parse_packet_struct(raw, 1)
        q = pkt.quic
        assert q is not None
        assert q.is_long_header is True
        assert q.version == 0x00000001
        assert q.packet_type == 0
        assert q.packet_type_str == "Initial"
        assert q.version_str == "QUICv1"
        assert q.dcid_len == len(dcid)

    def test_initial_v2(self):
        dcid = b"\xaa\xbb\xcc\xdd"
        # QUIC v2: Initial type is 0b01
        quic_pkt = _build_quic_long_header(
            packet_type=1, version=0x6b3343cf, dcid=dcid)
        raw = _build_eth_ipv4_udp(quic_pkt)
        pkt = self.engine._parser.parse_packet_struct(raw, 1)
        q = pkt.quic
        assert q is not None
        assert q.version == 0x6b3343cf
        assert q.version_str == "QUICv2"

    def test_handshake_type(self):
        dcid = b"\x01\x02\x03\x04"
        quic_pkt = _build_quic_long_header(
            packet_type=2, version=0x00000001, dcid=dcid)
        raw = _build_eth_ipv4_udp(quic_pkt)
        pkt = self.engine._parser.parse_packet_struct(raw, 1)
        q = pkt.quic
        assert q is not None
        assert q.packet_type == 2
        assert q.packet_type_str == "Handshake"

    def test_empty_dcid(self):
        quic_pkt = _build_quic_long_header(
            packet_type=0, version=0x00000001, dcid=b"")
        raw = _build_eth_ipv4_udp(quic_pkt)
        pkt = self.engine._parser.parse_packet_struct(raw, 1)
        q = pkt.quic
        assert q is not None
        assert q.dcid_len == 0

    def test_with_scid(self):
        dcid = b"\x01\x02\x03\x04"
        scid = b"\xaa\xbb\xcc\xdd\xee"
        quic_pkt = _build_quic_long_header(
            packet_type=0, version=0x00000001, dcid=dcid, scid=scid)
        raw = _build_eth_ipv4_udp(quic_pkt)
        pkt = self.engine._parser.parse_packet_struct(raw, 1)
        q = pkt.quic
        assert q is not None
        assert q.dcid_len == 4
        assert q.scid_len == 5

    def test_decryption_fails_gracefully(self):
        """Fake payload should not crash — decryption fails, fields stay empty."""
        dcid = b"\x08\x39\x4c\x2a\x11\x22\x33\x44"
        quic_pkt = _build_quic_long_header(
            packet_type=0, version=0x00000001, dcid=dcid,
            payload=b"\x00" * 100)
        raw = _build_eth_ipv4_udp(quic_pkt)
        pkt = self.engine._parser.parse_packet_struct(raw, 1)
        q = pkt.quic
        assert q is not None
        assert q.sni == ""
        assert list(q.alpn) == []
        assert list(q.cipher_suites) == []


# ── Test: Short Header flow-state identification ──

class TestQUICShortHeaderFlowState:
    def test_short_header_identification(self):
        """After seeing a Long Header, Short Header on same flow should be parsed."""
        from wa1kpcap.core.flow import Flow, FlowKey

        dcid = b"\x08\x39\x4c\x2a\x11\x22\x33\x44"

        # Simulate a flow that has seen a QUIC Initial
        key = FlowKey(
            src_ip="192.168.1.1", dst_ip="10.0.0.1",
            src_port=12345, dst_port=443, protocol=17
        )
        flow = Flow(key=key)
        flow._is_quic = True
        flow._quic_dcid_len = len(dcid)

        # Build a Short Header packet
        short_hdr = _build_quic_short_header(spin_bit=True, dcid=dcid)
        raw = _build_eth_ipv4_udp(short_hdr)

        pkt = ParsedPacket(
            timestamp=1.0,
            raw_data=raw,
            link_layer_type=1,
            caplen=len(raw),
            wirelen=len(raw),
        )
        pkt.ip = IPInfo(
            src="192.168.1.1", dst="10.0.0.1", proto=17,
            ttl=64, len=len(raw) - 14,
        )
        pkt.udp = UDPInfo(sport=12345, dport=443, len=len(raw) - 34)
        # app_len = UDP payload length
        pkt.app_len = len(short_hdr)

        # Import and call the handler directly
        from wa1kpcap.core.analyzer import Wa1kPcap
        analyzer = Wa1kPcap.__new__(Wa1kPcap)
        analyzer._handle_quic_flow_state(pkt, flow)

        q = pkt.quic
        assert q is not None
        assert q.is_long_header is False
        assert q.spin_bit is True
        assert q.dcid == dcid
        assert q.dcid_len == len(dcid)
        assert q.packet_type_str == "1-RTT"

    def test_short_header_spin_bit_false(self):
        """Short Header with spin_bit=False."""
        from wa1kpcap.core.flow import Flow, FlowKey

        dcid = b"\x01\x02\x03\x04"
        key = FlowKey(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=443, protocol=17
        )
        flow = Flow(key=key)
        flow._is_quic = True
        flow._quic_dcid_len = len(dcid)

        short_hdr = _build_quic_short_header(spin_bit=False, dcid=dcid)
        raw = _build_eth_ipv4_udp(short_hdr, sport=5000, dport=443,
                                   src_ip="10.0.0.1", dst_ip="10.0.0.2")
        pkt = ParsedPacket(
            timestamp=2.0, raw_data=raw, link_layer_type=1,
            caplen=len(raw), wirelen=len(raw),
        )
        pkt.ip = IPInfo(src="10.0.0.1", dst="10.0.0.2", proto=17, ttl=64, len=len(raw) - 14)
        pkt.udp = UDPInfo(sport=5000, dport=443, len=len(raw) - 34)
        pkt.app_len = len(short_hdr)

        from wa1kpcap.core.analyzer import Wa1kPcap
        analyzer = Wa1kPcap.__new__(Wa1kPcap)
        analyzer._handle_quic_flow_state(pkt, flow)

        assert pkt.quic is not None
        assert pkt.quic.spin_bit is False

    def test_non_quic_flow_ignored(self):
        """UDP packet on non-QUIC flow should not be parsed as QUIC."""
        from wa1kpcap.core.flow import Flow, FlowKey

        key = FlowKey(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=53, protocol=17
        )
        flow = Flow(key=key)
        # _is_quic defaults to False

        raw = _build_eth_ipv4_udp(b"\x40\x01\x02\x03\x04" + b"\x00" * 20,
                                   sport=5000, dport=53)
        pkt = ParsedPacket(
            timestamp=3.0, raw_data=raw, link_layer_type=1,
            caplen=len(raw), wirelen=len(raw),
        )
        pkt.udp = UDPInfo(sport=5000, dport=53, len=len(raw) - 34)
        pkt.app_len = 25

        from wa1kpcap.core.analyzer import Wa1kPcap
        analyzer = Wa1kPcap.__new__(Wa1kPcap)
        analyzer._handle_quic_flow_state(pkt, flow)

        assert pkt.quic is None

    def test_long_header_marks_flow(self):
        """Seeing a Long Header should mark the flow as QUIC."""
        from wa1kpcap.core.flow import Flow, FlowKey

        key = FlowKey(
            src_ip="10.0.0.1", dst_ip="10.0.0.2",
            src_port=5000, dst_port=443, protocol=17
        )
        flow = Flow(key=key)
        assert flow._is_quic is False

        pkt = ParsedPacket(
            timestamp=1.0, raw_data=b"", link_layer_type=1,
            caplen=0, wirelen=0,
        )
        pkt.quic = QUICInfo(
            is_long_header=True, packet_type=0,
            version=0x00000001, dcid=b"\x01\x02\x03\x04",
            dcid_len=4, version_str="QUICv1", packet_type_str="Initial",
        )

        from wa1kpcap.core.analyzer import Wa1kPcap
        analyzer = Wa1kPcap.__new__(Wa1kPcap)
        analyzer._handle_quic_flow_state(pkt, flow)

        assert flow._is_quic is True
        assert flow._quic_dcid_len == 4


# ── Test: RFC 9001 Appendix A crypto test vectors ──

class TestQUICCryptoVectors:
    """Verify HKDF / key derivation against RFC 9001 Appendix A values."""

    @pytest.fixture(autouse=True)
    def setup_native(self):
        try:
            from wa1kpcap._wa1kpcap_native import NativeParser
            self._available = True
        except ImportError:
            self._available = False

    def _skip_if_unavailable(self):
        if not self._available:
            pytest.skip("Native module not available")

    def test_sha256_empty(self):
        """SHA-256 of empty string should match known value."""
        self._skip_if_unavailable()
        from wa1kpcap._wa1kpcap_native import quic_sha256
        digest = quic_sha256(b"")
        expected = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert bytes(digest) == expected

    def test_sha256_abc(self):
        """SHA-256 of 'abc'."""
        self._skip_if_unavailable()
        from wa1kpcap._wa1kpcap_native import quic_sha256
        digest = quic_sha256(b"abc")
        expected = bytes.fromhex(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        assert bytes(digest) == expected

    def test_hmac_sha256(self):
        """HMAC-SHA256 test vector from RFC 4231 Test Case 2."""
        self._skip_if_unavailable()
        from wa1kpcap._wa1kpcap_native import quic_hmac_sha256
        key = b"Jefe"
        data = b"what do ya want for nothing?"
        mac = quic_hmac_sha256(key, data)
        expected = bytes.fromhex(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        )
        assert bytes(mac) == expected

    def test_hkdf_extract_rfc9001_initial_secret(self):
        """RFC 9001 Appendix A.1: initial_secret from DCID 0x8394c8f03e515708."""
        self._skip_if_unavailable()
        from wa1kpcap._wa1kpcap_native import quic_hkdf_extract
        salt = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
        dcid = bytes.fromhex("8394c8f03e515708")
        initial_secret = quic_hkdf_extract(salt, dcid)
        expected = bytes.fromhex(
            "7db5df06e7a69e432496adedb008519235952215"
            "96ae2ae9fb8115c1e9ed0a44"
        )
        assert bytes(initial_secret) == expected


# ── Test: exports ──

class TestQUICExports:
    def test_core_init_exports(self):
        from wa1kpcap.core import QUICInfo
        assert QUICInfo is not None

    def test_packet_module_exports(self):
        from wa1kpcap.core.packet import QUICInfo
        assert QUICInfo is not None
