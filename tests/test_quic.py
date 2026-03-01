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


# ── Test: End-to-end integration with real pcap ──

QUIC2_PCAP = "test/quic2.pcap"

class TestQUICIntegration:
    """Integration tests using real QUIC pcap — validates the full pipeline:
    parsing → decryption → CRYPTO frame reassembly → TLS ClientHello extraction.
    """

    @pytest.fixture(autouse=True)
    def setup(self):
        import os
        if not os.path.exists(QUIC2_PCAP):
            pytest.skip("test/quic2.pcap not found")
        try:
            from wa1kpcap import Wa1kPcap
            self.analyzer = Wa1kPcap(default_filter=None, app_layer_parsing='full')
            self.flows = self.analyzer.analyze_file(QUIC2_PCAP)
        except Exception as e:
            pytest.skip(f"Cannot analyze pcap: {e}")

    def test_flow_count(self):
        """Should detect 22 flows."""
        assert len(self.flows) == 22

    def test_quic_layer_count(self):
        """Flows with a captured Initial (Long Header) should have a QUIC layer.
        Flows that only contain Short Header packets (missed handshake) won't."""
        quic_flows = [f for f in self.flows if f.quic is not None]
        assert len(quic_flows) == 20  # 2 flows have only Short Header (no Initial)

    def test_quic_v1_sni_extraction(self):
        """All QUIC v1 flows should have SNI extracted via Initial decryption."""
        v1_flows = [f for f in self.flows if f.quic and f.quic.version == 1]
        assert len(v1_flows) >= 20  # at least 20 v1 flows
        for flow in v1_flows:
            assert flow.quic.sni is not None and flow.quic.sni != "", \
                f"Flow {flow.key} missing SNI"

    def test_quic_v1_alpn(self):
        """All QUIC v1 flows should have ALPN=['h3']."""
        v1_flows = [f for f in self.flows if f.quic and f.quic.version == 1]
        for flow in v1_flows:
            assert flow.quic.alpn == ['h3'], \
                f"Flow {flow.key} unexpected ALPN: {flow.quic.alpn}"

    def test_quic_v1_cipher_suites(self):
        """All QUIC v1 flows should have TLS 1.3 cipher suites."""
        tls13_suites = {4865, 4866, 4867}  # AES-128-GCM, AES-256-GCM, CHACHA20
        v1_flows = [f for f in self.flows if f.quic and f.quic.version == 1]
        for flow in v1_flows:
            assert set(flow.quic.cipher_suites) <= tls13_suites, \
                f"Flow {flow.key} unexpected suites: {flow.quic.cipher_suites}"

    def test_known_sni_values(self):
        """Spot-check specific SNI values we know are in the pcap."""
        sni_set = {f.quic.sni for f in self.flows if f.quic and f.quic.sni}
        expected = {
            'unpkg.zhimg.com', 'captcha.zhihu.com', 'apm.zhihu.com',
            'fonts.gstatic.com', 'fonts.googleapis.com', 'cdn.jsdelivr.net',
            'www.redditstatic.com', 'www.logitechg.com',
        }
        assert expected <= sni_set, f"Missing SNIs: {expected - sni_set}"

    def test_ext_protocol_contains_quic(self):
        """ext_protocol should include 'QUIC' for flows with a QUIC layer."""
        for flow in self.flows:
            if flow.quic is not None:
                assert 'QUIC' in flow.ext_protocol, \
                    f"Flow {flow.key} ext_protocol={flow.ext_protocol}"

    def test_flow_quic_property(self):
        """flow.quic should be accessible and match flow.layers['quic']."""
        for flow in self.flows:
            assert flow.quic is flow.layers.get('quic')

    def test_packet_level_quic(self):
        """First packet of flows with QUIC layer should have pkt.quic set."""
        for flow in self.flows:
            if flow.quic is not None and flow.packets:
                pkt = flow.packets[0]
                assert pkt.quic is not None, \
                    f"Flow {flow.key} first packet missing quic"

    def test_dcid_from_client_initial(self):
        """Flow-level DCID should come from the client's Initial packet."""
        for flow in self.flows:
            if flow.quic is None or not flow.quic.dcid:
                continue
            # First packet should be C2S Initial with matching DCID
            pkt0 = flow.packets[0]
            assert pkt0.is_client_to_server is True, \
                f"Flow {flow.key}: first packet should be C2S"
            assert pkt0.quic is not None
            assert flow.quic.dcid == pkt0.quic.dcid, \
                f"Flow {flow.key}: flow DCID should match first C2S Initial DCID"

    def test_scid_from_server_initial(self):
        """Flow-level SCID should come from the server's Initial packet (S2C)."""
        for flow in self.flows:
            if flow.quic is None or not flow.quic.scid:
                continue
            # Find first S2C packet with SCID
            server_scid = None
            for pkt in flow.packets:
                if not pkt.is_client_to_server and pkt.quic and pkt.quic.scid:
                    server_scid = pkt.quic.scid
                    break
            assert server_scid is not None, \
                f"Flow {flow.key}: should have a S2C packet with SCID"
            assert flow.quic.scid == server_scid, \
                f"Flow {flow.key}: flow SCID should match first S2C Initial SCID"

    def test_packet_direction_correctness(self):
        """Verify is_client_to_server is correct based on IP addresses."""
        for flow in self.flows:
            if flow.quic is None:
                continue
            src_ip = flow.key.src_ip
            for pkt in flow.packets[:4]:
                if pkt.ip:
                    if pkt.ip.src == src_ip:
                        assert pkt.is_client_to_server is True, \
                            f"Flow {flow.key}: pkt from {pkt.ip.src} should be C2S"
                    else:
                        assert pkt.is_client_to_server is False, \
                            f"Flow {flow.key}: pkt from {pkt.ip.src} should be S2C"

