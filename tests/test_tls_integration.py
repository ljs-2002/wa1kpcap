"""Test TLS integration with multi.pcap and scapy-generated packets."""

import pytest
import sys
import os

from conftest import MULTI_PCAP
from wa1kpcap import Wa1kPcap
from wa1kpcap.protocols.application import TLSFlowState, parse_tls, parse_cert_der, get_extension_name
from wa1kpcap.core.flow import Flow, FlowKey
from wa1kpcap.core.packet import ParsedPacket, TLSInfo


# Test with real pcap file (multi.pcap contains TLS flows)
def test_tls_with_multi_pcap():
    """Test TLS parsing with real multi.pcap file."""
    pcap_path = MULTI_PCAP

    if not os.path.exists(pcap_path):
        pytest.skip("multi.pcap not found")

    analyzer = Wa1kPcap(verbose_mode=True)
    flows = analyzer.analyze_file(pcap_path)

    # Should have TLS flows
    tls_flows = [f for f in flows if f.tls]
    assert len(tls_flows) > 0, "Should have at least one TLS flow"

    # Find a flow with certificates
    cert_flows = [f for f in tls_flows if f.tls.certificate]
    if cert_flows:
        flow = cert_flows[0]

        # Verify TLS info
        assert flow.tls is not None
        assert flow.tls.version is not None

        # Verify certificate is raw DER bytes
        assert flow.tls.certificate is not None
        assert isinstance(flow.tls.certificate, bytes)
        assert len(flow.tls.certificate) > 0
        # Verify parse_cert_der can parse it
        parsed = parse_cert_der(flow.tls.certificate)
        assert parsed is not None
        assert 'subject' in parsed
        assert 'issuer' in parsed

        # Verify exts dictionary
        assert isinstance(flow.tls.exts, dict)
        if flow.tls.exts:
            # Test get_extension method
            for ext_type in flow.tls.exts.keys():
                ext_list = flow.tls.get_extension(ext_type)
                assert ext_list is not None
                assert isinstance(ext_list, list)
                break

    # Verify sni and alpn are always lists
    for flow in tls_flows:
        assert isinstance(flow.tls.sni, list)
        assert isinstance(flow.tls.alpn, list)
        assert isinstance(flow.tls.signature_algorithms, list)
        assert isinstance(flow.tls.supported_groups, list)


def test_tls_flow_state():
    """Test TLSFlowState class."""
    state = TLSFlowState()

    # Test initial values
    assert state.version is not None
    assert state.sni == []
    assert state.alpn == []
    assert state.signature_algorithms == []
    assert state.supported_groups == []
    assert state.certs == []
    assert state.exts == {}


def test_parse_tls_basic():
    """Test parse_tls function with basic data."""
    import dpkt.ssl

    # Create a simple ClientHello
    # This is a minimal TLS ClientHello record
    client_hello = (
        b'\x16'  # Content type: Handshake (22)
        b'\x03\x01'  # Version: TLS 1.0
        b'\x00\x00'  # Length (placeholder, will fix)
    )

    # For now just test with empty data
    state = None
    new_state, parsed = parse_tls(b'', state)

    assert isinstance(new_state, TLSFlowState)
    assert parsed == 0


def test_tls_info_properties():
    """Test TLSInfo properties."""
    tls_info = TLSInfo()

    # Test default values
    assert tls_info.version is None
    assert tls_info.content_type is None
    assert tls_info.sni == []
    assert tls_info.alpn == []
    assert tls_info.signature_algorithms == []
    assert tls_info.supported_groups == []
    assert tls_info.exts == {}
    assert tls_info.extensions == []

    # Test with values
    tls_info.sni = ["example.com"]
    tls_info.alpn = ["h2", "http/1.1"]
    tls_info.exts = {0: [b"data"]}
    tls_info.extensions = [(0, b"data")]

    assert tls_info.sni == ["example.com"]
    assert tls_info.alpn == ["h2", "http/1.1"]
    assert 0 in tls_info.exts


def test_get_extension_name():
    """Test extension name mapping."""
    assert get_extension_name(0) == "server_name"
    assert get_extension_name(16) == "application_layer_protocol_negotiation"
    assert get_extension_name(13) == "signature_algorithms"
    assert get_extension_name(10) == "supported_groups"
    assert get_extension_name(999) == "unknown_999"


def test_tls_info_get_extension():
    """Test TLSInfo.get_extension method."""
    tls_info = TLSInfo()

    # Empty exts
    assert tls_info.get_extension(0) is None
    assert tls_info.get_extension_first(0) is None

    # With data
    tls_info.exts = {0: [b"data1", b"data2"]}
    assert tls_info.get_extension(0) == [b"data1", b"data2"]
    assert tls_info.get_extension_first(0) == b"data1"


def test_parse_cert_der():
    """Test certificate DER parsing."""
    # Test with invalid data
    result = parse_cert_der(b"invalid cert data")
    assert result is None

    # Test with empty data
    result = parse_cert_der(b"")
    assert result is None


def test_tls_content_type_names():
    """Test TLSInfo content type names."""
    tls_info = TLSInfo()

    tls_info.content_type = 22
    assert tls_info.content_type_name == "handshake"

    tls_info.content_type = 23
    assert tls_info.content_type_name == "application_data"

    tls_info.content_type = 20
    assert tls_info.content_type_name == "change_cipher_spec"

    tls_info.content_type = 21
    assert tls_info.content_type_name == "alert"

    tls_info.content_type = 24
    assert tls_info.content_type_name == "heartbeat"


def test_tls_handshake_type_names():
    """Test TLSInfo handshake type names."""
    tls_info = TLSInfo()

    tls_info.handshake_type = 1
    assert tls_info.handshake_type_name == "client_hello"

    tls_info.handshake_type = 2
    assert tls_info.handshake_type_name == "server_hello"

    tls_info.handshake_type = 11
    assert tls_info.handshake_type_name == "certificate"

    tls_info.handshake_type = 14
    assert tls_info.handshake_type_name == "server_hello_done"


def test_tls_version_name():
    """Test TLSInfo version name property."""
    tls_info = TLSInfo()

    tls_info.version = "3.1"
    assert tls_info.version_name == "TLS 1.0"

    tls_info.version = "3.2"
    assert tls_info.version_name == "TLS 1.1"

    tls_info.version = "3.3"
    assert tls_info.version_name == "TLS 1.2"

    tls_info.version = "3.4"
    assert tls_info.version_name == "TLS 1.3"

    tls_info.version = "unknown"
    assert tls_info.version_name == "unknown"


def test_flow_tls_state_integration():
    """Test Flow with TLS state integration."""
    key = FlowKey(
        src_ip='192.168.1.1',
        dst_ip='10.0.0.1',
        src_port=1234,
        dst_port=443,
        protocol=6
    )

    flow = Flow(key=key, start_time=0.0)

    # Verify TLS state initialization
    assert flow._tls_state is None
    assert flow._tls_incomplete_data == {1: b"", -1: b""}


def test_native_tls_flow_sni_content():
    """Test that native engine TLS flows have actual SNI domain names, not just list type."""
    pcap_path = MULTI_PCAP
    if not os.path.exists(pcap_path):
        pytest.skip("multi.pcap not found")

    analyzer = Wa1kPcap(verbose_mode=True)
    flows = analyzer.analyze_file(pcap_path)
    tls_flows = [f for f in flows if f.tls and f.tls.sni]
    assert len(tls_flows) > 0, "Should have TLS flows with SNI"

    for flow in tls_flows:
        for sni in flow.tls.sni:
            assert isinstance(sni, str), f"SNI should be str, got {type(sni)}"
            assert len(sni) > 0, "SNI should not be empty string"
            assert '.' in sni, f"SNI should be a domain name, got '{sni}'"


def test_native_tls_flow_certificates():
    """Test that native engine extracts TLS certificates at flow level."""
    pcap_path = MULTI_PCAP
    if not os.path.exists(pcap_path):
        pytest.skip("multi.pcap not found")

    analyzer = Wa1kPcap(verbose_mode=True)
    flows = analyzer.analyze_file(pcap_path)
    cert_flows = [f for f in flows if f.tls and f.tls.certificates]
    assert len(cert_flows) > 0, "Should have TLS flows with certificates"

    for flow in cert_flows:
        assert isinstance(flow.tls.certificates, list)
        for cert in flow.tls.certificates:
            assert isinstance(cert, bytes), f"Certificate should be bytes, got {type(cert)}"
            assert len(cert) > 0, "Certificate should not be empty"
        # certificate (singular) should be the first cert
        assert flow.tls.certificate == flow.tls.certificates[0]
        # Verify parse_cert_der can parse it
        parsed = parse_cert_der(flow.tls.certificate)
        if parsed is not None:
            assert 'subject' in parsed
            assert 'issuer' in parsed


def test_native_tls_flow_cipher_suite():
    """Test that native engine extracts ServerHello cipher_suite at flow level."""
    pcap_path = MULTI_PCAP
    if not os.path.exists(pcap_path):
        pytest.skip("multi.pcap not found")

    analyzer = Wa1kPcap(verbose_mode=True)
    flows = analyzer.analyze_file(pcap_path)
    tls_flows = [f for f in flows if f.tls and f.tls.cipher_suite is not None]
    assert len(tls_flows) > 0, "Should have TLS flows with cipher_suite"

    for flow in tls_flows:
        assert isinstance(flow.tls.cipher_suite, int)
        assert flow.tls.cipher_suite > 0, "cipher_suite should be positive"


def test_native_tls_flow_handshake_types():
    """Test that native engine populates _handshake_types at flow level."""
    pcap_path = MULTI_PCAP
    if not os.path.exists(pcap_path):
        pytest.skip("multi.pcap not found")

    analyzer = Wa1kPcap(verbose_mode=True)
    flows = analyzer.analyze_file(pcap_path)
    tls_flows = [f for f in flows if f.tls]
    assert len(tls_flows) > 0

    has_handshake_types = False
    for flow in tls_flows:
        if hasattr(flow.tls, '_handshake_types') and flow.tls._handshake_types:
            has_handshake_types = True
            for ht in flow.tls._handshake_types:
                assert isinstance(ht, int)
                assert 0 <= ht <= 255
            break
    assert has_handshake_types, "At least one TLS flow should have _handshake_types"
    test_tls_flow_state()
    test_parse_tls_basic()
    test_tls_info_properties()
    test_get_extension_name()
    test_tls_info_get_extension()
    test_parse_cert_der()
    test_tls_content_type_names()
    test_tls_handshake_type_names()
    test_tls_version_name()
    test_flow_tls_state_integration()
    print("test_tls_integration PASSED")
