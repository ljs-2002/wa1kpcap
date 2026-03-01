"""Test TLS integration with multi.pcap."""

import pytest
import os

from conftest import MULTI_PCAP
from wa1kpcap import Wa1kPcap
from wa1kpcap.core.packet import TLSInfo


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


def test_native_tls_flow_sni_content():
    """Test that native engine TLS flows have actual SNI domain names."""
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
