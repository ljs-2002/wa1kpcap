"""
Tests for ext_protocol field in Flow.
"""

import pytest
from wa1kpcap import Wa1kPcap
from wa1kpcap.core.flow import Flow, FlowKey
from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo, TLSInfo


def test_flow_ext_protocol_initial():
    """Test that ext_protocol is initialized as empty list."""
    flow = Flow(key=FlowKey("192.168.1.1", "10.0.0.1", 1234, 80, 6))
    assert flow.ext_protocol == []


def test_flow_build_ext_protocol_tcp():
    """Test build_ext_protocol for TCP flow."""
    from wa1kpcap.core.flow import Flow, FlowKey
    from wa1kpcap.core.packet import ParsedPacket, IPInfo

    flow = Flow(key=FlowKey("192.168.1.1", "10.0.0.1", 1234, 80, 6))

    # Create a mock packet with IPv4 and TCP
    pkt = ParsedPacket(timestamp=0.0)
    pkt.ip = IPInfo(
        version=4,
        src="192.168.1.1",
        dst="10.0.0.1",
        proto=6,
        ttl=64,
        len=100,
        id=12345,
        flags=0,
        offset=0
    )
    pkt.tcp = type('obj', (object,), {'sport': 1234, 'dport': 80})()
    flow.packets.append(pkt)

    result = flow.build_ext_protocol()
    assert result == ["IPv4", "TCP"]
    assert flow.ext_protocol == ["IPv4", "TCP"]


def test_flow_build_ext_protocol_tls_with_https():
    """Test build_ext_protocol for TLS flow with HTTPS ALPN."""
    from wa1kpcap.core.flow import Flow, FlowKey
    from wa1kpcap.core.packet import ParsedPacket, IPInfo, TLSInfo

    flow = Flow(key=FlowKey("192.168.1.1", "10.0.0.1", 1234, 443, 6))

    # Create a mock packet with IPv4 and TCP
    pkt = ParsedPacket(timestamp=0.0)
    pkt.ip = IPInfo(
        version=4,
        src="192.168.1.1",
        dst="10.0.0.1",
        proto=6,
        ttl=64,
        len=100,
        id=12345,
        flags=0,
        offset=0
    )
    pkt.tcp = type('obj', (object,), {'sport': 1234, 'dport': 443})()
    flow.packets.append(pkt)

    # Create TLS info with h2 ALPN
    flow.tls = TLSInfo(version="TLS 1.2", content_type=22, record_length=0)
    flow.tls.alpn = ["h2", "http/1.1"]

    result = flow.build_ext_protocol()
    assert result == ["IPv4", "TCP", "TLS", "HTTPS"]
    assert flow.ext_protocol == ["IPv4", "TCP", "TLS", "HTTPS"]


def test_flow_build_ext_protocol_tls_without_https():
    """Test build_ext_protocol for TLS flow without HTTPS ALPN."""
    from wa1kpcap.core.flow import Flow, FlowKey
    from wa1kpcap.core.packet import ParsedPacket, IPInfo, TLSInfo

    flow = Flow(key=FlowKey("192.168.1.1", "10.0.0.1", 1234, 443, 6))

    # Create a mock packet with IPv4 and TCP
    pkt = ParsedPacket(timestamp=0.0)
    pkt.ip = IPInfo(
        version=4,
        src="192.168.1.1",
        dst="10.0.0.1",
        proto=6,
        ttl=64,
        len=100,
        id=12345,
        flags=0,
        offset=0
    )
    pkt.tcp = type('obj', (object,), {'sport': 1234, 'dport': 443})()
    flow.packets.append(pkt)

    # Create TLS info without HTTPS ALPN
    flow.tls = TLSInfo(version="TLS 1.0", content_type=22, record_length=0)
    flow.tls.alpn = []

    result = flow.build_ext_protocol()
    assert result == ["IPv4", "TCP", "TLS"]
    assert flow.ext_protocol == ["IPv4", "TCP", "TLS"]


def test_flow_build_ext_protocol_ipv6_udp_dns():
    """Test build_ext_protocol for IPv6 UDP DNS flow."""
    from wa1kpcap.core.flow import Flow, FlowKey
    from wa1kpcap.core.packet import ParsedPacket, IP6Info, DNSInfo

    flow = Flow(key=FlowKey("fe80::1", "ff02::fb", 1234, 53, 17))

    # Create a mock packet with IPv6 and UDP
    pkt = ParsedPacket(timestamp=0.0)
    pkt.ip6 = IP6Info(
        version=6,
        src="fe80::1",
        dst="ff02::fb",
        next_header=17,
        hop_limit=255,
        flow_label=0,
        len=100
    )
    pkt.udp = type('obj', (object,), {'sport': 1234, 'dport': 53})()
    flow.packets.append(pkt)

    flow.dns = DNSInfo(queries=["example.com"], response_code=0)

    result = flow.build_ext_protocol()
    assert result == ["IPv6", "UDP", "DNS"]
    assert flow.ext_protocol == ["IPv6", "UDP", "DNS"]


def test_flow_to_dict_includes_ext_protocol():
    """Test that to_dict includes ext_protocol."""
    from wa1kpcap.core.flow import Flow, FlowKey

    flow = Flow(key=FlowKey("192.168.1.1", "10.0.0.1", 1234, 80, 6))
    flow.ext_protocol = ["IPv4", "TCP"]

    result = flow.to_dict()
    assert 'ext_protocol' in result
    assert result['ext_protocol'] == ["IPv4", "TCP"]


def test_analyzer_sets_ext_protocol():
    """Test that analyzer sets ext_protocol for flows."""
    analyzer = Wa1kPcap(verbose_mode=False)
    flows = analyzer.analyze_file('D:/MyProgram/wa1kpcap1/test/multi.pcap')

    # Check that all flows have ext_protocol set
    for flow in flows:
        assert isinstance(flow.ext_protocol, list)
        # At minimum, should have IP layer (may have only IP for some protocols like IGMP)
        assert len(flow.ext_protocol) >= 1
        # First element should be IP version
        assert flow.ext_protocol[0] in ["IPv4", "IPv6"]

    # Find DNS flows and verify DNS is in ext_protocol
    dns_flows = [f for f in flows if f.dns]
    if dns_flows:
        for flow in dns_flows:
            assert "DNS" in flow.ext_protocol

    # Find TLS flows and verify TLS is in ext_protocol
    tls_flows = [f for f in flows if f.tls]
    if tls_flows:
        for flow in tls_flows:
            assert "TLS" in flow.ext_protocol

    # Find flows with transport layer (TCP/UDP) and verify transport protocol
    transport_flows = [f for f in flows if f.key.protocol in (6, 17)]  # TCP or UDP
    if transport_flows:
        for flow in transport_flows[:5]:  # Check first 5
            if flow.key.protocol == 6:
                assert "TCP" in flow.ext_protocol
            elif flow.key.protocol == 17:
                assert "UDP" in flow.ext_protocol
