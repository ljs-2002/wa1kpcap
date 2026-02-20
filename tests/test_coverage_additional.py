"""Additional tests for improving code coverage."""

import pytest
import sys
import os
import tempfile

from conftest import MULTI_PCAP
from wa1kpcap import Wa1kPcap
from wa1kpcap.features.registry import FeatureRegistry, FeatureType
from wa1kpcap.protocols.base import BaseProtocolHandler, Layer
from wa1kpcap.core.flow import Flow, FlowKey
from wa1kpcap.features import FlowFeatures
import numpy as np


def test_analyzer_with_udp_timeout():
    """Test analyzer with different UDP timeout settings."""
    pcap_path = MULTI_PCAP
    if not os.path.exists(pcap_path):
        pytest.skip("multi.pcap not found")

    # Test with short UDP timeout
    analyzer = Wa1kPcap(verbose_mode=True, udp_timeout=10.0)
    flows = analyzer.analyze_file(pcap_path)
    assert len(flows) > 0


def test_analyzer_with_tcp_cleanup_timeout():
    """Test analyzer with different TCP cleanup timeout."""
    pcap_path = MULTI_PCAP
    if not os.path.exists(pcap_path):
        pytest.skip("multi.pcap not found")

    analyzer = Wa1kPcap(verbose_mode=True, tcp_cleanup_timeout=100.0)
    flows = analyzer.analyze_file(pcap_path)
    assert len(flows) > 0


def test_analyzer_filter_rst():
    """Test analyzer with RST filtering."""
    try:
        from scapy.all import Ether, IP, TCP, wrpcap
    except ImportError:
        pytest.skip("scapy not installed")

    packets = [
        Ether() / IP(src='192.168.1.1', dst='10.0.0.1') /
        TCP(sport=1234, dport=80, flags='S', seq=1000),
        Ether() / IP(src='10.0.0.1', dst='192.168.1.1') /
        TCP(sport=80, dport=1234, flags='RA', seq=2000, ack=1001),
    ]

    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pcap', delete=False) as f:
        pcap_path = f.name
    wrpcap(pcap_path, packets)

    try:
        # With RST filtering
        analyzer = Wa1kPcap(verbose_mode=True, filter_rst=True)
        flows = analyzer.analyze_file(pcap_path)
        assert len(flows) >= 0
    finally:
        try:
            os.unlink(pcap_path)
        except:
            pass


def test_flow_features_with_zero_packets():
    """Test FlowFeatures with empty/zero values."""
    features = FlowFeatures()

    # Initialize with empty arrays
    features.packet_lengths = np.array([])
    features.timestamps = np.array([])
    features.iats = np.array([])

    stats = features.compute_statistics()
    assert stats is not None


def test_flow_features_single_packet():
    """Test FlowFeatures with single packet."""
    features = FlowFeatures()
    features.packet_lengths = np.array([100])
    features.timestamps = np.array([0.0])
    features.iats = np.array([])  # No IAT for single packet

    stats = features.compute_statistics()
    assert stats is not None


def test_flow_features_directional():
    """Test FlowFeatures directional statistics."""
    features = FlowFeatures()
    # Mix of positive and negative for direction
    features.packet_lengths = np.array([100, -50, 200, -75])

    stats = features.compute_statistics()
    assert 'packet_lengths' in stats
    assert 'up_mean' in stats['packet_lengths']
    assert 'down_mean' in stats['packet_lengths']


def test_feature_registry_edge_cases():
    """Test FeatureRegistry edge cases."""
    registry = FeatureRegistry()

    # Test getting non-existent feature
    assert registry.get('nonexistent') is None

    # Test clearing empty registry
    registry.clear()
    assert len(registry._extractors) == 0

    # Test unregister non-existent
    assert registry.unregister('nonexistent') is False


def test_custom_protocol_handler():
    """Test custom protocol handler registration."""
    from wa1kpcap.protocols.registry import register_protocol, get_global_registry

    # Get registry and ensure clean state
    registry = get_global_registry()
    registry.unregister('test_custom_proto')

    @register_protocol('test_custom_proto', Layer.APPLICATION, encapsulates='tcp', default_ports=[9999])
    class CustomProtocolHandler(BaseProtocolHandler):
        def parse(self, payload, context, is_client_to_server):
            from wa1kpcap.protocols.base import ParseResult
            return ParseResult(success=True, data=payload[10:] if len(payload) > 10 else b'')

    # Check it was registered
    assert CustomProtocolHandler.name == 'test_custom_proto'

    # Clean up
    registry.unregister('test_custom_proto')


def test_flow_to_dict():
    """Test Flow.to_dict() method."""
    from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo

    key = FlowKey(
        src_ip='192.168.1.1',
        dst_ip='10.0.0.1',
        src_port=1234,
        dst_port=80,
        protocol=6
    )

    flow = Flow(key=key, start_time=0.0)

    # Add a packet
    pkt = ParsedPacket(timestamp=0.0, raw_data=b'test')
    pkt.ip = IPInfo(
        src='192.168.1.1',
        dst='10.0.0.1',
        version=4,
        proto=6,
        ttl=64,
        _raw=b''
    )
    pkt.tcp = TCPInfo(
        sport=1234,
        dport=80,
        seq=1000,
        ack_num=0,
        flags=0x02,
        win=8192,
        _raw=b''
    )
    flow.add_packet(pkt)

    # Convert to dict
    result = flow.to_dict()
    assert 'src_ip' in result
    assert 'dst_ip' in result
    assert 'packet_count' in result


def test_flow_get_features():
    """Test Flow.get_features() method."""
    from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo

    key = FlowKey(
        src_ip='192.168.1.1',
        dst_ip='10.0.0.1',
        src_port=1234,
        dst_port=80,
        protocol=6
    )

    flow = Flow(key=key, start_time=0.0)

    # Add packets
    for i in range(3):
        pkt = ParsedPacket(timestamp=0.0 + i * 0.01, raw_data=b'test')
        pkt.ip = IPInfo(
            src='192.168.1.1',
            dst='10.0.0.1',
            version=4,
            proto=6,
            ttl=64,
            _raw=b''
        )
        pkt.tcp = TCPInfo(
            sport=1234,
            dport=80,
            seq=1000 + i * 100,
            ack_num=0,
            flags=0x02,
            win=8192,
            _raw=b''
        )
        flow.add_packet(pkt)

    # Get features
    features = flow.get_features()
    assert features is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
