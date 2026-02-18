"""Configuration and fixtures for pytest tests."""

import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def sample_flow_key():
    """Provide a sample FlowKey for testing."""
    from wa1kpcap.core.flow import FlowKey
    return FlowKey(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=443,
        protocol=6  # TCP
    )


@pytest.fixture
def sample_flow(sample_flow_key):
    """Provide a sample Flow for testing."""
    from wa1kpcap.core.flow import Flow
    return Flow(key=sample_flow_key, start_time=0.0)


@pytest.fixture
def sample_packets():
    """Provide sample packets for testing."""
    from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo

    packets = []
    for i in range(5):
        ip = IPInfo(
            version=4,
            src="192.168.1.1",
            dst="10.0.0.1",
            proto=6,
            ttl=64,
            len=100 + i * 10,
            id=i,
            flags=0,
            offset=0
        )
        tcp = TCPInfo(
            sport=12345,
            dport=443,
            seq=i * 100,
            ack=i * 100 if i > 0 else 0,
            flags=0x18 if i > 0 else 0x02,
            win=8192,
            urgent=0,
            options=b''
        )
        pkt = ParsedPacket(
            timestamp=float(i),
            raw_data=b'\x00' * (100 + i * 10),
            link_layer_type=1,
            caplen=100 + i * 10,
            wirelen=100 + i * 10,
            ip_len=80 + i * 10,
            trans_len=60 + i * 10,
            app_len=40 + i * 10
        )
        pkt.ip = ip
        pkt.tcp = tcp
        packets.append(pkt)

    return packets
