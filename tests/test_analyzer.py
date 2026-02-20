"""Test Wa1kPcap analyzer class functionality."""

import pytest
import sys
import os
import tempfile

from wa1kpcap.core.analyzer import Wa1kPcap
from wa1kpcap.core.flow import Flow, FlowKey, FlowMetrics
from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo, UDPInfo


def create_test_pcap():
    """Create a minimal valid pcap file for testing using scapy."""
    try:
        from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap
    except ImportError:
        # Fallback: create manually
        return create_test_pcap_manual()

    import tempfile
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pcap', delete=False) as f:
        pcap_path = f.name

    # Create test packets
    packets = []

    # TCP SYN packet
    packets.append(Ether() / IP(src='192.168.1.1', dst='192.168.1.2') /
                  TCP(sport=1234, dport=443, flags='S', seq=1000))

    # TCP SYN-ACK packet
    packets.append(Ether() / IP(src='192.168.1.2', dst='192.168.1.1') /
                  TCP(sport=443, dport=1234, flags='SA', seq=2000, ack=1001))

    # TCP ACK packet with data
    packets.append(Ether() / IP(src='192.168.1.1', dst='192.168.1.2') /
                  TCP(sport=1234, dport=443, flags='A', seq=1001, ack=2001) /
                  Raw(b'GET / HTTP/1.1\r\n'))

    # TCP packet with data from server
    packets.append(Ether() / IP(src='192.168.1.2', dst='192.168.1.1') /
                  TCP(sport=443, dport=1234, flags='PA', seq=2001, ack=1014) /
                  Raw(b'HTTP/1.1 200 OK\r\n'))

    # UDP packet
    packets.append(Ether() / IP(src='192.168.1.1', dst='224.0.0.1') /
                  UDP(sport=1234, dport=5678) / Raw(b'test data'))

    wrpcap(pcap_path, packets)
    return pcap_path


def create_test_pcap_manual():
    """Create a minimal valid pcap file manually (fallback)."""
    import struct
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pcap', delete=False) as f:
        # Write pcap header (little-endian)
        f.write(b'\xd4\xc3\xb2\xa1')  # Magic number
        f.write(struct.pack('<H', 2))  # Version 2.4
        f.write(struct.pack('<H', 4))
        f.write(struct.pack('<i', 0))  # Thiszone (GMT)
        f.write(struct.pack('<I', 0))  # Sigfigs
        f.write(struct.pack('<I', 65535))  # Snaplen
        f.write(struct.pack('<I', 1))  # Network (Ethernet)

        # Write a simple packet record
        f.write(struct.pack('<I', 1234567890))  # Timestamp sec
        f.write(struct.pack('<I', 123456))  # Timestamp usec
        f.write(struct.pack('<I', 62))  # Captured length
        f.write(struct.pack('<I', 62))  # Original length

        # Ethernet frame (14 bytes) + IP (20) + TCP (20) + data (8)
        # Ethernet header
        f.write(b'\x00\x11\x22\x33\x44\x55')  # DST MAC
        f.write(b'\x00\xaa\xbb\xcc\xdd\xee')  # SRC MAC
        f.write(b'\x08\x00')  # EtherType: IPv4

        # IP header (20 bytes)
        f.write(b'\x45')  # Version=4, IHL=5 (20 bytes)
        f.write(b'\x00')  # TOS
        f.write(struct.pack('>H', 28))  # Total length (20 TCP + 8 data)
        f.write(b'\x00\x01')  # ID
        f.write(b'\x00\x00')  # Flags/Fragment
        f.write(b'\x40')  # TTL
        f.write(b'\x06')  # Protocol: TCP
        f.write(b'\x00\x00')  # Checksum (skip for test)
        f.write(b'\xc0\xa8\x01\x01')  # Source (192.168.1.1)
        f.write(b'\xc0\xa8\x01\x02')  # Dest (192.168.1.2)

        # TCP header (20 bytes)
        f.write(struct.pack('>H', 1234))  # Source port
        f.write(struct.pack('>H', 443))  # Dest port
        f.write(struct.pack('>I', 1))  # Seq
        f.write(struct.pack('>I', 0))  # Ack
        f.write(b'\x50\x10\x20\x00\x00')  # Header len, Flags
        f.write(struct.pack('>H', 8192))  # Window
        f.write(b'\x00\x00')  # Checksum
        f.write(b'\x00\x00')  # Urgent

        # Payload
        f.write(b'\x00' * 8)  # "testdata" (8 bytes)

        return f.name


def test_analyzer_initialization():
    """Test Wa1kPcap initialization."""
    analyzer = Wa1kPcap(
        udp_timeout=60.0,
        tcp_cleanup_timeout=300.0,
        filter_ack=False,
        filter_rst=False,
        verbose_mode=True,
        compute_statistics=True,
    )

    # Test attributes
    assert analyzer.udp_timeout == 60.0
    assert analyzer.tcp_cleanup_timeout == 300.0
    assert analyzer.filter_ack == False
    assert analyzer.filter_rst == False
    assert analyzer.verbose_mode == True
    assert analyzer.compute_statistics == True

    # Verify components
    assert analyzer._flow_manager is not None
    assert analyzer._feature_extractor is not None
    assert analyzer._protocol_registry is not None

    # Test stats
    assert analyzer._stats['files_processed'] == 0
    assert analyzer._stats['flows_created'] == 0
    assert analyzer._stats['flows_created'] == 0
    assert analyzer._stats['packets_filtered'] == 0
    assert analyzer._stats['packets_processed'] == 0


def test_analyzer_stats():
    """Test Wa1kPcap stats property."""
    analyzer = Wa1kPcap()

    stats = analyzer.stats
    assert stats['files_processed'] == 0
    assert stats['flows_created'] == 0
    assert stats['packets_processed'] == 0
    assert stats['packets_filtered'] == 0


def test_analyzer_reset_stats():
    """Test reset_stats method."""
    analyzer = Wa1kPcap()
    analyzer._stats['packets_processed'] = 100

    analyzer.reset_stats()

    assert analyzer._stats['packets_processed'] == 0
    assert analyzer._stats['files_processed'] == 0


def test_analyzer_analyze_file():
    """Test analyzer.analyze_file method."""
    pcap_path = create_test_pcap()

    try:
        analyzer = Wa1kPcap(verbose_mode=True, compute_statistics=True)

        # Analyze file
        flows = analyzer.analyze_file(pcap_path)

        # Should have at least one flow
        assert len(flows) >= 1

        # Verify flow structure
        for flow in flows:
            assert flow is not None
            assert isinstance(flow, Flow)
            assert flow.key is not None
            assert isinstance(flow.key, FlowKey)

            # In verbose mode, packets are available
            if analyzer.verbose_mode:
                assert len(flow.packets) >= 0
    finally:
        # Clean up
        import gc
        gc.collect()
        if os.path.exists(pcap_path):
            try:
                os.unlink(pcap_path)
            except (PermissionError, OSError):
                pass


def test_analyzer_analyze_directory():
    """Test analyzer.analyze_directory method."""
    import tempfile
    import shutil

    # Create temporary directory with multiple test pcaps
    temp_dir = tempfile.mkdtemp()
    pcap_files = []

    try:
        # Copy test pcap to temp directory
        src_pcap = create_test_pcap()
        dst_pcap = os.path.join(temp_dir, 'test.pcap')
        shutil.copy(src_pcap, dst_pcap)
        pcap_files.append('test.pcap')

        analyzer = Wa1kPcap(verbose_mode=True)

        # Analyze directory
        results = analyzer.analyze_directory(temp_dir, pattern='*.pcap')

        assert len(results) == 1
        assert 'test.pcap' in results
        assert len(results['test.pcap']) >= 1

    finally:
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_analyzer_filter_options():
    """Test analyzer with filter options."""
    analyzer = Wa1kPcap(
        filter_ack=True,
        filter_rst=True,
    )

    assert analyzer.filter_ack == True
    assert analyzer.filter_rst == True


def test_analyzer_reassembly_disabled():
    """Test analyzer with reassembly disabled."""
    analyzer = Wa1kPcap(enable_reassembly=False)

    assert analyzer._ip_reassembler is None
    assert analyzer._tcp_reassembler is None
    assert analyzer._tls_reassembler is None


def test_analyzer_nonexistent_file():
    """Test analyze_file with non-existent file."""
    analyzer = Wa1kPcap()

    with pytest.raises(FileNotFoundError):
        analyzer.analyze_file('/nonexistent/file.pcap')


def test_analyzer_empty_directory():
    """Test analyze_directory with empty directory."""
    import tempfile
    analyzer = Wa1kPcap()

    with tempfile.TemporaryDirectory() as temp_dir:
        results = analyzer.analyze_directory(temp_dir)
        assert results == {}


def test_analyzer_register_feature():
    """Test register_feature method."""
    from wa1kpcap.features.registry import BaseIncrementalFeature, FeatureType
    from wa1kpcap.core.flow import Flow

    class DummyFeature(BaseIncrementalFeature):
        def __init__(self):
            super().__init__("dummy", FeatureType.INCREMENTAL)
        def initialize(self, flow):
            pass
        def update(self, flow, pkt):
            pass
        def get_value(self, flow):
            return 42

    analyzer = Wa1kPcap()
    processor = DummyFeature()

    analyzer.register_feature("dummy", processor)

    assert "dummy" in analyzer._custom_features
    assert analyzer._custom_features["dummy"] is processor


def test_analyzer_works_without_dpkt():
    """Test that analyzer works when dpkt is not available (native engine only)."""
    import wa1kpcap.protocols.application as app

    # Simulate dpkt not being available
    original_has_dpkt = app._HAS_DPKT
    app._HAS_DPKT = False

    try:
        pcap_path = create_test_pcap()
        try:
            analyzer = Wa1kPcap(verbose_mode=True, compute_statistics=True)
            flows = analyzer.analyze_file(pcap_path)
            assert len(flows) >= 1
            for flow in flows:
                assert flow.src_ip is not None
                assert flow.dst_ip is not None
                assert flow.packet_count > 0
        finally:
            if os.path.exists(pcap_path):
                try:
                    os.unlink(pcap_path)
                except (PermissionError, OSError):
                    pass
    finally:
        app._HAS_DPKT = original_has_dpkt


if __name__ == '__main__':
    test_analyzer_initialization()
    test_analyzer_stats()
    test_analyzer_reset_stats()
    test_analyzer_analyze_file()
    test_analyzer_analyze_directory()
    test_analyzer_filter_options()
    test_analyzer_reassembly_disabled()
    test_analyzer_nonexistent_file()
    test_analyzer_empty_directory()
    test_analyzer_register_feature()
    print("test_analyzer PASSED")
