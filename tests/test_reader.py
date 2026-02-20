"""Test PcapReader class functionality."""

import pytest
import sys
import tempfile
import struct

from wa1kpcap.core.reader import (
    PcapReader,
    LinkLayerType,
    get_link_layer_type,
    DLT_EN10MB,
    DLT_LINUX_SLL,
    DLT_RAW,
    DLT_NULL,
    DLT_LOOP,
    DLT_NFLOG,
)


def test_get_link_layer_type():
    """Test link layer type mapping."""
    assert get_link_layer_type(DLT_EN10MB) == LinkLayerType.ETHERNET
    assert get_link_layer_type(DLT_LINUX_SLL) == LinkLayerType.LINUX_SLL
    assert get_link_layer_type(DLT_RAW) == LinkLayerType.RAW_IP
    assert get_link_layer_type(DLT_NULL) == LinkLayerType.NULL
    assert get_link_layer_type(DLT_LOOP) == LinkLayerType.LOOP
    assert get_link_layer_type(DLT_NFLOG) == LinkLayerType.NFLOG
    assert get_link_layer_type(999) == LinkLayerType.UNKNOWN


def test_pcap_reader_init():
    """Test PcapReader initialization."""
    reader = PcapReader("test.pcap")
    assert reader.pcap_path.name == "test.pcap"
    assert reader._reader is None
    assert reader._link_layer_type is None


def create_test_pcap_file(link_type=DLT_EN10MB):
    """Create a minimal valid pcap file for testing."""
    with tempfile.NamedTemporaryFile(mode='wb', suffix='.pcap', delete=False) as f:
        # Write pcap header (little-endian)
        f.write(b'\xd4\xc3\xb2\xa1')  # Magic number
        f.write(struct.pack('<H', 2))  # Version 2.4
        f.write(struct.pack('<H', 4))
        f.write(struct.pack('<i', 0))  # Thiszone (GMT)
        f.write(struct.pack('<I', 0))  # Sigfigs
        f.write(struct.pack('<i', 65535))  # Snaplen
        f.write(struct.pack('<i', link_type))  # Network (Ethernet)

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

        # IP header (minimal)
        f.write(b'\x45')  # Version=4, IHL=5 (20 bytes)
        f.write(b'\x00')  # TOS
        f.write(struct.pack('>H', 48))  # Total length (20 IP + 20 TCP + 8 data)
        f.write(b'\x00\x01')  # ID
        f.write(b'\x00\x00')  # Flags/Fragment
        f.write(b'\x40')  # TTL
        f.write(b'\x06')  # Protocol: TCP
        f.write(b'\x00\x00')  # Checksum (skip for test)
        f.write(b'\xc0\xa8\x01\x01')  # Source: 192.168.1.1
        f.write(b'\xc0\xa8\x01\x02')  # Dest: 192.168.1.2

        # TCP header
        f.write(struct.pack('>H', 12345))  # Src port
        f.write(struct.pack('>H', 80))  # Dst port
        f.write(struct.pack('>I', 1))  # Seq
        f.write(struct.pack('>I', 0))  # Ack
        f.write(b'\x50\x10')  # Header len (5*4=20) + flags (ACK=0x10)
        f.write(struct.pack('>H', 8192))  # Window
        f.write(b'\x00\x00')  # Checksum
        f.write(b'\x00\x00')  # Urgent

        # Payload
        f.write(b'testdata')

        return f.name


def test_pcap_reader_open():
    """Test opening a valid pcap file."""
    pcap_path = create_test_pcap_file()
    try:
        reader = PcapReader(pcap_path)
        reader.open()
        assert reader._reader is not None
        assert reader.link_layer_type == DLT_EN10MB
        assert reader.link_layer_name == LinkLayerType.ETHERNET
        reader.close()
    finally:
        import os
        import gc
        gc.collect()  # Force cleanup on Windows
        try:
            os.unlink(pcap_path)
        except (PermissionError, OSError):
            pass  # File still locked, will be cleaned up later


def test_pcap_reader_context_manager():
    """Test PcapReader as context manager."""
    pcap_path = create_test_pcap_file()
    try:
        with PcapReader(pcap_path) as reader:
            assert reader._reader is not None
            assert reader.link_layer_type == DLT_EN10MB
    finally:
        import os
        import gc
        gc.collect()  # Force cleanup on Windows
        try:
            os.unlink(pcap_path)
        except (PermissionError, OSError):
            pass


def test_pcap_reader_iterate():
    """Test iterating over packets."""
    pcap_path = create_test_pcap_file()
    try:
        with PcapReader(pcap_path) as reader:
            count = 0
            for ts, buf in reader:
                count += 1
                assert isinstance(ts, float)
                assert isinstance(buf, bytes)
                assert len(buf) > 0
            assert count == 1
    finally:
        import os
        import gc
        gc.collect()  # Force cleanup on Windows
        try:
            os.unlink(pcap_path)
        except (PermissionError, OSError):
            pass


def test_pcap_reader_packets():
    """Test packets() method."""
    pcap_path = create_test_pcap_file()
    try:
        with PcapReader(pcap_path) as reader:
            packets = list(reader.packets())
            assert len(packets) == 1
            ts, caplen, wirelen, buf = packets[0]
            assert isinstance(ts, float)
            assert caplen == 62
            assert wirelen == 62
            assert len(buf) == 62
    finally:
        import os
        import gc
        gc.collect()  # Force cleanup on Windows
        try:
            os.unlink(pcap_path)
        except (PermissionError, OSError):
            pass


def test_pcap_reader_decode_ethernet():
    """Test Ethernet packet decoding."""
    # Ethernet frame: DST(6) + SRC(6) + EtherType(2)
    eth_frame = (
        b'\x00\x11\x22\x33\x44\x55'  # DST
        b'\x00\xaa\xbb\xcc\xdd\xee'  # SRC
        b'\x08\x00'  # IPv4
        b'\x45'  # IP version
    )

    eth_obj, offset = PcapReader.decode_ethernet_packet(eth_frame)
    assert eth_obj is not None
    assert offset == 14  # Ethernet header is 14 bytes


def test_pcap_reader_decode_linux_sll():
    """Test Linux SLL packet decoding."""
    # SLL header (16 bytes)
    sll_frame = (
        b'\x00\x01'  # Packet type: Unicast to us
        b'\x00\x00'  # ARPHRD type
        b'\x00\x06'  # Addr len (6)
        b'\x00\x11\x22\x33\x44\x55'  # Addr (6 bytes)
        b'\x00\x00'  # Padding (2 bytes, so addr + padding = 8)
        b'\x08\x00'  # Protocol: IPv4
    )

    sll_obj, offset = PcapReader.decode_linux_sll_packet(sll_frame)
    assert sll_obj is not None
    assert offset == 16
    assert sll_obj.proto == 0x0800


def test_pcap_reader_decode_raw_ip():
    """Test raw IP packet decoding."""
    # Minimal IPv4 packet
    ip_packet = b'\x45\x00\x00\x14\x00\x01\x00\x00\x40\x06\x00\x00\xc0\xa8\x01\x01\xc0\xa8\x01\x02'

    ip_obj, offset = PcapReader.decode_raw_ip_packet(ip_packet)
    assert ip_obj is not None
    assert offset == 0  # Raw IP has no header


def test_pcap_reader_decode_null():
    """Test BSD null packet decoding."""
    # NULL header (4 bytes) + data
    null_packet = b'\x00\x00\x00\x02' + b'test data'

    null_obj, offset = PcapReader.decode_null_packet(null_packet)
    assert null_obj is not None
    assert offset == 4
    assert null_obj.af == 2  # AF_INET


def test_pcap_reader_nflog():
    """Test NFLOG packet decoding."""
    nflog_packet = b'\x00\x04\x00\x00'  # TLV header

    nflog_obj, offset = PcapReader.decode_nflog_packet(nflog_packet)
    assert nflog_obj is not None
    # NFLOG parsing returns 0 offset (simplified)


def test_is_pcap_file():
    """Test is_pcap_file static method."""
    # Test with actual pcap file
    pcap_path = create_test_pcap_file()
    try:
        assert PcapReader.is_pcap_file(pcap_path) == True
    finally:
        import os
        os.unlink(pcap_path)

    # Test with pcapng magic
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b'\x0a\x0d\x0d\x0a')  # PCAPNG magic
        pcapng_path = f.name

    try:
        assert PcapReader.is_pcap_file(pcapng_path) == True
    finally:
        import os
        os.unlink(pcapng_path)

    # Test with non-pcap file
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b'not a pcap')
        invalid_path = f.name

    try:
        assert PcapReader.is_pcap_file(invalid_path) == False
    finally:
        import os
        os.unlink(invalid_path)

    # Test with non-existent file
    assert PcapReader.is_pcap_file("nonexistent.pcap") == False


def test_pcap_reader_nonexistent():
    """Test opening non-existent file."""
    reader = PcapReader("nonexistent_test_file.pcap")
    with pytest.raises(FileNotFoundError):
        reader.open()


def test_pcap_reader_not_opened():
    """Test accessing properties before opening."""
    reader = PcapReader("test.pcap")
    with pytest.raises(RuntimeError):
        _ = reader.link_layer_type

    with pytest.raises(RuntimeError):
        for _ in reader:
            pass


def test_pcap_reader_read_packets():
    """Test read_packets with callback."""
    pcap_path = create_test_pcap_file()
    try:
        with PcapReader(pcap_path) as reader:
            packets_read = []

            def callback(ts, buf, link_obj):
                packets_read.append((ts, buf, link_obj))

            count = reader.read_packets(callback)
            assert count == 1
            assert len(packets_read) == 1
    finally:
        import os
        import gc
        # Force garbage collection to release file handle on Windows
        gc.collect()
        try:
            os.unlink(pcap_path)
        except (PermissionError, OSError):
            # File may still be locked on Windows
            pass


def test_pcap_reader_read_packets_with_limit():
    """Test read_packets with limit parameter."""
    pcap_path = create_test_pcap_file()
    try:
        with PcapReader(pcap_path) as reader:
            # Read at most 1 packet
            count = reader.read_packets(lambda ts, buf, lo: None, limit=1)
            assert count == 1
    finally:
        import os
        import gc
        gc.collect()
        try:
            os.unlink(pcap_path)
        except (PermissionError, OSError):
            pass


def test_pcap_reader_datalink_alias():
    """Test datalink property alias."""
    pcap_path = create_test_pcap_file()
    try:
        with PcapReader(pcap_path) as reader:
            assert reader.datalink == reader.link_layer_type
    finally:
        import os
        import gc
        gc.collect()
        try:
            os.unlink(pcap_path)
        except (PermissionError, OSError):
            pass


def test_all():
    """Run all reader tests."""
    test_get_link_layer_type()
    test_pcap_reader_init()
    test_pcap_reader_open()
    test_pcap_reader_context_manager()
    test_pcap_reader_iterate()
    test_pcap_reader_packets()
    test_pcap_reader_decode_ethernet()
    test_pcap_reader_decode_linux_sll()
    test_pcap_reader_decode_raw_ip()
    test_pcap_reader_decode_null()
    test_pcap_reader_nflog()
    test_is_pcap_file()
    test_pcap_reader_nonexistent()
    test_pcap_reader_not_opened()
    test_pcap_reader_read_packets()
    test_pcap_reader_read_packets_with_limit()
    test_pcap_reader_datalink_alias()
    print("test_reader PASSED")


if __name__ == '__main__':
    test_all()
