"""Test PcapReader class functionality."""

import pytest
import tempfile
import struct
import os

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


def test_is_pcap_file_valid_pcap():
    """Test is_pcap_file with valid pcap file."""
    pcap_path = create_test_pcap_file()
    try:
        assert PcapReader.is_pcap_file(pcap_path) == True
    finally:
        os.unlink(pcap_path)


def test_is_pcap_file_pcapng():
    """Test is_pcap_file with pcapng magic."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b'\x0a\x0d\x0d\x0a')  # PCAPNG magic
        pcapng_path = f.name

    try:
        assert PcapReader.is_pcap_file(pcapng_path) == True
    finally:
        os.unlink(pcapng_path)


def test_is_pcap_file_invalid():
    """Test is_pcap_file with non-pcap file."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
        f.write(b'not a pcap')
        invalid_path = f.name

    try:
        assert PcapReader.is_pcap_file(invalid_path) == False
    finally:
        os.unlink(invalid_path)


def test_is_pcap_file_nonexistent():
    """Test is_pcap_file with non-existent file."""
    assert PcapReader.is_pcap_file("nonexistent.pcap") == False


def test_is_pcap_file_directory():
    """Test is_pcap_file with a directory."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        assert PcapReader.is_pcap_file(tmpdir) == False


def test_link_layer_type_constants():
    """Test LinkLayerType constants."""
    assert LinkLayerType.ETHERNET == "ethernet"
    assert LinkLayerType.LINUX_SLL == "linux_sll"
    assert LinkLayerType.RAW_IP == "raw_ip"
    assert LinkLayerType.NULL == "null"
    assert LinkLayerType.LOOP == "loop"
    assert LinkLayerType.NFLOG == "nflog"
    assert LinkLayerType.UNKNOWN == "unknown"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
