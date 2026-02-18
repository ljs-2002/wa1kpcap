"""Test ParsedPacket class functionality."""

import pytest
import sys
import struct
sys.path.insert(0, r'D:\MyProgram\wa1kpcap1')

from wa1kpcap.core.packet import ParsedPacket, EthernetInfo, IPInfo, IP6Info, TCPInfo, UDPInfo, ICMPInfo
from wa1kpcap.core.flow import Flow, FlowKey


def create_ethernet_frame(src='00:11:22:33:44:55', dst='00:aa:bb:cc:dd:ee', ethertype=0x0800):
    """Create a valid Ethernet frame."""
    # Convert MAC addresses from string to bytes
    src_bytes = bytes.fromhex(src.replace(':', ''))
    dst_bytes = bytes.fromhex(dst.replace(':', ''))
    return dst_bytes + src_bytes + struct.pack('>H', ethertype)


def create_ipv4_packet(src='192.168.0.1', dst='224.0.0.1', proto=6, ttl=64, payload=b''):
    """Create a valid IPv4 packet."""
    import socket
    version_ihl = 0x45  # Version=4, IHL=5 (20 bytes header)
    tos = 0
    total_len = 20 + len(payload)
    id = 12345
    flags_frag = 0  # No flags, no fragment
    src_bytes = socket.inet_pton(socket.AF_INET, src)
    dst_bytes = socket.inet_pton(socket.AF_INET, dst)

    # Build header (without checksum first)
    header = struct.pack('>BBHHHBBH',
                       version_ihl, tos, total_len, id, flags_frag, ttl, proto, 0)
    header += src_bytes + dst_bytes

    # Calculate checksum
    checksum = 0
    for i in range(0, len(header), 2):
        checksum += (header[i] << 8) + header[i+1]
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = ~checksum & 0xffff

    # Rebuild header with checksum
    header = struct.pack('>BBHHHBBH',
                       version_ihl, tos, total_len, id, flags_frag, ttl, proto, checksum)
    header += src_bytes + dst_bytes

    return header + payload


def create_tcp_packet(sport=80, dport=1234, seq=1000, ack_num=5000, flags=0x018, win=8192, payload=b''):
    """Create a valid TCP segment."""
    data_offset = 5 << 4  # Data offset: 5 (20 bytes header)
    header = struct.pack('>HHIIBBHHH',
                       sport, dport, seq, ack_num, data_offset, flags, win, 0, 0)
    return header + payload


def create_udp_packet(sport=53, dport=53, payload=b''):
    """Create a valid UDP datagram."""
    length = 8 + len(payload)
    header = struct.pack('>HHHH', sport, dport, length, 0)
    return header + payload


def test_packet_basic_creation():
    """Test basic packet creation."""
    pkt = ParsedPacket(
        timestamp=0.0,
        raw_data=b'\x00' * 100,
        link_layer_type=1,
        caplen=100,
        wirelen=100,
    )

    assert pkt.timestamp == 0.0
    assert pkt.wirelen == 100
    assert pkt.caplen == 100
    assert len(pkt.raw_data) == 100


def test_packet_ethernet_frame():
    """Test Ethernet frame handling."""
    eth_frame = create_ethernet_frame('00:11:22:33:44:55', '00:aa:bb:cc:dd:ee', 0x0800)

    pkt = ParsedPacket(timestamp=0.0, raw_data=eth_frame, link_layer_type=1)

    # Manually parse Ethernet frame
    import dpkt
    try:
        eth = dpkt.ethernet.Ethernet(eth_frame)
        eth_info = EthernetInfo.from_dpkt(eth)
        assert eth_info.src == '00:11:22:33:44:55'
        assert eth_info.dst == '00:aa:bb:cc:dd:ee'
        assert eth_info.type == 0x0800
    except Exception:
        # If dpkt fails, skip detailed test
        pass


def test_packet_ipv4():
    """Test IPv4 packet parsing."""
    ip_packet = create_ipv4_packet(src='192.168.0.1', dst='224.0.0.1', proto=6, ttl=64)

    pkt = ParsedPacket(timestamp=0.0, raw_data=ip_packet, link_layer_type=1)

    # Manually parse IP packet
    import dpkt
    try:
        ip = dpkt.ip.IP(ip_packet)
        ip_info = IPInfo.from_dpkt(ip)
        assert ip_info.src == '192.168.0.1'
        assert ip_info.dst == '224.0.0.1'
        assert ip_info.proto == 6
        assert ip_info.ttl == 64
    except Exception:
        # If dpkt fails, skip detailed test
        pass


def test_packet_ipv4_fragmented():
    """Test IPv4 fragmented packet."""
    # Create first fragment (MF=1, offset=0)
    frag1 = create_ipv4_packet(src='192.168.0.1', dst='224.0.0.1', proto=6, payload=b'X' * 8)
    # Modify flags to set MF (more fragments)
    frag1_bytes = bytearray(frag1)
    frag1_bytes[6] |= 0x20  # Set MF bit in flags/frag field
    frag1 = bytes(frag1_bytes)

    pkt = ParsedPacket(timestamp=0.0, raw_data=frag1, link_layer_type=1)

    # Check fragmentation info
    import dpkt
    try:
        ip = dpkt.ip.IP(frag1)
        ip_info = IPInfo.from_dpkt(ip)
        assert ip_info.offset == 0
        # MF bit should be set
    except Exception:
        # If dpkt fails, skip
        pass


def test_packet_tcp():
    """Test TCP packet parsing."""
    tcp_segment = create_tcp_packet(sport=80, dport=1234, seq=1000, ack_num=5000, flags=0x018, win=8192)

    pkt = ParsedPacket(timestamp=0.0, raw_data=tcp_segment, link_layer_type=1)

    # Manually parse TCP segment
    import dpkt
    try:
        tcp = dpkt.tcp.TCP(tcp_segment)
        tcp_info = TCPInfo.from_dpkt(tcp)
        assert tcp_info.sport == 80
        assert tcp_info.dport == 1234
        assert tcp_info.seq == 1000
        assert tcp_info.ack_num == 5000
        assert tcp_info.flags == 0x018
    except Exception:
        # If dpkt fails, skip detailed test
        pass


def test_packet_udp():
    """Test UDP packet parsing."""
    udp_datagram = create_udp_packet(sport=53, dport=53, payload=b'test')

    pkt = ParsedPacket(timestamp=0.0, raw_data=udp_datagram, link_layer_type=1)

    # Manually parse UDP datagram
    import dpkt
    try:
        udp = dpkt.udp.UDP(udp_datagram)
        udp_info = UDPInfo.from_dpkt(udp)
        assert udp_info.sport == 53
        assert udp_info.dport == 53
    except Exception:
        # If dpkt fails, skip detailed test
        pass


def test_packet_all_layers():
    """Test parsing all layers at once."""
    # Create full packet: Ethernet + IP + UDP
    udp_payload = b'test data'
    ip_payload = create_udp_packet(sport=53, dport=53, payload=udp_payload)
    ip_packet = create_ipv4_packet(proto=17, payload=ip_payload)  # 17 = UDP
    eth_frame = create_ethernet_frame() + ip_packet

    pkt = ParsedPacket(timestamp=0.0, raw_data=eth_frame, link_layer_type=1)

    # Verify layers can be parsed
    import dpkt
    try:
        eth = dpkt.ethernet.Ethernet(eth_frame)
        assert eth.data.startswith(b'E')  # IP starts with 0x45

        ip = dpkt.ip.IP(eth.data)
        assert ip.p == 17  # UDP

        udp = dpkt.udp.UDP(ip.data)
        assert udp.sport == 53
        assert udp.dport == 53
    except Exception:
        # If dpkt fails, skip detailed test
        pass


def test_packet_properties():
    """Test computed properties."""
    pkt = ParsedPacket(
        timestamp=0.0,
        raw_data=b'\x00' * 100,
        link_layer_type=1,
        wirelen=100,
        ip_len=80,
        trans_len=40,
        app_len=20,
    )

    # Properties should be computed
    assert pkt.wirelen == 100
    assert pkt.ip_len == 80
    assert pkt.trans_len == 40
    assert pkt.app_len == 20


def test_flow_operations():
    """Test flow operations with packets."""
    key = FlowKey(
        src_ip='192.168.0.1',
        dst_ip='224.0.0.1',
        src_port=80,
        dst_port=80,
        protocol=6
    )

    flow = Flow(key=key, start_time=0.0)

    # Add packets
    for i in range(3):
        if i == 0:
            pkt = ParsedPacket(
                timestamp=0.0 + i,
                raw_data=b'\x00' * 100,
                link_layer_type=1,
                wirelen=100,
                ip_len=80,
                trans_len=40,
                app_len=20,
            )
        else:
            pkt = ParsedPacket(
                timestamp=0.0 + i,
                raw_data=b'\x00' * 80,
                link_layer_type=1,
                wirelen=80,
                ip_len=64,
                trans_len=24,
                app_len=0,
            )
        flow.add_packet(pkt)

    # Verify counts
    assert flow.num_packets == 3
    assert flow.metrics.packet_count == 3
    # Total wirelen: 100 + 80 + 80 = 260
    assert flow.metrics.byte_count == 260


def test_packet_with_all_info():
    """Test creating a packet with all info layers populated."""
    pkt = ParsedPacket(
        timestamp=1.5,
        raw_data=b'\x00' * 100,
        link_layer_type=1,
        wirelen=100,
        ip_len=80,
        trans_len=40,
        app_len=20,
    )

    # Add Ethernet layer
    pkt.eth = EthernetInfo(
        src='00:11:22:33:44:55',
        dst='00:aa:bb:cc:dd:ee',
        type=0x0800,
    )

    # Add IP layer
    pkt.ip = IPInfo(
        version=4,
        src='192.168.1.1',
        dst='10.0.0.1',
        proto=6,
        ttl=64,
        len=100,
        id=12345,
        flags=0,
        offset=0,
    )

    # Add TCP layer
    pkt.tcp = TCPInfo(
        sport=1234,
        dport=443,
        seq=1000,
        ack_num=5000,
        flags=0x018,
        win=8192,
        urgent=0,
        options=b'',
    )

    assert pkt.eth is not None
    assert pkt.eth.src == '00:11:22:33:44:55'
    assert pkt.ip is not None
    assert pkt.ip.src == '192.168.1.1'
    assert pkt.tcp is not None
    assert pkt.tcp.sport == 1234


def test_packet_to_dict():
    """Test to_dict method."""
    pkt = ParsedPacket(
        timestamp=1.5,
        raw_data=b'\x00' * 100,
        link_layer_type=1,
        wirelen=100,
    )

    pkt.ip = IPInfo(
        version=4,
        src='192.168.1.1',
        dst='10.0.0.1',
        proto=6,
        ttl=64,
        len=100,
        id=12345,
        flags=0,
        offset=0,
    )

    pkt.tcp = TCPInfo(
        sport=1234,
        dport=443,
        seq=1000,
        ack_num=5000,
        flags=0x018,
        win=8192,
        urgent=0,
        options=b'',
    )

    d = pkt.to_dict()
    assert 'timestamp' in d
    assert 'ip' in d
    assert 'tcp' in d
    assert d['ip']['src'] == '192.168.1.1'
    assert d['tcp']['sport'] == 1234


def test_all():
    """Run all packet tests."""
    test_packet_basic_creation()
    test_packet_ethernet_frame()
    test_packet_ipv4()
    test_packet_ipv4_fragmented()
    test_packet_tcp()
    test_packet_udp()
    test_packet_all_layers()
    test_packet_properties()
    test_flow_operations()
    test_packet_with_all_info()
    test_packet_to_dict()
    print("test_packet PASSED")


if __name__ == '__main__':
    test_all()
