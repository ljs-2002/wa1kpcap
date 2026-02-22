"""Tests for C++ NativeFlowManager (flow_manager.h)."""

import pytest

# Skip entire module if native extension unavailable
native = pytest.importorskip("wa1kpcap._wa1kpcap_native")

NativeFlowManager = native.NativeFlowManager
NativeFlowManagerConfig = native.NativeFlowManagerConfig
NativeParser = native.NativeParser

import os
PROTO_DIR = os.path.join(os.path.dirname(__file__), '..', 'wa1kpcap', 'native', 'protocols')


@pytest.fixture
def parser():
    return NativeParser(os.path.abspath(PROTO_DIR))


@pytest.fixture
def mgr():
    return NativeFlowManager()


def _make_tcp_syn_packet():
    """Build a minimal TCP SYN packet (Ethernet + IPv4 + TCP)."""
    import struct
    # Ethernet: dst(6) + src(6) + type(2) = 14 bytes
    eth = b'\x00' * 6 + b'\x00' * 6 + struct.pack('!H', 0x0800)
    # IPv4: version/IHL=0x45, TOS=0, total_len=40, id=1, flags/offset=0x4000(DF),
    #        TTL=64, proto=6(TCP), checksum=0, src=192.168.1.1, dst=10.0.0.1
    ip = struct.pack('!BBHHHBBH4s4s',
                     0x45, 0, 40, 1, 0x4000, 64, 6, 0,
                     bytes([192, 168, 1, 1]),
                     bytes([10, 0, 0, 1]))
    # TCP: sport=12345, dport=80, seq=100, ack=0, offset/flags=0x5002(SYN, data_offset=5),
    #      window=65535, checksum=0, urgent=0
    tcp = struct.pack('!HHIIBBHHH',
                      12345, 80, 100, 0,
                      0x50, 0x02,  # data_offset=5, SYN flag
                      65535, 0, 0)
    return eth + ip + tcp


def _make_tcp_synack_packet():
    """Build a TCP SYN-ACK packet (reverse direction)."""
    import struct
    eth = b'\x00' * 6 + b'\x00' * 6 + struct.pack('!H', 0x0800)
    ip = struct.pack('!BBHHHBBH4s4s',
                     0x45, 0, 40, 2, 0x4000, 64, 6, 0,
                     bytes([10, 0, 0, 1]),       # src = server
                     bytes([192, 168, 1, 1]))    # dst = client
    tcp = struct.pack('!HHIIBBHHH',
                      80, 12345, 200, 101,       # sport=80, dport=12345
                      0x50, 0x12,                 # SYN+ACK
                      32768, 0, 0)
    return eth + ip + tcp


def _make_tcp_ack_packet():
    """Build a TCP ACK packet (forward direction)."""
    import struct
    eth = b'\x00' * 6 + b'\x00' * 6 + struct.pack('!H', 0x0800)
    ip = struct.pack('!BBHHHBBH4s4s',
                     0x45, 0, 40, 3, 0x4000, 64, 6, 0,
                     bytes([192, 168, 1, 1]),
                     bytes([10, 0, 0, 1]))
    tcp = struct.pack('!HHIIBBHHH',
                      12345, 80, 101, 201,
                      0x50, 0x10,                 # ACK only
                      65535, 0, 0)
    return eth + ip + tcp


def _make_udp_packet(src_ip_bytes, dst_ip_bytes, sport, dport, payload_len=0):
    """Build a minimal UDP packet."""
    import struct
    eth = b'\x00' * 6 + b'\x00' * 6 + struct.pack('!H', 0x0800)
    udp_len = 8 + payload_len
    total_len = 20 + udp_len
    ip = struct.pack('!BBHHHBBH4s4s',
                     0x45, 0, total_len, 1, 0x4000, 64, 17, 0,
                     bytes(src_ip_bytes), bytes(dst_ip_bytes))
    udp = struct.pack('!HHHH', sport, dport, udp_len, 0)
    payload = b'\x00' * payload_len
    return eth + ip + udp + payload


class TestNativeFlowKey:
    def test_direction_forward(self):
        key = native.NativeFlowKey()
        key.src_ip = "192.168.1.1"
        key.dst_ip = "10.0.0.1"
        key.src_port = 12345
        key.dst_port = 80
        assert key.direction("192.168.1.1", 12345) == 1

    def test_direction_reverse(self):
        key = native.NativeFlowKey()
        key.src_ip = "192.168.1.1"
        key.dst_ip = "10.0.0.1"
        key.src_port = 12345
        key.dst_port = 80
        assert key.direction("10.0.0.1", 80) == -1


class TestNativeFlowMetrics:
    def test_defaults(self):
        m = native.NativeFlowMetrics()
        assert m.packet_count == 0
        assert m.byte_count == 0
        assert m.syn_count == 0
        assert m.min_window == 0
        assert m.max_window == 0


class TestNativeFlowManager:
    def test_create_flow_from_tcp(self, parser, mgr):
        """Parsing a TCP packet and adding to flow manager creates a flow."""
        raw = _make_tcp_syn_packet()
        pkt = parser.parse_packet_struct(raw, 1)  # LINKTYPE_ETHERNET=1
        flow = mgr.get_or_create(pkt)
        assert flow is not None
        assert mgr.flow_count() == 1

    def test_same_flow_bidirectional(self, parser, mgr):
        """Forward and reverse packets map to the same flow."""
        syn = _make_tcp_syn_packet()
        synack = _make_tcp_synack_packet()

        pkt1 = parser.parse_packet_struct(syn, 1)
        pkt2 = parser.parse_packet_struct(synack, 1)

        flow1 = mgr.get_or_create(pkt1)
        flow2 = mgr.get_or_create(pkt2)

        assert flow1 is not None
        assert flow2 is not None
        assert mgr.flow_count() == 1  # Same flow

    def test_flow_key_fields(self, parser, mgr):
        """Flow key has correct IP/port/protocol fields."""
        raw = _make_tcp_syn_packet()
        pkt = parser.parse_packet_struct(raw, 1)
        flow = mgr.get_or_create(pkt)

        key = flow.key
        assert key.src_ip == "192.168.1.1"
        assert key.dst_ip == "10.0.0.1"
        assert key.src_port == 12345
        assert key.dst_port == 80
        assert key.protocol == 6

    def test_add_packet_metrics(self, parser, mgr):
        """add_packet updates metrics correctly."""
        raw = _make_tcp_syn_packet()
        pkt = parser.parse_packet_struct(raw, 1)
        pkt.wirelen = 54
        pkt.timestamp = 1000.0

        flow = mgr.get_or_create(pkt)
        flow.add_packet(pkt)

        assert flow.metrics.packet_count == 1
        assert flow.metrics.byte_count == 54
        assert flow.metrics.up_packet_count == 1
        assert flow.metrics.syn_count == 1

    def test_add_packet_bidirectional_metrics(self, parser, mgr):
        """Forward and reverse packets update directional metrics."""
        syn = _make_tcp_syn_packet()
        synack = _make_tcp_synack_packet()

        pkt1 = parser.parse_packet_struct(syn, 1)
        pkt1.wirelen = 54
        pkt1.timestamp = 1000.0

        pkt2 = parser.parse_packet_struct(synack, 1)
        pkt2.wirelen = 54
        pkt2.timestamp = 1000.1

        flow = mgr.get_or_create(pkt1)
        flow.add_packet(pkt1)

        flow2 = mgr.get_or_create(pkt2)
        assert flow2 is flow  # same flow
        flow.add_packet(pkt2)

        assert flow.metrics.packet_count == 2
        assert flow.metrics.up_packet_count == 1
        assert flow.metrics.down_packet_count == 1
        assert flow.metrics.syn_count == 2  # SYN + SYN-ACK both have SYN

    def test_sequence_accumulators(self, parser, mgr):
        """Sequence accumulators are populated with direction-signed values."""
        raw = _make_tcp_syn_packet()
        pkt = parser.parse_packet_struct(raw, 1)
        pkt.wirelen = 54
        pkt.timestamp = 1000.0

        flow = mgr.get_or_create(pkt)
        flow.add_packet(pkt)

        assert len(flow.seq_packet_lengths) == 1
        assert flow.seq_packet_lengths[0] == 54  # forward = positive
        assert len(flow.seq_timestamps) == 1
        assert flow.seq_timestamps[0] == 1000.0

    def test_reverse_packet_negative_lengths(self, parser, mgr):
        """Reverse direction packets have negative signed lengths."""
        syn = _make_tcp_syn_packet()
        synack = _make_tcp_synack_packet()

        pkt1 = parser.parse_packet_struct(syn, 1)
        pkt1.wirelen = 54
        pkt1.timestamp = 1000.0

        pkt2 = parser.parse_packet_struct(synack, 1)
        pkt2.wirelen = 60
        pkt2.timestamp = 1000.1

        flow = mgr.get_or_create(pkt1)
        flow.add_packet(pkt1)
        mgr.get_or_create(pkt2)
        flow.add_packet(pkt2)

        assert flow.seq_packet_lengths[0] == 54   # forward
        assert flow.seq_packet_lengths[1] == -60   # reverse

    def test_tcp_state_machine(self, parser, mgr):
        """TCP state transitions through SYN → SYN-ACK → ACK."""
        syn = _make_tcp_syn_packet()
        synack = _make_tcp_synack_packet()
        ack = _make_tcp_ack_packet()

        pkt1 = parser.parse_packet_struct(syn, 1)
        pkt1.timestamp = 1.0
        pkt2 = parser.parse_packet_struct(synack, 1)
        pkt2.timestamp = 1.1
        pkt3 = parser.parse_packet_struct(ack, 1)
        pkt3.timestamp = 1.2

        flow = mgr.get_or_create(pkt1)
        flow.add_packet(pkt1)
        flow.update_tcp_state(flow.packets[-1], 1)

        mgr.get_or_create(pkt2)
        flow.add_packet(pkt2)
        flow.update_tcp_state(flow.packets[-1], -1)

        mgr.get_or_create(pkt3)
        flow.add_packet(pkt3)
        # ACK after SYN-ACK doesn't change state (already ESTABLISHED from SYN-ACK)

        assert not flow.is_tcp_closed()

    def test_udp_flow_creation(self, parser, mgr):
        """UDP packets create flows correctly."""
        raw = _make_udp_packet([192, 168, 1, 1], [10, 0, 0, 1], 5000, 53, 20)
        pkt = parser.parse_packet_struct(raw, 1)
        flow = mgr.get_or_create(pkt)

        assert flow is not None
        assert flow.key.protocol == 17
        assert flow.key.src_port == 5000
        assert flow.key.dst_port == 53

    def test_udp_timeout(self, parser):
        """UDP timeout creates a new flow."""
        config = NativeFlowManagerConfig()
        config.udp_timeout = 5.0
        mgr = NativeFlowManager(config)

        raw = _make_udp_packet([192, 168, 1, 1], [10, 0, 0, 1], 5000, 53, 20)

        pkt1 = parser.parse_packet_struct(raw, 1)
        pkt1.timestamp = 1000.0
        flow1 = mgr.get_or_create(pkt1)
        flow1.add_packet(pkt1)

        # Same 5-tuple, within timeout
        pkt2 = parser.parse_packet_struct(raw, 1)
        pkt2.timestamp = 1003.0
        flow2 = mgr.get_or_create(pkt2)
        assert mgr.flow_count() == 1  # same flow

        # Same 5-tuple, after timeout
        pkt3 = parser.parse_packet_struct(raw, 1)
        pkt3.timestamp = 1010.0
        flow3 = mgr.get_or_create(pkt3)
        assert mgr.flow_count() == 1  # old flow moved to completed
        assert mgr.total_flow_count() == 2  # 1 completed + 1 active

    def test_max_flows(self, parser):
        """max_flows limit is respected."""
        config = NativeFlowManagerConfig()
        config.max_flows = 2
        mgr = NativeFlowManager(config)

        # Create 2 different flows
        raw1 = _make_udp_packet([192, 168, 1, 1], [10, 0, 0, 1], 5000, 53)
        raw2 = _make_udp_packet([192, 168, 1, 2], [10, 0, 0, 2], 5001, 53)
        raw3 = _make_udp_packet([192, 168, 1, 3], [10, 0, 0, 3], 5002, 53)

        pkt1 = parser.parse_packet_struct(raw1, 1)
        pkt2 = parser.parse_packet_struct(raw2, 1)
        pkt3 = parser.parse_packet_struct(raw3, 1)

        assert mgr.get_or_create(pkt1) is not None
        assert mgr.get_or_create(pkt2) is not None
        assert mgr.get_or_create(pkt3) is None  # max_flows reached
        assert mgr.flow_count() == 2

    def test_no_ip_returns_none(self, parser, mgr):
        """Packet without IP layer returns None."""
        import struct
        # ARP packet (no IP)
        eth = b'\xff' * 6 + b'\x00' * 6 + struct.pack('!H', 0x0806)
        arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1) + b'\x00' * 20
        raw = eth + arp
        pkt = parser.parse_packet_struct(raw, 1)
        assert mgr.get_or_create(pkt) is None

    def test_get_all_flows(self, parser, mgr):
        """get_all_flows returns all active flows."""
        raw1 = _make_udp_packet([192, 168, 1, 1], [10, 0, 0, 1], 5000, 53)
        raw2 = _make_udp_packet([192, 168, 1, 2], [10, 0, 0, 2], 5001, 80)

        pkt1 = parser.parse_packet_struct(raw1, 1)
        pkt2 = parser.parse_packet_struct(raw2, 1)

        mgr.get_or_create(pkt1)
        mgr.get_or_create(pkt2)

        flows = mgr.get_all_flows()
        assert len(flows) == 2

    def test_window_tracking(self, parser, mgr):
        """TCP window size tracking works."""
        raw = _make_tcp_syn_packet()
        pkt = parser.parse_packet_struct(raw, 1)
        pkt.wirelen = 54
        pkt.timestamp = 1.0

        flow = mgr.get_or_create(pkt)
        flow.add_packet(pkt)

        assert flow.metrics.max_window == 65535
        assert flow.metrics.min_window == 65535
        assert flow.metrics.sum_window == 65535

    def test_tcp_flag_counting(self, parser, mgr):
        """All TCP flag counters work correctly through 3-way handshake."""
        syn = _make_tcp_syn_packet()
        synack = _make_tcp_synack_packet()
        ack = _make_tcp_ack_packet()

        pkt1 = parser.parse_packet_struct(syn, 1)
        pkt1.wirelen = 54; pkt1.timestamp = 1.0
        pkt2 = parser.parse_packet_struct(synack, 1)
        pkt2.wirelen = 54; pkt2.timestamp = 1.1
        pkt3 = parser.parse_packet_struct(ack, 1)
        pkt3.wirelen = 54; pkt3.timestamp = 1.2

        flow = mgr.get_or_create(pkt1)
        flow.add_packet(pkt1)
        mgr.get_or_create(pkt2)
        flow.add_packet(pkt2)
        mgr.get_or_create(pkt3)
        flow.add_packet(pkt3)

        assert flow.metrics.syn_count == 2   # SYN + SYN-ACK
        assert flow.metrics.ack_count == 2   # SYN-ACK + ACK
        assert flow.metrics.fin_count == 0
        assert flow.metrics.rst_count == 0

    def test_clear(self, parser, mgr):
        """clear() removes all flows."""
        raw = _make_tcp_syn_packet()
        pkt = parser.parse_packet_struct(raw, 1)
        mgr.get_or_create(pkt)
        assert mgr.flow_count() == 1

        mgr.clear()
        assert mgr.flow_count() == 0
        assert mgr.total_flow_count() == 0
