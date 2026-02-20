"""Test Flow and FlowManager classes with packet operations."""

import pytest
import sys

from wa1kpcap.core.flow import Flow, FlowKey, FlowManager, FlowMetrics, TCPState, FlowManagerConfig
from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo


class TestFlow:
    """Test Flow class with packet operations."""

    def test_add_packet_basic(self):
        """Test basic add_packet functionality."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='10.0.0.1',
            src_port=1234,
            dst_port=443,
            protocol=6
        )

        flow = Flow(key=key, start_time=0.0)

        # Create packet with ip and tcp layers
        pkt = ParsedPacket(
            timestamp=0.0,
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            wirelen=100,
            ip_len=80,
            trans_len=60,
            app_len=40
        )
        pkt.ip = IPInfo(
            version=4,
            src='192.168.1.1',
            dst='10.0.0.1',
            proto=6,
            ttl=64,
            len=80,
            id=1,
            flags=0,
            offset=0
        )
        pkt.tcp = TCPInfo(
            sport=1234,
            dport=443,
            seq=100,
            ack_num=0,
            flags=0x10,
            win=8192,
            urgent=0,
            options=b''
        )

        flow.add_packet(pkt)

        assert len(flow.packets) == 1
        assert flow.metrics.packet_count == 1

    def test_add_packet_with_direction(self):
        """Test add_packet with direction tracking."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='10.0.0.1',
            src_port=1234,
            dst_port=443,
            protocol=6
        )

        flow = Flow(key=key, start_time=0.0)

        # Forward packet
        pkt1 = ParsedPacket(
            timestamp=0.0,
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            wirelen=100,
            ip_len=80,
            trans_len=60,
            app_len=40
        )
        pkt1.ip = IPInfo(
            version=4,
            src='192.168.1.1',
            dst='10.0.0.1',
            proto=6,
            ttl=64,
            len=80,
            id=1,
            flags=0,
            offset=0
        )
        pkt1.tcp = TCPInfo(
            sport=1234,
            dport=443,
            seq=100,
            ack_num=0,
            flags=0x10,
            win=8192,
            urgent=0,
            options=b''
        )

        # Reverse packet
        pkt2 = ParsedPacket(
            timestamp=1.0,
            raw_data=b'\x00' * 80,
            link_layer_type=1,
            wirelen=80,
            ip_len=60,
            trans_len=40,
            app_len=20
        )
        pkt2.ip = IPInfo(
            version=4,
            src='10.0.0.1',
            dst='192.168.1.1',
            proto=6,
            ttl=64,
            len=60,
            id=2,
            flags=0,
            offset=0
        )
        pkt2.tcp = TCPInfo(
            sport=443,
            dport=1234,
            seq=100,
            ack_num=110,
            flags=0x10,
            win=8192,
            urgent=0,
            options=b''
        )

        flow.add_packet(pkt1)
        flow.add_packet(pkt2)

        assert len(flow.packets) == 2
        assert flow.metrics.up_packet_count == 1
        assert flow.metrics.down_packet_count == 1

    def test_flow_time_properties(self):
        """Test start_time, end_time, duration."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='10.0.0.1',
            src_port=1234,
            dst_port=443,
            protocol=6
        )

        # Flow with explicit start_time and end_time
        flow = Flow(key=key, start_time=100.0, end_time=110.0)

        assert flow.start_time == 100.0
        assert flow.end_time == 110.0
        assert flow.duration == 10.0
        assert int(flow.duration * 1000) == 10000

        # Test default end_time
        flow2 = Flow(key=key, start_time=100.0)
        assert flow2.start_time == 100.0
        assert flow2.end_time == 0.0
        assert flow2.duration == -100.0  # 0.0 - 100.0


class TestFlowManager:
    """Test FlowManager class."""

    def test_flow_manager_basic(self):
        """Test basic FlowManager functionality."""
        manager = FlowManager(FlowManagerConfig(
            udp_timeout=60.0,
            tcp_cleanup_timeout=300.0,
            max_flows=100000
        ))

        # Create two packets with different flows
        pkt1 = ParsedPacket(
            timestamp=0.0,
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            wirelen=100,
            ip_len=80,
            trans_len=60,
            app_len=40
        )
        pkt1.ip = IPInfo(
            version=4,
            src='192.168.1.1',
            dst='10.0.0.1',
            proto=6,
            ttl=64,
            len=80,
            id=1,
            flags=0,
            offset=0
        )
        pkt1.tcp = TCPInfo(
            sport=1234,
            dport=443,
            seq=100,
            ack_num=0,
            flags=0x10,
            win=8192,
            urgent=0,
            options=b''
        )

        pkt2 = ParsedPacket(
            timestamp=0.0,
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            wirelen=100,
            ip_len=80,
            trans_len=60,
            app_len=40
        )
        pkt2.ip = IPInfo(
            version=4,
            src='192.168.1.1',
            dst='10.0.0.2',  # Different dest
            proto=6,
            ttl=64,
            len=80,
            id=1,
            flags=0,
            offset=0
        )
        pkt2.tcp = TCPInfo(
            sport=1234,
            dport=443,
            seq=100,
            ack_num=0,
            flags=0x10,
            win=8192,
            urgent=0,
            options=b''
        )

        flow1 = manager.get_or_create_flow(pkt1)
        flow2 = manager.get_or_create_flow(pkt2)

        assert flow1 is not None
        assert flow2 is not None
        assert manager.flow_count == 2

    def test_flow_manager_get_flow(self):
        """Test get_or_create_flow returns same flow."""
        manager = FlowManager(FlowManagerConfig())

        pkt = ParsedPacket(
            timestamp=0.0,
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            wirelen=100,
            ip_len=80,
            trans_len=60,
            app_len=40
        )
        pkt.ip = IPInfo(
            version=4,
            src='192.168.1.1',
            dst='10.0.0.1',
            proto=6,
            ttl=64,
            len=80,
            id=1,
            flags=0,
            offset=0
        )
        pkt.tcp = TCPInfo(
            sport=1234,
            dport=443,
            seq=100,
            ack_num=0,
            flags=0x10,
            win=8192,
            urgent=0,
            options=b''
        )

        flow1 = manager.get_or_create_flow(pkt)
        flow2 = manager.get_or_create_flow(pkt)

        assert flow1 is flow2  # Same object
        assert manager.flow_count == 1

    def test_flow_manager_clear(self):
        """Test clear method."""
        manager = FlowManager(FlowManagerConfig())

        pkt = ParsedPacket(
            timestamp=0.0,
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            wirelen=100,
            ip_len=80,
            trans_len=60,
            app_len=40
        )
        pkt.ip = IPInfo(
            version=4,
            src='192.168.1.1',
            dst='10.0.0.1',
            proto=6,
            ttl=64,
            len=80,
            id=1,
            flags=0,
            offset=0
        )
        pkt.tcp = TCPInfo(
            sport=1234,
            dport=443,
            seq=100,
            ack_num=0,
            flags=0x10,
            win=8192,
            urgent=0,
            options=b''
        )

        manager.get_or_create_flow(pkt)
        assert manager.flow_count == 1

        manager.clear()
        assert manager.flow_count == 0


class TestTCPState:
    """Test TCPState enum and state machine."""

    def test_state_values(self):
        """Test state enum values."""
        assert TCPState.CLOSED.value == 0
        assert TCPState.SYN_SENT.value == 1
        assert TCPState.SYN_RECEIVED.value == 2
        assert TCPState.ESTABLISHED.value == 3
        assert TCPState.FIN_WAIT_1.value == 4
        assert TCPState.FIN_WAIT_2.value == 5
        assert TCPState.CLOSING.value == 6
        assert TCPState.TIME_WAIT.value == 7
        assert TCPState.CLOSE_WAIT.value == 8
        assert TCPState.LAST_ACK.value == 9
        assert TCPState.RESET.value == 10

    def test_state_names(self):
        """Test state names."""
        assert TCPState.CLOSED.name == 'CLOSED'
        assert TCPState.ESTABLISHED.name == 'ESTABLISHED'
        assert TCPState.CLOSING.name == 'CLOSING'
        assert TCPState.RESET.name == 'RESET'


class TestFlowMetrics:
    """Test FlowMetrics class."""

    def test_initialization(self):
        """Test initial values."""
        metrics = FlowMetrics()

        assert metrics.packet_count == 0
        assert metrics.byte_count == 0
        assert metrics.up_packet_count == 0
        assert metrics.down_packet_count == 0
        assert metrics.up_byte_count == 0
        assert metrics.down_byte_count == 0
        assert metrics.syn_count == 0
        assert metrics.fin_count == 0
        assert metrics.rst_count == 0
        assert metrics.ack_count == 0
        assert metrics.psh_count == 0
        assert metrics.urg_count == 0
        assert metrics.retrans_count == 0
        assert metrics.out_of_order_count == 0
        assert metrics.min_window == 0
        assert metrics.max_window == 0
        assert metrics.sum_window == 0

    def test_tcp_metrics(self):
        """Test TCP-specific metrics."""
        metrics = FlowMetrics()
        metrics.syn_count = 5
        metrics.fin_count = 2
        metrics.rst_count = 1
        metrics.ack_count = 10
        metrics.psh_count = 3
        metrics.urg_count = 0

        assert metrics.syn_count == 5
        assert metrics.fin_count == 2
        assert metrics.rst_count == 1
        assert metrics.ack_count == 10
        assert metrics.psh_count == 3

    def test_update_window(self):
        """Test update_window method."""
        metrics = FlowMetrics()

        # First update sets both min and max
        metrics.update_window(100)
        assert metrics.min_window == 100
        assert metrics.max_window == 100
        assert metrics.sum_window == 100

        # Lower value updates min
        metrics.update_window(64)
        assert metrics.min_window == 64
        assert metrics.max_window == 100
        assert metrics.sum_window == 164

        # Higher value updates max
        metrics.update_window(500)
        assert metrics.min_window == 64
        assert metrics.max_window == 500
        assert metrics.sum_window == 664


class TestFlowKey:
    """Test FlowKey class."""

    def test_basic_creation(self):
        """Test basic FlowKey creation."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='192.168.1.2',
            src_port=80,
            dst_port=80,
            protocol=6
        )

        assert key.src_ip == '192.168.1.1'
        assert key.dst_ip == '192.168.1.2'
        assert key.src_port == 80
        assert key.dst_port == 80
        assert key.protocol == 6

    def test_string_representation(self):
        """Test string representation of FlowKey."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='224.0.0.1',
            src_port=443,
            dst_port=80,
            protocol=6
        )

        key_str = str(key)
        assert '192.168.1.1:443 -> 224.0.0.1:80' in key_str
        assert '(TCP)' in key_str

    def test_direction_method(self):
        """Test direction method."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='10.0.0.1',
            src_port=1234,
            dst_port=5678,
            protocol=6
        )

        # Forward direction (src matches)
        assert key.direction('192.168.1.1', 1234) == 1

        # Reverse direction (dst matches)
        assert key.direction('10.0.0.1', 5678) == -1

    def test_reverse_method(self):
        """Test reverse method."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='10.0.0.1',
            src_port=1234,
            dst_port=5678,
            protocol=6
        )

        rev = key.reverse()
        assert rev.src_ip == '10.0.0.1'
        assert rev.dst_ip == '192.168.1.1'
        assert rev.src_port == 5678
        assert rev.dst_port == 1234

    def test_hash_and_equality(self):
        """Test hash and equality."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='224.0.0.1',
            src_port=80,
            dst_port=80,
            protocol=6
        )

        key2 = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='224.0.0.1',
            src_port=80,
            dst_port=80,
            protocol=6
        )

        # Hash equality
        assert hash(key) == hash(key2)

        # Object equality
        assert key == key2

    def test_udp_flow_key(self):
        """Test UDP FlowKey creation."""
        key = FlowKey(
            src_ip='192.168.1.1',
            dst_ip='224.0.0.1',
            src_port=53,
            dst_port=53,
            protocol=17
        )

        assert key.protocol == 17
        assert str(key) == '192.168.1.1:53 -> 224.0.0.1:53 (UDP)'
