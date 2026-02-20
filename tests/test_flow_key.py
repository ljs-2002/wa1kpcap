"""Test FlowKey class functionality."""

import pytest
import sys

from wa1kpcap.core.flow import FlowKey, FlowMetrics


def test_basic_creation():
    """Test basic FlowKey creation."""
    key = FlowKey(
        src_ip='192.168.0.1',
        dst_ip='192.168.0.2',
        src_port=80,
        dst_port=80,
        protocol=6
    )

    assert key.src_ip == '192.168.0.1'
    assert key.dst_ip == '192.168.0.2'
    assert key.src_port == 80
    assert key.dst_port == 80
    assert key.protocol == 6


def test_string_representation():
    """Test string representation of FlowKey."""
    key = FlowKey(
        src_ip='192.168.0.1',
        dst_ip='224.0.0.1',
        src_port=443,
        dst_port=80,
        protocol=6
    )

    key_str = str(key)
    assert '192.168.0.1:443 -> 224.0.0.1:80' in key_str
    assert '(TCP)' in key_str


def test_direction_method():
    """Test direction method."""
    key = FlowKey(
        src_ip='192.168.0.1',
        dst_ip='10.0.0.1',
        src_port=1234,
        dst_port=5678,
        protocol=6
    )

    # Forward direction (src matches)
    assert key.direction('192.168.0.1', 1234) == 1

    # Reverse direction (dst matches)
    assert key.direction('10.0.0.1', 5678) == -1


def test_reverse_method():
    """Test reverse method."""
    key = FlowKey(
        src_ip='192.168.0.1',
        dst_ip='10.0.0.1',
        src_port=1234,
        dst_port=5678,
        protocol=6
    )

    rev = key.reverse()
    assert rev.src_ip == '10.0.0.1'
    assert rev.dst_ip == '192.168.0.1'
    assert rev.src_port == 5678
    assert rev.dst_port == 1234


def test_hash_and_equality():
    """Test hash and equality."""
    key = FlowKey(
        src_ip='192.168.0.1',
        dst_ip='224.0.0.1',
        src_port=80,
        dst_port=80,
        protocol=6
    )

    key2 = FlowKey(
        src_ip='192.168.0.1',
        dst_ip='224.0.0.1',
        src_port=80,
        dst_port=80,
        protocol=6
    )

    # Hash equality
    assert hash(key) == hash(key2)

    # Object equality
    assert key == key2


def test_udp_flow_key():
    """Test UDP FlowKey creation."""
    key = FlowKey(
        src_ip='192.168.0.1',
        dst_ip='224.0.0.1',
        src_port=53,
        dst_port=53,
        protocol=17
    )

    assert key.protocol == 17
    assert str(key) == '192.168.0.1:53 -> 224.0.0.1:53 (UDP)'


def test_flow_metrics_initialization():
    """Test FlowMetrics initial values."""
    metrics = FlowMetrics()

    assert metrics.packet_count == 0
    assert metrics.byte_count == 0
    assert metrics.up_packet_count == 0
    assert metrics.down_packet_count == 0
    assert metrics.syn_count == 0
    assert metrics.fin_count == 0
    assert metrics.rst_count == 0
    assert metrics.min_window == 0
    assert metrics.max_window == 0
    assert metrics.sum_window == 0


def test_flow_metrics_update_window():
    """Test FlowMetrics update_window method."""
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


if __name__ == '__main__':
    test_basic_creation()
    test_string_representation()
    test_direction_method()
    test_reverse_method()
    test_hash_and_equality()
    test_udp_flow_key()
    test_flow_metrics_initialization()
    test_flow_metrics_update_window()
    print("test_flow_key PASSED")
