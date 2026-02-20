"""Test exporter functionality."""

import pytest
import sys

from wa1kpcap.core.flow import Flow, FlowKey
from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo
from wa1kpcap.exporters import to_dict, to_dataframe, to_json, to_csv
import tempfile
import os


def create_test_flow():
    """Create a test flow with packets."""
    key = FlowKey(
        src_ip='192.168.1.1',
        dst_ip='10.0.0.1',
        src_port=1234,
        dst_port=443,
        protocol=6
    )

    flow = Flow(key=key, start_time=0.0)

    # Add some packets
    for i in range(3):
        pkt = ParsedPacket(
            timestamp=float(i),
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            wirelen=100,
            ip_len=80,
            trans_len=40,
            app_len=20,
        )
        pkt.ip = IPInfo(
            version=4,
            src='192.168.1.1',
            dst='10.0.0.1',
            proto=6,
            ttl=64,
            len=100,
            id=i,
            flags=0,
            offset=0
        )
        pkt.tcp = TCPInfo(
            sport=1234,
            dport=443,
            seq=i*100,
            ack_num=i*100,
            flags=0x10,
            win=8192,
            urgent=0,
            options=b''
        )
        flow.add_packet(pkt)

    return flow


def test_to_dict():
    """Test to_dict exporter."""
    flows = [create_test_flow()]
    result = to_dict(flows)

    assert isinstance(result, list)
    assert len(result) == 1
    assert 'key' in result[0]
    assert 'packet_count' in result[0]
    assert result[0]['packet_count'] == 3
    assert result[0]['byte_count'] == 300


def test_to_dict_multiple_flows():
    """Test to_dict with multiple flows."""
    flows = [create_test_flow() for _ in range(2)]
    results = to_dict(flows)

    assert isinstance(results, list)
    assert len(results) == 2
    assert all('packet_count' in r for r in results)


def test_to_dataframe():
    """Test to_dataframe exporter."""
    flows = [create_test_flow()]
    df = to_dataframe(flows)

    assert df is not None
    assert len(df) == 1
    assert 'packet_count' in df.columns or 'metrics.packet_count' in df.columns


def test_to_json():
    """Test to_json exporter."""
    flows = [create_test_flow()]

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        json_path = f.name

    try:
        to_json(flows, json_path)
        assert os.path.exists(json_path)

        # Read back and verify
        import json
        with open(json_path, 'r') as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 1
    finally:
        if os.path.exists(json_path):
            try:
                os.unlink(json_path)
            except (PermissionError, OSError):
                pass


def test_to_csv():
    """Test to_csv exporter."""
    flows = [create_test_flow() for _ in range(2)]

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
        csv_path = f.name

    try:
        to_csv(flows, csv_path)
        assert os.path.exists(csv_path)

        # Read back and verify
        import csv
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
    finally:
        if os.path.exists(csv_path):
            try:
                os.unlink(csv_path)
            except (PermissionError, OSError):
                pass


def test_to_csv_empty():
    """Test to_csv with empty flow list."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.csv') as f:
        csv_path = f.name

    try:
        to_csv([], csv_path)
        assert os.path.exists(csv_path)
    finally:
        if os.path.exists(csv_path):
            try:
                os.unlink(csv_path)
            except (PermissionError, OSError):
                pass


def test_all():
    """Run all exporter tests."""
    test_to_dict()
    test_to_dict_multiple_flows()
    test_to_dataframe()
    test_to_json()
    test_to_csv()
    test_to_csv_empty()
    print("test_exporters PASSED")


if __name__ == '__main__':
    test_all()
