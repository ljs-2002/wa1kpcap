"""Test exporters module for coverage."""

import pytest
import sys
import os
import json
import tempfile
from pathlib import Path

sys.path.insert(0, r'D:\MyProgram\wa1kpcap1')

from wa1kpcap.exporters import to_dataframe, to_dict, to_json, to_csv, to_list_of_dicts, FlowExporter
from wa1kpcap.core.flow import Flow, FlowKey
from wa1kpcap.features import FlowFeatures
import numpy as np


def create_test_flow(flow_id=1, has_features=False):
    """Create a test flow for exporting."""
    from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo

    key = FlowKey(
        src_ip=f'192.168.1.{flow_id}',
        dst_ip=f'10.0.0.{flow_id}',
        src_port=1000 + flow_id,
        dst_port=80,
        protocol=6
    )

    flow = Flow(key=key, start_time=flow_id * 0.1)

    # Add some packets with proper IP and TCP info
    for i in range(3):
        pkt = ParsedPacket(timestamp=flow_id * 0.1 + i * 0.01, raw_data=b'data')
        pkt.ip = IPInfo(
            src=f'192.168.1.{flow_id}',
            dst=f'10.0.0.{flow_id}',
            version=4,
            proto=6,
            ttl=64,
            _raw=b''
        )
        # Alternate between client-to-server and server-to-client by changing ports
        if i % 2 == 0:
            pkt.tcp = TCPInfo(
                sport=1000 + flow_id,
                dport=80,
                seq=1000 + i * 100,
                ack_num=0,
                flags=0x02,
                win=8192,
                _raw=b''
            )
        else:
            pkt.tcp = TCPInfo(
                sport=80,
                dport=1000 + flow_id,
                seq=2000 + i * 100,
                ack_num=1100,
                flags=0x12,
                win=8192,
                _raw=b''
            )
        flow.add_packet(pkt)

    if has_features:
        flow.features = FlowFeatures()
        flow.features.packet_lengths = np.array([100, 200, -150])
        flow.features.timestamps = np.array([0.0, 0.01, 0.02])
        flow.features.iats = np.array([0.01, 0.01])
        flow.features.payload_bytes = np.array([50, 100, -75])

    return flow


def test_to_dict_with_features():
    """Test to_dict with features."""
    flows = [create_test_flow(1, has_features=True)]
    result = to_dict(flows, include_features=True)
    assert 'features' in result[0]


def test_to_dict_without_features():
    """Test to_dict without features."""
    flows = [create_test_flow(1, has_features=True)]
    result = to_dict(flows, include_features=False)
    assert 'features' not in result[0]


def test_to_dict_empty_flows():
    """Test to_dict with empty flow list."""
    result = to_dict([])
    assert result == []


def test_to_list_of_dicts_flatten_features():
    """Test to_list_of_dicts with flatten_features=True."""
    flows = [create_test_flow(1, has_features=True)]
    result = to_list_of_dicts(flows, flatten_features=True)

    # With flattened features, should have dot notation keys
    assert any('feature.' in k for k in result[0].keys())


def test_to_list_of_dicts_no_flatten():
    """Test to_list_of_dicts with flatten_features=False."""
    flows = [create_test_flow(1, has_features=True)]
    result = to_list_of_dicts(flows, flatten_features=False)

    # Features should be nested
    assert 'features' in result[0]


def test_to_list_of_dicts_no_features():
    """Test to_list_of_dicts with flow that has no features."""
    flows = [create_test_flow(1, has_features=False)]
    result = to_list_of_dicts(flows, flatten_features=True)
    # Should not crash and should not have feature keys
    assert not any('feature.' in k for k in result[0].keys())


def test_to_dataframe_with_features():
    """Test to_dataframe with features."""
    flows = [create_test_flow(1, has_features=True)]
    df = to_dataframe(flows)
    assert 'feature.packet_lengths' in df.columns


def test_to_dataframe_empty_flows():
    """Test to_dataframe with empty flow list."""
    df = to_dataframe([])
    assert len(df) == 0


def test_to_json_with_path_object():
    """Test to_json with Path object."""
    flows = [create_test_flow(1)]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json_path = Path(f.name)

    try:
        to_json(flows, json_path, include_features=False)
        assert json_path.exists()

        with open(json_path, 'r') as f:
            data = json.load(f)
        assert len(data) == 1
    finally:
        try:
            os.unlink(json_path)
        except:
            pass


def test_to_csv_with_path_object():
    """Test to_csv with Path object."""
    flows = [create_test_flow(1)]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        csv_path = Path(f.name)

    try:
        to_csv(flows, csv_path, include_features=False)
        assert csv_path.exists()
    finally:
        try:
            os.unlink(csv_path)
        except:
            pass


class TestFlowExporter:
    """Test FlowExporter class."""

    def test_init_defaults(self):
        """Test FlowExporter default initialization."""
        exporter = FlowExporter()
        assert exporter.include_features is True
        assert exporter.flatten_features is False

    def test_init_with_params(self):
        """Test FlowExporter initialization with params."""
        exporter = FlowExporter(include_features=False, flatten_features=True)
        assert exporter.include_features is False
        assert exporter.flatten_features is True

    def test_to_dataframe(self):
        """Test FlowExporter.to_dataframe."""
        exporter = FlowExporter()
        flows = [create_test_flow(1)]
        df = exporter.to_dataframe(flows)
        assert len(df) == 1

    def test_to_dict_flatten(self):
        """Test FlowExporter.to_dict with flatten."""
        exporter = FlowExporter(include_features=True, flatten_features=True)
        flows = [create_test_flow(1, has_features=True)]
        result = exporter.to_dict(flows)
        assert any('feature.' in k for k in result[0].keys())

    def test_to_dict_no_flatten(self):
        """Test FlowExporter.to_dict without flatten."""
        exporter = FlowExporter(include_features=True, flatten_features=False)
        flows = [create_test_flow(1, has_features=True)]
        result = exporter.to_dict(flows)
        assert 'features' in result[0]

    def test_to_json(self):
        """Test FlowExporter.to_json."""
        exporter = FlowExporter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json_path = f.name

        try:
            flows = [create_test_flow(1)]
            exporter.to_json(flows, json_path, indent=2)

            with open(json_path, 'r') as f:
                data = json.load(f)
            assert len(data) == 1
        finally:
            try:
                os.unlink(json_path)
            except:
                pass

    def test_to_csv(self):
        """Test FlowExporter.to_csv."""
        exporter = FlowExporter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            csv_path = Path(f.name)

        try:
            flows = [create_test_flow(1)]
            exporter.to_csv(flows, csv_path)
            assert csv_path.exists()
        finally:
            try:
                os.unlink(csv_path)
            except:
                pass

    def test_save_json(self):
        """Test FlowExporter.save with JSON."""
        exporter = FlowExporter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            path = f.name

        try:
            flows = [create_test_flow(1)]
            exporter.save(flows, path)
            assert os.path.exists(path)
        finally:
            try:
                os.unlink(path)
            except:
                pass

    def test_save_csv(self):
        """Test FlowExporter.save with CSV."""
        exporter = FlowExporter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            path = f.name

        try:
            flows = [create_test_flow(1)]
            exporter.save(flows, path)
            assert os.path.exists(path)
        finally:
            try:
                os.unlink(path)
            except:
                pass

    def test_save_parquet(self):
        """Test FlowExporter.save with parquet extension."""
        exporter = FlowExporter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.parquet', delete=False) as f:
            path = f.name

        try:
            flows = [create_test_flow(1)]
            exporter.save(flows, path)
            # Parquet file should be created
            assert os.path.exists(path) or os.path.exists(path + '.parquet')
        except ImportError:
            pytest.skip("pyarrow not installed")
        finally:
            try:
                if os.path.exists(path):
                    os.unlink(path)
                if os.path.exists(path + '.parquet'):
                    os.unlink(path + '.parquet')
            except:
                pass

    def test_save_unsupported_extension(self):
        """Test FlowExporter.save with unsupported extension."""
        exporter = FlowExporter()
        flows = [create_test_flow(1)]

        with pytest.raises(ValueError, match="Unsupported file extension"):
            exporter.save(flows, 'test.txt')

    def test_save_path_object(self):
        """Test FlowExporter.save with Path object."""
        exporter = FlowExporter()

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            path = Path(f.name)

        try:
            flows = [create_test_flow(1)]
            exporter.save(flows, path)
            assert path.exists()
        finally:
            try:
                os.unlink(path)
            except:
                pass


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
