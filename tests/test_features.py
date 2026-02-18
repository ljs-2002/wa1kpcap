"""Test feature extraction functionality."""

import pytest
import sys
import numpy as np
sys.path.insert(0, r'D:\MyProgram\wa1kpcap1')

from wa1kpcap.features.extractor import FlowFeatures, FeatureExtractor
from wa1kpcap.features.registry import (
    FeatureRegistry,
    FeatureType,
    BaseIncrementalFeature,
    EntropyFeatureProcessor,
    SlidingWindowStatsProcessor,
    ProtocolFieldProcessor,
    register_feature,
    get_global_registry,
)
from wa1kpcap.core.flow import Flow, FlowKey, FlowMetrics
from wa1kpcap.core.packet import ParsedPacket, IPInfo, TCPInfo


def test_flow_features_init():
    """Test FlowFeatures initialization."""
    features = FlowFeatures()
    assert len(features.packet_lengths) == 0
    assert len(features.ip_lengths) == 0
    assert len(features.trans_lengths) == 0
    assert len(features.app_lengths) == 0
    assert len(features.timestamps) == 0
    assert len(features.iats) == 0


def test_flow_features_from_flow_empty():
    """Test FlowFeatures.from_flow with empty flow."""
    key = FlowKey(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1, dst_port=2, protocol=6)
    flow = Flow(key=key, start_time=0.0)
    features = FlowFeatures.from_flow(flow)
    assert len(features.packet_lengths) == 0
    assert len(features.timestamps) == 0


def test_flow_features_from_flow():
    """Test FlowFeatures.from_flow with packets."""
    key = FlowKey(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1, dst_port=2, protocol=6)
    flow = Flow(key=key, start_time=0.0)

    # Add packets
    for i in range(3):
        ip = IPInfo(version=4, src="1.2.3.4", dst="5.6.7.8", proto=6, ttl=64, len=100, id=i, flags=0, offset=0)
        tcp = TCPInfo(sport=1, dport=2, seq=i*100, ack_num=i*100, flags=0x10, win=8192, urgent=0, options=b'')

        pkt = ParsedPacket(
            timestamp=float(i),
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            caplen=100,
            wirelen=100,
            ip_len=80,
            trans_len=60,
            app_len=40
        )
        pkt.ip = ip
        pkt.tcp = tcp
        flow.add_packet(pkt)

    features = FlowFeatures.from_flow(flow)
    assert len(features.packet_lengths) == 3
    assert len(features.timestamps) == 3
    assert len(features.tcp_flags) == 3
    assert len(features.tcp_window_sizes) == 3
    assert len(features.iats) == 2  # n-1 IAT values


def test_flow_features_compute_statistics():
    """Test statistics computation."""
    features = FlowFeatures()
    features.packet_lengths = np.array([100, 200, 300, 400, 500], dtype=np.int32)
    features.ip_lengths = np.array([80, 160, 240, 320, 400], dtype=np.int32)
    features.timestamps = np.array([0.0, 1.0, 2.0, 3.0, 4.0], dtype=np.float64)

    stats = features.compute_statistics()

    assert 'packet_lengths' in stats
    assert 'ip_lengths' in stats
    assert 'packet_count' in stats
    assert 'total_bytes' in stats
    assert 'duration' in stats

    pl_stats = stats['packet_lengths']
    assert pl_stats['mean'] == 300.0
    assert pl_stats['min'] == 100
    assert pl_stats['max'] == 500
    assert pl_stats['count'] == 5


def test_flow_features_compute_statistics_directional():
    """Test directional statistics."""
    features = FlowFeatures()
    # Positive = up (forward), negative = down (reverse)
    features.packet_lengths = np.array([100, 200, -150, -250, 300], dtype=np.int32)

    stats = features.compute_statistics()
    pl_stats = stats['packet_lengths']

    # Overall stats (absolute values)
    assert pl_stats['mean'] == 200.0
    assert pl_stats['count'] == 5

    # Up (positive)
    assert pl_stats['up_count'] == 3
    assert pl_stats['up_mean'] == 200.0

    # Down (negative, absolute)
    assert pl_stats['down_count'] == 2
    assert pl_stats['down_mean'] == 200.0


def test_flow_features_compute_statistics_empty():
    """Test statistics with empty arrays."""
    features = FlowFeatures()
    stats = features.compute_statistics()

    assert 'packet_count' in stats
    assert stats['packet_count'] == 0


def test_flow_features_to_dict():
    """Test to_dict method."""
    features = FlowFeatures()
    features.packet_lengths = np.array([100, 200], dtype=np.int32)
    features.timestamps = np.array([0.0, 1.0], dtype=np.float64)
    features.tcp_flags = np.array([0x10, 0x18], dtype=np.uint8)

    d = features.to_dict()
    assert 'packet_lengths' in d
    assert 'timestamps' in d
    assert 'tcp_flags' in d
    assert d['packet_lengths'] == [100, 200]
    assert d['timestamps'] == [0.0, 1.0]


def test_feature_extractor_init():
    """Test FeatureExtractor initialization."""
    extractor = FeatureExtractor(compute_statistics=True)
    assert extractor.compute_statistics == True

    extractor2 = FeatureExtractor(compute_statistics=False)
    assert extractor2.compute_statistics == False


def test_feature_extractor_extract():
    """Test extract method."""
    extractor = FeatureExtractor(compute_statistics=True)

    key = FlowKey(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1, dst_port=2, protocol=6)
    flow = Flow(key=key, start_time=0.0)

    # Add packets
    for i in range(3):
        ip = IPInfo(version=4, src="1.2.3.4", dst="5.6.7.8", proto=6, ttl=64, len=100, id=i, flags=0, offset=0)
        tcp = TCPInfo(sport=1, dport=2, seq=i*100, ack_num=i*100, flags=0x10, win=8192, urgent=0, options=b'')

        pkt = ParsedPacket(
            timestamp=float(i),
            raw_data=b'\x00' * 100,
            link_layer_type=1,
            caplen=100,
            wirelen=100,
            ip_len=80,
            trans_len=60,
            app_len=40
        )
        pkt.ip = ip
        pkt.tcp = tcp
        flow.add_packet(pkt)

    features = extractor.extract(flow)
    assert features is not None
    assert len(features.packet_lengths) == 3
    assert features._statistics != {}


def test_feature_extractor_extract_batch():
    """Test extract_batch method."""
    extractor = FeatureExtractor()

    key = FlowKey(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1, dst_port=2, protocol=6)
    flow = Flow(key=key, start_time=0.0)

    ip = IPInfo(version=4, src="1.2.3.4", dst="5.6.7.8", proto=6, ttl=64, len=100, id=1, flags=0, offset=0)
    tcp = TCPInfo(sport=1, dport=2, seq=100, ack_num=0, flags=0x10, win=8192, urgent=0, options=b'')
    pkt = ParsedPacket(timestamp=0.0, raw_data=b'\x00' * 100, link_layer_type=1, caplen=100, wirelen=100)
    pkt.ip = ip
    pkt.tcp = tcp
    flow.add_packet(pkt)

    flows = [flow]
    features_list = extractor.extract_batch(flows)
    assert len(features_list) == 1


def test_feature_extractor_extract_to_dict():
    """Test extract_to_dict method."""
    extractor = FeatureExtractor()

    key = FlowKey(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1, dst_port=2, protocol=6)
    flow = Flow(key=key, start_time=0.0)

    ip = IPInfo(version=4, src="1.2.3.4", dst="5.6.7.8", proto=6, ttl=64, len=100, id=1, flags=0, offset=0)
    tcp = TCPInfo(sport=1, dport=2, seq=100, ack_num=0, flags=0x10, win=8192, urgent=0, options=b'')
    pkt = ParsedPacket(timestamp=0.0, raw_data=b'\x00' * 100, link_layer_type=1, caplen=100, wirelen=100)
    pkt.ip = ip
    pkt.tcp = tcp
    flow.add_packet(pkt)

    d = extractor.extract_to_dict(flow)
    assert isinstance(d, dict)
    assert 'packet_lengths' in d


def test_feature_registry_init():
    """Test FeatureRegistry initialization."""
    registry = FeatureRegistry()
    assert len(registry._incremental_processors) == 0
    assert len(registry._extractors) == 0


def test_feature_registry_register_incremental():
    """Test registering incremental feature."""
    registry = FeatureRegistry()

    class DummyProcessor(BaseIncrementalFeature):
        def __init__(self):
            super().__init__("dummy", FeatureType.INCREMENTAL)
        def initialize(self, flow):
            pass
        def update(self, flow, pkt):
            pass
        def get_value(self, flow):
            return "dummy_value"

    processor = DummyProcessor()
    result = registry.register_incremental("dummy", processor, FeatureType.INCREMENTAL)

    assert result is processor
    assert registry.get_incremental_processor("dummy") is processor


def test_feature_registry_register_batch():
    """Test registering batch feature."""
    registry = FeatureRegistry()

    @registry.register("test_feature", FeatureType.STATISTICAL)
    def test_extractor(flow):
        return 42

    assert registry.get("test_feature") is not None
    assert registry.get("test_feature")(None) == 42


def test_feature_registry_get_by_type():
    """Test get_by_type method."""
    registry = FeatureRegistry()

    @registry.register("feat1", FeatureType.STATISTICAL)
    def feat1(flow):
        return 1

    @registry.register("feat2", FeatureType.STATISTICAL)
    def feat2(flow):
        return 2

    extractors = registry.get_by_type(FeatureType.STATISTICAL)
    assert len(extractors) == 2


def test_feature_registry_extract_all():
    """Test extract_all method."""
    registry = FeatureRegistry()

    @registry.register("feat1", FeatureType.STATISTICAL)
    def feat1(flow):
        return 1

    @registry.register("feat2", FeatureType.STATISTICAL)
    def feat2(flow):
        return 2

    results = registry.extract_all(None)
    assert 'feat1' in results
    assert 'feat2' in results


def test_feature_registry_extract_selected():
    """Test extract_selected method."""
    registry = FeatureRegistry()

    @registry.register("feat1", FeatureType.STATISTICAL)
    def feat1(flow):
        return 1

    @registry.register("feat2", FeatureType.STATISTICAL)
    def feat2(flow):
        return 2

    results = registry.extract_selected(None, ["feat1"])
    assert 'feat1' in results
    assert 'feat2' not in results


def test_feature_registry_unregister():
    """Test unregister method."""
    registry = FeatureRegistry()

    @registry.register("feat1", FeatureType.STATISTICAL)
    def feat1(flow):
        return 1

    assert registry.get("feat1") is not None
    assert registry.unregister("feat1") == True
    assert registry.get("feat1") is None


def test_feature_registry_clear():
    """Test clear method."""
    registry = FeatureRegistry()

    @registry.register("feat1", FeatureType.STATISTICAL)
    def feat1(flow):
        return 1

    registry.clear()
    assert len(registry._extractors) == 0
    assert len(registry._by_type) == 0


def test_feature_registry_list_features():
    """Test list_features method."""
    registry = FeatureRegistry()

    @registry.register("feat1", FeatureType.STATISTICAL)
    def feat1(flow):
        return 1

    @registry.register("feat2", FeatureType.STATISTICAL)
    def feat2(flow):
        return 2

    names = registry.list_features()
    assert "feat1" in names
    assert "feat2" in names


def test_entropy_feature_processor():
    """Test EntropyFeatureProcessor."""
    processor = EntropyFeatureProcessor()

    key = FlowKey(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1, dst_port=2, protocol=6)
    flow = Flow(key=key, start_time=0.0)

    processor.initialize(flow)
    assert 'entropy' in flow._feature_state

    pkt = ParsedPacket(timestamp=0.0, raw_data=b'\x00' * 100, link_layer_type=1, caplen=100, wirelen=100)
    processor.update(flow, pkt)

    value = processor.get_value(flow)
    assert 'raw_bytes_entropy' in value


def test_sliding_window_processor():
    """Test SlidingWindowStatsProcessor."""
    processor = SlidingWindowStatsProcessor(window_size=5)

    key = FlowKey(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1, dst_port=2, protocol=6)
    flow = Flow(key=key, start_time=0.0)

    processor.initialize(flow)
    assert 'sliding_window_stats' in flow._feature_state

    for i in range(5):
        pkt = ParsedPacket(timestamp=float(i), raw_data=b'\x00' * 100, link_layer_type=1, caplen=100, wirelen=100+i*10)
        processor.update(flow, pkt)

    value = processor.get_value(flow)
    assert 'packet_length_mean_sequence' in value


def test_protocol_field_processor():
    """Test ProtocolFieldProcessor."""
    processor = ProtocolFieldProcessor()

    key = FlowKey(src_ip="1.2.3.4", dst_ip="5.6.7.8", src_port=1, dst_port=2, protocol=6)
    flow = Flow(key=key, start_time=0.0)

    processor.initialize(flow)
    assert 'protocol_fields' in flow._feature_state

    ip = IPInfo(version=4, src="1.2.3.4", dst="5.6.7.8", proto=6, ttl=64, len=100, id=1, flags=0, offset=0)
    tcp = TCPInfo(sport=1, dport=2, seq=100, ack_num=0, flags=0x10, win=8192, urgent=0, options=b'')

    pkt = ParsedPacket(timestamp=0.0, raw_data=b'\x00' * 100, link_layer_type=1, caplen=100, wirelen=100)
    pkt.ip = ip
    pkt.tcp = tcp
    processor.update(flow, pkt)

    value = processor.get_value(flow)
    assert 'tcp_flags_sequence' in value
    assert 'tcp_window_sequence' in value


def test_register_feature_function():
    """Test register_feature helper function."""
    registry = get_global_registry()

    # Clean up first
    try:
        registry.unregister("test_helper_feat")
    except:
        pass

    @register_feature("test_helper_feat", FeatureType.STATISTICAL)
    def helper_feat(flow):
        return 123

    assert registry.get("test_helper_feat") is not None


def test_all():
    """Run all feature tests."""
    test_flow_features_init()
    test_flow_features_from_flow_empty()
    test_flow_features_from_flow()
    test_flow_features_compute_statistics()
    test_flow_features_compute_statistics_directional()
    test_flow_features_compute_statistics_empty()
    test_flow_features_to_dict()
    test_feature_extractor_init()
    test_feature_extractor_extract()
    test_feature_extractor_extract_batch()
    test_feature_extractor_extract_to_dict()
    test_feature_registry_init()
    test_feature_registry_register_incremental()
    test_feature_registry_register_batch()
    test_feature_registry_get_by_type()
    test_feature_registry_extract_all()
    test_feature_registry_extract_selected()
    test_feature_registry_unregister()
    test_feature_registry_clear()
    test_feature_registry_list_features()
    test_entropy_feature_processor()
    test_sliding_window_processor()
    test_protocol_field_processor()
    test_register_feature_function()
    print("test_features PASSED")


if __name__ == '__main__':
    test_all()
