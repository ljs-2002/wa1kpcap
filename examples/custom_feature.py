"""
Custom feature extraction example - Demonstrates incremental and non-incremental features.

Three parts:
1. How to define custom features (incremental and non-incremental)
2. Pass feature configuration to Wa1kPcap during initialization
3. Access custom features after parsing a pcap

Usage:
    flow.features.<name>.<attr>
    where <name> is your custom feature namespace and <attr> is the attribute
"""

from wa1kpcap import Wa1kPcap, Flow
from wa1kpcap.features.registry import BaseIncrementalFeature, FeatureType, register_feature
import numpy as np
from dataclasses import dataclass, field
from typing import Any
import math


# ============================================================================
# Part 1: Define Custom Features
# ============================================================================

# Example 1: Incremental feature - entropy sequence (computed per-packet)
@dataclass
class EntropyState:
    """State for entropy sequence feature."""
    raw_entropy: list[float] = field(default_factory=list)
    payload_entropy: list[float] = field(default_factory=list)


class EntropyFeature(BaseIncrementalFeature):
    """
    Incremental feature: computes entropy sequence per packet.

    Result access:
        flow.features.entropy.raw_entropy (array of per-packet raw entropy)
        flow.features.entropy.payload_entropy (array of per-packet payload entropy)
        flow.features.entropy.raw_entropy_max (single value: max raw entropy)
    """

    def __init__(self):
        super().__init__("entropy", FeatureType.INCREMENTAL)

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['entropy'] = EntropyState()

    def update(self, flow: Flow, pkt) -> None:
        state: EntropyState = flow._feature_state.get('entropy')
        if state is None:
            return

        # Compute raw packet entropy
        raw_ent = self._shannon_entropy(pkt.raw_data)
        state.raw_entropy.append(raw_ent)

        # Compute payload entropy
        if pkt.payload:
            payload_ent = self._shannon_entropy(pkt.payload)
            state.payload_entropy.append(payload_ent)

    def get_value(self, flow: Flow) -> dict:
        state: EntropyState = flow._feature_state.get('entropy')
        if state is None:
            return {}

        return {
            'raw_entropy': np.array(state.raw_entropy),
            'payload_entropy': np.array(state.payload_entropy),
            'raw_entropy_max': float(np.max(state.raw_entropy)) if state.raw_entropy else 0.0,
            'raw_entropy_mean': float(np.mean(state.raw_entropy)) if state.raw_entropy else 0.0,
        }

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        data_len = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        return entropy


# Example 2: Non-incremental feature - aggregate statistics (computed at end)
@dataclass
class AggregateState:
    """State for aggregate statistics feature."""
    packet_lengths: list[int] = field(default_factory=list)
    tcp_flags: list[int] = field(default_factory=list)

    def add_packet(self, wirelen: int, flags: int):
        self.packet_lengths.append(wirelen)
        self.tcp_flags.append(flags)


class AggregateFeature(BaseIncrementalFeature):
    """
    Non-incremental feature: collects packet data during flow,
    computes aggregate statistics at end.

    Result access:
        flow.features.agg.max_length (single value)
        flow.features.agg.min_length (single value)
        flow.features.agg.avg_length (single value)
    """

    def __init__(self):
        super().__init__("agg", FeatureType.STATISTICAL)

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['agg'] = AggregateState()

    def update(self, flow: Flow, pkt) -> None:
        state: AggregateState = flow._feature_state.get('agg')
        if state is None:
            return

        state.add_packet(pkt.wirelen, pkt.tcp.flags if pkt.tcp else 0)

    def get_value(self, flow: Flow) -> dict:
        state: AggregateState = flow._feature_state.get('agg')
        if state is None:
            return {}

        if not state.packet_lengths:
            return {}

        return {
            'max_length': int(np.max(state.packet_lengths)),
            'min_length': int(np.min(state.packet_lengths)),
            'avg_length': float(np.mean(state.packet_lengths)),
            'std_length': float(np.std(state.packet_lengths)),
        }


# Example 3: Sliding window statistics (cumulative sequences)
@dataclass
class SlidingWindowState:
    """State for sliding window statistics."""
    mean_sequence: list[float] = field(default_factory=list)
    window: list[int] = field(default_factory=list)
    window_size: int = 10
    count: int = 0
    sum: float = 0.0

    def update(self, value: float):
        self.count += 1
        self.sum += value
        mean = self.sum / self.count
        self.mean_sequence.append(mean)

        self.window.append(int(value))
        if len(self.window) > self.window_size:
            self.window.pop(0)


class SlidingWindowFeature(BaseIncrementalFeature):
    """
    Sliding window feature: computes cumulative mean sequence.

    Result access:
        flow.features.window.mean_sequence (array where value i = mean of first i packets)
        flow.features.window.current_mean (mean of last N packets)
    """

    def __init__(self, window_size: int = 10):
        super().__init__("window", FeatureType.SEQUENCE)
        self.window_size = window_size

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['window'] = SlidingWindowState(window_size=self.window_size)

    def update(self, flow: Flow, pkt) -> None:
        state: SlidingWindowState = flow._feature_state.get('window')
        if state is None:
            return

        state.update(float(pkt.wirelen))

    def get_value(self, flow: Flow) -> dict:
        state: SlidingWindowState = flow._feature_state.get('window')
        if state is None:
            return {}

        return {
            'mean_sequence': np.array(state.mean_sequence),
            'current_mean': float(np.mean(state.window)) if state.window else 0.0,
            'current_std': float(np.std(state.window)) if len(state.window) > 1 else 0.0,
        }


# ============================================================================
# Part 2: Initialize Wa1kPcap with Custom Features
# ============================================================================

# Create feature instances
entropy_feat = EntropyFeature()
agg_feat = AggregateFeature()
window_feat = SlidingWindowFeature(window_size=10)

# Create analyzer
analyzer = Wa1kPcap(
    verbose_mode=True,
    compute_statistics=True,
)

# Register custom features with analyzer
analyzer.register_feature('entropy', entropy_feat)
analyzer.register_feature('agg', agg_feat)
analyzer.register_feature('window', window_feat)

# Analyze pcap file
flows = analyzer.analyze_file('test/single.pcap')

print(f"Total flows: {len(flows)}")
print()

# ============================================================================
# Part 3: Access Custom Features
# ============================================================================

for flow in flows:
    print(f"Flow: {flow.src_ip}:{flow.sport} -> {flow.dst_ip}:{flow.dport}, {flow.proto}")
    print(f"  Packets: {flow.num_packets}")
    print(f"  Duration: {flow.duration:.6f}s")
    print()

    # Get all custom features
    features = flow.get_features()

    # Access entropy feature: flow.features.entropy.*
    if 'entropy' in features:
        entropy_data = features['entropy']
        print("  [entropy] Entropy Feature:")
        if 'raw_entropy' in entropy_data:
            raw_ent = entropy_data['raw_entropy']
            print(f"    Raw entropy: {raw_ent.tolist()[:5]}... (first 5)")
            print(f"    Max raw entropy: {entropy_data.get('raw_entropy_max', 0):.4f}")
            print(f"    Mean raw entropy: {entropy_data.get('raw_entropy_mean', 0):.4f}")
        if 'payload_entropy' in entropy_data:
            payload_ent = entropy_data['payload_entropy']
            print(f"    Payload entropy: {payload_ent.tolist()[:5]}... (first 5)")
        print()

    # Access aggregate feature: flow.features.agg.*
    if 'agg' in features:
        agg_data = features['agg']
        print("  [agg] Aggregate Feature:")
        print(f"    Max length: {agg_data.get('max_length', 0)}")
        print(f"    Min length: {agg_data.get('min_length', 0)}")
        print(f"    Avg length: {agg_data.get('avg_length', 0):.2f}")
        print(f"    Std length: {agg_data.get('std_length', 0):.2f}")
        print()

    # Access sliding window feature: flow.features.window.*
    if 'window' in features:
        window_data = features['window']
        print("  [window] Sliding Window Feature:")
        if 'mean_sequence' in window_data:
            mean_seq = window_data['mean_sequence']
            print(f"    Mean sequence: {mean_seq.tolist()[:5]}... (first 5)")
            print(f"    Final mean: {mean_seq[-1] if len(mean_seq) > 0 else 0:.2f}")
        print(f"    Current window mean: {window_data.get('current_mean', 0):.2f}")
        print(f"    Current window std: {window_data.get('current_std', 0):.2f}")
        print()

    # Show only first flow
    break
