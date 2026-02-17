"""
Feature extraction registry with decorator support.

Supports incremental per-packet feature computation during flow updates.

Architecture:
1. BaseIncrementalFeature: Abstract base class for incremental features
2. FeatureRegistry: Manages registered feature processors
3. register_feature decorator: Registers feature processors
4. Features are computed per-packet during Flow.add_packet()
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Callable, Any
from functools import wraps
import numpy as np
from typing import Deque
import math

if TYPE_CHECKING:
    from wa1kpcap.core.flow import Flow
    from wa1kpcap.core.packet import ParsedPacket


class FeatureType(Enum):
    """Feature type categories."""
    SEQUENCE = "sequence"  # Array of values (one per packet)
    STATISTICAL = "statistical"  # Single numeric value (aggregated)
    CATEGORICAL = "categorical"  # String or enum value
    BINARY = "binary"  # Boolean value
    CUSTOM = "custom"  # Any other type
    INCREMENTAL = "incremental"  # Incrementally computed per-packet


class BaseIncrementalFeature(ABC):
    """
    Abstract base class for incremental feature computation.

    Each feature processor maintains state across packets and computes
    feature values incrementally as packets are added.
    """

    def __init__(self, name: str, feature_type: FeatureType):
        self.name = name
        self.feature_type = feature_type

    @abstractmethod
    def initialize(self, flow: Flow) -> None:
        """Initialize feature state for a new flow."""
        pass

    @abstractmethod
    def update(self, flow: Flow, pkt: ParsedPacket) -> None:
        """Update feature state with a new packet."""
        pass

    @abstractmethod
    def get_value(self, flow: Flow) -> Any:
        """Get the current feature value."""
        pass


@dataclass
class EntropyFeatureState:
    """State for entropy-based features."""
    raw_bytes_entropy: list[float] = field(default_factory=list)
    transport_payload_entropy: list[float] = field(default_factory=list)
    app_payload_entropy: list[float] = field(default_factory=list)

    # For computing entropy incrementally
    _byte_counts: list[int] = field(default_factory=list)

    def add_entropy(self, entropy: float):
        self.raw_bytes_entropy.append(entropy)

    def add_transport_entropy(self, entropy: float):
        self.transport_payload_entropy.append(entropy)

    def add_app_entropy(self, entropy: float):
        self.app_payload_entropy.append(entropy)


@dataclass
class SlidingWindowFeatureState:
    """State for sliding window statistical features."""
    window_size: int = 10
    packet_length_window: Deque[float] = field(default_factory=deque)
    iat_window: Deque[float] = field(default_factory=deque)

    # Statistical sequences (value at position i = statistic over first i packets)
    mean_sequence: list[float] = field(default_factory=list)
    std_sequence: list[float] = field(default_factory=list)
    min_sequence: list[float] = field(default_factory=list)
    max_sequence: list[float] = field(default_factory=list)

    # Running statistics
    _count: int = 0
    _mean: float = 0.0
    _m2: float = 0.0  # For Welford's algorithm (variance)
    _min: float = float('inf')
    _max: float = float('-inf')

    def update(self, value: float) -> None:
        """Update running statistics with new value using Welford's algorithm."""
        self._count += 1

        # Update min/max
        if value < self._min:
            self._min = value
        if value > self._max:
            self._max = value

        # Welford's algorithm for online variance
        delta = value - self._mean
        self._mean += delta / self._count
        delta2 = value - self._mean
        self._m2 += delta * delta2

        # Store sequences
        self.mean_sequence.append(self._mean)

        if self._count >= 2:
            variance = self._m2 / self._count
            std = math.sqrt(variance)
        else:
            std = 0.0

        self.std_sequence.append(std)
        self.min_sequence.append(self._min if self._min != float('inf') else value)
        self.max_sequence.append(self._max if self._max != float('-inf') else value)

    def get_mean_sequence(self) -> np.ndarray:
        return np.array(self.mean_sequence)

    def get_std_sequence(self) -> np.ndarray:
        return np.array(self.std_sequence)

    def get_min_sequence(self) -> np.ndarray:
        return np.array(self.min_sequence)

    def get_max_sequence(self) -> np.ndarray:
        return np.array(self.max_sequence)


@dataclass
class ProtocolFieldFeatureState:
    """State for protocol field-based features."""
    tcp_flags_sequence: list[int] = field(default_factory=list)
    tcp_window_sequence: list[int] = field(default_factory=list)
    ttl_sequence: list[int] = field(default_factory=list)

    # Protocol-specific
    tls_content_types: list[int] = field(default_factory=list)
    tls_handshake_types: list[int] = field(default_factory=list)

    http_methods: list[str] = field(default_factory=list)
    http_user_agents: list[str] = field(default_factory=list)

    dns_query_names: list[str] = field(default_factory=list)

    # Direction-based sequences (up=forward, down=reverse)
    up_packet_lengths: list[int] = field(default_factory=list)
    down_packet_lengths: list[int] = field(default_factory=list)


class EntropyFeatureProcessor(BaseIncrementalFeature):
    """
    Computes entropy features from packet bytes.

    Features:
    - Raw bytes entropy per packet
    - Transport payload entropy per packet
    - App payload entropy per packet
    """

    def __init__(self):
        super().__init__("entropy", FeatureType.INCREMENTAL)

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['entropy'] = EntropyFeatureState()

    def update(self, flow: Flow, pkt: ParsedPacket) -> None:
        state: EntropyFeatureState = flow._feature_state.get('entropy')
        if state is None:
            return

        # Compute raw bytes entropy
        raw_entropy = self._compute_entropy(pkt.raw_data)
        state.add_entropy(raw_entropy)

        # Compute transport payload entropy (using app_len from pkt)
        # Transport payload = TCP/UDP header + app payload
        transport_payload_len = pkt.trans_len if hasattr(pkt, 'trans_len') else 0
        if transport_payload_len > 0 and len(pkt.raw_data) > 0:
            # For entropy, we need actual bytes, approximate from IP payload
            # IP payload = IP total - IP header (20 bytes typically)
            ip_payload_len = pkt.ip_len - 20 if hasattr(pkt, 'ip_len') and pkt.ip else 0
            if ip_payload_len > 0:
                # Create byte sequence representing payload (simplified)
                transport_payload = bytes([pkt.raw_data[i] if i < len(pkt.raw_data) else 0
                                          for i in range(min(ip_payload_len, 256))])
                transport_entropy = self._compute_entropy(transport_payload)
                state.add_transport_entropy(transport_entropy)

        # Compute app payload entropy
        app_payload_len = pkt.app_len if hasattr(pkt, 'app_len') else 0
        if app_payload_len > 0:
            # Get actual app payload bytes from packet
            app_payload = pkt.payload or b''
            if app_payload:
                app_entropy = self._compute_entropy(app_payload)
                state.add_app_entropy(app_entropy)

    def get_value(self, flow: Flow) -> dict[str, np.ndarray]:
        state: EntropyFeatureState = flow._feature_state.get('entropy')
        if state is None:
            return {}

        return {
            'raw_bytes_entropy': np.array(state.raw_bytes_entropy),
            'transport_payload_entropy': np.array(state.transport_payload_entropy),
            'app_payload_entropy': np.array(state.app_payload_entropy),
        }

    def _compute_entropy(self, data: bytes) -> float:
        """Compute Shannon entropy of byte sequence."""
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        data_len = len(data)
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy


class SlidingWindowStatsProcessor(BaseIncrementalFeature):
    """
    Computes sliding window and cumulative statistics.

    Features:
    - Cumulative mean sequence (value i = mean of first i packets)
    - Cumulative std sequence
    - Cumulative min/max sequences
    - Sliding window mean/std
    """

    def __init__(self, window_size: int = 10):
        super().__init__("sliding_window_stats", FeatureType.INCREMENTAL)
        self.window_size = window_size

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['sliding_window_stats'] = SlidingWindowFeatureState(
            window_size=self.window_size
        )
        flow._feature_state['iat_stats'] = SlidingWindowFeatureState(
            window_size=self.window_size
        )

    def update(self, flow: Flow, pkt: ParsedPacket) -> None:
        # Update packet length statistics
        stats_state: SlidingWindowFeatureState = flow._feature_state.get('sliding_window_stats')
        if stats_state:
            stats_state.update(float(pkt.wirelen))

            # Update sliding window
            stats_state.packet_length_window.append(pkt.wirelen)
            if len(stats_state.packet_length_window) > self.window_size:
                stats_state.packet_length_window.popleft()

    def get_value(self, flow: Flow) -> dict[str, Any]:
        stats_state: SlidingWindowFeatureState = flow._feature_state.get('sliding_window_stats')
        if stats_state is None:
            return {}

        return {
            'packet_length_mean_sequence': stats_state.get_mean_sequence(),
            'packet_length_std_sequence': stats_state.get_std_sequence(),
            'packet_length_min_sequence': stats_state.get_min_sequence(),
            'packet_length_max_sequence': stats_state.get_max_sequence(),
            'current_window_mean': np.mean(list(stats_state.packet_length_window)) if stats_state.packet_length_window else 0.0,
            'current_window_std': np.std(list(stats_state.packet_length_window)) if len(stats_state.packet_length_window) > 1 else 0.0,
        }


class ProtocolFieldProcessor(BaseIncrementalFeature):
    """
    Extracts protocol field-based features per packet.

    Features:
    - TCP flags sequence
    - TCP window size sequence
    - IP TTL sequence
    - TLS content types
    - HTTP methods
    - DNS query names/types
    - Direction-based packet lengths
    """

    def __init__(self):
        super().__init__("protocol_fields", FeatureType.INCREMENTAL)

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['protocol_fields'] = ProtocolFieldFeatureState()

    def update(self, flow: Flow, pkt: ParsedPacket) -> None:
        state: ProtocolFieldFeatureState = flow._feature_state.get('protocol_fields')
        if state is None:
            return

        # TCP fields
        if pkt.tcp:
            state.tcp_flags_sequence.append(pkt.tcp.flags)
            state.tcp_window_sequence.append(pkt.tcp.win)

        # IP TTL
        if pkt.ip:
            state.ttl_sequence.append(pkt.ip.ttl)
        elif pkt.ip6:
            state.ttl_sequence.append(pkt.ip6.hlim)

        # TLS fields (if available)
        if hasattr(pkt, 'tls') and pkt.tls:
            if hasattr(pkt.tls, 'content_type'):
                state.tls_content_types.append(pkt.tls.content_type)
            if hasattr(pkt.tls, 'handshake_type'):
                state.tls_handshake_types.append(pkt.tls.handshake_type)

        # HTTP fields (if available)
        if hasattr(pkt, 'http') and pkt.http:
            if hasattr(pkt.http, 'method'):
                state.http_methods.append(pkt.http.method)
            if hasattr(pkt.http, 'user_agent'):
                state.http_user_agents.append(pkt.http.user_agent)

        # DNS fields (if available)
        if hasattr(pkt, 'dns') and pkt.dns:
            if hasattr(pkt.dns, 'queries'):
                state.dns_query_names.extend(pkt.dns.queries)

        # Direction-based packet lengths
        direction = flow.key.direction(
            pkt.ip.src if pkt.ip else pkt.ip6.src if pkt.ip6 else "",
            pkt.tcp.sport if pkt.tcp else pkt.udp.sport if pkt.udp else 0
        )
        length = direction * pkt.wirelen
        if direction == 1:
            state.up_packet_lengths.append(length)
        else:
            state.down_packet_lengths.append(length)

    def get_value(self, flow: Flow) -> dict[str, Any]:
        state: ProtocolFieldFeatureState = flow._feature_state.get('protocol_fields')
        if state is None:
            return {}

        result = {}

        if state.tcp_flags_sequence:
            result['tcp_flags_sequence'] = np.array(state.tcp_flags_sequence)
        if state.tcp_window_sequence:
            result['tcp_window_sequence'] = np.array(state.tcp_window_sequence)
        if state.ttl_sequence:
            result['ttl_sequence'] = np.array(state.ttl_sequence)
        if state.tls_content_types:
            result['tls_content_types'] = np.array(state.tls_content_types)
        if state.tls_handshake_types:
            result['tls_handshake_types'] = np.array(state.tls_handshake_types)
        if state.http_methods:
            result['http_methods'] = state.http_methods
        if state.http_user_agents:
            result['http_user_agents'] = state.http_user_agents
        if state.dns_query_names:
            result['dns_query_names'] = state.dns_query_names
        if state.up_packet_lengths:
            result['up_packet_lengths'] = np.array(state.up_packet_lengths)
        if state.down_packet_lengths:
            result['down_packet_lengths'] = np.array(state.down_packet_lengths)

        return result


class FeatureRegistry:
    """
    Global registry for feature processors.

    Supports two types of feature extractors:
    1. Incremental processors (BaseIncrementalFeature): Computed per-packet
    2. Batch functions: Computed at the end of flow processing
    """

    def __init__(self):
        # Incremental processors (called per-packet)
        self._incremental_processors: dict[str, BaseIncrementalFeature] = {}

        # Batch extractors (called at end)
        self._extractors: dict[str, Callable[[Flow], Any]] = {}

        # Metadata
        self._by_type: dict[FeatureType, list[str]] = {}
        self._metadata: dict[str, dict] = {}

    def register_incremental(
        self,
        name: str,
        processor: BaseIncrementalFeature,
        feature_type: FeatureType = FeatureType.INCREMENTAL,
        description: str = ""
    ) -> BaseIncrementalFeature:
        """
        Register an incremental feature processor.

        Args:
            name: Unique feature name
            processor: Instance of BaseIncrementalFeature
            feature_type: Type of feature
            description: Human-readable description
        """
        if name in self._incremental_processors:
            raise ValueError(f"Feature {name} already registered as incremental")

        self._incremental_processors[name] = processor
        self._by_type.setdefault(feature_type, []).append(name)
        self._metadata[name] = {
            'type': feature_type,
            'description': description,
            'incremental': True
        }

        return processor

    def register(
        self,
        name: str,
        feature_type: FeatureType,
        dependencies: list[str] | None = None,
        description: str = ""
    ) -> Callable[[Callable], Callable]:
        """
        Register a batch feature extractor function.

        Args:
            name: Unique feature name
            feature_type: Type of feature
            dependencies: List of features this extractor depends on
            description: Human-readable description
        """
        def decorator(func: Callable[[Flow], Any]) -> Callable[[Flow], Any]:
            if name in self._extractors:
                raise ValueError(f"Feature {name} already registered")

            self._extractors[name] = func
            self._by_type.setdefault(feature_type, []).append(name)
            self._metadata[name] = {
                'type': feature_type,
                'dependencies': dependencies or [],
                'description': description,
                'incremental': False
            }

            @wraps(func)
            def wrapper(flow: Flow) -> Any:
                return func(flow)

            return wrapper

        return decorator

    def get_incremental_processor(self, name: str) -> BaseIncrementalFeature | None:
        """Get incremental processor by name."""
        return self._incremental_processors.get(name)

    def get(self, name: str) -> Callable[[Flow], Any] | None:
        """Get batch extractor by name."""
        return self._extractors.get(name)

    def get_by_type(self, feature_type: FeatureType) -> list[Callable[[Flow], Any]]:
        """Get all batch extractors for a specific type."""
        names = self._by_type.get(feature_type, [])
        return [self._extractors[name] for name in names if name in self._extractors]

    def extract(self, flow: Flow, name: str) -> Any:
        """Extract a specific feature from a flow."""
        # Try incremental processor first
        processor = self._incremental_processors.get(name)
        if processor:
            return processor.get_value(flow)

        # Try batch extractor
        extractor = self._extractors.get(name)
        if extractor:
            return extractor(flow)

        return None

    def extract_all(self, flow: Flow) -> dict[str, Any]:
        """Extract all registered features from a flow."""
        result = {}

        # Extract incremental features
        for name, processor in self._incremental_processors.items():
            try:
                value = processor.get_value(flow)
                if value is not None:
                    result[name] = value
            except Exception:
                pass

        # Extract batch features
        order = self._topological_sort()

        for name in order:
            if name in self._extractors:
                try:
                    result[name] = self._extractors[name](flow)
                except Exception:
                    result[name] = None

        return result

    def extract_selected(self, flow: Flow, names: list[str]) -> dict[str, Any]:
        """Extract selected features from a flow."""
        result = {}

        for name in names:
            # Try incremental first
            processor = self._incremental_processors.get(name)
            if processor:
                try:
                    value = processor.get_value(flow)
                    if value is not None:
                        result[name] = value
                except Exception:
                    result[name] = None
                continue

            # Try batch extractor
            if name in self._extractors:
                try:
                    result[name] = self._extractors[name](flow)
                except Exception:
                    result[name] = None

        return result

    def _topological_sort(self) -> list[str]:
        """Sort features by dependencies (topological order)."""
        visited = set()
        temp = set()
        result = []

        def visit(name: str):
            if name in temp:
                return  # Circular dependency
            if name in visited:
                return

            temp.add(name)

            meta = self._metadata.get(name, {})
            for dep in meta.get('dependencies', []):
                visit(dep)

            temp.remove(name)
            visited.add(name)
            result.append(name)

        for name in self._extractors:
            visit(name)

        return result

    def list_features(self) -> list[str]:
        """List all registered feature names."""
        all_names = list(self._incremental_processors.keys())
        all_names.extend(self._extractors.keys())
        return all_names

    def get_info(self, name: str) -> dict | None:
        """Get metadata about a feature."""
        return self._metadata.get(name)

    def unregister(self, name: str) -> bool:
        """Unregister a feature by name."""
        removed = False

        if name in self._incremental_processors:
            feature_type = self._metadata[name]['type']
            self._by_type[feature_type] = [
                n for n in self._by_type[feature_type] if n != name
            ]
            del self._incremental_processors[name]
            del self._metadata[name]
            removed = True

        if name in self._extractors:
            feature_type = self._metadata[name]['type']
            self._by_type[feature_type] = [
                n for n in self._by_type[feature_type] if n != name
            ]
            del self._extractors[name]
            del self._metadata[name]
            removed = True

        return removed

    def clear(self) -> None:
        """Clear all registered extractors."""
        self._incremental_processors.clear()
        self._extractors.clear()
        self._by_type.clear()
        self._metadata.clear()

    @property
    def incremental_processors(self) -> dict[str, BaseIncrementalFeature]:
        """Get all incremental processors."""
        return self._incremental_processors.copy()


# Global registry instance
_global_registry = FeatureRegistry()


def get_global_registry() -> FeatureRegistry:
    """Get the global feature registry."""
    return _global_registry


def register_feature(
    name: str,
    feature_type: FeatureType,
    dependencies: list[str] | None = None,
    description: str = "",
    registry: FeatureRegistry | None = None,
    processor: BaseIncrementalFeature | None = None
) -> Any:
    """
    Register a feature extractor or processor.

    For incremental features, pass a BaseIncrementalFeature instance.
    For batch features, use as a decorator on a function.

    Args:
        name: Unique feature name
        feature_type: Type of feature
        dependencies: List of features this extractor depends on (batch only)
        description: Human-readable description
        registry: Registry to use (defaults to global)
        processor: Incremental processor instance

    Examples:
        # Incremental feature
        register_feature('entropy', FeatureType.INCREMENTAL,
                        processor=EntropyFeatureProcessor())

        # Batch feature
        @register_feature('tcp_push_ratio', FeatureType.STATISTICAL)
        def tcp_push_ratio(flow: Flow) -> float:
            ...
    """
    if registry is None:
        registry = _global_registry

    # If processor is provided, register as incremental
    if processor is not None:
        return registry.register_incremental(name, processor, feature_type, description)

    # Otherwise, return decorator for batch function
    return registry.register(name, feature_type, dependencies, description)


def unregister_feature(name: str, registry: FeatureRegistry | None = None) -> bool:
    """Unregister a feature extractor by name."""
    if registry is None:
        registry = _global_registry
    return registry.unregister(name)


def get_feature_extractors(
    feature_type: FeatureType | None = None,
    registry: FeatureRegistry | None = None
) -> list[Callable]:
    """
    Get feature extractors matching the given criteria.

    Args:
        feature_type: Filter by feature type
        registry: Registry to query (defaults to global)

    Returns:
        List of matching extractor functions
    """
    if registry is None:
        registry = _global_registry

    if feature_type is not None:
        return registry.get_by_type(feature_type)

    return list(registry._extractors.values())
