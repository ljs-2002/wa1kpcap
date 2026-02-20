"""
Feature extraction for network flows.

Provides FlowFeatures class for storing extracted features and FeatureExtractor
for computing features from flows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
import numpy as np

if TYPE_CHECKING:
    from wa1kpcap.core.flow import Flow

try:
    from wa1kpcap._wa1kpcap_native import compute_array_stats as _native_compute_stats
    from wa1kpcap._wa1kpcap_native import compute_batch_stats as _native_batch_stats
except ImportError:
    _native_compute_stats = None
    _native_batch_stats = None

_STAT_KEYS = ('mean', 'std', 'var', 'min', 'max', 'range', 'median',
              'sum', 'up_mean', 'up_std', 'up_min', 'up_max',
              'up_sum', 'up_count', 'down_mean', 'down_std',
              'down_min', 'down_max', 'down_sum', 'down_count', 'count')


@dataclass
class FlowFeatures:
    """
    Container for flow features with sequence and statistical attributes.

    Stores both sequence features (numpy arrays) and statistical features (computed
    from sequences). Packet lengths are signed to indicate direction: positive
    for up (forward/C2S), negative for down (reverse/S2C).

    Attributes:
        packet_lengths: Total packet lengths on wire (signed for direction)
        ip_lengths: IP layer lengths (signed for direction)
        trans_lengths: Transport layer lengths (signed for direction)
        app_lengths: Application payload lengths (signed for direction)
        timestamps: Packet timestamps in seconds
        iats: Inter-arrival times between consecutive packets
        payload_bytes: Alias for app_lengths (signed for direction)
        tcp_flags: TCP flags for each TCP packet
        tcp_window_sizes: TCP window sizes for each TCP packet
        _statistics: Computed statistical features (lazy evaluation)
        protocol_fields: Protocol-specific extracted fields

    Examples:
        Access packet length sequence:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> for flow in flows:
            ...     if flow.features:
            ...         lengths = flow.features.packet_lengths
            ...         print(f"Packet lengths: {lengths}")  # [100, -50, 200, -75, ...]

        Access statistical features:
            >>> stats = flow.features.compute_statistics()
            >>> pkt_stats = stats['packet_lengths']
            >>> print(f"Mean: {pkt_stats['mean']}")
            >>> print(f"Up count: {pkt_stats['up_count']}")
            >>> print(f"Down count: {pkt_stats['down_count']}")
            >>> print(f"Total packets: {stats['packet_count']}")

        Access IAT statistics:
            >>> iat_stats = stats['iats']
            >>> print(f"Mean IAT: {iat_stats['mean']:.6f}s")
            >>> print(f"Max IAT: {iat_stats['max']:.6f}s")
    """

    # Sequence features - 4 types of packet lengths
    packet_lengths: np.ndarray = field(default_factory=lambda: np.array([]))  # Total packet length (wirelen)
    ip_lengths: np.ndarray = field(default_factory=lambda: np.array([]))      # IP layer length (ip_len)
    trans_lengths: np.ndarray = field(default_factory=lambda: np.array([]))    # Transport layer length (trans_len)
    app_lengths: np.ndarray = field(default_factory=lambda: np.array([]))      # App payload length (app_len)
    timestamps: np.ndarray = field(default_factory=lambda: np.array([]))
    iats: np.ndarray = field(default_factory=lambda: np.array([]))  # Inter-arrival times
    payload_bytes: np.ndarray = field(default_factory=lambda: np.array([]))  # Legacy alias for app_lengths

    # TCP specific sequences
    tcp_flags: np.ndarray = field(default_factory=lambda: np.array([]))
    tcp_window_sizes: np.ndarray = field(default_factory=lambda: np.array([]))

    # Statistical features (computed lazily)
    _statistics: dict[str, Any] = field(default_factory=dict)

    # Protocol fields
    protocol_fields: dict[str, Any] = field(default_factory=dict)

    def compute_statistics(self) -> dict[str, Any]:
        """
        Compute statistical features from sequences.

        Calculates mean, std, var, min, max, range, median, skew, kurtosis, CV,
        and directional statistics (up/down) for each sequence type.

        Returns:
            Dictionary with statistical features for each sequence type.
            Includes 'packet_count', 'total_bytes', 'duration' at top level.
        """
        stats = {}

        # Batch path: compute all array stats in one C++ call (flat array return)
        if _native_batch_stats is not None:
            named = {}
            if len(self.packet_lengths) > 0:
                named['packet_lengths'] = self.packet_lengths
            if len(self.ip_lengths) > 0:
                named['ip_lengths'] = self.ip_lengths
            if len(self.trans_lengths) > 0:
                named['trans_lengths'] = self.trans_lengths
            if len(self.app_lengths) > 0:
                named['app_lengths'] = self.app_lengths
            if len(self.iats) > 0:
                named['iats'] = self.iats
            if len(self.payload_bytes) > 0:
                named['payload_bytes'] = self.payload_bytes
            if len(self.tcp_flags) > 0:
                named['tcp_flags'] = self.tcp_flags.astype(np.float64)
            if len(self.tcp_window_sizes) > 0:
                named['tcp_window'] = self.tcp_window_sizes
            if named:
                names, flat = _native_batch_stats(named)
                # Convert to Python list once — avoids numpy scalar boxing per access
                flat = flat.tolist()
                n_keys = 21
                for i, name in enumerate(names):
                    base = i * n_keys
                    stats[name] = {
                        'mean': flat[base], 'std': flat[base+1], 'var': flat[base+2],
                        'min': flat[base+3], 'max': flat[base+4], 'range': flat[base+5],
                        'median': flat[base+6], 'sum': flat[base+7],
                        'up_mean': flat[base+8], 'up_std': flat[base+9],
                        'up_min': flat[base+10], 'up_max': flat[base+11],
                        'up_sum': flat[base+12], 'up_count': int(flat[base+13]),
                        'down_mean': flat[base+14], 'down_std': flat[base+15],
                        'down_min': flat[base+16], 'down_max': flat[base+17],
                        'down_sum': flat[base+18], 'down_count': int(flat[base+19]),
                        'count': int(flat[base+20]),
                    }
        else:
            # Fallback: individual calls
            if len(self.packet_lengths) > 0:
                stats['packet_lengths'] = self._compute_array_stats(self.packet_lengths)
            if len(self.ip_lengths) > 0:
                stats['ip_lengths'] = self._compute_array_stats(self.ip_lengths)
            if len(self.trans_lengths) > 0:
                stats['trans_lengths'] = self._compute_array_stats(self.trans_lengths)
            if len(self.app_lengths) > 0:
                stats['app_lengths'] = self._compute_array_stats(self.app_lengths)
            if len(self.iats) > 0:
                stats['iats'] = self._compute_array_stats(self.iats)
            if len(self.payload_bytes) > 0:
                stats['payload_bytes'] = self._compute_array_stats(self.payload_bytes)
            if len(self.tcp_flags) > 0:
                stats['tcp_flags'] = self._compute_array_stats(self.tcp_flags.astype(np.float64))
            if len(self.tcp_window_sizes) > 0:
                stats['tcp_window'] = self._compute_array_stats(self.tcp_window_sizes)

        # Basic flow stats — derive from already-computed stats to avoid numpy calls
        pkt_stats = stats.get('packet_lengths')
        if pkt_stats:
            stats['packet_count'] = pkt_stats['count']
            stats['total_bytes'] = int(pkt_stats['sum'])
            up_count = pkt_stats['up_count']
            down_count = pkt_stats['down_count']
            up_bytes = int(pkt_stats['up_sum'])
            down_bytes = int(pkt_stats['down_sum'])
        else:
            stats['packet_count'] = len(self.packet_lengths)
            stats['total_bytes'] = 0
            up_count = down_count = 0
            up_bytes = down_bytes = 0
        iat_stats = stats.get('iats')
        if iat_stats:
            stats['duration'] = iat_stats['sum']
        elif len(self.timestamps) > 1:
            stats['duration'] = float(self.timestamps[-1] - self.timestamps[0])
        else:
            stats['duration'] = 0.0

        # Directional ratios
        stats['up_down_pkt_ratio'] = float(up_count) / float(down_count) if down_count > 0 else 0.0
        stats['up_down_byte_ratio'] = float(up_bytes) / float(down_bytes) if down_bytes > 0 else 0.0

        self._statistics = stats
        return stats

    @staticmethod
    def _compute_array_stats(arr: np.ndarray) -> dict[str, float]:
        """
        Compute statistics for an array using absolute values.

        Uses C++ single-pass implementation when available, falling back to
        pure Python for environments without the native extension.

        Args:
            arr: Numpy array with signed values (positive=up, negative=down)

        Returns:
            Dictionary with computed statistics including mean, std, var, min,
            max, range, median, and directional stats.
        """
        n = len(arr)
        if n == 0:
            return {}

        if _native_compute_stats is not None:
            try:
                return _native_compute_stats(arr.astype(np.float64))
            except Exception:
                pass

        # Fallback: single pass in pure Python
        vals = arr.tolist()  # one numpy call, then pure Python

        total = 0.0
        sq_total = 0.0
        lo = hi = abs(vals[0])
        up_total = up_sq = 0.0
        up_lo = up_hi = 0.0
        n_up = 0
        dn_total = dn_sq = 0.0
        dn_lo = dn_hi = 0.0
        n_dn = 0
        abs_vals = [0.0] * n  # pre-allocate for median sort

        for i, v in enumerate(vals):
            a = abs(v)
            abs_vals[i] = a
            total += a
            sq_total += a * a
            if a < lo:
                lo = a
            if a > hi:
                hi = a
            if v > 0:
                if n_up == 0:
                    up_lo = up_hi = a
                else:
                    if a < up_lo:
                        up_lo = a
                    if a > up_hi:
                        up_hi = a
                up_total += a
                up_sq += a * a
                n_up += 1
            elif v < 0:
                if n_dn == 0:
                    dn_lo = dn_hi = a
                else:
                    if a < dn_lo:
                        dn_lo = a
                    if a > dn_hi:
                        dn_hi = a
                dn_total += a
                dn_sq += a * a
                n_dn += 1

        mean = total / n
        var = sq_total / n - mean * mean
        if var < 0:
            var = 0.0  # guard floating-point rounding
        std = var ** 0.5

        # Median via sorted list
        abs_vals.sort()
        if n % 2 == 1:
            median = abs_vals[n // 2]
        else:
            median = (abs_vals[n // 2 - 1] + abs_vals[n // 2]) * 0.5

        # Directional std
        if n_up > 1:
            up_mean = up_total / n_up
            up_var = up_sq / n_up - up_mean * up_mean
            up_std = max(0.0, up_var) ** 0.5
        elif n_up == 1:
            up_mean = up_total
            up_std = 0.0
        else:
            up_mean = up_std = 0.0

        if n_dn > 1:
            dn_mean = dn_total / n_dn
            dn_var = dn_sq / n_dn - dn_mean * dn_mean
            dn_std = max(0.0, dn_var) ** 0.5
        elif n_dn == 1:
            dn_mean = dn_total
            dn_std = 0.0
        else:
            dn_mean = dn_std = 0.0

        return {
            'mean': mean,
            'std': std,
            'var': var,
            'min': lo,
            'max': hi,
            'range': hi - lo,
            'median': median,
            'sum': total,
            'up_mean': up_mean,
            'up_std': up_std,
            'up_min': up_lo,
            'up_max': up_hi,
            'up_sum': up_total,
            'up_count': n_up,
            'down_mean': dn_mean,
            'down_std': dn_std,
            'down_min': dn_lo,
            'down_max': dn_hi,
            'down_sum': dn_total,
            'down_count': n_dn,
            'count': n,
        }

    def to_dict(self) -> dict[str, Any]:
        """
        Convert features to dictionary.

        Returns:
            Dictionary with sequence arrays as lists and computed statistics.
        """
        result = {
            'packet_lengths': self.packet_lengths.tolist() if len(self.packet_lengths) > 0 else [],
            'ip_lengths': self.ip_lengths.tolist() if len(self.ip_lengths) > 0 else [],
            'trans_lengths': self.trans_lengths.tolist() if len(self.trans_lengths) > 0 else [],
            'app_lengths': self.app_lengths.tolist() if len(self.app_lengths) > 0 else [],
            'timestamps': self.timestamps.tolist() if len(self.timestamps) > 0 else [],
            'iats': self.iats.tolist() if len(self.iats) > 0 else [],
            'payload_bytes': self.payload_bytes.tolist() if len(self.payload_bytes) > 0 else [],
        }

        if len(self.tcp_flags) > 0:
            result['tcp_flags'] = self.tcp_flags.tolist()

        if len(self.tcp_window_sizes) > 0:
            result['tcp_window_sizes'] = self.tcp_window_sizes.tolist()

        if self._statistics:
            result['statistics'] = self._statistics

        if self.protocol_fields:
            result['protocol_fields'] = self.protocol_fields

        return result

    @classmethod
    def from_flow(cls, flow: Flow) -> FlowFeatures:
        """
        Extract features from a flow.

        Creates sequence features (packet lengths, timestamps, IATs, etc.)
        from the packets in a flow. Direction is determined by FlowKey.direction().

        Args:
            flow: Flow object with packets

        Returns:
            FlowFeatures with extracted sequences
        """
        if not flow.packets:
            return cls()

        # Fast path: use incrementally accumulated sequences
        if flow._seq_packet_lengths:
            features = cls()
            features.packet_lengths = np.array(flow._seq_packet_lengths, dtype=np.int32)
            features.ip_lengths = np.array(flow._seq_ip_lengths, dtype=np.int32)
            features.trans_lengths = np.array(flow._seq_trans_lengths, dtype=np.int32)
            features.app_lengths = np.array(flow._seq_app_lengths, dtype=np.int32)
            features.timestamps = np.array(flow._seq_timestamps, dtype=np.float64)
            features.payload_bytes = np.array(flow._seq_payload_bytes, dtype=np.int32)
            if flow._seq_tcp_flags:
                features.tcp_flags = np.array(flow._seq_tcp_flags, dtype=np.uint8)
            if flow._seq_tcp_windows:
                features.tcp_window_sizes = np.array(flow._seq_tcp_windows, dtype=np.uint16)
            if len(features.timestamps) > 1:
                features.iats = np.diff(features.timestamps)
            return features

        # Fallback: original traversal path (for manually constructed Flows)
        features = cls()

        # Extract basic sequences
        lengths = []       # Total packet length (wirelen)
        ip_lengths = []   # IP layer length (ip_len)
        trans_lengths = []  # Transport layer length (trans_len)
        app_lengths = []   # App payload length (app_len)
        timestamps = []
        payloads = []
        flags = []
        windows = []

        for pkt in flow.packets:
            timestamps.append(pkt.timestamp)

            # Use signed length for direction indication
            direction = flow.key.direction(
                pkt.ip.src if pkt.ip else pkt.ip6.src if pkt.ip6 else "",
                pkt.tcp.sport if pkt.tcp else pkt.udp.sport if pkt.udp else 0
            )

            # 4 types of packet lengths
            length = direction * pkt.wirelen
            lengths.append(length)

            ip_length = direction * pkt.ip_len
            ip_lengths.append(ip_length)

            trans_length = direction * pkt.trans_len
            trans_lengths.append(trans_length)

            app_length = direction * pkt.app_len
            app_lengths.append(app_length)

            # Payload bytes (app level)
            payload_len = len(pkt.payload)
            payloads.append(direction * payload_len)

            if pkt.tcp:
                flags.append(pkt.tcp.flags)
                windows.append(pkt.tcp.win)

        features.packet_lengths = np.array(lengths, dtype=np.int32)
        features.ip_lengths = np.array(ip_lengths, dtype=np.int32)
        features.trans_lengths = np.array(trans_lengths, dtype=np.int32)
        features.app_lengths = np.array(app_lengths, dtype=np.int32)
        features.timestamps = np.array(timestamps, dtype=np.float64)
        features.payload_bytes = np.array(payloads, dtype=np.int32)  # Legacy alias

        if flags:
            features.tcp_flags = np.array(flags, dtype=np.uint8)
        if windows:
            features.tcp_window_sizes = np.array(windows, dtype=np.uint16)

        # Compute IATs
        if len(timestamps) > 1:
            iats = np.diff(timestamps)
            features.iats = iats

        return features


class FeatureExtractor:
    """
    Extracts features from flows.

    Provides methods to extract sequence features and statistical features
    from individual flows or batches of flows.

    Examples:
        Basic usage:
            >>> from wa1kpcap import Wa1kPcap, FeatureExtractor
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> extractor = FeatureExtractor(compute_statistics=True)
            >>> for flow in flows:
            ...     features = extractor.extract(flow)
            ...     print(f"Packet lengths: {features.packet_lengths}")
            ...     stats = features.compute_statistics()
            ...     print(f"Mean packet length: {stats['packet_lengths']['mean']}")

        Batch extraction:
            >>> features_list = extractor.extract_batch(flows)
    """

    def __init__(self, compute_statistics: bool = True):
        """
        Initialize the FeatureExtractor.

        Args:
            compute_statistics: Whether to automatically compute statistics
                when extracting features (default: True)
        """
        self.compute_statistics = compute_statistics

    def extract(self, flow: Flow) -> FlowFeatures:
        """
        Extract features from a flow.

        Args:
            flow: Flow object to extract features from

        Returns:
            FlowFeatures with extracted sequences and optionally statistics
        """
        features = FlowFeatures.from_flow(flow)

        if self.compute_statistics:
            features.compute_statistics()

        return features

    def extract_batch(self, flows: list[Flow]) -> list[FlowFeatures]:
        """
        Extract features from multiple flows.

        Args:
            flows: List of Flow objects

        Returns:
            List of FlowFeatures, one per flow
        """
        return [self.extract(flow) for flow in flows]

    def extract_to_dict(self, flow: Flow) -> dict[str, Any]:
        """
        Extract features and return as dictionary.

        Args:
            flow: Flow object to extract features from

        Returns:
            Dictionary representation of features
        """
        features = self.extract(flow)
        return features.to_dict()
