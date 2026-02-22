"""
Flow management - Flow, FlowKey, FlowManager, TCP state machine.

Implements flow tracking with TCP state machine and UDP timeout.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntFlag
import time
from typing import TYPE_CHECKING


class Protocol(IntFlag):
    """IP protocol numbers."""
    ICMP = 1
    TCP = 6
    UDP = 17
    ICMPv6 = 58
    OSPF = 89
    SCTP = 132


class TCPState(Enum):
    """TCP connection state machine."""
    CLOSED = 0
    SYN_SENT = 1
    SYN_RECEIVED = 2
    ESTABLISHED = 3
    FIN_WAIT_1 = 4
    FIN_WAIT_2 = 5
    CLOSING = 6
    TIME_WAIT = 7
    CLOSE_WAIT = 8
    LAST_ACK = 9
    RESET = 10


@dataclass(frozen=True)
class FlowKey:
    """
    Immutable hashable key for flow identification and direction tracking.

    A flow is identified by the 5-tuple (source IP, destination IP, source port,
    destination port, protocol) with optional VLAN ID. The direction is determined
    by the first packet that creates the flow - src_ip/src_port represents the
    sender of the first packet.

    Attributes:
        src_ip: Source IP address of the first packet
        dst_ip: Destination IP address of the first packet
        src_port: Source port of the first packet
        dst_port: Destination port of the first packet
        protocol: IP protocol number (6=TCP, 17=UDP, etc.)
        vlan_id: Optional VLAN ID for tagged flows (default: 0)

    Examples:
        >>> from wa1kpcap import FlowKey
        >>> key = FlowKey('192.168.1.1', '10.0.0.1', 1234, 80, 6)
        >>> print(key)
        192.168.1.1:1234 -> 10.0.0.1:80 (TCP)
        >>> key.direction('192.168.1.1', 1234)  # Forward
        1
        >>> key.direction('10.0.0.1', 80)  # Reverse
        -1
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    vlan_id: int = 0

    def __post_init__(self):
        # For IPv4, we want to normalize IP addresses to string format
        # But preserve the direction from the first packet
        # No canonical ordering - keep first packet's direction as-is
        if not isinstance(self.src_ip, str):
            object.__setattr__(self, 'src_ip', str(self.src_ip))
        if not isinstance(self.dst_ip, str):
            object.__setattr__(self, 'dst_ip', str(self.dst_ip))

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.protocol_name})"

    @property
    def protocol_name(self) -> str:
        names = {1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6'}
        return names.get(self.protocol, f'PROTO({self.protocol})')

    def direction(self, ip: str, port: int) -> int:
        """Returns 1 for forward direction, -1 for reverse."""
        if ip == self.src_ip and port == self.src_port:
            return 1
        return -1

    def reverse(self) -> FlowKey:
        """Create a reversed flow key."""
        return FlowKey(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
            vlan_id=self.vlan_id
        )


@dataclass
class FlowMetrics:
    """
    Per-flow metrics tracking packet and byte counts.

    Tracks basic statistics for each flow including total counts and
    directional (up/down) counts for packets and bytes.

    Attributes:
        packet_count: Total number of packets in the flow
        byte_count: Total number of bytes (wire length) in the flow
        up_packet_count: Number of packets in the up (forward) direction
        up_byte_count: Number of bytes in the up (forward) direction
        down_packet_count: Number of packets in the down (reverse) direction
        down_byte_count: Number of bytes in the down (reverse) direction
        syn_count: Number of TCP SYN packets
        fin_count: Number of TCP FIN packets
        rst_count: Number of TCP RST packets
        ack_count: Number of TCP ACK packets
        psh_count: Number of TCP PSH packets
        urg_count: Number of TCP URG packets
        retrans_count: Number of retransmitted packets
        out_of_order_count: Number of out-of-order packets
        min_window: Minimum TCP window size observed
        max_window: Maximum TCP window size observed
        sum_window: Sum of all TCP window sizes observed

    Examples:
        >>> from wa1kpcap import FlowMetrics
        >>> metrics = FlowMetrics()
        >>> metrics.packet_count = 100
        >>> metrics.up_packet_count = 60
        >>> metrics.down_packet_count = 40
    """
    packet_count: int = 0
    byte_count: int = 0
    up_packet_count: int = 0
    up_byte_count: int = 0
    down_packet_count: int = 0
    down_byte_count: int = 0

    # TCP specific
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    ack_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    # Retransmissions
    retrans_count: int = 0
    out_of_order_count: int = 0

    # Window size tracking
    min_window: int = 0
    max_window: int = 0
    sum_window: int = 0

    def update_window(self, win: int) -> None:
        """
        Update TCP window size statistics.

        Args:
            win: TCP window size from packet
        """
        if self.min_window == 0 or win < self.min_window:
            self.min_window = win
        if win > self.max_window:
            self.max_window = win
        self.sum_window += win


@dataclass
class Flow:
    """
    Represents a bidirectional network flow.

    A flow is a collection of packets sharing the same 5-tuple (source IP,
    destination IP, source port, destination port, protocol). It maintains
    packet data, protocol state (TCP FSM), extracted features, and protocol
    information (TLS, HTTP, DNS).

    Attributes:
        key: FlowKey identifying this flow
        start_time: Timestamp of first packet
        end_time: Timestamp of last packet
        packets: List of ParsedPacket objects (only in verbose mode)
        metrics: FlowMetrics with basic statistics
        tcp_state: TCP state machine state (forward direction)
        tcp_state_reverse: TCP state machine state (reverse direction)
        tls: TLSInfo if TLS was detected
        http: HTTPInfo if HTTP was detected
        dns: DNSInfo if DNS was detected
        features: FlowFeatures with extracted feature values
        ext_protocol: List of protocol names from IP layer upwards (e.g., ["IPv4", "TCP", "TLS", "HTTPS"])

    Examples:
        Basic flow access:
            >>> from wa1kpcap import Wa1kPcap
            >>> analyzer = Wa1kPcap(verbose_mode=True)
            >>> flows = analyzer.analyze_file('traffic.pcap')
            >>> flow = flows[0]
            >>> print(f"Flow: {flow.key}")
            >>> print(f"Packets: {flow.packet_count}")
            >>> print(f"Duration: {flow.duration:.3f}s")

        Access metrics:
            >>> print(f"Up packets: {flow.metrics.up_packet_count}")
            >>> print(f"Down packets: {flow.metrics.down_packet_count}")

        Access protocol info:
            >>> if flow.tls:
            ...     print(f"TLS version: {flow.tls.version}")
            ...     if flow.tls.sni:
            ...         print(f"SNI: {flow.tls.sni}")

        Access protocol stack:
            >>> print(f"Protocol stack: {flow.ext_protocol}")
            >>> # Example output: ["IPv4", "TCP", "TLS", "HTTPS"]

        Access features:
            >>> if flow.features:
            ...     lengths = flow.features.packet_lengths
            ...     stats = flow.stats
            ...     print(f"Mean packet length: {flow.pkt_mean:.1f}")
    """
    key: FlowKey
    start_time: float = 0.0
    end_time: float = 0.0
    packets: list[ParsedPacket] = field(default_factory=list)
    _raw_packets: list[bytes] = field(default_factory=list)
    metrics: FlowMetrics = field(default_factory=FlowMetrics)

    # TCP state
    tcp_state: TCPState = TCPState.CLOSED
    tcp_state_reverse: TCPState = TCPState.CLOSED

    # Protocol extraction results — stored in layers dict
    layers: dict = field(default_factory=dict)

    # Features
    features: object | None = None  # FlowFeatures

    # Extended protocol stack (from IP layer upwards)
    # e.g., ["IPv4", "TCP", "TLS", "HTTPS"] or ["IPv6", "UDP", "DNS"]
    ext_protocol: list[str] = field(default_factory=list)

    # Internal state
    _canonical_key: tuple = None  # Cached canonical key for FlowManager lookup
    _next_seq: dict[int, int] = field(default_factory=dict)  # Track expected TCP sequences
    _last_seen: float = 0.0
    _verbose: bool = True
    _save_raw: bool = False

    # QUIC flow state (for Short Header identification)
    _is_quic: bool = False
    _quic_dcid_len: int = 0

    # IP version hint (set by C++ pipeline when packets list is empty)
    _ip_version: int = 0  # 4 or 6

    # Incremental feature accumulation (populated by add_packet)
    _seq_packet_lengths: list = field(default_factory=list)
    _seq_ip_lengths: list = field(default_factory=list)
    _seq_trans_lengths: list = field(default_factory=list)
    _seq_app_lengths: list = field(default_factory=list)
    _seq_timestamps: list = field(default_factory=list)
    _seq_payload_bytes: list = field(default_factory=list)
    _seq_tcp_flags: list = field(default_factory=list)
    _seq_tcp_windows: list = field(default_factory=list)

    # Custom feature support - namespace for dynamic feature attributes
    # Features can be accessed via flow.<namespace>.<feature_name>
    _custom_features: dict = field(default_factory=dict)  # Store feature values by name
    _feature_initialized: bool = False  # Whether features have been initialized

    # TLS incomplete data buffers for reassembly (one per direction)
    # 1 = forward (C2S), -1 = reverse (S2C)
    _tls_incomplete_data: dict = field(default_factory=lambda: {1: b"", -1: b""})
    # TLS flow state - stores parsed TLS handshake data
    _tls_state: object = None  # TLSFlowState from application.py

    def __post_init__(self):
        if self.start_time == 0.0:
            self.start_time = time.time()

    # Protocol property aliases — source of truth is self.layers
    @property
    def tls(self):
        return self.layers.get('tls_record')
    @tls.setter
    def tls(self, v):
        if v is not None: self.layers['tls_record'] = v
        else: self.layers.pop('tls_record', None)

    @property
    def http(self):
        return self.layers.get('http')
    @http.setter
    def http(self, v):
        if v is not None: self.layers['http'] = v
        else: self.layers.pop('http', None)

    @property
    def dns(self):
        return self.layers.get('dns')
    @dns.setter
    def dns(self, v):
        if v is not None: self.layers['dns'] = v
        else: self.layers.pop('dns', None)

    @property
    def quic(self):
        return self.layers.get('quic')
    @quic.setter
    def quic(self, v):
        if v is not None: self.layers['quic'] = v
        else: self.layers.pop('quic', None)

    def register_incremental_feature(self, name: str, processor) -> None:
        """
        Register an incremental feature processor for this flow.

        Args:
            name: Feature name
            processor: BaseIncrementalFeature instance
        """
        self._custom_features[name] = processor

    def _initialize_features(self) -> None:
        """Initialize all registered incremental features."""
        if self._feature_initialized:
            return

        for name, processor in self._custom_features.items():
            processor.initialize(self)

        self._feature_initialized = True

    @property
    def duration(self) -> float:
        """Flow duration in seconds (end_time - start_time)."""
        return self.end_time - self.start_time

    @property
    def packet_count(self) -> int:
        """Total number of packets in the flow."""
        return self.metrics.packet_count

    @property
    def byte_count(self) -> int:
        """Total number of bytes in the flow (wire length)."""
        return self.metrics.byte_count

    @property
    def is_closed(self) -> bool:
        """Check if flow is closed (TCP) or timed out (UDP)."""
        return self.tcp_state in (TCPState.CLOSED, TCPState.TIME_WAIT, TCPState.RESET)

    # Convenient access to flow key fields
    @property
    def src_ip(self) -> str:
        """Source IP address."""
        return self.key.src_ip

    @property
    def dst_ip(self) -> str:
        """Destination IP address."""
        return self.key.dst_ip

    @property
    def sport(self) -> int:
        """Source port."""
        return self.key.src_port

    @property
    def dport(self) -> int:
        """Destination port."""
        return self.key.dst_port

    @property
    def protocol(self) -> int:
        """Protocol number (6=TCP, 17=UDP, etc.)."""
        return self.key.protocol

    @property
    def proto(self) -> str:
        """Protocol name (TCP, UDP, etc.)."""
        return self.key.protocol_name

    # Convenient access to packet count
    @property
    def num_packets(self) -> int:
        """Number of packets in this flow."""
        return self.metrics.packet_count

    # Convenient access to features (if computed)
    @property
    def packet_lengths(self):
        """Total packet length sequence (wirelen)."""
        if self.features and hasattr(self.features, 'packet_lengths'):
            return self.features.packet_lengths
        return None

    @property
    def ip_lengths(self):
        """IP layer length sequence (ip_len)."""
        if self.features and hasattr(self.features, 'ip_lengths'):
            return self.features.ip_lengths
        return None

    @property
    def trans_lengths(self):
        """Transport layer length sequence (trans_len)."""
        if self.features and hasattr(self.features, 'trans_lengths'):
            return self.features.trans_lengths
        return None

    @property
    def app_lengths(self):
        """App payload length sequence (app_len)."""
        if self.features and hasattr(self.features, 'app_lengths'):
            return self.features.app_lengths
        return None

    @property
    def timestamps(self):
        """Timestamp sequence."""
        if self.features and hasattr(self.features, 'timestamps'):
            return self.features.timestamps
        return None

    @property
    def iats(self):
        """Inter-arrival time sequence."""
        if self.features and hasattr(self.features, 'iats'):
            return self.features.iats
        return None

    @property
    def payload_bytes(self):
        """Payload byte sequence."""
        if self.features and hasattr(self.features, 'payload_bytes'):
            return self.features.payload_bytes
        return None

    @property
    def tcp_flags(self):
        """TCP flags sequence."""
        if self.features and hasattr(self.features, 'tcp_flags'):
            return self.features.tcp_flags
        return None

    @property
    def tcp_window_sizes(self):
        """TCP window size sequence."""
        if self.features and hasattr(self.features, 'tcp_window_sizes'):
            return self.features.tcp_window_sizes
        return None

    @property
    def stats(self) -> dict:
        """Statistical features (computed if not already)."""
        if self.features:
            if not self.features._statistics:
                self.features.compute_statistics()
            return self.features._statistics
        return {}

    # Individual statistical feature access
    @property
    def pkt_mean(self) -> float:
        """Mean total packet length."""
        return self.stats.get('packet_lengths', {}).get('mean', 0.0)

    @property
    def pkt_std(self) -> float:
        """Standard deviation of total packet lengths."""
        return self.stats.get('packet_lengths', {}).get('std', 0.0)

    @property
    def pkt_var(self) -> float:
        """Variance of total packet lengths."""
        return self.stats.get('packet_lengths', {}).get('var', 0.0)

    @property
    def pkt_min(self) -> float:
        """Minimum total packet length."""
        return self.stats.get('packet_lengths', {}).get('min', 0.0)

    @property
    def pkt_max(self) -> float:
        """Maximum total packet length."""
        return self.stats.get('packet_lengths', {}).get('max', 0.0)

    @property
    def pkt_range(self) -> float:
        """Range of total packet lengths."""
        return self.stats.get('packet_lengths', {}).get('range', 0.0)

    @property
    def pkt_median(self) -> float:
        """Median total packet length."""
        return self.stats.get('packet_lengths', {}).get('median', 0.0)

    @property
    def pkt_skew(self) -> float:
        """Skewness of total packet lengths."""
        return self.stats.get('packet_lengths', {}).get('skew', 0.0)

    @property
    def pkt_kurt(self) -> float:
        """Kurtosis of total packet lengths."""
        return self.stats.get('packet_lengths', {}).get('kurt', 0.0)

    @property
    def pkt_cv(self) -> float:
        """Coefficient of variation of total packet lengths."""
        return self.stats.get('packet_lengths', {}).get('cv', 0.0)

    # Up (forward) direction statistics (positive packet lengths)
    @property
    def pkt_up_mean(self) -> float:
        """Mean up (forward) packet length."""
        return self.stats.get('packet_lengths', {}).get('up_mean', 0.0)

    @property
    def pkt_up_std(self) -> float:
        """Standard deviation of up (forward) packet lengths."""
        return self.stats.get('packet_lengths', {}).get('up_std', 0.0)

    @property
    def pkt_up_min(self) -> float:
        """Minimum up (forward) packet length."""
        return self.stats.get('packet_lengths', {}).get('up_min', 0.0)

    @property
    def pkt_up_max(self) -> float:
        """Maximum up (forward) packet length."""
        return self.stats.get('packet_lengths', {}).get('up_max', 0.0)

    @property
    def pkt_up_sum(self) -> float:
        """Sum of up (forward) packet lengths."""
        return self.stats.get('packet_lengths', {}).get('up_sum', 0.0)

    @property
    def pkt_up_count(self) -> int:
        """Count of up (forward) packets."""
        return self.stats.get('packet_lengths', {}).get('up_count', 0)

    # Down (reverse) direction statistics (negative packet lengths, but reported as absolute)
    @property
    def pkt_down_mean(self) -> float:
        """Mean down (reverse) packet length."""
        return self.stats.get('packet_lengths', {}).get('down_mean', 0.0)

    @property
    def pkt_down_std(self) -> float:
        """Standard deviation of down (reverse) packet lengths."""
        return self.stats.get('packet_lengths', {}).get('down_std', 0.0)

    @property
    def pkt_down_min(self) -> float:
        """Minimum down (reverse) packet length."""
        return self.stats.get('packet_lengths', {}).get('down_min', 0.0)

    @property
    def pkt_down_max(self) -> float:
        """Maximum down (reverse) packet length."""
        return self.stats.get('packet_lengths', {}).get('down_max', 0.0)

    @property
    def pkt_down_sum(self) -> float:
        """Sum of down (reverse) packet lengths."""
        return self.stats.get('packet_lengths', {}).get('down_sum', 0.0)

    @property
    def pkt_down_count(self) -> int:
        """Count of down (reverse) packets."""
        return self.stats.get('packet_lengths', {}).get('down_count', 0)

    # IP layer statistics
    @property
    def ip_mean(self) -> float:
        """Mean IP layer length."""
        return self.stats.get('ip_lengths', {}).get('mean', 0.0)

    @property
    def ip_std(self) -> float:
        """Standard deviation of IP layer lengths."""
        return self.stats.get('ip_lengths', {}).get('std', 0.0)

    @property
    def ip_var(self) -> float:
        """Variance of IP layer lengths."""
        return self.stats.get('ip_lengths', {}).get('var', 0.0)

    @property
    def ip_min(self) -> float:
        """Minimum IP layer length."""
        return self.stats.get('ip_lengths', {}).get('min', 0.0)

    @property
    def ip_max(self) -> float:
        """Maximum IP layer length."""
        return self.stats.get('ip_lengths', {}).get('max', 0.0)

    @property
    def ip_range(self) -> float:
        """Range of IP layer lengths."""
        return self.stats.get('ip_lengths', {}).get('range', 0.0)

    @property
    def ip_median(self) -> float:
        """Median IP layer length."""
        return self.stats.get('ip_lengths', {}).get('median', 0.0)

    @property
    def ip_skew(self) -> float:
        """Skewness of IP layer lengths."""
        return self.stats.get('ip_lengths', {}).get('skew', 0.0)

    @property
    def ip_kurt(self) -> float:
        """Kurtosis of IP layer lengths."""
        return self.stats.get('ip_lengths', {}).get('kurt', 0.0)

    @property
    def ip_cv(self) -> float:
        """Coefficient of variation of IP layer lengths."""
        return self.stats.get('ip_lengths', {}).get('cv', 0.0)

    # Transport layer statistics
    @property
    def trans_mean(self) -> float:
        """Mean transport layer length."""
        return self.stats.get('trans_lengths', {}).get('mean', 0.0)

    @property
    def trans_std(self) -> float:
        """Standard deviation of transport layer lengths."""
        return self.stats.get('trans_lengths', {}).get('std', 0.0)

    @property
    def trans_var(self) -> float:
        """Variance of transport layer lengths."""
        return self.stats.get('trans_lengths', {}).get('var', 0.0)

    @property
    def trans_min(self) -> float:
        """Minimum transport layer length."""
        return self.stats.get('trans_lengths', {}).get('min', 0.0)

    @property
    def trans_max(self) -> float:
        """Maximum transport layer length."""
        return self.stats.get('trans_lengths', {}).get('max', 0.0)

    @property
    def trans_range(self) -> float:
        """Range of transport layer lengths."""
        return self.stats.get('trans_lengths', {}).get('range', 0.0)

    @property
    def trans_median(self) -> float:
        """Median transport layer length."""
        return self.stats.get('trans_lengths', {}).get('median', 0.0)

    @property
    def trans_skew(self) -> float:
        """Skewness of transport layer lengths."""
        return self.stats.get('trans_lengths', {}).get('skew', 0.0)

    @property
    def trans_kurt(self) -> float:
        """Kurtosis of transport layer lengths."""
        return self.stats.get('trans_lengths', {}).get('kurt', 0.0)

    @property
    def trans_cv(self) -> float:
        """Coefficient of variation of transport layer lengths."""
        return self.stats.get('trans_lengths', {}).get('cv', 0.0)

    # App layer statistics
    @property
    def app_mean(self) -> float:
        """Mean app payload length."""
        return self.stats.get('app_lengths', {}).get('mean', 0.0)

    @property
    def app_std(self) -> float:
        """Standard deviation of app payload lengths."""
        return self.stats.get('app_lengths', {}).get('std', 0.0)

    @property
    def app_var(self) -> float:
        """Variance of app payload lengths."""
        return self.stats.get('app_lengths', {}).get('var', 0.0)

    @property
    def app_min(self) -> float:
        """Minimum app payload length."""
        return self.stats.get('app_lengths', {}).get('min', 0.0)

    @property
    def app_max(self) -> float:
        """Maximum app payload length."""
        return self.stats.get('app_lengths', {}).get('max', 0.0)

    @property
    def app_range(self) -> float:
        """Range of app payload lengths."""
        return self.stats.get('app_lengths', {}).get('range', 0.0)

    @property
    def app_median(self) -> float:
        """Median app payload length."""
        return self.stats.get('app_lengths', {}).get('median', 0.0)

    @property
    def app_skew(self) -> float:
        """Skewness of app payload lengths."""
        return self.stats.get('app_lengths', {}).get('skew', 0.0)

    @property
    def app_kurt(self) -> float:
        """Kurtosis of app payload lengths."""
        return self.stats.get('app_lengths', {}).get('kurt', 0.0)

    @property
    def app_cv(self) -> float:
        """Coefficient of variation of app payload lengths."""
        return self.stats.get('app_lengths', {}).get('cv', 0.0)

    # IAT statistics (unchanged for all)
    @property
    def iat_mean(self) -> float:
        """Mean inter-arrival time."""
        return self.stats.get('iats', {}).get('mean', 0.0)

    @property
    def iat_std(self) -> float:
        """Standard deviation of inter-arrival times."""
        return self.stats.get('iats', {}).get('std', 0.0)

    @property
    def iat_var(self) -> float:
        """Variance of inter-arrival times."""
        return self.stats.get('iats', {}).get('var', 0.0)

    @property
    def iat_min(self) -> float:
        """Minimum inter-arrival time."""
        return self.stats.get('iats', {}).get('min', 0.0)

    @property
    def iat_max(self) -> float:
        """Maximum inter-arrival time."""
        return self.stats.get('iats', {}).get('max', 0.0)

    @property
    def iat_range(self) -> float:
        """Range of inter-arrival times."""
        return self.stats.get('iats', {}).get('range', 0.0)

    @property
    def iat_median(self) -> float:
        """Median inter-arrival time."""
        return self.stats.get('iats', {}).get('median', 0.0)

    @property
    def iat_skew(self) -> float:
        """Skewness of inter-arrival times."""
        return self.stats.get('iats', {}).get('skew', 0.0)

    @property
    def iat_kurt(self) -> float:
        """Kurtosis of inter-arrival times."""
        return self.stats.get('iats', {}).get('kurt', 0.0)

    @property
    def iat_cv(self) -> float:
        """Coefficient of variation of inter-arrival times."""
        return self.stats.get('iats', {}).get('cv', 0.0)

    def add_packet(self, pkt: ParsedPacket) -> None:
        """Add a packet to this flow.

        This method:
        1. Adds the packet to the flow's packet list
        2. Updates basic metrics
        3. Updates all registered incremental features
        """
        self.packets.append(pkt)
        self.metrics.packet_count += 1

        # Update metrics
        wirelen = pkt.wirelen
        self.metrics.byte_count += wirelen

        direction = self.key.direction(
            pkt.ip.src if pkt.ip else pkt.ip6.src if pkt.ip6 else "",
            pkt.tcp.sport if pkt.tcp else pkt.udp.sport if pkt.udp else 0
        )

        if direction == 1:
            self.metrics.up_packet_count += 1
            self.metrics.up_byte_count += wirelen
        else:
            self.metrics.down_packet_count += 1
            self.metrics.down_byte_count += wirelen

        # Update TCP metrics
        if pkt.tcp:
            flags = pkt.tcp.flags
            if flags & 0x02:  # SYN
                self.metrics.syn_count += 1
            if flags & 0x01:  # FIN
                self.metrics.fin_count += 1
            if flags & 0x04:  # RST
                self.metrics.rst_count += 1
            if flags & 0x10:  # ACK
                self.metrics.ack_count += 1
            if flags & 0x08:  # PSH
                self.metrics.psh_count += 1
            if flags & 0x20:  # URG
                self.metrics.urg_count += 1

            self.metrics.update_window(pkt.tcp.win)

        # Update timestamps
        if pkt.timestamp > self.end_time:
            self.end_time = pkt.timestamp
        self._last_seen = pkt.timestamp

        # Incremental feature accumulation
        self._seq_packet_lengths.append(direction * wirelen)
        self._seq_ip_lengths.append(direction * pkt.ip_len)
        self._seq_trans_lengths.append(direction * pkt.trans_len)
        self._seq_app_lengths.append(direction * pkt.app_len)
        self._seq_timestamps.append(pkt.timestamp)
        payload = getattr(pkt, '_raw_tcp_payload', b'') or getattr(pkt, 'payload', b'')
        self._seq_payload_bytes.append(direction * len(payload))
        if pkt.tcp:
            self._seq_tcp_flags.append(pkt.tcp.flags)
            self._seq_tcp_windows.append(pkt.tcp.win)

        # Store raw bytes if configured
        if self._save_raw:
            self._raw_packets.append(pkt.raw_data)

        # Update incremental features (if registered)
        self._update_incremental_features(pkt)

    def _update_incremental_features(self, pkt: ParsedPacket) -> None:
        """Update all registered incremental features with new packet."""
        if not self._custom_features:
            return

        # Initialize features on first packet
        if not self._feature_initialized:
            self._initialize_features()

        # Update each registered feature processor
        for name, processor in self._custom_features.items():
            try:
                processor.update(self, pkt)
            except Exception:
                pass  # Feature update failed, continue with others

    def get_features(self) -> dict:
        """Get all incremental feature values.

        Returns:
            Dictionary with feature names as keys and computed values as values
        """
        if not self._feature_initialized:
            return {}

        result = {}
        # Use _custom_features (the actual field name in Flow)
        for name, processor in self._custom_features.items():
            try:
                value = processor.get_value(self)
                if value is not None:
                    result[name] = value
            except Exception:
                result[name] = None

        return result

    @property
    def feature_values(self) -> dict:
        """Convenient property to access all incremental feature values."""
        return self.get_features()

    def packets_forward(self) -> list[ParsedPacket]:
        """Get forward direction packets."""
        return [p for p in self.packets if self.key.direction(
            p.ip.src if p.ip else p.ip6.src if p.ip6 else "",
            p.tcp.sport if p.tcp else p.udp.sport if p.udp else 0
        ) == 1]

    def packets_reverse(self) -> list[ParsedPacket]:
        """Get reverse direction packets."""
        return [p for p in self.packets if self.key.direction(
            p.ip.src if p.ip else p.ip6.src if p.ip6 else "",
            p.tcp.sport if p.tcp else p.udp.sport if p.udp else 0
        ) == -1]

    def to_dict(self) -> dict:
        """Convert to dictionary representation."""
        result = {
            'key': str(self.key),
            'protocol': self.key.protocol_name,
            'src_ip': self.key.src_ip,
            'dst_ip': self.key.dst_ip,
            'src_port': self.key.src_port,
            'dst_port': self.key.dst_port,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'duration': self.duration,
            'packet_count': self.metrics.packet_count,
            'byte_count': self.metrics.byte_count,
            'up_packet_count': self.metrics.up_packet_count,
            'up_byte_count': self.metrics.up_byte_count,
            'down_packet_count': self.metrics.down_packet_count,
            'down_byte_count': self.metrics.down_byte_count,
            'ext_protocol': self.ext_protocol,
        }

        if self.tcp_state != TCPState.CLOSED:
            result['tcp_state'] = self.tcp_state.name

        if self.tls:
            result['tls'] = {
                'version': self.tls.version,
            }
            if self.tls.sni:
                result['tls']['sni'] = self.tls.sni
            if self.tls.certificate:
                result['tls']['cert_subject'] = self.tls.certificate.subject
                result['tls']['cert_issuer'] = self.tls.certificate.issuer

        if self.http:
            result['http'] = {
                'host': self.http.host,
                'user_agent': self.http.user_agent,
            }

        if self.dns:
            result['dns'] = {
                'queries': self.dns.queries,
            }

        return result

    def build_ext_protocol(self) -> list[str]:
        """
        Build the extended protocol stack list.

        Constructs a list of protocol names from the IP layer upwards.
        For example:
        - IPv4 + TCP + TLS with ALPN h2: ["IPv4", "TCP", "TLS", "HTTPS"]
        - IPv6 + UDP + DNS: ["IPv6", "UDP", "DNS"]

        Returns:
            List of protocol names from IP layer upwards
        """
        protocol_stack = []

        # IP layer
        if self.packets and (self.packets[0].ip or self.packets[0].ip6):
            if self.packets[0].ip:
                protocol_stack.append("IPv4")
            elif self.packets[0].ip6:
                protocol_stack.append("IPv6")
        elif self._ip_version == 4:
            protocol_stack.append("IPv4")
        elif self._ip_version == 6:
            protocol_stack.append("IPv6")

        # Transport layer
        protocol_num = self.key.protocol
        if protocol_num == 6:  # TCP
            protocol_stack.append("TCP")
        elif protocol_num == 17:  # UDP
            protocol_stack.append("UDP")
        elif protocol_num == 1:  # ICMP
            protocol_stack.append("ICMP")
        elif protocol_num == 58:  # ICMPv6
            protocol_stack.append("ICMPv6")
        elif protocol_num == 132:  # SCTP
            protocol_stack.append("SCTP")

        # Application layer — dynamic from self.layers
        _NETWORK_TRANSPORT = {'ethernet', 'ipv4', 'ipv6', 'tcp', 'udp', 'icmp'}
        for layer_name in self.layers:
            if layer_name in _NETWORK_TRANSPORT:
                continue

            display_name = layer_name.upper()

            # TLS special case: check ALPN for HTTPS indication
            if layer_name == 'tls_record':
                display_name = "TLS"
                protocol_stack.append(display_name)
                tls_info = self.layers[layer_name]
                if hasattr(tls_info, 'alpn') and tls_info.alpn:
                    https_protocols = {"h2", "http/1.1", "http/1.0", "http/0.9", "http"}
                    if any(alpn.lower() in https_protocols or alpn.lower().startswith("http/")
                           for alpn in tls_info.alpn):
                        protocol_stack.append("HTTPS")
            else:
                protocol_stack.append(display_name)

        self.ext_protocol = protocol_stack
        return protocol_stack


# Import for type annotations (avoid circular import)
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from wa1kpcap.core.packet import ParsedPacket, TLSInfo, HTTPInfo, DNSInfo, TCPInfo, UDPInfo


def _make_canonical_key(src_ip, dst_ip, src_port, dst_port, protocol, vlan_id=0):
    """Canonical tuple key: same for A→B and B→A."""
    if (src_ip, src_port) <= (dst_ip, dst_port):
        return (src_ip, src_port, dst_ip, dst_port, protocol, vlan_id)
    return (dst_ip, dst_port, src_ip, src_port, protocol, vlan_id)


@dataclass
class FlowManagerConfig:
    """Configuration for flow manager."""
    udp_timeout: float = 0
    tcp_cleanup_timeout: float = 300.0
    max_flows: int = 100000


class FlowManager:
    """
    Manages flow lifecycle and packet-to-flow assignment.

    Handles TCP state machine for proper flow splitting and UDP timeout.
    """

    def __init__(self, config: FlowManagerConfig | None = None):
        self.config = config or FlowManagerConfig()
        self._flows: dict[tuple, Flow] = {}
        self._tcp_states: dict[tuple, tuple[TCPState, TCPState]] = {}
        self._udp_last_seen: dict[tuple, float] = {}
        self._completed_flows: list[Flow] = []

        # Custom feature processors to register on new flows
        self._custom_features: dict = {}

    def register_custom_feature(self, name: str, processor) -> None:
        """Register a custom feature processor for new flows."""
        self._custom_features[name] = processor

    def _register_features_on_flow(self, flow: Flow) -> None:
        """Register all custom features on a newly created flow."""
        for name, processor in self._custom_features.items():
            flow.register_incremental_feature(name, processor)

    def get_or_create_flow(self, pkt: ParsedPacket) -> Flow | None:
        """Get existing flow or create new one for this packet.

        Uses canonical tuple key for single-lookup bidirectional matching.
        Defers FlowKey creation until a new flow is actually needed.
        """
        # Extract canonical tuple and raw fields (no FlowKey yet)
        result = self._extract_flow_tuple(pkt)
        if result is None:
            return None

        canonical, src_ip, dst_ip, src_port, dst_port, protocol, vlan_id = result

        # Single lookup with canonical tuple key
        flow = self._flows.get(canonical)

        if flow is None:
            # New flow — only now create FlowKey
            if len(self._flows) >= self.config.max_flows:
                return None
            key = FlowKey(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                          dst_port=dst_port, protocol=protocol, vlan_id=vlan_id)
            flow = Flow(key=key, start_time=pkt.timestamp, _verbose=True, _save_raw=False)
            flow._canonical_key = canonical
            self._flows[canonical] = flow

            # Register custom features on new flow
            self._register_features_on_flow(flow)

            # Initialize TCP state for new flows
            if protocol == Protocol.TCP:
                self._tcp_states[canonical] = (TCPState.CLOSED, TCPState.CLOSED)

        # Check for UDP timeout (disabled when udp_timeout <= 0)
        if protocol == Protocol.UDP and self.config.udp_timeout > 0:
            if canonical in self._udp_last_seen:
                if pkt.timestamp - self._udp_last_seen[canonical] > self.config.udp_timeout:
                    # Complete old flow, create new one for this packet
                    old_flow = self._flows.pop(canonical, None)
                    if old_flow:
                        self._completed_flows.append(old_flow)
                    self._udp_last_seen.pop(canonical, None)

                    key = FlowKey(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port,
                                  dst_port=dst_port, protocol=protocol, vlan_id=vlan_id)
                    flow = Flow(key=key, start_time=pkt.timestamp, _verbose=True, _save_raw=False)
                    flow._canonical_key = canonical
                    self._flows[canonical] = flow
                    self._register_features_on_flow(flow)
            self._udp_last_seen[canonical] = pkt.timestamp

        # Update TCP state
        if pkt.tcp and protocol == Protocol.TCP:
            self._update_tcp_state(flow, pkt)

        return flow

    def _extract_flow_tuple(self, pkt: ParsedPacket) -> tuple | None:
        """Extract canonical tuple and raw fields from packet.

        Returns (canonical, src_ip, dst_ip, src_port, dst_port, protocol, vlan_id)
        or None if packet has no IP layer.
        """
        # Fast path: use pre-computed flow key from C++ parse_to_dataclass
        cache = getattr(pkt, '_flow_key_cache', None)
        if cache is not None:
            return cache  # already (canonical, src_ip, dst_ip, src_port, dst_port, protocol, vlan_id)

        # Fallback: original Python path (dpkt engine)
        ip = pkt.ip
        ip6 = pkt.ip6

        if not ip and not ip6:
            return None

        if ip:
            src_ip = ip.src
            dst_ip = ip.dst
            protocol = ip.proto
        elif ip6:
            src_ip = ip6.src
            dst_ip = ip6.dst
            protocol = ip6.next_header
        else:
            return None

        src_port = 0
        dst_port = 0

        if pkt.tcp:
            src_port = pkt.tcp.sport
            dst_port = pkt.tcp.dport
        elif pkt.udp:
            src_port = pkt.udp.sport
            dst_port = pkt.udp.dport

        vlan_id = pkt.vlan.vlan_id if pkt.vlan else 0

        canonical = _make_canonical_key(src_ip, dst_ip, src_port, dst_port, protocol, vlan_id)
        return canonical, src_ip, dst_ip, src_port, dst_port, protocol, vlan_id

    def _update_tcp_state(self, flow: Flow, pkt: ParsedPacket) -> None:
        """Update TCP state machine based on packet flags."""
        flags = pkt.tcp.flags
        ckey = flow._canonical_key
        state_fwd, state_rev = self._tcp_states[ckey]

        direction = flow.key.direction(
            pkt.ip.src if pkt.ip else pkt.ip6.src if pkt.ip6 else "",
            pkt.tcp.sport
        )

        syn = bool(flags & 0x02)
        fin = bool(flags & 0x01)
        rst = bool(flags & 0x04)
        ack = bool(flags & 0x10)

        if direction == 1:  # Forward
            if rst:
                state_fwd = TCPState.RESET
            elif syn and not ack:
                state_fwd = TCPState.SYN_SENT
            elif syn and ack:
                state_fwd = TCPState.ESTABLISHED
            elif fin and state_fwd == TCPState.ESTABLISHED:
                state_fwd = TCPState.FIN_WAIT_1
            elif fin and state_fwd == TCPState.FIN_WAIT_1:
                state_fwd = TCPState.FIN_WAIT_2
            elif ack and state_fwd == TCPState.FIN_WAIT_1:
                state_fwd = TCPState.FIN_WAIT_2
        else:  # Reverse
            if rst:
                state_rev = TCPState.RESET
            elif syn and not ack:
                state_rev = TCPState.SYN_SENT
            elif syn and ack:
                state_rev = TCPState.ESTABLISHED
            elif fin and state_rev == TCPState.ESTABLISHED:
                state_rev = TCPState.FIN_WAIT_1
            elif fin and state_rev == TCPState.FIN_WAIT_1:
                state_rev = TCPState.FIN_WAIT_2
            elif ack and state_rev == TCPState.FIN_WAIT_1:
                state_rev = TCPState.FIN_WAIT_2

        # Check if both sides closed
        if (state_fwd in (TCPState.FIN_WAIT_2, TCPState.CLOSED, TCPState.TIME_WAIT) and
            state_rev in (TCPState.FIN_WAIT_2, TCPState.CLOSED, TCPState.TIME_WAIT)):
            flow.tcp_state = TCPState.CLOSED
        else:
            flow.tcp_state = state_fwd

        flow.tcp_state_reverse = state_rev
        self._tcp_states[ckey] = (state_fwd, state_rev)

    def expire_flows(self, current_time: float) -> list[Flow]:
        """Expire UDP flows that have timed out."""
        if self.config.udp_timeout <= 0:
            return []

        expired = []
        to_remove = []

        for key, last_seen in self._udp_last_seen.items():
            if current_time - last_seen > self.config.udp_timeout:
                if key in self._flows:
                    flow = self._flows[key]
                    flow.end_time = current_time
                    expired.append(flow)
                    to_remove.append(key)

        for key in to_remove:
            del self._flows[key]
            del self._udp_last_seen[key]
            self._tcp_states.pop(key, None)

        return expired

    def complete_flow(self, key: FlowKey) -> Flow | None:
        """Mark a flow as complete and remove from active tracking."""
        canonical = _make_canonical_key(key.src_ip, key.dst_ip, key.src_port, key.dst_port, key.protocol)
        if canonical in self._flows:
            flow = self._flows.pop(canonical)
            self._completed_flows.append(flow)
            self._tcp_states.pop(canonical, None)
            self._udp_last_seen.pop(canonical, None)
            return flow
        return None

    def get_all_flows(self) -> list[Flow]:
        """Get all completed and active flows."""
        all_flows = list(self._completed_flows)
        all_flows.extend(self._flows.values())
        return all_flows

    def get_active_flows(self) -> list[Flow]:
        """Get currently active flows."""
        return list(self._flows.values())

    def clear(self) -> None:
        """Clear all flows."""
        self._flows.clear()
        self._tcp_states.clear()
        self._udp_last_seen.clear()
        self._completed_flows.clear()

    @property
    def flow_count(self) -> int:
        return len(self._flows)
