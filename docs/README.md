# wa1kpcap - Detailed Documentation

Complete documentation for the wa1kpcap PCAP analysis library.

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Concepts](#core-concepts)
4. [Feature Extraction](#feature-extraction)
5. [Custom Features](#custom-features)
6. [Protocol Parsing](#protocol-parsing)
7. [Export Options](#export-options)
8. [API Reference](#api-reference)

## Installation

### Basic Installation

```bash
pip install dpkt numpy pandas cryptography
```

### With Conda

```bash
conda install dpkt numpy pandas cryptography
```

## Quick Start

### Basic Usage

```python
from wa1kpcap import Wa1kPcap

# Create analyzer
analyzer = Wa1kPcap(verbose_mode=True, compute_statistics=True)

# Analyze a PCAP file
flows = analyzer.analyze_file('traffic.pcap')

# Iterate through flows
for flow in flows:
    print(f"Flow: {flow.key}")
    print(f"  Packets: {flow.packet_count}")
    print(f"  Duration: {flow.duration:.3f}s")
```

## Core Concepts

### Flow Representation

A **flow** is a bidirectional communication between two endpoints, identified by the 5-tuple:
- Source IP
- Destination IP
- Source Port
- Destination Port
- Protocol (TCP/UDP/etc.)

### Direction Tracking

Packet lengths and statistics use **signed values** to indicate direction:
- **Positive values** → Up (forward/C2S direction)
- **Negative values** → Down (reverse/S2C direction)

The direction is determined by the first packet that creates the flow.

### Verbose vs Non-Verbose Mode

**Verbose mode** (`verbose_mode=True`):
- Stores packet-level data
- Allows iteration through individual packets
- Higher memory usage

**Non-verbose mode** (`verbose_mode=False`):
- Only stores aggregated flow-level data
- Cannot iterate through packets
- Lower memory usage

## Feature Extraction

### Sequence Features

Available when `verbose_mode=True`:

```python
for flow in flows:
    if flow.features:
        # Packet lengths (signed for direction)
        print(flow.features.packet_lengths)  # [100, -50, 200, -75, ...]

        # IP layer lengths
        print(flow.features.ip_lengths)

        # Transport layer lengths
        print(flow.features.trans_lengths)

        # App payload lengths
        print(flow.features.app_lengths)

        # Timestamps
        print(flow.features.timestamps)

        # Inter-arrival times
        print(flow.features.iats)

        # TCP-specific sequences
        print(flow.features.tcp_flags)
        print(flow.features.tcp_window_sizes)
```

### Statistical Features

Available when `compute_statistics=True`:

```python
for flow in flows:
    # Total packet statistics
    print(f"Mean: {flow.pkt_mean}")
    print(f"Std: {flow.pkt_std}")
    print(f"Min: {flow.pkt_min}")
    print(f"Max: {flow.pkt_max}")
    print(f"Median: {flow.pkt_median}")

    # Directional statistics
    print(f"Up count: {flow.pkt_up_count}")
    print(f"Down count: {flow.pkt_down_count}")
    print(f"Up mean: {flow.pkt_up_mean}")
    print(f"Down mean: {flow.pkt_down_mean}")

    # Other layer statistics
    print(f"IP mean: {flow.ip_mean}")
    print(f"Transport mean: {flow.trans_mean}")
    print(f"App mean: {flow.app_mean}")

    # IAT statistics
    print(f"IAT mean: {flow.iat_mean}")
    print(f"IAT std: {flow.iat_std}")

    # Or access full statistics dictionary
    stats = flow.stats
    print(stats['packet_count'])
    print(stats['packet_lengths']['mean'])
```

### Available Statistical Properties

| Property | Description |
|----------|-------------|
| `pkt_mean`, `pkt_std`, `pkt_var` | Total packet mean/std/var |
| `pkt_min`, `pkt_max`, `pkt_range` | Total packet min/max/range |
| `pkt_median` | Total packet median |
| `pkt_skew`, `pkt_kurt`, `pkt_cv` | Total packet skewness/kurtosis/CV |
| `pkt_up_mean`, `pkt_up_count` | Up direction statistics |
| `pkt_down_mean`, `pkt_down_count` | Down direction statistics |
| `ip_mean`, `ip_std`, ...` | IP layer statistics |
| `trans_mean`, `trans_std`, ...` | Transport layer statistics |
| `app_mean`, `app_std`, ...` | App payload statistics |
| `iat_mean`, `iat_std`, ...` | Inter-arrival time statistics |

## Custom Features

### Custom Feature Registration

Custom features allow you to extract domain-specific features during PCAP analysis.

#### Basic Example: Transport Entropy

```python
from wa1kpcap import Wa1kPcap, Flow
from wa1kpcap.features.registry import BaseIncrementalFeature, FeatureType
from dataclasses import dataclass, field
import numpy as np
import math

# Define feature state
@dataclass
class TransportEntropyState:
    """State for transport payload entropy feature."""
    entropy_sequence: list[float] = field(default_factory=list)

# Define incremental feature
class TransportEntropyFeature(BaseIncrementalFeature):
    """
    Computes transport payload entropy sequence per packet.

    Access via: flow.get_features()['trans_entropy']['entropy_sequence']
    """

    def __init__(self):
        super().__init__("trans_entropy", FeatureType.SEQUENCE)

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['trans_entropy'] = TransportEntropyState()

    def update(self, flow: Flow, pkt) -> None:
        state: TransportEntropyState = flow._feature_state.get('trans_entropy')
        if state is None:
            return

        # Get transport payload (TCP/UDP data)
        payload = pkt.payload or b''
        if payload:
            entropy = self._shannon_entropy(payload)
            state.entropy_sequence.append(entropy)

    def get_value(self, flow: Flow) -> dict:
        state: TransportEntropyState = flow._feature_state.get('trans_entropy')
        if state is None:
            return {}
        return {
            'entropy_sequence': np.array(state.entropy_sequence),
            'entropy_mean': float(np.mean(state.entropy_sequence)) if state.entropy_sequence else 0.0,
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

# Create analyzer and register feature
analyzer = Wa1kPcap(verbose_mode=True)
entropy_feature = TransportEntropyFeature()
analyzer.register_feature('trans_entropy', entropy_feature)

# Analyze
flows = analyzer.analyze_file('traffic.pcap')

# Access feature results
for flow in flows:
    features = flow.get_features()
    if 'trans_entropy' in features:
        data = features['trans_entropy']
        print(f"Entropy sequence: {data['entropy_sequence']}")
        print(f"Mean entropy: {data['entropy_mean']}")
```

#### Cumulative Statistics Feature

```python
from wa1kpcap import Wa1kPcap, Flow
from wa1kpcap.features.registry import BaseIncrementalFeature, FeatureType
from dataclasses import dataclass, field
import numpy as np

@dataclass
class CumulativeStatsState:
    """State for cumulative statistics feature."""
    max_sequence: list[int] = field(default_factory=list)
    min_sequence: list[int] = field(default_factory=list)
    mean_sequence: list[float] = field(default_factory=list)
    packet_lengths: list[int] = field(default_factory=list)

class CumulativeStatsFeature(BaseIncrementalFeature):
    """
    Computes cumulative statistics sequences.

    Value i = statistics over first i packets:
    - max_sequence[i] = max(packet_lengths[0:i])
    - min_sequence[i] = min(packet_lengths[0:i])
    - mean_sequence[i] = mean(packet_lengths[0:i])

    Access via: flow.get_features()['cum_stats']['max_sequence']
    """

    def __init__(self):
        super().__init__("cum_stats", FeatureType.SEQUENCE)

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['cum_stats'] = CumulativeStatsState()

    def update(self, flow: Flow, pkt) -> None:
        state: CumulativeStatsState = flow._feature_state.get('cum_stats')
        if state is None:
            return

        state.packet_lengths.append(pkt.wirelen)

        # Update cumulative sequences
        state.max_sequence.append(int(np.max(state.packet_lengths)))
        state.min_sequence.append(int(np.min(state.packet_lengths)))
        state.mean_sequence.append(float(np.mean(state.packet_lengths)))

    def get_value(self, flow: Flow) -> dict:
        state: CumulativeStatsState = flow._feature_state.get('cum_stats')
        if state is None:
            return {}
        return {
            'max_sequence': np.array(state.max_sequence),
            'min_sequence': np.array(state.min_sequence),
            'mean_sequence': np.array(state.mean_sequence),
            'final_max': int(np.max(state.packet_lengths)) if state.packet_lengths else 0,
            'final_min': int(np.min(state.packet_lengths)) if state.packet_lengths else 0,
            'final_mean': float(np.mean(state.packet_lengths)) if state.packet_lengths else 0.0,
        }

# Register and use
analyzer = Wa1kPcap(verbose_mode=True)
analyzer.register_feature('cum_stats', CumulativeStatsFeature())
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    features = flow.get_features()
    if 'cum_stats' in features:
        print(f"Cumulative max: {features['cum_stats']['max_sequence']}")
```

### Key Points for Custom Features

1. Features are registered via `analyzer.register_feature(name, processor)`
2. Each feature processor must inherit from `BaseIncrementalFeature`
3. Features are computed incrementally per-packet during `flow.add_packet()`
4. Access results via `flow.get_features()[name]`

### Feature Types

```python
from wa1kpcap.features.registry import FeatureType

FeatureType.SEQUENCE    # Sequence/array features
FeatureType.STATISTICAL  # Scalar statistical features
FeatureType.INCREMENTAL # Incrementally computed features
```

## Protocol Parsing

### TLS Information

```python
for flow in flows:
    if flow.tls:
        # Basic TLS info
        print(f"Version: {flow.tls.version}")
        print(f"Content Type: {flow.tls.content_type_name}")

        # Handshake info
        print(f"Handshake Type: {flow.tls.handshake_type_name}")

        # Extensions
        if flow.tls.sni:
            print(f"SNI: {flow.tls.sni}")  # List of server names
        if flow.tls.alpn:
            print(f"ALPN: {flow.tls.alpn}")  # List of protocols

        # Certificate
        if flow.tls.certificate:
            cert = flow.tls.certificate
            print(f"Subject: {cert.get('subject')}")
            print(f"Issuer: {cert.get('issuer')}")
            print(f"Valid: {cert.get('not_before')} - {cert.get('not_after')}")

        # Extension access
        if flow.tls.exts:
            # Get specific extension type
            ext_list = flow.tls.get_extension(0)  # server_name
            if ext_list:
                print(f"SNI extension data: {ext_list}")
```

### HTTP Information

```python
for flow in flows:
    if flow.http:
        print(f"Method: {flow.http.method}")
        print(f"Host: {flow.http.host}")
        print(f"User Agent: {flow.http.user_agent}")
        print(f"URI: {flow.http.uri}")
```

### DNS Information

```python
for flow in flows:
    if flow.dns:
        print(f"Queries: {flow.dns.queries}")
        print(f"Response Code: {flow.dns.response_code}")
```

## Export Options

### Export to DataFrame

```python
from wa1kpcap import Wa1kPcap, to_dataframe

analyzer = Wa1kPcap(verbose_mode=True, compute_statistics=True)
flows = analyzer.analyze_file('traffic.pcap')

df = to_dataframe(flows)
print(df[['src_ip', 'dst_ip', 'packet_count', 'feature.packet_lengths.mean']].head())
```

### Export to CSV/JSON

```python
from wa1kpcap import Wa1kPcap, to_csv, to_json

analyzer = Wa1kPcap(verbose_mode=True, compute_statistics=True)
flows = analyzer.analyze_file('traffic.pcap')

to_csv(flows, 'output.csv')
to_json(flows, 'output.json', indent=2)
```

### Using FlowExporter

```python
from wa1kpcap import Wa1kPcap, FlowExporter

analyzer = Wa1kPcap(verbose_mode=True, compute_statistics=True)
flows = analyzer.analyze_file('traffic.pcap')

exporter = FlowExporter(include_features=True, flatten_features=False)
exporter.to_csv(flows, 'output.csv')
exporter.to_json(flows, 'output.json')
exporter.save(flows, 'output.csv')  # Auto-detect format
```

### Auto Format Detection

The `save()` method automatically detects the format from file extension:
- `.json` → JSON format
- `.csv` → CSV format
- `.parquet` → Parquet format

## API Reference

### Wa1kPcap Class

```python
Wa1kPcap(
    udp_timeout: float = 0,               # UDP flow timeout (0=no timeout)
    tcp_cleanup_timeout: float = 300.0,  # TCP cleanup timeout (seconds)
    filter_ack: bool = False,             # Filter pure ACK packets
    filter_rst: bool = False,             # Filter RST packets
    verbose_mode: bool = False,           # Store packet-level data
    enabled_features: list[str] | None = None,  # Specific features to extract
    save_raw_bytes: bool = False,         # Save raw packet bytes
    compute_statistics: bool = True,      # Compute statistical features
    enable_reassembly: bool = True,       # Enable IP/TCP/TLS reassembly
    protocols: list[str] | None = None,    # Protocols to parse
)
```

**Methods:**
- `analyze_file(pcap_path: str | Path) -> list[Flow]`: Analyze a single PCAP file
- `analyze_directory(directory: str | Path, pattern: str = "*.pcap") -> dict`: Analyze all PCAP files in a directory
- `register_feature(name: str, processor: BaseIncrementalFeature) -> None`: Register a custom feature processor

### Flow Class

**Five-tuple Access:**
```python
flow.key.src_ip      # Source IP address
flow.key.dst_ip      # Destination IP address
flow.key.src_port    # Source port
flow.key.dst_port    # Destination port
flow.key.protocol    # Protocol (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, etc.)
```

**Time Access:**
```python
flow.start_time   # Flow start timestamp
flow.end_time     # Flow end timestamp
flow.duration     # Flow duration in seconds
```

**Metrics:**
```python
flow.metrics.packet_count          # Total packets
flow.metrics.up_packet_count      # Up direction packets
flow.metrics.down_packet_count    # Down direction packets
flow.metrics.up_byte_count        # Up direction bytes
flow.metrics.down_byte_count      # Down direction bytes
```

**Features:**
```python
flow.features                      # FlowFeatures object
flow.features.packet_lengths      # Packet length array (signed)
flow.features.timestamps           # Timestamp array
flow.features.iats                 # IAT array
flow.features.tcp_flags            # TCP flags array
flow.features.tcp_window_sizes    # TCP window sizes array
```

**Protocol Info:**
```python
flow.tls      # TLSInfo if TLS detected
flow.http     # HTTPInfo if HTTP detected
flow.dns      # DNSInfo if DNS detected
```

**Statistics Properties:**
```python
# Total packet
flow.pkt_mean, flow.pkt_std, flow.pkt_var, flow.pkt_min, flow.pkt_max
flow.pkt_range, flow.pkt_median, flow.pkt_skew, flow.pkt_kurt, flow.pkt_cv
flow.pkt_up_mean, flow.pkt_up_std, flow.pkt_up_min, flow.pkt_up_max
flow.pkt_up_sum, flow.pkt_up_count
flow.pkt_down_mean, flow.pkt_down_std, flow.pkt_down_min, flow.pkt_down_max
flow.pkt_down_sum, flow.pkt_down_count

# IP layer
flow.ip_mean, flow.ip_std, flow.ip_var, flow.ip_min, flow.ip_max
flow.ip_range, flow.ip_median, flow.ip_skew, flow.ip_kurt, flow.ip_cv

# Transport layer
flow.trans_mean, flow.trans_std, flow.trans_var, flow.trans_min, flow.trans_max
flow.trans_range, flow.trans_median, flow.trans_skew, flow.trans_kurt, flow.trans_cv

# App payload
flow.app_mean, flow.app_std, flow.app_var, flow.app_min, flow.app_max
flow.app_range, flow.app_median, flow.app_skew, flow.app_kurt, flow.app_cv

# IAT
flow.iat_mean, flow.iat_std, flow.iat_var, flow.iat_min, flow.iat_max
flow.iat_range, flow.iat_median, flow.iat_skew, flow.iat_kurt, flow.iat_cv
```

**Full Statistics Dictionary:**
```python
stats = flow.stats
# Contains:
# - packet_count: int
# - total_bytes: int
# - duration: float
# - packet_lengths: dict with all packet statistics
# - ip_lengths: dict with all IP layer statistics
# - trans_lengths: dict with all transport layer statistics
# - app_lengths: dict with all app payload statistics
# - iats: dict with all IAT statistics
# - tcp_window: dict with TCP window statistics
```

## Advanced Usage

### Custom Protocol Handler

```python
from wa1kpcap.protocols.registry import register_protocol
from wa1kpcap.protocols.base import BaseProtocolHandler, Layer, ParseResult, ProtocolContext

@register_protocol('custom_proto', Layer.APPLICATION, encapsulates='tcp', default_ports=[9999])
class CustomProtocolHandler(BaseProtocolHandler):
    """Handler for custom protocol."""

    def parse(self, payload: bytes, context: ProtocolContext, is_client_to_server: bool) -> ParseResult:
        # Parse your protocol here
        return ParseResult(success=True, data=payload[10:], info=None)
```

### Filtering Options

```python
# Filter pure ACK packets (no payload)
analyzer = Wa1kPcap(filter_ack=True)

# Filter RST packets
analyzer = Wa1kPcap(filter_rst=True)

# Combine filters
analyzer = Wa1kPcap(filter_ack=True, filter_rst=True)
```

### Memory Optimization

```python
# For large files, use non-verbose mode
analyzer = Wa1kPcap(
    verbose_mode=False,      # Don't store packets
    save_raw_bytes=False,    # Don't store raw bytes
)

# Only compute specific features
analyzer = Wa1kPcap(
    enabled_features=['packet_lengths', 'timestamps']
)
```

## Tips and Best Practices

1. **Use verbose_mode=True** when you need packet-level access
2. **Use compute_statistics=True** for statistical features (default)
3. **Use filter_ack=True** to reduce noise in TCP traffic analysis
4. **Access flow.stats** for complete statistics instead of individual properties
5. **Export to DataFrame** for batch analysis with pandas
6. **Register custom features** before calling `analyze_file()`
