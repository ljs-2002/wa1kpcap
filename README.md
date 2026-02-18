# wa1kpcap

A powerful Python PCAP analysis library providing flow-level feature extraction and protocol field parsing using dpkt.

## Documentation

- **[README.md](README.md)** - This file (quick start and basic usage)
- **[docs/README.md](docs/README.md)** - Detailed documentation with advanced features

## Features

### Core Capabilities
- **Multi-format PCAP Support**: Standard pcap, pcapng, NFLOG, Linux SLL, Raw IP, BSD Loopback
- **Flow Tracking**: TCP state machine for proper flow splitting, UDP timeout handling
- **Protocol Parsing**:
  - Link Layer: Ethernet, Linux SLL (cooked capture), Raw IP, BSD Loopback, NFLOG
  - Network Layer: IPv4/IPv6, ICMP/ICMPv6
  - Transport Layer: TCP/UDP/SCTP with full header parsing
  - Application Layer: TLS (with SNI/ALPN/cipher suite/certificate extraction), HTTP, DNS

### Feature Extraction

#### Sequence Features (per-flow)
- `packet_lengths`: Total packet length (signed: positive=up, negative=down)
- `ip_lengths`: IP layer length (signed)
- `trans_lengths`: Transport layer length (signed)
- `app_lengths`: Application payload length (signed)
- `timestamps`: Packet timestamps
- `iats`: Inter-arrival times
- `tcp_flags`: TCP flags sequence
- `tcp_window_sizes`: TCP window sizes

#### Statistical Features (computed with numpy)
- Basic: mean, std, var, min, max, range, median, sum
- Distribution: skewness, kurtosis, CV (coefficient of variation)
- Directional: up/down (forward/reverse) statistics

## Installation

```bash
pip install dpkt numpy pandas cryptography
```

Or use conda:

```bash
conda install dpkt numpy pandas cryptography
```

## Quick Start

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

## Usage Examples

### Extract Packet Length Sequences

```python
from wa1kpcap import Wa1kPcap

analyzer = Wa1kPcap(verbose_mode=True, compute_statistics=True)
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    if flow.features:
        # Packet lengths (positive=up, negative=down)
        lengths = flow.features.packet_lengths
        print(f"Packet lengths: {lengths.tolist()}")

        # IATs
        iats = flow.features.iats
        print(f"IATs: {iats.tolist()}")
```

### Extract Statistical Features

```python
from wa1kpcap import Wa1kPcap

analyzer = Wa1kPcap(verbose_mode=True, compute_statistics=True)
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    # Access pre-computed statistics via properties
    print(f"Mean packet length: {flow.pkt_mean:.1f}")
    print(f"Std packet length: {flow.pkt_std:.1f}")

    # Directional statistics
    print(f"Up packet count: {flow.pkt_up_count}")
    print(f"Down packet count: {flow.pkt_down_count}")
    print(f"Up mean: {flow.pkt_up_mean:.1f}")
    print(f"Down mean: {flow.pkt_down_mean:.1f}")

    # IAT statistics
    print(f"IAT mean: {flow.iat_mean:.6f}")
    print(f"IAT max: {flow.iat_max:.6f}")

    # Or access all stats via dictionary
    stats = flow.stats
    print(f"Total packets: {stats['packet_count']}")
```

### Extract TLS SNI

```python
from wa1kpcap import Wa1kPcap

analyzer = Wa1kPcap(verbose_mode=True)
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    if flow.tls:
        print(f"TLS version: {flow.tls.version}")
        if flow.tls.sni:
            print(f"  SNI: {flow.tls.sni}")
        if flow.tls.alpn:
            print(f"  ALPN: {flow.tls.alpn}")
        if flow.tls.certificate:
            cert = flow.tls.certificate
            print(f"  Cert subject: {cert.get('subject')}")
            print(f"  Cert issuer: {cert.get('issuer')}")
```

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

### Access Flow Metrics

```python
from wa1kpcap import Wa1kPcap

analyzer = Wa1kPcap(verbose_mode=True)
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    # Basic metrics
    print(f"Total packets: {flow.metrics.packet_count}")
    print(f"Up packets: {flow.metrics.up_packet_count}")
    print(f"Down packets: {flow.metrics.down_packet_count}")
    print(f"Up bytes: {flow.metrics.up_byte_count}")
    print(f"Down bytes: {flow.metrics.down_byte_count}")
```

## API Reference

### Wa1kPcap

Main entry point for PCAP analysis.

```python
Wa1kPcap(
    udp_timeout: float = 0,               # UDP flow timeout (0=no timeout)
    tcp_cleanup_timeout: float = 300.0,  # TCP cleanup timeout (seconds)
    filter_ack: bool = False,             # Filter pure ACK packets
    filter_rst: bool = False,             # Filter RST packets
    filter_retrans: bool = True,          # Filter TCP retransmissions
    verbose_mode: bool = False,           # Store packet-level data
    save_raw_bytes: bool = False,         # Save raw packet bytes
    compute_statistics: bool = True,      # Compute statistical features
    enable_reassembly: bool = True,       # Enable IP/TCP/TLS reassembly
)
```

**Methods:**
- `analyze_file(pcap_path) -> list[Flow]`: Analyze a single PCAP file
- `analyze_directory(directory, pattern="*.pcap") -> dict`: Analyze all PCAP files in a directory
- `register_feature(name, processor)`: Register a custom feature processor

### Flow

Represents a bidirectional network flow.

**Five-tuple Access:**
```python
flow.key.src_ip      # Source IP address
flow.key.dst_ip      # Destination IP address
flow.key.src_port    # Source port
flow.key.dst_port    # Destination port
flow.key.protocol    # Protocol (6=TCP, 17=UDP, etc.)
```

**Time Access:**
```python
flow.start_time   # Flow start timestamp
flow.end_time     # Flow end timestamp
flow.duration     # Flow duration in seconds
```

**Basic Metrics:**
```python
flow.packet_count            # Total packets
flow.metrics.up_packet_count   # Up direction packets
flow.metrics.down_packet_count # Down direction packets
```

**Statistical Features (if compute_statistics=True):**

Total packet statistics:
- `flow.pkt_mean`, `flow.pkt_std`, `flow.pkt_var`, `flow.pkt_min`, `flow.pkt_max`, `flow.pkt_range`, `flow.pkt_median`, `flow.pkt_skew`, `flow.pkt_kurt`, `flow.pkt_cv`

Directional packet statistics:
- `flow.pkt_up_mean`, `flow.pkt_up_std`, `flow.pkt_up_min`, `flow.pkt_up_max`, `flow.pkt_up_sum`, `flow.pkt_up_count`
- `flow.pkt_down_mean`, `flow.pkt_down_std`, `flow.pkt_down_min`, `flow.pkt_down_max`, `flow.pkt_down_sum`, `flow.pkt_down_count`

IP layer statistics:
- `flow.ip_mean`, `flow.ip_std`, `flow.ip_var`, `flow.ip_min`, `flow.ip_max`, `flow.ip_range`, `flow.ip_median`, `flow.ip_skew`, `flow.ip_kurt`, `flow.ip_cv`

Transport layer statistics:
- `flow.trans_mean`, `flow.trans_std`, `flow.trans_var`, `flow.trans_min`, `flow.trans_max`, `flow.trans_range`, `flow.trans_median`, `flow.trans_skew`, `flow.trans_kurt`, `flow.trans_cv`

App payload statistics:
- `flow.app_mean`, `flow.app_std`, `flow.app_var`, `flow.app_min`, `flow.app_max`, `flow.app_range`, `flow.app_median`, `flow.app_skew`, `flow.app_kurt`, `flow.app_cv`

IAT statistics:
- `flow.iat_mean`, `flow.iat_std`, `flow.iat_var`, `flow.iat_min`, `flow.iat_max`, `flow.iat_range`, `flow.iat_median`, `flow.iat_skew`, `flow.iat_kurt`, `flow.iat_cv`

**Full Statistics Dictionary:**
```python
stats = flow.stats
stats['packet_count']      # Total packets
stats['packet_lengths']    # Total packet length statistics
stats['ip_lengths']        # IP layer statistics
stats['trans_lengths']     # Transport layer statistics
stats['app_lengths']       # App payload statistics
stats['iats']              # IAT statistics
```

**Protocol Fields:**
```python
flow.tls      # TLSInfo if TLS detected
flow.http     # HTTPInfo if HTTP detected
flow.dns      # DNSInfo if DNS detected
```

### Exporters

```python
from wa1kpcap import to_dataframe, to_dict, to_csv, to_json, FlowExporter

# Export to pandas DataFrame
df = to_dataframe(flows)

# Export to dictionary
flow_dicts = to_dict(flows, include_features=True)

# Export to files
to_csv(flows, 'output.csv')
to_json(flows, 'output.json', indent=2)

# Using FlowExporter class
exporter = FlowExporter(include_features=True)
exporter.to_csv(flows, 'output.csv')
exporter.to_json(flows, 'output.json')
exporter.save(flows, 'output.csv')  # Auto-detect format
```

## Statistical Features

The following statistics are computed for each sequence type:

| Statistic | Description |
|-----------|-------------|
| mean | Mean value |
| std | Standard deviation |
| var | Variance |
| min | Minimum value |
| max | Maximum value |
| range | Range (max - min) |
| median | Median value |
| skew | Skewness |
| kurt | Kurtosis |
| cv | Coefficient of variation |
| up_mean, up_std, ... | Up direction statistics |
| down_mean, down_std, ... | Down direction statistics |
| up_count, down_count | Directional packet counts |

## Project Structure

```
wa1kpcap/
├── __init__.py              # Public API exports
├── core/
│   ├── analyzer.py          # Wa1kPcap main class
│   ├── flow.py             # Flow, FlowKey, FlowManager, FlowMetrics
│   ├── packet.py           # ParsedPacket wrapper
│   └── reader.py           # Multi-format PCAP reader
├── protocols/
│   ├── registry.py         # Protocol handler registry
│   ├── base.py            # BaseProtocolHandler
│   ├── link.py            # Link layer handlers
│   ├── network.py         # IPv4/IPv6 handlers
│   ├── transport.py        # TCP/UDP handlers
│   └── application.py     # TLS/HTTP/DNS handlers
├── reassembly/
│   ├── ip_fragment.py      # IP fragment reassembly
│   ├── tcp_stream.py       # TCP stream reassembly
│   └── tls_record.py       # TLS record reassembly
├── features/
│   ├── extractor.py        # FeatureExtractor, FlowFeatures
│   └── registry.py         # Feature registry
└── exporters.py            # DataFrame/CSV/JSON export
```

## Supported DLT Types

| DLT | Value | Description |
|-----|-------|-------------|
| DLT_NULL | 0 | BSD Loopback |
| DLT_EN10MB | 1 | Ethernet |
| DLT_RAW | 101 | Raw IP |
| DLT_LINUX_SLL | 113 | Linux Cooked Capture |
| DLT_NFLOG | 117 | iptables NFLOG |

## License

MIT License

## Author

wa1k

## Documentation

For detailed documentation including:
- Custom feature registration examples
- Advanced protocol parsing
- Complete API reference
- Export options

See [docs/README.md](docs/README.md)
