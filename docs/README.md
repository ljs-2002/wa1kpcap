# wa1kpcap — Detailed Documentation

[中文文档](README_CN.md)

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Core Concepts](#core-concepts)
4. [Engine Selection](#engine-selection)
5. [BPF Filtering](#bpf-filtering)
6. [Application Layer Parsing](#application-layer-parsing)
7. [Feature Extraction](#feature-extraction)
8. [Custom Features](#custom-features)
9. [Protocol Parsing](#protocol-parsing)
10. [Export](#export)
11. [API Reference](#api-reference)
12. [Supported DLT Types](#supported-dlt-types)
13. [Project Structure](#project-structure)

## Installation

```bash
pip install wa1kpcap
```

Optional dependencies:

```bash
pip install wa1kpcap[dpkt]      # dpkt engine support
pip install wa1kpcap[export]    # pandas DataFrame export
pip install wa1kpcap[crypto]    # TLS certificate parsing
pip install wa1kpcap[dev]       # development (pytest, scapy, etc.)
```

## Quick Start

```python
from wa1kpcap import Wa1kPcap

analyzer = Wa1kPcap()
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    print(f"{flow.key}  packets={flow.packet_count}  duration={flow.duration:.3f}s")
```

## Core Concepts

### Flow

A **flow** is a bidirectional communication between two endpoints, identified by a 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol). The first packet that creates the flow defines the "forward" (up) direction.

### Direction

Packet lengths use **signed values** to indicate direction:
- **Positive** → forward (client-to-server)
- **Negative** → reverse (server-to-client)

### Verbose Mode

| Mode | `verbose_mode` | Behavior |
|------|---------------|----------|
| Non-verbose | `False` (default) | Aggregated flow-level data only, lower memory |
| Verbose | `True` | Stores packet-level data, allows per-packet iteration |

## Engine Selection

wa1kpcap provides two parsing engines:

```python
# Native C++ engine (default, faster)
analyzer = Wa1kPcap(engine="native")

# dpkt engine (requires pip install wa1kpcap[dpkt])
analyzer = Wa1kPcap(engine="dpkt")
```

If `engine="dpkt"` is specified but dpkt is not installed, it falls back to native with a warning.

## BPF Filtering

### Default Filter

By default, ARP/ICMP/DHCP packets are excluded:

```python
# Default: "not arp and not icmp and not icmpv6 and not dhcp and not dhcpv6"
analyzer = Wa1kPcap()

# Disable default filter
analyzer = Wa1kPcap(default_filter=None)
```

### Custom BPF Filter

```python
# Standard BPF syntax
analyzer = Wa1kPcap(bpf_filter="tcp port 443")
analyzer = Wa1kPcap(bpf_filter="host 192.168.1.1 and tcp")
analyzer = Wa1kPcap(bpf_filter="net 10.0.0.0/8")
```

### Protocol-Aware Keywords

Extended BPF keywords for application-layer protocols:

```python
analyzer = Wa1kPcap(bpf_filter="not vlan and not gre")
analyzer = Wa1kPcap(bpf_filter="dhcp or dhcpv6")
analyzer = Wa1kPcap(bpf_filter="not vxlan and not mpls")
```

Supported keywords: `dhcp`, `dhcpv6`, `vlan`, `gre`, `vxlan`, `mpls`.

### Combining Filters

`bpf_filter` is combined with `default_filter` using AND logic:

```python
# Effective filter: "(not arp and not icmp and ...) and (tcp port 443)"
analyzer = Wa1kPcap(bpf_filter="tcp port 443")
```

### Packet-Level Filters

```python
analyzer = Wa1kPcap(
    filter_ack=True,       # Exclude pure ACK packets (no payload)
    filter_rst=True,       # Exclude RST packets
    filter_retrans=True,   # Exclude TCP retransmissions (default: True)
)
```

## Application Layer Parsing

Control how deep the parser goes beyond the transport layer:

```python
# Full (default): all protocols — TLS handshake, DNS, HTTP, etc.
analyzer = Wa1kPcap(app_layer_parsing="full")

# Port-only: dispatch by port number, skip slow-path parsing (TLS handshake, etc.)
analyzer = Wa1kPcap(app_layer_parsing="port_only")

# None: TCP/UDP headers only, no application layer parsing
analyzer = Wa1kPcap(app_layer_parsing="none")
```

Use `"port_only"` or `"none"` when you only need flow-level features and want faster processing.

## Feature Extraction

### Sequence Features

```python
analyzer = Wa1kPcap(compute_statistics=True)
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    if flow.features:
        print(flow.features.packet_lengths)    # signed total packet lengths
        print(flow.features.ip_lengths)        # signed IP layer lengths
        print(flow.features.trans_lengths)     # signed transport layer lengths
        print(flow.features.app_lengths)       # signed app payload lengths
        print(flow.features.timestamps)        # packet timestamps
        print(flow.features.iats)              # inter-arrival times
        print(flow.features.tcp_flags)         # TCP flags per packet
        print(flow.features.tcp_window_sizes)  # TCP window sizes
```

### Statistical Features

When `compute_statistics=True`, each sequence produces a full set of statistics:

```python
for flow in flows:
    # Packet length statistics
    print(f"mean={flow.pkt_mean:.1f}  std={flow.pkt_std:.1f}")
    print(f"min={flow.pkt_min}  max={flow.pkt_max}  range={flow.pkt_range}")
    print(f"median={flow.pkt_median}  skew={flow.pkt_skew:.3f}  kurt={flow.pkt_kurt:.3f}")

    # Directional statistics
    print(f"up: count={flow.pkt_up_count}  mean={flow.pkt_up_mean:.1f}  sum={flow.pkt_up_sum}")
    print(f"down: count={flow.pkt_down_count}  mean={flow.pkt_down_mean:.1f}  sum={flow.pkt_down_sum}")

    # IAT statistics
    print(f"iat mean={flow.iat_mean:.6f}  max={flow.iat_max:.6f}")

    # IP / Transport / App layer — same pattern
    print(f"ip mean={flow.ip_mean:.1f}  trans mean={flow.trans_mean:.1f}  app mean={flow.app_mean:.1f}")
```

### Statistics Dictionary

```python
stats = flow.stats
# stats['packet_count']       → int
# stats['total_bytes']        → int
# stats['duration']           → float
# stats['packet_lengths']     → {'mean': ..., 'std': ..., 'min': ..., 'max': ..., ...}
# stats['ip_lengths']         → same structure
# stats['trans_lengths']      → same structure
# stats['app_lengths']        → same structure
# stats['iats']               → same structure
# stats['tcp_flags']          → same structure
# stats['up_down_pkt_ratio']  → float
# stats['up_down_byte_ratio'] → float
```

Each sub-dict contains: `mean`, `std`, `var`, `min`, `max`, `range`, `median`, `skew`, `kurt`, `cv`, `sum`, `count`, plus `up_*` and `down_*` variants.

### Flow Metrics

```python
for flow in flows:
    print(f"Total packets: {flow.packet_count}")
    print(f"Up packets: {flow.metrics.up_packet_count}")
    print(f"Down packets: {flow.metrics.down_packet_count}")
    print(f"Up bytes: {flow.metrics.up_byte_count}")
    print(f"Down bytes: {flow.metrics.down_byte_count}")
    print(f"Duration: {flow.duration:.3f}s")
```

## Custom Features

Register custom incremental features that are computed per-packet during analysis.

```python
from wa1kpcap import Wa1kPcap, Flow
from wa1kpcap.features.registry import BaseIncrementalFeature, FeatureType
from dataclasses import dataclass, field
import numpy as np
import math

@dataclass
class EntropyState:
    values: list[float] = field(default_factory=list)

class PayloadEntropyFeature(BaseIncrementalFeature):
    def __init__(self):
        super().__init__("payload_entropy", FeatureType.SEQUENCE)

    def initialize(self, flow: Flow) -> None:
        if not hasattr(flow, '_feature_state'):
            flow._feature_state = {}
        flow._feature_state['payload_entropy'] = EntropyState()

    def update(self, flow: Flow, pkt) -> None:
        state = flow._feature_state.get('payload_entropy')
        if state is None:
            return
        payload = pkt.payload or b''
        if payload:
            counts = [0] * 256
            for b in payload:
                counts[b] += 1
            n = len(payload)
            entropy = -sum(
                (c / n) * math.log2(c / n) for c in counts if c > 0
            )
            state.values.append(entropy)

    def get_value(self, flow: Flow) -> dict:
        state = flow._feature_state.get('payload_entropy')
        if state is None:
            return {}
        arr = np.array(state.values)
        return {
            'sequence': arr,
            'mean': float(arr.mean()) if len(arr) > 0 else 0.0,
        }

# Usage
analyzer = Wa1kPcap(verbose_mode=True)
analyzer.register_feature('payload_entropy', PayloadEntropyFeature())
flows = analyzer.analyze_file('traffic.pcap')

for flow in flows:
    features = flow.get_features()
    if 'payload_entropy' in features:
        print(f"Entropy mean: {features['payload_entropy']['mean']:.3f}")
```

Key points:
- Inherit from `BaseIncrementalFeature`
- Implement `initialize()`, `update()`, `get_value()`
- Register before calling `analyze_file()`
- Access results via `flow.get_features()[name]`

## Protocol Parsing

### TLS

SNI, ALPN, and version are always available. Certificate fields (`subject`, `issuer`, `not_before`, etc.) require `pip install wa1kpcap[crypto]`. Without it, `flow.tls.certificates` contains raw DER bytes that you can parse yourself.

```python
for flow in flows:
    if flow.tls:
        print(f"Version: {flow.tls.version}")
        print(f"SNI: {flow.tls.sni}")
        print(f"ALPN: {flow.tls.alpn}")
        if flow.tls.certificate:
            # Requires wa1kpcap[crypto]; without it, certificate is raw DER bytes
            cert = flow.tls.certificate
            print(f"Subject: {cert.get('subject')}")
            print(f"Issuer: {cert.get('issuer')}")
            print(f"Valid: {cert.get('not_before')} - {cert.get('not_after')}")
```

### DNS

```python
for flow in flows:
    if flow.dns:
        print(f"Queries: {flow.dns.queries}")
        print(f"Response code: {flow.dns.response_code}")
```

### HTTP

```python
for flow in flows:
    if flow.http:
        print(f"Method: {flow.http.method}")
        print(f"Host: {flow.http.host}")
        print(f"Path: {flow.http.path}")
        print(f"User-Agent: {flow.http.user_agent}")
```

## Export

### DataFrame

```python
from wa1kpcap import to_dataframe

df = to_dataframe(flows)
print(df[['src_ip', 'dst_ip', 'packet_count', 'feature.packet_lengths.mean']].head())
```

### CSV / JSON

```python
from wa1kpcap import to_csv, to_json

to_csv(flows, 'output.csv')
to_json(flows, 'output.json', indent=2)
```

### FlowExporter

```python
from wa1kpcap import FlowExporter

exporter = FlowExporter(include_features=True)
exporter.to_csv(flows, 'output.csv')
exporter.to_json(flows, 'output.json')
exporter.save(flows, 'output.csv')  # auto-detect format by extension
```

## API Reference

### Wa1kPcap

```python
Wa1kPcap(
    # Engine
    engine: str = "native",                # "native" (C++) or "dpkt"

    # Flow management
    udp_timeout: float = 0,                # UDP flow timeout (0=no timeout)
    tcp_cleanup_timeout: float = 300.0,    # TCP cleanup timeout (seconds)

    # Packet filtering
    filter_ack: bool = False,              # Filter pure ACK packets
    filter_rst: bool = False,              # Filter RST packets
    filter_retrans: bool = True,           # Filter TCP retransmissions
    bpf_filter: str | None = None,         # BPF filter expression
    default_filter: str | None = "not arp and not icmp and not icmpv6 and not dhcp and not dhcpv6",

    # Feature extraction
    verbose_mode: bool = False,            # Store packet-level data
    save_raw_bytes: bool = False,          # Save raw packet bytes
    compute_statistics: bool = True,       # Compute statistical features
    enabled_features: list[str] | None = None,

    # Protocol parsing
    enable_reassembly: bool = True,        # IP/TCP/TLS reassembly
    protocols: list[str] | None = None,    # Restrict to specific protocols
    app_layer_parsing: str = "full",       # "full", "port_only", or "none"
)
```

Methods:
- `analyze_file(pcap_path) -> list[Flow]` — Analyze a PCAP/PCAPNG file
- `analyze_directory(directory, pattern="*.pcap") -> dict` — Analyze all matching files in a directory
- `register_feature(name, processor)` — Register a custom incremental feature

### Flow

```python
# Five-tuple
flow.key.src_ip / dst_ip / src_port / dst_port / protocol

# Time
flow.start_time / end_time / duration

# Counts
flow.packet_count
flow.metrics.up_packet_count / down_packet_count
flow.metrics.up_byte_count / down_byte_count

# Features
flow.features                    # FlowFeatures object
flow.features.packet_lengths     # numpy array (signed)
flow.features.timestamps         # numpy array
flow.features.iats               # numpy array
flow.features.tcp_flags          # numpy array
flow.features.tcp_window_sizes   # numpy array

# Statistics (shortcut properties)
flow.pkt_mean / pkt_std / pkt_var / pkt_min / pkt_max / pkt_range
flow.pkt_median / pkt_skew / pkt_kurt / pkt_cv
flow.pkt_up_mean / pkt_up_std / pkt_up_min / pkt_up_max / pkt_up_sum / pkt_up_count
flow.pkt_down_mean / pkt_down_std / pkt_down_min / pkt_down_max / pkt_down_sum / pkt_down_count
# Same pattern for: ip_*, trans_*, app_*, iat_*

# Full statistics dict
flow.stats

# Protocol info
flow.tls / flow.dns / flow.http
```

## Supported DLT Types

| DLT | Value | Description |
|-----|-------|-------------|
| DLT_NULL | 0 | BSD Loopback |
| DLT_EN10MB | 1 | Ethernet |
| DLT_RAW | 101 | Raw IP |
| DLT_LOOP | 108 | OpenBSD Loopback |
| DLT_LINUX_SLL | 113 | Linux Cooked Capture v1 |
| DLT_NFLOG | 239 | NFLOG |
| DLT_LINUX_SLL2 | 276 | Linux Cooked Capture v2 |

## Project Structure

```
wa1kpcap/
├── __init__.py              # Public API
├── core/
│   ├── analyzer.py          # Wa1kPcap main class
│   ├── filter.py            # BPF filter compiler
│   ├── flow.py              # Flow, FlowKey, FlowManager
│   ├── packet.py            # ParsedPacket, ProtocolInfo classes
│   └── reader.py            # Multi-format PCAP reader
├── native/
│   ├── engine.py            # C++ engine Python wrapper
│   ├── converter.py         # Native→Python type conversion
│   └── protocols/           # YAML protocol definitions
├── protocols/
│   ├── base.py              # BaseProtocolHandler
│   ├── registry.py          # Protocol handler registry
│   ├── link.py              # Link layer (dpkt engine)
│   ├── network.py           # IPv4/IPv6 (dpkt engine)
│   ├── transport.py         # TCP/UDP (dpkt engine)
│   └── application.py       # TLS/HTTP/DNS (dpkt engine)
├── reassembly/
│   ├── ip_fragment.py       # IP fragment reassembly
│   ├── tcp_stream.py        # TCP stream reassembly
│   └── tls_record.py        # TLS record reassembly
├── features/
│   ├── extractor.py         # FeatureExtractor, FlowFeatures
│   └── registry.py          # Feature registry
└── exporters.py             # DataFrame/CSV/JSON export
```
