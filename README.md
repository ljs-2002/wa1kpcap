# wa1kpcap

[![PyPI](https://img.shields.io/pypi/v/wa1kpcap)](https://pypi.org/project/wa1kpcap/)
[![Python](https://img.shields.io/pypi/pyversions/wa1kpcap)](https://pypi.org/project/wa1kpcap/)
[![License](https://img.shields.io/pypi/l/wa1kpcap)](https://github.com/ljs-2002/wa1kpcap/blob/main/LICENSE)
[![Tests](https://github.com/ljs-2002/wa1kpcap/actions/workflows/tests.yml/badge.svg)](https://github.com/ljs-2002/wa1kpcap/actions/workflows/tests.yml)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)](https://pypi.org/project/wa1kpcap/)

[中文文档](https://github.com/ljs-2002/wa1kpcap/blob/main/README_CN.md)

Fast PCAP analysis library for Python. Extracts multi-level flow features and protocol fields across all layers from network traffic captures, with a native C++ parsing engine.

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

## Supported Protocols

| Layer | Protocols |
|-------|-----------|
| Link | Ethernet, VLAN (802.1Q), Linux SLL/SLL2, Raw IP, BSD Loopback, NFLOG |
| Network | IPv4, IPv6, ARP, ICMP, ICMPv6 |
| Tunnel | GRE, VXLAN, MPLS |
| Transport | TCP, UDP |
| Application | TLS (SNI/ALPN/certs), DNS, HTTP, DHCP, DHCPv6 |

All protocols have C++ fast-path implementations. Tunnel protocols (GRE, VXLAN, MPLS) support recursive inner-packet dispatch.

## Features

- Fast C++ native parsing engine with Python API, also supports dpkt as alternative engine (`pip install wa1kpcap[dpkt]`)
- Flow-level feature extraction with signed directional packet lengths
- 8 sequence features per flow: packet_lengths, ip_lengths, trans_lengths, app_lengths, timestamps, iats, tcp_flags, tcp_window_sizes
- Statistical aggregation: mean, std, var, min, max, range, median, skew, kurt, cv, plus up/down directional breakdowns
- Multi-layer protocol field extraction from link layer to application layer
- BPF filter with protocol-aware keywords (dhcp, dhcpv6, vlan, gre, vxlan, mpls)
- IP fragment, TCP stream, and TLS record reassembly
- Export to DataFrame, CSV, JSON
- Custom incremental feature registration
- YAML-based protocol extension for adding new protocols without C++ code

## Documentation

For detailed usage, API reference, and examples, see [docs/README.md](https://github.com/ljs-2002/wa1kpcap/blob/main/docs/README.md).

## License

MIT License

## Author

1in_js
