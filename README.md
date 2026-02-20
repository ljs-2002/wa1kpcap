# wa1kpcap

[中文文档](README_CN.md)

Dual-engine PCAP analysis library for Python. Extracts flow-level features and protocol fields from network traffic captures using a native C++ engine (default) or dpkt as fallback.

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

- Dual engine: native C++ (default) or dpkt fallback
- Flow-level feature extraction with signed directional lengths
- 8 sequence features per flow: packet_lengths, ip_lengths, trans_lengths, app_lengths, timestamps, iats, tcp_flags, tcp_window_sizes
- Statistical aggregation: mean, std, var, min, max, range, median, skew, kurt, cv, plus directional breakdowns
- BPF filter with protocol-aware keywords (dhcp, dhcpv6, vlan, gre, vxlan, mpls)
- Application layer parsing control: full / port_only / none
- IP/TCP/TLS reassembly
- Export to DataFrame, CSV, JSON
- Custom incremental feature registration
- YAML-based protocol extension

## Documentation

For detailed usage, API reference, and examples, see [docs/README.md](docs/README.md).

## License

MIT License

## Author

1in_js
