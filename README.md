# wa1kpcap

[![PyPI](https://img.shields.io/pypi/v/wa1kpcap?cacheSeconds=60)](https://pypi.org/project/wa1kpcap/)
[![Python](https://img.shields.io/pypi/pyversions/wa1kpcap?cacheSeconds=60)](https://pypi.org/project/wa1kpcap/)
[![License](https://img.shields.io/pypi/l/wa1kpcap?cacheSeconds=60)](https://github.com/ShituoMa/wa1kpcap/blob/main/LICENSE)
[![Tests](https://github.com/ShituoMa/wa1kpcap/actions/workflows/tests.yml/badge.svg)](https://github.com/ShituoMa/wa1kpcap/actions/workflows/tests.yml)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)](https://pypi.org/project/wa1kpcap/)

[中文文档](README_CN.md)

Efficient, extensible, out-of-the-box PCAP analysis library for Python. Extracts multi-level flow features and protocol fields from network traffic captures, powered by **two complementary C++ pipelines**:

| Pipeline | Module | Best for |
|----------|--------|----------|
| **YAML protocol engine** | `_wa1kpcap_native` | Custom protocols, QUIC/TLS/DNS field parsing, flow reassembly |
| **Native batch extractors (nvers)** | `_wa1kpcap_nvers` | CIC/CICext, sequences, TLS/DNS/L7 JSONL, VPN/IM, high-throughput offline jobs |

## What's New in v0.2.0

- **Integrated nvers extractors** — all high-throughput libpcap code lives under `src/cpp/nvers/` with a unified Python API (`wa1kpcap.extract`, `wa1kpcap.protocols`).
- **20 native feature types** — one-line batch extraction via `extract_all()`.
- **L7 protocol JSONL** — HTTP, SSH, MQTT, SIP, QUIC, RDP, VNC (from header-only parsers + new extractors).
- **Unified sequences** — `extract_unified_seq()` merges YAML-engine and native seq into a single JSONL with flat `sequences` fields.
- **Removed dpkt engine** — native C++ is the only parsing engine for `Wa1kPcap()` (see [CHANGELOG](CHANGELOG.md)).

## Installation

```bash
pip install wa1kpcap
```

On **Python 3.10–3.13** with a matching platform wheel (Linux/macOS/Windows), no local compilation is needed.

If no wheel matches your platform/Python version, install build deps and compile from source:

```bash
# Debian/Ubuntu
sudo apt install build-essential cmake libpcap-dev libssl-dev
pip install wa1kpcap
```

Optional dependencies:

```bash
pip install wa1kpcap[export]    # pandas DataFrame export
pip install wa1kpcap[crypto]    # TLS certificate parsing
pip install wa1kpcap[dev]       # development (pytest, scapy, etc.)
```

## Quick Start

### YAML engine — per-flow protocol fields

```python
from wa1kpcap import Wa1kPcap

flows = Wa1kPcap().analyze_file("traffic.pcap")
for flow in flows:
    print(flow.key, flow.packet_count, flow.duration)
```

### Native extractors — batch CIC / TLS / sequences

```python
from wa1kpcap.extract import extract_all, extract

# Default batch: cic, cicext, seq, payload, tls, dns
paths = extract_all("traffic.pcap", output_dir="out/")

# Or single feature
extract("traffic.pcap", "tls", output_path="out/tls.log")
```

### Unified sequence (YAML + native, one JSONL)

```python
from wa1kpcap.extract import extract_unified_seq

path = extract_unified_seq("traffic.pcap", "out/seq_unified.log")
```

See [docs/API_EXTRACT_CN.md](docs/API_EXTRACT_CN.md) (Chinese) for the full native extractor API.

## Native Features (`extract` / `extract_all`)

| Name | Output | Description |
|------|--------|-------------|
| `cic` / `cicext` | CSV | CIC-FlowMeter 80-dim / 272-dim extended stats |
| `seq` / `payload` | JSONL | Per-flow packet sequences / payload hex |
| `tls` / `dns` | JSONL | TLS handshake & certs / DNS queries |
| `smtp` / `dhcp` / `ftp` | JSONL | Mail, DHCP, FTP control channel |
| `http` / `ssh` / `mqtt` / `sip` / `quic` / `rdp` / `vnc` | JSONL | L7 protocol metadata |
| `vpn` / `im` | log | VPN / instant-messaging detection |
| `flow` | JSON | NetFlow v5 / IPFIX / Argus fields |
| `pcap_split` | dir | Split by 5-tuple into per-flow pcaps |

## Supported Protocols (YAML engine)

| Layer | Protocols |
|-------|-----------|
| Link | Ethernet, VLAN (802.1Q), Linux SLL/SLL2, Raw IP, BSD Loopback, NFLOG |
| Network | IPv4, IPv6, ARP, ICMP, ICMPv6 |
| Tunnel | GRE, VXLAN, MPLS |
| Transport | TCP, UDP |
| Application | TLS, DNS, HTTP, DHCP, DHCPv6, QUIC (Initial decryption, SNI/ALPN) |

Tunnel protocols (GRE, VXLAN, MPLS) support recursive inner-packet dispatch. L7 batch extractors above cover additional protocols via the native pipeline.

## Features

- Fast C++ native parsing engine with Python API
- **Dual pipelines**: flexible YAML engine + high-throughput libpcap extractors
- Flow-level features with signed directional packet lengths
- 8 sequence features per flow: packet_lengths, ip_lengths, trans_lengths, app_lengths, timestamps, iats, tcp_flags, tcp_window_sizes
- Statistical aggregation: mean, std, var, min, max, range, median, skew, kurt, cv, plus up/down breakdowns
- BPF filter with protocol-aware keywords (dhcp, dhcpv6, vlan, gre, vxlan, mpls)
- Cross-packet reassembly: IP fragments, TCP streams, TLS records, QUIC CRYPTO frames
- Export to DataFrame, CSV, JSON
- YAML-based protocol extension without recompiling for new field layouts

## Documentation

- [docs/README.md](docs/README.md) — detailed usage (English)
- [docs/README_CN.md](docs/README_CN.md) — 中文详细文档
- [docs/API_EXTRACT_CN.md](docs/API_EXTRACT_CN.md) — native extractor API
- [examples/](examples/) — demos (`demo_01` … `demo_08`)

## Roadmap

- [x] SMTP, SIP, SSH, HTTP L7 batch extractors (native)
- [ ] Field masking in raw bytes to reduce model overfitting
- [ ] CLI tool for quick pcap inspection
- [ ] Single-pass multi-feature extraction (shared pcap read)

## License

MIT License

## Author

1in_js · maintained by [ShituoMa/wa1kpcap](https://github.com/ShituoMa/wa1kpcap)
