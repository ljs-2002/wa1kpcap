# Changelog

## v0.1.1 (2026-02-21)

### Bug Fixes

- Make dpkt a truly optional dependency: core analysis now works without dpkt installed
- Replace std::filesystem with portable helpers for macOS < 10.15 compatibility
- Fix hardcoded Windows paths in test files for cross-platform CI
- Remove License classifier conflicting with SPDX license expression

### Improvements

- Add paths-ignore to test workflow to skip CI on docs/workflow-only changes
- Add no-dpkt smoke test to catch optional dependency issues

## v0.1.0 (2026-02-20)

Initial release.

### Features

- Dual-engine architecture: native C++ engine (default) and dpkt fallback
- Flow-level feature extraction with signed directional lengths
- 8 sequence features per flow: packet_lengths, ip_lengths, trans_lengths, app_lengths, timestamps, iats, tcp_flags, tcp_window_sizes
- Statistical aggregation: mean, std, var, min, max, range, median, skew, kurt, cv, plus up/down directional breakdowns
- BPF filter with protocol-aware keywords (dhcp, dhcpv6, vlan, gre, vxlan, mpls)
- Application layer parsing control: full / port_only / none
- IP fragment, TCP stream, and TLS record reassembly
- Export to pandas DataFrame, CSV, JSON
- Custom incremental feature registration via BaseIncrementalFeature
- YAML-based protocol extension for the native engine

### Supported Protocols

- Link: Ethernet, VLAN (802.1Q), Linux SLL/SLL2, Raw IP, BSD Loopback, NFLOG
- Network: IPv4, IPv6, ARP, ICMP, ICMPv6
- Tunnel: GRE, VXLAN, MPLS
- Transport: TCP, UDP
- Application: TLS (SNI/ALPN/certs), DNS, HTTP, DHCP, DHCPv6

### Supported Platforms

- Python 3.10 - 3.13
- Linux (x86_64, aarch64), macOS (x86_64, arm64), Windows (AMD64)
