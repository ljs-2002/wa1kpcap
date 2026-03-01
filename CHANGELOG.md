# Changelog

## v0.2.0 (2026-03-01)

### Breaking Changes

- **Removed dpkt engine**: The dpkt-based Python parsing engine has been completely removed. The native C++ engine is now the only engine.
  - Removed `engine="dpkt"` parameter from `Wa1kPcap` constructor
  - Removed `wa1kpcap[dpkt]` optional dependency
  - Removed `wa1kpcap/protocols/` directory (all dpkt protocol handlers)
  - Removed `from_dpkt()` methods from all protocol Info classes
  - Removed dpkt-related test cases

### Migration Guide

If you were using `engine="dpkt"`:
```python
# Before (v0.1.x)
analyzer = Wa1kPcap(engine="dpkt")

# After (v0.2.0)
analyzer = Wa1kPcap()  # native engine is now the default and only option
```

## v0.1.4 (2026-02-23)

### New Features

- C++ flow management pipeline: fused read, parse, filter, and flow management in C++ (`process_file`), eliminating per-packet Python-C++ boundary crossing
- C++ protocol aggregation: TLS/DNS/QUIC first-wins merge, TLS stream reassembly, and QUIC CRYPTO reassembly all in C++ (`aggregate_full`)
- C++ feature computation: statistical features (packet lengths, IATs, TCP flags, windows) computed entirely in C++ (`compute_features`)
- DNS fast-path C++ parser with compressed name decompression
- LazyPacketList: deferred C++ to Python packet conversion, only materializes on access
- Codecov integration for test coverage tracking

### Bug Fixes

- Fix packet direction detection: `is_client_to_server` was hardcoded to True in pybind11 bindings
- Fix QUIC SCID aggregation: now direction-aware, SCID taken from server (S2C) packets only
- Fix TLS flow-level conversion: certificates, handshake_types now properly propagated
- Fix TLS certificate access: use `parse_cert_der` for DER bytes instead of treating as object
- Fix IPv6 address support in BPF filter tokenizer (both Python and C++)

### Improvements

- Batch pybind11 calls: `aggregate_all`, `compute_all_features_dicts`, `export_all_flow_data` minimize boundary crossings
- dpkt engine marked as deprecated with DeprecationWarning

### Tests

- Protocol field verification against tshark (zero mismatches on multi.pcap and quic2.pcap)
- New test suites: test_flow_manager_native.py, test_process_file.py
- Expanded coverage: TLS certificates/SNI/cipher_suite, QUIC direction/SCID, DNS queries, DHCP fields, ICMP rest_data

## v0.1.3 (2026-02-22)

### Bug Fixes

- Replace port-based QUIC routing (`443: quic`) with payload heuristic detection, preventing gQUIC/DTLS from being misidentified as IETF QUIC
- Fix Short Header packets being misidentified as Long Header (version=0) by slow path `fill_quic`
- Fix QUIC CRYPTO frame reassembly: support offset-aware intra-packet sorting and cross-packet fragment collection for complete ClientHello extraction

### Improvements

- Improve flow-level QUIC aggregation: remove per-packet fields (`is_long_header`, `packet_type`, `token`, `spin_bit`), add server SCID aggregation from first responding Initial packet
- Add `flow.quic` property accessor on Flow class

### Tests

- Add QUIC integration tests using real pcap (test/quic2.pcap): flow count, SNI extraction, ALPN, cipher suites, known SNI values
- Update existing QUIC tests for corrected Short Header behavior

## v0.1.2 (2026-02-21)

### New Features

- QUIC protocol support: Long Header parsing (Initial, Handshake, 0-RTT, Retry) with C++ fast-path
- QUIC Initial packet decryption: zero-dependency embedded crypto (SHA-256, HMAC-SHA256, HKDF, AES-128-GCM)
- Extract SNI, ALPN, and cipher_suites from QUIC Initial Client Hello via decryption + TLS handshake parsing
- QUIC Short Header (1-RTT) identification via flow state: spin bit and DCID extraction
- QUICInfo dataclass with full field support (version, dcid, scid, token, spin_bit, sni, alpn, cipher_suites)
- Python bindings for crypto primitives (quic_sha256, quic_hmac_sha256, quic_hkdf_extract) for testing

### Tests

- 22 new QUIC tests: QUICInfo class, Long Header struct parsing, Short Header flow-state identification, RFC 9001 crypto test vectors

### Documentation

- Add QUIC to supported protocols in README (EN/CN)
- Add Roadmap section to README (EN/CN)
- Add C++ source tree to project structure in docs (EN/CN)

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
