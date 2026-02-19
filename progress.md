# Progress Log

## Session 1: Phase 0–2
- Committed baseline state (Phase 0)
- Completed docs update: merge() mechanisms, Info class inheritance (Phase 1)
- Added 5 built-in protocols: GRE, VXLAN, MPLS, DHCP, DHCPv6 (Phase 2)
- DHCP/DHCPv6 upgraded from Type B to Type A fast-path
- 363 tests passing

## Session 2: Phase 3–4
- Added `default_filter` parameter with AND merge logic (Phase 3)
- Extended BPF compiler with 6 new keywords: dhcp, dhcpv6, vlan, gre, vxlan, mpls
- Added `app_layer_parsing` parameter: full/port_only/none (Phase 4)
- C++ gate logic in `parse_packet_struct`, Python gates in analyzer.py

## Session 3: Phase 5 — Performance fix & final validation
- **BPF performance regression found & fixed**: `dhcp`/`dhcpv6` BPF keywords forced slow parsed-dict matching path (`can_match_raw()=false`). Implemented port-based raw-byte matching for dhcp(UDP 67/68), dhcpv6(UDP 546/547), gre(IP proto 47), vxlan(UDP 4789). Fix: 34s → 21s on FTP.pcap.
- **app_layer_parsing simplified**: Removed `fast` mode (benchmark showed no difference vs `port_only`). Now 3 modes: full(0), port_only(1), none(2).
- **Final benchmark** (FTP.pcap, 360K pkts, native engine, 5 runs avg):
  - full: 20.7s (baseline)
  - port_only: 20.4s (-1.3%)
  - none: 20.2s (-2.2%)
- **Tests**: 363 passed, 2 skipped, 0 failures
