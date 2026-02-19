#pragma once

// ── Built-in protocol registry (X-Macro) ──
// Single source of truth for all built-in protocols.
// Adding a new protocol = add one line here + write struct/fill/fast_parse/build.
//
// X(PascalName, snake_name, CppStruct, PyClass)
//   PascalName  — used for ClassCache field names (e.g. EthernetInfo_cls)
//   snake_name  — used for struct field + has_flag in NativeParsedPacket
//   CppStruct   — the C++ struct type (e.g. NativeEthernetInfo)
//   PyClass     — Python class name string for import (e.g. "EthernetInfo")

#define BUILTIN_PROTOCOLS(X) \
    X(Ethernet, eth,   NativeEthernetInfo, "EthernetInfo") \
    X(IP,       ip,    NativeIPInfo,       "IPInfo")       \
    X(IP6,      ip6,   NativeIP6Info,      "IP6Info")      \
    X(TCP,      tcp,   NativeTCPInfo,      "TCPInfo")      \
    X(UDP,      udp,   NativeUDPInfo,      "UDPInfo")      \
    X(TLS,      tls,   NativeTLSInfo,      "TLSInfo")      \
    X(DNS,      dns,   NativeDNSInfo,      "DNSInfo")      \
    X(ARP,      arp,   NativeARPInfo,      "ARPInfo")      \
    X(ICMP,     icmp,  NativeICMPInfo,     "ICMPInfo")     \
    X(ICMP6,    icmp6, NativeICMP6Info,    "ICMP6Info")    \
    X(VLAN,     vlan,  NativeVLANInfo,     "VLANInfo")     \
    X(SLL,      sll,   NativeSLLInfo,      "SLLInfo")      \
    X(SLL2,     sll2,  NativeSLL2Info,     "SLL2Info")     \
    X(GRE,      gre,   NativeGREInfo,      "GREInfo")      \
    X(VXLAN,    vxlan, NativeVXLANInfo,    "VXLANInfo")    \
    X(MPLS,     mpls,  NativeMPLSInfo,     "MPLSInfo")     \
    X(DHCP,     dhcp,  NativeDHCPInfo,     "DHCPInfo")     \
    X(DHCPv6,   dhcpv6, NativeDHCPv6Info,  "DHCPv6Info")
