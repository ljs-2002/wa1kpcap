#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include "field_value.h"
#include "protocol_registry.h"

// ── C++ structs mirroring Python dataclasses in wa1kpcap/core/packet.py ──
// Used by parse_packet_struct to return structured data directly,
// bypassing the dict → converter.py path.
//
// All sub-structs are embedded directly (no shared_ptr heap allocs).
// Presence is tracked via has_* bool flags.

struct NativeEthernetInfo {
    std::string src;
    std::string dst;
    int64_t type = 0;
};

struct NativeIPInfo {
    int64_t version = 4;
    std::string src;
    std::string dst;
    int64_t proto = 0;
    int64_t ttl = 0;
    int64_t len = 0;
    int64_t id = 0;
    int64_t flags = 0;    // Combined flags: bit 0 = MF, bit 1 = DF
    int64_t offset = 0;   // Fragment offset
    std::string options_raw;  // raw IP options bytes (IHL > 5)

    // Computed properties (read-only from Python)
    bool is_fragment() const { return (flags & 0x1) != 0 || offset != 0; }
    bool more_fragments() const { return (flags & 0x1) != 0; }
};

struct NativeIP6Info {
    int64_t version = 6;
    std::string src;
    std::string dst;
    int64_t next_header = 0;
    int64_t hop_limit = 0;
    int64_t flow_label = 0;
    int64_t len = 0;
    std::string options_raw;  // raw extension header bytes
};

struct NativeTCPInfo {
    int64_t sport = 0;
    int64_t dport = 0;
    int64_t seq = 0;
    int64_t ack_num = 0;
    int64_t flags = 0;
    int64_t win = 0;
    int64_t urgent = 0;
    std::string options;  // stored as bytes via py::bytes

    // Flag accessors (read-only from Python)
    bool syn() const { return (flags & 0x02) != 0; }
    bool fin() const { return (flags & 0x01) != 0; }
    bool rst() const { return (flags & 0x04) != 0; }
    bool psh() const { return (flags & 0x08) != 0; }
    bool ack() const { return (flags & 0x10) != 0; }
    bool urg() const { return (flags & 0x20) != 0; }
    bool ece() const { return (flags & 0x40) != 0; }
    bool cwr() const { return (flags & 0x80) != 0; }
    bool is_handshake() const { return syn() && !ack(); }
    bool is_handshake_ack() const { return syn() && ack(); }
};

struct NativeUDPInfo {
    int64_t sport = 0;
    int64_t dport = 0;
    int64_t len = 0;
};

struct NativeTLSInfo {
    std::string version;          // e.g. "3.3"
    int64_t content_type = -1;    // -1 = not set
    int64_t handshake_type = -1;  // -1 = not set
    std::string sni;              // Single SNI string (most common case)
    std::vector<int64_t> cipher_suites;
    int64_t cipher_suite = -1;    // Selected cipher suite (ServerHello)
    int64_t record_length = 0;
    std::vector<std::string> alpn;
    std::vector<int64_t> signature_algorithms;
    std::vector<int64_t> supported_groups;
    std::vector<int64_t> handshake_types;  // All handshake types (in order)
    std::vector<std::string> certificates;  // Raw DER bytes of each certificate
};

struct NativeDNSInfo {
    std::vector<std::string> queries;
    int64_t response_code = 0;
    int64_t question_count = 0;
    int64_t answer_count = 0;
    int64_t authority_count = 0;
    int64_t additional_count = 0;
    int64_t flags = 0;

    bool is_query() const { return (flags & 0x8000) == 0; }
    bool is_response() const { return (flags & 0x8000) != 0; }
};

struct NativeARPInfo {
    int64_t hw_type = 0;
    int64_t proto_type = 0;
    int64_t opcode = 0;
    std::string sender_mac;
    std::string sender_ip;
    std::string target_mac;
    std::string target_ip;
};

struct NativeICMPInfo {
    int64_t type = 0;
    int64_t code = 0;
    int64_t checksum = 0;
    std::string rest_data;  // raw bytes after 4-byte header
};

struct NativeICMP6Info {
    int64_t type = 0;
    int64_t code = 0;
    int64_t checksum = 0;
    std::string rest_data;  // raw bytes after 4-byte header
};

struct NativeVLANInfo {
    int64_t vlan_id = 0;
    int64_t priority = 0;
    int64_t dei = 0;
    int64_t ether_type = 0;
};

struct NativeSLLInfo {
    int64_t packet_type = 0;
    int64_t arphrd_type = 0;
    std::string addr;           // 8-byte link-layer address as hex string
    int64_t protocol = 0;
};

struct NativeSLL2Info {
    int64_t protocol_type = 0;
    int64_t interface_index = 0;
    int64_t arphrd_type = 0;
    int64_t packet_type = 0;
    std::string addr;           // 8-byte link-layer address as hex string
};

struct NativeGREInfo {
    int64_t flags = 0;          // Full 2-byte flags+version field
    int64_t protocol_type = 0;  // Ethertype of encapsulated payload
    int64_t checksum = 0;       // Optional (present if C bit set)
    int64_t key = 0;            // Optional (present if K bit set)
    int64_t sequence = 0;       // Optional (present if S bit set)
    bool has_checksum = false;
    bool has_key = false;
    bool has_sequence = false;
};

struct NativeVXLANInfo {
    int64_t flags = 0;          // 1 byte flags (bit 3 = VNI valid)
    int64_t vni = 0;            // 24-bit VXLAN Network Identifier
};

struct NativeMPLSInfo {
    int64_t label = 0;          // 20-bit label of bottom-of-stack entry
    int64_t tc = 0;             // 3-bit traffic class
    int64_t ttl = 0;            // 8-bit TTL
    int64_t stack_depth = 0;    // Number of label entries in the stack
    bool bottom_of_stack = false;
};

struct NativeDHCPInfo {
    int64_t op = 0;             // 1=BOOTREQUEST, 2=BOOTREPLY
    int64_t htype = 0;          // Hardware type (1=Ethernet)
    int64_t xid = 0;            // Transaction ID
    std::string ciaddr;         // Client IP
    std::string yiaddr;         // 'Your' IP
    std::string siaddr;         // Server IP
    std::string giaddr;         // Gateway IP
    std::string chaddr;         // Client hardware address (MAC)
    std::vector<uint8_t> options_raw; // Raw options bytes for user-side parsing
};

struct NativeDHCPv6Info {
    int64_t msg_type = 0;       // Message type (1=Solicit, 2=Advertise, etc.)
    int64_t transaction_id = 0; // 24-bit transaction ID
    std::vector<uint8_t> options_raw; // Raw options bytes for user-side parsing
};

struct NativeParsedPacket {
    double timestamp = 0.0;
    std::string raw_data;         // stored as py::bytes
    int64_t link_layer_type = 0;
    int64_t caplen = 0;
    int64_t wirelen = 0;
    int64_t ip_len = 0;
    int64_t trans_len = 0;
    int64_t app_len = 0;

    // Protocol layers — embedded directly (zero heap allocs)
    #define X_FIELD(P, s, S, Py) S s;
    BUILTIN_PROTOCOLS(X_FIELD)
    #undef X_FIELD

    // Presence flags (replaces shared_ptr nullptr checks)
    #define X_HAS(P, s, S, Py) bool has_##s = false;
    BUILTIN_PROTOCOLS(X_HAS)
    #undef X_HAS

    // Flow tracking (mutated by Python)
    bool is_client_to_server = true;
    int64_t packet_index = -1;
    int64_t flow_index = -1;

    // Raw TCP payload for reassembly
    std::string _raw_tcp_payload;  // stored as py::bytes

    // TLS bytes consumed by parse_tls_stream (for Python buffer management)
    int64_t tls_bytes_consumed = 0;

    // Extra layers: YAML-parsed protocols not covered by fixed structs above
    std::map<std::string, FieldMap> extra_layers;
};
