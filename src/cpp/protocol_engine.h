#pragma once

#include "field_value.h"
#include "yaml_loader.h"
#include "parsed_packet.h"
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <functional>
#include <chrono>
#include <atomic>

namespace py = pybind11;

// Lightweight profiling counters for parse_packet_struct
struct ProfilingStats {
    std::atomic<uint64_t> total_ns{0};
    std::atomic<uint64_t> parse_layer_ns{0};    // time in parse_layer calls
    std::atomic<uint64_t> fill_struct_ns{0};     // time in fill_* calls
    std::atomic<uint64_t> next_proto_ns{0};      // time in next_protocol + heuristics (inside parse_layer)
    std::atomic<uint64_t> fieldmap_insert_ns{0}; // time in FieldMap insertions (inside parse_field)
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_layers{0};

    // Per-primitive counters
    std::atomic<uint64_t> fixed_ns{0};
    std::atomic<uint64_t> fixed_count{0};
    std::atomic<uint64_t> bitfield_ns{0};
    std::atomic<uint64_t> bitfield_count{0};
    std::atomic<uint64_t> computed_ns{0};
    std::atomic<uint64_t> computed_count{0};
    std::atomic<uint64_t> length_prefixed_ns{0};
    std::atomic<uint64_t> length_prefixed_count{0};
    std::atomic<uint64_t> hardcoded_ns{0};
    std::atomic<uint64_t> hardcoded_count{0};
    std::atomic<uint64_t> tlv_ns{0};
    std::atomic<uint64_t> tlv_count{0};
    std::atomic<uint64_t> counted_list_ns{0};
    std::atomic<uint64_t> counted_list_count{0};
    std::atomic<uint64_t> rest_ns{0};
    std::atomic<uint64_t> rest_count{0};
    std::atomic<uint64_t> prefixed_list_ns{0};
    std::atomic<uint64_t> prefixed_list_count{0};
    std::atomic<uint64_t> repeat_ns{0};
    std::atomic<uint64_t> repeat_count{0};
    std::atomic<uint64_t> ext_list_ns{0};
    std::atomic<uint64_t> ext_list_count{0};

    void reset() {
        total_ns = parse_layer_ns = fill_struct_ns = next_proto_ns = fieldmap_insert_ns = 0;
        total_packets = total_layers = 0;
        fixed_ns = fixed_count = 0;
        bitfield_ns = bitfield_count = 0;
        computed_ns = computed_count = 0;
        length_prefixed_ns = length_prefixed_count = 0;
        hardcoded_ns = hardcoded_count = 0;
        tlv_ns = tlv_count = 0;
        counted_list_ns = counted_list_count = 0;
        rest_ns = rest_count = 0;
        prefixed_list_ns = prefixed_list_count = 0;
        repeat_ns = repeat_count = 0;
        ext_list_ns = ext_list_count = 0;
    }
};

// Global profiling stats (enabled/disabled at runtime)
extern ProfilingStats g_prof;
extern bool g_profiling_enabled;

// RAII timer helper
struct ScopedTimer {
    std::atomic<uint64_t>& target;
    std::chrono::high_resolution_clock::time_point start;
    ScopedTimer(std::atomic<uint64_t>& t) : target(t), start(std::chrono::high_resolution_clock::now()) {}
    ~ScopedTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        target.fetch_add(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count(),
                         std::memory_order_relaxed);
    }
};

// The main protocol parsing engine.
// Driven by YAML-loaded ProtocolDefinitions, uses 8 primitive types
// to parse arbitrary protocol stacks.
class ProtocolEngine {
public:
    explicit ProtocolEngine(const YamlLoader& loader);

    // Parse a single protocol layer from buf[offset..offset+len).
    // Returns parsed fields and the number of bytes consumed.
    struct ParseResult {
        FieldMap fields;
        size_t bytes_consumed = 0;
        std::string next_protocol;  // empty if no next layer
        size_t next_offset = 0;     // offset for next layer in original buffer
    };

    ParseResult parse_layer(const std::string& protocol_name,
                            const uint8_t* buf, size_t len,
                            const uint8_t* pkt_base = nullptr,
                            size_t pkt_len = 0) const;

    // Parse full packet: chain through layers starting from link_type.
    // Returns a py::dict with protocol layers as nested dicts.
    py::dict parse_packet(const uint8_t* buf, size_t len, uint32_t link_type,
                          bool save_raw_bytes = false) const;

    // Parse full packet into C++ struct (bypasses dict + converter.py).
    // app_layer_mode: 0=full, 1=fast, 2=port_only, 3=none
    NativeParsedPacket parse_packet_struct(const uint8_t* buf, size_t len,
                                           uint32_t link_type,
                                           bool save_raw_bytes = false,
                                           int app_layer_mode = 0) const;

    // Parse from a specific protocol (not from link_type), return struct with TLS filled.
    NativeParsedPacket parse_from_protocol_struct(const uint8_t* buf, size_t len,
                                                   const std::string& start_protocol) const;

    const YamlLoader& loader() const { return loader_; }

private:
    // Parse a single field
    size_t parse_field(const FieldDef& field, const uint8_t* buf, size_t len,
                       FieldMap& out, const uint8_t* pkt_base, size_t pkt_len) const;

    // Primitive parsers
    size_t parse_fixed(const FieldDef& f, const uint8_t* buf, size_t len, FieldMap& out) const;
    size_t parse_bitfield(const FieldDef& f, const uint8_t* buf, size_t len, FieldMap& out) const;
    size_t parse_length_prefixed(const FieldDef& f, const uint8_t* buf, size_t len,
                                  FieldMap& out, const uint8_t* pkt_base, size_t pkt_len) const;
    size_t parse_computed(const FieldDef& f, FieldMap& out) const;
    size_t parse_tlv(const FieldDef& f, const uint8_t* buf, size_t len,
                     FieldMap& out, const uint8_t* pkt_base, size_t pkt_len) const;
    size_t parse_counted_list(const FieldDef& f, const uint8_t* buf, size_t len,
                              FieldMap& out, const uint8_t* pkt_base, size_t pkt_len) const;
    size_t parse_rest(const FieldDef& f, const uint8_t* buf, size_t len, FieldMap& out) const;
    size_t parse_hardcoded(const FieldDef& f, const uint8_t* buf, size_t len,
                           FieldMap& out, const uint8_t* pkt_base, size_t pkt_len) const;
    size_t parse_prefixed_list(const FieldDef& f, const uint8_t* buf, size_t len,
                               FieldMap& out, const uint8_t* pkt_base, size_t pkt_len) const;
    size_t parse_repeat(const FieldDef& f, const uint8_t* buf, size_t len,
                        FieldMap& out, const uint8_t* pkt_base, size_t pkt_len) const;

    // Fill struct fields from FieldMap for a given protocol layer
    void fill_ethernet(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_ipv4(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_ipv6(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_tcp(NativeParsedPacket& pkt, const FieldMap& fm, int64_t app_len) const;
    void fill_udp(NativeParsedPacket& pkt, const FieldMap& fm, int64_t app_len) const;
    void fill_dns(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_tls(NativeParsedPacket& pkt, const std::map<std::string, FieldMap>& layers) const;
    void fill_arp(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_icmp(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_icmpv6(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_vlan(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_sll(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_sll2(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_gre(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_vxlan(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_mpls(NativeParsedPacket& pkt, const FieldMap& fm) const;
    void fill_quic(NativeParsedPacket& pkt, const FieldMap& fm) const;

    // Fast-path: parse directly from buf into struct, bypassing FieldMap entirely.
    // Returns {bytes_consumed, next_protocol}. Returns {0, ""} if buf too short.
    struct FastResult {
        size_t bytes_consumed = 0;
        std::string next_protocol;
        bool bounds_remaining = false;  // true if ip_len should bound remaining
    };
    FastResult fast_parse_ethernet(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_ipv4(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_ipv6(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_tcp(const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt) const;
    FastResult fast_parse_udp(const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt) const;
    FastResult fast_parse_arp(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_icmp(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_icmpv6(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_vlan(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_sll(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_sll2(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_gre(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_vxlan(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_mpls(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_dhcp(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_dhcpv6(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_quic(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;

    // Merge a single TLS parse result into pkt.tls (first-wins for most fields, accumulate handshake_types)
    void merge_tls(NativeParsedPacket& pkt, const NativeTLSInfo& src) const;

    // Evaluate heuristic rules against payload bytes
    std::string evaluate_heuristics(
        const std::vector<HeuristicRule>& rules,
        const uint8_t* payload, size_t payload_len) const;

    // YAML fallback: look up next_protocol mapping from YAML definition
    std::string yaml_next_protocol_lookup(const std::string& proto_name, int value) const;

    const YamlLoader& loader_;

    // ── Dispatch tables (populated in constructor) ──

    // Fast-path: protocol name → parser function
    // Unified signature: all receive (buf, len, remaining, pkt). Protocols that
    // don't need remaining simply ignore it.
    using FastParseFn = std::function<FastResult(const uint8_t*, size_t, size_t, NativeParsedPacket&)>;
    std::unordered_map<std::string, FastParseFn> fast_dispatch_;

    // Slow-path fill: protocol name → fill function
    // Context struct passed to fill functions for protocols that need extra state
    struct SlowFillContext {
        NativeParsedPacket& pkt;
        FieldMap& fields;
        const uint8_t* cur;       // current position in packet buffer
        size_t bytes_consumed;    // bytes consumed by parse_layer
        size_t remaining;         // remaining bytes after current layer
        bool& has_tls;
        std::map<std::string, FieldMap>& tls_layers;
        const std::string& proto_name;
    };
    using SlowFillFn = std::function<void(SlowFillContext&)>;
    std::unordered_map<std::string, SlowFillFn> fill_dispatch_;
};

// Top-level parser exposed to Python via pybind11
class NativeParser {
public:
    explicit NativeParser(const std::string& protocols_dir);

    // Parse a raw packet buffer into a Python dict
    py::dict parse_packet(py::bytes buf, uint32_t link_type, bool save_raw_bytes = false);

    // Parse a raw packet buffer into a C++ struct (fast path)
    // app_layer_mode: 0=full, 1=fast, 2=port_only, 3=none
    NativeParsedPacket parse_packet_struct(py::bytes buf, uint32_t link_type,
                                            bool save_raw_bytes = false,
                                            int app_layer_mode = 0);

    // Parse a TLS record buffer starting from tls_record protocol, return struct with TLS filled.
    NativeParsedPacket parse_tls_record(py::bytes buf);

    // Load an additional YAML protocol file at runtime
    void load_extra_file(const std::string& file_path);

    // Inject a next_protocol mapping into an existing protocol's routing table
    void add_protocol_routing(const std::string& parent_proto, int value, const std::string& target_proto);

    // Access the underlying engine (for NativePipeline zero-copy path)
    const ProtocolEngine& engine() const { return engine_; }

private:
    YamlLoader loader_;
    ProtocolEngine engine_;
};

// Convert FieldMap to Python dict (recursive)
py::dict fieldmap_to_pydict(const FieldMap& fm);
