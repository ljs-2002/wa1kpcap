#pragma once

#include "field_value.h"
#include "yaml_loader.h"
#include "parsed_packet.h"
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <vector>
#include <map>
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
    NativeParsedPacket parse_packet_struct(const uint8_t* buf, size_t len,
                                           uint32_t link_type,
                                           bool save_raw_bytes = false) const;

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

    // Fast-path: parse directly from buf into struct, bypassing FieldMap entirely.
    // Returns {bytes_consumed, next_protocol}. Returns {0, ""} if buf too short.
    struct FastResult {
        size_t bytes_consumed = 0;
        std::string next_protocol;
    };
    FastResult fast_parse_ethernet(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_ipv4(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_ipv6(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_tcp(const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt) const;
    FastResult fast_parse_udp(const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt) const;
    FastResult fast_parse_arp(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_icmp(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;
    FastResult fast_parse_icmpv6(const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const;

    // Merge a single TLS parse result into pkt.tls (first-wins for most fields, accumulate handshake_types)
    void merge_tls(NativeParsedPacket& pkt, const NativeTLSInfo& src) const;

    // Evaluate heuristic rules against payload bytes
    std::string evaluate_heuristics(
        const std::vector<HeuristicRule>& rules,
        const uint8_t* payload, size_t payload_len) const;

    const YamlLoader& loader_;
};

// Top-level parser exposed to Python via pybind11
class NativeParser {
public:
    explicit NativeParser(const std::string& protocols_dir);

    // Parse a raw packet buffer into a Python dict
    py::dict parse_packet(py::bytes buf, uint32_t link_type, bool save_raw_bytes = false);

    // Parse a raw packet buffer into a C++ struct (fast path)
    NativeParsedPacket parse_packet_struct(py::bytes buf, uint32_t link_type,
                                            bool save_raw_bytes = false);

    // Parse a TLS record buffer starting from tls_record protocol, return struct with TLS filled.
    NativeParsedPacket parse_tls_record(py::bytes buf);

    // Access the underlying engine (for NativePipeline zero-copy path)
    const ProtocolEngine& engine() const { return engine_; }

private:
    YamlLoader loader_;
    ProtocolEngine engine_;
};

// Convert FieldMap to Python dict (recursive)
py::dict fieldmap_to_pydict(const FieldMap& fm);
