#pragma once

#include "field_value.h"
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <memory>

// Forward declarations
struct ProtocolDefinition;
class CompiledExpression;

// ── Field primitive types ──
enum class PrimitiveType {
    FIXED,            // fixed-size integer/bytes
    BITFIELD,         // bit-level fields within a byte group
    LENGTH_PREFIXED,  // length-prefixed data (e.g., TLS extensions)
    COMPUTED,         // computed from other fields via expression
    TLV,              // type-length-value
    COUNTED_LIST,     // repeated structure with count from another field
    REST,             // consume remaining bytes
    HARDCODED,        // special parser (dns_name, bsd_loopback_af, etc.)
    PREFIXED_LIST,    // length-prefixed list of length-prefixed items (e.g., ALPN)
    REPEAT,           // repeat a sub-protocol chain until buffer exhausted
};

// ── Field definition ──
struct FieldDef {
    std::string name;
    PrimitiveType type = PrimitiveType::FIXED;

    // FIXED
    int size = 0;           // bytes
    std::string endian = "big";
    std::string format;     // "uint", "int", "ipv4", "ipv6", "mac", "bytes", "hex"

    // BITFIELD
    struct BitFieldEntry {
        std::string name;
        int bits = 0;
    };
    int group_size = 0;     // total bytes for bitfield group
    std::vector<BitFieldEntry> bit_fields;

    // LENGTH_PREFIXED
    int length_size = 0;    // bytes for the length prefix
    std::string sub_protocol; // protocol to parse the content

    // COMPUTED
    std::string expression; // e.g., "total_length - header_length"
    std::shared_ptr<CompiledExpression> compiled_expr; // precompiled AST

    // TLV
    int type_size = 0;
    int tlv_length_size = 0;
    std::map<int, std::string> type_mapping; // type_value -> sub_protocol

    // COUNTED_LIST
    std::string count_field;    // field name that holds the count
    std::string item_protocol;  // protocol for each item

    // REST
    // (no extra fields — just consumes remaining bytes)

    // HARDCODED
    std::string parser_name; // "dns_name", "bsd_loopback_af", "nflog_payload"

    // PREFIXED_LIST
    int list_length_size = 0;    // bytes for the outer list length prefix
    int item_length_size = 0;    // bytes for each item's length prefix
    std::string item_format;     // "string" or "bytes" (default: "string")

    // REPEAT
    std::string merge_mode;      // "tls" for TLS-specific merge logic
};

// ── Heuristic condition for payload-based protocol detection ──
struct HeuristicCondition {
    enum class Type { BYTE_IN, BYTE_EQ, BYTE_LE, PREFIX_IN };
    Type type;
    size_t offset = 0;
    uint8_t byte_eq_value = 0;
    uint8_t byte_le_value = 0;
    std::vector<uint8_t> byte_in_set;
    std::vector<std::string> prefix_in;
};

struct HeuristicRule {
    std::string protocol;
    size_t min_length = 0;
    std::vector<HeuristicCondition> conditions;
};

// ── Next protocol mapping ──
struct NextProtocol {
    std::vector<std::string> fields;  // field names to check in order
    std::map<int, std::string> mapping; // field_value -> protocol_name
    std::string default_protocol;
    std::vector<HeuristicRule> heuristics; // payload-based protocol detection
};

// ── Protocol definition ──
struct ProtocolDefinition {
    std::string name;
    std::vector<FieldDef> fields;
    std::optional<NextProtocol> next_protocol;
    std::string header_size_field;  // computed field whose value is the true header size
    std::string total_length_field; // field whose value is the total layer size (header + payload)
};

// ── Link type mapping ──
struct LinkTypeConfig {
    std::map<int, std::string> dlt_to_protocol; // DLT value -> protocol name
};

// ── YAML Loader ──
class YamlLoader {
public:
    // Load all .yaml files from a directory
    void load_directory(const std::string& dir_path);

    // Load a single YAML file
    void load_file(const std::string& file_path);

    // Access loaded definitions
    const std::map<std::string, ProtocolDefinition>& protocols() const { return protocols_; }
    const LinkTypeConfig& link_types() const { return link_types_; }

    const ProtocolDefinition* get_protocol(const std::string& name) const;

private:
    std::map<std::string, ProtocolDefinition> protocols_;
    LinkTypeConfig link_types_;
};
