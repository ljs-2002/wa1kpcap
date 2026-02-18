#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>
#include <unordered_map>

// FieldValue: the variant type returned by protocol parsing primitives.
// Each parsed field is one of these types.
// NOTE: No recursive map type here — MSVC cannot handle recursive std::variant.
// Nested dicts (sub-protocol layers) are handled at the parse_packet level
// by building py::dict directly.
using FieldValue = std::variant<
    std::monostate,                          // null / not present
    int64_t,                                 // integers (signed for computed expressions)
    uint64_t,                                // unsigned integers
    double,                                  // floating point
    std::string,                             // strings (IP addresses, MAC, domain names)
    std::vector<uint8_t>,                    // raw bytes
    std::vector<int64_t>,                    // integer lists (cipher suites, etc.)
    std::vector<std::string>                 // string lists (SNI list, ALPN, etc.)
>;

// Convenience aliases
using FieldMap = std::unordered_map<std::string, FieldValue>;
using ByteVec = std::vector<uint8_t>;

// Helper to get int value from FieldValue (returns 0 if not int type)
inline int64_t field_to_int(const FieldValue& v) {
    if (auto* p = std::get_if<int64_t>(&v)) return *p;
    if (auto* p = std::get_if<uint64_t>(&v)) return static_cast<int64_t>(*p);
    if (auto* p = std::get_if<double>(&v)) return static_cast<int64_t>(*p);
    return 0;
}

inline uint64_t field_to_uint(const FieldValue& v) {
    if (auto* p = std::get_if<uint64_t>(&v)) return *p;
    if (auto* p = std::get_if<int64_t>(&v)) return static_cast<uint64_t>(*p);
    if (auto* p = std::get_if<double>(&v)) return static_cast<uint64_t>(*p);
    return 0;
}

inline std::string field_to_string(const FieldValue& v) {
    if (auto* p = std::get_if<std::string>(&v)) return *p;
    if (auto* p = std::get_if<int64_t>(&v)) return std::to_string(*p);
    if (auto* p = std::get_if<uint64_t>(&v)) return std::to_string(*p);
    return "";
}
