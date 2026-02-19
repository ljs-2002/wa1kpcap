#pragma once

#include "field_value.h"
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <string>
#include <memory>
#include <vector>
#include <set>
#include <cstdint>
#include <cstring>

namespace py = pybind11;

// ── Raw packet fields extracted from bytes for pre-parse filtering ──

struct RawPacketFields {
    uint8_t ip_version = 0;     // 4 or 6, 0 if no IP
    uint8_t ip_proto = 0;       // IP protocol number
    uint8_t src_ip[16] = {};    // IPv4 in first 4 bytes, IPv6 all 16
    uint8_t dst_ip[16] = {};
    uint8_t ip_len = 0;         // 4 for IPv4, 16 for IPv6
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    bool has_ip = false;
    bool has_transport = false;
    bool is_arp = false;
};

// ── Condition tree nodes ──

struct FilterNode {
    virtual ~FilterNode() = default;
    virtual bool matches(const py::dict& parsed) const = 0;
    // Raw byte matching — returns true if matches, false if not.
    // can_match_raw() returns false if this node requires full parse (app-layer filters).
    virtual bool matches_raw(const RawPacketFields& raw) const = 0;
    virtual bool can_match_raw() const = 0;
};

struct ProtocolFilterNode : FilterNode {
    std::set<int> protocols;  // IP protocol numbers (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)
    bool is_ip = false;
    bool is_ipv6 = false;
    bool is_arp = false;
    bool negate = false;
    bool matches(const py::dict& parsed) const override;
    bool matches_raw(const RawPacketFields& raw) const override;
    bool can_match_raw() const override { return true; }
};

struct IPFilterNode : FilterNode {
    std::set<std::string> src_ips;
    std::set<std::string> dst_ips;
    std::set<std::string> any_ips;
    bool negate = false;
    // Pre-parsed IP bytes for raw matching
    struct IPBytes { uint8_t bytes[16]; uint8_t len; };
    std::vector<IPBytes> src_ip_bytes;
    std::vector<IPBytes> dst_ip_bytes;
    std::vector<IPBytes> any_ip_bytes;
    void precompute_ip_bytes();
    bool matches(const py::dict& parsed) const override;
    bool matches_raw(const RawPacketFields& raw) const override;
    bool can_match_raw() const override { return true; }
};

struct PortFilterNode : FilterNode {
    std::set<int> src_ports;
    std::set<int> dst_ports;
    std::set<int> any_ports;
    bool negate = false;
    bool matches(const py::dict& parsed) const override;
    bool matches_raw(const RawPacketFields& raw) const override;
    bool can_match_raw() const override { return true; }
};

struct AppProtocolFilterNode : FilterNode {
    std::set<std::string> protocols; // "tls", "http", "dns", "dhcp", "dhcpv6", etc.
    bool negate = false;
    bool matches(const py::dict& parsed) const override;
    bool matches_raw(const RawPacketFields& raw) const override;
    bool can_match_raw() const override;
};

struct CompoundFilterNode : FilterNode {
    std::vector<std::unique_ptr<FilterNode>> children;
    bool is_and = true; // true=AND, false=OR
    bool negate = false;
    bool matches(const py::dict& parsed) const override;
    bool matches_raw(const RawPacketFields& raw) const override;
    bool can_match_raw() const override;
};

// ── BPF Filter compiler + matcher ──

class NativeFilter {
public:
    explicit NativeFilter(const std::string& filter_str);

    // Match against a parsed packet dict (output of NativeParser.parse_packet)
    bool matches(const py::dict& parsed_dict) const;

    // Match against raw packet bytes (fast pre-parse path).
    // Returns true if packet matches or filter requires full parse (app-layer).
    bool matches_raw(const uint8_t* buf, size_t len, uint32_t link_type) const;

    // Whether this filter can be fully evaluated on raw bytes
    bool can_match_raw() const;

    // Extract raw packet fields from bytes for matching
    static RawPacketFields extract_raw_fields(const uint8_t* buf, size_t len, uint32_t link_type);

    // Tokenizer types (public for use in implementation file)
    enum class TokenType {
        LPAREN, RPAREN, AND, OR, NOT,
        TCP, UDP, ICMP, ICMPV6, ARP, IP, IPV6,
        HOST, SRC, DST, PORT,
        TLS, HTTP, DNS, DHCP, DHCPV6, VLAN, GRE, VXLAN, MPLS,
        IPV4_ADDR, NUMBER, END
    };
    struct Token {
        TokenType type;
        std::string value;
    };

private:
    std::unique_ptr<FilterNode> root_;
    bool can_match_raw_ = true;  // cached at construction time

    std::vector<Token> tokenize(const std::string& s);

    // Recursive descent parser
    size_t pos_ = 0;
    std::vector<Token> tokens_;

    const Token& peek() const;
    Token consume();
    bool match(TokenType t);

    std::unique_ptr<FilterNode> parse_or();
    std::unique_ptr<FilterNode> parse_and();
    std::unique_ptr<FilterNode> parse_not();
    std::unique_ptr<FilterNode> parse_primary();
    std::unique_ptr<FilterNode> parse_atom();
};
