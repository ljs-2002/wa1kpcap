#include "bpf_filter.h"
#include "hardcoded_parsers.h"
#include "util.h"

#include <regex>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <sstream>

// ── Helper: extract string field from nested parsed dict ──

static std::string get_nested_str(const py::dict& d, const char* layer, const char* field) {
    if (!d.contains(layer)) return "";
    auto sub = d[layer];
    if (!py::isinstance<py::dict>(sub)) return "";
    auto sd = sub.cast<py::dict>();
    if (!sd.contains(field)) return "";
    try { return sd[field].cast<std::string>(); } catch (...) { return ""; }
}

static int64_t get_nested_int(const py::dict& d, const char* layer, const char* field, int64_t def = -1) {
    if (!d.contains(layer)) return def;
    auto sub = d[layer];
    if (!py::isinstance<py::dict>(sub)) return def;
    auto sd = sub.cast<py::dict>();
    if (!sd.contains(field)) return def;
    try { return sd[field].cast<int64_t>(); } catch (...) { return def; }
}

// ── FilterNode implementations ──

bool ProtocolFilterNode::matches(const py::dict& parsed) const {
    bool result = false;

    if (is_ip) {
        result = parsed.contains("ipv4");
    } else if (is_ipv6) {
        result = parsed.contains("ipv6");
    } else if (is_arp) {
        result = parsed.contains("arp");
    } else if (!protocols.empty()) {
        // Check IP protocol number
        int64_t proto = get_nested_int(parsed, "ipv4", "protocol", -1);
        if (proto < 0) proto = get_nested_int(parsed, "ipv6", "next_header", -1);
        if (proto >= 0) {
            result = protocols.count(static_cast<int>(proto)) > 0;
        }
    }

    return result != negate;
}

bool IPFilterNode::matches(const py::dict& parsed) const {
    std::string src = get_nested_str(parsed, "ipv4", "src");
    std::string dst = get_nested_str(parsed, "ipv4", "dst");
    if (src.empty()) src = get_nested_str(parsed, "ipv6", "src");
    if (dst.empty()) dst = get_nested_str(parsed, "ipv6", "dst");

    bool result = false;
    if (!any_ips.empty()) {
        result = any_ips.count(src) > 0 || any_ips.count(dst) > 0;
    }
    if (!src_ips.empty()) {
        result = result || src_ips.count(src) > 0;
    }
    if (!dst_ips.empty()) {
        result = result || dst_ips.count(dst) > 0;
    }

    return result != negate;
}

bool PortFilterNode::matches(const py::dict& parsed) const {
    int64_t sp = get_nested_int(parsed, "tcp", "src_port", -1);
    int64_t dp = get_nested_int(parsed, "tcp", "dst_port", -1);
    if (sp < 0) sp = get_nested_int(parsed, "udp", "src_port", -1);
    if (dp < 0) dp = get_nested_int(parsed, "udp", "dst_port", -1);

    bool result = false;
    if (!any_ports.empty()) {
        result = (sp >= 0 && any_ports.count(static_cast<int>(sp))) ||
                 (dp >= 0 && any_ports.count(static_cast<int>(dp)));
    }
    if (!src_ports.empty()) {
        result = result || (sp >= 0 && src_ports.count(static_cast<int>(sp)));
    }
    if (!dst_ports.empty()) {
        result = result || (dp >= 0 && dst_ports.count(static_cast<int>(dp)));
    }

    return result != negate;
}

bool AppProtocolFilterNode::matches(const py::dict& parsed) const {
    bool result = false;
    if (protocols.count("tls")) result = result || parsed.contains("tls_record");
    if (protocols.count("http")) result = result || parsed.contains("http");
    if (protocols.count("dns")) result = result || parsed.contains("dns");
    if (protocols.count("dhcp")) result = result || parsed.contains("dhcp");
    if (protocols.count("dhcpv6")) result = result || parsed.contains("dhcpv6");
    if (protocols.count("vlan")) result = result || parsed.contains("vlan");
    if (protocols.count("gre")) result = result || parsed.contains("gre");
    if (protocols.count("vxlan")) result = result || parsed.contains("vxlan");
    if (protocols.count("mpls")) result = result || parsed.contains("mpls");
    return result != negate;
}

bool CompoundFilterNode::matches(const py::dict& parsed) const {
    bool result;
    if (is_and) {
        result = true;
        for (auto& c : children) {
            if (!c->matches(parsed)) { result = false; break; }
        }
    } else {
        result = false;
        for (auto& c : children) {
            if (c->matches(parsed)) { result = true; break; }
        }
    }
    return result != negate;
}

// ── Tokenizer ──

static const NativeFilter::Token END_TOKEN{NativeFilter::TokenType::END, ""};

std::vector<NativeFilter::Token> NativeFilter::tokenize(const std::string& s) {
    std::vector<Token> tokens;
    size_t i = 0;
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    while (i < lower.size()) {
        // Skip whitespace
        if (std::isspace(lower[i])) { i++; continue; }

        // Parentheses
        if (lower[i] == '(') { tokens.push_back({TokenType::LPAREN, "("}); i++; continue; }
        if (lower[i] == ')') { tokens.push_back({TokenType::RPAREN, ")"}); i++; continue; }

        // Keywords and identifiers
        if (std::isalpha(lower[i])) {
            size_t start = i;
            while (i < lower.size() && (std::isalnum(lower[i]) || lower[i] == '_')) i++;
            std::string word = lower.substr(start, i - start);

            if (word == "and") tokens.push_back({TokenType::AND, word});
            else if (word == "or") tokens.push_back({TokenType::OR, word});
            else if (word == "not") tokens.push_back({TokenType::NOT, word});
            else if (word == "tcp") tokens.push_back({TokenType::TCP, word});
            else if (word == "udp") tokens.push_back({TokenType::UDP, word});
            else if (word == "icmpv6") tokens.push_back({TokenType::ICMPV6, word});
            else if (word == "icmp") tokens.push_back({TokenType::ICMP, word});
            else if (word == "arp") tokens.push_back({TokenType::ARP, word});
            else if (word == "ipv6") tokens.push_back({TokenType::IPV6, word});
            else if (word == "ip") tokens.push_back({TokenType::IP, word});
            else if (word == "host") tokens.push_back({TokenType::HOST, word});
            else if (word == "src") tokens.push_back({TokenType::SRC, word});
            else if (word == "dst") tokens.push_back({TokenType::DST, word});
            else if (word == "port") tokens.push_back({TokenType::PORT, word});
            else if (word == "tls") tokens.push_back({TokenType::TLS, word});
            else if (word == "http") tokens.push_back({TokenType::HTTP, word});
            else if (word == "dns") tokens.push_back({TokenType::DNS, word});
            else if (word == "dhcpv6") tokens.push_back({TokenType::DHCPV6, word});
            else if (word == "dhcp") tokens.push_back({TokenType::DHCP, word});
            else if (word == "vxlan") tokens.push_back({TokenType::VXLAN, word});
            else if (word == "vlan") tokens.push_back({TokenType::VLAN, word});
            else if (word == "gre") tokens.push_back({TokenType::GRE, word});
            else if (word == "mpls") tokens.push_back({TokenType::MPLS, word});
            else throw std::runtime_error("Unknown keyword: " + word);
            continue;
        }

        // Numbers and IP addresses
        if (std::isdigit(lower[i])) {
            size_t start = i;
            bool has_dot = false;
            int dot_count = 0;
            while (i < lower.size() && (std::isdigit(lower[i]) || lower[i] == '.')) {
                if (lower[i] == '.') { has_dot = true; dot_count++; }
                i++;
            }
            std::string num = lower.substr(start, i - start);
            if (dot_count == 3) {
                tokens.push_back({TokenType::IPV4_ADDR, num});
            } else {
                tokens.push_back({TokenType::NUMBER, num});
            }
            continue;
        }

        throw std::runtime_error(std::string("Unexpected character in filter: ") + lower[i]);
    }

    return tokens;
}

// ── Parser ──

const NativeFilter::Token& NativeFilter::peek() const {
    if (pos_ >= tokens_.size()) return END_TOKEN;
    return tokens_[pos_];
}

NativeFilter::Token NativeFilter::consume() {
    if (pos_ >= tokens_.size()) return END_TOKEN;
    return tokens_[pos_++];
}

bool NativeFilter::match(TokenType t) {
    if (peek().type == t) { consume(); return true; }
    return false;
}

NativeFilter::NativeFilter(const std::string& filter_str) {
    if (filter_str.empty()) {
        root_ = nullptr;
        can_match_raw_ = true;
        return;
    }

    tokens_ = tokenize(filter_str);
    pos_ = 0;

    if (tokens_.empty()) {
        root_ = nullptr;
        can_match_raw_ = true;
        return;
    }

    root_ = parse_or();

    if (pos_ < tokens_.size()) {
        throw std::runtime_error("Unexpected token at position " + std::to_string(pos_));
    }

    can_match_raw_ = root_ ? root_->can_match_raw() : true;
}

bool NativeFilter::matches(const py::dict& parsed_dict) const {
    if (!root_) return true; // no filter = pass all
    return root_->matches(parsed_dict);
}

std::unique_ptr<FilterNode> NativeFilter::parse_or() {
    auto left = parse_and();
    while (peek().type == TokenType::OR) {
        consume();
        auto right = parse_and();
        auto compound = std::make_unique<CompoundFilterNode>();
        compound->is_and = false;
        compound->children.push_back(std::move(left));
        compound->children.push_back(std::move(right));
        left = std::move(compound);
    }
    return left;
}

std::unique_ptr<FilterNode> NativeFilter::parse_and() {
    auto left = parse_not();
    while (peek().type == TokenType::AND) {
        consume();
        auto right = parse_not();
        auto compound = std::make_unique<CompoundFilterNode>();
        compound->is_and = true;
        compound->children.push_back(std::move(left));
        compound->children.push_back(std::move(right));
        left = std::move(compound);
    }
    return left;
}

std::unique_ptr<FilterNode> NativeFilter::parse_not() {
    if (peek().type == TokenType::NOT) {
        consume();
        auto child = parse_not();
        // Toggle negate on the child
        if (auto* p = dynamic_cast<ProtocolFilterNode*>(child.get())) p->negate = !p->negate;
        else if (auto* p = dynamic_cast<IPFilterNode*>(child.get())) p->negate = !p->negate;
        else if (auto* p = dynamic_cast<PortFilterNode*>(child.get())) p->negate = !p->negate;
        else if (auto* p = dynamic_cast<AppProtocolFilterNode*>(child.get())) p->negate = !p->negate;
        else if (auto* p = dynamic_cast<CompoundFilterNode*>(child.get())) p->negate = !p->negate;
        return child;
    }
    return parse_primary();
}

std::unique_ptr<FilterNode> NativeFilter::parse_primary() {
    if (peek().type == TokenType::LPAREN) {
        consume();
        auto node = parse_or();
        if (peek().type != TokenType::RPAREN) {
            throw std::runtime_error("Expected closing parenthesis");
        }
        consume();
        return node;
    }
    return parse_atom();
}

std::unique_ptr<FilterNode> NativeFilter::parse_atom() {
    auto tok = peek();

    switch (tok.type) {
    case TokenType::TCP: {
        consume();
        auto n = std::make_unique<ProtocolFilterNode>();
        n->protocols.insert(6);
        return n;
    }
    case TokenType::UDP: {
        consume();
        auto n = std::make_unique<ProtocolFilterNode>();
        n->protocols.insert(17);
        return n;
    }
    case TokenType::ICMP: {
        consume();
        auto n = std::make_unique<ProtocolFilterNode>();
        n->protocols.insert(1);
        return n;
    }
    case TokenType::ICMPV6: {
        consume();
        auto n = std::make_unique<ProtocolFilterNode>();
        n->protocols.insert(58);
        return n;
    }
    case TokenType::ARP: {
        consume();
        auto n = std::make_unique<ProtocolFilterNode>();
        n->is_arp = true;
        return n;
    }
    case TokenType::IP: {
        consume();
        auto n = std::make_unique<ProtocolFilterNode>();
        n->is_ip = true;
        return n;
    }
    case TokenType::IPV6: {
        consume();
        auto n = std::make_unique<ProtocolFilterNode>();
        n->is_ipv6 = true;
        return n;
    }
    case TokenType::TLS: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("tls");
        return n;
    }
    case TokenType::HTTP: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("http");
        return n;
    }
    case TokenType::DNS: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("dns");
        return n;
    }
    case TokenType::DHCP: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("dhcp");
        return n;
    }
    case TokenType::DHCPV6: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("dhcpv6");
        return n;
    }
    case TokenType::VLAN: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("vlan");
        return n;
    }
    case TokenType::GRE: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("gre");
        return n;
    }
    case TokenType::VXLAN: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("vxlan");
        return n;
    }
    case TokenType::MPLS: {
        consume();
        auto n = std::make_unique<AppProtocolFilterNode>();
        n->protocols.insert("mpls");
        return n;
    }
    case TokenType::HOST: {
        consume();
        if (peek().type != TokenType::IPV4_ADDR) {
            throw std::runtime_error("Expected IP address after 'host'");
        }
        auto addr = consume().value;
        auto n = std::make_unique<IPFilterNode>();
        n->any_ips.insert(addr);
        n->precompute_ip_bytes();
        return n;
    }
    case TokenType::SRC: {
        consume();
        if (peek().type == TokenType::PORT) {
            consume();
            if (peek().type != TokenType::NUMBER) {
                throw std::runtime_error("Expected port number after 'src port'");
            }
            int port = std::stoi(consume().value);
            auto n = std::make_unique<PortFilterNode>();
            n->src_ports.insert(port);
            return n;
        }
        if (peek().type == TokenType::IPV4_ADDR) {
            auto addr = consume().value;
            auto n = std::make_unique<IPFilterNode>();
            n->src_ips.insert(addr);
            n->precompute_ip_bytes();
            return n;
        }
        throw std::runtime_error("Expected IP address or 'port' after 'src'");
    }
    case TokenType::DST: {
        consume();
        if (peek().type == TokenType::PORT) {
            consume();
            if (peek().type != TokenType::NUMBER) {
                throw std::runtime_error("Expected port number after 'dst port'");
            }
            int port = std::stoi(consume().value);
            auto n = std::make_unique<PortFilterNode>();
            n->dst_ports.insert(port);
            return n;
        }
        if (peek().type == TokenType::IPV4_ADDR) {
            auto addr = consume().value;
            auto n = std::make_unique<IPFilterNode>();
            n->dst_ips.insert(addr);
            n->precompute_ip_bytes();
            return n;
        }
        throw std::runtime_error("Expected IP address or 'port' after 'dst'");
    }
    case TokenType::IPV4_ADDR: {
        auto addr = consume().value;
        auto n = std::make_unique<IPFilterNode>();
        n->any_ips.insert(addr);
        n->precompute_ip_bytes();
        return n;
    }
    case TokenType::PORT: {
        consume();
        if (peek().type != TokenType::NUMBER) {
            throw std::runtime_error("Expected port number after 'port'");
        }
        int port = std::stoi(consume().value);
        auto n = std::make_unique<PortFilterNode>();
        n->any_ports.insert(port);
        return n;
    }
    default:
        throw std::runtime_error("Unexpected token: " + tok.value);
    }
}

// ── Raw byte matching implementations ──

// Helper: parse IPv4 address string to 4 bytes
static bool parse_ipv4_to_bytes(const std::string& addr, uint8_t out[4]) {
    unsigned a, b, c, d;
    if (sscanf(addr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    out[0] = static_cast<uint8_t>(a);
    out[1] = static_cast<uint8_t>(b);
    out[2] = static_cast<uint8_t>(c);
    out[3] = static_cast<uint8_t>(d);
    return true;
}

void IPFilterNode::precompute_ip_bytes() {
    auto convert = [](const std::set<std::string>& ips, std::vector<IPBytes>& out) {
        for (auto& ip : ips) {
            IPBytes ib;
            std::memset(&ib, 0, sizeof(ib));
            if (parse_ipv4_to_bytes(ip, ib.bytes)) {
                ib.len = 4;
                out.push_back(ib);
            }
            // TODO: IPv6 address parsing if needed
        }
    };
    convert(src_ips, src_ip_bytes);
    convert(dst_ips, dst_ip_bytes);
    convert(any_ips, any_ip_bytes);
}

RawPacketFields NativeFilter::extract_raw_fields(const uint8_t* buf, size_t len, uint32_t link_type) {
    RawPacketFields raw;
    if (len == 0) return raw;

    const uint8_t* ip_start = nullptr;
    size_t ip_avail = 0;
    uint16_t ether_type = 0;

    // Determine IP layer start based on link type
    switch (link_type) {
    case 1: { // Ethernet (DLT_EN10MB)
        if (len < 14) return raw;
        ether_type = util::read_u16_be(buf + 12);
        size_t offset = 14;
        // Handle VLAN tags (0x8100)
        while (ether_type == 0x8100 && offset + 4 <= len) {
            ether_type = util::read_u16_be(buf + offset + 2);
            offset += 4;
        }
        if (ether_type == 0x0806) { raw.is_arp = true; return raw; }
        if (ether_type != 0x0800 && ether_type != 0x86DD) return raw;
        ip_start = buf + offset;
        ip_avail = len - offset;
        break;
    }
    case 113: { // Linux SLL (DLT_LINUX_SLL)
        if (len < 16) return raw;
        ether_type = util::read_u16_be(buf + 14);
        if (ether_type == 0x0806) { raw.is_arp = true; return raw; }
        if (ether_type != 0x0800 && ether_type != 0x86DD) return raw;
        ip_start = buf + 16;
        ip_avail = len - 16;
        break;
    }
    case 101: { // Raw IP (DLT_RAW)
        ip_start = buf;
        ip_avail = len;
        // Determine version from first nibble
        uint8_t ver = (buf[0] >> 4) & 0xF;
        if (ver == 4) ether_type = 0x0800;
        else if (ver == 6) ether_type = 0x86DD;
        else return raw;
        break;
    }
    case 0:   // BSD Loopback (DLT_NULL)
    case 108: { // BSD Loopback (DLT_LOOP)
        if (len < 4) return raw;
        // AF is in host byte order
        uint32_t af = util::read_u32_le(buf);
        if (af == 2) ether_type = 0x0800;       // AF_INET
        else if (af == 24 || af == 28 || af == 30) ether_type = 0x86DD; // AF_INET6 varies by OS
        else return raw;
        ip_start = buf + 4;
        ip_avail = len - 4;
        break;
    }
    case 239: { // NFLOG (DLT_NFLOG)
        auto result = hardcoded::parse_nflog_payload(buf, len);
        if (!result.found) return raw;
        ip_start = buf + result.offset;
        ip_avail = result.length;
        uint8_t ver = (ip_start[0] >> 4) & 0xF;
        if (ver == 4) ether_type = 0x0800;
        else if (ver == 6) ether_type = 0x86DD;
        else return raw;
        break;
    }
    default:
        return raw;
    }

    if (!ip_start || ip_avail == 0) return raw;

    // Parse IP header
    if (ether_type == 0x0800) {
        // IPv4
        if (ip_avail < 20) return raw;
        raw.ip_version = 4;
        raw.has_ip = true;
        raw.ip_len = 4;
        raw.ip_proto = ip_start[9];
        std::memcpy(raw.src_ip, ip_start + 12, 4);
        std::memcpy(raw.dst_ip, ip_start + 16, 4);

        // Transport layer
        uint8_t ihl = (ip_start[0] & 0x0F) * 4;
        if (ihl < 20) ihl = 20;
        if (ip_avail >= static_cast<size_t>(ihl) + 4 &&
            (raw.ip_proto == 6 || raw.ip_proto == 17)) {
            const uint8_t* trans = ip_start + ihl;
            raw.src_port = util::read_u16_be(trans);
            raw.dst_port = util::read_u16_be(trans + 2);
            raw.has_transport = true;
        }
    } else if (ether_type == 0x86DD) {
        // IPv6
        if (ip_avail < 40) return raw;
        raw.ip_version = 6;
        raw.has_ip = true;
        raw.ip_len = 16;
        raw.ip_proto = ip_start[6];
        std::memcpy(raw.src_ip, ip_start + 8, 16);
        std::memcpy(raw.dst_ip, ip_start + 24, 16);

        // Transport layer (skip extension headers not supported for now)
        if (ip_avail >= 44 && (raw.ip_proto == 6 || raw.ip_proto == 17)) {
            const uint8_t* trans = ip_start + 40;
            raw.src_port = util::read_u16_be(trans);
            raw.dst_port = util::read_u16_be(trans + 2);
            raw.has_transport = true;
        }
    }

    return raw;
}

bool NativeFilter::matches_raw(const uint8_t* buf, size_t len, uint32_t link_type) const {
    if (!root_) return true;
    if (!can_match_raw_) return true;  // can't filter on raw bytes, pass through
    auto raw = extract_raw_fields(buf, len, link_type);
    return root_->matches_raw(raw);
}

bool NativeFilter::can_match_raw() const {
    return can_match_raw_;
}

// ── FilterNode::matches_raw implementations ──

bool ProtocolFilterNode::matches_raw(const RawPacketFields& raw) const {
    bool result = false;
    if (is_ip) {
        result = raw.has_ip && raw.ip_version == 4;
    } else if (is_ipv6) {
        result = raw.has_ip && raw.ip_version == 6;
    } else if (is_arp) {
        result = raw.is_arp;
    } else if (!protocols.empty()) {
        if (raw.has_ip) {
            result = protocols.count(static_cast<int>(raw.ip_proto)) > 0;
        }
    }
    return result != negate;
}

bool IPFilterNode::matches_raw(const RawPacketFields& raw) const {
    if (!raw.has_ip) return negate;  // no IP = no match (unless negated)

    bool result = false;
    auto check = [&](const std::vector<IPBytes>& ip_bytes, const uint8_t* addr) {
        for (auto& ib : ip_bytes) {
            if (ib.len == raw.ip_len && std::memcmp(ib.bytes, addr, ib.len) == 0) {
                return true;
            }
        }
        return false;
    };

    if (!any_ip_bytes.empty()) {
        result = check(any_ip_bytes, raw.src_ip) || check(any_ip_bytes, raw.dst_ip);
    }
    if (!src_ip_bytes.empty()) {
        result = result || check(src_ip_bytes, raw.src_ip);
    }
    if (!dst_ip_bytes.empty()) {
        result = result || check(dst_ip_bytes, raw.dst_ip);
    }

    return result != negate;
}

bool PortFilterNode::matches_raw(const RawPacketFields& raw) const {
    if (!raw.has_transport) return negate;

    bool result = false;
    int sp = raw.src_port;
    int dp = raw.dst_port;

    if (!any_ports.empty()) {
        result = any_ports.count(sp) > 0 || any_ports.count(dp) > 0;
    }
    if (!src_ports.empty()) {
        result = result || src_ports.count(sp) > 0;
    }
    if (!dst_ports.empty()) {
        result = result || dst_ports.count(dp) > 0;
    }

    return result != negate;
}

bool AppProtocolFilterNode::matches_raw(const RawPacketFields& raw) const {
    // Port-matchable protocols can be checked on raw bytes
    bool result = false;

    if (protocols.count("dhcp")) {
        // DHCP = UDP (proto 17) port 67 or 68
        if (raw.has_ip && raw.ip_proto == 17 && raw.has_transport) {
            result = result || raw.src_port == 67 || raw.dst_port == 67
                            || raw.src_port == 68 || raw.dst_port == 68;
        }
    }
    if (protocols.count("dhcpv6")) {
        // DHCPv6 = UDP (proto 17) port 546 or 547
        if (raw.has_ip && raw.ip_proto == 17 && raw.has_transport) {
            result = result || raw.src_port == 546 || raw.dst_port == 546
                            || raw.src_port == 547 || raw.dst_port == 547;
        }
    }
    if (protocols.count("vlan")) {
        // VLAN: ethertype 0x8100 — check is_arp field repurpose won't work,
        // but we can't detect VLAN from RawPacketFields. Fall through.
    }
    if (protocols.count("gre")) {
        // GRE = IP proto 47
        if (raw.has_ip) {
            result = result || raw.ip_proto == 47;
        }
    }
    if (protocols.count("vxlan")) {
        // VXLAN = UDP (proto 17) port 4789
        if (raw.has_ip && raw.ip_proto == 17 && raw.has_transport) {
            result = result || raw.src_port == 4789 || raw.dst_port == 4789;
        }
    }
    if (protocols.count("mpls")) {
        // MPLS: ethertype 0x8847/0x8848 — can't detect from RawPacketFields
    }

    // For truly app-layer protocols (tls, http, dns), return true to pass through
    static const std::set<std::string> raw_matchable = {
        "dhcp", "dhcpv6", "gre", "vxlan"
    };
    for (auto& p : protocols) {
        if (!raw_matchable.count(p)) return true;  // can't filter, pass through
    }

    return result != negate;
}

bool AppProtocolFilterNode::can_match_raw() const {
    // Only raw-matchable if ALL protocols in the set can be checked on raw bytes
    static const std::set<std::string> raw_matchable = {
        "dhcp", "dhcpv6", "gre", "vxlan"
    };
    for (auto& p : protocols) {
        if (!raw_matchable.count(p)) return false;
    }
    return true;
}

bool CompoundFilterNode::matches_raw(const RawPacketFields& raw) const {
    bool result;
    if (is_and) {
        result = true;
        for (auto& c : children) {
            if (!c->matches_raw(raw)) { result = false; break; }
        }
    } else {
        result = false;
        for (auto& c : children) {
            if (c->matches_raw(raw)) { result = true; break; }
        }
    }
    return result != negate;
}

bool CompoundFilterNode::can_match_raw() const {
    for (auto& c : children) {
        if (!c->can_match_raw()) return false;
    }
    return true;
}
