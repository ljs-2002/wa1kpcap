#include "protocol_engine.h"
#include "expression_eval.h"
#include "hardcoded_parsers.h"
#include "quic_crypto.h"
#include "util.h"

#include <stdexcept>
#include <cstring>
#include <algorithm>

// Global profiling state
ProfilingStats g_prof;
bool g_profiling_enabled = false;

// ── Helper: extract _tls_* keys from repeat merge into NativeParsedPacket ──

static void extract_tls_from_repeat_fields(const FieldMap& fields, NativeParsedPacket& pkt) {
    if (!fields.count("_tls_repeat_merged")) return;

    pkt.has_tls = true;
    auto& t = pkt.tls;

    auto get_str = [&](const std::string& k) -> std::string {
        auto it = fields.find(k);
        if (it == fields.end()) return {};
        auto* v = std::get_if<std::string>(&it->second);
        return v ? *v : std::string{};
    };
    auto get_i64 = [&](const std::string& k) -> int64_t {
        auto it = fields.find(k);
        if (it == fields.end()) return -1;
        auto* v = std::get_if<int64_t>(&it->second);
        return v ? *v : -1;
    };
    auto get_vec_i64 = [&](const std::string& k) -> std::vector<int64_t> {
        auto it = fields.find(k);
        if (it == fields.end()) return {};
        auto* v = std::get_if<std::vector<int64_t>>(&it->second);
        return v ? *v : std::vector<int64_t>{};
    };
    auto get_vec_str = [&](const std::string& k) -> std::vector<std::string> {
        auto it = fields.find(k);
        if (it == fields.end()) return {};
        auto* v = std::get_if<std::vector<std::string>>(&it->second);
        return v ? *v : std::vector<std::string>{};
    };

    std::string ver = get_str("_tls_version");
    if (!ver.empty()) t.version = ver;
    int64_t ct = get_i64("_tls_content_type");
    if (ct >= 0) t.content_type = static_cast<int>(ct);
    int64_t ht = get_i64("_tls_handshake_type");
    if (ht >= 0) t.handshake_type = static_cast<int>(ht);
    std::string sni = get_str("_tls_sni");
    if (!sni.empty()) t.sni = sni;
    auto cs = get_vec_i64("_tls_cipher_suites");
    if (!cs.empty()) t.cipher_suites = cs;
    int64_t csu = get_i64("_tls_cipher_suite");
    if (csu >= 0) t.cipher_suite = static_cast<int>(csu);
    int64_t rl = get_i64("_tls_record_length");
    if (rl > 0) t.record_length = static_cast<int>(rl);
    auto alpn = get_vec_str("_tls_alpn");
    if (!alpn.empty()) t.alpn = alpn;
    auto sa = get_vec_i64("_tls_signature_algorithms");
    if (!sa.empty()) t.signature_algorithms = sa;
    auto sg = get_vec_i64("_tls_supported_groups");
    if (!sg.empty()) t.supported_groups = sg;
    auto hts = get_vec_i64("_tls_handshake_types");
    if (!hts.empty()) t.handshake_types = hts;
    auto certs = get_vec_str("_tls_certificates");
    if (!certs.empty()) t.certificates = certs;
}

// ── FieldMap → Python dict conversion ──

py::dict fieldmap_to_pydict(const FieldMap& fm) {
    py::dict d;
    for (auto& [key, val] : fm) {
        std::visit([&](auto&& v) {
            using T = std::decay_t<decltype(v)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                d[py::cast(key)] = py::none();
            } else if constexpr (std::is_same_v<T, int64_t>) {
                d[py::cast(key)] = py::cast(v);
            } else if constexpr (std::is_same_v<T, uint64_t>) {
                d[py::cast(key)] = py::cast(v);
            } else if constexpr (std::is_same_v<T, double>) {
                d[py::cast(key)] = py::cast(v);
            } else if constexpr (std::is_same_v<T, std::string>) {
                d[py::cast(key)] = py::cast(v);
            } else if constexpr (std::is_same_v<T, std::vector<uint8_t>>) {
                d[py::cast(key)] = py::bytes(reinterpret_cast<const char*>(v.data()), v.size());
            } else if constexpr (std::is_same_v<T, std::vector<int64_t>>) {
                d[py::cast(key)] = py::cast(v);
            } else if constexpr (std::is_same_v<T, std::vector<std::string>>) {
                d[py::cast(key)] = py::cast(v);
            }
        }, val);
    }
    return d;
}

// ── ProtocolEngine ──

ProtocolEngine::ProtocolEngine(const YamlLoader& loader)
    : loader_(loader)
{
    // ── Populate fast-path dispatch table ──
    fast_dispatch_["ethernet"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_ethernet(buf, len, pkt);
    };
    fast_dispatch_["ipv4"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        auto fr = fast_parse_ipv4(buf, len, pkt);
        if (fr.bytes_consumed > 0) fr.bounds_remaining = true;
        return fr;
    };
    fast_dispatch_["ipv6"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        auto fr = fast_parse_ipv6(buf, len, pkt);
        if (fr.bytes_consumed > 0) fr.bounds_remaining = true;
        return fr;
    };
    fast_dispatch_["tcp"] = [this](const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt) {
        return fast_parse_tcp(buf, len, remaining, pkt);
    };
    fast_dispatch_["udp"] = [this](const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt) {
        return fast_parse_udp(buf, len, remaining, pkt);
    };
    fast_dispatch_["arp"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_arp(buf, len, pkt);
    };
    fast_dispatch_["icmp"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_icmp(buf, len, pkt);
    };
    fast_dispatch_["icmpv6"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_icmpv6(buf, len, pkt);
    };

    // ── Transparent fast-path: dispatch-only, no struct ──

    // raw_ip: peek version nibble → ipv4 or ipv6
    fast_dispatch_["raw_ip"] = [](const uint8_t* buf, size_t len, size_t, NativeParsedPacket&) -> FastResult {
        if (len < 1) return {};
        uint8_t version = (buf[0] >> 4) & 0x0F;
        if (version == 4) return {0, "ipv4"};
        if (version == 6) return {0, "ipv6"};
        return {};
    };

    // bsd_loopback: 4-byte AF field (host byte order) → ipv4 or ipv6
    fast_dispatch_["bsd_loopback"] = [](const uint8_t* buf, size_t len, size_t, NativeParsedPacket&) -> FastResult {
        if (len < 4) return {};
        uint32_t af = hardcoded::parse_bsd_loopback_af(buf, len);
        if (af == 0x0800) return {4, "ipv4"};
        if (af == 0x86DD) return {4, "ipv6"};
        return {4, ""};  // unknown AF, consume header but stop
    };

    // nflog: walk TLV to find NFULA_PAYLOAD, then peek version nibble
    fast_dispatch_["nflog"] = [](const uint8_t* buf, size_t len, size_t, NativeParsedPacket&) -> FastResult {
        auto result = hardcoded::parse_nflog_payload(buf, len);
        if (!result.found || result.length < 1) return {};
        uint8_t version = (buf[result.offset] >> 4) & 0x0F;
        if (version == 4) return {result.offset, "ipv4"};
        if (version == 6) return {result.offset, "ipv6"};
        return {};
    };

    // ── Full built-in fast-path: struct + dispatch ──

    fast_dispatch_["vlan"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_vlan(buf, len, pkt);
    };
    fast_dispatch_["linux_sll"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_sll(buf, len, pkt);
    };
    fast_dispatch_["linux_sll2"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_sll2(buf, len, pkt);
    };
    fast_dispatch_["gre"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_gre(buf, len, pkt);
    };
    fast_dispatch_["vxlan"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_vxlan(buf, len, pkt);
    };
    fast_dispatch_["mpls"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_mpls(buf, len, pkt);
    };
    fast_dispatch_["dhcp"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_dhcp(buf, len, pkt);
    };
    fast_dispatch_["dhcpv6"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_dhcpv6(buf, len, pkt);
    };
    fast_dispatch_["quic"] = [this](const uint8_t* buf, size_t len, size_t, NativeParsedPacket& pkt) {
        return fast_parse_quic(buf, len, pkt);
    };

    // ── Populate slow-path fill dispatch table ──
    fill_dispatch_["ethernet"] = [this](SlowFillContext& ctx) {
        fill_ethernet(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["ipv4"] = [this](SlowFillContext& ctx) {
        fill_ipv4(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["ipv6"] = [this](SlowFillContext& ctx) {
        fill_ipv6(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["tcp"] = [this](SlowFillContext& ctx) {
        int64_t app_len_val = 0;
        if (ctx.bytes_consumed < ctx.remaining) {
            app_len_val = static_cast<int64_t>(ctx.remaining - ctx.bytes_consumed);
        }
        fill_tcp(ctx.pkt, ctx.fields, app_len_val);
        if (app_len_val > 0) {
            const uint8_t* payload = ctx.cur + ctx.bytes_consumed;
            ctx.pkt._raw_tcp_payload.assign(
                reinterpret_cast<const char*>(payload), static_cast<size_t>(app_len_val));
        }
    };
    fill_dispatch_["udp"] = [this](SlowFillContext& ctx) {
        int64_t app_len_val = 0;
        if (ctx.bytes_consumed < ctx.remaining) {
            app_len_val = static_cast<int64_t>(ctx.remaining - ctx.bytes_consumed);
        }
        fill_udp(ctx.pkt, ctx.fields, app_len_val);
    };
    fill_dispatch_["dns"] = [this](SlowFillContext& ctx) {
        fill_dns(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["arp"] = [this](SlowFillContext& ctx) {
        fill_arp(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["icmp"] = [this](SlowFillContext& ctx) {
        fill_icmp(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["icmpv6"] = [this](SlowFillContext& ctx) {
        fill_icmpv6(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["vlan"] = [this](SlowFillContext& ctx) {
        fill_vlan(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["linux_sll"] = [this](SlowFillContext& ctx) {
        fill_sll(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["linux_sll2"] = [this](SlowFillContext& ctx) {
        fill_sll2(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["gre"] = [this](SlowFillContext& ctx) {
        fill_gre(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["vxlan"] = [this](SlowFillContext& ctx) {
        fill_vxlan(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["mpls"] = [this](SlowFillContext& ctx) {
        fill_mpls(ctx.pkt, ctx.fields);
    };
    fill_dispatch_["tls_stream"] = [](SlowFillContext& ctx) {
        extract_tls_from_repeat_fields(ctx.fields, ctx.pkt);
    };
    // TLS sub-layers: store into tls_layers for deferred fill_tls
    auto tls_layer_fn = [](SlowFillContext& ctx) {
        ctx.has_tls = true;
        ctx.tls_layers[ctx.proto_name] = std::move(ctx.fields);
    };
    fill_dispatch_["tls_record"] = tls_layer_fn;
    fill_dispatch_["tls_handshake"] = tls_layer_fn;
    fill_dispatch_["tls_client_hello"] = tls_layer_fn;
    fill_dispatch_["tls_server_hello"] = tls_layer_fn;
    fill_dispatch_["tls_certificate"] = tls_layer_fn;
    fill_dispatch_["quic"] = [this](SlowFillContext& ctx) {
        fill_quic(ctx.pkt, ctx.fields);
    };
}

ProtocolEngine::ParseResult ProtocolEngine::parse_layer(
    const std::string& protocol_name,
    const uint8_t* buf, size_t len,
    const uint8_t* pkt_base, size_t pkt_len) const
{
    ParseResult result;

    auto* proto = loader_.get_protocol(protocol_name);
    if (!proto) return result;

    size_t offset = 0;
    for (auto& field : proto->fields) {
        // Computed fields consume 0 bytes — always evaluate them
        if (offset >= len && field.type != PrimitiveType::COMPUTED) break;
        try {
            size_t consumed = parse_field(field, buf + offset, len - offset,
                                          result.fields, pkt_base, pkt_len);
            offset += consumed;
        } catch (...) {
            // Parse failure: stop at current layer, keep what we have
            break;
        }
    }

    result.bytes_consumed = offset;

    // If protocol declares a header_size_field, use it to adjust bytes_consumed
    // so the next layer starts after the full header (including options/padding)
    if (!proto->header_size_field.empty()) {
        auto hsf_it = result.fields.find(proto->header_size_field);
        if (hsf_it != result.fields.end()) {
            size_t real_header_size = static_cast<size_t>(field_to_int(hsf_it->second));
            if (real_header_size > offset && real_header_size <= len) {
                result.bytes_consumed = real_header_size;
            }
        }
    }

    // Determine next protocol
    auto np_start = std::chrono::high_resolution_clock::now();

    if (proto->next_protocol) {
        auto& np = *proto->next_protocol;
        bool found = false;
        for (const auto& fname : np.fields) {
            auto it = result.fields.find(fname);
            if (it != result.fields.end()) {
                int64_t val = field_to_int(it->second);
                auto mit = np.mapping.find(static_cast<int>(val));
                if (mit != np.mapping.end()) {
                    result.next_protocol = mit->second;
                    found = true;
                    break;
                }
            }
        }
        // Payload heuristics: try byte-pattern matching on remaining data
        if (!found && !np.heuristics.empty() && result.bytes_consumed < len) {
            const uint8_t* payload = buf + result.bytes_consumed;
            size_t payload_len = len - result.bytes_consumed;
            std::string heuristic_proto = evaluate_heuristics(
                np.heuristics, payload, payload_len);
            if (!heuristic_proto.empty()) {
                result.next_protocol = heuristic_proto;
                found = true;
            }
        }
        if (!found && !np.default_protocol.empty()) {
            result.next_protocol = np.default_protocol;
        }
    }

    // Suppress transport-layer chaining for non-initial IP fragments.
    // Non-initial fragments have no transport header — only payload data.
    if (!result.next_protocol.empty() &&
        (protocol_name == "ipv4" || protocol_name == "ipv6")) {
        auto fo_it = result.fields.find("fragment_offset");
        if (fo_it != result.fields.end() && field_to_int(fo_it->second) > 0) {
            result.next_protocol.clear();
        }
    }

    if (g_profiling_enabled) {
        auto np_end = std::chrono::high_resolution_clock::now();
        g_prof.next_proto_ns.fetch_add(
            std::chrono::duration_cast<std::chrono::nanoseconds>(np_end - np_start).count(),
            std::memory_order_relaxed);
    }

    result.next_offset = offset;
    return result;
}

py::dict ProtocolEngine::parse_packet(const uint8_t* buf, size_t len,
                                       uint32_t link_type, bool save_raw_bytes) const
{
    py::dict result;

    // Find starting protocol from link type
    auto& lt_cfg = loader_.link_types();
    auto it = lt_cfg.dlt_to_protocol.find(static_cast<int>(link_type));
    if (it == lt_cfg.dlt_to_protocol.end()) return result;

    std::string current_proto = it->second;
    const uint8_t* cur = buf;
    size_t remaining = len;
    int max_layers = 16; // prevent infinite loops

    while (!current_proto.empty() && remaining > 0 && max_layers-- > 0) {
        auto pr = parse_layer(current_proto, cur, remaining, buf, len);

        // Store layer results as a nested py::dict
        result[py::cast(current_proto)] = fieldmap_to_pydict(pr.fields);

        // If protocol declares total_length_field, bound remaining to exclude
        // link-layer padding (e.g., Ethernet minimum 60-byte frames)
        auto* proto_def = loader_.get_protocol(current_proto);
        if (proto_def && !proto_def->total_length_field.empty()) {
            auto tl_it = pr.fields.find(proto_def->total_length_field);
            if (tl_it != pr.fields.end()) {
                size_t total_len = static_cast<size_t>(field_to_int(tl_it->second));
                if (total_len < remaining) {
                    remaining = total_len;
                }
            }
        }

        // Also store raw payload for TCP (needed by Python TCP reassembly)
        if (current_proto == "tcp" && pr.bytes_consumed < remaining) {
            size_t payload_len = remaining - pr.bytes_consumed;
            if (payload_len > 0) {
                std::vector<uint8_t> payload(cur + pr.bytes_consumed,
                                              cur + pr.bytes_consumed + payload_len);
                result[py::cast("_raw_tcp_payload")] = py::bytes(
                    reinterpret_cast<const char*>(payload.data()), payload.size());
                result[py::cast("app_len")] = py::cast(static_cast<int64_t>(payload_len));

                // Only chain into TLS if the first record is complete.
                if (pr.next_protocol == "tls_stream" && payload_len >= 5) {
                    uint16_t rec_len = (static_cast<uint16_t>(payload[3]) << 8) | payload[4];
                    if (5 + rec_len > payload_len) {
                        pr.next_protocol.clear();
                    }
                }
            }
        }

        if (current_proto == "udp" && pr.bytes_consumed < remaining) {
            size_t payload_len = remaining - pr.bytes_consumed;
            if (payload_len > 0) {
                result[py::cast("app_len")] = py::cast(static_cast<int64_t>(payload_len));
            }
        }

        cur += pr.bytes_consumed;
        remaining -= pr.bytes_consumed;
        current_proto = pr.next_protocol;
    }

    // Store metadata
    result[py::cast("_link_type")] = py::cast(static_cast<int64_t>(link_type));

    if (save_raw_bytes) {
        result[py::cast("_raw_data")] = py::bytes(reinterpret_cast<const char*>(buf), len);
    }

    return result;
}

// ── Field parsing dispatch ──

size_t ProtocolEngine::parse_field(const FieldDef& field, const uint8_t* buf, size_t len,
                                    FieldMap& out, const uint8_t* pkt_base, size_t pkt_len) const
{
    if (!g_profiling_enabled) {
        switch (field.type) {
        case PrimitiveType::FIXED:
            return parse_fixed(field, buf, len, out);
        case PrimitiveType::BITFIELD:
            return parse_bitfield(field, buf, len, out);
        case PrimitiveType::LENGTH_PREFIXED:
            return parse_length_prefixed(field, buf, len, out, pkt_base, pkt_len);
        case PrimitiveType::COMPUTED:
            return parse_computed(field, out);
        case PrimitiveType::TLV:
            return parse_tlv(field, buf, len, out, pkt_base, pkt_len);
        case PrimitiveType::COUNTED_LIST:
            return parse_counted_list(field, buf, len, out, pkt_base, pkt_len);
        case PrimitiveType::REST:
            return parse_rest(field, buf, len, out);
        case PrimitiveType::HARDCODED:
            return parse_hardcoded(field, buf, len, out, pkt_base, pkt_len);
        case PrimitiveType::PREFIXED_LIST:
            return parse_prefixed_list(field, buf, len, out, pkt_base, pkt_len);
        case PrimitiveType::REPEAT:
            return parse_repeat(field, buf, len, out, pkt_base, pkt_len);
        }
        return 0;
    }

    // Profiling-enabled path
    switch (field.type) {
    case PrimitiveType::FIXED: {
        ScopedTimer t(g_prof.fixed_ns); g_prof.fixed_count++;
        return parse_fixed(field, buf, len, out);
    }
    case PrimitiveType::BITFIELD: {
        ScopedTimer t(g_prof.bitfield_ns); g_prof.bitfield_count++;
        return parse_bitfield(field, buf, len, out);
    }
    case PrimitiveType::LENGTH_PREFIXED: {
        ScopedTimer t(g_prof.length_prefixed_ns); g_prof.length_prefixed_count++;
        return parse_length_prefixed(field, buf, len, out, pkt_base, pkt_len);
    }
    case PrimitiveType::COMPUTED: {
        ScopedTimer t(g_prof.computed_ns); g_prof.computed_count++;
        return parse_computed(field, out);
    }
    case PrimitiveType::TLV: {
        ScopedTimer t(g_prof.tlv_ns); g_prof.tlv_count++;
        return parse_tlv(field, buf, len, out, pkt_base, pkt_len);
    }
    case PrimitiveType::COUNTED_LIST: {
        ScopedTimer t(g_prof.counted_list_ns); g_prof.counted_list_count++;
        return parse_counted_list(field, buf, len, out, pkt_base, pkt_len);
    }
    case PrimitiveType::REST: {
        ScopedTimer t(g_prof.rest_ns); g_prof.rest_count++;
        return parse_rest(field, buf, len, out);
    }
    case PrimitiveType::HARDCODED: {
        ScopedTimer t(g_prof.hardcoded_ns); g_prof.hardcoded_count++;
        return parse_hardcoded(field, buf, len, out, pkt_base, pkt_len);
    }
    case PrimitiveType::PREFIXED_LIST: {
        ScopedTimer t(g_prof.prefixed_list_ns); g_prof.prefixed_list_count++;
        return parse_prefixed_list(field, buf, len, out, pkt_base, pkt_len);
    }
    case PrimitiveType::REPEAT: {
        ScopedTimer t(g_prof.repeat_ns); g_prof.repeat_count++;
        return parse_repeat(field, buf, len, out, pkt_base, pkt_len);
    }
    }
    return 0;
}

// ── FIXED ──

size_t ProtocolEngine::parse_fixed(const FieldDef& f, const uint8_t* buf, size_t len,
                                    FieldMap& out) const
{
    if (static_cast<size_t>(f.size) > len) return 0;

    if (f.format == "ipv4" && f.size == 4) {
        out[f.name] = util::format_ipv4(buf);
    } else if (f.format == "ipv6" && f.size == 16) {
        out[f.name] = util::format_ipv6(buf);
    } else if (f.format == "mac" && f.size == 6) {
        out[f.name] = util::format_mac(buf);
    } else if (f.format == "bytes" || f.format == "hex") {
        out[f.name] = std::vector<uint8_t>(buf, buf + f.size);
    } else {
        // Integer (uint or int)
        uint64_t val = 0;
        if (f.endian == "big") {
            for (int i = 0; i < f.size; i++) {
                val = (val << 8) | buf[i];
            }
        } else {
            for (int i = f.size - 1; i >= 0; i--) {
                val = (val << 8) | buf[i];
            }
        }

        if (f.format == "int") {
            // Sign-extend
            int64_t sval = static_cast<int64_t>(val);
            if (f.size < 8) {
                uint64_t sign_bit = 1ULL << (f.size * 8 - 1);
                if (val & sign_bit) {
                    sval = static_cast<int64_t>(val | ~((1ULL << (f.size * 8)) - 1));
                }
            }
            out[f.name] = sval;
        } else {
            out[f.name] = static_cast<int64_t>(val);
        }
    }

    return f.size;
}

// ── BITFIELD ──

size_t ProtocolEngine::parse_bitfield(const FieldDef& f, const uint8_t* buf, size_t len,
                                       FieldMap& out) const
{
    if (static_cast<size_t>(f.group_size) > len) return 0;

    // Read the group as a big-endian integer
    uint64_t group_val = 0;
    for (int i = 0; i < f.group_size; i++) {
        group_val = (group_val << 8) | buf[i];
    }

    // Extract bit fields from MSB to LSB
    int total_bits = f.group_size * 8;
    int bit_offset = total_bits;

    for (auto& bf : f.bit_fields) {
        bit_offset -= bf.bits;
        uint64_t mask = (1ULL << bf.bits) - 1;
        int64_t val = static_cast<int64_t>((group_val >> bit_offset) & mask);
        out[bf.name] = val;
    }

    return f.group_size;
}

// ── LENGTH_PREFIXED ──

size_t ProtocolEngine::parse_length_prefixed(const FieldDef& f, const uint8_t* buf, size_t len,
                                              FieldMap& out,
                                              const uint8_t* pkt_base, size_t pkt_len) const
{
    if (static_cast<size_t>(f.length_size) > len) return 0;

    // Read length prefix (big-endian)
    uint64_t data_len = 0;
    for (int i = 0; i < f.length_size; i++) {
        data_len = (data_len << 8) | buf[i];
    }

    size_t header = f.length_size;
    if (header + data_len > len) {
        // Truncated — use what we have
        data_len = len - header;
    }

    if (!f.sub_protocol.empty()) {
        // Parse content as sub-protocol — flatten fields into parent
        auto pr = parse_layer(f.sub_protocol, buf + header, data_len, pkt_base, pkt_len);
        for (auto& [k, v] : pr.fields) {
            out[k] = std::move(v);
        }
    } else if (f.format == "string") {
        out[f.name] = std::string(reinterpret_cast<const char*>(buf + header), data_len);
    } else if (f.format == "bytes" || f.format.empty()) {
        out[f.name] = std::vector<uint8_t>(buf + header, buf + header + data_len);
    } else {
        // Store length
        out[f.name] = static_cast<int64_t>(data_len);
    }

    return header + data_len;
}

// ── COMPUTED ──

size_t ProtocolEngine::parse_computed(const FieldDef& f, FieldMap& out) const {
    try {
        int64_t val;
        if (f.compiled_expr && f.compiled_expr->valid()) {
            val = f.compiled_expr->evaluate(out);
        } else {
            val = ExpressionEval::evaluate(f.expression, out);
        }
        out[f.name] = val;
    } catch (...) {
        out[f.name] = static_cast<int64_t>(0);
    }
    return 0; // computed fields don't consume bytes
}

// ── TLV ──

size_t ProtocolEngine::parse_tlv(const FieldDef& f, const uint8_t* buf, size_t len,
                                  FieldMap& out,
                                  const uint8_t* pkt_base, size_t pkt_len) const
{
    size_t offset = 0;

    while (offset + f.type_size + f.tlv_length_size <= len) {
        // Read type
        uint64_t type_val = 0;
        for (int i = 0; i < f.type_size; i++) {
            type_val = (type_val << 8) | buf[offset + i];
        }
        offset += f.type_size;

        // Read length
        uint64_t val_len = 0;
        for (int i = 0; i < f.tlv_length_size; i++) {
            val_len = (val_len << 8) | buf[offset + i];
        }
        offset += f.tlv_length_size;

        if (offset + val_len > len) break;

        // Check if we have a sub-protocol for this type
        auto mit = f.type_mapping.find(static_cast<int>(type_val));
        if (mit != f.type_mapping.end()) {
            auto pr = parse_layer(mit->second, buf + offset, val_len, pkt_base, pkt_len);
            // Flatten sub-protocol fields into parent with sub-protocol name prefix
            for (auto& [k, v] : pr.fields) {
                out[k] = std::move(v);
            }
        }

        offset += val_len;
    }

    return offset;
}

// ── COUNTED_LIST ──

size_t ProtocolEngine::parse_counted_list(const FieldDef& f, const uint8_t* buf, size_t len,
                                           FieldMap& out,
                                           const uint8_t* pkt_base, size_t pkt_len) const
{
    // Get count from previously parsed field
    auto it = out.find(f.count_field);
    if (it == out.end()) return 0;
    int64_t count = field_to_int(it->second);
    if (count <= 0) return 0;

    size_t offset = 0;

    if (!f.item_protocol.empty()) {
        // Parse each item as a sub-protocol
        std::vector<std::string> items; // for string results
        std::vector<int64_t> int_items; // for integer results
        bool is_string_list = false;
        bool is_int_list = false;

        for (int64_t i = 0; i < count && offset < len; i++) {
            auto pr = parse_layer(f.item_protocol, buf + offset, len - offset, pkt_base, pkt_len);
            if (pr.bytes_consumed == 0) break;
            offset += pr.bytes_consumed;
        }
    } else if (f.size > 0) {
        // Fixed-size items (e.g., cipher suites = 2-byte integers)
        std::vector<int64_t> items;
        for (int64_t i = 0; i < count && offset + f.size <= len; i++) {
            uint64_t val = 0;
            for (int j = 0; j < f.size; j++) {
                val = (val << 8) | buf[offset + j];
            }
            items.push_back(static_cast<int64_t>(val));
            offset += f.size;
        }
        out[f.name] = std::move(items);
    }

    return offset;
}

// ── REST ──

size_t ProtocolEngine::parse_rest(const FieldDef& f, const uint8_t* buf, size_t len,
                                   FieldMap& out) const
{
    if (f.format == "bytes" || f.format.empty()) {
        out[f.name] = std::vector<uint8_t>(buf, buf + len);
    } else {
        out[f.name] = static_cast<int64_t>(len);
    }
    return len;
}

// ── HARDCODED ──

size_t ProtocolEngine::parse_hardcoded(const FieldDef& f, const uint8_t* buf, size_t len,
                                        FieldMap& out,
                                        const uint8_t* pkt_base, size_t pkt_len) const
{
    if (f.parser_name == "dns_name") {
        auto result = hardcoded::parse_dns_name(
            pkt_base ? pkt_base : buf, pkt_base ? pkt_len : len,
            buf, len);
        out[f.name] = result.name;
        return result.bytes_consumed;
    }

    if (f.parser_name == "bsd_loopback_af") {
        uint32_t af = hardcoded::parse_bsd_loopback_af(buf, len);
        out[f.name] = static_cast<int64_t>(af);
        return 4;
    }

    if (f.parser_name == "nflog_payload") {
        auto result = hardcoded::parse_nflog_payload(buf, len);
        if (result.found) {
            out[f.name] = std::vector<uint8_t>(buf + result.offset,
                                                buf + result.offset + result.length);
            // Store offset for next_protocol to use
            out["_nflog_payload_offset"] = static_cast<int64_t>(result.offset);
            return result.offset + result.length;
        }
        return len; // consume all if not found
    }

    return 0;
}

// ── PREFIXED_LIST ──
// Format: [list_length_size bytes total length][item_length_size bytes item len][item data]...
// Produces a vector<string> (item_format="string") or vector<uint8_t> per item.

size_t ProtocolEngine::parse_prefixed_list(const FieldDef& f, const uint8_t* buf, size_t len,
                                            FieldMap& out,
                                            const uint8_t* pkt_base, size_t pkt_len) const
{
    if (static_cast<size_t>(f.list_length_size) > len) return 0;

    // Read outer list length
    uint64_t list_len = 0;
    for (int i = 0; i < f.list_length_size; i++) {
        list_len = (list_len << 8) | buf[i];
    }

    size_t offset = f.list_length_size;
    size_t end = offset + list_len;
    if (end > len) end = len;

    // TLV mode: type_size > 0 means each entry is [type][length][data] with sub-protocol dispatch
    if (f.type_size > 0) {
        while (offset + f.type_size + f.item_length_size <= end) {
            // Read type
            uint64_t type_val = 0;
            for (int i = 0; i < f.type_size; i++) {
                type_val = (type_val << 8) | buf[offset + i];
            }
            offset += f.type_size;

            // Read data length
            uint64_t data_len = 0;
            for (int i = 0; i < f.item_length_size; i++) {
                data_len = (data_len << 8) | buf[offset + i];
            }
            offset += f.item_length_size;

            if (offset + data_len > end) break;

            // Dispatch to sub-protocol if mapped
            auto mit = f.type_mapping.find(static_cast<int>(type_val));
            if (mit != f.type_mapping.end()) {
                auto pr = parse_layer(mit->second, buf + offset, data_len, pkt_base, pkt_len);
                for (auto& [k, v] : pr.fields) {
                    out[mit->second + "." + k] = std::move(v);
                }
            }

            offset += data_len;
        }
        return end;
    }

    // Homogeneous list mode: [item_length][item_data]...
    if (f.item_format == "bytes") {
        std::vector<std::string> items;
        while (offset + f.item_length_size <= end) {
            uint64_t item_len = 0;
            for (int i = 0; i < f.item_length_size; i++) {
                item_len = (item_len << 8) | buf[offset + i];
            }
            offset += f.item_length_size;
            if (offset + item_len > end) break;
            items.emplace_back(reinterpret_cast<const char*>(buf + offset), item_len);
            offset += item_len;
        }
        out[f.name] = std::move(items);
    } else {
        std::vector<std::string> string_items;
        while (offset + f.item_length_size <= end) {
            uint64_t item_len = 0;
            for (int i = 0; i < f.item_length_size; i++) {
                item_len = (item_len << 8) | buf[offset + i];
            }
            offset += f.item_length_size;
            if (offset + item_len > end) break;
            string_items.emplace_back(reinterpret_cast<const char*>(buf + offset), item_len);
            offset += item_len;
        }
        out[f.name] = std::move(string_items);
    }
    return end;
}

// ── REPEAT ──
// Repeatedly parse a sub-protocol chain from the remaining buffer.
// merge="tls": TLS-aware repeat with record boundaries and handshake splitting.

size_t ProtocolEngine::parse_repeat(const FieldDef& f, const uint8_t* buf, size_t len,
                                     FieldMap& out,
                                     const uint8_t* pkt_base, size_t pkt_len) const
{
    if (f.merge_mode == "tls") {
        // TLS-aware repeat: parse TLS records with handshake message splitting.
        size_t offset = 0;
        NativeParsedPacket merged;

        while (offset + 5 <= len) {
            uint8_t content_type = buf[offset];
            if (content_type < 20 || content_type > 23) break;

            uint16_t record_length = (static_cast<uint16_t>(buf[offset + 3]) << 8)
                                   | buf[offset + 4];
            if (record_length > 16640) break;
            if (offset + 5 + record_length > len) break;

            if (content_type == 22) {
                // Handshake: split internal handshake messages
                const uint8_t* body = buf + offset + 5;
                size_t body_len = record_length;
                size_t hs_off = 0;
                bool parsed_any = false;

                while (hs_off + 4 <= body_len) {
                    uint32_t hs_length = (static_cast<uint32_t>(body[hs_off + 1]) << 16)
                                       | (static_cast<uint32_t>(body[hs_off + 2]) << 8)
                                       | body[hs_off + 3];
                    if (hs_off + 4 + hs_length > body_len) break;

                    size_t hs_msg_len = 4 + hs_length;
                    std::vector<uint8_t> synthetic(5 + hs_msg_len);
                    synthetic[0] = buf[offset];
                    synthetic[1] = buf[offset + 1];
                    synthetic[2] = buf[offset + 2];
                    synthetic[3] = static_cast<uint8_t>((hs_msg_len >> 8) & 0xFF);
                    synthetic[4] = static_cast<uint8_t>(hs_msg_len & 0xFF);
                    std::memcpy(synthetic.data() + 5, body + hs_off, hs_msg_len);

                    NativeParsedPacket tmp = parse_from_protocol_struct(
                        synthetic.data(), synthetic.size(), f.sub_protocol);
                    if (tmp.has_tls) {
                        merged.has_tls = true;
                        merge_tls(merged, tmp.tls);
                    }
                    parsed_any = true;
                    hs_off += hs_msg_len;
                }

                if (!parsed_any) {
                    NativeParsedPacket tmp = parse_from_protocol_struct(
                        buf + offset, 5 + record_length, f.sub_protocol);
                    if (tmp.has_tls) {
                        merged.has_tls = true;
                        merge_tls(merged, tmp.tls);
                    }
                }
            } else {
                NativeParsedPacket tmp = parse_from_protocol_struct(
                    buf + offset, 5 + record_length, f.sub_protocol);
                if (tmp.has_tls) {
                    merged.has_tls = true;
                    merge_tls(merged, tmp.tls);
                }
            }

            offset += 5 + record_length;
        }

        // Store merged TLS as special key so parse_packet_struct can extract it
        if (merged.has_tls) {
            // Encode the merged NativeTLSInfo pointer as an int64 (tag for detection)
            out["_tls_repeat_merged"] = static_cast<int64_t>(1);
            auto& t = merged.tls;
            if (!t.version.empty()) out["_tls_version"] = t.version;
            if (t.content_type >= 0) out["_tls_content_type"] = static_cast<int64_t>(t.content_type);
            if (t.handshake_type >= 0) out["_tls_handshake_type"] = static_cast<int64_t>(t.handshake_type);
            if (!t.sni.empty()) out["_tls_sni"] = t.sni;
            if (!t.cipher_suites.empty()) out["_tls_cipher_suites"] = t.cipher_suites;
            if (t.cipher_suite >= 0) out["_tls_cipher_suite"] = static_cast<int64_t>(t.cipher_suite);
            if (t.record_length > 0) out["_tls_record_length"] = static_cast<int64_t>(t.record_length);
            if (!t.alpn.empty()) out["_tls_alpn"] = t.alpn;
            if (!t.signature_algorithms.empty()) out["_tls_signature_algorithms"] = t.signature_algorithms;
            if (!t.supported_groups.empty()) out["_tls_supported_groups"] = t.supported_groups;
            if (!t.handshake_types.empty()) out["_tls_handshake_types"] = t.handshake_types;
            if (!t.certificates.empty()) out["_tls_certificates"] = t.certificates;
        }

        return offset;
    }

    // Generic repeat: parse sub-protocol chain until buffer exhausted
    size_t offset = 0;
    int max_iter = 256;
    while (offset < len && max_iter-- > 0) {
        auto pr = parse_layer(f.sub_protocol, buf + offset, len - offset, pkt_base, pkt_len);
        if (pr.bytes_consumed == 0) break;
        for (auto& [k, v] : pr.fields) {
            out[k] = std::move(v);
        }
        offset += pr.bytes_consumed;
    }
    return offset;
}

// ── Heuristic payload matching ──

std::string ProtocolEngine::evaluate_heuristics(
    const std::vector<HeuristicRule>& rules,
    const uint8_t* payload, size_t payload_len) const
{
    for (const auto& rule : rules) {
        if (payload_len < rule.min_length) continue;

        bool all_match = true;
        for (const auto& cond : rule.conditions) {
            switch (cond.type) {
            case HeuristicCondition::Type::BYTE_EQ:
                if (cond.offset >= payload_len || payload[cond.offset] != cond.byte_eq_value) {
                    all_match = false;
                }
                break;
            case HeuristicCondition::Type::BYTE_LE:
                if (cond.offset >= payload_len || payload[cond.offset] > cond.byte_le_value) {
                    all_match = false;
                }
                break;
            case HeuristicCondition::Type::BYTE_IN: {
                if (cond.offset >= payload_len) {
                    all_match = false;
                    break;
                }
                uint8_t b = payload[cond.offset];
                bool found = false;
                for (uint8_t v : cond.byte_in_set) {
                    if (b == v) { found = true; break; }
                }
                if (!found) all_match = false;
                break;
            }
            case HeuristicCondition::Type::PREFIX_IN: {
                bool found = false;
                for (const auto& prefix : cond.prefix_in) {
                    if (payload_len >= prefix.size() &&
                        std::memcmp(payload, prefix.data(), prefix.size()) == 0) {
                        found = true;
                        break;
                    }
                }
                if (!found) all_match = false;
                break;
            }
            }
            if (!all_match) break;
        }

        if (all_match) return rule.protocol;
    }
    return {};
}

// ── NativeParser (Python-facing) ──

NativeParser::NativeParser(const std::string& protocols_dir)
    : loader_(), engine_(loader_)
{
    loader_.load_directory(protocols_dir);
    // engine_ already holds a reference to loader_, which is now populated
}

py::dict NativeParser::parse_packet(py::bytes buf, uint32_t link_type, bool save_raw_bytes) {
    std::string data = buf;
    return engine_.parse_packet(
        reinterpret_cast<const uint8_t*>(data.data()), data.size(),
        link_type, save_raw_bytes);
}

NativeParsedPacket NativeParser::parse_packet_struct(py::bytes buf, uint32_t link_type,
                                                      bool save_raw_bytes,
                                                      int app_layer_mode) {
    std::string data = buf;
    return engine_.parse_packet_struct(
        reinterpret_cast<const uint8_t*>(data.data()), data.size(),
        link_type, save_raw_bytes, app_layer_mode);
}

void NativeParser::load_extra_file(const std::string& file_path) {
    loader_.load_file(file_path);
}

void NativeParser::add_protocol_routing(const std::string& parent_proto, int value, const std::string& target_proto) {
    loader_.add_next_protocol_mapping(parent_proto, value, target_proto);
}

// ── Fill helpers: FieldMap → NativeParsedPacket struct fields ──
// All helpers write directly into embedded structs (no heap allocs).
// Single-pass iteration over FieldMap instead of multiple find() calls.

void ProtocolEngine::fill_ethernet(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_eth = true;
    auto& info = pkt.eth;
    for (auto& [key, val] : fm) {
        if (key == "src") info.src = field_to_string(val);
        else if (key == "dst") info.dst = field_to_string(val);
        else if (key == "ether_type") info.type = field_to_int(val);
    }
}

void ProtocolEngine::fill_ipv4(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_ip = true;
    auto& info = pkt.ip;
    info.flags = 0;
    for (auto& [key, val] : fm) {
        if (key == "version") info.version = field_to_int(val);
        else if (key == "src") info.src = field_to_string(val);
        else if (key == "dst") info.dst = field_to_string(val);
        else if (key == "protocol") info.proto = field_to_int(val);
        else if (key == "ttl") info.ttl = field_to_int(val);
        else if (key == "total_length") { info.len = field_to_int(val); pkt.ip_len = info.len; }
        else if (key == "identification") info.id = field_to_int(val);
        else if (key == "mf") { if (field_to_int(val)) info.flags |= 0x1; }
        else if (key == "df") { if (field_to_int(val)) info.flags |= 0x2; }
        else if (key == "fragment_offset") info.offset = field_to_int(val);
    }
}

void ProtocolEngine::fill_ipv6(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_ip6 = true;
    auto& info = pkt.ip6;
    for (auto& [key, val] : fm) {
        if (key == "version") info.version = field_to_int(val);
        else if (key == "src") info.src = field_to_string(val);
        else if (key == "dst") info.dst = field_to_string(val);
        else if (key == "next_header") info.next_header = field_to_int(val);
        else if (key == "hop_limit") info.hop_limit = field_to_int(val);
        else if (key == "flow_label") info.flow_label = field_to_int(val);
        else if (key == "payload_length") { info.len = field_to_int(val); pkt.ip_len = 40 + info.len; }
    }
}

void ProtocolEngine::fill_tcp(NativeParsedPacket& pkt, const FieldMap& fm, int64_t app_len) const {
    pkt.has_tcp = true;
    auto& info = pkt.tcp;
    int64_t header_len = 20;
    for (auto& [key, val] : fm) {
        if (key == "src_port") info.sport = field_to_int(val);
        else if (key == "dst_port") info.dport = field_to_int(val);
        else if (key == "seq") info.seq = field_to_int(val);
        else if (key == "ack_num") info.ack_num = field_to_int(val);
        else if (key == "flags") info.flags = field_to_int(val);
        else if (key == "window") info.win = field_to_int(val);
        else if (key == "urgent_pointer") info.urgent = field_to_int(val);
        else if (key == "header_length") header_len = field_to_int(val);
    }
    pkt.trans_len = header_len + app_len;
    pkt.app_len = app_len;
}

void ProtocolEngine::fill_udp(NativeParsedPacket& pkt, const FieldMap& fm, int64_t app_len) const {
    pkt.has_udp = true;
    auto& info = pkt.udp;
    for (auto& [key, val] : fm) {
        if (key == "src_port") info.sport = field_to_int(val);
        else if (key == "dst_port") info.dport = field_to_int(val);
        else if (key == "length") { info.len = field_to_int(val); pkt.trans_len = info.len; }
    }
    pkt.app_len = app_len;
}

void ProtocolEngine::fill_dns(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_dns = true;
    auto& info = pkt.dns;
    for (auto& [key, val] : fm) {
        if (key == "response_code") info.response_code = field_to_int(val);
        else if (key == "question_count") info.question_count = field_to_int(val);
        else if (key == "answer_count") info.answer_count = field_to_int(val);
        else if (key == "authority_count") info.authority_count = field_to_int(val);
        else if (key == "additional_count") info.additional_count = field_to_int(val);
        else if (key == "flags") info.flags = field_to_int(val);
    }
}

void ProtocolEngine::fill_tls(NativeParsedPacket& pkt,
                               const std::map<std::string, FieldMap>& layers) const {
    pkt.has_tls = true;
    auto& info = pkt.tls;

    // tls_record layer — single pass
    auto lr = layers.find("tls_record");
    if (lr != layers.end()) {
        int64_t major = 0, minor = 0;
        for (auto& [key, val] : lr->second) {
            if (key == "version_major") major = field_to_int(val);
            else if (key == "version_minor") minor = field_to_int(val);
            else if (key == "content_type") info.content_type = field_to_int(val);
            else if (key == "record_length") info.record_length = field_to_int(val);
        }
        if (major && minor) {
            info.version = std::to_string(major) + "." + std::to_string(minor);
        }
    }

    // tls_handshake layer
    auto lh = layers.find("tls_handshake");
    if (lh != layers.end()) {
        for (auto& [key, val] : lh->second) {
            if (key == "handshake_type") { info.handshake_type = field_to_int(val); break; }
        }
    }

    // tls_client_hello layer — extensions parsed via prefixed_list TLV mode with prefixed keys
    auto lc = layers.find("tls_client_hello");
    if (lc != layers.end()) {
        info.handshake_type = 1;
        for (auto& [key, val] : lc->second) {
            if (key == "cipher_suites") {
                if (auto* v = std::get_if<std::vector<int64_t>>(&val)) {
                    info.cipher_suites = *v;
                }
            } else if (key == "tls_ext_sni.server_name") {
                info.sni = field_to_string(val);
            } else if (key == "tls_ext_supported_groups.groups") {
                if (auto* v = std::get_if<std::vector<int64_t>>(&val)) {
                    info.supported_groups = *v;
                }
            } else if (key == "tls_ext_signature_algorithms.algorithms") {
                if (auto* v = std::get_if<std::vector<int64_t>>(&val)) {
                    info.signature_algorithms = *v;
                }
            } else if (key == "tls_ext_alpn.protocols") {
                if (auto* v = std::get_if<std::vector<std::string>>(&val)) {
                    info.alpn = *v;
                }
            }
        }
    }

    // tls_server_hello layer
    auto ls = layers.find("tls_server_hello");
    if (ls != layers.end()) {
        info.handshake_type = 2;
        for (auto& [key, val] : ls->second) {
            if (key == "cipher_suite") {
                info.cipher_suite = field_to_int(val);
            } else if (key == "tls_ext_sni.server_name") {
                info.sni = field_to_string(val);
            } else if (key == "tls_ext_supported_groups.groups") {
                if (auto* v = std::get_if<std::vector<int64_t>>(&val)) {
                    info.supported_groups = *v;
                }
            } else if (key == "tls_ext_signature_algorithms.algorithms") {
                if (auto* v = std::get_if<std::vector<int64_t>>(&val)) {
                    info.signature_algorithms = *v;
                }
            } else if (key == "tls_ext_alpn.protocols") {
                if (auto* v = std::get_if<std::vector<std::string>>(&val)) {
                    info.alpn = *v;
                }
            }
        }
    }

    // tls_certificate layer
    auto lcer = layers.find("tls_certificate");
    if (lcer != layers.end()) {
        info.handshake_type = 11;
        for (auto& [key, val] : lcer->second) {
            if (key == "certificates") {
                if (auto* v = std::get_if<std::vector<std::string>>(&val)) {
                    info.certificates = *v;
                }
            }
        }
    }
}

void ProtocolEngine::fill_arp(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_arp = true;
    auto& info = pkt.arp;
    for (auto& [key, val] : fm) {
        if (key == "hw_type") info.hw_type = field_to_int(val);
        else if (key == "proto_type") info.proto_type = field_to_int(val);
        else if (key == "opcode") info.opcode = field_to_int(val);
        else if (key == "sender_mac") info.sender_mac = field_to_string(val);
        else if (key == "sender_ip") info.sender_ip = field_to_string(val);
        else if (key == "target_mac") info.target_mac = field_to_string(val);
        else if (key == "target_ip") info.target_ip = field_to_string(val);
    }
}

void ProtocolEngine::fill_icmp(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_icmp = true;
    auto& info = pkt.icmp;
    for (auto& [key, val] : fm) {
        if (key == "type") info.type = field_to_int(val);
        else if (key == "code") info.code = field_to_int(val);
        else if (key == "checksum") info.checksum = field_to_int(val);
    }
}

void ProtocolEngine::fill_icmpv6(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_icmp6 = true;
    auto& info = pkt.icmp6;
    for (auto& [key, val] : fm) {
        if (key == "type") info.type = field_to_int(val);
        else if (key == "code") info.code = field_to_int(val);
        else if (key == "checksum") info.checksum = field_to_int(val);
    }
}

// ── merge_tls: merge a single TLS parse result into pkt.tls ──

void ProtocolEngine::merge_tls(NativeParsedPacket& pkt, const NativeTLSInfo& src) const {
    auto& dst = pkt.tls;

    // Accumulate handshake types
    if (src.handshake_type >= 0) {
        dst.handshake_types.push_back(src.handshake_type);
        dst.handshake_type = src.handshake_type;  // last one, backward compat
    }

    // First-wins for version
    if (dst.version.empty() && !src.version.empty()) {
        dst.version = src.version;
    }

    // First-wins for content_type
    if (dst.content_type < 0 && src.content_type >= 0) {
        dst.content_type = src.content_type;
    }

    // First-wins for SNI
    if (dst.sni.empty() && !src.sni.empty()) {
        dst.sni = src.sni;
    }

    // First-wins for cipher_suites (ClientHello)
    if (dst.cipher_suites.empty() && !src.cipher_suites.empty()) {
        dst.cipher_suites = src.cipher_suites;
    }

    // First-wins for cipher_suite (ServerHello)
    if (dst.cipher_suite < 0 && src.cipher_suite >= 0) {
        dst.cipher_suite = src.cipher_suite;
    }

    // First-wins for ALPN
    if (dst.alpn.empty() && !src.alpn.empty()) {
        dst.alpn = src.alpn;
    }

    // First-wins for signature_algorithms
    if (dst.signature_algorithms.empty() && !src.signature_algorithms.empty()) {
        dst.signature_algorithms = src.signature_algorithms;
    }

    // First-wins for supported_groups
    if (dst.supported_groups.empty() && !src.supported_groups.empty()) {
        dst.supported_groups = src.supported_groups;
    }

    // First-wins for certificates
    if (dst.certificates.empty() && !src.certificates.empty()) {
        dst.certificates = src.certificates;
    }

    // Accumulate record_length (use first non-zero)
    if (dst.record_length == 0 && src.record_length > 0) {
        dst.record_length = src.record_length;
    }
}


// ═══════════════════════════════════════════════════════════
// Fast-path parsers: buf → struct directly, no FieldMap
// ═══════════════════════════════════════════════════════════

std::string ProtocolEngine::yaml_next_protocol_lookup(
    const std::string& proto_name, int value) const {
    auto* proto_def = loader_.get_protocol(proto_name);
    if (proto_def && proto_def->next_protocol) {
        auto mit = proto_def->next_protocol->mapping.find(value);
        if (mit != proto_def->next_protocol->mapping.end()) {
            return mit->second;
        }
    }
    return {};
}

// ── QUIC version constants (needed by fast_parse_udp heuristic) ──
static const uint32_t QUIC_V1 = 0x00000001;
static const uint32_t QUIC_V2 = 0x6b3343cf;

static bool is_quic_version(uint32_t ver) {
    return ver == QUIC_V1 || ver == QUIC_V2;
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_ethernet(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 14) return {};
    pkt.has_eth = true;
    pkt.eth.dst = util::format_mac(buf);
    pkt.eth.src = util::format_mac(buf + 6);
    uint16_t ether_type = (buf[12] << 8) | buf[13];
    pkt.eth.type = ether_type;

    std::string next;
    switch (ether_type) {
    case 0x0800: next = "ipv4"; break;
    case 0x86DD: next = "ipv6"; break;
    case 0x0806: next = "arp"; break;
    case 0x8100: next = "vlan"; break;
    case 0x8847: next = "mpls"; break;
    case 0x8848: next = "mpls"; break;
    }
    if (next.empty()) next = yaml_next_protocol_lookup("ethernet", ether_type);
    return {14, std::move(next)};
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_ipv4(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 20) return {};
    pkt.has_ip = true;
    auto& ip = pkt.ip;

    uint8_t ver_ihl = buf[0];
    ip.version = (ver_ihl >> 4) & 0xF;
    uint8_t ihl = ver_ihl & 0xF;

    ip.len = (buf[2] << 8) | buf[3];
    pkt.ip_len = ip.len;
    ip.id = (buf[4] << 8) | buf[5];

    uint16_t flags_offset = (buf[6] << 8) | buf[7];
    ip.flags = 0;
    if (flags_offset & 0x4000) ip.flags |= 0x2; // DF
    if (flags_offset & 0x2000) ip.flags |= 0x1; // MF
    ip.offset = flags_offset & 0x1FFF;

    ip.ttl = buf[8];
    ip.proto = buf[9];
    // checksum at [10..11] — not stored in struct
    ip.src = util::format_ipv4(buf + 12);
    ip.dst = util::format_ipv4(buf + 16);

    size_t header_length = static_cast<size_t>(ihl) * 4;
    if (header_length < 20) header_length = 20;
    if (header_length > len) header_length = len;

    // Capture IPv4 options (IHL > 5 means options present)
    if (header_length > 20) {
        ip.options_raw.assign(reinterpret_cast<const char*>(buf + 20), header_length - 20);
    }

    // Bound remaining by total_length
    size_t bytes_consumed = header_length;

    // Suppress next protocol for non-initial fragments
    if (ip.offset > 0) return {bytes_consumed, ""};

    std::string next;
    switch (ip.proto) {
    case 6:  next = "tcp"; break;
    case 17: next = "udp"; break;
    case 1:  next = "icmp"; break;
    case 58: next = "icmpv6"; break;
    case 47: next = "gre"; break;
    }
    if (next.empty()) next = yaml_next_protocol_lookup("ipv4", ip.proto);
    return {bytes_consumed, std::move(next)};
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_ipv6(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 40) return {};
    pkt.has_ip6 = true;
    auto& ip6 = pkt.ip6;

    ip6.version = (buf[0] >> 4) & 0xF;
    ip6.flow_label = ((buf[1] & 0xF) << 16) | (buf[2] << 8) | buf[3];
    uint16_t payload_length = (buf[4] << 8) | buf[5];
    uint8_t next_header = buf[6];
    ip6.hop_limit = buf[7];
    ip6.src = util::format_ipv6(buf + 8);
    ip6.dst = util::format_ipv6(buf + 24);
    ip6.len = payload_length;
    pkt.ip_len = 40 + payload_length;

    // Walk extension header chain
    size_t offset = 40;
    size_t max_offset = len < static_cast<size_t>(40 + payload_length) ? len : static_cast<size_t>(40 + payload_length);
    while (offset < max_offset) {
        // Known extension header next_header values
        bool is_ext = false;
        switch (next_header) {
        case 0:   // Hop-by-Hop Options
        case 43:  // Routing
        case 60:  // Destination Options
        case 51:  // Authentication Header
        case 50:  // ESP
            is_ext = true;
            break;
        case 44:  // Fragment Header (fixed 8 bytes)
            is_ext = true;
            break;
        default:
            break;
        }
        if (!is_ext) break;

        if (offset + 2 > max_offset) break;

        uint8_t ext_next = buf[offset];
        size_t ext_len;
        if (next_header == 44) {
            // Fragment header: fixed 8 bytes
            ext_len = 8;
        } else {
            // Standard: (hdr_ext_len + 1) * 8
            ext_len = (static_cast<size_t>(buf[offset + 1]) + 1) * 8;
        }

        if (offset + ext_len > max_offset) break;

        // Append extension header raw bytes
        ip6.options_raw.append(reinterpret_cast<const char*>(buf + offset), ext_len);

        next_header = ext_next;
        offset += ext_len;
    }

    ip6.next_header = next_header;

    // Map next_header to protocol name
    std::string next;
    switch (next_header) {
    case 6:  next = "tcp"; break;
    case 17: next = "udp"; break;
    case 1:  next = "icmp"; break;
    case 58: next = "icmpv6"; break;
    case 47: next = "gre"; break;
    }
    if (next.empty()) next = yaml_next_protocol_lookup("ipv6", next_header);
    return {offset, std::move(next)};
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_tcp(
    const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt) const
{
    if (len < 20) return {};
    pkt.has_tcp = true;
    auto& tcp = pkt.tcp;

    tcp.sport = (buf[0] << 8) | buf[1];
    tcp.dport = (buf[2] << 8) | buf[3];
    tcp.seq = (static_cast<int64_t>(buf[4]) << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
    tcp.ack_num = (static_cast<int64_t>(buf[8]) << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11];

    uint16_t doff_flags = (buf[12] << 8) | buf[13];
    uint8_t data_offset = (doff_flags >> 12) & 0xF;
    // Reconstruct flags: fin + syn*2 + rst*4 + psh*8 + ack*16 + urg*32 + ece*64 + cwr*128
    tcp.flags = doff_flags & 0x1FF; // lower 9 bits (ns + standard 8 flags)
    // Actually the YAML computes: fin + syn*2 + rst*4 + psh*8 + ack*16 + urg*32 + ece*64 + cwr*128
    // which is just the lower 8 bits of the TCP flags field
    tcp.flags = doff_flags & 0xFF;

    tcp.win = (buf[14] << 8) | buf[15];
    // checksum at [16..17]
    tcp.urgent = (buf[18] << 8) | buf[19];

    size_t header_length = static_cast<size_t>(data_offset) * 4;
    if (header_length < 20) header_length = 20;
    if (header_length > len) header_length = len;

    // Capture TCP options (data_offset > 5 means options present)
    if (header_length > 20) {
        tcp.options.assign(reinterpret_cast<const char*>(buf + 20), header_length - 20);
    }

    int64_t app_len = 0;
    if (header_length < remaining) {
        app_len = static_cast<int64_t>(remaining - header_length);
    }
    pkt.trans_len = static_cast<int64_t>(header_length) + app_len;
    pkt.app_len = app_len;

    // Store raw TCP payload
    if (app_len > 0) {
        const uint8_t* payload = buf + header_length;
        pkt._raw_tcp_payload.assign(
            reinterpret_cast<const char*>(payload), static_cast<size_t>(app_len));
    }

    // TLS heuristic: check payload for TLS record header
    std::string next;
    if (app_len >= 5) {
        const uint8_t* payload = buf + header_length;
        uint8_t ct = payload[0];
        if ((ct == 0x14 || ct == 0x15 || ct == 0x16 || ct == 0x17) &&
            payload[1] == 3 && payload[2] <= 4) {
            next = "tls_stream";
        }
    }
    if (next.empty()) next = yaml_next_protocol_lookup("tcp", tcp.dport);
    if (next.empty()) next = yaml_next_protocol_lookup("tcp", tcp.sport);
    return {header_length, std::move(next)};
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_udp(
    const uint8_t* buf, size_t len, size_t remaining, NativeParsedPacket& pkt) const
{
    if (len < 8) return {};
    pkt.has_udp = true;
    auto& udp = pkt.udp;

    udp.sport = (buf[0] << 8) | buf[1];
    udp.dport = (buf[2] << 8) | buf[3];
    udp.len = (buf[4] << 8) | buf[5];
    pkt.trans_len = udp.len;
    // checksum at [6..7]

    int64_t app_len = 0;
    if (8 < remaining) {
        app_len = static_cast<int64_t>(remaining - 8);
    }
    pkt.app_len = app_len;

    // Hardcoded well-known ports + YAML fallback for custom protocols
    std::string next;
    switch (udp.dport) {
        case 53: next = "dns"; break;
        case 4789: next = "vxlan"; break;
        case 67: next = "dhcp"; break;
        case 68: next = "dhcp"; break;
        case 546: next = "dhcpv6"; break;
        case 547: next = "dhcpv6"; break;
    }
    if (next.empty()) {
        switch (udp.sport) {
            case 53: next = "dns"; break;
            case 67: next = "dhcp"; break;
            case 68: next = "dhcp"; break;
            case 546: next = "dhcpv6"; break;
            case 547: next = "dhcpv6"; break;
        }
    }

    // QUIC heuristic: check UDP payload for IETF QUIC Long Header
    // (bit 7=1, followed by a known QUIC version)
    if (next.empty() && app_len >= 5) {
        const uint8_t* payload = buf + 8;
        if ((payload[0] & 0x80) != 0) {
            uint32_t ver = (static_cast<uint32_t>(payload[1]) << 24) |
                           (static_cast<uint32_t>(payload[2]) << 16) |
                           (static_cast<uint32_t>(payload[3]) << 8)  |
                           static_cast<uint32_t>(payload[4]);
            if (is_quic_version(ver)) {
                next = "quic";
            }
        }
    }

    if (next.empty()) next = yaml_next_protocol_lookup("udp", udp.dport);
    if (next.empty()) next = yaml_next_protocol_lookup("udp", udp.sport);
    return {8, std::move(next)};
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_arp(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    // Standard ARP for IPv4 over Ethernet: 28 bytes
    if (len < 28) return {};
    pkt.has_arp = true;
    auto& arp = pkt.arp;

    arp.hw_type    = (buf[0] << 8) | buf[1];
    arp.proto_type = (buf[2] << 8) | buf[3];
    // hw_size = buf[4], proto_size = buf[5]
    arp.opcode     = (buf[6] << 8) | buf[7];
    arp.sender_mac = util::format_mac(buf + 8);
    arp.sender_ip  = util::format_ipv4(buf + 14);
    arp.target_mac = util::format_mac(buf + 18);
    arp.target_ip  = util::format_ipv4(buf + 24);

    return {28, ""};  // ARP is a leaf protocol
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_icmp(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 4) return {};
    pkt.has_icmp = true;
    auto& icmp = pkt.icmp;

    icmp.type     = buf[0];
    icmp.code     = buf[1];
    icmp.checksum = (buf[2] << 8) | buf[3];
    if (len > 4) {
        icmp.rest_data.assign(reinterpret_cast<const char*>(buf + 4), len - 4);
    }

    return {len, ""};  // ICMP is a leaf protocol
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_icmpv6(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 4) return {};
    pkt.has_icmp6 = true;
    auto& icmp6 = pkt.icmp6;

    icmp6.type     = buf[0];
    icmp6.code     = buf[1];
    icmp6.checksum = (buf[2] << 8) | buf[3];
    if (len > 4) {
        icmp6.rest_data.assign(reinterpret_cast<const char*>(buf + 4), len - 4);
    }

    return {len, ""};  // ICMPv6 is a leaf protocol
}

// ── VLAN (802.1Q): 4 bytes ──

ProtocolEngine::FastResult ProtocolEngine::fast_parse_vlan(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 4) return {};
    pkt.has_vlan = true;
    auto& v = pkt.vlan;

    uint16_t tci = util::read_u16_be(buf);
    v.priority   = (tci >> 13) & 0x07;
    v.dei        = (tci >> 12) & 0x01;
    v.vlan_id    = tci & 0x0FFF;
    v.ether_type = util::read_u16_be(buf + 2);

    // next_protocol from ether_type
    std::string next;
    switch (v.ether_type) {
        case 0x0800: next = "ipv4"; break;
        case 0x86DD: next = "ipv6"; break;
        case 0x0806: next = "arp";  break;
        case 0x8100: next = "vlan"; break;  // Q-in-Q
        case 0x8847: next = "mpls"; break;
        case 0x8848: next = "mpls"; break;
    }
    if (next.empty()) next = yaml_next_protocol_lookup("vlan", v.ether_type);
    return {4, std::move(next)};
}

// ── Linux SLL (cooked capture v1): 16 bytes ──

ProtocolEngine::FastResult ProtocolEngine::fast_parse_sll(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 16) return {};
    pkt.has_sll = true;
    auto& s = pkt.sll;

    s.packet_type = util::read_u16_be(buf);
    s.arphrd_type = util::read_u16_be(buf + 2);
    uint16_t addr_len = util::read_u16_be(buf + 4);
    if (addr_len > 8) addr_len = 8;
    s.addr = util::format_hex(buf + 6, addr_len);
    s.protocol = util::read_u16_be(buf + 14);

    std::string next;
    switch (s.protocol) {
        case 0x0800: next = "ipv4"; break;
        case 0x86DD: next = "ipv6"; break;
        case 0x0806: next = "arp";  break;
    }
    if (next.empty()) next = yaml_next_protocol_lookup("linux_sll", s.protocol);
    return {16, std::move(next)};
}

// ── Linux SLL2 (cooked capture v2): 20 bytes ──

ProtocolEngine::FastResult ProtocolEngine::fast_parse_sll2(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 20) return {};
    pkt.has_sll2 = true;
    auto& s = pkt.sll2;

    s.protocol_type   = util::read_u16_be(buf);
    s.interface_index  = util::read_u32_be(buf + 4);
    s.arphrd_type     = util::read_u16_be(buf + 8);
    s.packet_type     = buf[10];
    uint8_t addr_len  = buf[11];
    if (addr_len > 8) addr_len = 8;
    s.addr = util::format_hex(buf + 12, addr_len);

    std::string next;
    switch (s.protocol_type) {
        case 0x0800: next = "ipv4"; break;
        case 0x86DD: next = "ipv6"; break;
        case 0x0806: next = "arp";  break;
    }
    if (next.empty()) next = yaml_next_protocol_lookup("linux_sll2", s.protocol_type);
    return {20, std::move(next)};
}

// ── fill_vlan: slow-path fill from FieldMap ──

void ProtocolEngine::fill_vlan(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_vlan = true;
    auto& v = pkt.vlan;
    for (auto& [k, val] : fm) {
        if (k == "vlan_id")    v.vlan_id    = field_to_int(val);
        else if (k == "priority") v.priority = field_to_int(val);
        else if (k == "dei")      v.dei      = field_to_int(val);
        else if (k == "ether_type") v.ether_type = field_to_int(val);
    }
}

// ── fill_sll: slow-path fill from FieldMap ──

void ProtocolEngine::fill_sll(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_sll = true;
    auto& s = pkt.sll;
    for (auto& [k, val] : fm) {
        if (k == "packet_type")    s.packet_type = field_to_int(val);
        else if (k == "arphrd_type") s.arphrd_type = field_to_int(val);
        else if (k == "protocol")    s.protocol    = field_to_int(val);
        else if (k == "addr") {
            // addr from YAML is bytes; convert to hex string
            if (auto* bv = std::get_if<std::vector<uint8_t>>(&val)) {
                s.addr = util::format_hex(bv->data(), bv->size());
            } else if (auto* sv = std::get_if<std::string>(&val)) {
                s.addr = *sv;
            }
        }
    }
}

// ── fill_sll2: slow-path fill from FieldMap ──

void ProtocolEngine::fill_sll2(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_sll2 = true;
    auto& s = pkt.sll2;
    for (auto& [k, val] : fm) {
        if (k == "protocol_type")      s.protocol_type   = field_to_int(val);
        else if (k == "interface_index") s.interface_index = field_to_int(val);
        else if (k == "arphrd_type")     s.arphrd_type    = field_to_int(val);
        else if (k == "packet_type")     s.packet_type    = field_to_int(val);
        else if (k == "addr") {
            if (auto* bv = std::get_if<std::vector<uint8_t>>(&val)) {
                s.addr = util::format_hex(bv->data(), bv->size());
            } else if (auto* sv = std::get_if<std::string>(&val)) {
                s.addr = *sv;
            }
        }
    }
}

// ── GRE (Generic Routing Encapsulation): 4+ bytes ──
// RFC 2784 / RFC 2890
// Flags: C (bit 15) = checksum present, K (bit 13) = key present, S (bit 12) = sequence present
// Header: 2 bytes flags+version, 2 bytes protocol_type, then optional fields

ProtocolEngine::FastResult ProtocolEngine::fast_parse_gre(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 4) return {};
    pkt.has_gre = true;
    auto& g = pkt.gre;

    uint16_t flags_ver = util::read_u16_be(buf);
    g.flags = flags_ver;
    g.protocol_type = util::read_u16_be(buf + 2);

    bool c_bit = (flags_ver & 0x8000) != 0;  // bit 15: checksum
    bool k_bit = (flags_ver & 0x2000) != 0;  // bit 13: key
    bool s_bit = (flags_ver & 0x1000) != 0;  // bit 12: sequence

    size_t offset = 4;

    if (c_bit) {
        if (offset + 4 > len) return {offset, ""};
        g.checksum = util::read_u16_be(buf + offset);
        g.has_checksum = true;
        offset += 4;  // checksum (2) + reserved1 (2)
    }
    if (k_bit) {
        if (offset + 4 > len) return {offset, ""};
        g.key = util::read_u32_be(buf + offset);
        g.has_key = true;
        offset += 4;
    }
    if (s_bit) {
        if (offset + 4 > len) return {offset, ""};
        g.sequence = util::read_u32_be(buf + offset);
        g.has_sequence = true;
        offset += 4;
    }

    // Dispatch inner protocol by ether_type
    std::string next;
    switch (g.protocol_type) {
    case 0x0800: next = "ipv4"; break;
    case 0x86DD: next = "ipv6"; break;
    case 0x6558: next = "ethernet"; break;  // Transparent Ethernet Bridging
    case 0x0806: next = "arp"; break;
    case 0x8847: next = "mpls"; break;
    case 0x8848: next = "mpls"; break;
    }
    if (next.empty()) next = yaml_next_protocol_lookup("gre", g.protocol_type);
    return {offset, std::move(next)};
}

// ── fill_gre: slow-path fill from FieldMap ──

void ProtocolEngine::fill_gre(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_gre = true;
    auto& g = pkt.gre;
    for (auto& [k, val] : fm) {
        if (k == "flags")              g.flags = field_to_int(val);
        else if (k == "protocol_type") g.protocol_type = field_to_int(val);
        else if (k == "checksum")      { g.checksum = field_to_int(val); g.has_checksum = true; }
        else if (k == "key")           { g.key = field_to_int(val); g.has_key = true; }
        else if (k == "sequence")      { g.sequence = field_to_int(val); g.has_sequence = true; }
    }
}

// ── VXLAN (Virtual Extensible LAN): 8 bytes ──
// RFC 7348: flags (1) + reserved (3) + VNI (3) + reserved (1)
// Always chains to ethernet for the inner frame

ProtocolEngine::FastResult ProtocolEngine::fast_parse_vxlan(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 8) return {};
    pkt.has_vxlan = true;
    auto& v = pkt.vxlan;

    v.flags = buf[0];
    // bytes [1..3] reserved
    v.vni = (static_cast<int64_t>(buf[4]) << 16) |
            (static_cast<int64_t>(buf[5]) << 8) |
             static_cast<int64_t>(buf[6]);
    // byte [7] reserved

    return {8, "ethernet"};
}

// ── fill_vxlan: slow-path fill from FieldMap ──

void ProtocolEngine::fill_vxlan(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_vxlan = true;
    auto& v = pkt.vxlan;
    for (auto& [k, val] : fm) {
        if (k == "flags")    v.flags = field_to_int(val);
        else if (k == "vni") v.vni = field_to_int(val);
    }
}

// ── MPLS (Multi-Protocol Label Switching): 4 bytes per label entry ──
// Label stack: walk 4-byte entries until S-bit (bit 0 of byte 2) is set
// Then peek version nibble of inner payload for IPv4/IPv6

ProtocolEngine::FastResult ProtocolEngine::fast_parse_mpls(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 4) return {};
    pkt.has_mpls = true;
    auto& m = pkt.mpls;

    size_t offset = 0;
    int depth = 0;

    // Walk the label stack
    while (offset + 4 <= len) {
        uint32_t entry = util::read_u32_be(buf + offset);
        depth++;

        int64_t label = (entry >> 12) & 0xFFFFF;
        int64_t tc    = (entry >> 9) & 0x07;
        bool s_bit    = (entry >> 8) & 0x01;
        int64_t ttl   = entry & 0xFF;

        // Store bottom-of-stack entry fields
        m.label = label;
        m.tc = tc;
        m.ttl = ttl;
        m.bottom_of_stack = s_bit;

        offset += 4;

        if (s_bit) break;  // Bottom of stack reached
    }

    m.stack_depth = depth;

    // Peek inner payload version nibble
    std::string next;
    if (offset < len) {
        uint8_t version = (buf[offset] >> 4) & 0x0F;
        if (version == 4) next = "ipv4";
        else if (version == 6) next = "ipv6";
        // Could also be ethernet (pseudowire), but version nibble check handles common cases
    }

    return {offset, std::move(next)};
}

// ── fill_mpls: slow-path fill from FieldMap ──

void ProtocolEngine::fill_mpls(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_mpls = true;
    auto& m = pkt.mpls;
    for (auto& [k, val] : fm) {
        if (k == "label")            m.label = field_to_int(val);
        else if (k == "tc")          m.tc = field_to_int(val);
        else if (k == "ttl")         m.ttl = field_to_int(val);
        else if (k == "stack_depth") m.stack_depth = field_to_int(val);
        else if (k == "bottom_of_stack") m.bottom_of_stack = (field_to_int(val) != 0);
    }
}

// ── DHCP fast-path: 236-byte BOOTP header + 4-byte magic cookie + options_raw ──

ProtocolEngine::FastResult ProtocolEngine::fast_parse_dhcp(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    // Minimum: 236 (BOOTP) + 4 (magic cookie) = 240 bytes
    if (len < 240) return {};
    pkt.has_dhcp = true;
    auto& d = pkt.dhcp;

    d.op    = buf[0];
    d.htype = buf[1];
    // hlen = buf[2], hops = buf[3] — skipped
    d.xid   = util::read_u32_be(buf + 4);
    // secs = buf[8..9], flags = buf[10..11] — skipped

    d.ciaddr = util::format_ipv4(buf + 12);
    d.yiaddr = util::format_ipv4(buf + 16);
    d.siaddr = util::format_ipv4(buf + 20);
    d.giaddr = util::format_ipv4(buf + 24);
    d.chaddr = util::format_mac(buf + 28);
    // chaddr_padding(10) + sname(64) + file(128) = 202 bytes at offset 34
    // magic_cookie at offset 236

    // options_raw: everything after magic cookie
    if (len > 240) {
        d.options_raw.assign(buf + 240, buf + len);
    }

    return {len, ""};  // terminal protocol, no next
}

// ── DHCPv6 fast-path: 1-byte msg_type + 3-byte transaction_id + options_raw ──

ProtocolEngine::FastResult ProtocolEngine::fast_parse_dhcpv6(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 4) return {};
    pkt.has_dhcpv6 = true;
    auto& d = pkt.dhcpv6;

    d.msg_type = buf[0];
    d.transaction_id = (buf[1] << 16) | (buf[2] << 8) | buf[3];

    if (len > 4) {
        d.options_raw.assign(buf + 4, buf + len);
    }

    return {len, ""};  // terminal protocol, no next
}

// ── QUIC version constants ──
static const char* quic_version_str(uint32_t ver) {
    switch (ver) {
        case QUIC_V1: return "QUICv1";
        case QUIC_V2: return "QUICv2";
        default: return "unknown";
    }
}

static const char* quic_long_packet_type_str(int type) {
    switch (type) {
        case 0: return "Initial";
        case 1: return "0-RTT";
        case 2: return "Handshake";
        case 3: return "Retry";
        default: return "unknown";
    }
}

ProtocolEngine::FastResult ProtocolEngine::fast_parse_quic(
    const uint8_t* buf, size_t len, NativeParsedPacket& pkt) const
{
    if (len < 5) return {};

    uint8_t first = buf[0];
    bool is_long = (first & 0x80) != 0;

    if (is_long) {
        // Long Header: 1 byte header + 4 bytes version + DCID len + DCID + SCID len + SCID
        if (len < 7) return {};  // minimum: 1 + 4 + 1 + 0 + 1 + 0

        uint32_t version = (static_cast<uint32_t>(buf[1]) << 24) |
                           (static_cast<uint32_t>(buf[2]) << 16) |
                           (static_cast<uint32_t>(buf[3]) << 8)  |
                           static_cast<uint32_t>(buf[4]);

        if (!is_quic_version(version)) return {};  // not QUIC, let other parsers handle it

        pkt.has_quic = true;
        auto& q = pkt.quic;
        q.is_long_header = true;
        q.version = version;
        q.version_str = quic_version_str(version);

        // Packet type: bits 4-5 of first byte (for v1)
        q.packet_type = (first >> 4) & 0x03;
        q.packet_type_str = quic_long_packet_type_str(q.packet_type);

        size_t offset = 5;

        // DCID
        if (offset >= len) return {offset, ""};
        q.dcid_len = buf[offset++];
        if (offset + q.dcid_len > len) return {offset, ""};
        q.dcid.assign(reinterpret_cast<const char*>(buf + offset), q.dcid_len);
        offset += q.dcid_len;

        // SCID
        if (offset >= len) return {offset, ""};
        q.scid_len = buf[offset++];
        if (offset + q.scid_len > len) return {offset, ""};
        q.scid.assign(reinterpret_cast<const char*>(buf + offset), q.scid_len);
        offset += q.scid_len;

        // Initial packet: token length + token + decryption
        if (q.packet_type == 0) {
            // Token length is a variable-length integer
            if (offset >= len) return {offset, ""};
            uint8_t first_token_byte = buf[offset];
            uint8_t prefix = first_token_byte >> 6;
            uint64_t token_len = 0;

            if (prefix == 0) {
                token_len = first_token_byte & 0x3f;
                offset += 1;
            } else if (prefix == 1) {
                if (offset + 2 > len) return {offset, ""};
                token_len = ((static_cast<uint64_t>(first_token_byte) & 0x3f) << 8) |
                            buf[offset + 1];
                offset += 2;
            } else if (prefix == 2) {
                if (offset + 4 > len) return {offset, ""};
                token_len = ((static_cast<uint64_t>(first_token_byte) & 0x3f) << 24) |
                            (static_cast<uint64_t>(buf[offset + 1]) << 16) |
                            (static_cast<uint64_t>(buf[offset + 2]) << 8) |
                            buf[offset + 3];
                offset += 4;
            } else {
                if (offset + 8 > len) return {offset, ""};
                token_len = ((static_cast<uint64_t>(first_token_byte) & 0x3f) << 56) |
                            (static_cast<uint64_t>(buf[offset + 1]) << 48) |
                            (static_cast<uint64_t>(buf[offset + 2]) << 40) |
                            (static_cast<uint64_t>(buf[offset + 3]) << 32) |
                            (static_cast<uint64_t>(buf[offset + 4]) << 24) |
                            (static_cast<uint64_t>(buf[offset + 5]) << 16) |
                            (static_cast<uint64_t>(buf[offset + 6]) << 8) |
                            buf[offset + 7];
                offset += 8;
            }

            q.token_len = static_cast<int64_t>(token_len);
            if (token_len > 0 && offset + token_len <= len) {
                q.token.assign(reinterpret_cast<const char*>(buf + offset), token_len);
                offset += token_len;
            }

            // Attempt Initial packet decryption to extract CRYPTO fragments
            auto decrypt_result = quic_crypto::decrypt_initial_packet(buf, len);
            if (decrypt_result.success && !decrypt_result.plaintext.empty()) {
                // Extract CRYPTO frame fragments (offset, data) pairs
                auto frags = quic_crypto::extract_crypto_fragments(
                    decrypt_result.plaintext.data(), decrypt_result.plaintext.size());
                q.crypto_fragments = std::move(frags);
            }
        }

        return {len, ""};  // terminal protocol
    } else {
        // Short Header: first byte bit 7 = 0
        // Consume all bytes but don't set has_quic — Python-side flow state
        // handler (_handle_quic_flow_state) will parse Short Headers using
        // DCID length learned from prior Long Header packets.
        return {len, ""};
    }
}

void ProtocolEngine::fill_quic(NativeParsedPacket& pkt, const FieldMap& fm) const {
    pkt.has_quic = true;
    auto& q = pkt.quic;
    for (auto& [key, val] : fm) {
        if (key == "is_long_header") q.is_long_header = field_to_int(val) != 0;
        else if (key == "packet_type") q.packet_type = field_to_int(val);
        else if (key == "version") q.version = field_to_int(val);
        else if (key == "dcid") q.dcid = field_to_string(val);
        else if (key == "scid") q.scid = field_to_string(val);
        else if (key == "dcid_len") q.dcid_len = field_to_int(val);
        else if (key == "scid_len") q.scid_len = field_to_int(val);
        else if (key == "token") q.token = field_to_string(val);
        else if (key == "token_len") q.token_len = field_to_int(val);
        else if (key == "spin_bit") q.spin_bit = field_to_int(val) != 0;
        else if (key == "sni") q.sni = field_to_string(val);
        else if (key == "version_str") q.version_str = field_to_string(val);
        else if (key == "packet_type_str") q.packet_type_str = field_to_string(val);
    }
}
// ── parse_packet_struct: structured output path ──

NativeParsedPacket ProtocolEngine::parse_packet_struct(
    const uint8_t* buf, size_t len, uint32_t link_type, bool save_raw_bytes,
    int app_layer_mode) const
{
    auto pkt_start = std::chrono::high_resolution_clock::now();

    NativeParsedPacket pkt;
    pkt.link_layer_type = static_cast<int64_t>(link_type);

    auto& lt_cfg = loader_.link_types();
    auto it = lt_cfg.dlt_to_protocol.find(static_cast<int>(link_type));
    if (it == lt_cfg.dlt_to_protocol.end()) return pkt;

    std::string current_proto = it->second;
    const uint8_t* cur = buf;
    size_t remaining = len;
    int max_layers = 16;

    // Only collect TLS layers (most packets don't have TLS at all)
    std::map<std::string, FieldMap> tls_layers;
    bool has_tls = false;
    int64_t app_len_val = 0;

    // app_layer_mode gate: applied after transport layer (tcp/udp) resolves next_protocol
    // 0=full: no filtering
    // 1=fast: only allow protocols with fast_dispatch_ entries
    // 2=port_only: same as fast, plus suppress heuristic-detected protocols (tls_stream)
    // 3=none: suppress all post-transport chaining
    bool after_transport = false;

    while (!current_proto.empty() && remaining > 0 && max_layers-- > 0) {
        // Track when we've just parsed a transport layer
        bool is_transport = (current_proto == "tcp" || current_proto == "udp");

        // Fast path: table-driven dispatch into struct
        bool used_fast_path = false;
        auto fast_it = fast_dispatch_.find(current_proto);
        if (fast_it != fast_dispatch_.end()) {
            auto fr = fast_it->second(cur, remaining, remaining, pkt);
            if (fr.bytes_consumed > 0 || !fr.next_protocol.empty()) {
                used_fast_path = true;
                if (fr.bounds_remaining && static_cast<size_t>(pkt.ip_len) < remaining) {
                    remaining = static_cast<size_t>(pkt.ip_len);
                }
                if (g_profiling_enabled) {
                    g_prof.total_layers.fetch_add(1, std::memory_order_relaxed);
                }
                cur += fr.bytes_consumed;
                remaining -= fr.bytes_consumed;

                // Apply app_layer_mode gate after transport layer
                if (is_transport) after_transport = true;
                if (after_transport && !fr.next_protocol.empty() && app_layer_mode > 0) {
                    if (app_layer_mode == 2) {
                        // none: stop all post-transport chaining
                        fr.next_protocol.clear();
                    } else if (app_layer_mode == 1) {
                        // port_only: suppress heuristic + non-fast-dispatch protocols
                        if (fr.next_protocol == "tls_stream") {
                            fr.next_protocol.clear();
                        }
                        if (!fr.next_protocol.empty() &&
                            fast_dispatch_.find(fr.next_protocol) == fast_dispatch_.end()) {
                            fr.next_protocol.clear();
                        }
                    }
                }

                current_proto = std::move(fr.next_protocol);
                continue;
            }
        }

        // Slow path: generic YAML-driven parse_layer + fill_struct
        auto pl_start = std::chrono::high_resolution_clock::now();
        auto pr = parse_layer(current_proto, cur, remaining, buf, len);
        auto pl_end = std::chrono::high_resolution_clock::now();

        if (g_profiling_enabled) {
            g_prof.parse_layer_ns.fetch_add(
                std::chrono::duration_cast<std::chrono::nanoseconds>(pl_end - pl_start).count(),
                std::memory_order_relaxed);
            g_prof.total_layers.fetch_add(1, std::memory_order_relaxed);
        }

        // Handle total_length_field bounding
        auto* proto_def = loader_.get_protocol(current_proto);
        if (proto_def && !proto_def->total_length_field.empty()) {
            auto tl_it = pr.fields.find(proto_def->total_length_field);
            if (tl_it != pr.fields.end()) {
                size_t total_len = static_cast<size_t>(field_to_int(tl_it->second));
                if (total_len < remaining) {
                    remaining = total_len;
                }
            }
        }

        // Fill struct: table-driven dispatch
        auto fill_start = std::chrono::high_resolution_clock::now();

        auto fill_it = fill_dispatch_.find(current_proto);
        if (fill_it != fill_dispatch_.end()) {
            SlowFillContext ctx{pkt, pr.fields, cur, pr.bytes_consumed, remaining,
                                has_tls, tls_layers, current_proto};
            fill_it->second(ctx);
        } else {
            // Unknown protocol — store in extra_layers for Python-side handling
            pkt.extra_layers[current_proto] = std::move(pr.fields);
        }

        if (g_profiling_enabled) {
            auto fill_end = std::chrono::high_resolution_clock::now();
            g_prof.fill_struct_ns.fetch_add(
                std::chrono::duration_cast<std::chrono::nanoseconds>(fill_end - fill_start).count(),
                std::memory_order_relaxed);
        }

        cur += pr.bytes_consumed;
        remaining -= pr.bytes_consumed;

        // Apply app_layer_mode gate after transport layer (slow path)
        if (is_transport) after_transport = true;
        if (after_transport && !pr.next_protocol.empty() && app_layer_mode > 0) {
            if (app_layer_mode == 2) {
                pr.next_protocol.clear();
            } else if (app_layer_mode == 1) {
                if (pr.next_protocol == "tls_stream") {
                    pr.next_protocol.clear();
                }
                if (!pr.next_protocol.empty() &&
                    fast_dispatch_.find(pr.next_protocol) == fast_dispatch_.end()) {
                    pr.next_protocol.clear();
                }
            }
        }

        current_proto = pr.next_protocol;
    }

    // Fill TLS only when TLS layers were actually seen
    if (has_tls) {
        auto tls_fill_start = std::chrono::high_resolution_clock::now();
        fill_tls(pkt, tls_layers);
        if (g_profiling_enabled) {
            auto tls_fill_end = std::chrono::high_resolution_clock::now();
            g_prof.fill_struct_ns.fetch_add(
                std::chrono::duration_cast<std::chrono::nanoseconds>(tls_fill_end - tls_fill_start).count(),
                std::memory_order_relaxed);
        }
    }

    if (save_raw_bytes) {
        pkt.raw_data.assign(reinterpret_cast<const char*>(buf), len);
    }

    if (g_profiling_enabled) {
        auto pkt_end = std::chrono::high_resolution_clock::now();
        g_prof.total_ns.fetch_add(
            std::chrono::duration_cast<std::chrono::nanoseconds>(pkt_end - pkt_start).count(),
            std::memory_order_relaxed);
        g_prof.total_packets.fetch_add(1, std::memory_order_relaxed);
    }

    return pkt;
}

// ── parse_from_protocol_struct: parse starting from a named protocol ──

NativeParsedPacket ProtocolEngine::parse_from_protocol_struct(
    const uint8_t* buf, size_t len, const std::string& start_protocol) const
{
    NativeParsedPacket pkt;

    std::string current_proto = start_protocol;
    const uint8_t* cur = buf;
    size_t remaining = len;
    int max_layers = 16;

    std::map<std::string, FieldMap> tls_layers;
    bool has_tls = false;

    while (!current_proto.empty() && remaining > 0 && max_layers-- > 0) {
        auto pr = parse_layer(current_proto, cur, remaining, buf, len);

        auto* proto_def = loader_.get_protocol(current_proto);
        if (proto_def && !proto_def->total_length_field.empty()) {
            auto tl_it = pr.fields.find(proto_def->total_length_field);
            if (tl_it != pr.fields.end()) {
                size_t total_len = static_cast<size_t>(field_to_int(tl_it->second));
                if (total_len < remaining) {
                    remaining = total_len;
                }
            }
        }

        if (current_proto == "tls_record" || current_proto == "tls_handshake" ||
            current_proto == "tls_client_hello" || current_proto == "tls_server_hello" ||
            current_proto == "tls_certificate" || current_proto == "tls_stream") {
            has_tls = true;
            tls_layers[current_proto] = std::move(pr.fields);
        }

        cur += pr.bytes_consumed;
        remaining -= pr.bytes_consumed;
        current_proto = pr.next_protocol;
    }

    if (has_tls) {
        fill_tls(pkt, tls_layers);
    }

    return pkt;
}

NativeParsedPacket NativeParser::parse_tls_record(py::bytes buf) {
    std::string data = buf;
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data.data());
    size_t len = data.size();

    // Parse via tls_stream protocol (repeat primitive with merge=tls)
    auto pr = engine_.parse_layer("tls_stream", ptr, len, ptr, len);

    NativeParsedPacket pkt;
    extract_tls_from_repeat_fields(pr.fields, pkt);
    return pkt;
}
