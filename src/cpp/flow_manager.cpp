#include "flow_manager.h"
#include "pcap_reader.h"
#include "protocol_engine.h"
#include "bpf_filter.h"
#include <algorithm>
#include <cstring>

ProcessStats process_file(
    const std::string& pcap_path,
    const ProtocolEngine& engine,
    const NativeFilter* filter,
    const ProcessConfig& config,
    NativeFlowManager& flow_manager)
{
    ProcessStats stats;

    NativePcapReader reader(pcap_path);
    reader.open();

    bool filter_can_raw = filter ? filter->can_match_raw() : false;

    while (true) {
        auto view = reader.next_view();
        if (!view.has_value()) break;

        stats.packets_processed++;

        const uint8_t* buf = view->data;
        size_t len = view->caplen;
        uint32_t link_type = view->link_type;

        // BPF pre-filter on raw bytes
        if (filter && filter_can_raw) {
            if (!filter->matches_raw(buf, len, link_type)) {
                stats.packets_filtered++;
                continue;
            }
        }

        // Parse packet to C++ struct
        NativeParsedPacket pkt = engine.parse_packet_struct(
            buf, len, link_type, config.save_raw_bytes, config.app_layer_mode);

        // Set metadata from pcap
        pkt.timestamp = view->timestamp;
        pkt.caplen = static_cast<int64_t>(view->caplen);
        pkt.wirelen = static_cast<int64_t>(view->wirelen);

        // Store raw bytes for QUIC Short Header parsing
        // Only needed if flow might be QUIC and we need to parse Short Headers
        if (pkt.has_udp && pkt._raw_bytes.empty()) {
            pkt._raw_bytes.assign(buf, buf + len);
        }

        // ACK/RST filter
        if (should_filter_packet(pkt, config.filter_ack, config.filter_rst)) {
            stats.packets_filtered++;
            continue;
        }

        // Get or create flow
        NativeFlow* flow = flow_manager.get_or_create(pkt);
        if (!flow) continue;

        // Determine direction for retransmission check and TCP state
        std::string pkt_src_ip;
        uint16_t pkt_src_port = 0;
        if (pkt.has_ip) {
            pkt_src_ip = pkt.ip.src;
        } else if (pkt.has_ip6) {
            pkt_src_ip = pkt.ip6.src;
        }
        if (pkt.has_tcp) {
            pkt_src_port = static_cast<uint16_t>(pkt.tcp.sport);
        } else if (pkt.has_udp) {
            pkt_src_port = static_cast<uint16_t>(pkt.udp.sport);
        }
        int dir = flow->key.direction(pkt_src_ip, pkt_src_port);

        // TCP retransmission detection
        if (pkt.has_tcp) {
            bool is_retrans = check_retransmission(pkt, *flow, dir);
            if (is_retrans) {
                flow->metrics.retrans_count++;
                if (config.filter_retrans) {
                    stats.packets_filtered++;
                    continue;
                }
            }
        }

        // TCP state machine
        if (pkt.has_tcp) {
            flow->update_tcp_state(pkt, dir);
        }

        // QUIC flow state handling
        handle_quic_flow_state(pkt, *flow);

        // Add packet to flow
        flow->add_packet(std::move(pkt));
    }

    reader.close();

    stats.flows_created = static_cast<int64_t>(flow_manager.total_flow_count());
    return stats;
}

// ── Protocol aggregation: first-wins merge across packets ──

// Helper: merge a string field (first non-empty wins)
static inline void merge_str(std::string& dst, const std::string& src) {
    if (dst.empty() && !src.empty()) dst = src;
}

AggregatedFlowInfo NativeFlow::aggregate() const {
    AggregatedFlowInfo info;

    // IP version from first packet
    if (!packets.empty()) {
        if (packets[0].has_ip) info.ip_version = 4;
        else if (packets[0].has_ip6) info.ip_version = 6;
    }

    for (const auto& pkt : packets) {
        // TLS aggregation
        if (pkt.has_tls) {
            if (!info.has_tls) {
                info.tls = pkt.tls;
                info.has_tls = true;
            } else {
                // First-wins merge: only fill empty/default fields
                auto& t = info.tls;
                const auto& s = pkt.tls;
                merge_str(t.version, s.version);
                if (t.content_type < 0 && s.content_type >= 0) t.content_type = s.content_type;
                if (t.handshake_type < 0 && s.handshake_type >= 0) t.handshake_type = s.handshake_type;
                merge_str(t.sni, s.sni);
                if (t.cipher_suites.empty() && !s.cipher_suites.empty()) t.cipher_suites = s.cipher_suites;
                if (t.cipher_suite < 0 && s.cipher_suite >= 0) t.cipher_suite = s.cipher_suite;
                if (t.alpn.empty() && !s.alpn.empty()) t.alpn = s.alpn;
                if (t.signature_algorithms.empty() && !s.signature_algorithms.empty()) t.signature_algorithms = s.signature_algorithms;
                if (t.supported_groups.empty() && !s.supported_groups.empty()) t.supported_groups = s.supported_groups;
                // Accumulate handshake_types from all packets
                for (auto ht : s.handshake_types) {
                    t.handshake_types.push_back(ht);
                }
                // Certificates: accumulate from all packets (rare in per-packet path)
                for (const auto& cert : s.certificates) {
                    t.certificates.push_back(cert);
                }
            }
        }

        // DNS aggregation
        if (pkt.has_dns) {
            if (!info.has_dns) {
                info.dns = pkt.dns;
                info.has_dns = true;
            } else {
                auto& d = info.dns;
                const auto& s = pkt.dns;
                // Accumulate unique query names from all packets
                for (const auto& q : s.queries) {
                    bool found = false;
                    for (const auto& existing : d.queries) {
                        if (existing == q) { found = true; break; }
                    }
                    if (!found) d.queries.push_back(q);
                }
                if (d.response_code == 0 && s.response_code != 0) d.response_code = s.response_code;
                // Merge counts from response packets (query has 0 answers)
                if (d.answer_count == 0 && s.answer_count != 0) d.answer_count = s.answer_count;
                if (d.authority_count == 0 && s.authority_count != 0) d.authority_count = s.authority_count;
                if (d.additional_count == 0 && s.additional_count != 0) d.additional_count = s.additional_count;
            }
        }

        // QUIC aggregation
        if (pkt.has_quic) {
            if (!info.has_quic) {
                info.quic = pkt.quic;
                info.has_quic = true;
                // SCID should only come from S2C (server) packets.
                // If first packet is C2S, clear SCID so it gets filled from server later.
                if (pkt.is_client_to_server) {
                    info.quic.scid.clear();
                    info.quic.scid_len = 0;
                }
            } else {
                auto& q = info.quic;
                const auto& s = pkt.quic;
                merge_str(q.sni, s.sni);
                if (q.alpn.empty() && !s.alpn.empty()) q.alpn = s.alpn;
                if (q.cipher_suites.empty() && !s.cipher_suites.empty()) q.cipher_suites = s.cipher_suites;
                // SCID: direction-aware — take from first S2C (server) packet
                if (q.scid.empty() && !s.scid.empty() && !pkt.is_client_to_server) {
                    q.scid = s.scid;
                    q.scid_len = s.scid_len;
                }
            }
            // Accumulate crypto_fragments from all packets
            if (!pkt.quic.crypto_fragments.empty()) {
                info.quic.crypto_fragments.insert(
                    info.quic.crypto_fragments.end(),
                    pkt.quic.crypto_fragments.begin(),
                    pkt.quic.crypto_fragments.end());
            }
        }
    }

    // Build extended protocol stack
    // IP layer
    if (info.ip_version == 4) info.ext_protocol.push_back("IPv4");
    else if (info.ip_version == 6) info.ext_protocol.push_back("IPv6");

    // Transport layer
    switch (key.protocol) {
        case 6:   info.ext_protocol.push_back("TCP"); break;
        case 17:  info.ext_protocol.push_back("UDP"); break;
        case 1:   info.ext_protocol.push_back("ICMP"); break;
        case 58:  info.ext_protocol.push_back("ICMPv6"); break;
        case 132: info.ext_protocol.push_back("SCTP"); break;
    }

    // Application layer
    if (info.has_tls) {
        info.ext_protocol.push_back("TLS");
        // Check ALPN for HTTPS indication
        for (const auto& a : info.tls.alpn) {
            std::string lower = a;
            for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower == "h2" || lower == "http/1.1" || lower == "http/1.0" ||
                lower == "http/0.9" || lower == "http" || lower.substr(0, 5) == "http/") {
                info.ext_protocol.push_back("HTTPS");
                break;
            }
        }
    }
    if (info.has_dns) info.ext_protocol.push_back("DNS");
    if (info.has_quic) info.ext_protocol.push_back("QUIC");

    return info;
}

// ── TLS stream reassembly ──

// Helper: first-wins merge of NativeTLSInfo into aggregated TLS
static void merge_tls_first_wins(NativeTLSInfo& dst, const NativeTLSInfo& src) {
    merge_str(dst.version, src.version);
    if (dst.content_type < 0 && src.content_type >= 0) dst.content_type = src.content_type;
    if (dst.handshake_type < 0 && src.handshake_type >= 0) dst.handshake_type = src.handshake_type;
    merge_str(dst.sni, src.sni);
    if (dst.cipher_suites.empty() && !src.cipher_suites.empty()) dst.cipher_suites = src.cipher_suites;
    if (dst.cipher_suite < 0 && src.cipher_suite >= 0) dst.cipher_suite = src.cipher_suite;
    if (dst.alpn.empty() && !src.alpn.empty()) dst.alpn = src.alpn;
    if (dst.signature_algorithms.empty() && !src.signature_algorithms.empty()) dst.signature_algorithms = src.signature_algorithms;
    if (dst.supported_groups.empty() && !src.supported_groups.empty()) dst.supported_groups = src.supported_groups;
}

// Helper: extract raw DER certificates from a TLS Certificate handshake record
static void extract_certs_from_record(const uint8_t* record, size_t record_len,
                                       std::vector<std::string>& certs) {
    if (record_len < 5) return;
    const uint8_t* body = record + 5;  // skip TLS record header
    size_t body_len = record_len - 5;

    size_t off = 0;
    while (off + 4 <= body_len) {
        uint8_t hs_type = body[off];
        uint32_t hs_len = (static_cast<uint32_t>(body[off + 1]) << 16) |
                          (static_cast<uint32_t>(body[off + 2]) << 8) |
                          static_cast<uint32_t>(body[off + 3]);
        if (off + 4 + hs_len > body_len) break;

        if (hs_type == 11 && hs_len >= 3) {  // Certificate
            const uint8_t* hs_body = body + off + 4;
            uint32_t certs_len = (static_cast<uint32_t>(hs_body[0]) << 16) |
                                 (static_cast<uint32_t>(hs_body[1]) << 8) |
                                 static_cast<uint32_t>(hs_body[2]);
            size_t coff = 3;
            while (coff + 3 <= 3 + certs_len && coff + 3 <= hs_len) {
                uint32_t cert_len = (static_cast<uint32_t>(hs_body[coff]) << 16) |
                                    (static_cast<uint32_t>(hs_body[coff + 1]) << 8) |
                                    static_cast<uint32_t>(hs_body[coff + 2]);
                coff += 3;
                if (coff + cert_len > hs_len) break;
                certs.emplace_back(reinterpret_cast<const char*>(hs_body + coff), cert_len);
                coff += cert_len;
            }
        }
        off += 4 + hs_len;
    }
}

void NativeFlow::reassemble_tls(const ProtocolEngine& engine, AggregatedFlowInfo& info) const {
    if (packets.empty() || key.protocol != 6) return;

    // Check if this is a TLS-relevant flow
    uint16_t dport = key.dst_port;
    uint16_t sport = key.src_port;
    bool has_tls = (dport == 443 || dport == 465 || dport == 993 || dport == 995 || dport == 5061 ||
                    sport == 443 || sport == 465 || sport == 993 || sport == 995 || sport == 5061);
    has_tls = has_tls || info.has_tls;

    if (!has_tls) {
        for (const auto& pkt : packets) {
            if (pkt.has_tls) { has_tls = true; break; }
        }
    }
    if (!has_tls) return;

    // Clear aggregated TLS from single-packet parse — reassembly will rebuild it
    info.has_tls = false;
    info.tls = NativeTLSInfo();

    // Per-direction incomplete data buffers
    std::string buf_fwd, buf_rev;
    // ChangeCipherSpec skip state per direction
    bool ccs_skip_fwd = false, ccs_skip_rev = false;

    const std::string& src_ip = key.src_ip;
    uint16_t src_port_key = key.src_port;

    for (const auto& cpkt : packets) {
        const std::string& tcp_data = cpkt._raw_tcp_payload;
        if (tcp_data.empty() || !cpkt.has_tcp) continue;

        // Determine direction
        std::string pkt_src_ip;
        if (cpkt.has_ip) pkt_src_ip = cpkt.ip.src;
        else if (cpkt.has_ip6) pkt_src_ip = cpkt.ip6.src;
        uint16_t pkt_src_port = static_cast<uint16_t>(cpkt.tcp.sport);
        bool is_forward = (pkt_src_ip == src_ip && pkt_src_port == src_port_key);

        std::string& buf = is_forward ? buf_fwd : buf_rev;
        bool& ccs_skip = is_forward ? ccs_skip_fwd : ccs_skip_rev;

        buf.append(tcp_data);

        const uint8_t* full = reinterpret_cast<const uint8_t*>(buf.data());
        size_t full_len = buf.size();
        size_t offset = 0;

        while (offset + 5 <= full_len) {
            uint8_t content_type = full[offset];
            if (content_type != 20 && content_type != 21 &&
                content_type != 22 && content_type != 23) break;

            uint16_t record_len = (static_cast<uint16_t>(full[offset + 3]) << 8) |
                                   static_cast<uint16_t>(full[offset + 4]);
            if (record_len > 16384 + 256) break;
            if (offset + 5 + record_len > full_len) break;

            if (content_type == 20) {  // ChangeCipherSpec
                ccs_skip = true;
            } else if (content_type == 22) {  // Handshake
                const uint8_t* record_start = full + offset;
                size_t total_record_len = 5 + record_len;

                bool should_parse = true;
                if (ccs_skip) {
                    const uint8_t* body = full + offset + 5;
                    bool is_valid_hs = (record_len >= 4) &&
                        ((static_cast<uint32_t>(body[1]) << 16) |
                         (static_cast<uint32_t>(body[2]) << 8) |
                         static_cast<uint32_t>(body[3])) == static_cast<uint32_t>(record_len - 4);
                    ccs_skip = false;
                    if (!is_valid_hs) should_parse = false;
                }

                if (should_parse) {
                    NativeParsedPacket result = engine.parse_tls_record_raw(
                        record_start, total_record_len);

                    if (result.has_tls) {
                        if (!info.has_tls) {
                            info.tls = result.tls;
                            info.has_tls = true;
                        } else {
                            merge_tls_first_wins(info.tls, result.tls);
                        }

                        // Extract certificates from Certificate handshake (type 11)
                        bool has_cert = false;
                        for (auto ht : result.tls.handshake_types) {
                            if (ht == 11) { has_cert = true; break; }
                        }
                        if (has_cert) {
                            extract_certs_from_record(record_start, total_record_len,
                                                      info.tls.certificates);
                        }
                    }
                }
            } else if (content_type == 23) {  // Application Data
                if (!info.has_tls) {
                    info.tls.content_type = 23;
                    info.has_tls = true;
                }
            }

            offset += 5 + record_len;
        }

        // Keep incomplete data
        if (offset > 0) {
            buf = buf.substr(offset);
        }
    }

    if (info.has_tls) {
        info.tls_reassembled = true;
    }
}

// ── QUIC cross-packet CRYPTO frame reassembly ──

void NativeFlow::reassemble_quic_crypto(const ProtocolEngine& engine, AggregatedFlowInfo& info) const {
    if (!info.has_quic) return;

    auto& fragments = info.quic.crypto_fragments;
    if (fragments.empty()) return;

    // Sort by offset
    std::sort(fragments.begin(), fragments.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    // Find max end
    uint64_t max_end = 0;
    for (const auto& [off, data] : fragments) {
        uint64_t end = off + data.size();
        if (end > max_end) max_end = end;
    }
    if (max_end > 65536) max_end = 65536;

    // Reassemble into contiguous buffer
    std::vector<uint8_t> reassembled(max_end, 0);
    for (const auto& [off, data] : fragments) {
        if (off < max_end) {
            size_t end = std::min(static_cast<size_t>(off + data.size()), static_cast<size_t>(max_end));
            std::memcpy(reassembled.data() + off, data.data(), end - off);
        }
    }

    // Need at least TLS handshake header (4 bytes), first byte must be 1 (ClientHello)
    if (reassembled.size() < 4 || reassembled[0] != 1) return;

    // Parse via engine's TLS handshake parser
    try {
        NativeParsedPacket result = engine.parse_from_protocol_struct(
            reassembled.data(), reassembled.size(), "tls_handshake");

        if (result.has_tls) {
            if (!result.tls.sni.empty())
                info.quic.sni = result.tls.sni;
            if (!result.tls.alpn.empty())
                info.quic.alpn = result.tls.alpn;
            if (!result.tls.cipher_suites.empty())
                info.quic.cipher_suites = result.tls.cipher_suites;
        }
    } catch (...) {
        // Ignore parse errors
    }
}

// ── Full aggregation: aggregate + TLS reassembly + QUIC crypto ──

AggregatedFlowInfo NativeFlow::aggregate_full(const ProtocolEngine& engine) const {
    AggregatedFlowInfo info = aggregate();

    // TLS stream reassembly (TCP flows only)
    if (key.protocol == 6) {
        reassemble_tls(engine, info);
    }

    // QUIC cross-packet CRYPTO frame reassembly
    if (info.has_quic && info.quic.sni.empty()) {
        reassemble_quic_crypto(engine, info);
    }

    // Rebuild ext_protocol after reassembly may have added TLS/HTTPS
    // (reassemble_tls may set has_tls on flows that only had fragmented TLS)
    if (info.tls_reassembled) {
        info.ext_protocol.clear();
        if (info.ip_version == 4) info.ext_protocol.push_back("IPv4");
        else if (info.ip_version == 6) info.ext_protocol.push_back("IPv6");
        switch (key.protocol) {
            case 6:   info.ext_protocol.push_back("TCP"); break;
            case 17:  info.ext_protocol.push_back("UDP"); break;
            case 1:   info.ext_protocol.push_back("ICMP"); break;
            case 58:  info.ext_protocol.push_back("ICMPv6"); break;
            case 132: info.ext_protocol.push_back("SCTP"); break;
        }
        if (info.has_tls) {
            info.ext_protocol.push_back("TLS");
            for (const auto& a : info.tls.alpn) {
                std::string lower = a;
                for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (lower == "h2" || lower == "http/1.1" || lower == "http/1.0" ||
                    lower == "http/0.9" || lower == "http" || lower.substr(0, 5) == "http/") {
                    info.ext_protocol.push_back("HTTPS");
                    break;
                }
            }
        }
        if (info.has_dns) info.ext_protocol.push_back("DNS");
        if (info.has_quic) info.ext_protocol.push_back("QUIC");
    }

    return info;
}
