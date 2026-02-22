#pragma once

#include "parsed_packet.h"
#include "stats_core.h"
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <limits>

// Forward declarations
class ProtocolEngine;
class NativeFilter;
class NativePcapReader;

// ── Flow key: 5-tuple + VLAN for bidirectional flow identification ──

struct NativeFlowKey {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t protocol = 0;   // 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6
    uint16_t vlan_id = 0;

    // Direction: 1 = forward (matches src), -1 = reverse
    int direction(const std::string& pkt_src_ip, uint16_t pkt_src_port) const {
        if (pkt_src_ip == src_ip && pkt_src_port == src_port)
            return 1;
        return -1;
    }
};

// Canonical key for bidirectional lookup (same for A→B and B→A)
struct CanonicalFlowKey {
    std::string lo_ip;    // lexicographically lower (ip, port)
    std::string hi_ip;
    uint16_t lo_port = 0;
    uint16_t hi_port = 0;
    uint8_t protocol = 0;
    uint16_t vlan_id = 0;

    bool operator==(const CanonicalFlowKey& o) const {
        return lo_ip == o.lo_ip && hi_ip == o.hi_ip &&
               lo_port == o.lo_port && hi_port == o.hi_port &&
               protocol == o.protocol && vlan_id == o.vlan_id;
    }
};

struct CanonicalFlowKeyHash {
    size_t operator()(const CanonicalFlowKey& k) const {
        // FNV-1a inspired hash
        size_t h = 14695981039346656037ULL;
        auto mix = [&](const void* data, size_t len) {
            auto p = static_cast<const uint8_t*>(data);
            for (size_t i = 0; i < len; ++i) {
                h ^= p[i];
                h *= 1099511628211ULL;
            }
        };
        mix(k.lo_ip.data(), k.lo_ip.size());
        mix(k.hi_ip.data(), k.hi_ip.size());
        mix(&k.lo_port, sizeof(k.lo_port));
        mix(&k.hi_port, sizeof(k.hi_port));
        mix(&k.protocol, sizeof(k.protocol));
        mix(&k.vlan_id, sizeof(k.vlan_id));
        return h;
    }
};

inline CanonicalFlowKey make_canonical_key(
    const std::string& src_ip, const std::string& dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint8_t protocol, uint16_t vlan_id = 0)
{
    CanonicalFlowKey ck;
    ck.protocol = protocol;
    ck.vlan_id = vlan_id;
    if (std::tie(src_ip, src_port) <= std::tie(dst_ip, dst_port)) {
        ck.lo_ip = src_ip;  ck.lo_port = src_port;
        ck.hi_ip = dst_ip;  ck.hi_port = dst_port;
    } else {
        ck.lo_ip = dst_ip;  ck.lo_port = dst_port;
        ck.hi_ip = src_ip;  ck.hi_port = src_port;
    }
    return ck;
}

// ── Flow metrics ──

struct NativeFlowMetrics {
    int64_t packet_count = 0;
    int64_t byte_count = 0;
    int64_t up_packet_count = 0;
    int64_t up_byte_count = 0;
    int64_t down_packet_count = 0;
    int64_t down_byte_count = 0;

    // TCP flags
    int64_t syn_count = 0;
    int64_t fin_count = 0;
    int64_t rst_count = 0;
    int64_t ack_count = 0;
    int64_t psh_count = 0;
    int64_t urg_count = 0;

    // Retransmissions
    int64_t retrans_count = 0;
    int64_t out_of_order_count = 0;

    // Window size tracking
    int64_t min_window = 0;
    int64_t max_window = 0;
    int64_t sum_window = 0;

    void update_window(int64_t win) {
        if (min_window == 0 || win < min_window)
            min_window = win;
        if (win > max_window)
            max_window = win;
        sum_window += win;
    }
};

// ── TCP state machine ──

enum class NativeTCPState : uint8_t {
    CLOSED = 0,
    SYN_SENT = 1,
    SYN_RECEIVED = 2,
    ESTABLISHED = 3,
    FIN_WAIT_1 = 4,
    FIN_WAIT_2 = 5,
    CLOSING = 6,
    TIME_WAIT = 7,
    CLOSE_WAIT = 8,
    LAST_ACK = 9,
    RESET = 10
};

// ── Flow features (pre-computed statistics) ──
// Uses ArrayStats from stats_core.h

// Alias for clarity in Python bindings
using NativeArrayStats = ArrayStats;

struct NativeFlowFeatures {
    ArrayStats packet_lengths;
    ArrayStats ip_lengths;
    ArrayStats trans_lengths;
    ArrayStats app_lengths;
    ArrayStats iats;
    ArrayStats payload_bytes;
    ArrayStats tcp_flags;
    ArrayStats tcp_window;

    bool has_packet_lengths = false;
    bool has_ip_lengths = false;
    bool has_trans_lengths = false;
    bool has_app_lengths = false;
    bool has_iats = false;
    bool has_payload_bytes = false;
    bool has_tcp_flags = false;
    bool has_tcp_window = false;

    // Raw sequences for FlowFeatures dataclass fields
    std::vector<double> iat_values;  // computed from seq_timestamps diff

    double duration = 0.0;
    int64_t packet_count = 0;
    int64_t total_bytes = 0;
};

// ── Aggregated flow info (protocol merge + ext_protocol) ──

struct AggregatedFlowInfo {
    // TLS (first-wins merge across all packets)
    bool has_tls = false;
    NativeTLSInfo tls;

    // DNS (first-wins merge)
    bool has_dns = false;
    NativeDNSInfo dns;

    // QUIC (first-wins merge + crypto_fragments accumulation)
    bool has_quic = false;
    NativeQUICInfo quic;

    // Extended protocol stack (e.g., ["IPv4", "TCP", "TLS", "HTTPS"])
    std::vector<std::string> ext_protocol;

    // IP version from first packet (4 or 6)
    int ip_version = 0;

    // Whether TLS reassembly produced results (for lazy packet injection)
    bool tls_reassembled = false;
};

// ── Native Flow ──

struct NativeFlow {
    NativeFlowKey key;
    NativeFlowMetrics metrics;
    double start_time = 0.0;
    double end_time = 0.0;

    // TCP state (forward and reverse)
    NativeTCPState tcp_state_fwd = NativeTCPState::CLOSED;
    NativeTCPState tcp_state_rev = NativeTCPState::CLOSED;

    // Stored parsed packets (for protocol aggregation + lazy loading)
    std::vector<NativeParsedPacket> packets;

    // Sequence accumulators (direction-signed: positive=forward, negative=reverse)
    std::vector<int64_t> seq_packet_lengths;
    std::vector<int64_t> seq_ip_lengths;
    std::vector<int64_t> seq_trans_lengths;
    std::vector<int64_t> seq_app_lengths;
    std::vector<double>  seq_timestamps;
    std::vector<int64_t> seq_payload_bytes;
    std::vector<int64_t> seq_tcp_flags;
    std::vector<int64_t> seq_tcp_windows;

    // QUIC flow state (for Short Header identification)
    bool is_quic = false;
    int quic_dcid_len = 0;

    // TCP sequence tracking for retransmission detection
    // Maps direction (1 or -1) → expected next seq
    std::unordered_map<int, uint32_t> next_seq;

    // Extended protocol stack (built after aggregation)
    std::vector<std::string> ext_protocol;

    // Add a parsed packet to this flow
    void add_packet(NativeParsedPacket&& pkt) {
        int64_t wirelen = pkt.wirelen;
        metrics.packet_count++;
        metrics.byte_count += wirelen;

        // Determine direction
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

        int dir = key.direction(pkt_src_ip, pkt_src_port);
        pkt.is_client_to_server = (dir == 1);

        if (dir == 1) {
            metrics.up_packet_count++;
            metrics.up_byte_count += wirelen;
        } else {
            metrics.down_packet_count++;
            metrics.down_byte_count += wirelen;
        }

        // TCP flag counting + window tracking
        if (pkt.has_tcp) {
            int64_t flags = pkt.tcp.flags;
            if (flags & 0x02) metrics.syn_count++;
            if (flags & 0x01) metrics.fin_count++;
            if (flags & 0x04) metrics.rst_count++;
            if (flags & 0x10) metrics.ack_count++;
            if (flags & 0x08) metrics.psh_count++;
            if (flags & 0x20) metrics.urg_count++;
            metrics.update_window(pkt.tcp.win);
        }

        // Timestamps
        if (pkt.timestamp > end_time)
            end_time = pkt.timestamp;

        // Sequence accumulators
        seq_packet_lengths.push_back(dir * wirelen);
        seq_ip_lengths.push_back(dir * pkt.ip_len);
        seq_trans_lengths.push_back(dir * pkt.trans_len);
        seq_app_lengths.push_back(dir * pkt.app_len);
        seq_timestamps.push_back(pkt.timestamp);

        // Payload bytes: use _raw_tcp_payload length
        int64_t payload_len = static_cast<int64_t>(pkt._raw_tcp_payload.size());
        seq_payload_bytes.push_back(dir * payload_len);

        if (pkt.has_tcp) {
            seq_tcp_flags.push_back(pkt.tcp.flags);
            seq_tcp_windows.push_back(pkt.tcp.win);
        }

        // Store packet
        pkt.packet_index = static_cast<int64_t>(packets.size());
        packets.push_back(std::move(pkt));
    }

    // Update TCP state machine
    void update_tcp_state(const NativeParsedPacket& pkt, int dir) {
        int64_t flags = pkt.tcp.flags;
        bool syn = (flags & 0x02) != 0;
        bool fin = (flags & 0x01) != 0;
        bool rst = (flags & 0x04) != 0;
        bool ack = (flags & 0x10) != 0;

        auto& state = (dir == 1) ? tcp_state_fwd : tcp_state_rev;

        if (rst) {
            state = NativeTCPState::RESET;
        } else if (syn && !ack) {
            state = NativeTCPState::SYN_SENT;
        } else if (syn && ack) {
            state = NativeTCPState::ESTABLISHED;
        } else if (fin && state == NativeTCPState::ESTABLISHED) {
            state = NativeTCPState::FIN_WAIT_1;
        } else if (fin && state == NativeTCPState::FIN_WAIT_1) {
            state = NativeTCPState::FIN_WAIT_2;
        } else if (ack && state == NativeTCPState::FIN_WAIT_1) {
            state = NativeTCPState::FIN_WAIT_2;
        }
    }

    // Check if TCP connection is closed (both sides done)
    bool is_tcp_closed() const {
        auto is_done = [](NativeTCPState s) {
            return s == NativeTCPState::FIN_WAIT_2 ||
                   s == NativeTCPState::CLOSED ||
                   s == NativeTCPState::TIME_WAIT;
        };
        return is_done(tcp_state_fwd) && is_done(tcp_state_rev);
    }

    // Compute all flow features (stats + IATs) in C++
    NativeFlowFeatures compute_features() const {
        NativeFlowFeatures f;
        f.packet_count = metrics.packet_count;
        f.total_bytes = metrics.byte_count;
        f.duration = (end_time > start_time) ? (end_time - start_time) : 0.0;

        if (!seq_packet_lengths.empty()) {
            f.packet_lengths = compute_stats_from_ints(seq_packet_lengths);
            f.has_packet_lengths = true;
        }
        if (!seq_ip_lengths.empty()) {
            f.ip_lengths = compute_stats_from_ints(seq_ip_lengths);
            f.has_ip_lengths = true;
        }
        if (!seq_trans_lengths.empty()) {
            f.trans_lengths = compute_stats_from_ints(seq_trans_lengths);
            f.has_trans_lengths = true;
        }
        if (!seq_app_lengths.empty()) {
            f.app_lengths = compute_stats_from_ints(seq_app_lengths);
            f.has_app_lengths = true;
        }
        if (!seq_payload_bytes.empty()) {
            f.payload_bytes = compute_stats_from_ints(seq_payload_bytes);
            f.has_payload_bytes = true;
        }
        if (!seq_tcp_flags.empty()) {
            // TCP flags are unsigned but stored as int64_t; convert to double
            std::vector<double> dv(seq_tcp_flags.begin(), seq_tcp_flags.end());
            f.tcp_flags = compute_stats_core(dv.data(), static_cast<int64_t>(dv.size()));
            f.has_tcp_flags = true;
        }
        if (!seq_tcp_windows.empty()) {
            std::vector<double> dv(seq_tcp_windows.begin(), seq_tcp_windows.end());
            f.tcp_window = compute_stats_core(dv.data(), static_cast<int64_t>(dv.size()));
            f.has_tcp_window = true;
        }

        // Compute IATs from timestamps
        if (seq_timestamps.size() > 1) {
            f.iat_values.resize(seq_timestamps.size() - 1);
            for (size_t i = 1; i < seq_timestamps.size(); i++) {
                f.iat_values[i - 1] = seq_timestamps[i] - seq_timestamps[i - 1];
            }
            f.iats = compute_stats_from_doubles(f.iat_values);
            f.has_iats = true;
        }

        return f;
    }

    // Protocol aggregation: first-wins merge of TLS/DNS/QUIC across packets
    AggregatedFlowInfo aggregate() const;

    // TLS stream reassembly over stored packets
    void reassemble_tls(const ProtocolEngine& engine, AggregatedFlowInfo& info) const;

    // QUIC cross-packet CRYPTO frame reassembly
    void reassemble_quic_crypto(const ProtocolEngine& engine, AggregatedFlowInfo& info) const;

    // Full aggregation: aggregate + TLS reassembly + QUIC crypto
    AggregatedFlowInfo aggregate_full(const ProtocolEngine& engine) const;
};

// ── Flow Manager configuration ──

struct NativeFlowManagerConfig {
    double udp_timeout = 0.0;       // 0 = no timeout
    double tcp_cleanup_timeout = 300.0;
    int64_t max_flows = 100000;
};

// ── Flow Manager ──

class NativeFlowManager {
public:
    explicit NativeFlowManager(const NativeFlowManagerConfig& config = {})
        : config_(config) {}

    // Get or create flow for a parsed packet.
    // Returns pointer to the flow (owned by manager), or nullptr if no IP layer or max_flows reached.
    NativeFlow* get_or_create(const NativeParsedPacket& pkt) {
        // Extract IP + transport fields
        std::string src_ip, dst_ip;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t protocol = 0;
        uint16_t vlan_id = 0;

        if (pkt.has_ip) {
            src_ip = pkt.ip.src;
            dst_ip = pkt.ip.dst;
            protocol = static_cast<uint8_t>(pkt.ip.proto);
        } else if (pkt.has_ip6) {
            src_ip = pkt.ip6.src;
            dst_ip = pkt.ip6.dst;
            protocol = static_cast<uint8_t>(pkt.ip6.next_header);
        } else {
            return nullptr;  // No IP layer
        }

        if (pkt.has_tcp) {
            src_port = static_cast<uint16_t>(pkt.tcp.sport);
            dst_port = static_cast<uint16_t>(pkt.tcp.dport);
        } else if (pkt.has_udp) {
            src_port = static_cast<uint16_t>(pkt.udp.sport);
            dst_port = static_cast<uint16_t>(pkt.udp.dport);
        }

        if (pkt.has_vlan) {
            vlan_id = static_cast<uint16_t>(pkt.vlan.vlan_id);
        }

        auto canonical = make_canonical_key(src_ip, dst_ip, src_port, dst_port, protocol, vlan_id);

        auto it = flows_.find(canonical);

        // UDP timeout check
        if (it != flows_.end() && protocol == 17 && config_.udp_timeout > 0) {
            NativeFlow& existing = *(it->second);
            if (pkt.timestamp - existing.end_time > config_.udp_timeout) {
                // Move old flow to completed, create new one
                completed_flows_.push_back(std::move(it->second));
                flows_.erase(it);
                it = flows_.end();
            }
        }

        if (it != flows_.end()) {
            return it->second.get();
        }

        // New flow
        if (static_cast<int64_t>(flows_.size()) >= config_.max_flows) {
            return nullptr;
        }

        auto flow = std::make_unique<NativeFlow>();
        flow->key.src_ip = src_ip;
        flow->key.dst_ip = dst_ip;
        flow->key.src_port = src_port;
        flow->key.dst_port = dst_port;
        flow->key.protocol = protocol;
        flow->key.vlan_id = vlan_id;
        flow->start_time = pkt.timestamp;
        flow->end_time = pkt.timestamp;

        NativeFlow* ptr = flow.get();
        flows_.emplace(canonical, std::move(flow));
        return ptr;
    }

    // Get all flows (completed + active)
    std::vector<NativeFlow*> get_all_flows() {
        std::vector<NativeFlow*> result;
        result.reserve(completed_flows_.size() + flows_.size());
        for (auto& f : completed_flows_)
            result.push_back(f.get());
        for (auto& [k, f] : flows_)
            result.push_back(f.get());
        return result;
    }

    size_t flow_count() const {
        return flows_.size();
    }

    size_t total_flow_count() const {
        return completed_flows_.size() + flows_.size();
    }

    void clear() {
        flows_.clear();
        completed_flows_.clear();
    }

private:
    NativeFlowManagerConfig config_;
    std::unordered_map<CanonicalFlowKey, std::unique_ptr<NativeFlow>, CanonicalFlowKeyHash> flows_;
    std::vector<std::unique_ptr<NativeFlow>> completed_flows_;
};

// ── Process pipeline configuration ──

struct ProcessConfig {
    // Filtering
    bool filter_ack = false;
    bool filter_rst = false;
    bool filter_retrans = true;

    // Flow management
    NativeFlowManagerConfig flow_config;

    // Parsing
    int app_layer_mode = 0;  // 0=full, 1=port_only, 2=none
    bool save_raw_bytes = false;
};

// ── Process pipeline statistics ──

struct ProcessStats {
    int64_t packets_processed = 0;
    int64_t packets_filtered = 0;
    int64_t flows_created = 0;
    int64_t errors = 0;
};

// ── Per-packet helpers (used by process_file) ──

// Check if packet should be filtered (ACK-only / RST)
inline bool should_filter_packet(const NativeParsedPacket& pkt,
                                  bool filter_ack, bool filter_rst) {
    if (!pkt.has_tcp) return false;

    // Filter RST
    if (filter_rst && (pkt.tcp.flags & 0x04))
        return true;

    // Filter pure ACK (only ACK flag, no payload, no options)
    if (filter_ack) {
        bool is_pure_ack = (pkt.tcp.flags == 0x10) &&
                           pkt.tcp.options.empty() &&
                           (pkt.app_len == 0);
        if (is_pure_ack) return true;
    }

    return false;
}

// Check TCP retransmission. Returns true if retransmitted.
inline bool check_retransmission(const NativeParsedPacket& pkt,
                                  NativeFlow& flow, int dir) {
    if (!pkt.has_tcp) return false;

    int64_t flags = pkt.tcp.flags;
    int64_t seq_len = pkt.app_len;
    if (flags & 0x02) seq_len++;  // SYN
    if (flags & 0x01) seq_len++;  // FIN
    if (seq_len == 0) return false;

    uint32_t seq = static_cast<uint32_t>(pkt.tcp.seq);
    uint32_t seq_end = (seq + static_cast<uint32_t>(seq_len)) & 0xFFFFFFFF;

    auto it = flow.next_seq.find(dir);
    if (it == flow.next_seq.end()) {
        // First data packet in this direction
        flow.next_seq[dir] = seq_end;
        return false;
    }

    uint32_t next = it->second;

    // TCP Keep-Alive: seq == next_seq - 1, payload <= 1, no SYN/FIN
    if (pkt.app_len <= 1 && !(flags & 0x03)) {
        if (((seq - (next - 1)) & 0xFFFFFFFF) == 0)
            return false;
    }

    uint32_t diff = (seq_end - next) & 0xFFFFFFFF;
    if (diff == 0) {
        return true;  // Exact duplicate
    }
    if (diff < 0x80000000U) {
        // New data — advance tracker
        flow.next_seq[dir] = seq_end;
        return false;
    }
    // Already seen
    return true;
}

// Handle QUIC flow state: mark flow on Long Header, parse Short Header
inline void handle_quic_flow_state(NativeParsedPacket& pkt, NativeFlow& flow) {
    if (pkt.has_quic && pkt.quic.is_long_header) {
        flow.is_quic = true;
        if (pkt.quic.dcid_len > 0)
            flow.quic_dcid_len = pkt.quic.dcid_len;
        return;
    }

    if (pkt.has_quic) return;  // Already parsed

    // Not identified as QUIC — check if UDP on a QUIC flow
    if (!flow.is_quic || !pkt.has_udp) return;

    // Try Short Header parse from raw payload
    // Short Header: bit 7 = 0, Fixed Bit (bit 6) = 1
    // We need the UDP payload. Compute offset: caplen - app_len
    if (pkt.app_len < 2) return;

    // Access raw bytes stored in the packet
    const std::vector<uint8_t>& raw = pkt._raw_bytes;
    if (raw.empty()) return;

    size_t udp_payload_offset = pkt.caplen - pkt.app_len;
    if (udp_payload_offset >= raw.size()) return;

    const uint8_t* buf = raw.data() + udp_payload_offset;
    size_t buf_len = raw.size() - udp_payload_offset;
    if (buf_len < 2) return;

    uint8_t first = buf[0];
    if ((first & 0x80) != 0 || (first & 0x40) == 0) return;

    // Parse spin bit
    bool spin_bit = (first & 0x20) != 0;

    // Extract DCID
    int dcid_len = flow.quic_dcid_len;
    if (static_cast<int>(buf_len) < 1 + dcid_len) return;

    pkt.has_quic = true;
    pkt.quic.is_long_header = false;
    pkt.quic.spin_bit = spin_bit;
    pkt.quic.dcid_len = dcid_len;
    if (dcid_len > 0) {
        pkt.quic.dcid.assign(buf + 1, buf + 1 + dcid_len);
    }
    pkt.quic.packet_type_str = "1-RTT";
}

// ── process_file: fused read → parse → filter → flow management pipeline ──
// Returns the flow manager with all flows populated.
// The caller owns the returned FlowManager.

ProcessStats process_file(
    const std::string& pcap_path,
    const ProtocolEngine& engine,
    const NativeFilter* filter,       // may be nullptr
    const ProcessConfig& config,
    NativeFlowManager& flow_manager   // output: populated with flows
);
