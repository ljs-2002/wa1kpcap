#include "flow_manager.h"
#include "pcap_reader.h"
#include "protocol_engine.h"
#include "bpf_filter.h"

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
