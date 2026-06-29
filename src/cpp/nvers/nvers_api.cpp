#include "nvers_api.h"

#include <filesystem>
#include <unordered_map>

namespace fs = std::filesystem;

namespace wa1kpcap::nvers {

static std::string stem(const std::string& path) {
    return fs::path(path).stem().string();
}

std::string default_output_name(FeatureKind kind, const std::string& pcap_basename) {
    switch (kind) {
    case FeatureKind::CIC:        return pcap_basename + "_cic.csv";
    case FeatureKind::CICEXT:     return pcap_basename + "_cicext.csv";
    case FeatureKind::SEQ:        return pcap_basename + "_seq.log";
    case FeatureKind::PAYLOAD:    return pcap_basename + "_payload.log";
    case FeatureKind::TLS:        return pcap_basename + "_tls.log";
    case FeatureKind::DNS:        return pcap_basename + "_dns.log";
    case FeatureKind::SMTP:       return pcap_basename + "_smtp.log";
    case FeatureKind::DHCP:       return pcap_basename + "_dhcp.log";
    case FeatureKind::FTP:        return pcap_basename + "_ftp.log";
    case FeatureKind::HTTP:       return pcap_basename + "_http.log";
    case FeatureKind::SSH:        return pcap_basename + "_ssh.log";
    case FeatureKind::MQTT:       return pcap_basename + "_mqtt.log";
    case FeatureKind::SIP:        return pcap_basename + "_sip.log";
    case FeatureKind::QUIC:       return pcap_basename + "_quic.log";
    case FeatureKind::RDP:        return pcap_basename + "_rdp.log";
    case FeatureKind::VNC:        return pcap_basename + "_vnc.log";
    case FeatureKind::PCAP_SPLIT: return pcap_basename + "_flows";
    case FeatureKind::VPN:        return pcap_basename + "_vpn.log";
    case FeatureKind::IM:         return pcap_basename + "_im.log";
    case FeatureKind::FLOW:       return pcap_basename + "_flow.json";
    }
    return "output";
}

ExtractResult run_feature(FeatureKind kind, const ExtractConfig& cfg) {
    switch (kind) {
    case FeatureKind::CIC:        return run_cic(cfg);
    case FeatureKind::CICEXT:     return run_cicext(cfg);
    case FeatureKind::SEQ:        return run_seq(cfg);
    case FeatureKind::PAYLOAD:    return run_payload(cfg);
    case FeatureKind::TLS:        return run_tls(cfg);
    case FeatureKind::DNS:        return run_dns(cfg);
    case FeatureKind::SMTP:       return run_smtp(cfg);
    case FeatureKind::DHCP:       return run_dhcp(cfg);
    case FeatureKind::FTP:        return run_ftp(cfg);
    case FeatureKind::HTTP:       return run_http(cfg);
    case FeatureKind::SSH:        return run_ssh(cfg);
    case FeatureKind::MQTT:       return run_mqtt(cfg);
    case FeatureKind::SIP:        return run_sip(cfg);
    case FeatureKind::QUIC:       return run_quic(cfg);
    case FeatureKind::RDP:        return run_rdp(cfg);
    case FeatureKind::VNC:        return run_vnc(cfg);
    case FeatureKind::PCAP_SPLIT: return run_pcap_split(cfg);
    case FeatureKind::VPN:        return run_vpn(cfg);
    case FeatureKind::IM:         return run_im(cfg);
    case FeatureKind::FLOW:       return run_flow(cfg);
    }
    return {1, "unknown feature kind"};
}

ExtractResult run_batch(const std::vector<FeatureKind>& kinds, ExtractConfig base_cfg) {
    ExtractResult aggregate;
    aggregate.exit_code = 0;
    const std::string base = stem(base_cfg.pcap_path);

    for (FeatureKind kind : kinds) {
        ExtractConfig cfg = base_cfg;
        if (cfg.output_path.empty()) {
            cfg.output_path = default_output_name(kind, base);
        } else if (fs::is_directory(cfg.output_path) || kind == FeatureKind::PCAP_SPLIT) {
            cfg.output_path = (fs::path(cfg.output_path) / default_output_name(kind, base)).string();
        }
        ExtractResult r = run_feature(kind, cfg);
        if (r.exit_code != 0) {
            aggregate.exit_code = r.exit_code;
            if (!aggregate.message.empty()) aggregate.message += "; ";
            aggregate.message += r.message;
        }
        aggregate.flows += r.flows;
        aggregate.packets += r.packets;
        aggregate.elapsed_sec += r.elapsed_sec;
    }
    if (aggregate.message.empty() && aggregate.exit_code == 0)
        aggregate.message = "ok";
    return aggregate;
}

std::vector<std::string> unified_sequence_fields() {
    return {
        // wa1kpcap built-in (signed direction where noted)
        "packet_lengths", "ip_lengths", "trans_lengths", "app_lengths",
        "timestamps", "iats", "tcp_flags", "tcp_window_sizes",
        // nvers seq (JSONL keys)
        "direction", "pkt_len", "pay_len", "iat_us", "ts_rel_us",
        "tls_type", "burst",
        // nvers payload-only
        "payload_hex",
    };
}

std::string wa1k_to_nvers_seq_key(const std::string& wa1k_field) {
    static const std::unordered_map<std::string, std::string> m = {
        {"packet_lengths", "pkt_len"},
        {"ip_lengths", "pkt_len"},
        {"trans_lengths", "pkt_len"},
        {"app_lengths", "pay_len"},
        {"payload_bytes", "pay_len"},
        {"iats", "iat_us"},
        {"timestamps", "ts_rel_us"},
        {"tcp_flags", "tcp_flags"},
    };
    auto it = m.find(wa1k_field);
    return it == m.end() ? "" : it->second;
}

}  // namespace wa1kpcap::nvers
