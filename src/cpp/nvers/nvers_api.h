/**
 * nvers_api.h — unified library API for nvers feature extractors (wa1kpcap integration)
 */
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace wa1kpcap::nvers {

struct ExtractResult {
    int exit_code = 0;
    std::string message;
    int64_t flows = 0;
    int64_t packets = 0;
    double elapsed_sec = 0.0;
};

struct ExtractConfig {
    std::string pcap_path;
    std::string output_path;   // file or directory (pcap_split)
    int n_limit = 0;           // packets per flow, 0 = all
    int workers = 0;           // 0 = auto (CPU cores, max 16)
    int filter_port = 0;       // TLS: 0 = all ports
    bool verbose = false;
};

enum class FeatureKind {
    CIC,
    CICEXT,
    SEQ,
    PAYLOAD,
    TLS,
    DNS,
    SMTP,
    DHCP,
    FTP,
    HTTP,
    SSH,
    MQTT,
    SIP,
    QUIC,
    RDP,
    VNC,
    PCAP_SPLIT,
    VPN,
    IM,
    FLOW,
};

/** Default output filename for a feature kind inside output_dir. */
std::string default_output_name(FeatureKind kind, const std::string& pcap_basename);

ExtractResult run_cic(const ExtractConfig& cfg);
ExtractResult run_cicext(const ExtractConfig& cfg);
ExtractResult run_seq(const ExtractConfig& cfg);
ExtractResult run_payload(const ExtractConfig& cfg);
ExtractResult run_tls(const ExtractConfig& cfg);
ExtractResult run_dns(const ExtractConfig& cfg);
ExtractResult run_smtp(const ExtractConfig& cfg);
ExtractResult run_dhcp(const ExtractConfig& cfg);
ExtractResult run_ftp(const ExtractConfig& cfg);
ExtractResult run_http(const ExtractConfig& cfg);
ExtractResult run_ssh(const ExtractConfig& cfg);
ExtractResult run_mqtt(const ExtractConfig& cfg);
ExtractResult run_sip(const ExtractConfig& cfg);
ExtractResult run_quic(const ExtractConfig& cfg);
ExtractResult run_rdp(const ExtractConfig& cfg);
ExtractResult run_vnc(const ExtractConfig& cfg);
ExtractResult run_pcap_split(const ExtractConfig& cfg);
ExtractResult run_vpn(const ExtractConfig& cfg);
ExtractResult run_im(const ExtractConfig& cfg);
ExtractResult run_flow(const ExtractConfig& cfg);

ExtractResult run_feature(FeatureKind kind, const ExtractConfig& cfg);
ExtractResult run_batch(const std::vector<FeatureKind>& kinds, ExtractConfig base_cfg);

/** All sequence field names (wa1kpcap ∪ nvers union). */
std::vector<std::string> unified_sequence_fields();

/** Map wa1kpcap FlowFeatures field name → nvers seq JSON key (empty if nvers-only). */
std::string wa1k_to_nvers_seq_key(const std::string& wa1k_field);

}  // namespace wa1kpcap::nvers
