/**
 * l7_extractors.cpp — HTTP/SSH/MQTT/SIP/QUIC/RDP/VNC JSONL extractors
 */
#include "protocol_common.h"
#include "protocol_json_emit.h"

#include <pcap/pcap.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>

#include "nvers_api.h"

namespace {

struct FlowCtx {
    uint32_t sip = 0, dip = 0;
    uint16_t sp = 0, dp = 0;
    uint8_t  proto = 0;
    std::string id;
};

template <typename Rec>
using FlowTable = std::unordered_map<ProtoFlowKey, std::pair<FlowCtx, Rec>, ProtoFlowKeyHash>;

std::string pcap_basename(const std::string& path) {
    if (const char* b = strrchr(path.c_str(), '/')) return b + 1;
    if (const char* b = strrchr(path.c_str(), '\\')) return b + 1;
    return path;
}

ProtoFlowKey canonical_server_port(const ProtoFlowKey& raw, bool (*port_check)(uint16_t)) {
    if (port_check(raw.dst_port)) return raw;
    if (port_check(raw.src_port))
        return {raw.dst_ip, raw.src_ip, raw.dst_port, raw.src_port, raw.proto};
    return raw.canonical();
}

bool client_to_server(uint16_t sp, uint16_t dp, bool (*port_check)(uint16_t)) {
    if (port_check(dp) && !port_check(sp)) return true;
    if (port_check(sp) && !port_check(dp)) return false;
    return sp > dp;
}

static inline bool detect_vnc(const uint8_t* p, int len) {
    return VncFlowRecord::is_rfb_banner(p, len);
}

template <typename Rec, bool (*PortCheck)(uint16_t), bool (*Detect)(const uint8_t*, int),
          void (*Process)(Rec&, const uint8_t*, int, bool, double),
          bool (*HasSignal)(const Rec&),
          void (*EmitJson)(FILE*, const char*, const char*, uint32_t, uint16_t, uint32_t, uint16_t,
                           uint8_t, const Rec&),
          uint8_t L4Proto = 6>
wa1kpcap::nvers::ExtractResult run_l7(const wa1kpcap::nvers::ExtractConfig& cfg,
                                      const char* default_out) {
    wa1kpcap::nvers::ExtractResult res;
    if (cfg.pcap_path.empty()) {
        res.exit_code = 1;
        res.message = "pcap_path required";
        return res;
    }

    FlowTable<Rec> flows;
    std::string pcap_name = pcap_basename(cfg.pcap_path);
    const char* out_path = cfg.output_path.empty() ? default_out : cfg.output_path.c_str();
    FILE* out = fopen(out_path, "w");
    if (!out) {
        res.exit_code = 1;
        res.message = "fopen failed";
        return res;
    }

    char err[PCAP_ERRBUF_SIZE];
    pcap_t* ph = pcap_open_offline(cfg.pcap_path.c_str(), err);
    if (!ph) {
        fclose(out);
        res.exit_code = 1;
        res.message = err;
        return res;
    }

    std::atomic<uint64_t> total{0};
    uint64_t flow_cnt = 0;

    struct CbState {
        FlowTable<Rec>* flows;
        std::atomic<uint64_t>* total;
        uint64_t* flow_cnt;
        bool (*port_check)(uint16_t);
    } state{&flows, &total, &flow_cnt, PortCheck};

    auto loop_cb = [](uint8_t* user, const pcap_pkthdr* hdr, const uint8_t* pkt) {
        auto* st = reinterpret_cast<CbState*>(user);
        st->total->fetch_add(1, std::memory_order_relaxed);

        uint32_t sip = 0, dip = 0, l4rem = 0;
        uint16_t sp = 0, dp = 0;
        uint8_t proto = 0;
        const uint8_t* l4 = nullptr;
        if (!parse_l4(pkt, hdr->caplen, sip, dip, sp, dp, proto, l4, l4rem)) return;

        const uint8_t* pay = nullptr;
        int plen = 0;
        if (L4Proto == 0) {
            if (proto != 6 && proto != 17) return;
            if (proto == 6) {
                if (!tcp_payload(l4, l4rem, pay, plen)) return;
            } else {
                if (!udp_payload(l4, l4rem, pay, plen)) return;
            }
        } else if (proto != L4Proto) {
            return;
        } else if (L4Proto == 6) {
            if (!tcp_payload(l4, l4rem, pay, plen)) return;
        } else {
            if (!udp_payload(l4, l4rem, pay, plen)) return;
        }
        if (plen <= 0) return;
        if (!st->port_check(sp) && !st->port_check(dp) && !Detect(pay, plen)) return;

        ProtoFlowKey raw{sip, dip, sp, dp, proto};
        ProtoFlowKey key = canonical_server_port(raw, st->port_check);
        bool is_fwd = client_to_server(sp, dp, st->port_check);
        double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;

        auto it = st->flows->find(key);
        if (it == st->flows->end()) {
            FlowCtx ctx{sip, dip, sp, dp, proto, raw.id()};
            Rec rec;
            rec.init();
            (*st->flows)[key] = {ctx, rec};
            it = st->flows->find(key);
            (*st->flow_cnt)++;
        }
        Process(it->second.second, pay, plen, is_fwd, ts);
    };

    auto t0 = std::chrono::steady_clock::now();
    pcap_loop(ph, 0, loop_cb, reinterpret_cast<uint8_t*>(&state));
    pcap_close(ph);
    res.elapsed_sec =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    for (const auto& kv : flows) {
        const FlowCtx& ctx = kv.second.first;
        const Rec& rec = kv.second.second;
        if (!HasSignal(rec)) continue;
        EmitJson(out, pcap_name.c_str(), ctx.id.c_str(),
                 ctx.sip, ctx.sp, ctx.dip, ctx.dp, ctx.proto, rec);
    }

    fclose(out);
    res.packets = (int64_t)total.load();
    res.flows = (int64_t)flow_cnt;
    res.message = "ok";
    return res;
}

void http_process(HttpFlowRecord& r, const uint8_t* pay, int plen, bool is_client, double ts) {
    r.process_pkt(pay, plen, is_client, ts);
}

void ssh_process(SshFlowRecord& r, const uint8_t* pay, int plen, bool is_client, double ts) {
    r.process_pkt(pay, plen, is_client, ts);
}

void mqtt_process(MqttFlowRecord& r, const uint8_t* pay, int plen, bool is_client, double ts) {
    r.process_pkt(pay, plen, is_client, ts);
}

void sip_process(SipFlowRecord& r, const uint8_t* pay, int plen, bool is_fwd, double ts) {
    r.process_pkt(pay, plen, is_fwd, false, ts);
}

void quic_process(QuicFlowRecord& r, const uint8_t* pay, int plen, bool is_fwd, double ts) {
    r.process_pkt(pay, plen, is_fwd, ts);
}

void rdp_process(RdpFlowRecord& r, const uint8_t* pay, int plen, bool /*is_fwd*/, double /*ts*/) {
    r.process_pkt(pay, plen, false);
}

void vnc_process(VncFlowRecord& r, const uint8_t* pay, int plen, bool is_fwd, double /*ts*/) {
    r.process_pkt(pay, plen, is_fwd);
}

}  // namespace

namespace wa1kpcap::nvers {

ExtractResult run_http(const ExtractConfig& cfg) {
    return run_l7<HttpFlowRecord, is_http_port, detect_http, http_process,
                  http_has_signal, http_emit_json, 6>(cfg, "http.log");
}

ExtractResult run_ssh(const ExtractConfig& cfg) {
    return run_l7<SshFlowRecord, is_ssh_port, detect_ssh, ssh_process,
                  ssh_has_signal, ssh_emit_json, 6>(cfg, "ssh.log");
}

ExtractResult run_mqtt(const ExtractConfig& cfg) {
    return run_l7<MqttFlowRecord, is_mqtt_port, detect_mqtt, mqtt_process,
                  mqtt_has_signal, mqtt_emit_json, 6>(cfg, "mqtt.log");
}

ExtractResult run_sip(const ExtractConfig& cfg) {
    return run_l7<SipFlowRecord, is_sip_port, detect_sip, sip_process,
                  sip_has_signal, sip_emit_json, 0>(cfg, "sip.log");
}

ExtractResult run_quic(const ExtractConfig& cfg) {
    return run_l7<QuicFlowRecord, is_quic_port, detect_quic, quic_process,
                  quic_has_signal, quic_emit_json, 17>(cfg, "quic.log");
}

ExtractResult run_rdp(const ExtractConfig& cfg) {
    return run_l7<RdpFlowRecord, is_rdp_port, detect_rdp, rdp_process,
                  rdp_has_signal, rdp_emit_json, 6>(cfg, "rdp.log");
}

ExtractResult run_vnc(const ExtractConfig& cfg) {
    return run_l7<VncFlowRecord, is_vnc_port, detect_vnc, vnc_process,
                  vnc_has_signal, vnc_emit_json, 6>(cfg, "vnc.log");
}

}  // namespace wa1kpcap::nvers
