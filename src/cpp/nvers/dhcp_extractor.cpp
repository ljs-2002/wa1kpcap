/**
 * dhcp_extractor.cpp  ——  DHCP 元特征提取（JSON Lines）
 * 用法：./dhcp_extractor -r <file.pcap> [-w dhcp.log] [-v]
 */
#include "dhcp_flow.h"

#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

#include "nvers_api.h"

struct DhcpFlowKey {
    uint32_t xid;
    uint8_t  mac[6];
    bool operator==(const DhcpFlowKey& o) const noexcept {
        return xid == o.xid && !memcmp(mac, o.mac, 6);
    }
};
struct DhcpFlowKeyHash {
    size_t operator()(const DhcpFlowKey& k) const noexcept {
        uint64_t m = 0;
        for (int i = 0; i < 6; i++) m = (m << 8) | k.mac[i];
        return (size_t)(k.xid ^ (m * 0x9e3779b97f4a7c15ULL));
    }
};

static std::unordered_map<DhcpFlowKey, DhcpFlowRecord, DhcpFlowKeyHash> g_flows;
static FILE* g_out = nullptr;
static std::string g_pcap_name;
static std::atomic<uint64_t> g_total{0}, g_msgs{0}, g_flow_cnt{0};

static void handle_dhcp(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
                        double ts, const uint8_t* data, int dlen) {
    if (!is_dhcp_port(sp) && !is_dhcp_port(dp)) return;
    DhcpMsgInfo msg;
    if (!DhcpFlowRecord::parse_dhcp(data, dlen, ts, msg)) return;
    g_msgs++;

    DhcpFlowKey key{};
    key.xid = msg.xid;
    memcpy(key.mac, msg.chaddr, 6);

    auto it = g_flows.find(key);
    if (it == g_flows.end()) {
        char fid[128];
        snprintf(fid, sizeof fid, "xid=0x%08x mac=%s", msg.xid, msg.chaddr_hex);
        DhcpFlowRecord rec;
        rec.init(fid, 17, sip, dip, sp, dp);
        g_flows[key] = rec;
        it = g_flows.find(key);
        g_flow_cnt++;
    }
    it->second.add_msg(msg);
}

static void pcap_cb(uint8_t*, const struct pcap_pkthdr* hdr, const uint8_t* pkt) {
    g_total++;
    if (hdr->caplen < 14) return;
    uint16_t etype = (uint16_t)((pkt[12]<<8)|pkt[13]);
    const uint8_t* ip = pkt + 14;
    uint32_t rem = hdr->caplen - 14;
    while (etype == 0x8100 && rem >= 4) {
        etype = (uint16_t)((ip[2]<<8)|ip[3]); ip += 4; rem -= 4;
    }
    if (etype != 0x0800 || rem < 20) return;
    uint8_t ihl = (ip[0]&0xF)*4;
    if (ip[9] != 17 || rem < ihl + 8) return;
    uint32_t sip = *(const uint32_t*)(ip+12);
    uint32_t dip = *(const uint32_t*)(ip+16);
    const uint8_t* up = ip + ihl;
    uint32_t urem = rem - ihl;
    uint16_t sp = (uint16_t)((up[0]<<8)|up[1]);
    uint16_t dp = (uint16_t)((up[2]<<8)|up[3]);
    uint16_t ulen = (uint16_t)((up[4]<<8)|up[5]);
    int dlen = (int)ulen - 8;
    if (dlen < 240 || (uint32_t)dlen > urem - 8) dlen = (int)(urem - 8);
    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;
    handle_dhcp(sip, dip, sp, dp, ts, up + 8, dlen);
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_dhcp(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) { res.exit_code = 1; res.message = "pcap_path required"; return res; }
    g_pcap_name = cfg.pcap_path;
    if (const char* b = strrchr(cfg.pcap_path.c_str(), '/')) g_pcap_name = b + 1;
    const char* out = cfg.output_path.empty() ? "dhcp.log" : cfg.output_path.c_str();
    g_out = fopen(out, "w");
    if (!g_out) { res.exit_code = 1; res.message = "fopen failed"; return res; }
    char err[PCAP_ERRBUF_SIZE];
    pcap_t* ph = pcap_open_offline(cfg.pcap_path.c_str(), err);
    if (!ph) { fclose(g_out); res.exit_code = 1; res.message = err; return res; }
    auto t0 = std::chrono::steady_clock::now();
    pcap_loop(ph, 0, pcap_cb, nullptr);
    pcap_close(ph);
    res.elapsed_sec = std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
    for (auto& [k, rec] : g_flows) rec.emit_json(g_out, g_pcap_name.c_str());
    fclose(g_out);
    res.packets = (int64_t)g_total.load();
    res.flows = (int64_t)g_flow_cnt.load();
    res.message = "ok";
    return res;
}

#ifndef NVERS_LIBRARY
int main(int argc, char* argv[]) {
    const char* pcap = nullptr;
    const char* out = "dhcp.log";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i+1<argc) pcap = argv[++i];
        else if (!strcmp(argv[i], "-w") && i+1<argc) out = argv[++i];
    }
    if (!pcap) {
        fprintf(stderr, "用法: %s -r <file.pcap> [-w dhcp.log]\n", argv[0]);
        return 1;
    }
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap;
    cfg.output_path = out;
    return wa1kpcap::nvers::run_dhcp(cfg).exit_code;
}
#endif
