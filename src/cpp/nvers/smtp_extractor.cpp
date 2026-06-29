/**
 * smtp_extractor.cpp  ——  SMTP 元特征提取（JSON Lines）
 * 用法：./smtp_extractor -r <file.pcap> [-w smtp.log] [-v]
 */
#include "smtp_flow.h"

#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "nvers_api.h"

struct SmtpFlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;
    bool operator==(const SmtpFlowKey& o) const noexcept {
        return src_ip==o.src_ip && dst_ip==o.dst_ip &&
               src_port==o.src_port && dst_port==o.dst_port && proto==o.proto;
    }
    SmtpFlowKey canonical() const noexcept {
        if (is_smtp_port(dst_port)) return *this;
        if (is_smtp_port(src_port)) return {dst_ip, src_ip, dst_port, src_port, proto};
        if (src_ip < dst_ip) return *this;
        if (src_ip > dst_ip) return {dst_ip, src_ip, dst_port, src_port, proto};
        return src_port <= dst_port ? *this
               : SmtpFlowKey{dst_ip, src_ip, dst_port, src_port, proto};
    }
    std::string id() const {
        char buf[96];
        in_addr s{src_ip}, d{dst_ip};
        char ss[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s, ss, sizeof ss);
        inet_ntop(AF_INET, &d, ds, sizeof ds);
        snprintf(buf, sizeof buf, "%s:%u-%s:%u/%u", ss, src_port, ds, dst_port, proto);
        return buf;
    }
};
struct SmtpFlowKeyHash {
    size_t operator()(const SmtpFlowKey& k) const noexcept {
        auto h=[](uint64_t x){x^=x>>33;x*=0xff51afd7ed558ccdULL;x^=x>>33;x*=0xc4ceb9fe1a85ec53ULL;x^=x>>33;return x;};
        return (size_t)(h((uint64_t)k.src_ip|((uint64_t)k.dst_ip<<32))^h((uint64_t)k.src_port|((uint64_t)k.dst_port<<16)|((uint64_t)k.proto<<32)));
    }
};

static std::unordered_map<SmtpFlowKey, SmtpFlowRecord, SmtpFlowKeyHash> g_flows;
static FILE* g_out = nullptr;
static std::string g_pcap_name;
static std::atomic<uint64_t> g_total{0}, g_events{0}, g_flow_cnt{0};

static void handle_tcp(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
                       double ts, const uint8_t* pay, int plen) {
    if (!is_smtp_port(sp) && !is_smtp_port(dp)) return;
    if (plen <= 0) return;

    SmtpFlowKey raw{sip, dip, sp, dp, 6};
    SmtpFlowKey can = raw.canonical();
    bool is_client = is_smtp_port(dp);

    auto it = g_flows.find(can);
    if (it == g_flows.end()) {
        SmtpFlowRecord rec;
        rec.init(raw.id().c_str(), 6, sip, dip, sp, dp);
        g_flows[can] = rec;
        it = g_flows.find(can);
        g_flow_cnt++;
    }
    int before = it->second.n_events;
    it->second.add_payload(is_client, ts, pay, plen);
    g_events += (uint64_t)(it->second.n_events - before);
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
    if (ip[9] != 6 || rem < ihl) return;
    uint32_t sip = *(const uint32_t*)(ip+12);
    uint32_t dip = *(const uint32_t*)(ip+16);
    const uint8_t* tp = ip + ihl;
    uint32_t trem = rem - ihl;
    if (trem < 20) return;
    uint16_t sp = (uint16_t)((tp[0]<<8)|tp[1]);
    uint16_t dp = (uint16_t)((tp[2]<<8)|tp[3]);
    uint8_t th = (tp[12]>>4)*4;
    if (trem < th) return;
    int plen = (int)(trem - th);
    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;
    handle_tcp(sip, dip, sp, dp, ts, tp + th, plen);
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_smtp(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) { res.exit_code = 1; res.message = "pcap_path required"; return res; }
    g_pcap_name = cfg.pcap_path;
    if (const char* b = strrchr(cfg.pcap_path.c_str(), '/')) g_pcap_name = b + 1;
    const char* out = cfg.output_path.empty() ? "smtp.log" : cfg.output_path.c_str();
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
    const char* out = "smtp.log";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i+1<argc) pcap = argv[++i];
        else if (!strcmp(argv[i], "-w") && i+1<argc) out = argv[++i];
    }
    if (!pcap) {
        fprintf(stderr, "用法: %s -r <file.pcap> [-w smtp.log]\n", argv[0]);
        return 1;
    }
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap;
    cfg.output_path = out;
    return wa1kpcap::nvers::run_smtp(cfg).exit_code;
}
#endif
