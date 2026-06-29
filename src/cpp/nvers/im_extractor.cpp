/**
 * im_extractor.cpp  ——  即时通讯应用 / 协议识别可执行工具
 *
 * 用法：
 *   ./im_extractor -r <input.pcap> [-w <output.log>] [-v]
 *
 * 编译：
 *   g++ -O3 -std=c++17 im_extractor.cpp im_detect.cpp -lpcap -lm -o im_extractor
 */

#include "im_detect.h"

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unordered_map>
#include <chrono>

#include "nvers_api.h"

struct FlowKey {
    uint32_t ip_lo, ip_hi;
    uint16_t port_lo, port_hi;
    uint8_t  proto;
    bool operator==(const FlowKey &o) const noexcept {
        return ip_lo==o.ip_lo && ip_hi==o.ip_hi &&
               port_lo==o.port_lo && port_hi==o.port_hi && proto==o.proto;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey &k) const noexcept {
        std::size_t h = k.ip_lo ^ (k.ip_hi * 2654435761u);
        h ^= ((uint32_t)k.port_lo << 16) | k.port_hi;
        h ^= k.proto * 6364136223846793005ULL;
        return h;
    }
};

static FlowKey make_key(uint32_t sip, uint32_t dip,
                         uint16_t sp, uint16_t dp, uint8_t proto) {
    FlowKey k;
    k.proto = proto;
    if (sip < dip || (sip == dip && sp < dp)) {
        k.ip_lo = sip; k.ip_hi = dip; k.port_lo = sp; k.port_hi = dp;
    } else {
        k.ip_lo = dip; k.ip_hi = sip; k.port_lo = dp; k.port_hi = sp;
    }
    return k;
}

struct FlowEntry {
    ImFlow   flow;
    uint32_t src_ip;
    uint16_t src_port;
    bool     emitted;
    FlowEntry() : src_ip(0), src_port(0), emitted(false) {
        memset(&flow, 0, sizeof flow);
    }
};

static std::unordered_map<FlowKey, FlowEntry, FlowKeyHash> g_flow_table;
static uint64_t g_total_pkts = 0, g_total_bytes = 0;
static uint64_t g_im_pkts = 0, g_flows_seen = 0, g_im_flows = 0;
static FILE *g_logfp = nullptr;
static bool  g_verbose = false;

static char *ip4str(uint32_t ip, char *buf, int bsz) {
    snprintf(buf, bsz, "%u.%u.%u.%u",
             (ip>>24)&0xff,(ip>>16)&0xff,(ip>>8)&0xff,ip&0xff);
    return buf;
}

static void pkt_callback(u_char *, const struct pcap_pkthdr *hdr, const u_char *raw) {
    g_total_pkts++;
    g_total_bytes += hdr->caplen;

    if ((unsigned)hdr->caplen < sizeof(struct ether_header)) return;
    const struct ether_header *eth = (const struct ether_header*)raw;
    uint16_t etype = ntohs(eth->ether_type);
    const uint8_t *payload = raw + sizeof(struct ether_header);
    int remain = (int)hdr->caplen - (int)sizeof(struct ether_header);

    while ((etype == 0x8100 || etype == 0x88a8) && remain >= 4) {
        etype = (uint16_t)((payload[2]<<8)|payload[3]);
        payload += 4; remain -= 4;
    }
    if (etype != ETHERTYPE_IP || remain < (int)sizeof(struct ip)) return;

    const struct ip *iph = (const struct ip*)payload;
    if (iph->ip_v != 4) return;
    int iphlen = iph->ip_hl * 4;
    if (iphlen < 20 || remain < iphlen) return;

    uint8_t  proto = iph->ip_p;
    uint32_t sip   = ntohl(iph->ip_src.s_addr);
    uint32_t dip   = ntohl(iph->ip_dst.s_addr);
    int ip_payload_len = ntohs(iph->ip_len) - iphlen;
    if (ip_payload_len <= 0) return;

    const uint8_t *l4 = payload + iphlen;
    int l4_remain = std::min(remain - iphlen, ip_payload_len);

    uint16_t sp = 0, dp = 0;
    const uint8_t *l4_payload = nullptr;
    int l4_payload_len = 0;

    if (proto == IPPROTO_TCP) {
        if (l4_remain < (int)sizeof(struct tcphdr)) return;
        const struct tcphdr *tcp = (const struct tcphdr*)l4;
        sp = ntohs(tcp->th_sport); dp = ntohs(tcp->th_dport);
        int tcphlen = tcp->th_off * 4;
        if (tcphlen < 20 || l4_remain < tcphlen) return;
        l4_payload = l4 + tcphlen;
        l4_payload_len = l4_remain - tcphlen;
    } else if (proto == IPPROTO_UDP) {
        if (l4_remain < 8) return;
        const struct udphdr *udp = (const struct udphdr*)l4;
        sp = ntohs(udp->uh_sport); dp = ntohs(udp->uh_dport);
        l4_payload = l4 + 8;
        l4_payload_len = l4_remain - 8;
    } else {
        return;
    }

    if (l4_payload_len <= 0) return;

    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;
    FlowKey key = make_key(sip, dip, sp, dp, proto);
    auto it = g_flow_table.find(key);
    if (it == g_flow_table.end()) {
        g_flows_seen++;
        FlowEntry entry;
        entry.src_ip = sip;
        entry.src_port = sp;
        im_flow_init(&entry.flow, sp, dp, proto);
        g_flow_table.emplace(key, std::move(entry));
        it = g_flow_table.find(key);
    }

    FlowEntry &fe = it->second;
    bool is_fwd = (fe.src_ip == sip && fe.src_port == sp);
    uint32_t server_ip   = is_fwd ? dip : sip;
    uint16_t server_port = is_fwd ? dp  : sp;
    im_flow_set_server(&fe.flow, server_ip, server_port);

    ImProto prev = fe.flow.proto;
    im_flow_update(&fe.flow, l4_payload, l4_payload_len, is_fwd, ts);

    if (fe.flow.proto != IM_UNKNOWN) {
        g_im_pkts++;
        if (g_verbose && prev == IM_UNKNOWN) {
            char s1[20], s2[20];
            printf("[DETECT] %s:%u → %s:%u  %s  conf=%s  %s\n",
                   ip4str(sip,s1,sizeof s1), sp,
                   ip4str(dip,s2,sizeof s2), dp,
                   im_proto_name(fe.flow.proto),
                   im_conf_name(fe.flow.confidence),
                   fe.flow.detail);
        }
    }
}

static void emit_all_flows() {
    for (auto &[key, fe] : g_flow_table) {
        (void)key;
        if (fe.flow.proto == IM_UNKNOWN || fe.emitted) continue;
        fe.emitted = true;
        g_im_flows++;
        if (g_logfp) {
            char s1[20], s2[20];
            ip4str(fe.src_ip, s1, sizeof s1);
            uint32_t dip = (key.ip_lo == fe.src_ip) ? key.ip_hi : key.ip_lo;
            ip4str(dip, s2, sizeof s2);
            fprintf(g_logfp, "Flow %s:%u ↔ %s:%u\n", s1, fe.src_port, s2,
                    (key.port_lo == fe.src_port) ? key.port_hi : key.port_lo);
            im_flow_emit(&fe.flow, g_logfp);
        }
    }
}

static void print_stats(double elapsed_sec) {
    printf("\n=== IM Extractor Summary ===\n");
    printf("  Input packets : %llu\n", (unsigned long long)g_total_pkts);
    printf("  Input bytes   : %llu\n", (unsigned long long)g_total_bytes);
    printf("  Total flows   : %llu\n", (unsigned long long)g_flows_seen);
    printf("  IM flows      : %llu\n", (unsigned long long)g_im_flows);
    printf("  IM packets    : %llu\n", (unsigned long long)g_im_pkts);
    printf("  Elapsed       : %.3f s\n", elapsed_sec);

    uint64_t cnt[IM_PROTO_COUNT] = {};
    for (const auto &[k, fe] : g_flow_table) {
        (void)k;
        if (fe.flow.proto < IM_PROTO_COUNT)
            cnt[(int)fe.flow.proto]++;
    }
    printf("\n  Protocol breakdown:\n");
    for (int i = 1; i < IM_PROTO_COUNT; i++) {
        if (cnt[i] > 0)
            printf("    %-22s %llu flows\n",
                   im_proto_name((ImProto)i),
                   (unsigned long long)cnt[i]);
    }
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -r <pcap_file> [-w <log_file>] [-v]\n"
        "  -r <file>   input pcap (required)\n"
        "  -w <file>   output log (default: im.log)\n"
        "  -v          verbose\n",
        prog);
    exit(1);
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_im(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) {
        res.exit_code = 1;
        res.message = "pcap_path required";
        return res;
    }

    g_flow_table.clear();
    g_total_pkts = g_total_bytes = g_im_pkts = g_flows_seen = g_im_flows = 0;
    g_verbose = cfg.verbose;

    const char* log_file = cfg.output_path.empty() ? "im.log" : cfg.output_path.c_str();
    g_logfp = fopen(log_file, "w");
    if (!g_logfp) {
        res.exit_code = 1;
        res.message = "fopen output failed";
        return res;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pc = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
    if (!pc) {
        fclose(g_logfp);
        g_logfp = nullptr;
        res.exit_code = 1;
        res.message = errbuf;
        return res;
    }

    auto t0 = std::chrono::steady_clock::now();
    pcap_loop(pc, 0, pkt_callback, nullptr);
    auto t1 = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();
    pcap_close(pc);

    emit_all_flows();
    fclose(g_logfp);
    g_logfp = nullptr;

    res.elapsed_sec = elapsed;
    res.packets = (int64_t)g_total_pkts;
    res.flows = (int64_t)g_im_flows;
    res.message = "ok";
    return res;
}

#ifndef NVERS_LIBRARY
int main(int argc, char* argv[]) {
    const char *pcap_file = nullptr;
    const char *log_file  = "im.log";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i+1 < argc) pcap_file = argv[++i];
        else if (!strcmp(argv[i], "-w") && i+1 < argc) log_file = argv[++i];
        else if (!strcmp(argv[i], "-v")) g_verbose = true;
        else usage(argv[0]);
    }
    if (!pcap_file) usage(argv[0]);
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_file;
    cfg.output_path = log_file;
    cfg.verbose = g_verbose;
    return wa1kpcap::nvers::run_im(cfg).exit_code;
}
#endif
