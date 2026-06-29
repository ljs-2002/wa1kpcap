/**
 * vpn_extractor.cpp  ——  广义 VPN 协议识别可执行工具
 *
 * 功能：
 *   读取 pcap 文件，逐包解析 Ethernet/VLAN/IPv4/TCP/UDP，
 *   使用 vpn_detect 库（vpn_detect.cpp + vpn_detect.h）对每条流进行
 *   有状态协议识别，将检测到的 VPN 流写入日志文件，并在终端输出统计。
 *
 * 检测协议：
 *   WireGuard, OpenVPN, Shadowsocks, VMess, VLESS, Trojan,
 *   Psiphon, Lantern, Clash, Hysteria/QUIC-VPN
 *
 * 用法：
 *   ./vpn_extractor -r <input.pcap> [-w <output.log>] [-v]
 *
 * 编译：
 *   g++ -O3 -std=c++17 vpn_extractor.cpp vpn_detect.cpp -lpcap -lm -o vpn_extractor
 */

#include "vpn_detect.h"

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
#include <cmath>
#include <unordered_map>
#include <string>
#include <vector>
#include <mutex>
#include <chrono>

#include "nvers_api.h"

/* ============================================================
 * 流 Key（5-tuple，canonical 双向）
 * ============================================================ */
struct FlowKey {
    uint32_t ip_lo, ip_hi;
    uint16_t port_lo, port_hi;
    uint8_t  proto;
    bool operator==(const FlowKey &o) const noexcept {
        return ip_lo==o.ip_lo && ip_hi==o.ip_hi &&
               port_lo==o.port_lo && port_hi==o.port_hi &&
               proto==o.proto;
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

/* 构造 canonical（方向无关）FlowKey */
static FlowKey make_key(uint32_t sip, uint32_t dip,
                         uint16_t sp, uint16_t dp, uint8_t proto) {
    FlowKey k;
    k.proto = proto;
    if (sip < dip || (sip == dip && sp < dp)) {
        k.ip_lo=sip; k.ip_hi=dip; k.port_lo=sp; k.port_hi=dp;
    } else {
        k.ip_lo=dip; k.ip_hi=sip; k.port_lo=dp; k.port_hi=sp;
    }
    return k;
}

/* ============================================================
 * 每流状态包装
 * ============================================================ */
struct FlowEntry {
    VpnFlow  flow;
    uint32_t src_ip;   /* 首包来源（决定 is_fwd 方向） */
    uint16_t src_port;
    bool     emitted;

    FlowEntry() : src_ip(0), src_port(0), emitted(false) {
        memset(&flow, 0, sizeof flow);
    }
};

/* ============================================================
 * 全局流表
 * ============================================================ */
static std::unordered_map<FlowKey, FlowEntry, FlowKeyHash> g_flow_table;

/* 统计 */
static uint64_t g_total_pkts  = 0;
static uint64_t g_total_bytes = 0;
static uint64_t g_vpn_pkts    = 0;
static uint64_t g_flows_seen  = 0;
static uint64_t g_vpn_flows   = 0;

/* 输出文件 */
static FILE *g_logfp = nullptr;
static bool  g_verbose = false;

/* ============================================================
 * IP → 字符串
 * ============================================================ */
static char *ip4str(uint32_t ip, char *buf, int bsz) {
    snprintf(buf, bsz, "%u.%u.%u.%u",
             (ip>>24)&0xff,(ip>>16)&0xff,(ip>>8)&0xff,ip&0xff);
    return buf;
}

/* ============================================================
 * pcap 回调
 * ============================================================ */
static void pkt_callback(u_char * /*arg*/,
                          const struct pcap_pkthdr *hdr,
                          const u_char *raw) {
    g_total_pkts++;
    g_total_bytes += hdr->caplen;

    /* ---- 以太帧解析 ---- */
    if ((unsigned)hdr->caplen < sizeof(struct ether_header)) return;
    const struct ether_header *eth = reinterpret_cast<const struct ether_header*>(raw);
    uint16_t etype = ntohs(eth->ether_type);
    const uint8_t *payload = raw + sizeof(struct ether_header);
    int remain = (int)hdr->caplen - (int)sizeof(struct ether_header);

    /* 跳过 VLAN tag(s) */
    while ((etype == 0x8100 || etype == 0x88a8) && remain >= 4) {
        etype   = (uint16_t)((payload[2]<<8)|payload[3]);
        payload += 4; remain -= 4;
    }
    if (etype != ETHERTYPE_IP || remain < (int)sizeof(struct ip)) return;

    /* ---- IPv4 解析 ---- */
    const struct ip *iph = reinterpret_cast<const struct ip*>(payload);
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
        const struct tcphdr *tcp = reinterpret_cast<const struct tcphdr*>(l4);
        sp = ntohs(tcp->th_sport); dp = ntohs(tcp->th_dport);
        int tcphlen = tcp->th_off * 4;
        if (tcphlen < 20 || l4_remain < tcphlen) return;
        l4_payload     = l4 + tcphlen;
        l4_payload_len = l4_remain - tcphlen;
    } else if (proto == IPPROTO_UDP) {
        if (l4_remain < 8) return;
        const struct udphdr *udp = reinterpret_cast<const struct udphdr*>(l4);
        sp = ntohs(udp->uh_sport); dp = ntohs(udp->uh_dport);
        l4_payload     = l4 + 8;
        l4_payload_len = l4_remain - 8;
    } else {
        return; /* 仅处理 TCP/UDP */
    }

    if (l4_payload_len <= 0) return;

    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;

    /* ---- 查找或创建流表条目 ---- */
    FlowKey key = make_key(sip, dip, sp, dp, proto);
    auto it = g_flow_table.find(key);
    if (it == g_flow_table.end()) {
        g_flows_seen++;
        FlowEntry entry;
        entry.src_ip   = sip;
        entry.src_port = sp;
        vpn_flow_init(&entry.flow, sp, dp, proto);
        g_flow_table.emplace(key, std::move(entry));
        it = g_flow_table.find(key);
    }

    FlowEntry &fe = it->second;
    bool is_fwd = (fe.src_ip == sip && fe.src_port == sp);

    /* ---- 更新流状态 ---- */
    VpnProto prev_proto = fe.flow.proto;
    vpn_flow_update(&fe.flow, l4_payload, l4_payload_len, is_fwd, ts);

    if (fe.flow.proto != VPN_UNKNOWN) {
        g_vpn_pkts++;
        /* 首次识别时打印（verbose 模式） */
        if (g_verbose && prev_proto == VPN_UNKNOWN &&
            fe.flow.proto != VPN_UNKNOWN) {
            char s1[20], s2[20];
            printf("[DETECT] %s:%u → %s:%u  %s  conf=%s\n",
                   ip4str(sip,s1,sizeof s1), sp,
                   ip4str(dip,s2,sizeof s2), dp,
                   vpn_proto_name(fe.flow.proto),
                   vpn_conf_name(fe.flow.confidence));
        }
    }
}

/* ============================================================
 * 输出所有检测到的 VPN 流
 * ============================================================ */
static void emit_all_flows() {
    for (auto &[key, fe] : g_flow_table) {
        (void)key;
        if (fe.flow.proto == VPN_UNKNOWN) continue;
        if (fe.emitted) continue;
        fe.emitted = true;
        g_vpn_flows++;
        if (g_logfp) vpn_flow_emit(&fe.flow, g_logfp);
    }
}

/* ============================================================
 * 打印统计摘要
 * ============================================================ */
static void print_stats(double elapsed_sec) {
    printf("\n=== VPN Extractor Summary ===\n");
    printf("  Input packets : %llu\n",   (unsigned long long)g_total_pkts);
    printf("  Input bytes   : %llu\n",   (unsigned long long)g_total_bytes);
    printf("  Total flows   : %llu\n",   (unsigned long long)g_flows_seen);
    printf("  VPN flows     : %llu\n",   (unsigned long long)g_vpn_flows);
    printf("  VPN packets   : %llu\n",   (unsigned long long)g_vpn_pkts);
    printf("  Elapsed       : %.3f s\n", elapsed_sec);
    printf("  Throughput    : %.1f kpkt/s\n",
           elapsed_sec > 0.0 ? (double)g_total_pkts / elapsed_sec / 1000.0 : 0.0);

    /* 协议分布 */
    uint64_t cnt[VPN_PROTO_COUNT] = {};
    for (const auto &[k, fe] : g_flow_table) {
        (void)k;
        if (fe.flow.proto < VPN_PROTO_COUNT)
            cnt[(int)fe.flow.proto]++;
    }
    printf("\n  Protocol breakdown:\n");
    for (int i = 1; i < VPN_PROTO_COUNT; i++) {
        if (cnt[i] > 0)
            printf("    %-22s %llu flows\n",
                   vpn_proto_name((VpnProto)i),
                   (unsigned long long)cnt[i]);
    }
    if (g_logfp && g_logfp != stdout)
        printf("\n  Log written to: vpn.log\n");
}

/* ============================================================
 * main
 * ============================================================ */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -r <pcap_file> [-w <log_file>] [-v]\n"
        "  -r <file>   input pcap file (required)\n"
        "  -w <file>   output log file (default: vpn.log)\n"
        "  -v          verbose: print each new VPN flow as detected\n",
        prog);
    exit(1);
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_vpn(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) {
        res.exit_code = 1;
        res.message = "pcap_path required";
        return res;
    }

    g_flow_table.clear();
    g_total_pkts = g_total_bytes = g_vpn_pkts = g_flows_seen = g_vpn_flows = 0;
    g_verbose = cfg.verbose;

    const char* log_file = cfg.output_path.empty() ? "vpn.log" : cfg.output_path.c_str();
    g_logfp = fopen(log_file, "w");
    if (!g_logfp) {
        res.exit_code = 1;
        res.message = "fopen output failed";
        return res;
    }
    fprintf(g_logfp, "# VPN Extractor Log\n# Input: %s\n\n", cfg.pcap_path.c_str());

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
    res.flows = (int64_t)g_vpn_flows;
    res.message = "ok";
    return res;
}

#ifndef NVERS_LIBRARY
int main(int argc, char* argv[]) {
    const char *pcap_file = nullptr;
    const char *log_file  = "vpn.log";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i+1 < argc)
            pcap_file = argv[++i];
        else if (strcmp(argv[i], "-w") == 0 && i+1 < argc)
            log_file = argv[++i];
        else if (strcmp(argv[i], "-v") == 0)
            g_verbose = true;
        else
            usage(argv[0]);
    }
    if (!pcap_file) usage(argv[0]);
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_file;
    cfg.output_path = log_file;
    cfg.verbose = g_verbose;
    return wa1kpcap::nvers::run_vpn(cfg).exit_code;
}
#endif
