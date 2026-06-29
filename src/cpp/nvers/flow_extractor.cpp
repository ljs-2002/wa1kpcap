/**
 * flow_extractor.cpp  ——  NetFlow / IPFIX / Argus 特征提取，输出 JSON
 *
 * 用法：
 *   ./flow_extractor -r <pcap> [-w <output.json>] [-n <max_pkts>] [-v]
 *
 * 输出格式（flows.json）：
 *   {
 *     "meta": { ... },
 *     "flows": [
 *       {
 *         "flow_id": 1,
 *         "five_tuple": { ... },
 *         "netflow_v5": { ... },   // RFC 3954 §8.1 核心字段
 *         "ipfix": { ... },        // RFC 7011/7012 扩展 IE
 *         "argus": { ... }         // Argus 双向审计字段
 *       },
 *       ...
 *     ]
 *   }
 *
 * 编译：
 *   g++ -O3 -std=c++17 flow_extractor.cpp -lpcap -lm -o flow_extractor
 */

#include "netflow_flow.h"
#include "argus_flow.h"
#include "flow_limit.h"

#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <unordered_map>
#include <string>
#include <chrono>
#include <vector>

#include "nvers_api.h"

/* ============================================================
 * 5-tuple 流 Key（双向 canonical）
 * ============================================================ */
struct FlowKey {
    uint32_t ip_a, ip_b;
    uint16_t port_a, port_b;
    uint8_t  proto;
    bool operator==(const FlowKey &o) const noexcept {
        return ip_a==o.ip_a && ip_b==o.ip_b &&
               port_a==o.port_a && port_b==o.port_b && proto==o.proto;
    }
};
struct FlowKeyHash {
    size_t operator()(const FlowKey &k) const noexcept {
        size_t h = (size_t)k.ip_a * 2654435761u ^ (size_t)k.ip_b * 1234567891u;
        h ^= ((size_t)k.port_a << 16) | k.port_b;
        h ^= (size_t)k.proto * 6364136223846793005ULL;
        return h;
    }
};

static FlowKey make_key(uint32_t sip, uint32_t dip,
                         uint16_t sp,  uint16_t dp, uint8_t proto) {
    FlowKey k; k.proto = proto;
    if (sip < dip || (sip==dip && sp<dp)) { k.ip_a=sip; k.ip_b=dip; k.port_a=sp;  k.port_b=dp; }
    else                                   { k.ip_a=dip; k.ip_b=sip; k.port_a=dp;  k.port_b=sp; }
    return k;
}

/* ============================================================
 * 流条目：NetFlow + Argus 记录合并
 * ============================================================ */
struct FlowEntry {
    NetFlowRecord nf;
    ArgusRecord   argus;
    uint32_t      src_ip_first;   /* 首包来源，决定 is_fwd */
    uint16_t      src_port_first;
    uint32_t      flow_id;
};

/* ============================================================
 * 全局状态
 * ============================================================ */
static std::unordered_map<FlowKey, FlowEntry, FlowKeyHash> g_flows;
static uint64_t g_total_pkts  = 0;
static uint64_t g_total_bytes = 0;
static uint64_t g_flow_id_seq = 0;

/* CLI 参数 */
static std::string g_pcap_path_storage;
static const char *g_out_file  = "flows.json";
static bool        g_verbose   = false;
static int         g_n_limit   = FLOW_LIMIT_ALL;

/* ============================================================
 * 辅助：写 JSON 中的协议名
 * ============================================================ */
static const char *proto_name(uint8_t p) {
    switch (p) {
    case 6:  return "TCP";
    case 17: return "UDP";
    case 1:  return "ICMP";
    case 47: return "GRE";
    case 50: return "ESP";
    case 132:return "SCTP";
    default: return "OTHER";
    }
}

/* ============================================================
 * pcap 回调
 * ============================================================ */
static void pkt_cb(u_char * /*arg*/,
                    const struct pcap_pkthdr *hdr,
                    const u_char *raw) {
    g_total_pkts++;
    g_total_bytes += hdr->caplen;

    /* ---- L2: Ethernet ---- */
    if ((unsigned)hdr->caplen < sizeof(struct ether_header)) return;
    const struct ether_header *eth = (const struct ether_header*)raw;
    uint16_t etype = ntohs(eth->ether_type);
    const uint8_t *p   = raw + sizeof(struct ether_header);
    int            rem = (int)hdr->caplen - (int)sizeof(struct ether_header);

    /* VLAN tags */
    while ((etype == 0x8100 || etype == 0x88a8) && rem >= 4) {
        etype = (uint16_t)((p[2]<<8)|p[3]); p += 4; rem -= 4;
    }
    if (etype != ETHERTYPE_IP || rem < (int)sizeof(struct ip)) return;

    /* ---- L3: IPv4 ---- */
    const struct ip *iph = (const struct ip*)p;
    if (iph->ip_v != 4) return;
    int iphlen     = iph->ip_hl * 4;
    if (iphlen < 20 || rem < iphlen) return;
    int ip_total   = ntohs(iph->ip_len);
    uint8_t  proto = iph->ip_p;
    uint32_t sip   = ntohl(iph->ip_src.s_addr);
    uint32_t dip   = ntohl(iph->ip_dst.s_addr);
    uint8_t  ttl   = iph->ip_ttl;
    uint8_t  tos   = iph->ip_tos;
    uint16_t ip_id = ntohs(iph->ip_id);

    const uint8_t *l4 = p + iphlen;
    int l4_rem = std::min(rem - iphlen, ip_total - iphlen);

    uint16_t sp = 0, dp = 0;
    uint8_t  tcp_fl  = 0;
    uint16_t tcp_win = 0;
    uint32_t tcp_seq = 0;
    int tcp_payload  = 0;

    if (proto == IPPROTO_TCP) {
        if (l4_rem < (int)sizeof(struct tcphdr)) return;
        const struct tcphdr *tcph = (const struct tcphdr*)l4;
        sp      = ntohs(tcph->th_sport);
        dp      = ntohs(tcph->th_dport);
        tcp_fl  = tcph->th_flags;
        tcp_win = ntohs(tcph->th_win);
        tcp_seq = ntohl(tcph->th_seq);
        int tcphlen = tcph->th_off * 4;
        tcp_payload = l4_rem - tcphlen;
        if (tcp_payload < 0) tcp_payload = 0;
    } else if (proto == IPPROTO_UDP) {
        if (l4_rem < 8) return;
        const struct udphdr *udph = (const struct udphdr*)l4;
        sp = ntohs(udph->uh_sport);
        dp = ntohs(udph->uh_dport);
        tcp_payload = l4_rem - 8;
    } else { return; }

    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;
    FlowKey key = make_key(sip, dip, sp, dp, proto);

    /* 查找或新建流 */
    auto it = g_flows.find(key);
    if (it == g_flows.end()) {
        FlowEntry fe;
        fe.flow_id          = ++g_flow_id_seq;
        fe.src_ip_first     = sip;
        fe.src_port_first   = sp;
        fe.nf.init(sip, dip, sp, dp, proto);
        fe.argus.init(sip, dip, sp, dp, proto);
        g_flows.emplace(key, std::move(fe));
        it = g_flows.find(key);
    }

    FlowEntry &fe = it->second;
    uint32_t cur_pkts = (uint32_t)(fe.nf.fwd_pkts + fe.nf.bwd_pkts);
    if (flow_limit_reached(cur_pkts, g_n_limit)) return;

    bool is_fwd = (fe.src_ip_first == sip && fe.src_port_first == sp);

    fe.nf.process_packet(ip_total, iphlen, tcp_fl, ttl, tos, is_fwd, ts);
    fe.argus.process_packet(ip_total, tcp_fl, tcp_win, tcp_seq,
                             tcp_payload, ttl, tos, ip_id, is_fwd, ts);

    if (g_verbose && (fe.nf.fwd_pkts + fe.nf.bwd_pkts) == 1) {
        char s1[20], s2[20];
        nf_ip4str(sip, s1, sizeof s1);
        nf_ip4str(dip, s2, sizeof s2);
        printf("  [NEW FLOW #%u] %s:%u → %s:%u %s\n",
               fe.flow_id, s1, sp, s2, dp, proto_name(proto));
    }
}

/* ============================================================
 * JSON 输出
 * ============================================================ */
static void write_json(FILE *fp, double capture_dur) {
    /* ---- meta ---- */
    fprintf(fp, "{\n");
    fprintf(fp, "  \"meta\": {\n");
    fprintf(fp, "    \"generator\":       \"flow_extractor\",\n");
    fprintf(fp, "    \"formats\":         [\"netflow_v5\", \"ipfix\", \"argus\"],\n");
    fprintf(fp, "    \"pcap_file\":       \"%s\",\n", g_pcap_path_storage.c_str());
    fprintf(fp, "    \"total_packets\":   %llu,\n", (unsigned long long)g_total_pkts);
    fprintf(fp, "    \"total_bytes\":     %llu,\n", (unsigned long long)g_total_bytes);
    fprintf(fp, "    \"total_flows\":     %zu,\n", g_flows.size());
    fprintf(fp, "    \"n_limit\":         %d,\n", g_n_limit);
    fprintf(fp, "    \"capture_dur_s\":   %.6f\n", capture_dur);
    fprintf(fp, "  },\n\n");

    /* ---- flows ---- */
    fprintf(fp, "  \"flows\": [\n");
    bool first_flow = true;
    for (auto &[key, fe] : g_flows) {
        (void)key;
        fe.nf.finalize();
        fe.argus.finalize();

        if (!first_flow) fprintf(fp, ",\n");
        first_flow = false;

        char s1[20], s2[20];
        nf_ip4str(fe.nf.src_ip, s1, sizeof s1);
        nf_ip4str(fe.nf.dst_ip, s2, sizeof s2);

        fprintf(fp, "    {\n");
        fprintf(fp, "      \"flow_id\":    %u,\n", fe.flow_id);

        /* five_tuple */
        fprintf(fp, "      \"five_tuple\": {\n");
        fprintf(fp, "        \"src_ip\":   \"%s\",\n", s1);
        fprintf(fp, "        \"dst_ip\":   \"%s\",\n", s2);
        fprintf(fp, "        \"src_port\": %u,\n", fe.nf.src_port);
        fprintf(fp, "        \"dst_port\": %u,\n", fe.nf.dst_port);
        fprintf(fp, "        \"protocol\": %u,\n", (unsigned)fe.nf.prot);
        fprintf(fp, "        \"proto_name\": \"%s\"\n", proto_name(fe.nf.prot));
        fprintf(fp, "      },\n");

        /* NetFlow v5 */
        fe.nf.emit_json_netflow_v5(fp, "      ");
        fprintf(fp, ",\n");

        /* IPFIX */
        fe.nf.emit_json_ipfix(fp, "      ");
        fprintf(fp, ",\n");

        /* Argus */
        fe.argus.emit_json_argus(fp, "      ");
        fprintf(fp, "\n");

        fprintf(fp, "    }");
    }
    fprintf(fp, "\n  ]\n}\n");
}

/* ============================================================
 * main
 * ============================================================ */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s -r <pcap> [-w <output.json>] [-n N] [-v]\n"
        "  -r <file>  Input pcap file\n"
        "  -w <file>  Output JSON file (default: flows.json)\n"
        "  -n <N>     Packets per flow to analyze, 0=all (default 0)\n"
        "  -v         Verbose: print new flows\n",
        prog);
    exit(1);
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_flow(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) {
        res.exit_code = 1;
        res.message = "pcap_path required";
        return res;
    }

    g_flows.clear();
    g_total_pkts = g_total_bytes = g_flow_id_seq = 0;
    g_pcap_path_storage = cfg.pcap_path;
    g_n_limit = cfg.n_limit >= 0 ? cfg.n_limit : FLOW_LIMIT_ALL;
    g_verbose = cfg.verbose;

    const char* out_file = cfg.output_path.empty() ? "flows.json" : cfg.output_path.c_str();

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pc = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
    if (!pc) {
        res.exit_code = 1;
        res.message = errbuf;
        return res;
    }

    auto t0 = std::chrono::steady_clock::now();
    pcap_loop(pc, 0, pkt_cb, nullptr);
    auto t1 = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(t1 - t0).count();
    pcap_close(pc);

    FILE* fp = fopen(out_file, "w");
    if (!fp) {
        res.exit_code = 1;
        res.message = "fopen output failed";
        return res;
    }
    write_json(fp, elapsed);
    fclose(fp);

    res.elapsed_sec = elapsed;
    res.packets = (int64_t)g_total_pkts;
    res.flows = (int64_t)g_flows.size();
    res.message = "ok";
    return res;
}

#ifndef NVERS_LIBRARY
int main(int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        if      (!strcmp(argv[i],"-r") && i+1<argc) g_pcap_path_storage = argv[++i];
        else if (!strcmp(argv[i],"-w") && i+1<argc) g_out_file  = argv[++i];
        else if (!strcmp(argv[i],"-n") && i+1<argc) g_n_limit   = atoi(argv[++i]);
        else if (!strcmp(argv[i],"-v"))              g_verbose   = true;
        else    usage(argv[0]);
    }
    if (g_pcap_path_storage.empty()) usage(argv[0]);
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = g_pcap_path_storage;
    cfg.output_path = g_out_file;
    cfg.n_limit = g_n_limit;
    cfg.verbose = g_verbose;
    return wa1kpcap::nvers::run_flow(cfg).exit_code;
}
#endif
