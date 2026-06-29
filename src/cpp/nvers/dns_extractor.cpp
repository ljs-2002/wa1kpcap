/**
 * dns_extractor.cpp  ——  DNS 流量字段提取器
 *
 * 用法：
 *   ./dns_extractor -r <file.pcap> [-w out.log] [-v]
 *
 * 支持：
 *   UDP/TCP port 53   (标准 DNS)
 *   UDP port 5353     (mDNS)
 *   UDP port 5355     (LLMNR)
 *   DNS over TCP 2字节长度前缀（单 segment 内完整消息）
 *
 * 架构：单线程（DNS 流量远比 TLS 稀疏，解析开销集中在名称解压缩）
 * 输出：JSON Lines（每行一条 DNS 流）
 */

#include "dns_flow.h"

#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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

// ============================================================
// 流键（5 元组，双向规范化）
// ============================================================
struct DnsFlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;

    bool operator==(const DnsFlowKey& o) const noexcept {
        return src_ip==o.src_ip && dst_ip==o.dst_ip &&
               src_port==o.src_port && dst_port==o.dst_port && proto==o.proto;
    }
    // 对于 DNS：以 DNS 服务器端（port==53）为 dst
    DnsFlowKey canonical() const noexcept {
        // 如果 dst 是 DNS 端口则已规范；否则翻转
        if (is_dns_port(dst_port)) return *this;
        if (is_dns_port(src_port)) return {dst_ip,src_ip,dst_port,src_port,proto};
        // 两端都不是 DNS 端口（mDNS 等多播）：按 IP/port 排序
        if (src_ip < dst_ip) return *this;
        if (src_ip > dst_ip) return {dst_ip,src_ip,dst_port,src_port,proto};
        if (src_port <= dst_port) return *this;
        return {dst_ip,src_ip,dst_port,src_port,proto};
    }
    std::string id() const {
        char buf[96];
        in_addr s{src_ip}, d{dst_ip};
        char ss[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN];
        inet_ntop(AF_INET,&s,ss,sizeof ss);
        inet_ntop(AF_INET,&d,ds,sizeof ds);
        snprintf(buf,sizeof buf,"%s:%u->%s:%u",ss,src_port,ds,dst_port);
        return buf;
    }
};

struct DnsFlowKeyHash {
    size_t operator()(const DnsFlowKey& k) const noexcept {
        auto h64=[](uint64_t x)->uint64_t{
            x^=x>>33; x*=0xff51afd7ed558ccdULL;
            x^=x>>33; x*=0xc4ceb9fe1a85ec53ULL;
            x^=x>>33; return x;
        };
        uint64_t a=h64((uint64_t)k.src_ip|((uint64_t)k.dst_ip<<32));
        uint64_t b=h64((uint64_t)k.src_port|((uint64_t)k.dst_port<<16)|((uint64_t)k.proto<<32));
        return (size_t)(a^b);
    }
};

// ============================================================
// 全局状态
// ============================================================
static std::unordered_map<DnsFlowKey, DnsFlowRecord, DnsFlowKeyHash> g_flows;
static FILE*  g_out    = nullptr;
static bool   g_verbose= false;
static std::string g_pcap_name;

static std::atomic<uint64_t> g_total{0};
static std::atomic<uint64_t> g_dns_msgs{0};
static std::atomic<uint64_t> g_dns_flows{0};

// ============================================================
// 处理一段 DNS 消息字节（来自 UDP 或 TCP）
// ============================================================
static void handle_dns_payload(
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint8_t proto, bool is_tcp,
        double ts,
        const uint8_t* dns_data, int dns_len)
{
    DnsMsgInfo msg;
    if (!parse_dns_message(dns_data, dns_len, ts, is_tcp, msg)) return;

    g_dns_msgs++;

    // 规范化流键
    DnsFlowKey raw{src_ip, dst_ip, src_port, dst_port, proto};
    DnsFlowKey can = raw.canonical();

    auto it = g_flows.find(can);
    if (it == g_flows.end()) {
        DnsFlowRecord rec;
        std::string fid = raw.id();
        rec.init(fid.c_str(), proto, src_ip, dst_ip, src_port, dst_port);
        g_flows[can] = rec;
        it = g_flows.find(can);
        g_dns_flows++;
    }
    it->second.add_msg(msg);
}

// ============================================================
// pcap 回调
// ============================================================
static void pcap_cb(uint8_t* /*user*/,
                    const struct pcap_pkthdr* hdr,
                    const uint8_t* pkt)
{
    g_total++;
    if (hdr->caplen < 14) return;

    // 以太网
    uint16_t etype = (uint16_t)((pkt[12]<<8)|pkt[13]);
    const uint8_t* ip = pkt + 14;
    uint32_t cap_rem  = hdr->caplen - 14;

    // VLAN 802.1Q 剥离
    while (etype == 0x8100 && cap_rem >= 4) {
        etype  = (uint16_t)((ip[2]<<8)|ip[3]);
        ip    += 4; cap_rem -= 4;
    }
    if (etype != 0x0800 || cap_rem < 20) return;

    // IPv4
    uint8_t  ihl    = (ip[0] & 0xF) * 4;
    uint8_t  proto  = ip[9];
    if (proto != 6 && proto != 17) return;
    uint16_t ip_len = (uint16_t)((ip[2]<<8)|ip[3]);
    uint32_t src_ip = *(const uint32_t*)(ip+12);
    uint32_t dst_ip = *(const uint32_t*)(ip+16);
    if (cap_rem < ihl || ihl < 20) return;

    const uint8_t* tp    = ip + ihl;
    uint32_t       tp_rem= (cap_rem >= ihl) ? cap_rem - ihl : 0;
    if (tp_rem < 4) return;

    uint16_t sport = (uint16_t)((tp[0]<<8)|tp[1]);
    uint16_t dport = (uint16_t)((tp[2]<<8)|tp[3]);

    // 快速过滤非 DNS 端口
    if (!is_dns_port(sport) && !is_dns_port(dport)) return;

    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;

    if (proto == 17) {
        // UDP DNS
        if (tp_rem < 8) return;
        uint16_t ulen = (uint16_t)((tp[4]<<8)|tp[5]);
        if (ulen < 12) return;
        int dns_len = (int)(ulen - 8);
        if ((uint32_t)dns_len > tp_rem - 8) dns_len = (int)(tp_rem - 8);
        handle_dns_payload(src_ip, dst_ip, sport, dport, proto, false,
                           ts, tp + 8, dns_len);
    } else {
        // TCP DNS (with 2-byte length prefix)
        uint32_t thl = (uint32_t)((tp[12] >> 4) * 4);
        if (tp_rem < thl + 2) return;
        int pl = (int)ip_len - (int)ihl - (int)thl;
        if (pl < 2) return;
        const uint8_t* pay = tp + thl;
        uint32_t cap_pay   = (tp_rem >= thl) ? tp_rem - thl : 0U;
        // 可能有多条 DNS 消息（DNS over TCP pipelining）
        while (cap_pay >= 2) {
            uint16_t dns_len = (uint16_t)((pay[0]<<8)|pay[1]);
            pay += 2; cap_pay -= 2;
            if (dns_len < 12 || cap_pay < dns_len) break;
            handle_dns_payload(src_ip, dst_ip, sport, dport, proto, true,
                               ts, pay, (int)dns_len);
            pay += dns_len; cap_pay -= dns_len;
        }
    }
}

// ============================================================
// library entry
// ============================================================
wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_dns(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) {
        res.exit_code = 1; res.message = "pcap_path required"; return res;
    }
    g_verbose = cfg.verbose;
    g_pcap_name = cfg.pcap_path;
    {
        const char* base = strrchr(cfg.pcap_path.c_str(), '/');
        if (!base) base = strrchr(cfg.pcap_path.c_str(), '\\');
        if (base) g_pcap_name = base + 1;
    }
    const char* out_file = cfg.output_path.empty() ? "dns.log" : cfg.output_path.c_str();
    g_out = fopen(out_file, "w");
    if (!g_out) { res.exit_code = 1; res.message = "fopen output failed"; return res; }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* ph = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
    if (!ph) { fclose(g_out); res.exit_code = 1; res.message = errbuf; return res; }

    auto t0 = std::chrono::steady_clock::now();
    pcap_loop(ph, 0, pcap_cb, nullptr);
    pcap_close(ph);
    auto t1 = std::chrono::steady_clock::now();
    res.elapsed_sec = std::chrono::duration<double>(t1 - t0).count();

    for (auto& [k, rec] : g_flows) rec.emit_json(g_out, g_pcap_name.c_str());
    fclose(g_out);

    res.packets = (int64_t)g_total.load();
    res.flows = (int64_t)g_dns_flows.load();
    res.message = "ok";
    return res;
}

#ifndef NVERS_LIBRARY
// ============================================================
// main
// ============================================================
int main(int argc, char* argv[]) {
    const char* pcap_file = nullptr;
    const char* out_file  = "dns.log";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i+1<argc) pcap_file = argv[++i];
        else if (!strcmp(argv[i], "-w") && i+1<argc) out_file = argv[++i];
        else if (!strcmp(argv[i], "-v")) g_verbose = true;
    }
    if (!pcap_file) {
        fprintf(stderr, "用法: %s -r <file.pcap> [-w out.log] [-v]\n", argv[0]);
        return 1;
    }
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_file;
    cfg.output_path = out_file;
    cfg.verbose = g_verbose;
    return wa1kpcap::nvers::run_dns(cfg).exit_code;
}
#endif
