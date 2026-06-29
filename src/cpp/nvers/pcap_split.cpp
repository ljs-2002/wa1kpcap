/**
 * pcap_split.cpp  ——  按五元组（双向 canonical 流）切分 pcap
 *
 * 用法：
 *   ./pcap_split -r <file.pcap> [-o <输出目录>]
 *
 * 若不指定 -o，则在 pcap 所在目录下创建与 pcap 同名（无扩展名）的文件夹，
 * 将各流写入独立 pcap 文件。
 *
 * 输出命名：<pcap基名>_<srcip>_<sport>_<dstip>_<dport>_<proto>.pcap
 *   五元组按 canonical 排序（与 seq_extractor 等工具一致的双向流键）。
 */

#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include <filesystem>
#include <chrono>

#include "nvers_api.h"

namespace fs = std::filesystem;

// ============================================================
// 五元组流键（双向 canonical）
// ============================================================
struct FlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;

    bool operator==(const FlowKey& o) const noexcept {
        return src_ip == o.src_ip && dst_ip == o.dst_ip &&
               src_port == o.src_port && dst_port == o.dst_port &&
               proto == o.proto;
    }

    FlowKey canonical() const noexcept {
        if (src_ip < dst_ip) return *this;
        if (src_ip > dst_ip) return {dst_ip, src_ip, dst_port, src_port, proto};
        if (src_port <= dst_port) return *this;
        return {dst_ip, src_ip, dst_port, src_port, proto};
    }

    std::string filename_suffix() const {
        char buf[128];
        in_addr sa{src_ip}, da{dst_ip};
        char ss[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sa, ss, sizeof ss);
        inet_ntop(AF_INET, &da, ds, sizeof ds);
        snprintf(buf, sizeof buf, "%s_%u_%s_%u_%u",
                 ss, (unsigned)src_port, ds, (unsigned)dst_port, (unsigned)proto);
        return buf;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
        auto h64 = [](uint64_t x) -> uint64_t {
            x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
            x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
            x ^= x >> 33; return x;
        };
        uint64_t a = h64((uint64_t)k.src_ip | ((uint64_t)k.dst_ip << 32));
        uint64_t b = h64((uint64_t)k.src_port | ((uint64_t)k.dst_port << 16) |
                         ((uint64_t)k.proto << 32));
        return (size_t)(a ^ b);
    }
};

struct FlowDumper {
    pcap_dumper_t* dumper = nullptr;
    std::string    path;
    uint64_t       pkt_count = 0;
};

static std::string path_dir(const std::string& path) {
    fs::path p(path);
    if (p.has_parent_path()) return p.parent_path().string();
    return ".";
}

static std::string path_stem(const std::string& path) {
    return fs::path(path).stem().string();
}

static std::string join_path(const std::string& dir, const std::string& name) {
    return (fs::path(dir) / name).string();
}

static bool parse_ipv4_5tuple(const uint8_t* pkt, uint32_t caplen,
                              FlowKey& out) {
    if (caplen < 14) return false;
    uint16_t etype = (uint16_t)((pkt[12] << 8) | pkt[13]);
    const uint8_t* ip_start = pkt + 14;
    uint32_t rem = caplen - 14;

    while (etype == 0x8100 && rem >= 4) {
        etype = (uint16_t)((ip_start[2] << 8) | ip_start[3]);
        ip_start += 4;
        rem -= 4;
    }
    if (etype != 0x0800 || rem < 20) return false;

    uint8_t ihl = (ip_start[0] & 0x0F) * 4;
    uint8_t proto = ip_start[9];
    if (ihl < 20 || rem < (uint32_t)ihl) return false;
    if (proto != 6 && proto != 17) return false;

    uint32_t sip = *(const uint32_t*)(ip_start + 12);
    uint32_t dip = *(const uint32_t*)(ip_start + 16);
    const uint8_t* tp = ip_start + ihl;
    uint32_t tp_rem = rem - ihl;
    if (tp_rem < 4) return false;

    uint16_t sport = (uint16_t)((tp[0] << 8) | tp[1]);
    uint16_t dport = (uint16_t)((tp[2] << 8) | tp[3]);

    out = FlowKey{sip, dip, sport, dport, proto};
    return true;
}

static pcap_dumper_t* open_flow_dumper(pcap_t* pd, const std::string& out_path,
                                       std::unordered_map<FlowKey, FlowDumper, FlowKeyHash>& flows,
                                       const FlowKey& key) {
    auto it = flows.find(key);
    if (it != flows.end()) return it->second.dumper;

    FlowDumper fd;
    fd.path = out_path;
    fd.dumper = pcap_dump_open(pd, fd.path.c_str());
    if (!fd.dumper) {
        fprintf(stderr, "无法创建 %s: %s\n", fd.path.c_str(), pcap_geterr(pd));
        return nullptr;
    }
    auto [ins, ok] = flows.emplace(key, std::move(fd));
    (void)ok;
    return ins->second.dumper;
}

struct SplitCtx {
    pcap_t* pd;
    std::unordered_map<FlowKey, FlowDumper, FlowKeyHash>* flows;
    const std::string* out_dir;
    const std::string* base_name;
    uint64_t* total;
    uint64_t* written;
    uint64_t* skipped;
};

static void split_cb(u_char* user, const struct pcap_pkthdr* hdr, const u_char* pkt) {
    auto* ctx = reinterpret_cast<SplitCtx*>(user);
    (*ctx->total)++;

    FlowKey raw;
    if (!parse_ipv4_5tuple(pkt, hdr->caplen, raw)) {
        (*ctx->skipped)++;
        return;
    }
    FlowKey key = raw.canonical();

    std::string fname = *ctx->base_name + "_" + key.filename_suffix() + ".pcap";
    std::string fpath = join_path(*ctx->out_dir, fname);

    pcap_dumper_t* dumper = open_flow_dumper(ctx->pd, fpath, *ctx->flows, key);
    if (!dumper) return;

    pcap_dump((u_char*)dumper, hdr, pkt);
    auto it = ctx->flows->find(key);
    if (it != ctx->flows->end()) it->second.pkt_count++;
    (*ctx->written)++;
}

static void usage(const char* prog) {
    fprintf(stderr,
        "用法: %s -r <file.pcap> [-o <输出目录>]\n"
        "\n"
        "  -r <pcap>   输入 pcap 文件\n"
        "  -o <dir>    输出目录；省略则在 pcap 同目录下创建 <pcap基名>/\n"
        "\n"
        "每条双向流输出一个 pcap，命名：\n"
        "  <基名>_<srcip>_<sport>_<dstip>_<dport>_<proto>.pcap\n",
        prog);
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_pcap_split(const ExtractConfig& cfg) {
    ExtractResult res;
    auto t0 = std::chrono::steady_clock::now();

    if (cfg.pcap_path.empty()) {
        res.exit_code = 1;
        res.message = "pcap_path required";
        return res;
    }

    std::string pcap_path = cfg.pcap_path;
    std::string output_dir = cfg.output_path.empty()
        ? join_path(path_dir(pcap_path), path_stem(pcap_path))
        : cfg.output_path;
    std::string base_name = path_stem(pcap_path);

    std::error_code ec;
    if (!fs::create_directories(output_dir, ec) && ec) {
        res.exit_code = 1;
        res.message = std::string("mkdir failed: ") + ec.message();
        return res;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pd = pcap_open_offline(pcap_path.c_str(), errbuf);
    if (!pd) {
        res.exit_code = 1;
        res.message = std::string("pcap_open_offline: ") + errbuf;
        return res;
    }

    std::unordered_map<FlowKey, FlowDumper, FlowKeyHash> flows;
    uint64_t total_pkts = 0, written_pkts = 0, skipped_pkts = 0;

    SplitCtx ctx{pd, &flows, &output_dir, &base_name,
                 &total_pkts, &written_pkts, &skipped_pkts};
    int rc = pcap_loop(pd, 0, split_cb, reinterpret_cast<u_char*>(&ctx));

    if (rc == -1)
        fprintf(stderr, "pcap_loop 错误: %s\n", pcap_geterr(pd));

    for (auto& [k, fd] : flows) {
        if (fd.dumper) pcap_dump_close(fd.dumper);
    }
    pcap_close(pd);

    fprintf(stderr, "输入包数: %llu  写入: %llu  跳过(非TCP/UDP IPv4): %llu\n",
            (unsigned long long)total_pkts,
            (unsigned long long)written_pkts,
            (unsigned long long)skipped_pkts);
    fprintf(stderr, "流数量: %zu  输出目录: %s\n", flows.size(), output_dir.c_str());

    for (const auto& [k, fd] : flows) {
        fprintf(stderr, "  %s  (%llu pkts)\n",
                fd.path.c_str(), (unsigned long long)fd.pkt_count);
    }

    auto t1 = std::chrono::steady_clock::now();
    res.elapsed_sec = std::chrono::duration<double>(t1 - t0).count();
    res.packets = (int64_t)total_pkts;
    res.flows = (int64_t)flows.size();
    res.exit_code = (rc == -1) ? 1 : 0;
    res.message = res.exit_code ? "pcap_loop error" : "ok";
    return res;
}

#ifndef NVERS_LIBRARY
int main(int argc, char* argv[]) {
    const char* pcap_file = nullptr;
    const char* out_dir   = nullptr;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i + 1 < argc) pcap_file = argv[++i];
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) out_dir = argv[++i];
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]); return 0;
        } else {
            usage(argv[0]); return 1;
        }
    }
    if (!pcap_file) { usage(argv[0]); return 1; }

    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_file;
    if (out_dir) cfg.output_path = out_dir;
    auto r = wa1kpcap::nvers::run_pcap_split(cfg);
    return r.exit_code;
}
#endif
