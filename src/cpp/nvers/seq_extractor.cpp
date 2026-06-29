/**
 * seq_extractor.cpp  ——  每流前 N 包序列特征提取器
 *
 * 用法：
 *   ./seq_extractor -r <file.pcap> [-n N] [-j threads] [-w out.log]
 *   # -n 0 或不指定：分析全流； -n 30：仅前 30 包
 *
 * 输出：JSON Lines（每行一条流），列定义见 seq_flow.h::SeqFlowRecord::emit_json()
 *
 * 架构：与 cic_extractor 相同的 SPSC 多线程分片流表 + 离线反压机制。
 */

#include "seq_flow.h"

#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <cstdio>

#include "nvers_api.h"

// ============================================================
// 全局参数
// ============================================================
static int    g_n_pkts   = FLOW_LIMIT_ALL;
static int    g_n_workers= 4;
static bool   g_offline  = true;

// ============================================================
// 流键（5 元组）
// ============================================================
struct FlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;

    bool operator==(const FlowKey& o) const noexcept {
        return src_ip==o.src_ip && dst_ip==o.dst_ip &&
               src_port==o.src_port && dst_port==o.dst_port &&
               proto==o.proto;
    }
    FlowKey canonical() const noexcept {
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
        snprintf(buf,sizeof buf,"%s:%u-%s:%u/%u",ss,src_port,ds,dst_port,proto);
        return buf;
    }
};
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
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
// SPSC 无锁环形队列
// ============================================================
static constexpr uint32_t RING_CAP = 8192;

struct PktSlot {
    double   ts;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;
    uint16_t ip_len;
    uint16_t pay_len;
    uint8_t  tcp_flags;
    uint8_t  tls_type;
};

struct alignas(64) SPSCRing {
    alignas(64) std::atomic<uint32_t> w_{0};
    alignas(64) std::atomic<uint32_t> r_{0};
    PktSlot slots_[RING_CAP];

    bool push(const PktSlot& s) noexcept {
        uint32_t w = w_.load(std::memory_order_relaxed);
        uint32_t nw= (w+1) & (RING_CAP-1);
        if (nw == r_.load(std::memory_order_acquire)) return false;
        slots_[w] = s;
        w_.store(nw, std::memory_order_release);
        return true;
    }
    bool pop(PktSlot& s) noexcept {
        uint32_t r = r_.load(std::memory_order_relaxed);
        if (r == w_.load(std::memory_order_acquire)) return false;
        s = slots_[r];
        r_.store((r+1)&(RING_CAP-1), std::memory_order_release);
        return true;
    }
};

// ============================================================
// 每 Worker 的流分片状态
// ============================================================
struct FlowShard {
    std::unordered_map<FlowKey,SeqFlowRecord,FlowKeyHash> table;
    // 首包确认正向方向的映射（使用规范键指向首包 src）
    std::unordered_map<FlowKey,uint32_t,FlowKeyHash> fwd_src;
    SPSCRing ring;
};

// ============================================================
// 全局共享
// ============================================================
static std::vector<FlowShard*> g_shards;
static FILE*  g_out   = nullptr;
static std::mutex g_out_mtx;
static std::string g_pcap_file;
static std::atomic<uint64_t> g_pkt_total{0};
static std::atomic<uint64_t> g_pkt_drop{0};

// ============================================================
// Worker 线程
// ============================================================
static void worker_fn(FlowShard* sh, int /*id*/) {
    PktSlot pkt;
    uint64_t local_processed = 0;
    auto last_age = std::chrono::steady_clock::now();

    while (true) {
        while (sh->ring.pop(pkt)) {
            local_processed++;
            FlowKey raw{pkt.src_ip,pkt.dst_ip,pkt.src_port,pkt.dst_port,pkt.proto};
            FlowKey can = raw.canonical();

            // 确认正向
            auto fit = sh->fwd_src.find(can);
            bool is_fwd;
            if (fit == sh->fwd_src.end()) {
                sh->fwd_src[can] = pkt.src_ip;
                is_fwd = true;
            } else {
                is_fwd = (fit->second == pkt.src_ip);
            }

            // 查找或创建流记录
            auto& rec = sh->table[can];
            if (rec.n_pkts == 0 && rec.first_ts == 0.0) {
                std::string fid = raw.id();
                rec.init(fid.c_str(), pkt.proto, g_n_pkts,
                         pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port);
            }
            rec.add_packet(is_fwd, pkt.ts, pkt.ip_len, pkt.pay_len,
                           pkt.tcp_flags, pkt.tls_type);

            // 流已满 —— 提前输出并删除
            if (flow_limit_reached((uint32_t)rec.n_pkts, g_n_pkts)) {
                rec.flush_burst();
                {
                    std::lock_guard<std::mutex> lk(g_out_mtx);
                    rec.emit_json(g_out, g_pcap_file.c_str());
                }
                sh->table.erase(can);
                sh->fwd_src.erase(can);
            }
        }

        // 流老化（每 ~2000 包或 2 秒检查一次）
        if ((local_processed & 0x7FF) == 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_age).count() >= 2) {
                last_age = now;
                std::vector<FlowKey> expired;
                for (auto& [k,r] : sh->table) {
                    if (r.n_pkts == 0) continue;
                    double age = now.time_since_epoch().count() * 1e-9 - r.last_ts;
                    double timeout = (r.proto == 6) ? 120.0 : 60.0;
                    if (age > timeout) expired.push_back(k);
                }
                for (auto& k : expired) {
                    auto& r = sh->table[k];
                    r.flush_burst();
                    {
                        std::lock_guard<std::mutex> lk(g_out_mtx);
                        r.emit_json(g_out, g_pcap_file.c_str());
                    }
                    sh->table.erase(k);
                    sh->fwd_src.erase(k);
                }
            }
        }

        std::this_thread::yield();
    }
}

// ============================================================
// pcap 回调（主线程）
// ============================================================
struct AppCtx {
    pcap_t*  handle;
    bool     offline;
};

static void pcap_cb(uint8_t* user, const struct pcap_pkthdr* hdr,
                    const uint8_t* pkt) {
    (void)user;
    g_pkt_total++;

    // 以太网头
    if (hdr->caplen < 14) return;
    uint16_t etype = (uint16_t)((pkt[12]<<8)|pkt[13]);
    const uint8_t* ip_start = pkt + 14;
    uint32_t cap_remain = hdr->caplen - 14;

    // VLAN 802.1Q
    while (etype == 0x8100 && cap_remain >= 4) {
        etype = (uint16_t)((ip_start[2]<<8)|ip_start[3]);
        ip_start    += 4;
        cap_remain  -= 4;
    }
    if (etype != 0x0800) return;
    if (cap_remain < 20) return;

    // IPv4
    uint8_t  ihl     = (ip_start[0] & 0x0F) * 4;
    uint8_t  proto   = ip_start[9];
    if (proto != 6 && proto != 17) return;   // 只处理 TCP/UDP
    uint16_t ip_len  = (uint16_t)((ip_start[2]<<8)|ip_start[3]);
    uint32_t src_ip  = *(const uint32_t*)(ip_start + 12);
    uint32_t dst_ip  = *(const uint32_t*)(ip_start + 16);
    if (cap_remain < ihl) return;

    const uint8_t* tp = ip_start + ihl;
    uint32_t tp_rem = (cap_remain >= ihl) ? cap_remain - ihl : 0;
    if (tp_rem < 4) return;

    uint16_t sport = (uint16_t)((tp[0]<<8)|tp[1]);
    uint16_t dport = (uint16_t)((tp[2]<<8)|tp[3]);
    uint8_t  flags = 0;
    uint16_t pay_len = 0;
    const uint8_t* pay_ptr = nullptr;

    if (proto == 6) {
        if (tp_rem < 20) return;
        uint8_t  th = (tp[12] >> 4) * 4;
        flags    = tp[13];
        int pl   = (int)ip_len - (int)ihl - (int)th;
        pay_len  = (pl > 0) ? (uint16_t)pl : 0;
        pay_ptr  = tp + th;
    } else {
        if (tp_rem < 8) return;
        uint16_t ulen = (uint16_t)((tp[4]<<8)|tp[5]);
        pay_len = (ulen > 8) ? ulen - 8 : 0;
        pay_ptr = tp + 8;
    }

    // TLS 类型检测
    uint32_t cap_pay = (tp_rem > (uint32_t)(pay_ptr - tp)) ?
                       tp_rem - (uint32_t)(pay_ptr - tp) : 0;
    uint8_t tls_t = detect_tls_type(pay_ptr,
                                    (int)(cap_pay < pay_len ? cap_pay : pay_len));

    // 路由到 worker
    FlowKey can = FlowKey{src_ip,dst_ip,sport,dport,proto}.canonical();
    uint32_t shard_id = (uint32_t)(FlowKeyHash{}(can) % (uint32_t)g_n_workers);
    SPSCRing* ring = &g_shards[shard_id]->ring;

    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;
    PktSlot slot{ts, src_ip, dst_ip, sport, dport, proto,
                 ip_len, pay_len, flags, tls_t};

    if (g_offline) {
        // 离线模式：反压，自旋等待空闲槽
        while (!ring->push(slot)) std::this_thread::yield();
    } else {
        if (!ring->push(slot)) g_pkt_drop++;
    }
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_seq(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) { res.exit_code = 1; res.message = "pcap_path required"; return res; }

    g_n_pkts = cfg.n_limit >= 0 ? cfg.n_limit : FLOW_LIMIT_ALL;
    g_n_workers = cfg.workers > 0 ? cfg.workers : 4;
    if (g_n_workers < 1) g_n_workers = 1;
    if (g_n_workers > 64) g_n_workers = 64;

    g_pcap_file = cfg.pcap_path;
    if (const char* base = strrchr(cfg.pcap_path.c_str(), '/')) g_pcap_file = base + 1;

    const char* out_file = cfg.output_path.empty() ? "seq_features.log" : cfg.output_path.c_str();
    g_out = (!strcmp(out_file, "/dev/null")) ? fopen("/dev/null", "w") : fopen(out_file, "w");
    if (!g_out) { res.exit_code = 1; res.message = "fopen output failed"; return res; }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* ph = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
    if (!ph) { fclose(g_out); res.exit_code = 1; res.message = errbuf; return res; }
    g_offline = true;

    g_shards.resize(g_n_workers);
    for (int i = 0; i < g_n_workers; i++) g_shards[i] = new FlowShard();
    std::vector<std::thread> threads;
    threads.reserve(g_n_workers);
    for (int i = 0; i < g_n_workers; i++)
        threads.emplace_back(worker_fn, g_shards[i], i);

    auto t0 = std::chrono::steady_clock::now();
    pcap_loop(ph, 0, pcap_cb, nullptr);
    pcap_close(ph);

    for (int i = 0; i < g_n_workers; i++) {
        while (g_shards[i]->ring.w_.load() != g_shards[i]->ring.r_.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    for (int i = 0; i < g_n_workers; i++) {
        for (auto& [k, rec] : g_shards[i]->table) {
            if (rec.n_pkts == 0) continue;
            rec.flush_burst();
            rec.emit_json(g_out, g_pcap_file.c_str());
        }
    }
    auto t1 = std::chrono::steady_clock::now();
    res.elapsed_sec = std::chrono::duration<double>(t1 - t0).count();
    for (auto& t : threads) t.detach();
    fclose(g_out);
    res.packets = (int64_t)g_pkt_total.load();
    res.message = "ok";
    return res;
}

#ifndef NVERS_LIBRARY
// ============================================================
// main
// ============================================================
int main(int argc, char* argv[]) {
    const char* pcap_file = nullptr;
    const char* out_file  = "seq_features.log";
    g_n_pkts   = FLOW_LIMIT_ALL;
    g_n_workers = 4;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i+1 < argc) pcap_file = argv[++i];
        else if (!strcmp(argv[i], "-n") && i+1 < argc) g_n_pkts = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-j") && i+1 < argc) g_n_workers = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i+1 < argc) out_file  = argv[++i];
    }
    if (!pcap_file) {
        fprintf(stderr, "用法: %s -r <file.pcap> [-n N] [-j threads] [-w out.log]\n"
                        "  -n 0 默认，分析每条流的全部包\n", argv[0]);
        return 1;
    }
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_file;
    cfg.output_path = out_file;
    cfg.n_limit = g_n_pkts;
    cfg.workers = g_n_workers;
    return wa1kpcap::nvers::run_seq(cfg).exit_code;
}
#endif
