/**
 * payload_extractor.cpp  ——  每流前 N 包原始 TCP/UDP 负载提取器
 *
 *   ./payload_extractor -r <file.pcap> [-n N] [-m max_bytes] [-j threads] [-w out.csv]
 *   # -n 0 默认：保存全流所有包
 *   ./payload_extractor -r <file.pcap> [-n N] [-m max_bytes] [-j threads] [-w out.csv]
 *
 * 输出：JSON Lines（每行一条流，packets 为列表）
 *
 * 注意：-m 设置每包最多保存字节数（默认 256，最大 PAY_MAX_BYTES=256 编译常量）。
 */

#include "payload_flow.h"

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
static int  g_n_pkts    = FLOW_LIMIT_ALL;
static int  g_max_bytes = PAY_BUF_SIZE;
static int  g_n_workers = 4;
static bool g_offline   = true;

// ============================================================
// 流键（5 元组）
// ============================================================
struct FlowKey {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;
    bool operator==(const FlowKey& o) const noexcept {
        return src_ip==o.src_ip && dst_ip==o.dst_ip &&
               src_port==o.src_port && dst_port==o.dst_port && proto==o.proto;
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
// SPSC 环形队列（携带负载字节）
// ============================================================
static constexpr uint32_t PAY_RING_CAP = 4096;  // 更小以节省内存

struct PayPktSlot {
    double   ts;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  proto;
    uint16_t ip_len;
    uint16_t pay_len;
    uint16_t cap_bytes;
    uint8_t  data[PAY_BUF_SIZE];
};

struct alignas(64) PaySPSCRing {
    alignas(64) std::atomic<uint32_t> w_{0};
    alignas(64) std::atomic<uint32_t> r_{0};
    PayPktSlot slots_[PAY_RING_CAP];

    bool push(const PayPktSlot& s) noexcept {
        uint32_t w  = w_.load(std::memory_order_relaxed);
        uint32_t nw = (w+1) & (PAY_RING_CAP-1);
        if (nw == r_.load(std::memory_order_acquire)) return false;
        slots_[w] = s;
        w_.store(nw, std::memory_order_release);
        return true;
    }
    bool pop(PayPktSlot& s) noexcept {
        uint32_t r = r_.load(std::memory_order_relaxed);
        if (r == w_.load(std::memory_order_acquire)) return false;
        s = slots_[r];
        r_.store((r+1)&(PAY_RING_CAP-1), std::memory_order_release);
        return true;
    }
};

// ============================================================
// Worker 分片状态
// ============================================================
struct PayFlowShard {
    std::unordered_map<FlowKey, PayloadFlowRecord, FlowKeyHash> table;
    std::unordered_map<FlowKey, uint32_t, FlowKeyHash> fwd_src;
    PaySPSCRing ring;
};

// ============================================================
// 全局共享
// ============================================================
static std::vector<PayFlowShard*> g_shards;
static FILE*  g_out   = nullptr;
static std::mutex g_out_mtx;
static std::string g_pcap_name;
static std::atomic<uint64_t> g_pkt_total{0};
static std::atomic<uint64_t> g_pkt_drop{0};

// ============================================================
// Worker 线程
// ============================================================
static void worker_fn(PayFlowShard* sh, int /*id*/) {
    PayPktSlot pkt;
    uint64_t local_cnt = 0;
    auto last_age = std::chrono::steady_clock::now();

    while (true) {
        while (sh->ring.pop(pkt)) {
            local_cnt++;
            FlowKey raw{pkt.src_ip,pkt.dst_ip,pkt.src_port,pkt.dst_port,pkt.proto};
            FlowKey can = raw.canonical();

            auto fit = sh->fwd_src.find(can);
            bool is_fwd;
            if (fit == sh->fwd_src.end()) {
                sh->fwd_src[can] = pkt.src_ip;
                is_fwd = true;
            } else {
                is_fwd = (fit->second == pkt.src_ip);
            }

            auto& rec = sh->table[can];
            if (!rec._initialized) {
                std::string fid = raw.id();
                rec.init(fid.c_str(), pkt.proto, g_n_pkts,
                         pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port);
            }
            rec.add_packet(is_fwd, pkt.ts,
                           pkt.ip_len, pkt.pay_len,
                           pkt.data, (uint32_t)pkt.cap_bytes);

            // 满 N 包：输出并删除
            if (flow_limit_reached((uint32_t)rec.n_pkts, g_n_pkts)) {
                {
                    std::lock_guard<std::mutex> lk(g_out_mtx);
                    rec.emit_json(g_out, g_pcap_name.c_str());
                }
                sh->table.erase(can);
                sh->fwd_src.erase(can);
            }
        }

        // 流老化
        if ((local_cnt & 0x3FF) == 0) {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_age).count() >= 2) {
                last_age = now;
                std::vector<FlowKey> expired;
                for (auto& [k, r] : sh->table) {
                    if (!r._initialized || r.n_pkts == 0) continue;
                    double age = now.time_since_epoch().count() * 1e-9 - r.last_ts;
                    double timeout = (r.proto == 6) ? 120.0 : 60.0;
                    if (age > timeout) expired.push_back(k);
                }
                for (auto& k : expired) {
                    {
                        std::lock_guard<std::mutex> lk(g_out_mtx);
                        sh->table[k].emit_json(g_out, g_pcap_name.c_str());
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
// pcap 回调
// ============================================================
static void pcap_cb(uint8_t* /*user*/, const struct pcap_pkthdr* hdr,
                    const uint8_t* pkt) {
    g_pkt_total++;

    if (hdr->caplen < 14) return;
    uint16_t etype = (uint16_t)((pkt[12]<<8)|pkt[13]);
    const uint8_t* ip = pkt + 14;
    uint32_t cap_rem  = hdr->caplen - 14;

    while (etype == 0x8100 && cap_rem >= 4) {
        etype   = (uint16_t)((ip[2]<<8)|ip[3]);
        ip     += 4; cap_rem -= 4;
    }
    if (etype != 0x0800 || cap_rem < 20) return;

    uint8_t  ihl   = (ip[0] & 0xF) * 4;
    uint8_t  proto = ip[9];
    if (proto != 6 && proto != 17) return;
    uint16_t ip_len = (uint16_t)((ip[2]<<8)|ip[3]);
    uint32_t src_ip = *(const uint32_t*)(ip+12);
    uint32_t dst_ip = *(const uint32_t*)(ip+16);
    if (cap_rem < ihl) return;

    const uint8_t* tp    = ip + ihl;
    uint32_t       tp_rem = (cap_rem >= ihl) ? cap_rem - ihl : 0;
    if (tp_rem < 4) return;

    uint16_t sport = (uint16_t)((tp[0]<<8)|tp[1]);
    uint16_t dport = (uint16_t)((tp[2]<<8)|tp[3]);
    uint16_t pay_len = 0;
    const uint8_t* pay_ptr = nullptr;
    uint32_t cap_pay = 0;

    if (proto == 6) {
        if (tp_rem < 20) return;
        uint8_t th = (tp[12] >> 4) * 4;
        int pl = (int)ip_len - (int)ihl - (int)th;
        pay_len = (pl > 0) ? (uint16_t)pl : 0;
        pay_ptr = tp + th;
        cap_pay = (tp_rem >= th) ? tp_rem - th : 0;
    } else {
        if (tp_rem < 8) return;
        uint16_t ulen = (uint16_t)((tp[4]<<8)|tp[5]);
        pay_len = (ulen > 8) ? ulen - 8 : 0;
        pay_ptr = tp + 8;
        cap_pay = (tp_rem >= 8) ? tp_rem - 8 : 0;
    }

    // 构建 slot
    FlowKey can = FlowKey{src_ip,dst_ip,sport,dport,proto}.canonical();
    uint32_t sid = (uint32_t)(FlowKeyHash{}(can) % (uint32_t)g_n_workers);
    PaySPSCRing* ring = &g_shards[sid]->ring;

    PayPktSlot slot{};
    slot.ts        = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;
    slot.src_ip    = src_ip;
    slot.dst_ip    = dst_ip;
    slot.src_port  = sport;
    slot.dst_port  = dport;
    slot.proto     = proto;
    slot.ip_len    = ip_len;
    slot.pay_len   = pay_len;
    uint16_t to_cap = (uint16_t)(cap_pay < (uint32_t)g_max_bytes ? cap_pay : (uint32_t)g_max_bytes);
    if (to_cap > pay_len) to_cap = pay_len;
    slot.cap_bytes = to_cap;
    if (pay_ptr && to_cap > 0) memcpy(slot.data, pay_ptr, to_cap);

    if (g_offline) {
        while (!ring->push(slot)) std::this_thread::yield();
    } else {
        if (!ring->push(slot)) g_pkt_drop++;
    }
}

wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_payload(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) { res.exit_code = 1; res.message = "pcap_path required"; return res; }

    g_n_pkts = cfg.n_limit >= 0 ? cfg.n_limit : FLOW_LIMIT_ALL;
    g_n_workers = cfg.workers > 0 ? cfg.workers : 4;
    if (g_n_workers < 1) g_n_workers = 1;
    if (g_n_workers > 64) g_n_workers = 64;

    g_pcap_name = cfg.pcap_path;
    if (const char* base = strrchr(cfg.pcap_path.c_str(), '/')) g_pcap_name = base + 1;

    const char* out_file = cfg.output_path.empty() ? "payload.log" : cfg.output_path.c_str();
    g_out = fopen(out_file, "w");
    if (!g_out) { res.exit_code = 1; res.message = "fopen output failed"; return res; }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* ph = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
    if (!ph) { fclose(g_out); res.exit_code = 1; res.message = errbuf; return res; }
    g_offline = true;

    g_shards.resize(g_n_workers);
    for (int i = 0; i < g_n_workers; i++) g_shards[i] = new PayFlowShard();
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
            if (!rec._initialized || rec.n_pkts == 0) continue;
            rec.emit_json(g_out, g_pcap_name.c_str());
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
    const char* out_file  = "payload.log";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-r") && i+1<argc) pcap_file   = argv[++i];
        else if (!strcmp(argv[i], "-n") && i+1<argc) g_n_pkts    = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-m") && i+1<argc) g_max_bytes = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-j") && i+1<argc) g_n_workers = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-w") && i+1<argc) out_file    = argv[++i];
    }
    if (!pcap_file) {
        fprintf(stderr,
            "用法: %s -r <file.pcap> [-n N] [-m max_bytes] [-j threads] [-w out.log]\n"
            "  -n 0 默认，保存每条流的全部包\n",
            argv[0]);
        return 1;
    }
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_file;
    cfg.output_path = out_file;
    cfg.n_limit = g_n_pkts;
    cfg.workers = g_n_workers;
    return wa1kpcap::nvers::run_payload(cfg).exit_code;
}
#endif
