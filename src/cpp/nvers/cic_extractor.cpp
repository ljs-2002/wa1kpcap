/**
 * cic_extractor.cpp  ——  并行 CIC-FlowMeter 特征提取器
 *
 * ┌───────────────────────────────────────────────────────────┐
 * │  架构（多生产者-多消费者流水线）                          │
 * │                                                           │
 * │  libpcap Capture Thread                                   │
 * │     │ 解析 IP 五元组 → 计算 canonical hash → shard_id    │
 * │     ├──SPSC Ring 0──► Worker 0 (FlowShard 0) ──┐        │
 * │     ├──SPSC Ring 1──► Worker 1 (FlowShard 1) ──┤        │
 * │     │      ...               ...              ──┤──► CSV │
 * │     └──SPSC Ring N──► Worker N (FlowShard N) ──┘        │
 * │                                                           │
 * │  每个 Worker 独占自己的流表分片（无锁），仅在输出时     │
 * │  竞争一把互斥量（输出速率远低于处理速率，瓶颈很小）     │
 * └───────────────────────────────────────────────────────────┘
 *
 * 流老化（aging）机制：
 *   - TCP 流：超过 FLOW_TCP_TIMEOUT 秒无新包则驱逐
 *   - UDP 流：超过 FLOW_UDP_TIMEOUT 秒无新包则驱逐
 *   - 任意流：持续超过 FLOW_MAX_DURATION 秒则强制驱逐
 *   - Worker 每处理 AGE_CHECK_INTERVAL 个包检查一次（同时
 *     受 Wall-Clock 1 秒定时器保护，确保低速流也能老化）
 *
 * 用法：
 *   ./cic_extractor -r <pcap>   [-n N] [-j <线程数>] [-w <csv>]   # -n 0=全流(默认)
 *   ./cic_extractor -i <网卡>   [-n N] [-j <线程数>] [-w <csv>]
 */

#include "cic_flow.h"

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <vector>
#include <memory>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <getopt.h>
#include <signal.h>

#include "nvers_api.h"

// ============================================================
// SPSC（单生产者-单消费者）无锁环形队列
//
// 内存布局：
//   [64B cache line] 写指针 w_  (生产者独写)
//   [64B cache line] 读指针 r_  (消费者独写)
//   slots_[RING_CAP]             (数据区)
//
// 每 slot 存储原始包数据的副本（最多 MAX_PKT_SNAP 字节），
// 使用 memcpy 避免依赖 libpcap 内部缓冲区的生命期。
// ============================================================
static constexpr uint32_t RING_CAP     = 1u << 13;  // 8192 slots/worker（2 的幂）
static constexpr uint32_t RING_MASK    = RING_CAP - 1;
static constexpr uint32_t MAX_PKT_SNAP = 1600;       // 抓包截断长度（标准 MTU）
static constexpr int      AGE_CHECK_INTERVAL = 2000; // 每处理多少包做一次老化检查

struct PktSlot {
    double   ts;
    uint16_t caplen;
    uint8_t  data[MAX_PKT_SNAP];
};

// 约 8192 * (8+2+1600) = ~13 MB per ring，需堆分配
struct alignas(64) SPSCRing {
    alignas(64) std::atomic<uint32_t> w_{0}; // 生产者写
    alignas(64) std::atomic<uint32_t> r_{0}; // 消费者写
    PktSlot slots_[RING_CAP];

    // 生产者调用：push 失败（环满）返回 false
    inline bool push(double ts, const uint8_t* pkt, uint32_t len) noexcept {
        uint32_t w = w_.load(std::memory_order_relaxed);
        if (w - r_.load(std::memory_order_acquire) >= RING_CAP) return false;
        PktSlot& s = slots_[w & RING_MASK];
        s.ts     = ts;
        s.caplen = (uint16_t)std::min(len, MAX_PKT_SNAP);
        std::memcpy(s.data, pkt, s.caplen);
        w_.store(w + 1, std::memory_order_release);
        return true;
    }

    // 消费者调用：返回下一可读 slot，没有则 nullptr（非阻塞）
    inline const PktSlot* peek() const noexcept {
        uint32_t r = r_.load(std::memory_order_relaxed);
        if (r == w_.load(std::memory_order_acquire)) return nullptr;
        return &slots_[r & RING_MASK];
    }

    // 消费者调用：消费当前 slot（需在 peek() 返回非空后调用）
    inline void pop() noexcept {
        r_.store(r_.load(std::memory_order_relaxed) + 1,
                 std::memory_order_release);
    }

    inline bool empty() const noexcept {
        return r_.load(std::memory_order_acquire)
               == w_.load(std::memory_order_acquire);
    }

    inline uint32_t size() const noexcept {
        return w_.load(std::memory_order_acquire)
             - r_.load(std::memory_order_acquire);
    }
};

// ============================================================
// 全局共享输出状态
// ============================================================
static std::mutex        g_out_mutex;
static std::ostream*     g_out = nullptr;
static std::atomic<long> g_emitted{0};
static std::atomic<long> g_dropped{0};

static inline void emit_record(FlowRecord& rec) {
    rec.finalize();
    {
        std::lock_guard<std::mutex> lk(g_out_mutex);
        rec.emit(*g_out);
    }
    rec.emitted = true;
    g_emitted.fetch_add(1, std::memory_order_relaxed);
}

// ============================================================
// FlowShard —— 单个 Worker 线程拥有的流表分片
// ============================================================
class FlowShard {
public:
    // 环形队列由堆分配（~13 MB），避免栈溢出或 BSS 过大
    std::unique_ptr<SPSCRing> ring;

    FlowShard() : ring(new SPSCRing()) {}
    ~FlowShard() { stop(); }

    void start(int n_limit) {
        n_limit_ = n_limit;
        running_.store(true, std::memory_order_release);
        thread_ = std::thread(&FlowShard::worker_loop, this);
    }

    void stop() {
        running_.store(false, std::memory_order_release);
        if (thread_.joinable()) thread_.join();
    }

    // 运行时统计（原子，可被主线程安全读取）
    std::atomic<long> pkts_processed{0};
    std::atomic<long> flows_seen{0};
    std::atomic<long> flows_aged{0};
    std::atomic<uint32_t> max_ring_depth{0};

private:
    std::thread         thread_;
    std::atomic<bool>   running_{false};
    int                 n_limit_ = CIC_DEFAULT_N;

    // 流表：canonical FlowKey → FlowRecord（无锁，仅本 Worker 访问）
    std::unordered_map<FlowKey, FlowRecord, FlowKeyHash> flows_;

    // --------------------------------------------------------
    // 包解析 & 流更新
    // --------------------------------------------------------
    void process_slot(const PktSlot& slot) {
        const uint8_t* raw   = slot.data;
        uint32_t       caplen = slot.caplen;

        // -- Ethernet 解析 --
        if (caplen < 14) return;
        uint16_t       eth_type = ntohs(*(const uint16_t*)(raw + 12));
        const uint8_t* ip_start = raw + 14;
        uint32_t       remain   = caplen - 14;

        // 跳过 VLAN tag (802.1Q / QinQ)
        while ((eth_type == 0x8100 || eth_type == 0x88a8) && remain >= 4) {
            eth_type = ntohs(*(const uint16_t*)(ip_start + 2));
            ip_start += 4; remain -= 4;
        }
        if (eth_type != 0x0800 || remain < sizeof(struct iphdr)) return;

        // -- IPv4 解析 --
        const struct iphdr* iph = (const struct iphdr*)ip_start;
        int ip_hdr_len = iph->ihl * 4;
        if (ip_hdr_len < 20 || (uint32_t)ip_hdr_len > remain) return;

        uint8_t  proto     = iph->protocol;
        uint32_t src_ip    = iph->saddr;
        uint32_t dst_ip    = iph->daddr;
        int      ip_tot    = ntohs(iph->tot_len);

        if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) return;

        const uint8_t* tpkt    = ip_start + ip_hdr_len;
        uint32_t       tpkt_rm = remain - ip_hdr_len;

        uint16_t src_port = 0, dst_port = 0;
        uint8_t  tcp_flags = 0;
        int      win_size = -1, thdr_len = 0, payload = 0;

        if (proto == IPPROTO_TCP) {
            if (tpkt_rm < sizeof(struct tcphdr)) return;
            const struct tcphdr* th = (const struct tcphdr*)tpkt;
            src_port  = th->source; dst_port = th->dest;
            tcp_flags = th->th_flags;
            win_size  = ntohs(th->window);
            thdr_len  = th->doff * 4;
            payload   = std::max(0, ip_tot - ip_hdr_len - thdr_len);
        } else {
            if (tpkt_rm < sizeof(struct udphdr)) return;
            const struct udphdr* uh = (const struct udphdr*)tpkt;
            src_port  = uh->source; dst_port = uh->dest;
            thdr_len  = 8;
            payload   = std::max(0, (int)ntohs(uh->len) - 8);
        }

        int hdr_total = ip_hdr_len + thdr_len;

        // -- 构造流键（canonical 查找） --
        FlowKey key;
        key.src_ip = src_ip; key.dst_ip = dst_ip;
        key.src_port = src_port; key.dst_port = dst_port;
        key.proto = proto;
        FlowKey ckey = key.canonical();

        auto it = flows_.find(ckey);
        bool is_fwd;

        if (it == flows_.end()) {
            // 新流
            FlowRecord rec;
            rec.fwd_key = key;
            rec.n_limit = n_limit_;

            char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
            struct in_addr sa{src_ip}, da{dst_ip};
            inet_ntop(AF_INET, &sa, s, sizeof(s));
            inet_ntop(AF_INET, &da, d, sizeof(d));
            snprintf(rec.flow_id, sizeof(rec.flow_id),
                     "%s_%u_%s_%u_%u",
                     s, ntohs(src_port), d, ntohs(dst_port), (unsigned)proto);

            flows_.emplace(ckey, std::move(rec));
            it = flows_.find(ckey);
            flows_seen.fetch_add(1, std::memory_order_relaxed);
            is_fwd = true;
        } else {
            is_fwd = (key == it->second.fwd_key);
        }

        it->second.process_packet(is_fwd, slot.ts,
                                  ip_tot, payload, hdr_total,
                                  tcp_flags, win_size);

        if (it->second.done && !it->second.emitted) {
            emit_record(it->second);
            flows_.erase(it);
        }
    }

    // --------------------------------------------------------
    // 流老化驱逐
    //   force=true 时忽略超时，强制驱逐全部流（pcap 结束时调用）
    // --------------------------------------------------------
    void age_flows(double now_ts, bool force = false) {
        std::vector<FlowKey> expired;
        for (auto& [k, rec] : flows_) {
            if (rec.emitted) { expired.push_back(k); continue; }
            double idle = now_ts - rec.last_ts;
            double dur  = rec.last_ts - rec.start_ts;
            double timeout = (rec.fwd_key.proto == IPPROTO_TCP)
                             ? FLOW_TCP_TIMEOUT : FLOW_UDP_TIMEOUT;
            if (force || idle > timeout || dur > FLOW_MAX_DURATION) {
                emit_record(rec);
                expired.push_back(k);
            }
        }
        flows_aged.fetch_add((long)expired.size(), std::memory_order_relaxed);
        for (auto& k : expired) flows_.erase(k);
    }

    // --------------------------------------------------------
    // Worker 主循环
    // --------------------------------------------------------
    void worker_loop() {
        double   latest_ts = 0.0;
        long     proc_cnt  = 0;
        auto     last_age  = std::chrono::steady_clock::now();

        while (running_.load(std::memory_order_acquire)) {
            const PktSlot* slot = ring->peek();
            if (slot) {
                if (slot->ts > latest_ts) latest_ts = slot->ts;
                process_slot(*slot);
                ring->pop();
                ++proc_cnt;
                pkts_processed.fetch_add(1, std::memory_order_relaxed);

                // 定期老化（包计数 + Wall Clock 双保险）
                if (proc_cnt % AGE_CHECK_INTERVAL == 0) {
                    auto now = std::chrono::steady_clock::now();
                    double wall_elapsed = std::chrono::duration<double>(
                        now - last_age).count();
                    if (wall_elapsed >= 1.0) {
                        age_flows(latest_ts);
                        last_age = now;
                    }
                }

                // 记录峰值队列深度（用于性能分析）
                uint32_t depth = ring->size();
                uint32_t cur_max = max_ring_depth.load(std::memory_order_relaxed);
                if (depth > cur_max)
                    max_ring_depth.store(depth, std::memory_order_relaxed);
            } else {
                // 队列为空：短暂让出 CPU（避免 busy-spin 耗核）
                std::this_thread::yield();
            }
        }

        // 停止信号后排空队列中剩余的包
        while (const PktSlot* slot = ring->peek()) {
            if (slot->ts > latest_ts) latest_ts = slot->ts;
            process_slot(*slot);
            ring->pop();
            pkts_processed.fetch_add(1, std::memory_order_relaxed);
        }

        // 强制驱逐所有剩余流（包括未满 N 包的）
        age_flows(latest_ts, true);
    }
};

// ============================================================
// AppCtx —— 全局应用状态
// ============================================================
struct AppCtx {
    std::vector<std::unique_ptr<FlowShard>> shards;
    int n_workers = 4;
    int n_limit   = CIC_DEFAULT_N;

    std::atomic<long> total_pkts{0};

    /**
     * offline_mode = true（离线 pcap）：
     *   dispatch 使用阻塞式 push（自旋等待直到 ring 有空间），
     *   保证零丢包，同时让 Worker 决定处理速率（反压机制）。
     *
     * offline_mode = false（在线抓包）：
     *   dispatch 使用非阻塞 push，Ring 满时丢包并计数，
     *   优先保证不阻塞内核缓冲区，避免内核侧丢包更严重。
     */
    bool offline_mode = false;

    // pcap 句柄（用于在信号处理中 breakloop）
    pcap_t* handle = nullptr;
};

static AppCtx* g_ctx = nullptr;

// ============================================================
// 数据包 dispatch（在 libpcap 捕获线程中调用）
// ============================================================
static void pcap_dispatch_cb(u_char* user,
                             const struct pcap_pkthdr* hdr,
                             const uint8_t* pkt)
{
    AppCtx* ctx = reinterpret_cast<AppCtx*>(user);
    ctx->total_pkts.fetch_add(1, std::memory_order_relaxed);

    // 快速解析五元组，仅用于路由，不做完整校验
    if (hdr->caplen < 34) return;

    const uint8_t* p = pkt;
    uint16_t eth_type = ntohs(*(const uint16_t*)(p + 12));
    const uint8_t* iph_ptr = p + 14;
    uint32_t remain = hdr->caplen - 14;

    while ((eth_type == 0x8100 || eth_type == 0x88a8) && remain >= 4) {
        eth_type = ntohs(*(const uint16_t*)(iph_ptr + 2));
        iph_ptr += 4; remain -= 4;
    }
    if (eth_type != 0x0800 || remain < sizeof(struct iphdr)) return;

    const struct iphdr* iph = (const struct iphdr*)iph_ptr;
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) return;

    int ihl = iph->ihl * 4;
    if (ihl < 20 || (uint32_t)(ihl + 4) > remain) return;

    const uint8_t* tp = iph_ptr + ihl;
    // TCP & UDP 的 src/dst port 偏移相同（均在 transport header 前 4 字节）
    uint32_t sip = iph->saddr, dip = iph->daddr;
    uint16_t sp  = *(const uint16_t*)(tp),
             dp  = *(const uint16_t*)(tp + 2);

    // canonical → routing hash（与 FlowKeyHash 等价，避免构造对象）
    uint32_t rs = sip, rd = dip;
    uint16_t rsp = sp, rdp = dp;
    if (rs > rd || (rs == rd && rsp > rdp)) {
        std::swap(rs, rd); std::swap(rsp, rdp);
    }
    uint64_t a = (uint64_t)rs  | ((uint64_t)rd  << 32);
    uint64_t b = (uint64_t)rsp | ((uint64_t)rdp << 16)
                               | ((uint64_t)iph->protocol << 32);
    auto mix = [](uint64_t x) -> uint64_t {
        x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
        x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
        x ^= x >> 33; return x;
    };
    int shard_id = (int)((mix(a) ^ mix(b)) % (uint64_t)ctx->n_workers);

    double ts = hdr->ts.tv_sec + hdr->ts.tv_usec * 1e-6;
    SPSCRing* ring = ctx->shards[shard_id]->ring.get();

    if (ctx->offline_mode) {
        // 离线模式：阻塞自旋，让 Worker 的处理速率决定整体节奏（零丢包）
        while (!ring->push(ts, pkt, hdr->caplen))
            std::this_thread::yield();
    } else {
        // 在线模式：非阻塞，Ring 满则丢包（保护内核捕获缓冲区不溢出）
        if (!ring->push(ts, pkt, hdr->caplen))
            g_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}

// ============================================================
// 信号处理
// ============================================================
static void sig_handler(int) {
    if (g_ctx && g_ctx->handle)
        pcap_breakloop(g_ctx->handle);
}

// ============================================================
// 帮助文档
// ============================================================
static void print_usage(const char* prog) {
    fprintf(stderr,
        "用法:\n"
        "  %s -r <pcap文件> [-n N] [-j 线程数] [-w 输出csv]\n"
        "  %s -i <网卡名>   [-n N] [-j 线程数] [-w 输出csv]\n"
        "\n"
        "选项:\n"
        "  -r <pcap>   读取离线 pcap 文件\n"
        "  -i <iface>  在线抓包（需 root；配合 tcpreplay 使用）\n"
        "  -n <N>      每流分析包数，0=全部（默认 0）\n"
        "  -j <J>      Worker 线程数（默认 CPU 核数，上限 16）\n"
        "  -w <csv>    输出 CSV（默认 features.csv，- 表示 stdout）\n"
        "  -h          显示帮助\n",
        prog, prog);
}

// ============================================================
// library entry
// ============================================================
wa1kpcap::nvers::ExtractResult wa1kpcap::nvers::run_cic(const ExtractConfig& cfg) {
    ExtractResult res;
    if (cfg.pcap_path.empty()) { res.exit_code = 1; res.message = "pcap_path required"; return res; }

    std::string output_file = cfg.output_path.empty() ? "features.csv" : cfg.output_path;
    int n_limit = cfg.n_limit >= 0 ? cfg.n_limit : CIC_DEFAULT_N;
    int n_workers = cfg.workers;
    if (n_workers <= 0) {
        int hw = (int)std::thread::hardware_concurrency();
        n_workers = std::min(std::max(hw, 1), 16);
    }
    n_workers = std::max(1, std::min(n_workers, 64));

    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_open_offline(cfg.pcap_path.c_str(), errbuf);
    if (!handle) { res.exit_code = 1; res.message = errbuf; return res; }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    std::ofstream fout;
    std::ostream* out_ptr = nullptr;
    if (output_file == "-") {
        out_ptr = &std::cout;
    } else {
        fout.open(output_file);
        if (!fout) {
            pcap_close(handle);
            res.exit_code = 1;
            res.message = "cannot open output";
            return res;
        }
        out_ptr = &fout;
    }
    g_out = out_ptr;

    AppCtx ctx;
    ctx.n_workers = n_workers;
    ctx.n_limit = n_limit;
    ctx.handle = handle;
    ctx.offline_mode = true;
    g_ctx = &ctx;

    ctx.shards.resize(n_workers);
    for (int i = 0; i < n_workers; ++i) {
        ctx.shards[i] = std::make_unique<FlowShard>();
        ctx.shards[i]->start(n_limit);
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    write_csv_header(*out_ptr);

    auto t0 = std::chrono::high_resolution_clock::now();
    pcap_loop(handle, 0, pcap_dispatch_cb, reinterpret_cast<u_char*>(&ctx));
    auto t_capture_done = std::chrono::high_resolution_clock::now();

    for (auto& s : ctx.shards) s->stop();

    auto t1 = std::chrono::high_resolution_clock::now();
    res.elapsed_sec = std::chrono::duration<double>(t1 - t0).count();

    pcap_close(handle);
    if (fout.is_open()) fout.close();

    long total_flows = 0;
    for (auto& s : ctx.shards) total_flows += s->flows_seen.load();
    res.packets = ctx.total_pkts.load();
    res.flows = g_emitted.load();
    res.message = "ok";
    (void)t_capture_done;
    (void)total_flows;
    return res;
}

#ifndef NVERS_LIBRARY
// ============================================================
// main
// ============================================================
int main(int argc, char* argv[]) {
    std::string pcap_file, iface;
    std::string output_file = "features.csv";
    int  n_limit   = CIC_DEFAULT_N;
    int  n_workers = -1;   // -1 = auto
    bool live_mode = false;

    int opt;
    while ((opt = getopt(argc, argv, "r:i:n:j:w:h")) != -1) {
        switch (opt) {
        case 'r': pcap_file = optarg; break;
        case 'i': iface = optarg; live_mode = true; break;
        case 'n': n_limit   = std::atoi(optarg); break;
        case 'j': n_workers = std::atoi(optarg); break;
        case 'w': output_file = optarg; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (pcap_file.empty() && !live_mode) {
        fprintf(stderr, "错误：请指定 -r <pcap> 或 -i <网卡名>\n\n");
        print_usage(argv[0]); return 1;
    }
    if (live_mode) {
        fprintf(stderr, "库模式仅支持离线 pcap\n");
        return 1;
    }
    wa1kpcap::nvers::ExtractConfig cfg;
    cfg.pcap_path = pcap_file;
    cfg.output_path = output_file;
    cfg.n_limit = n_limit;
    cfg.workers = n_workers;
    return wa1kpcap::nvers::run_cic(cfg).exit_code;
}
#endif
