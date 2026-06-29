/**
 * cic_flow.h  ——  CIC-FlowMeter 特征数据结构（Header-Only）
 *
 * 设计原则：
 *   - 纯头文件，所有方法 inline，可安全被多个编译单元包含
 *   - 所有统计量使用 Welford 在线算法（O(1) 内存，数值稳定）
 *   - process_packet() 被标注为 noexcept，尽量内联，适合高频调用
 *   - 双向流方向由首包决定；FlowKey::canonical() 提供规范化键用于 hash 路由
 *
 * 特征列表（78 列，与 CIC-FlowMeter CICIDS-2017 对齐）：
 *   flow_id, dst_port, protocol, flow_duration,
 *   tot_fwd_pkts, tot_bwd_pkts, totlen_fwd_pkts, totlen_bwd_pkts,
 *   fwd_pkt_len_{max,min,mean,std}, bwd_pkt_len_{max,min,mean,std},
 *   flow_byts_s, flow_pkts_s,
 *   flow_iat_{mean,std,max,min},
 *   fwd_iat_{tot,mean,std,max,min}, bwd_iat_{tot,mean,std,max,min},
 *   fwd/bwd_{psh,urg}_flags, fwd/bwd_header_len,
 *   fwd/bwd_pkts_s, pkt_len_{min,max,mean,std,var},
 *   {fin,syn,rst,psh,ack,urg,cwe,ece}_flag_cnt,
 *   down_up_ratio, pkt_size_avg, fwd/bwd_seg_size_avg, fwd_header_len2,
 *   fwd/bwd_{byts,pkts,blk_rate}_b_avg,
 *   subflow_{fwd,bwd}_{pkts,byts},
 *   init_{fwd,bwd}_win_byts, fwd_act_data_pkts, fwd_seg_size_min,
 *   active_{mean,std,max,min}, idle_{mean,std,max,min}
 */
#pragma once

#include <cstdint>
#include <cmath>
#include <climits>
#include <cstring>
#include <cstdio>
#include <ostream>
#include <iomanip>
#include <arpa/inet.h>   // ntohs, inet_ntop
#include <netinet/in.h>

#include "flow_limit.h"

// ============================================================
// 全局超时 / 阈值常量
// ============================================================
static constexpr int    CIC_DEFAULT_N      = FLOW_LIMIT_ALL;  // 0=全流，>0=前 N 包
static constexpr double ACTIVITY_TIMEOUT   = 5.0;   // Active/Idle 分割阈值（秒）
static constexpr double BULK_GAP_SEC       = 1.0;   // Bulk 包间最大间隔（秒）
static constexpr int    BULK_MIN_PKTS      = 4;     // 构成 Bulk 的最少包数
static constexpr double FLOW_TCP_TIMEOUT   = 120.0; // TCP 流老化（秒）
static constexpr double FLOW_UDP_TIMEOUT   = 60.0;  // UDP 流老化（秒）
static constexpr double FLOW_MAX_DURATION  = 600.0; // 流最大持续时间（秒）

// ============================================================
// Welford 在线统计量（均值 / 方差 / min / max）
// ============================================================
struct Stats {
    uint32_t n    = 0;
    double   mean_= 0.0, M2_ = 0.0;
    double   min_ = 1e18, max_ = -1e18;
    double   sum_ = 0.0;

    inline void add(double x) noexcept {
        ++n; sum_ += x;
        double d = x - mean_; mean_ += d / n;
        M2_ += d * (x - mean_);
        if (x < min_) min_ = x;
        if (x > max_) max_ = x;
    }

    inline uint32_t count() const noexcept { return n; }
    inline double   total() const noexcept { return sum_; }
    inline double   mean()  const noexcept { return n ? mean_ : 0.0; }
    inline double   var()   const noexcept { return n > 1 ? M2_/(n-1) : 0.0; }
    inline double   std()   const noexcept { return std::sqrt(std::max(0.0, var())); }
    inline double   min()   const noexcept { return n ? min_ : 0.0; }
    inline double   max()   const noexcept { return n ? max_ : 0.0; }
};

// ============================================================
// Bulk 突发段追踪器
//   同方向连续 >= BULK_MIN_PKTS 个带 payload 的包，
//   且对端无更新、且包间隔 < BULK_GAP_SEC，判定为一次 Bulk。
// ============================================================
struct BulkTracker {
    uint32_t cur_n   = 0;
    double   cur_b   = 0.0, cur_s = 0.0, cur_l = 0.0; // bytes, start_ts, last_ts
    uint32_t states  = 0;                               // bulk 段计数
    uint32_t tot_pkts= 0;
    double   tot_bytes=0.0, tot_dur=0.0;

    inline void flush() noexcept {
        if (cur_n >= (uint32_t)BULK_MIN_PKTS) {
            ++states; tot_pkts += cur_n; tot_bytes += cur_b;
            double d = cur_l - cur_s; if (d > 0) tot_dur += d;
        }
        cur_n = 0; cur_b = cur_s = cur_l = 0.0;
    }

    inline void update(double ts, double payload, double other_last) noexcept {
        // 若对端有更新（在本方向上一包之后），中断当前 Bulk
        if (other_last > 0.0 && cur_l > 0.0 && other_last > cur_l) flush();
        if (payload <= 0.0) return;
        if (!cur_n) {
            cur_s = cur_l = ts; cur_n = 1; cur_b = payload;
        } else if (ts - cur_l > BULK_GAP_SEC) {
            flush(); cur_s = cur_l = ts; cur_n = 1; cur_b = payload;
        } else {
            ++cur_n; cur_b += payload; cur_l = ts;
        }
    }

    inline void finalize() noexcept { flush(); }

    inline double avg_bytes() const noexcept { return states ? tot_bytes/states : 0.0; }
    inline double avg_pkts()  const noexcept { return states ? (double)tot_pkts/states : 0.0; }
    inline double avg_rate()  const noexcept { return tot_dur > 0 ? tot_bytes/tot_dur : 0.0; }
};

// ============================================================
// 五元组流键
// ============================================================
struct FlowKey {
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t  proto = 0;

    inline bool operator==(const FlowKey& o) const noexcept {
        return src_ip==o.src_ip && dst_ip==o.dst_ip
            && src_port==o.src_port && dst_port==o.dst_port
            && proto==o.proto;
    }

    inline FlowKey rev() const noexcept {
        FlowKey r; r.src_ip=dst_ip; r.dst_ip=src_ip;
        r.src_port=dst_port; r.dst_port=src_port; r.proto=proto;
        return r;
    }

    /**
     * 规范化键：保证双向包路由到同一 Worker Shard。
     * 约定：src_ip 较小的方向为正向；相等时 src_port 较小者为正向。
     */
    inline FlowKey canonical() const noexcept {
        return (src_ip > dst_ip || (src_ip==dst_ip && src_port > dst_port))
               ? rev() : *this;
    }
};

struct FlowKeyHash {
    inline size_t operator()(const FlowKey& k) const noexcept {
        auto h64 = [](uint64_t x) -> uint64_t {
            x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
            x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
            x ^= x >> 33; return x;
        };
        uint64_t a = h64((uint64_t)k.src_ip | ((uint64_t)k.dst_ip << 32));
        uint64_t b = h64((uint64_t)k.src_port
                       | ((uint64_t)k.dst_port << 16)
                       | ((uint64_t)k.proto   << 32));
        return (size_t)(a ^ b);
    }
};

// ============================================================
// 流记录（CIC-FlowMeter 特征：78 列数值 + 元信息）
// ============================================================
struct FlowRecord {
    FlowKey  fwd_key;               // 正向方向键（首包方向）
    int      n_limit   = CIC_DEFAULT_N;
    uint32_t pkt_count = 0;
    bool     done    = false;
    bool     emitted = false;

    // ---------- 时间 ----------
    double start_ts    = 0.0, last_ts   = 0.0;
    double last_fwd_ts = -1.0, last_bwd_ts = -1.0;

    // ---------- 包长统计 ----------
    Stats fwd_len, bwd_len, all_len;

    // ---------- IAT 统计 ----------
    Stats flow_iat, fwd_iat, bwd_iat;

    // ---------- 头部长度（总和） ----------
    double fwd_hdr_sum = 0.0, bwd_hdr_sum = 0.0;

    // ---------- TCP 标志位 ----------
    int fin_cnt=0, syn_cnt=0, rst_cnt=0, psh_cnt=0;
    int ack_cnt=0, urg_cnt=0, cwe_cnt=0, ece_cnt=0;
    int fwd_psh=0, bwd_psh=0, fwd_urg=0, bwd_urg=0;

    // ---------- 初始窗口 ----------
    int32_t init_win_fwd = -1, init_win_bwd = -1;

    // ---------- 正向数据包 / 最小段大小 ----------
    int act_data_fwd = 0;
    int min_seg_fwd  = INT_MAX;

    // ---------- Bulk ----------
    BulkTracker fwd_bulk, bwd_bulk;

    // ---------- Active / Idle ----------
    Stats  active_stats, idle_stats;
    double active_start  = 0.0, last_active_ts = 0.0;

    // ---------- Subflow ----------
    int    sf_fwd_pkts = 0, sf_bwd_pkts = 0;
    double sf_fwd_bytes= 0.0, sf_bwd_bytes= 0.0;
    int    subflow_cnt = 0;

    // ---------- 流标识字符串 ----------
    char flow_id[96] = {};

    // ----------------------------------------------------------
    // 在线更新：每收到一个包调用一次
    // ----------------------------------------------------------
    inline void process_packet(bool is_fwd, double ts,
                               int ip_len, int payload_len, int hdr_len,
                               uint8_t tcp_flags, int win_size) noexcept
    {
        if (done) return;
        ++pkt_count;

        // --- 时间 & Active/Idle & Subflow ---
        if (pkt_count == 1) {
            start_ts = last_ts = ts;
            active_start = last_active_ts = ts;
            subflow_cnt = 1;
        } else {
            double iat = ts - last_ts;
            if (iat >= 0.0) flow_iat.add(iat);
            if (iat > ACTIVITY_TIMEOUT) {
                double dur = last_active_ts - active_start;
                if (dur > 0.0) active_stats.add(dur);
                idle_stats.add(iat);
                active_start = ts;
                ++subflow_cnt;
            }
            last_active_ts = ts;
            last_ts = ts;
        }

        // --- 全局包长 ---
        all_len.add((double)ip_len);

        if (is_fwd) {
            fwd_len.add((double)ip_len);
            if (last_fwd_ts >= 0.0) fwd_iat.add(ts - last_fwd_ts);
            fwd_hdr_sum += hdr_len;
            ++sf_fwd_pkts; sf_fwd_bytes += ip_len;
            fwd_bulk.update(ts, (double)payload_len, last_bwd_ts);
            if (init_win_fwd < 0 && win_size >= 0) init_win_fwd = win_size;
            if (payload_len > 0) ++act_data_fwd;
            if (hdr_len > 0 && hdr_len < min_seg_fwd) min_seg_fwd = hdr_len;
            if (tcp_flags & 0x08) ++fwd_psh;
            if (tcp_flags & 0x20) ++fwd_urg;
            last_fwd_ts = ts;
        } else {
            bwd_len.add((double)ip_len);
            if (last_bwd_ts >= 0.0) bwd_iat.add(ts - last_bwd_ts);
            bwd_hdr_sum += hdr_len;
            ++sf_bwd_pkts; sf_bwd_bytes += ip_len;
            bwd_bulk.update(ts, (double)payload_len, last_fwd_ts);
            if (init_win_bwd < 0 && win_size >= 0) init_win_bwd = win_size;
            if (tcp_flags & 0x08) ++bwd_psh;
            if (tcp_flags & 0x20) ++bwd_urg;
            last_bwd_ts = ts;
        }

        // --- TCP 标志位（双向统计） ---
        if (tcp_flags) {
            if (tcp_flags & 0x01) ++fin_cnt;
            if (tcp_flags & 0x02) ++syn_cnt;
            if (tcp_flags & 0x04) ++rst_cnt;
            if (tcp_flags & 0x08) ++psh_cnt;
            if (tcp_flags & 0x10) ++ack_cnt;
            if (tcp_flags & 0x20) ++urg_cnt;
            if (tcp_flags & 0x40) ++ece_cnt;
            if (tcp_flags & 0x80) ++cwe_cnt;
        }

        if (flow_limit_reached(pkt_count, n_limit)) {
            finalize();
            done = true;
        }
    }

    // 流结束时调用（关闭最后一个活跃期 + Bulk 收尾）
    inline void finalize() noexcept {
        if (emitted) return;
        double dur = last_active_ts - active_start;
        if (dur > 0.0) active_stats.add(dur);
        fwd_bulk.finalize();
        bwd_bulk.finalize();
    }

    // 输出一行 CSV 字段（不含换行；供 cicext 等扩展模块拼接列）
    void emit_fields(std::ostream& out) const {
        double dur    = last_ts - start_ts;
        double dur_us = dur * 1e6;
        double bps    = dur > 0 ? all_len.total() / dur : 0.0;
        double pps    = dur > 0 ? pkt_count / dur : 0.0;
        double fps    = dur > 0 ? fwd_len.count() / dur : 0.0;
        double bpps   = dur > 0 ? bwd_len.count() / dur : 0.0;
        double du     = fwd_len.count() > 0 ? (double)bwd_len.count()/fwd_len.count() : 0.0;
        double sc     = std::max(1, subflow_cnt);
        auto F = [](double v) noexcept { return std::isfinite(v) ? v : 0.0; };

        out << std::fixed
            << flow_id              << ","
            << ntohs(fwd_key.dst_port) << ","
            << (int)fwd_key.proto   << ","
            << std::setprecision(0) << F(dur_us) << ","
            // fwd/bwd packet counts & lengths
            << fwd_len.count()      << "," << bwd_len.count()      << ","
            << F(fwd_len.total())   << "," << F(bwd_len.total())    << ","
            << F(fwd_len.max())     << "," << F(fwd_len.min())      << ","
            << std::setprecision(4) << F(fwd_len.mean()) << "," << F(fwd_len.std()) << ","
            << std::setprecision(0) << F(bwd_len.max())  << "," << F(bwd_len.min()) << ","
            << std::setprecision(4) << F(bwd_len.mean()) << "," << F(bwd_len.std()) << ","
            // flow rates
            << F(bps) << "," << F(pps) << ","
            // flow IAT (us)
            << F(flow_iat.mean()*1e6) << "," << F(flow_iat.std()*1e6) << ","
            << std::setprecision(0)
            << F(flow_iat.max()*1e6) << "," << F(flow_iat.min()*1e6) << ","
            // fwd IAT
            << F(fwd_iat.total()*1e6) << ","
            << std::setprecision(4)
            << F(fwd_iat.mean()*1e6) << "," << F(fwd_iat.std()*1e6) << ","
            << std::setprecision(0)
            << F(fwd_iat.max()*1e6)  << "," << F(fwd_iat.min()*1e6) << ","
            // bwd IAT
            << F(bwd_iat.total()*1e6) << ","
            << std::setprecision(4)
            << F(bwd_iat.mean()*1e6) << "," << F(bwd_iat.std()*1e6) << ","
            << std::setprecision(0)
            << F(bwd_iat.max()*1e6)  << "," << F(bwd_iat.min()*1e6) << ","
            // PSH/URG flags, header len
            << fwd_psh << "," << bwd_psh << "," << fwd_urg << "," << bwd_urg << ","
            << F(fwd_hdr_sum) << "," << F(bwd_hdr_sum) << ","
            // per-direction packet rate
            << std::setprecision(4) << F(fps) << "," << F(bpps) << ","
            // overall packet length stats
            << std::setprecision(0) << F(all_len.min()) << "," << F(all_len.max()) << ","
            << std::setprecision(4)
            << F(all_len.mean()) << "," << F(all_len.std()) << "," << F(all_len.var()) << ","
            // flag counts
            << fin_cnt << "," << syn_cnt << "," << rst_cnt << "," << psh_cnt << ","
            << ack_cnt << "," << urg_cnt << "," << cwe_cnt << "," << ece_cnt << ","
            // ratio, segment sizes
            << F(du) << "," << F(all_len.mean()) << ","
            << F(fwd_len.mean()) << "," << F(bwd_len.mean()) << ","
            << std::setprecision(0) << F(fwd_hdr_sum) << ","
            // bulk
            << std::setprecision(4)
            << F(fwd_bulk.avg_bytes()) << "," << F(fwd_bulk.avg_pkts()) << "," << F(fwd_bulk.avg_rate()) << ","
            << F(bwd_bulk.avg_bytes()) << "," << F(bwd_bulk.avg_pkts()) << "," << F(bwd_bulk.avg_rate()) << ","
            // subflow
            << std::setprecision(0)
            << F(sf_fwd_pkts/sc)  << "," << F(sf_fwd_bytes/sc) << ","
            << F(sf_bwd_pkts/sc)  << "," << F(sf_bwd_bytes/sc) << ","
            // init window, act_data, min_seg
            << init_win_fwd << "," << init_win_bwd << ","
            << act_data_fwd << "," << (min_seg_fwd == INT_MAX ? 0 : min_seg_fwd) << ","
            // active/idle (us)
            << std::setprecision(4)
            << F(active_stats.mean()*1e6) << "," << F(active_stats.std()*1e6) << ","
            << std::setprecision(0)
            << F(active_stats.max()*1e6)  << "," << F(active_stats.min()*1e6) << ","
            << std::setprecision(4)
            << F(idle_stats.mean()*1e6) << "," << F(idle_stats.std()*1e6) << ","
            << std::setprecision(0)
            << F(idle_stats.max()*1e6)  << "," << F(idle_stats.min()*1e6);
    }

    // 输出一行 CSV（调用前请先获取输出互斥量）
    void emit(std::ostream& out) const {
        emit_fields(out);
        out << "\n";
    }
};

// ============================================================
// CSV 表头（与 FlowRecord::emit() 严格对应）
// ============================================================
inline void write_csv_header_fields(std::ostream& out) {
    out <<
        "flow_id,dst_port,protocol,flow_duration,"
        "tot_fwd_pkts,tot_bwd_pkts,totlen_fwd_pkts,totlen_bwd_pkts,"
        "fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,fwd_pkt_len_std,"
        "bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,bwd_pkt_len_std,"
        "flow_byts_s,flow_pkts_s,"
        "flow_iat_mean,flow_iat_std,flow_iat_max,flow_iat_min,"
        "fwd_iat_tot,fwd_iat_mean,fwd_iat_std,fwd_iat_max,fwd_iat_min,"
        "bwd_iat_tot,bwd_iat_mean,bwd_iat_std,bwd_iat_max,bwd_iat_min,"
        "fwd_psh_flags,bwd_psh_flags,fwd_urg_flags,bwd_urg_flags,"
        "fwd_header_len,bwd_header_len,fwd_pkts_s,bwd_pkts_s,"
        "pkt_len_min,pkt_len_max,pkt_len_mean,pkt_len_std,pkt_len_var,"
        "fin_flag_cnt,syn_flag_cnt,rst_flag_cnt,psh_flag_cnt,"
        "ack_flag_cnt,urg_flag_cnt,cwe_flag_cnt,ece_flag_cnt,"
        "down_up_ratio,pkt_size_avg,fwd_seg_size_avg,bwd_seg_size_avg,"
        "fwd_header_len2,"
        "fwd_byts_b_avg,fwd_pkts_b_avg,fwd_blk_rate_avg,"
        "bwd_byts_b_avg,bwd_pkts_b_avg,bwd_blk_rate_avg,"
        "subflow_fwd_pkts,subflow_fwd_byts,subflow_bwd_pkts,subflow_bwd_byts,"
        "init_fwd_win_byts,init_bwd_win_byts,"
        "fwd_act_data_pkts,fwd_seg_size_min,"
        "active_mean,active_std,active_max,active_min,"
        "idle_mean,idle_std,idle_max,idle_min";
}

inline void write_csv_header(std::ostream& out) {
    write_csv_header_fields(out);
    out << "\n";
}
