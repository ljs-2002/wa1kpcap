/**
 * cicext_flow.h  ——  CIC-FlowMeter 扩展版（序列分位数 + 偏度峰度）
 *
 * 在标准 CIC 78 列基础上，对前 N 个包构成的序列计算分布特征：
 *
 *   序列类型（4 种）：
 *     pkt_len   — IP 全包长
 *     pay_len   — TCP/UDP 负载长度
 *     iat_us    — 包间到达时间（微秒，首包为 0）
 *     hdr_len   — IP 头 + 传输层头长度
 *
 *   方向（3 种）：
 *     all  — 全流按时间顺序
 *     fwd  — 正向（首包方向）
 *     bwd  — 反向
 *
 *   每条序列统计量（16 项）：
 *     p10, p20, p30, p40, p50, p60, p70, p80, p90  （10%–90% 分位数）
 *     mean, std, min, max, median, skew, kurt
 *
 *   扩展列数：4 × 3 × 16 = 192 列
 *   总列数：80 + 192 = 272
 *
 * nvers：序列采样包数由运行时 -n 控制，0 表示全流。
 */
#pragma once

#include "cic_flow.h"
#include "flow_limit.h"

#include <algorithm>
#include <cmath>
#include <ostream>
#include <vector>
#include <iomanip>

/* ============================================================
 * 序列缓冲（动态增长，受 n_limit 约束）
 * ============================================================ */
struct SeqBuf {
    std::vector<double> vals;

    inline void clear() noexcept { vals.clear(); }

    inline void push(double v) noexcept { vals.push_back(v); }
};

/* ============================================================
 * 分布统计结果
 * ============================================================ */
struct DistFeat {
    double p10 = 0, p20 = 0, p30 = 0, p40 = 0, p50 = 0;
    double p60 = 0, p70 = 0, p80 = 0, p90 = 0;
    double mean = 0, std = 0, min = 0, max = 0, median = 0;
    double skew = 0, kurt = 0;
};

/* 线性插值分位数，q ∈ [0,1] */
static inline double seq_percentile(const double *sorted, int n, double q) noexcept {
    if (n <= 0) return 0.0;
    if (n == 1) return sorted[0];
    double pos = q * (double)(n - 1);
    int    lo  = (int)pos;
    int    hi  = lo + 1;
    if (hi >= n) return sorted[n - 1];
    double frac = pos - (double)lo;
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

/* 从原始序列计算完整分布特征 */
static inline DistFeat seq_compute_dist(const double *data, int n) noexcept {
    DistFeat d;
    if (n <= 0) return d;

    std::vector<double> v((size_t)n);
    for (int i = 0; i < n; i++) v[(size_t)i] = data[i];
    std::sort(v.begin(), v.end());

    d.min    = v[0];
    d.max    = v[(size_t)n - 1];
    d.median = seq_percentile(v.data(), n, 0.5);
    d.p10    = seq_percentile(v.data(), n, 0.10);
    d.p20    = seq_percentile(v.data(), n, 0.20);
    d.p30    = seq_percentile(v.data(), n, 0.30);
    d.p40    = seq_percentile(v.data(), n, 0.40);
    d.p50    = d.median;
    d.p60    = seq_percentile(v.data(), n, 0.60);
    d.p70    = seq_percentile(v.data(), n, 0.70);
    d.p80    = seq_percentile(v.data(), n, 0.80);
    d.p90    = seq_percentile(v.data(), n, 0.90);

    double sum = 0.0;
    for (int i = 0; i < n; i++) sum += data[i];
    d.mean = sum / (double)n;

    double m2 = 0.0;
    for (int i = 0; i < n; i++) {
        double x = data[i] - d.mean;
        m2 += x * x;
    }

    d.std = (n > 1) ? std::sqrt(m2 * (double)n / (double)(n - 1)) : 0.0;

    if (n >= 3 && d.std > 1e-12) {
        double z3 = 0.0, z4 = 0.0;
        for (int i = 0; i < n; i++) {
            double z = (data[i] - d.mean) / d.std;
            z3 += z * z * z;
            z4 += z * z * z * z;
        }
        double nf = (double)n;
        d.skew = (nf / ((nf - 1.0) * (nf - 2.0))) * z3;
        if (n >= 4) {
            d.kurt = (nf * (nf + 1.0) / ((nf - 1.0) * (nf - 2.0) * (nf - 3.0))) * z4
                   - 3.0 * (nf - 1.0) * (nf - 1.0) / ((nf - 2.0) * (nf - 3.0));
        }
    }

    return d;
}

static inline void emit_dist_csv(std::ostream& out, const DistFeat& d) {
    auto F = [](double v) noexcept { return std::isfinite(v) ? v : 0.0; };
    out << std::setprecision(4)
        << F(d.p10) << "," << F(d.p20) << "," << F(d.p30) << ","
        << F(d.p40) << "," << F(d.p50) << "," << F(d.p60) << ","
        << F(d.p70) << "," << F(d.p80) << "," << F(d.p90) << ","
        << F(d.mean) << "," << F(d.std) << ","
        << std::setprecision(0) << F(d.min) << "," << F(d.max) << ","
        << std::setprecision(4) << F(d.median) << ","
        << F(d.skew) << "," << F(d.kurt);
}

/* ============================================================
 * CIC 扩展流记录
 * ============================================================ */
struct CicExtRecord {
    FlowRecord base;

    /* 12 条序列缓冲：4 类型 × 3 方向 */
    SeqBuf all_pkt_len, fwd_pkt_len, bwd_pkt_len;
    SeqBuf all_pay_len, fwd_pay_len, bwd_pay_len;
    SeqBuf all_iat_us,  fwd_iat_us,  bwd_iat_us;
    SeqBuf all_hdr_len, fwd_hdr_len, bwd_hdr_len;

    /* IAT 追踪（与 base 独立，用于序列首包=0） */
    double seq_last_ts      = -1.0;
    double seq_last_fwd_ts  = -1.0;
    double seq_last_bwd_ts  = -1.0;

    inline void process_packet(bool is_fwd, double ts,
                               int ip_len, int payload_len, int hdr_len,
                               uint8_t tcp_flags, int win_size) noexcept
    {
        if (base.done) return;

        /* 序列采样（在 base 更新前记录 IAT） */
        if (!flow_limit_reached(base.pkt_count, base.n_limit)) {
            double iat_all = 0.0, iat_fwd = 0.0, iat_bwd = 0.0;
            if (seq_last_ts >= 0.0) {
                iat_all = (ts - seq_last_ts) * 1e6;
                if (iat_all < 0.0) iat_all = 0.0;
            }
            if (is_fwd) {
                if (seq_last_fwd_ts >= 0.0) {
                    iat_fwd = (ts - seq_last_fwd_ts) * 1e6;
                    if (iat_fwd < 0.0) iat_fwd = 0.0;
                }
            } else {
                if (seq_last_bwd_ts >= 0.0) {
                    iat_bwd = (ts - seq_last_bwd_ts) * 1e6;
                    if (iat_bwd < 0.0) iat_bwd = 0.0;
                }
            }

            all_pkt_len.push((double)ip_len);
            all_pay_len.push((double)payload_len);
            all_iat_us.push(iat_all);
            all_hdr_len.push((double)hdr_len);

            if (is_fwd) {
                fwd_pkt_len.push((double)ip_len);
                fwd_pay_len.push((double)payload_len);
                fwd_iat_us.push(iat_fwd);
                fwd_hdr_len.push((double)hdr_len);
                seq_last_fwd_ts = ts;
            } else {
                bwd_pkt_len.push((double)ip_len);
                bwd_pay_len.push((double)payload_len);
                bwd_iat_us.push(iat_bwd);
                bwd_hdr_len.push((double)hdr_len);
                seq_last_bwd_ts = ts;
            }
            seq_last_ts = ts;
        }

        base.process_packet(is_fwd, ts, ip_len, payload_len, hdr_len,
                            tcp_flags, win_size);
    }

    inline void finalize() noexcept { base.finalize(); }

    inline bool done()    const noexcept { return base.done; }
    inline bool emitted() const noexcept { return base.emitted; }
    inline void set_emitted(bool v) noexcept { base.emitted = v; }

    /* 代理常用字段供 extractor 老化逻辑使用 */
    double last_ts()  const noexcept { return base.last_ts; }
    double start_ts() const noexcept { return base.start_ts; }
    const FlowKey& fwd_key() const noexcept { return base.fwd_key; }
    char* flow_id() noexcept { return base.flow_id; }
    int  n_limit()  const noexcept { return base.n_limit; }

    void emit(std::ostream& out) const {
        base.emit_fields(out);

        auto emit_seq = [&](const SeqBuf& buf) {
            DistFeat d = seq_compute_dist(buf.vals.data(), (int)buf.vals.size());
            out << ",";
            emit_dist_csv(out, d);
        };

        emit_seq(all_pkt_len);
        emit_seq(fwd_pkt_len);
        emit_seq(bwd_pkt_len);
        emit_seq(all_pay_len);
        emit_seq(fwd_pay_len);
        emit_seq(bwd_pay_len);
        emit_seq(all_iat_us);
        emit_seq(fwd_iat_us);
        emit_seq(bwd_iat_us);
        emit_seq(all_hdr_len);
        emit_seq(fwd_hdr_len);
        emit_seq(bwd_hdr_len);

        out << "\n";
    }
};

/* ============================================================
 * 扩展 CSV 表头
 * ============================================================ */
static inline void write_dist_header(std::ostream& out, const char *prefix) {
    out << prefix << "_p10,"  << prefix << "_p20,"  << prefix << "_p30,"
        << prefix << "_p40,"  << prefix << "_p50,"  << prefix << "_p60,"
        << prefix << "_p70,"  << prefix << "_p80,"  << prefix << "_p90,"
        << prefix << "_mean," << prefix << "_std,"
        << prefix << "_min,"  << prefix << "_max,"  << prefix << "_median,"
        << prefix << "_skew," << prefix << "_kurt";
}

inline void write_cicext_csv_header(std::ostream& out) {
    write_csv_header_fields(out);
    static const char *seqs[] = {
        "all_pkt_len","fwd_pkt_len","bwd_pkt_len",
        "all_pay_len","fwd_pay_len","bwd_pay_len",
        "all_iat_us","fwd_iat_us","bwd_iat_us",
        "all_hdr_len","fwd_hdr_len","bwd_hdr_len"
    };
    for (int i = 0; i < 12; i++) {
        out << ",";
        write_dist_header(out, seqs[i]);
    }
    out << "\n";
}
