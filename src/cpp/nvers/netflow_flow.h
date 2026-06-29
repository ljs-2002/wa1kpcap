/**
 * netflow_flow.h  ——  NetFlow v5 + NetFlow v9 / IPFIX 流特征定义
 *
 * 实现的标准字段：
 *   NetFlow v5 (RFC 3954 §8.1)          — 核心 15 字段
 *   NetFlow v9 / IPFIX (RFC 7011/7012)  — 常用 Information Elements
 *
 * IPFIX IE 对照表（本文件覆盖）：
 *   IE   1  octetDeltaCount                IE   2  packetDeltaCount
 *   IE   4  protocolIdentifier             IE   5  ipClassOfService
 *   IE   6  tcpControlBits                 IE   7  sourceTransportPort
 *   IE   8  sourceIPv4Address              IE  11  destinationTransportPort
 *   IE  12  destinationIPv4Address         IE  16  bgpSourceAsNumber
 *   IE  17  bgpDestinationAsNumber         IE  25  minimumIpTotalLength
 *   IE  26  maximumIpTotalLength           IE  52  minimumTTL
 *   IE  53  maximumTTL                     IE  85  octetTotalCount
 *   IE  86  packetTotalCount               IE 152  flowStartMilliseconds
 *   IE 153  flowEndMilliseconds            IE 155  flowStartMicroseconds
 *   IE 161  flowDurationMilliseconds       IE 163  observationPointType
 *   IE 232  initiatorOctets                IE 233  responderOctets
 *   Biflow reverse IEs (RFC 5103)
 *
 * 除标准字段外，还包含统计特征供机器学习使用：
 *   pkt_len_(mean/std/min/max), IAT 统计, fwd/bwd 分向统计, TCP 各标志计数
 */
#pragma once

#include <cstdint>
#include <cstring>
#include <cmath>
#include <cstdio>
#include <algorithm>

/* ============================================================
 * Welford 在线统计量（与 cic_flow.h 独立，避免符号冲突）
 * ============================================================ */
struct NfStats {
    uint32_t n;
    double   mean, M2;
    double   vmin, vmax;
    double   sum;
    /* 不提供默认构造器，使 struct 保持 POD，配合 memset 使用 */

    void reset() noexcept { n=0; mean=M2=sum=0.0; vmin=1e18; vmax=-1e18; }
    void add(double x) noexcept {
        n++; sum += x;
        double d = x - mean; mean += d / n;
        M2 += d * (x - mean);
        if (x < vmin) vmin = x;
        if (x > vmax) vmax = x;
    }
    double var() const noexcept { return n > 1 ? M2 / (n-1) : 0.0; }
    double std() const noexcept { return std::sqrt(std::max(0.0, var())); }
    double min() const noexcept { return n ? vmin : 0.0; }
    double max() const noexcept { return n ? vmax : 0.0; }
};

/* ============================================================
 * 辅助：uint32 IPv4 → "a.b.c.d"
 * ============================================================ */
static inline void nf_ip4str(uint32_t ip, char *buf, int bsz) {
    snprintf(buf, bsz, "%u.%u.%u.%u",
             (ip>>24)&0xff,(ip>>16)&0xff,(ip>>8)&0xff,ip&0xff);
}

/* ============================================================
 * NetFlow / IPFIX 合并流记录
 * ============================================================ */
struct NetFlowRecord {

    /* ---- § NetFlow v5 核心字段 ---- */
    uint32_t src_ip;         /* IE 8  sourceIPv4Address                    */
    uint32_t dst_ip;         /* IE 12 destinationIPv4Address               */
    uint32_t nexthop_ip;     /* 下一跳 IP（pcap 模式置 0）                 */
    uint16_t input_snmp;     /* 输入接口 SNMP index（置 0）                */
    uint16_t output_snmp;    /* 输出接口 SNMP index（置 0）                */
    uint32_t d_pkts;         /* IE  2 packetDeltaCount（总包数）           */
    uint32_t d_octets;       /* IE  1 octetDeltaCount（总字节，IP 层）     */
    uint32_t first_ms;       /* flowStartSysUpTime (ms，相对首包)          */
    uint32_t last_ms;        /* flowEndSysUpTime   (ms，相对首包)          */
    uint16_t src_port;       /* IE  7 sourceTransportPort                  */
    uint16_t dst_port;       /* IE 11 destinationTransportPort             */
    uint8_t  tcp_flags;      /* IE  6 tcpControlBits（所有包 OR）          */
    uint8_t  prot;           /* IE  4 protocolIdentifier                   */
    uint8_t  tos;            /* IE  5 ipClassOfService（首包）             */
    uint16_t src_as;         /* IE 16 bgpSourceAsNumber（未知置 0）        */
    uint16_t dst_as;         /* IE 17 bgpDestinationAsNumber               */
    uint8_t  src_mask;       /* 源 IP 前缀掩码长度（未知置 0）             */
    uint8_t  dst_mask;       /* 目的 IP 前缀掩码长度                       */

    /* ---- § NetFlow v9 / IPFIX 扩展字段 ---- */
    /* 时间戳 */
    uint64_t flow_start_ms;  /* IE 152 flowStartMilliseconds (Unix ms)     */
    uint64_t flow_end_ms;    /* IE 153 flowEndMilliseconds                 */
    uint32_t flow_dur_ms;    /* IE 161 flowDurationMilliseconds            */
    uint64_t flow_start_us;  /* IE 155 flowStartMicroseconds               */

    /* TTL */
    uint8_t  min_ttl;        /* IE 52  minimumTTL                          */
    uint8_t  max_ttl;        /* IE 53  maximumTTL                          */

    /* 包长 */
    uint16_t min_ip_len;     /* IE 25  minimumIpTotalLength                */
    uint16_t max_ip_len;     /* IE 26  maximumIpTotalLength                */

    /* 双向分量（Biflow, RFC 5103 reverse IEs）*/
    uint64_t fwd_pkts;       /* IE  2 正向                                 */
    uint64_t bwd_pkts;       /* reverse packetDeltaCount                   */
    uint64_t fwd_octets;     /* IE  1 正向                                 */
    uint64_t bwd_octets;     /* IE 233 responderOctets                     */

    /* DSCP / ECN */
    uint8_t  dscp;           /* DSCP 值（tos >> 2）                        */
    uint8_t  ecn;            /* ECN 值（tos & 0x03）                       */

    /* TCP 标志计数（各标志位的包计数） */
    uint32_t tcp_syn_cnt;
    uint32_t tcp_fin_cnt;
    uint32_t tcp_rst_cnt;
    uint32_t tcp_psh_cnt;
    uint32_t tcp_ack_cnt;
    uint32_t tcp_urg_cnt;
    uint32_t tcp_cwr_cnt;
    uint32_t tcp_ece_cnt;
    uint8_t  tcp_flags_fwd;  /* 正向包 TCP flags OR                        */
    uint8_t  tcp_flags_bwd;  /* 反向包 TCP flags OR                        */

    /* 统计量：包长（IP total length） */
    NfStats  pkt_len;        /* 所有方向                                   */
    NfStats  fwd_pkt_len;    /* 正向                                       */
    NfStats  bwd_pkt_len;    /* 反向                                       */

    /* 统计量：IAT (inter-arrival time, 微秒) */
    NfStats  iat;            /* 所有方向                                   */
    NfStats  fwd_iat;        /* 正向                                       */
    NfStats  bwd_iat;        /* 反向                                       */

    /* 流速率 */
    double   flow_bytes_ps;  /* bytes/second                               */
    double   flow_pkts_ps;   /* packets/second                             */
    double   fwd_bytes_ps;
    double   bwd_bytes_ps;

    /* IP header length 均值 */
    double   avg_ip_hdr_len;
    double   avg_fwd_ip_hdr_len;
    double   avg_bwd_ip_hdr_len;

    /* ---- 内部追踪（不进 JSON）---- */
    double   _ts_first;
    double   _ts_last;
    double   _ts_last_fwd;
    double   _ts_last_bwd;
    uint64_t _fwd_ip_hdr_sum;
    uint64_t _bwd_ip_hdr_sum;

    /* ============================================================
     * 初始化
     * ============================================================ */
    void init(uint32_t sip, uint32_t dip, uint16_t sp, uint16_t dp,
              uint8_t proto_val) noexcept {
        memset(this, 0, sizeof *this);  /* NfStats 是 POD，可安全 memset */
        pkt_len.reset(); fwd_pkt_len.reset(); bwd_pkt_len.reset();
        iat.reset(); fwd_iat.reset(); bwd_iat.reset();
        src_ip = sip; dst_ip = dip;
        src_port = sp; dst_port = dp;
        prot = proto_val;
        min_ttl = 255; max_ttl = 0;
        min_ip_len = 65535; max_ip_len = 0;
    }

    /* ============================================================
     * 每包处理
     * @param ip_total_len  IP 总长度 (ntohs(iph->ip_len))
     * @param ip_hdr_len    IP 头长度 (iph->ip_hl*4)
     * @param tcp_fl        TCP 标志字节 (0 for UDP)
     * @param ttl           IP TTL
     * @param tos_val       IP ToS
     * @param is_fwd        true = 与首包同向
     * @param ts            绝对时间戳（秒）
     * ============================================================ */
    void process_packet(int ip_total_len, int ip_hdr_len,
                        uint8_t tcp_fl, uint8_t ttl, uint8_t tos_val,
                        bool is_fwd, double ts) noexcept {
        uint64_t total = fwd_pkts + bwd_pkts;

        /* 时间戳初始化 */
        if (total == 0) {
            _ts_first = _ts_last = ts;
            flow_start_ms = (uint64_t)(ts * 1000.0);
            flow_start_us = (uint64_t)(ts * 1e6);
            tos = tos_val;
        }

        /* IAT */
        if (total > 0) {
            iat.add((ts - _ts_last) * 1e6);
            if (is_fwd && fwd_pkts > 0 && _ts_last_fwd > 0.0)
                fwd_iat.add((ts - _ts_last_fwd) * 1e6);
            if (!is_fwd && bwd_pkts > 0 && _ts_last_bwd > 0.0)
                bwd_iat.add((ts - _ts_last_bwd) * 1e6);
        }
        _ts_last = ts;
        if (is_fwd) _ts_last_fwd = ts;
        else        _ts_last_bwd = ts;

        /* 包长统计 */
        pkt_len.add(ip_total_len);
        if (is_fwd) fwd_pkt_len.add(ip_total_len);
        else        bwd_pkt_len.add(ip_total_len);

        /* IP 头长 */
        if (is_fwd) { _fwd_ip_hdr_sum += (uint64_t)ip_hdr_len; fwd_pkts++; fwd_octets += (uint64_t)ip_total_len; }
        else        { _bwd_ip_hdr_sum += (uint64_t)ip_hdr_len; bwd_pkts++; bwd_octets += (uint64_t)ip_total_len; }
        d_pkts   = (uint32_t)(fwd_pkts + bwd_pkts);
        d_octets = (uint32_t)(fwd_octets + bwd_octets);

        /* TTL / TOS */
        if (ttl < min_ttl) min_ttl = ttl;
        if (ttl > max_ttl) max_ttl = ttl;
        dscp = tos_val >> 2;
        ecn  = tos_val & 0x03;

        /* 包长 min/max */
        if ((uint16_t)ip_total_len < min_ip_len) min_ip_len = (uint16_t)ip_total_len;
        if ((uint16_t)ip_total_len > max_ip_len) max_ip_len = (uint16_t)ip_total_len;

        /* TCP flags */
        if (prot == 6) {
            tcp_flags |= tcp_fl;
            if (is_fwd) tcp_flags_fwd |= tcp_fl;
            else        tcp_flags_bwd |= tcp_fl;
            if (tcp_fl & 0x02) tcp_syn_cnt++;
            if (tcp_fl & 0x01) tcp_fin_cnt++;
            if (tcp_fl & 0x04) tcp_rst_cnt++;
            if (tcp_fl & 0x08) tcp_psh_cnt++;
            if (tcp_fl & 0x10) tcp_ack_cnt++;
            if (tcp_fl & 0x20) tcp_urg_cnt++;
            if (tcp_fl & 0x80) tcp_cwr_cnt++;
            if (tcp_fl & 0x40) tcp_ece_cnt++;
        }
    }

    /* ============================================================
     * 流结束时调用：计算派生统计量
     * ============================================================ */
    void finalize() noexcept {
        flow_end_ms  = (uint64_t)(_ts_last * 1000.0);
        flow_dur_ms  = (uint32_t)((_ts_last - _ts_first) * 1000.0);
        last_ms      = flow_dur_ms;
        double dur   = _ts_last - _ts_first;
        if (dur > 0.0) {
            flow_bytes_ps = (double)(fwd_octets + bwd_octets) / dur;
            flow_pkts_ps  = (double)(fwd_pkts   + bwd_pkts)   / dur;
            fwd_bytes_ps  = fwd_pkts > 0 ? (double)fwd_octets / dur : 0.0;
            bwd_bytes_ps  = bwd_pkts > 0 ? (double)bwd_octets / dur : 0.0;
        }
        avg_ip_hdr_len     = (fwd_pkts+bwd_pkts) > 0 ?
            (double)(_fwd_ip_hdr_sum + _bwd_ip_hdr_sum) / (fwd_pkts+bwd_pkts) : 0.0;
        avg_fwd_ip_hdr_len = fwd_pkts > 0 ? (double)_fwd_ip_hdr_sum / fwd_pkts : 0.0;
        avg_bwd_ip_hdr_len = bwd_pkts > 0 ? (double)_bwd_ip_hdr_sum / bwd_pkts : 0.0;
    }

    /* ============================================================
     * JSON 序列化（写入 FILE *）
     * 参数 indent: 缩进字符串（e.g. "    "）
     * ============================================================ */
    void emit_json_netflow_v5(FILE *fp, const char *ind) const {
        char s1[20], s2[20], s3[20];
        nf_ip4str(src_ip,     s1, sizeof s1);
        nf_ip4str(dst_ip,     s2, sizeof s2);
        nf_ip4str(nexthop_ip, s3, sizeof s3);
        fprintf(fp,
            "%s\"netflow_v5\": {\n"
            "%s  \"srcaddr\":     \"%s\",\n"
            "%s  \"dstaddr\":     \"%s\",\n"
            "%s  \"nexthop\":     \"%s\",\n"
            "%s  \"input_snmp\":  %u,\n"
            "%s  \"output_snmp\": %u,\n"
            "%s  \"d_pkts\":      %u,\n"
            "%s  \"d_octets\":    %u,\n"
            "%s  \"first_ms\":    %u,\n"
            "%s  \"last_ms\":     %u,\n"
            "%s  \"srcport\":     %u,\n"
            "%s  \"dstport\":     %u,\n"
            "%s  \"tcp_flags\":   %u,\n"
            "%s  \"prot\":        %u,\n"
            "%s  \"tos\":         %u,\n"
            "%s  \"src_as\":      %u,\n"
            "%s  \"dst_as\":      %u,\n"
            "%s  \"src_mask\":    %u,\n"
            "%s  \"dst_mask\":    %u\n"
            "%s}",
            ind,
            ind, s1, ind, s2, ind, s3,
            ind, input_snmp, ind, output_snmp,
            ind, d_pkts, ind, d_octets,
            ind, first_ms, ind, last_ms,
            ind, src_port, ind, dst_port,
            ind, (unsigned)tcp_flags, ind, (unsigned)prot, ind, (unsigned)tos,
            ind, (unsigned)src_as, ind, (unsigned)dst_as,
            ind, (unsigned)src_mask, ind, (unsigned)dst_mask,
            ind);
    }

    void emit_json_ipfix(FILE *fp, const char *ind) const {
        fprintf(fp,
            "%s\"ipfix\": {\n"
            "%s  \"flow_start_ms\":        %llu,\n"
            "%s  \"flow_end_ms\":          %llu,\n"
            "%s  \"flow_start_us\":        %llu,\n"
            "%s  \"flow_dur_ms\":          %u,\n"
            "%s  \"protocol\":             %u,\n"
            "%s  \"ip_class_of_service\":  %u,\n"
            "%s  \"dscp\":                 %u,\n"
            "%s  \"ecn\":                  %u,\n"
            "%s  \"min_ttl\":              %u,\n"
            "%s  \"max_ttl\":              %u,\n"
            "%s  \"min_ip_total_len\":     %u,\n"
            "%s  \"max_ip_total_len\":     %u,\n"
            "%s  \"fwd_pkts\":             %llu,\n"
            "%s  \"bwd_pkts\":             %llu,\n"
            "%s  \"fwd_octets\":           %llu,\n"
            "%s  \"bwd_octets\":           %llu,\n"
            "%s  \"tcp_control_bits\":     %u,\n"
            "%s  \"tcp_flags_fwd\":        %u,\n"
            "%s  \"tcp_flags_bwd\":        %u,\n"
            "%s  \"tcp_syn_cnt\":          %u,\n"
            "%s  \"tcp_fin_cnt\":          %u,\n"
            "%s  \"tcp_rst_cnt\":          %u,\n"
            "%s  \"tcp_psh_cnt\":          %u,\n"
            "%s  \"tcp_ack_cnt\":          %u,\n"
            "%s  \"tcp_urg_cnt\":          %u,\n"
            "%s  \"tcp_cwr_cnt\":          %u,\n"
            "%s  \"tcp_ece_cnt\":          %u,\n"
            "%s  \"pkt_len_mean\":         %.4f,\n"
            "%s  \"pkt_len_std\":          %.4f,\n"
            "%s  \"pkt_len_min\":          %.0f,\n"
            "%s  \"pkt_len_max\":          %.0f,\n"
            "%s  \"fwd_pkt_len_mean\":     %.4f,\n"
            "%s  \"fwd_pkt_len_std\":      %.4f,\n"
            "%s  \"bwd_pkt_len_mean\":     %.4f,\n"
            "%s  \"bwd_pkt_len_std\":      %.4f,\n"
            "%s  \"iat_mean_us\":          %.4f,\n"
            "%s  \"iat_std_us\":           %.4f,\n"
            "%s  \"iat_min_us\":           %.4f,\n"
            "%s  \"iat_max_us\":           %.4f,\n"
            "%s  \"fwd_iat_mean_us\":      %.4f,\n"
            "%s  \"fwd_iat_std_us\":       %.4f,\n"
            "%s  \"bwd_iat_mean_us\":      %.4f,\n"
            "%s  \"bwd_iat_std_us\":       %.4f,\n"
            "%s  \"flow_bytes_ps\":        %.4f,\n"
            "%s  \"flow_pkts_ps\":         %.4f,\n"
            "%s  \"fwd_bytes_ps\":         %.4f,\n"
            "%s  \"bwd_bytes_ps\":         %.4f,\n"
            "%s  \"avg_ip_hdr_len\":       %.2f,\n"
            "%s  \"avg_fwd_ip_hdr_len\":   %.2f,\n"
            "%s  \"avg_bwd_ip_hdr_len\":   %.2f\n"
            "%s}",
            ind,
            ind,(unsigned long long)flow_start_ms,
            ind,(unsigned long long)flow_end_ms,
            ind,(unsigned long long)flow_start_us,
            ind,flow_dur_ms,
            ind,(unsigned)prot, ind,(unsigned)tos,
            ind,(unsigned)dscp, ind,(unsigned)ecn,
            ind,(unsigned)min_ttl, ind,(unsigned)max_ttl,
            ind,(unsigned)min_ip_len, ind,(unsigned)max_ip_len,
            ind,(unsigned long long)fwd_pkts, ind,(unsigned long long)bwd_pkts,
            ind,(unsigned long long)fwd_octets, ind,(unsigned long long)bwd_octets,
            ind,(unsigned)tcp_flags, ind,(unsigned)tcp_flags_fwd, ind,(unsigned)tcp_flags_bwd,
            ind,tcp_syn_cnt, ind,tcp_fin_cnt, ind,tcp_rst_cnt,
            ind,tcp_psh_cnt, ind,tcp_ack_cnt, ind,tcp_urg_cnt,
            ind,tcp_cwr_cnt, ind,tcp_ece_cnt,
            ind,pkt_len.mean, ind,pkt_len.std(),
            ind,pkt_len.min(), ind,pkt_len.max(),
            ind,fwd_pkt_len.mean, ind,fwd_pkt_len.std(),
            ind,bwd_pkt_len.mean, ind,bwd_pkt_len.std(),
            ind,iat.mean, ind,iat.std(),
            ind,iat.min(), ind,iat.max(),
            ind,fwd_iat.mean, ind,fwd_iat.std(),
            ind,bwd_iat.mean, ind,bwd_iat.std(),
            ind,flow_bytes_ps, ind,flow_pkts_ps,
            ind,fwd_bytes_ps, ind,bwd_bytes_ps,
            ind,avg_ip_hdr_len,
            ind,avg_fwd_ip_hdr_len,
            ind,avg_bwd_ip_hdr_len,
            ind);
    }
};
